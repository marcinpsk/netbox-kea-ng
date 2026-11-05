# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The judgment and the removal of Stale DHCP Import Objects.

* **Removal.** A mapped row whose Kea source a Complete observation of its kind no longer reports is a Stale DHCP Import
  Object (:func:`stale_judgment`, :func:`remove_stale_objects`). The run removes it, children first, and reports it. An
  Incomplete observation keeps every row of its kind. A row whose delete would also delete a DHCP plugin row that the
  run keeps, that an Option still uses, or that a kept row names in a client class relation, stays. IPAM objects stay:
  ADR 0006 ownership decides them.
  The Subnet writes run first, so a kept Subnet that left a stale Shared Network no longer belongs to it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.apps import apps
from django.db.models import F
from django.db.models.deletion import Collector, ProtectedError

from .. import event_scope
from .dhcp_import_mappings import mapped_links, mapped_option_keys
from .dhcp_import_plan import MappingSource, kind_path, mapped_kinds
from .dhcp_import_report import KIND_LABELS, Kind, Outcome, Reason, counted, not_written, written
from .dhcp_import_summary import ImportSummary
from .dhcp_import_write import FAILED
from .dhcp_plugin_capabilities import PLUGIN_APP_LABEL, plugin_model

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .dhcp_import_plan import FamilyPlan, KindObservation


def unobserved_kinds(judgment: StaleJudgment, removed: set[MappingSource]) -> set[Kind]:
    """Return the kinds that still have a mapped DHCP plugin row whose Kea source the read does not observe.

    *removed* holds the sources that :func:`remove_stale_objects` removed. Each other unobserved row stayed: its kind
    was not observed in full, its removal failed or was blocked, another writer confirmed its mapping after the cutoff,
    or the plan has no cutoff.
    """
    return {
        kind
        for kind, judged in judgment.kinds.items()
        if judged.not_judged or judged.kept or judged.newer or judged.removable.keys() - removed
    }


@dataclass(frozen=True)
class _StaleRow:
    """A mapped row whose Kea source the run did not observe."""

    source: MappingSource
    # A DHCP plugin model instance; the plugin is optional, so its models have no static type here.
    target: Any


def _row_key(obj) -> tuple:
    return obj._meta.concrete_model, obj.pk


def _goes_with_parent(model) -> bool:
    """Return whether rows of *model* go with a deleted parent: models outside the DHCP plugin, Options, through rows.

    A mapped Option goes only when it is stale itself (:func:`_removal_plan`).
    """
    return model._meta.app_label != PLUGIN_APP_LABEL or model._meta.auto_created or model is plugin_model("Option")


def _counted_rows(rows: list) -> str:
    """Return the number of *rows* of each model, for the detail of an entry."""
    models = Counter(row._meta.concrete_model for row in rows)
    return ", ".join(
        counted(count, model._meta.verbose_name, model._meta.verbose_name_plural) for model, count in models.items()
    )


class _FootprintCollector(Collector):
    """A delete collector that leaves out the Options that the removal deletes before its row."""

    def __init__(self, using: str, deleted_first: frozenset[int]) -> None:
        super().__init__(using=using)
        self.deleted_first = deleted_first

    def related_objects(self, related_model, related_fields, objs):
        """Return the related rows of *objs*, without the Options that go first."""
        rows = super().related_objects(related_model, related_fields, objs)
        return rows.exclude(pk__in=self.deleted_first) if related_model is plugin_model("Option") else rows


def _collected(collector: Collector) -> list:
    rows = [obj for objects in collector.data.values() for obj in objects]
    rows.extend(obj for queryset in collector.fast_deletes for obj in queryset)
    return rows


def _owner_key(option) -> tuple:
    """Return the row key of the object that *option* is assigned to."""
    return option.assigned_object_type.model_class()._meta.concrete_model, option.assigned_object_id


def _option_goes_with(option, stale: dict, mapped_options: frozenset[tuple]) -> tuple | None:
    """Return the row whose removal takes *option*: the Option when it is stale, its owner when it is unmapped.

    Return ``None`` for a mapped Option that the run keeps: no removal takes it.
    """
    own = _row_key(option)
    if own in stale:
        return own
    return None if own in mapped_options else _owner_key(option)


def _class_relation_rows(targets: Iterable[tuple]) -> dict[tuple, list]:
    """Return the DHCP plugin rows that name each row key of *targets* in a many-to-many relation, by row key.

    A relation such as ``client_classes`` takes one query for all *targets*, whatever their number.
    """
    pks: dict[Any, list] = {}
    for model, pk in targets:
        pks.setdefault(model, []).append(pk)
    rows: dict[tuple, dict[tuple, Any]] = {}
    for model in apps.get_app_config(PLUGIN_APP_LABEL).get_models():
        for relation in model._meta.many_to_many:
            if relation.related_model in pks:
                named: Any = model.objects.filter(**{f"{relation.name}__in": pks[relation.related_model]})
                for row in named.annotate(named_pk=F(relation.name)):
                    rows.setdefault((relation.related_model, row.named_pk), {})[_row_key(row)] = row
    return {key: list(each.values()) for key, each in rows.items()}


@dataclass(frozen=True)
class _RemovalPlan:
    """The read-only plan of the delete of one stale row, with its evidence as row keys."""

    # The Options to delete before the row: each uses a definition that the delete removes, and it or its owner goes.
    options_first: tuple = ()
    # The other stale rows that the delete removes.
    cascaded: frozenset = frozenset()
    # The other stale rows that must go too, or the delete would remove or change a kept row: the rows that it
    # removes, the rows that name it in a class relation, and the stale Options, or the owners, that go with it.
    relies_on: frozenset = frozenset()
    # Why the row stays whatever else the run removes, for its entry. Empty when only kept stale rows can block it.
    blocked: str = ""


def _removal_plan(target, stale: dict, mapped_options: frozenset[tuple], named_by: dict[tuple, list]) -> _RemovalPlan:
    """Plan the delete of the stale row *target* against every *stale* row of the run. It writes nothing.

    A row outside *stale* is kept: when the delete would remove it, when it uses a row that the delete removes, or when
    it names the row in a many-to-many relation (without it, that row would reach more clients), the row stays. Each
    stale row with such a part is evidence in ``relies_on``. A stale Option goes alone, and an unmapped Option goes with
    the object that it is assigned to. A mapped Option of *mapped_options* outside *stale* is kept. *named_by* gives the
    rows that name each stale row in a many-to-many relation.
    """
    Option = plugin_model("Option")
    own = _row_key(target)
    first: dict[int, Any] = {}
    while True:
        collector = _FootprintCollector(target._state.db, frozenset(first))
        try:
            collector.collect([target])
            break
        except ProtectedError as error:
            removed = {own, *(_row_key(obj) for obj in _collected(collector)), *stale}
            protected = list(error.protected_objects)
            going = [
                obj
                for obj in protected
                if isinstance(obj, Option) and _option_goes_with(obj, stale, mapped_options) in removed
            ]
            if len(going) < len(protected):
                users = [obj for obj in protected if obj not in going]
                return _RemovalPlan(blocked=f"It is kept while it is in use by {_counted_rows(users)}.")
            first.update((obj.pk, obj) for obj in going)
    rows = _collected(collector)
    footprint = {own, *(_row_key(obj) for obj in rows)}
    # Counts only: any viewer of the Server reads the run, without permission on the rows.
    kept = [
        obj
        for obj in rows
        if _row_key(obj) not in stale
        and _row_key(obj) != own
        and (_row_key(obj) in mapped_options or not _goes_with_parent(obj._meta.concrete_model))
    ]
    if kept:
        return _RemovalPlan(blocked=f"It is kept because its removal would also remove {_counted_rows(kept)}.")
    cascaded = frozenset(_row_key(obj) for obj in rows if _row_key(obj) != own and _row_key(obj) in stale)
    relies_on = {*cascaded, *(_option_goes_with(obj, stale, mapped_options) for obj in first.values())}
    users = []
    for obj in named_by.get(own, ()):
        goes_with = _option_goes_with(obj, stale, mapped_options) if isinstance(obj, Option) else _row_key(obj)
        if goes_with is not None and (goes_with in stale or goes_with in footprint):
            relies_on.add(goes_with)
        else:
            users.append(obj)
    if users:
        return _RemovalPlan(blocked=f"It is kept while a class list of {_counted_rows(users)} names it.")
    return _RemovalPlan(tuple(first.values()), cascaded, frozenset(relies_on & stale.keys() - {own}))


def _keep_dependents(start: tuple, dependents: dict, alive: set, kept: dict, detail: str) -> list[tuple]:
    """Keep every row of *alive* that relies on the row *start*, directly or through other rows, with *detail*.

    Return the rows that it kept, in the order that it found them.
    """
    found: list[tuple] = []
    work = [start]
    while work:
        for key in dependents.get(work.pop(), ()):
            if key in alive:
                alive.discard(key)
                kept[key] = detail
                found.append(key)
                work.append(key)
    return found


def _dependents(plans: dict[tuple, _RemovalPlan]) -> dict[tuple, set[tuple]]:
    """Return the rows whose plan relies on each row: the reverse index of ``relies_on``."""
    index: dict[tuple, set[tuple]] = {}
    for key, plan in plans.items():
        for each in plan.relies_on:
            index.setdefault(each, set()).add(key)
    return index


def _relied_on_detail(row: _StaleRow, what: str) -> str:
    return f"It is kept because its removal relies on the removal of {_counted_rows([row.target])}, which {what}."


def _removal_set(
    stale: dict[tuple, _StaleRow], mapped_options: frozenset[tuple]
) -> tuple[dict[tuple, _RemovalPlan], dict[tuple, str]]:
    """Return the largest subset of stale rows whose deletion removes or changes no kept row.

    Return the plan of each row of that subset, and why each other stale row stays. Each plan is read once; a row that
    stays keeps every row that relies on it, through the reverse index.
    """
    named_by = _class_relation_rows(stale)
    plans = {key: _removal_plan(row.target, stale, mapped_options, named_by) for key, row in stale.items()}
    kept = {key: plan.blocked for key, plan in plans.items() if plan.blocked}
    alive = set(plans) - kept.keys()
    dependents = _dependents(plans)
    for key in list(kept):
        _keep_dependents(key, dependents, alive, kept, _relied_on_detail(stale[key], "is kept"))
    return {key: plan for key, plan in plans.items() if key in alive}, kept


def _components(plans: dict[tuple, _RemovalPlan]) -> list[list[tuple]]:
    """Return the strongly connected components of the ``relies_on`` graph, each after every component it relies on.

    Rows that rely on each other form one component. Tarjan's algorithm, without recursion, gives the components in
    this order. The rows and edges follow the order of *plans*, so the result does not change between runs.
    """
    order = {key: position for position, key in enumerate(plans)}

    def edges(key: tuple):
        return iter(sorted(plans[key].relies_on & plans.keys(), key=order.__getitem__))

    index: dict[tuple, int] = {}
    low: dict[tuple, int] = {}
    stack: list[tuple] = []
    on_stack: set[tuple] = set()
    components: list[list[tuple]] = []

    def visit(key: tuple) -> None:
        index[key] = low[key] = len(index)
        stack.append(key)
        on_stack.add(key)

    for root in plans:
        if root in index:
            continue
        visit(root)
        work = [(root, edges(root))]
        while work:
            key, successors = work[-1]
            for successor in successors:
                if successor not in index:
                    visit(successor)
                    work.append((successor, edges(successor)))
                    break
                if successor in on_stack:
                    low[key] = min(low[key], index[successor])
            else:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[key])
                if low[key] == index[key]:
                    component = []
                    while (member := stack.pop()) != key:
                        on_stack.discard(member)
                        component.append(member)
                    on_stack.discard(key)
                    components.append(sorted([*component, key], key=order.__getitem__))
    return components


def _delete_component(
    keys: list[tuple], plans: dict, removable: dict, removed: set, family: int, summary: ImportSummary
) -> tuple[list[tuple], tuple | None]:
    """Delete the rows of one component in one transaction, all or nothing, through the ORM.

    The ORM delete runs the guards, the mapping cleanup and the change log. Return the rows that the component
    removed, and ``None``; or no rows and the row whose delete failed, which has a write-failed entry.
    """
    gone: list[tuple] = []
    current = keys[0]
    try:
        with event_scope.atomic():
            for current in keys:
                if current in removed or current in gone:
                    continue
                plan = plans[current]
                # An Option that the delete of its own owner already removed is gone.
                for option in plugin_model("Option").objects.filter(
                    pk__in=[option.pk for option in plan.options_first]
                ):
                    option.delete()
                removable[current].target.delete()
                gone += [current, *(each for each in plan.cascaded if each not in removed and each not in gone)]
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001 (one failed removal must not abort the import)
        source = removable[current].source
        summary.record(FAILED.entry(family, source.kind, source.path(family)))
        summary.warn(f"stale {source.kind.value} {source.path(family)}: {exc}")
        return [], current
    return gone, None


@dataclass(frozen=True)
class KeptRow:
    """A stale row that the run keeps, and why, in counts only: a viewer of the Server may not view the rows."""

    # A DHCP plugin model instance; the plugin is optional, so its models have no static type here.
    target: Any
    reason: str


@dataclass(frozen=True)
class KindJudgment:
    """How one read judges the mapped rows of one kind, each by its Kea source."""

    # The rows whose source the read reports.
    observed: dict[MappingSource, Any]
    # The stale rows that the run removes.
    removable: dict[MappingSource, Any]
    # The stale rows that the run keeps, because a row that it keeps uses them.
    kept: dict[MappingSource, KeptRow]
    # The unobserved rows that a gap of the observation covers, and the gaps.
    not_judged: dict[MappingSource, Any]
    gaps: tuple[str, ...]
    # The unobserved rows that the read cannot judge: confirmed at or after the cutoff, or every one without a cutoff.
    newer: dict[MappingSource, Any]


@dataclass(frozen=True)
class StaleJudgment:
    """The judgment of every mapped row of one family against one read, and the read-only plan of its removal."""

    kinds: dict[Kind, KindJudgment]
    # Each stale row by row key, children first: the order of the removal.
    stale: dict[tuple, _StaleRow]
    # The delete plan of each removable row, by row key.
    plans: dict[tuple, _RemovalPlan]
    # Why each kept row stays, by row key, in the order that the removal plan found it.
    staying: dict[tuple, str]


def stale_judgment(server, plan: FamilyPlan, observed: Mapping[Kind, KindObservation]) -> StaleJudgment:
    """Judge each mapped row of the family of *plan* against the read that *observed* gives. It writes nothing.

    A mapping confirmed with a number at or above the cutoff of the plan belongs to a newer read, so it is never stale
    here. The import lock keeps two runs of one Server apart; the cutoff covers the other writers, such as an ADR 0008
    merge or revert replay in main. A plan without a cutoff can judge no unobserved mapping. :func:`_removal_set` then
    finds the stale rows whose deletion removes or changes no kept row, and no mapped Option that the run keeps.
    """
    family = plan.family
    judged: dict[Kind, dict[MappingSource, Any]] = {kind: {} for kind in mapped_kinds(family)}
    newer: dict[Kind, dict[MappingSource, Any]] = {kind: {} for kind in mapped_kinds(family)}
    for source, link in mapped_links(server, family):
        unordered = plan.cutoff is None or link.confirmation >= plan.cutoff
        rows = newer if unordered and source not in observed[source.kind].sources else judged
        rows[source.kind][source] = link.sys4_object
    splits = {kind: observed[kind].judge(rows, family) for kind, rows in judged.items()}
    stale = {_row_key(row): _StaleRow(source, row) for split in splits.values() for source, row in split.stale.items()}
    plans, staying = _removal_set(stale, mapped_option_keys())
    kinds = {
        kind: KindJudgment(
            observed=split.observed,
            removable={source: row for source, row in split.stale.items() if _row_key(row) in plans},
            kept={
                source: KeptRow(row, staying[_row_key(row)])
                for source, row in split.stale.items()
                if _row_key(row) in staying
            },
            not_judged=split.not_judged,
            gaps=split.gaps,
            newer=newer[kind],
        )
        for kind, split in splits.items()
    }
    return StaleJudgment(kinds, stale, plans, staying)


def remove_stale_objects(judgment: StaleJudgment, family: int, summary: ImportSummary) -> set[MappingSource]:
    """Remove each removable Stale DHCP Import Object of *judgment*, children first, report it, and return its source.

    Each kind with rows that its Incomplete observation cannot judge has one entry that says why, and each kept stale
    row has its own. Rows that rely on each other form one component, which goes in one transaction, all or nothing,
    after every component that it relies on. When a component fails, every pending row that relies on it, directly or
    through other rows, is kept too. IPAM objects stay: the DHCP plugin rows only reference them.
    """
    for kind, judged in judgment.kinds.items():
        if judged.not_judged:
            label = KIND_LABELS[kind]
            kept = counted(len(judged.not_judged), f"mapped {label} row was", f"mapped {label} rows were")
            detail = f"{' '.join(judged.gaps)} {kept} kept."
            summary.record(not_written(family, kind, kind_path(family, kind), Reason.INCOMPLETE_OBSERVATION, detail))
    removable, plans = judgment.stale, judgment.plans
    for key, detail in judgment.staying.items():
        _record_kept(removable[key], detail, family, summary)
    # A deleted instance has no pk, so every key comes from before the deletes.
    dependents = _dependents(plans)
    pending = set(plans)
    removed: set[tuple] = set()
    for component in _components(plans):
        if not pending.issuperset(component):
            # A failed component that it relies on keeps it.
            continue
        pending.difference_update(component)
        gone, failed = _delete_component(component, plans, removable, removed, family, summary)
        if failed is None:
            removed.update(gone)
            for source in (removable[each].source for each in gone):
                summary.record(written(family, source.kind, source.path(family), Outcome.REMOVED))
            continue
        together = _together_detail(removable[failed])
        for key in component:
            if key != failed:
                _record_kept(removable[key], together, family, summary)
        relied_on: dict[tuple, str] = {}
        for key in component:
            detail = _relied_on_detail(removable[key], "failed" if key == failed else "is kept")
            for each in _keep_dependents(key, dependents, pending, relied_on, detail):
                _record_kept(removable[each], detail, family, summary)
    return {removable[key].source for key in removed}


def _together_detail(row: _StaleRow) -> str:
    return f"It is kept because it is removed together with {_counted_rows([row.target])}, whose removal failed."


def _record_kept(row: _StaleRow, detail: str, family: int, summary: ImportSummary) -> None:
    summary.record(not_written(family, row.source.kind, row.source.path(family), Reason.REMOVAL_BLOCKED, detail))
