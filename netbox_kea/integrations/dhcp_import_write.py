# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one write protocol of each DHCP plugin row that the DHCP Import writes, except the DHCPServer.

:func:`write_row` writes one planned object through its :class:`RowAdapter`: in one atomic block it finds the row
through the DHCP Import Mapping of the key, or adopts an unmapped row, writes the managed fields and relations, and
observes the mapping. It records the entry of the object. When it does not write the object, it records an entry for
each descendant in the planned subtree of the object too, and returns why (:class:`NotWritten`). Only this module
decides how a failed write is reported (the failure table of :func:`write_row`). :func:`adopt_options` maps the
unmapped DHCP Options of one parent before any Option write. The DHCPServer is the root of a run, and its failure
ends the run, so ``upsert_dhcp_server`` and ``_apply_global_settings`` in :mod:`.dhcp_plugin` write it themselves.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol

from django.core.exceptions import ValidationError

from .. import event_scope
from ..dhcp_mapping_lifecycle import mapped_target, mark_options_mapped, observe_mapping
from .dhcp_import_fields import managed_fields
from .dhcp_import_report import REASON_OUTCOME, Capability, ImportEntry, Kind, Outcome, Reason, written

if TYPE_CHECKING:
    from ..models import Server
    from .dhcp_import_plan import MappingSource
    from .dhcp_plugin import ImportSummary
    from .dhcp_plugin_capabilities import PluginCapabilities

logger = logging.getLogger(__name__)


class ManagedFieldsMismatch(RuntimeError):
    """A writer's fields are not the managed fields of its model: a programming error that fails the run."""


@dataclass(frozen=True)
class NotWritten:
    """Why the run did not write one object: its reason, detail and capability.

    A result that *covers_subtree* (a taken Subnet ID) is also the result of each descendant of the object. Every
    other result gives a descendant the reason that its parent was not imported.
    """

    reason: Reason
    detail: str = ""
    capability: Capability | None = None
    covers_subtree: bool = False

    def entry(self, family: int, kind: Kind, path: str) -> ImportEntry:
        """Return the entry of the fact of *kind* at *path* that this result stops."""
        return ImportEntry(family, kind, path, REASON_OUTCOME[self.reason], self.reason, self.detail, self.capability)

    def descendant(self) -> NotWritten:
        """Return the result of a descendant of the object that was not written."""
        return self if self.covers_subtree else NotWritten(Reason.PARENT_NOT_IMPORTED)


#: The result of a write that failed for a reason that only the server log holds.
FAILED = NotWritten(Reason.WRITE_FAILED, "See server logs.")


@dataclass(frozen=True)
class WriteScope:
    """The Server, family, summary and DHCP plugin capabilities that every row write of one family shares."""

    server: Server
    family: int
    summary: ImportSummary
    capabilities: PluginCapabilities


class RowState(NamedTuple):
    """The name, the managed values and the managed relations of a DHCP plugin row: it tells an update from no change."""

    name: str
    values: tuple
    relations: Mapping[str, frozenset[int]]


@dataclass(frozen=True)
class LateOutcome:
    """A row whose created or updated entry its caller records: the row, and its state before the write.

    The state is ``None`` for a new row.
    """

    row: Any
    before: RowState | None


class RowKey(Protocol):
    """The key of a planned object: its kind, its mapping source and its Kea path."""

    @property
    def kind(self) -> Kind:
        """Return the kind of the object."""
        ...

    @property
    def source(self) -> MappingSource | None:
        """Return the mapping source of the object, or ``None``: a Pool that is not valid has none."""
        ...

    def path(self, family: int) -> str:
        """Return the Kea path of the object in *family*."""
        ...


class RowAdapter(Protocol):
    """How :func:`write_row` writes one planned object of one kind. Each kind is one small class.

    The adapter holds the context of the object, such as its parent row, the IPAM claims and the references, and
    the key of the planned object, which gives its mapping source and its Kea path. A kind overrides only the members
    whose default does not fit it.
    """

    scope: WriteScope
    key: RowKey
    #: The reason of a ValidationError of the write: a plugin gap when the plugin refuses a fact that Kea accepts.
    refused_reason: Reason = Reason.WRITE_FAILED
    #: The caller records the created or updated entry, after it writes more of the row (:class:`LateOutcome`).
    late_outcome: bool = False
    #: A step before the write changed the row (a Subnet that ``settle_subnet_ids`` renumbered).
    changed_before: bool = False

    def blocked(self) -> NotWritten | None:
        """Return why the run does not write the object at all, mapped or not, or ``None``."""
        return None

    def adopt(self) -> Any:
        """Return the unmapped row that the object takes over when its mapping finds no row, or ``None``."""
        return None

    def refusal(self) -> NotWritten | None:
        """Return why the run does not create the object when no row holds it, or ``None``."""
        return None

    def new_row(self) -> Any:
        """Return the new, unsaved row of the object."""
        ...

    def fields(self, row) -> dict:
        """Return the managed fields of *row*: exactly the scalar managed fields of its model."""
        ...

    def relations(self, row) -> dict[str, set[int]]:
        """Return the related rows of each managed many-to-many relation that the object sets."""
        return {}

    def adoption_fields(self, row) -> dict:
        """Return the fields outside the managed set that the adoption of *row* changes."""
        return {}

    def diagnostics(self, row) -> list[ImportEntry]:
        """Return the entries of the facts that the write of *row* keeps as they are, such as a taken name."""
        return []

    def descendants(self) -> Iterable[tuple[Kind, str]]:
        """Return the kind and the Kea path of each object in the planned subtree of the object."""
        return ()

    def state(self, row) -> RowState:
        """Return the state of the stored *row* before the write, for a late outcome (:func:`row_state`)."""
        return row_state(row, self.scope.capabilities)


def write_row(adapter: RowAdapter) -> Any:
    """Write the object of *adapter* and its mapping. Return the row, or why the run did not write it.

    With a late outcome, return a :class:`LateOutcome` and record no created or updated entry. When the object is
    not written, each descendant in its planned subtree has an entry too. The failure table: an
    ``EventDispatchError`` or a ``ManagedFieldsMismatch`` fails the run; a ``ValidationError`` gives the messages of
    the plugin; any other error gives a write failure, and the server log holds it.
    """
    scope, key = adapter.scope, adapter.key
    path = key.path(scope.family)
    diagnostics: list[ImportEntry] = []
    outcome: Outcome | None = None
    before: RowState | None = None
    try:
        with event_scope.atomic():
            result = adapter.blocked()
            if result is None:
                row, adopted, result = _find(adapter)
            if result is None:
                created = row is None
                if created:
                    row = adapter.new_row()
                elif adapter.late_outcome:
                    before = adapter.state(row)
                extra = adapter.adoption_fields(row) if adopted else {}
                outcome = _write_child(row, created, adapter, extra, before.relations if before is not None else None)
                observe_mapping(scope.server, scope.family, row, _source(key))
                diagnostics = adapter.diagnostics(row)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except ValidationError as error:
        result = NotWritten(adapter.refused_reason, f"The DHCP plugin refuses it: {' '.join(error.messages)}")
    except Exception as error:  # noqa: BLE001 (one bad object must not abort the import)
        scope.summary.warn(f"{path}: {type(error).__name__}: {error}", error)
        _skip(adapter, path, FAILED)
        return FAILED
    if result is not None:
        scope.summary.warn(f"{path}: {result.detail}")
        _skip(adapter, path, result)
        return result
    for entry in diagnostics:
        scope.summary.record(entry)
        scope.summary.warn(f"{entry.path}: {entry.detail}")
    if adapter.late_outcome:
        return LateOutcome(row, before)
    if outcome is None and adapter.changed_before:
        outcome = Outcome.UPDATED
    if outcome is not None:
        scope.summary.record(written(scope.family, key.kind, path, outcome))
    return row


def _source(key: RowKey) -> MappingSource:
    """Return the mapping source of *key*. Only an object with a mapping source can be written."""
    if key.source is None:
        raise ValueError("A planned object without a mapping source has no row to write.")
    return key.source


def _find(adapter: RowAdapter) -> tuple[Any, bool, NotWritten | None]:
    """Return the row of the object, whether the object adopts it, and why a new row is refused (``None``: it is not)."""
    scope = adapter.scope
    row = mapped_target(scope.server, scope.family, _source(adapter.key))
    if row is not None:
        return row, False, None
    row = adapter.adopt()
    if row is not None:
        return row, True, None
    return None, False, adapter.refusal()


def _skip(adapter: RowAdapter, path: str, result: NotWritten) -> None:
    """Record the entry of the object that the run did not write, and an entry for each object of its subtree."""
    family, summary = adapter.scope.family, adapter.scope.summary
    summary.record(result.entry(family, adapter.key.kind, path))
    descendant = result.descendant()
    for kind, descendant_path in adapter.descendants():
        summary.record(descendant.entry(family, kind, descendant_path))


def adopt_options(
    scope: WriteScope, parent: MappingSource, adopted: Iterable[tuple[Any, MappingSource]], *, mapped: bool
) -> None:
    """Map each unmapped DHCP Option of the object of *parent* that a planned Option adopts, before any Option write.

    With *mapped*, also record that the Options of the object are mapped. One atomic block holds both, so an
    adopted Option stays mapped when its own write fails.
    """
    with event_scope.atomic():
        for row, source in adopted:
            observe_mapping(scope.server, scope.family, row, source)
        if mapped:
            mark_options_mapped(scope.server, scope.family, parent)


def _write_child(
    row, created: bool, adapter: RowAdapter, extra: dict, current: Mapping[str, frozenset[int]] | None
) -> Outcome | None:
    """Write the managed fields, the *extra* fields and the relations of a DHCP plugin *row*. Return its outcome.

    *current* holds the related rows that the caller already read. The outcome is ``None`` for a row that did not
    change. With a late outcome the caller writes more of the row, so an existing row takes its change-log snapshot
    also when this write changes nothing.
    """
    capabilities = adapter.scope.capabilities
    fields = adapter.fields(row)
    relations = _relation_changes(row, adapter.relations(row), current)
    changes: dict = {}
    if created:
        _create_row(row, fields, capabilities)
    elif changes := {
        **_managed_changes(row, fields, capabilities),
        **{name: value for name, value in extra.items() if getattr(row, name) != value},
    }:
        _save_changes(row, changes)
    elif relations or adapter.late_outcome:
        row.snapshot()
    for name, pks in relations.items():
        getattr(row, name).set(pks)
    if created:
        return Outcome.CREATED
    return Outcome.UPDATED if changes or relations else None


def row_state(row, capabilities: PluginCapabilities, relations: Mapping[str, frozenset[int]] | None = None) -> RowState:
    """Return the state of a DHCP plugin *row*: its name, its managed values and its managed relations.

    *relations* gives the related rows of each managed relation that a caller read already, for example for many rows
    at once; without it, each relation is read here.
    """
    managed = managed_fields(type(row).__name__, capabilities)
    scalars = tuple(getattr(row, row._meta.get_field(field.name).attname) for field in managed if not field.relation)
    if relations is None:
        relations = {
            field.name: frozenset(getattr(row, field.name).values_list("pk", flat=True))
            for field in managed
            if field.relation
        }
    return RowState(row.name, scalars, relations)


def _managed_changes(obj, desired: dict, capabilities: PluginCapabilities) -> dict:
    """Return the managed fields of obj whose value differs from desired.

    *desired* must name each scalar managed field of the model that the installed plugin has, by field name or by
    the column name of a foreign key. Relations are not checked here.
    """
    model = type(obj).__name__
    named = {obj._meta.get_field(key).name for key in desired}
    expected = {field.name for field in managed_fields(model, capabilities) if not field.relation}
    if named != expected or len(named) != len(desired):
        raise ManagedFieldsMismatch(
            f"The {model} write does not match its managed fields: "
            f"missing {sorted(expected - named)}, unexpected {sorted(named - expected)}"
        )
    return {key: value for key, value in desired.items() if getattr(obj, key) != value}


def _create_row(obj, desired: dict, capabilities: PluginCapabilities) -> None:
    """Set the managed fields of the new row *obj* to *desired* and save it."""
    for name, value in _managed_changes(obj, desired, capabilities).items():
        setattr(obj, name, value)
    obj.save()


def _save_changes(obj, changes: dict) -> None:
    """Write *changes* to the loaded row *obj* after its change-log snapshot."""
    obj.snapshot()
    for name, value in changes.items():
        setattr(obj, name, value)
    obj.save()


def _relation_changes(
    obj, desired: dict[str, set[int]], current: Mapping[str, frozenset[int]] | None = None
) -> dict[str, set[int]]:
    """Return the many-to-many relations of *obj* whose rows differ from *desired*. A new row has no rows yet.

    *current* holds the related rows that the caller already read; without it, each relation is read here.
    """
    if obj.pk is None:
        return {name: pks for name, pks in desired.items() if pks}
    if current is None:
        current = {name: frozenset(getattr(obj, name).values_list("pk", flat=True)) for name in desired}
    return {name: pks for name, pks in desired.items() if current[name] != pks}
