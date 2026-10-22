# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Views for the optional "Sync to DHCP plugin" integration: the import, its latest run, and the drift card.

These are inert unless ``dhcp_plugin.runs_for`` allows the integration for the server:
the per-server tab hides itself, the page and the drift card read no Kea and show why, and the sync action
refuses. The drift card reads Kea as the import does, and changes nothing.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from django.contrib import messages
from django.db.models import Count
from django.http import HttpRequest, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views import View
from netbox.views import generic
from utilities.views import register_model_view

from ..constants import Family
from ..dhcp_mapping_lifecycle import ImportEventsNotDispatched, MetadataBusy
from ..integrations import dhcp_plugin
from ..integrations.dhcp_import import (
    FamilyRead,
    UnsupportedPluginVersion,
    enabled_versions,
    read_family,
    run_dhcp_plugin_import,
)
from ..integrations.dhcp_import_plan import MappingSource, mapped_kinds, observations, plan_family
from ..integrations.dhcp_import_report import KIND_LABELS, OUTCOME_LABELS, Kind, Outcome
from ..models import DhcpImportTrigger, Server
from ..sync_permissions import sync_gate
from ..tables import DhcpImportEntryTable
from .notices import Notice
from .workspace import server_family_url

logger = logging.getLogger(__name__)


def sync_nav_context(
    request: HttpRequest, server: Server, view: object, subsection: str, *, integration_runs: bool
) -> dict[str, Any]:
    """Return the Sync subsections, IPAM and DHCP Plugin, or none when the integration does not run for *server*."""
    if not integration_runs:
        return {"sync_subsections": []}
    return {
        "sync_subsections": [
            (key, label, server_family_url(request, server, view, name), key == subsection)
            for key, label, name in (
                ("ipam", "IPAM", "server_sync_status"),
                ("dhcp_plugin", "DHCP Plugin", "server_dhcp_plugin"),
            )
        ]
    }


def _summary_problems(summary) -> list[str]:
    """Return one note per non-zero problem count in *summary*.

    Every note is reported together: an if/elif chain hid the later counts whenever
    an earlier one was set, so one import could look cleaner than it was.
    """
    problems = []
    if summary.reservations_unread:
        problems.append(
            "The Reservation Snapshot could not be read in full. "
            "Check Snapshot diagnostics and logs for read or validation errors. Reservation counts may be incomplete."
        )
    if summary.reservations_quarantined:
        problems.append(f"{summary.reservations_quarantined} malformed reservation(s) were quarantined.")
    if summary.reservations_skipped:
        problems.append(f"{summary.reservations_skipped} reservation(s) were skipped after they were read.")
    if summary.foreign_addresses_skipped:
        problems.append(
            f"{summary.foreign_addresses_skipped} manually curated NetBox IP(s) were left unchanged. "
            "Use the per-reservation Sync to claim one."
        )
    if summary.owner_disagreements:
        problems.append(f"{summary.owner_disagreements} IPAM owner disagreement(s) left the shared objects unchanged.")
    if summary.addresses_unattached:
        problems.append(
            f"{summary.addresses_unattached} reserved address(es) were not attached because no NetBox IP "
            "holds them. A Global Reservation has no Subnet to size an address from."
        )
    if summary.errors:
        problems.append(f"{summary.errors} errors occurred. See the logs.")
    return problems


def _summary_text(version: int, summary) -> str:
    """Return the counts of one family's import, with a note for each other non-zero count."""
    text = (
        f"DHCPv{version}: {summary.subnets_created} subnets created, "
        f"{summary.subnets_updated} updated, {summary.pools_created} pools, "
        f"{summary.reservations_created} reservations created, "
        f"{summary.reservations_updated} updated, "
        f"{summary.options_created} options created, {summary.options_updated} updated, "
        f"{summary.client_classes_created} client classes created, "
        f"{summary.client_classes_updated} updated, "
        f"{summary.shared_networks_created} shared networks created, "
        f"{summary.shared_networks_updated} updated, "
        f"{summary.removed} stale objects removed"
    )
    notes = []
    if summary.option_defs_created:
        notes.append(f"{summary.option_defs_created} custom option definition(s) created")
    if summary.pd_pools_created:
        notes.append(f"{summary.pd_pools_created} delegated-prefix Pool(s) created")
    if summary.options_skipped:
        notes.append(f"{summary.options_skipped} option(s) skipped (unresolved/invalid)")
    if summary.shared_networks_unsupported:
        notes.append(f"{summary.shared_networks_unsupported} Shared Network(s) unsupported; see Latest run")
    return f"{text} ({'; '.join(notes)})" if notes else text


_SHOWN_OBJECTS = 50


class DriftState(str, Enum):
    """How one object of the drift card stands between live Kea and its DHCP Import Mapping."""

    # Kea has the object, and no mapping names it.
    MISSING = "missing"
    # A Complete observation no longer reports the mapped row, so the next run removes it.
    STALE = "stale"
    # An Incomplete observation did not report the mapped row, so it cannot judge it.
    UNSEEN = "unseen"
    # Kea was not read for the family.
    UNKNOWN = "unknown"


# The badge text and colour of each state.
_STATE_BADGES: dict[DriftState, tuple[str, str]] = {
    DriftState.MISSING: ("Missing", "info"),
    DriftState.STALE: ("Stale", "warning"),
    DriftState.UNSEEN: ("Not seen", "secondary"),
    DriftState.UNKNOWN: ("Unknown", "secondary"),
}


@dataclass(frozen=True)
class DriftObject:
    """One object that live Kea and the DHCP Import Mappings disagree on, or that the read cannot judge."""

    kind: Kind
    path: str
    state: DriftState
    # The mapped DHCP plugin row; a missing object has none. The plugin is optional, so its models have no type here.
    target: Any = None

    @property
    def label(self) -> str:
        """Return the label of the kind."""
        return KIND_LABELS[self.kind]

    @property
    def badge(self) -> tuple[str, str]:
        """Return the badge text and colour of the state."""
        return _STATE_BADGES[self.state]


@dataclass(frozen=True)
class KindDrift:
    """The counts of one mapped kind of one family, and why its observation is Incomplete ("" when Complete)."""

    kind: Kind
    in_step: int
    missing: int
    stale: int
    unseen: int
    incomplete: str

    @property
    def label(self) -> str:
        """Return the label of the kind."""
        return KIND_LABELS[self.kind]


@dataclass
class FamilyDrift:
    """The drift of one family: per-kind counts and the objects to show, or why Kea could not be read."""

    family: int
    kinds: list[KindDrift] = field(default_factory=list)
    objects: list[DriftObject] = field(default_factory=list)
    hidden: int = 0
    notice: Notice | None = None
    unparsable: bool = False

    def show(self, objects: list[DriftObject]) -> None:
        """Add *objects* until the family shows the shown number, and count the others as hidden."""
        room = max(_SHOWN_OBJECTS - len(self.objects), 0)
        self.objects.extend(objects[:room])
        self.hidden += max(len(objects) - room, 0)


def family_drift(server: Server, family: Family, user) -> FamilyDrift:
    """Compare a live read of *family* with its DHCP Import Mappings, through the rule that the removal uses.

    A missing object is in Kea without a mapping. A stale object has a mapping that a Complete observation no longer
    reports, so the next run removes it. An Incomplete observation cannot judge its unobserved rows, and a family that
    Kea did not give leaves every mapped row unknown. An object names its imported row only when *user* may view it.
    """
    mapped = dhcp_plugin.mapped_rows(server, family)
    drift = FamilyDrift(family)
    read = read_family(server, family)
    if not isinstance(read, FamilyRead):
        drift.notice, drift.unparsable = read, read is None
        for kind, rows in mapped.items():
            drift.show(_drift_objects(family, kind, rows, DriftState.UNKNOWN))
        drift.objects = _viewable_targets(drift.objects, user)
        return drift
    observed = observations(plan_family(read.config, read.reservations))
    for kind in mapped_kinds(family):
        observation, rows = observed[kind], mapped[kind]
        missing = dict.fromkeys(observation.sources - rows.keys())
        unobserved = {source: row for source, row in rows.items() if source not in observation.sources}
        state = DriftState.STALE if observation.complete else DriftState.UNSEEN
        drift.kinds.append(
            KindDrift(
                kind,
                in_step=len(rows) - len(unobserved),
                missing=len(missing),
                stale=len(unobserved) if observation.complete else 0,
                unseen=0 if observation.complete else len(unobserved),
                incomplete=observation.incomplete,
            )
        )
        drift.show(_drift_objects(family, kind, missing, DriftState.MISSING))
        drift.show(_drift_objects(family, kind, unobserved, state))
    drift.objects = _viewable_targets(drift.objects, user)
    return drift


# The relations that the name of a DHCP plugin row reads, by model.
_NAME_RELATIONS: dict[str, tuple[str, ...]] = {
    "optiondefinition": ("dhcp_server", "client_class"),
    "option": ("definition__dhcp_server", "definition__client_class"),
}


def _viewable_targets(objects: list[DriftObject], user) -> list[DriftObject]:
    """Keep the imported row of each object only when *user* may view it, loaded with what its name reads.

    One query for each model, so the card reads a fixed number of queries for any number of rows.
    """
    pks: dict[Any, set[int]] = defaultdict(set)
    for obj in objects:
        if obj.target is not None:
            pks[obj.target._meta.concrete_model].add(obj.target.pk)
    viewable = {}
    for model, selected in pks.items():
        queryset = model.objects.restrict(user, "view").filter(pk__in=selected)
        for row in queryset.select_related(*_NAME_RELATIONS.get(model._meta.model_name, ())):
            viewable[model, row.pk] = row
    return [
        replace(obj, target=viewable.get((obj.target._meta.concrete_model, obj.target.pk)))
        if obj.target is not None
        else obj
        for obj in objects
    ]


def _drift_objects(family: int, kind: Kind, rows: dict[MappingSource, Any], state: DriftState) -> list[DriftObject]:
    """Return one object of *state* for each source of *rows*, in Kea path order."""
    objects = [DriftObject(kind, source.path(family), state, row) for source, row in rows.items()]
    return sorted(objects, key=lambda obj: obj.path)


@register_model_view(Server, "dhcp_plugin")
class ServerDhcpPluginView(generic.ObjectView):
    """Sync subsection: the import, its latest run, and the drift card that htmx loads after the page."""

    workspace_section = "sync"
    queryset = Server.objects.all()
    template_name = "netbox_kea/server_dhcp_plugin.html"

    def get_extra_context(self, request, instance):
        """Return the import and latest-run context. The page reads no Kea: htmx loads the drift card after it."""
        refusal = dhcp_plugin.integration_refusal(instance)
        return {
            "integration_refusal": refusal,
            "mapping_unavailable": _mapping_unavailable() if not refusal else None,
            "sync_refusal": _sync_refusal(request.user, instance),
            **latest_run_context(request, instance),
            **sync_nav_context(request, instance, self, "dhcp_plugin", integration_runs=not refusal),
        }


def _mapping_unavailable() -> str | None:
    """Return why the active branch cannot read DHCP Import Mappings, or ``None`` when it can."""
    from ..dhcp_mapping_lifecycle import MappingUnavailable, require_branch_mappings

    try:
        require_branch_mappings()
    except MappingUnavailable as error:
        return str(error)
    return None


@register_model_view(Server, "dhcp_plugin_drift")
class ServerDhcpPluginDriftView(generic.ObjectView):
    """The drift card of the DHCP Plugin page: a live read of every enabled family against its mappings.

    htmx loads it after the page. Every refusal and every failed read is a 200 reply with a warning, because htmx
    swaps no error reply.
    """

    queryset = Server.objects.all()
    template_name = "netbox_kea/inc/dhcp_plugin_drift.html"

    def get_extra_context(self, request, instance):
        """Return the drift of each enabled family, or why the card cannot read it."""
        refusal = dhcp_plugin.integration_refusal(instance) or _mapping_unavailable()
        if refusal:
            return {"drift_refusal": refusal}
        return {"families": [family_drift(instance, family, request.user) for family in enabled_versions(instance)]}


def latest_run_context(request: HttpRequest, server: Server) -> dict[str, Any]:
    """Return the latest stored DHCP Import run of *server*, its counts per family and kind, and its entry table."""
    run = server.dhcp_import_runs.first()
    if run is None:
        return {"latest_run": None}
    counts: dict[tuple[int, str], dict[str, int]] = {}
    for row in run.entries.values("family", "kind", "outcome").annotate(total=Count("pk")):
        counts.setdefault((row["family"], row["kind"]), {})[row["outcome"]] = row["total"]
    count_rows = [
        {
            "family": family,
            "kind": KIND_LABELS[Kind(kind)],
            "counts": [by_outcome.get(outcome, 0) for outcome in Outcome],
        }
        for (family, kind), by_outcome in sorted(counts.items(), key=lambda item: (item[0][0], _KIND_ORDER[item[0][1]]))
    ]
    table = DhcpImportEntryTable(run.entries.all(), user=request.user)
    table.configure(request)
    return {
        "latest_run": run,
        "run_outcomes": list(OUTCOME_LABELS.values()),
        "run_count_rows": count_rows,
        "run_entry_table": table,
    }


_KIND_ORDER = {kind.value: index for index, kind in enumerate(KIND_LABELS)}


def _sync_refusal(user, server: Server) -> str:
    """Return why *user* may not run the import on *server*, or an empty string when the user may.

    The import needs change permission on the Server and the manual Sync rule for its IPAM, DCIM and DHCP plugin writes.
    """
    if not Server.objects.restrict(user, "change").filter(pk=server.pk).exists():
        return "Sync to DHCP plugin needs change permission on this Server."
    return sync_gate(user, dhcp_plugin.import_permissions(server)).reason


class ServerDhcpPluginSyncNowView(View):
    """POST-only: import this server's live Kea data-tier config into the DHCP plugin."""

    def post(self, request, pk):
        """Run the import and report a per-version summary."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        redirect = HttpResponseRedirect(reverse("plugins:netbox_kea:server_dhcp_plugin", args=[pk]))

        if refusal := dhcp_plugin.integration_refusal(server):
            messages.error(request, refusal)
            return redirect
        if refusal := _sync_refusal(request.user, server):
            return HttpResponseForbidden(refusal)

        try:
            results = run_dhcp_plugin_import(server, DhcpImportTrigger.MANUAL)
        except (MetadataBusy, UnsupportedPluginVersion) as error:
            messages.error(request, error.message)
            return redirect
        except ImportEventsNotDispatched:
            logger.exception("The events of the DHCP-plugin import for server %s could not be dispatched", server.name)
            messages.error(
                request,
                "The DHCP-plugin import saved its changes, but NetBox could not dispatch their events, "
                "and the import stopped. See the server logs.",
            )
            return redirect
        except Exception:
            # The import writes NetBox and DHCP plugin rows; a failure of any of them ends the import.
            logger.exception("DHCP-plugin import failed for server %s", server.name)
            messages.error(request, "An internal error occurred during the DHCP-plugin import.")
            return redirect

        if not results:
            messages.warning(request, "No Kea configuration could be imported. See server logs.")
            return redirect

        for version, summary in results:
            if isinstance(summary, Notice):
                for line in summary.lines:
                    messages.add_message(request, summary.level, f"DHCPv{version}: {line}")
                continue
            text = _summary_text(version, summary)
            problems = _summary_problems(summary)
            if problems:
                messages.warning(request, f"{text}. {' '.join(problems)}")
            else:
                messages.success(request, text + ".")
        return redirect
