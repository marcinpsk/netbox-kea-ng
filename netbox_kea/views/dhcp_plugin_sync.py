# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Views for the optional "Sync to DHCP plugin" integration (import + drift, v1).

These are inert unless ``dhcp_plugin.runs_for`` allows the integration for the server:
the per-server tab hides itself, the page reads no Kea and shows why, and the sync action
refuses.  All reads against Kea are read-only (``config-get``).
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib import messages
from django.db.models import Count
from django.http import HttpRequest, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views import View
from netbox.views import generic
from utilities.views import register_model_view

from ..dhcp_mapping_lifecycle import ImportEventsNotDispatched, MetadataBusy
from ..integrations import dhcp_plugin
from ..integrations.dhcp_import import (
    UnsupportedPluginVersion,
    _fetch_config_intent,
    enabled_versions,
    run_dhcp_plugin_import,
)
from ..integrations.dhcp_import_report import KIND_LABELS, OUTCOME_LABELS, Kind, Outcome
from ..mappers.kea_to_dhcp import ServerConfigIntent
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


def compute_drift(server: Server) -> dict:
    """Compare live Kea subnets against the imported DHCP-plugin records.

    Returns ``{"versions": [...], "kea_unreachable": bool}`` where each version
    entry lists subnet rows tagged ``imported`` (in both), ``new`` (in Kea, not
    yet imported), or ``orphaned`` (imported, no longer in Kea).
    """
    from ..dhcp_mapping_lifecycle import require_branch_mappings
    from ..models import KeaDhcpLink

    require_branch_mappings()

    versions = []
    kea_unreachable = False
    for version in enabled_versions(server):
        intent = _fetch_config_intent(server, version)
        links = {
            link.kea_subnet_id: link
            for link in KeaDhcpLink.objects.filter(server=server, family=version, kind=Kind.SUBNET.value)
        }
        rows = []
        # A failed read (a Notice) and a configuration that could not be parsed (None) both give no live rows.
        if not isinstance(intent, ServerConfigIntent):
            kea_unreachable = True
            # Without a live read we can still list what was imported before.
            for sid, link in sorted(links.items()):
                rows.append(
                    {
                        "kea_subnet_id": sid,
                        "cidr": _link_cidr(link),
                        "status": "unknown",
                        "pools": "—",
                        "reservations": "—",
                    }
                )
            versions.append({"version": version, "rows": rows, "live": False})
            continue

        live_ids = set()
        for subnet in intent.subnets:
            live_ids.add(subnet.kea_subnet_id)
            rows.append(
                {
                    "kea_subnet_id": subnet.kea_subnet_id,
                    "cidr": subnet.cidr,
                    "status": "imported" if subnet.kea_subnet_id in links else "new",
                    "pools": len(subnet.pools),
                    "reservations": "Not scanned",
                }
            )
        for sid, link in sorted(links.items()):
            if sid not in live_ids:
                rows.append(
                    {
                        "kea_subnet_id": sid,
                        "cidr": _link_cidr(link),
                        "status": "orphaned",
                        "pools": "—",
                        "reservations": "—",
                    }
                )
        versions.append({"version": version, "rows": rows, "live": True})

    return {"versions": versions, "kea_unreachable": kea_unreachable}


def _link_cidr(link) -> str:
    """Best-effort CIDR for a link's imported subnet (the DHCP-plugin prefix)."""
    obj = link.sys4_object
    prefix = getattr(obj, "prefix", None)
    return str(getattr(prefix, "prefix", "")) if prefix is not None else ""


@register_model_view(Server, "dhcp_plugin")
class ServerDhcpPluginView(generic.ObjectView):
    """Sync subsection: import status + drift between live Kea and DHCP-plugin records."""

    workspace_section = "sync"
    queryset = Server.objects.all()
    template_name = "netbox_kea/server_dhcp_plugin.html"

    def get_extra_context(self, request, instance):
        """Return drift context for the template (live, read-only Kea read). A refused integration reads no Kea."""
        from ..dhcp_mapping_lifecycle import MappingUnavailable

        refusal = dhcp_plugin.integration_refusal(instance)
        unavailable = None
        drift = None
        if not refusal:
            try:
                drift = compute_drift(instance)
            except MappingUnavailable as error:
                unavailable = str(error)
        return {
            "integration_refusal": refusal,
            "mapping_unavailable": unavailable,
            "drift": drift,
            "sync_refusal": _sync_refusal(request.user, instance),
            **latest_run_context(request, instance),
            **sync_nav_context(request, instance, self, "dhcp_plugin", integration_runs=not refusal),
        }


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
            text = (
                f"DHCPv{version}: {summary.subnets_created} subnets created, "
                f"{summary.subnets_updated} updated, {summary.pools_created} pools, "
                f"{summary.reservations_created} reservations created, "
                f"{summary.reservations_updated} updated, "
                f"{summary.options_created} options created, {summary.options_updated} updated, "
                f"{summary.client_classes_created} client classes created, "
                f"{summary.client_classes_updated} updated, "
                f"{summary.removed} stale objects removed"
            )
            notes = []
            if summary.option_defs_created:
                notes.append(f"{summary.option_defs_created} custom option definition(s) created")
            if summary.options_skipped:
                notes.append(f"{summary.options_skipped} option(s) skipped (unresolved/invalid)")
            if summary.shared_networks_not_imported:
                notes.append(
                    f"{summary.shared_networks_not_imported} Shared Network(s) not imported; "
                    "their Subnets were imported without them"
                )
            if notes:
                text += f" ({'; '.join(notes)})"
            problems = _summary_problems(summary)
            if problems:
                messages.warning(request, f"{text}. {' '.join(problems)}")
            else:
                messages.success(request, text + ".")
        return redirect
