# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCP Import of one Server: read Kea for every enabled family, then plan and apply each family.

The read step is the only one that talks to Kea. :func:`.dhcp_plugin.import_server_config` builds the pure plan of
one family (:mod:`.dhcp_import_plan`) and applies it (:func:`.dhcp_plugin.apply_plan`), which writes NetBox and the
DHCP plugin and holds the mapping lock once per family. Each run then stores its result (:func:`store_run`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

import requests
from django.apps import apps
from django.db import DatabaseError
from django.utils import timezone
from packaging.version import InvalidVersion, Version

from .. import event_scope, kea_paths, server_configuration
from ..constants import Family
from ..dhcp_mapping_lifecycle import ImportEventsNotDispatched
from ..ipam_reconciliation import complete_import_observation
from ..kea import KeaException
from ..mappers.kea_to_dhcp import ServerConfigIntent, parse_dhcp_config
from ..server_configuration import ServerConfigurationSnapshot
from . import dhcp_plugin
from .dhcp_import_report import ImportEntry, Kind, Reason, not_written

if TYPE_CHECKING:
    from netbox.plugins import PluginConfig

    from ..ipam_reconciliation import ReservationObservation
    from ..models import DhcpImportTrigger, Server
    from ..views.notices import Notice

logger = logging.getLogger(__name__)

#: The oldest netbox-plugin-dhcp release that the DHCP Import supports.
REQUIRED_PLUGIN_VERSION = "0.2.0"


class UnsupportedPluginVersion(Exception):
    """The installed netbox-plugin-dhcp is older than :data:`REQUIRED_PLUGIN_VERSION`."""

    def __init__(self, installed: str) -> None:
        self.message = (
            f"The DHCP Import needs netbox-plugin-dhcp {REQUIRED_PLUGIN_VERSION} or later. "
            f"The installed version is {installed}."
        )
        super().__init__(self.message)


def require_supported_plugin() -> None:
    """Raise :class:`UnsupportedPluginVersion` when the installed netbox-plugin-dhcp is too old or has no valid version."""
    plugin: PluginConfig = apps.get_app_config(dhcp_plugin.PLUGIN_APP_LABEL)
    installed = plugin.version
    try:
        supported = Version(installed) >= Version(REQUIRED_PLUGIN_VERSION)
    except (InvalidVersion, TypeError):
        supported = False
    if not supported:
        raise UnsupportedPluginVersion(str(installed))


def enabled_versions(server: Server) -> list[Family]:
    """Return the DHCP protocol versions enabled on *server* (4 and/or 6)."""
    versions: list[Family] = []
    if server.dhcp4:
        versions.append(4)
    if server.dhcp6:
        versions.append(6)
    return versions


def _fetch_config_intent(server: Server, version: Family) -> ServerConfigIntent | Notice | None:
    """Read live configuration for one version and parse it to intent (read-only).

    ``config-get`` is issued exactly once here. Reservations use their separate
    typed Snapshot read. Returns the :class:`ServerConfigIntent`, the Notice of a
    read that failed, or ``None`` when the configuration could not be parsed.
    """
    # Imported here: the views package imports this module.
    from ..views.notices import failed_load

    read = server_configuration.for_import(server, version)
    if isinstance(read, ServerConfigurationSnapshot):
        logger.warning("DHCP-plugin sync: config-get failed for %s (v%s)", server.name, version)
        return failed_load(read)
    try:
        intent = parse_dhcp_config(read.configuration, version)
    except (ValueError, RuntimeError):
        logger.warning(
            "DHCP-plugin sync: could not parse the configuration of %s (v%s)", server.name, version, exc_info=True
        )
        return None
    intent.configuration_complete = not read.snapshot.subnet_diagnostics
    intent.host_reservation_identifiers = read.snapshot.host_reservation_identifiers
    return intent


def _read_reservation_observation(server: Server, version: Family) -> ReservationObservation | None:
    """Return the Reservation observation of the import, possibly incomplete, or ``None`` after a read failure."""
    from ..ipam_reconciliation import ReservationObservation
    from ..models import next_confirmation_number
    from ..subnet_catalogue import for_synchronization

    cutoff = next_confirmation_number()
    try:
        client = server.get_client(version=version)
        catalogue = for_synchronization(server, version)
        return ReservationObservation(client.reservation_snapshot(version, catalogue), cutoff, catalogue)
    except (KeaException, requests.RequestException, RuntimeError, ValueError):
        logger.warning(
            "DHCP-plugin sync: Reservation Snapshot failed for %s (v%s)", server.name, version, exc_info=True
        )
        return None


@dataclass(frozen=True)
class FamilyRead:
    """What the read step observed for one family: the parsed configuration and the Reservation observation."""

    config: ServerConfigIntent
    reservations: ReservationObservation | None


def read_family(server: Server, version: Family) -> FamilyRead | Notice | None:
    """Read one family from Kea: a :class:`FamilyRead`, the Notice of a failed read, or ``None`` (unparsable)."""
    config = _fetch_config_intent(server, version)
    if not isinstance(config, ServerConfigIntent):
        return config
    return FamilyRead(config, _read_reservation_observation(server, version))


def run_dhcp_plugin_import(
    server: Server, trigger: DhcpImportTrigger
) -> list[tuple[Family, dhcp_plugin.ImportSummary | Notice]]:
    """Import every enabled version's live Kea config into the DHCP plugin, and store the result of the run.

    Returns ``(version, ImportSummary)`` for each version that was imported, and ``(version, Notice)`` for each
    version whose configuration Kea did not give. A version whose configuration could not be parsed is left out.
    The stored result has an entry for each of them.

    Raises:
        UnsupportedPluginVersion: Before any Kea read, when the installed netbox-plugin-dhcp is too old.

    """
    require_supported_plugin()
    started = timezone.now()
    results: list[tuple[Family, dhcp_plugin.ImportSummary | Notice]] = []
    entries: list[ImportEntry] = []
    reads = [(version, read_family(server, version)) for version in enabled_versions(server)]
    for version, read in reads:
        path = kea_paths.daemon(version)
        if isinstance(read, FamilyRead):
            try:
                summary = dhcp_plugin.import_server_config(server, read.config, read.reservations)
            except ImportEventsNotDispatched as error:
                # The family committed: its entries are true, only its events are lost.
                entries.extend(error.summary.entries)
                store_run(server, trigger, started, entries)
                raise
            except Exception:
                # The family wrote nothing, and the earlier families stay written, so the run keeps their entries.
                detail = "The import stopped before this family was written. See the message and the server logs."
                entries.append(not_written(version, Kind.SERVER, path, Reason.WRITE_FAILED, detail))
                store_run(server, trigger, started, entries)
                raise
            results.append((version, summary))
            entries.extend(summary.entries)
        elif read is None:
            detail = "The configuration could not be parsed."
            entries.append(not_written(version, Kind.SERVER, path, Reason.INVALID_KEA_DATA, detail))
        else:
            results.append((version, read))
            entries.append(not_written(version, Kind.SERVER, path, Reason.READ_FAILED, " ".join(read.lines)))
    try:
        complete_import_observation(
            server,
            {
                family: summary.ownership
                for family, summary in results
                if isinstance(summary, dhcp_plugin.ImportSummary)
            },
        )
    finally:
        # Every family has committed, so the run is stored even when the receipt fails.
        store_run(server, trigger, started, entries)
    return results


def store_run(server: Server, trigger: DhcpImportTrigger, started: datetime, entries: list[ImportEntry]) -> None:
    """Store the result of one run and delete the Server's runs beyond the retained ones.

    A database failure is logged and never raised: the import has already written NetBox.
    """
    from ..models import DhcpImportEntry, DhcpImportRun, Server

    try:
        with event_scope.atomic():
            # One run of a Server at a time from here, so two runs cannot both keep one run too many.
            list(Server.objects.select_for_update().filter(pk=server.pk).values_list("pk", flat=True))
            run = DhcpImportRun.objects.create(server=server, trigger=trigger, started=started, finished=timezone.now())
            DhcpImportEntry.objects.bulk_create(
                DhcpImportEntry(
                    run=run,
                    family=entry.family,
                    kind=entry.kind.value,
                    outcome=entry.outcome.value,
                    reason=entry.reason.value if entry.reason is not None else "",
                    capability=entry.capability.value if entry.capability is not None else "",
                    kea_path=entry.path,
                    detail=entry.detail,
                )
                for entry in entries
            )
            retained = DhcpImportRun.objects.filter(server=server)[: DhcpImportRun.RETAINED_RUNS]
            DhcpImportRun.objects.filter(server=server).exclude(pk__in=retained.values("pk")).delete()
    except DatabaseError:
        logger.exception("DHCP-plugin sync: the result of the run could not be stored for %s", server.name)
