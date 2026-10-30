# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCP Import of one Server: read Kea for every enabled family, then plan and apply each family.

The read step is the only one that talks to Kea. :func:`.dhcp_plugin.import_server_config` builds the pure plan of
one family (:mod:`.dhcp_import_plan`) and applies it (:func:`.dhcp_plugin.apply_plan`), which writes NetBox and the
DHCP plugin and holds the mapping lock once per family. Each run then stores its result (:func:`store_run`).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from django.apps import apps
from django.db import DatabaseError, connection
from django.utils import timezone
from packaging.version import InvalidVersion, Version

from .. import event_scope, kea_paths, server_configuration
from ..constants import Family
from ..dhcp_mapping_lifecycle import ImportEventsNotDispatched, MetadataBusy
from ..ipam_reconciliation import complete_import_observation
from ..mappers.kea_to_dhcp import ServerConfigIntent, parse_dhcp_config
from ..read_failure import ReadFailure, attempt
from ..server_configuration import ServerConfigurationSnapshot
from . import dhcp_plugin
from .dhcp_import_report import ImportEntry, Kind, Reason, not_written

if TYPE_CHECKING:
    from netbox.plugins import PluginConfig

    from ..ipam_reconciliation import ReservationObservation
    from ..models import DhcpImportTrigger, Server
    from ..views.notices import Notice

logger = logging.getLogger(__name__)


def _int4(text: str) -> int:
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:4], "big", signed=True)


#: The first key of the two-key advisory lock that serializes the DHCP Imports of one Server; the Server is the second.
IMPORT_LOCK_CLASS = _int4("netbox_kea.dhcp_import")
_IMPORT_RUNNING = "Another DHCP Import of this Server is running. Nothing changed. Retry this operation."

#: The oldest netbox-plugin-dhcp release that the DHCP Import supports.
REQUIRED_PLUGIN_VERSION = "0.2.0"


class ImportRunning(MetadataBusy):
    """Another DHCP Import of the Server holds its import lock. The run read nothing and changed nothing."""


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
    from ..models import next_confirmation_number

    # Imported here: the views package imports this module.
    from ..views.notices import failed_load

    # Taken before config-get: a mapping or IPAM link confirmed after it belongs to a newer read.
    cutoff = next_confirmation_number()
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
    intent.cutoff = cutoff
    intent.host_reservation_identifiers = read.snapshot.host_reservation_identifiers
    return intent


def _read_reservation_observation(server: Server, version: Family) -> ReservationObservation | None:
    """Return the Reservation observation of the import, possibly incomplete, or ``None`` after a read failure."""
    from ..ipam_reconciliation import ReservationObservation
    from ..models import next_confirmation_number
    from ..subnet_catalogue import CatalogueUnavailable, for_synchronization

    cutoff = next_confirmation_number()
    try:
        catalogue = for_synchronization(server, version)
    except CatalogueUnavailable:
        logger.warning("DHCP-plugin sync: no complete Subnet Catalogue for %s (v%s)", server.name, version)
        return None
    snapshot = attempt(
        f"DHCP-plugin sync: the Reservation Snapshot of {server.name} (v{version})",
        lambda: server.get_client(version=version).reservation_snapshot(version, catalogue),
    )
    if isinstance(snapshot, ReadFailure):
        return None
    return ReservationObservation(snapshot, cutoff, catalogue)


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


@contextmanager
def _server_import_lock(server: Server) -> Iterator[None]:
    """Hold the import lock of *server* for one run, or refuse when another run holds it.

    A session lock, so the run holds no transaction open across its Kea reads.

    Raises:
        ImportRunning: Another session holds the lock.

    """
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", [IMPORT_LOCK_CLASS, server.pk])
        (taken,) = cursor.fetchone()
    if not taken:
        raise ImportRunning(_IMPORT_RUNNING)
    try:
        yield
    finally:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s, %s)", [IMPORT_LOCK_CLASS, server.pk])
                (released,) = cursor.fetchone()
        except DatabaseError:
            # A failed transaction refuses the unlock; ending the session releases the lock.
            logger.exception("DHCP-plugin sync: could not release the import lock of %s", server.name)
            connection.close()
        else:
            if not released:
                logger.error("DHCP-plugin sync: the import lock of %s was not held at release", server.name)


def run_dhcp_plugin_import(
    server: Server, trigger: DhcpImportTrigger
) -> list[tuple[Family, dhcp_plugin.ImportSummary | Notice]]:
    """Import every enabled version's live Kea config into the DHCP plugin, and store the result of the run.

    Returns ``(version, ImportSummary)`` for each version that was imported, and ``(version, Notice)`` for each
    version whose configuration Kea did not give. A version whose configuration could not be parsed is left out.
    The stored result has an entry for each of them.

    One run of a Server at a time: the run holds the import lock of the Server from before its first Kea read to the
    stored result, so the read of one run and the apply of another cannot interleave.

    Raises:
        UnsupportedPluginVersion: Before any Kea read, when the installed netbox-plugin-dhcp is too old.
        ImportRunning: Before any Kea read, when another run of the Server holds the lock.
        MetadataBusy: When the mapping coordination refuses the apply of a family, after its result is stored.

    """
    require_supported_plugin()
    with _server_import_lock(server):
        return _run_locked(server, trigger)


def _run_locked(server: Server, trigger: DhcpImportTrigger) -> list[tuple[Family, dhcp_plugin.ImportSummary | Notice]]:
    """Run the import of every enabled family of *server* while the run holds the import lock of the Server."""
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
