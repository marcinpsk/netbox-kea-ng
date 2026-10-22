# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Background jobs for netbox-kea-ng plugin.

Registers periodic Kea→NetBox IPAM sync jobs using NetBox's built-in
``JobRunner`` / ``@system_job`` infrastructure so they run automatically via
``manage.py rqworker`` without any external scheduler.

The sync interval comes from ``SyncConfig.interval_minutes``, which the Settings
page edits. ``enqueue_once`` and each periodic run read it, so a saved value
applies after the next scheduled run.
"""

from __future__ import annotations

import logging
from contextvars import copy_context
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

from core import signals as core_signals
from core.exceptions import JobFailed
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.http import HttpRequest
from netbox.context_managers import event_tracking
from netbox.jobs import JobRunner, system_job

if TYPE_CHECKING:
    from .integrations.dhcp_plugin import ImportSummary
    from .models import Server

# Runtime imports: get_type_hints() resolves this module's annotations, so a
# TYPE_CHECKING-only Family or SyncReport would raise NameError.
from . import branching, event_scope
from .constants import Family
from .ipam_reconciliation import SyncReport, complete_job_observation, upgrade_counts

logger = logging.getLogger(__name__)

# NetBox requires a registry interval; enqueue_once replaces it with SyncConfig.interval_minutes.
_DEFAULT_INTERVAL = 5


#: How many conflicting IPs to name in the job summary and log line.  A bare count
#: tells an operator nothing about which manually-curated IPs the sync left alone.
_CONFLICT_SAMPLE_SIZE = 20
_SYNC_USER = "netbox-kea-sync"


def _failed_facts(summary: ImportSummary) -> int:
    """Return the facts of one family that the DHCP Import could not read or write, and its IPAM reconciliation errors.

    ``ImportSummary.errors`` leaves out failed reads and failed Option writes, so the job counts them here.
    """
    from .integrations.dhcp_import_report import Reason

    failed = (Reason.READ_FAILED, Reason.WRITE_FAILED)
    return sum(entry.reason in failed for entry in summary.entries) + summary.ownership_errors


class _SyncJobRequest(HttpRequest):
    """An empty worker request with NetBox's change-tracking request ID."""

    id: UUID


def _sync_one_server(
    server: Server,
    sync_leases: bool,
    sync_reservations: bool,
    sync_prefixes: bool,
    sync_ip_ranges: bool,
    max_leases: int,
) -> SyncReport:
    """Reconcile every enabled family and publish completion from the whole run."""
    from .ipam_reconciliation import (
        LeasePhase,
        LeasePrefixPhase,
        Phase,
        PoolPhase,
        ReservationPhase,
        SubnetPhase,
        lease_prefixes_enabled,
        read_catalogue,
        read_leases,
        reconcile,
    )

    combined = SyncReport()
    if not any((sync_leases, sync_reservations, sync_prefixes, sync_ip_ranges)):
        return combined
    reports: dict[Family, SyncReport] = {}
    versions: tuple[tuple[Family, bool], ...] = ((4, server.dhcp4), (6, server.dhcp6))
    for version, enabled in versions:
        if not enabled:
            continue

        observation = read_catalogue(server, version)
        catalogue = observation.catalogue
        if catalogue is None:
            logger.warning("Server %s (v%s): Subnet Catalogue unavailable", server.name, version)
        subnet_prefix_map = (
            {subnet.identity.subnet_id: subnet.identity.network.prefixlen for subnet in catalogue.subnets}
            if catalogue is not None
            else None
        )
        if catalogue is None and sync_leases:
            logger.info(
                "Server %s (v%s): Subnet Catalogue unavailable; lease masks fall back to NetBox prefix matching",
                server.name,
                version,
            )

        phases: list[Phase] = []
        leases = read_leases(server, version, max_leases or None) if sync_leases else None
        if leases is not None:
            phases.append(LeasePhase(leases, subnet_prefix_lengths=subnet_prefix_map))
        if sync_reservations:
            phases.append(ReservationPhase(catalogue=catalogue))
        if sync_prefixes:
            phases.append(SubnetPhase(observation))
        if sync_ip_ranges:
            phases.append(PoolPhase(observation))
        if leases is not None and lease_prefixes_enabled(version, sync_leases, sync_prefixes):
            phases.append(LeasePrefixPhase(leases, catalogue))
        reports[version] = reconcile(server, version, phases)
        combined.merge(reports[version])

    complete_job_observation(server, reports)

    if combined.disagreements:
        sample = sorted(combined.disagreements)[:_CONFLICT_SAMPLE_SIZE]
        logger.warning(
            "Server %s: %d NetBox IPAM object(s) keep their facts because their owners report different facts; first %d: %s",
            server.name,
            len(combined.disagreements),
            len(sample),
            ", ".join(sample),
        )
    if combined.unclassified:
        logger.warning(
            "Server %s: %d NetBox IP address(es) keep a stale DHCPv6 lease link of unknown allocation kind;"
            " a later Kea report of the address or of its delegated prefix classifies the link,"
            " and removing the sync marker releases it",
            server.name,
            combined.unclassified,
        )
    if combined.conflicts:
        sample = sorted(combined.conflicts)[:_CONFLICT_SAMPLE_SIZE]
        logger.warning(
            "Server %s: %d NetBox IPAM object(s) left untouched: the description does not start with the sync marker,"
            " or the new marker and the note do not fit; first %d: %s",
            server.name,
            len(combined.conflicts),
            len(sample),
            ", ".join(sample),
        )

    return combined


@system_job(interval=_DEFAULT_INTERVAL)
class KeaIpamSyncJob(JobRunner):
    """Periodic Kea→NetBox IPAM sync job.

    Iterates over all configured ``Server`` objects and syncs their active
    leases and/or reservations into NetBox ``IPAddress`` records.  Error on
    one server does not prevent syncing the remaining servers.  With the scheduled
    DHCP Import on, it first runs the DHCP Import of each Server that the integration
    runs for.

    The sync is idempotent: existing ``IPAddress`` objects are updated in place
    when their fields have changed; unchanged records are left untouched.
    """

    class Meta:
        name = "Kea IPAM Sync"

    def __init__(self, job: Any) -> None:
        """Use the same job logger on each supported native runner."""
        super().__init__(job)
        self.logger = logging.getLogger(f"netbox.jobs.{type(self).__name__}")
        self.logger.setLevel(logging.DEBUG)

    @classmethod
    def handle(cls, job: Any, *args: Any, **kwargs: Any) -> None:
        """Refresh the queued actor before native lifecycle writes can restore a deleted user."""
        job.refresh_from_db(fields=["user"])
        super().handle(job, *args, **kwargs)

    @classmethod
    def enqueue_once(
        cls, instance: Any = None, schedule_at: Any = None, interval: int | None = None, *args: Any, **kwargs: Any
    ) -> Any:
        """Heal ghost scheduled-job records before delegating to NetBox.

        NetBox schedules system jobs by calling ``enqueue_once`` on the job class
        once per ``rqworker`` startup (``core/management/commands/rqworker.py``).
        That runs after app initialisation and on the worker process only — so it
        is the correct place to reconcile stale schedule state, unlike
        ``AppConfig.ready()`` which also fires during ``collectstatic``/``migrate``
        (where the DB may be unreachable) and triggers Django's "database access
        during app initialization" warning.

        We clean ghost records first, then delegate to the stock
        ``enqueue_once`` so it can create a fresh schedule.  The signature is
        NetBox's, so a positional ``interval`` binds once; ``SyncConfig.interval_minutes``
        replaces it, and the other arguments are forwarded verbatim.
        """
        from .models import SyncConfig

        cls._heal_ghost_scheduled_jobs()
        return super().enqueue_once(instance, schedule_at, SyncConfig.get().interval_minutes, *args, **kwargs)

    @classmethod
    def _heal_ghost_scheduled_jobs(cls) -> None:
        """Remove ghost scheduled-job DB records that have no live RQ counterpart.

        A ghost record arises when a periodic job's execution fails at the DB level
        (e.g. PostgreSQL in recovery mode) — the DB record stays ``scheduled`` forever
        while RQ marks the job ``failed``.  NetBox's ``enqueue_once()`` trusts the DB
        status and skips re-scheduling, silently breaking the periodic chain.

        Deleting stale DB records here lets the immediately-following
        ``super().enqueue_once()`` call create a fresh schedule.

        Safe to call in all contexts:
        - Never enqueues jobs (the caller handles that).
        - All DB and Redis I/O is wrapped so a missing DB or a Redis still coming
          up at worker startup never breaks scheduling.
        """
        try:
            import django_rq
            from rq.exceptions import NoSuchJobError
            from rq.job import Job as RQJob

            candidates = cls.get_jobs(None).filter(status__in=("scheduled", "pending"))
            if not candidates.exists():
                return

            conn = django_rq.get_connection("default")
            _DEAD = {"failed", "canceled", "stopped"}

            deleted = 0
            for db_job in candidates:
                try:
                    job_id = str(db_job.job_id) if db_job.job_id else None
                    if job_id is None:
                        db_job.delete()
                        deleted += 1
                        continue
                    try:
                        rq_job = RQJob.fetch(job_id, connection=conn)
                        status = rq_job.get_status()
                        # Handle both enum (rq ≥ 1.16) and plain string
                        status_str = status.value if hasattr(status, "value") else str(status)
                        if status_str in _DEAD:
                            db_job.delete()
                            deleted += 1
                    except NoSuchJobError:
                        db_job.delete()
                        deleted += 1
                except Exception:
                    logger.debug(
                        "netbox_kea: skipping ghost-job check for record %r due to per-record error.",
                        getattr(db_job, "pk", None),
                        exc_info=True,
                    )

            if deleted:
                logger.warning(
                    "netbox_kea: removed %d ghost scheduled-job record(s) with a dead or missing "
                    "RQ counterpart. Periodic IPAM sync will resume now.",
                    deleted,
                )
        except Exception:
            logger.warning(
                "netbox_kea: ghost-job self-heal skipped (DB or Redis not available at scheduling time).",
                exc_info=True,
            )

    def _fail_in_branch(self) -> None:
        """Raise JobFailed when a branch is active in the worker: the job reads and writes main only."""
        if (branch := branching.active_branch()) is not None:
            # NetBox saves the error when it marks the job failed; the job itself writes nothing here.
            self.job.error = f"Branch {branch} is active in the worker. The Kea IPAM sync runs on main only."
            raise JobFailed(self.job.error)

    def run(self, *args: Any, **kwargs: Any) -> None:
        """Execute the sync across all servers. It fails before any read when a branch is active in the worker."""
        self._fail_in_branch()
        copy_context().run(self._run_tracked, *args, **kwargs)

    def _run_tracked(self, *args: Any, **kwargs: Any) -> None:
        """Track one execution without leaking native tracking state into the caller."""
        # Older supported NetBox releases have no delete suppression history.
        clear_history = getattr(core_signals, "clear_signal_history", None)
        if clear_history is not None:
            clear_history(sender=type(self))
        try:
            request = _SyncJobRequest()
            request.method = "POST"
            request.path = "/plugins/kea/sync-jobs/"
            request.user = self._change_actor()
            request.id = uuid4()
            with event_tracking(request):
                self._run_sync(*args, **kwargs)
        finally:
            if clear_history is not None:
                clear_history(sender=type(self))

    def _change_actor(self) -> Any:
        """Return the initiator, or reserve a disabled account for system attribution."""
        if self.job.user is not None:
            return self.job.user
        user_model: Any = get_user_model()
        actor, _ = user_model.objects.get_or_create(
            username__iexact=_SYNC_USER,
            defaults={
                "username": _SYNC_USER,
                "is_active": False,
                "is_superuser": False,
                "password": make_password(None),
            },
        )
        if (
            actor.username != _SYNC_USER
            or actor.is_active
            or actor.is_superuser
            or getattr(actor, "is_staff", False)
            or actor.has_usable_password()
            or actor.groups.exists()
            or actor.user_permissions.exists()
            or actor.object_permissions.exists()
        ):
            self.job.error = f"Reserved user {_SYNC_USER} must be inactive, without a usable password or permissions."
            raise JobFailed(self.job.error)
        return actor

    def _run_sync(self, *args: Any, **kwargs: Any) -> None:
        """Run the scheduled DHCP Import, then the IPAM sync; fail the job when either one failed."""
        from .models import SyncConfig

        if self.job.interval:
            # handle() schedules the successor with job.interval, also when a pass raises.
            self.job.interval = SyncConfig.get().interval_minutes
        server_pk = kwargs.get("server_pk")
        failed = False
        finished = False
        summary: list[dict] = []
        started: dict[int, str] = {}
        try:
            # A Run Now of one Server syncs its IPAM only: its trigger is not the schedule.
            if server_pk is None:
                # The stale DHCP plugin rows go first, so the IPAM cleanup no longer counts their objects as used.
                failed = self._run_scheduled_imports(started)
            failed = self._run_ipam_sync(server_pk, summary, started) or failed
            finished = True
        finally:
            # A pass raised: each Server that it left without an IPAM summary gets an entry without counts.
            synced = {entry["pk"] for entry in summary}
            unfinished = (
                [] if finished else [{"name": name, "pk": pk} for pk, name in started.items() if pk not in synced]
            )
            self._save_summary([*summary, *unfinished])
        if failed:
            raise JobFailed

    def _save_summary(self, summary: list[dict]) -> None:
        """Store the per-server summary, which attributes a periodic job to its Servers."""
        if not isinstance(self.job.data, dict):
            self.job.data = {}
        self.job.data["summary"] = summary
        try:
            self.job.save(update_fields=["data"])
        except Exception:
            logger.exception("Failed to persist sync job summary data")

    def _run_ipam_sync(self, server_pk: int | None, summary: list[dict], started: dict[int, str]) -> bool:
        """Apply the configured IPAM synchronization, add a summary entry per Server, and return whether it failed.

        *started* gets each Server before its sync starts.
        """
        from .models import Server, SyncConfig

        sync_cfg = SyncConfig.get()
        if not sync_cfg.sync_enabled:
            self.logger.info("Global sync kill-switch is active (SyncConfig.sync_enabled=False) — skipping.")
            return False

        sync_leases = sync_cfg.sync_leases_enabled
        sync_reservations = sync_cfg.sync_reservations_enabled
        sync_prefixes = sync_cfg.sync_prefixes_enabled
        sync_ip_ranges = sync_cfg.sync_ip_ranges_enabled
        max_leases = sync_cfg.sync_max_leases_per_server

        if not any([sync_leases, sync_reservations, sync_prefixes, sync_ip_ranges]):
            self.logger.info("All sync type flags are False — nothing to do.")
            return False

        server_qs = Server.objects.filter(pk=server_pk) if server_pk is not None else Server.objects.all()
        servers = list(server_qs)

        if not servers:
            self.logger.info("No Kea servers configured. Count unowned IPAM objects.")

        self.logger.info(f"Starting Kea IPAM sync for {len(servers)} server(s).")
        total = SyncReport()
        total_conflicts = 0
        total_disagreements = 0

        for server in servers:
            # In Run Now mode (server_pk provided), honour the explicit selection
            # and skip the per-server enabled check.
            if server_pk is None and not server.sync_enabled:
                self.logger.info(f"Server {server.name}: sync_enabled=False — skipping.")
                continue

            # Per-server type overrides: AND global flag with server flag.
            effective_leases = sync_leases and server.sync_leases_enabled
            effective_reservations = sync_reservations and server.sync_reservations_enabled
            effective_prefixes = sync_prefixes and server.sync_prefixes_enabled
            effective_ip_ranges = sync_ip_ranges and server.sync_ip_ranges_enabled

            self.logger.debug(f"Syncing server: {server.name} (pk={server.pk})")
            started[server.pk] = server.name
            report = SyncReport()

            try:
                report = _sync_one_server(
                    server,
                    effective_leases,
                    effective_reservations,
                    effective_prefixes,
                    effective_ip_ranges,
                    max_leases,
                )
            except event_scope.EventDispatchError:
                raise
            except Exception as exc:
                # The job log keeps only the message, so the traceback goes to the module logger.
                logger.exception("Unhandled error syncing server %s", server.name)
                self.logger.error(  # noqa: TRY400 - the module logger above has the traceback
                    f"Unhandled error syncing server {server.name}: {type(exc).__name__}: {exc};"
                    " the worker log has the traceback"
                )
                report.errors += 1

            self.logger.info(
                f"Server {server.name}: created={report.created}"
                f" updated={report.updated} errors={report.errors}"
                f" prefix_errors={report.prefix_errors}"
                f" conflicts={len(report.conflicts)}"
                f" disagreements={len(report.disagreements)}"
                f" skipped={len(report.skipped_reservations)}"
                f" waiting={report.waiting}"
                f" unclassified={report.unclassified}"
            )
            # No row pks here: the list URL applies the viewer's own IPAM permissions.
            for dup in report.duplicates:
                self.logger.error(
                    f"Server {server.name}: Kea {dup.kea_object} matches duplicate NetBox {dup.rows};"
                    f" the sync leaves them unchanged. Review them at {dup.list_url}"
                )
            total.merge(report)
            total_conflicts += len(report.conflicts)
            total_disagreements += len(report.disagreements)

            summary.append(
                {
                    "name": server.name,
                    "pk": server.pk,
                    "created": report.created,
                    "updated": report.updated,
                    "errors": report.errors,
                    "prefix_errors": report.prefix_errors,
                    "conflicts": len(report.conflicts),
                    "conflict_sample": sorted(report.conflicts)[:_CONFLICT_SAMPLE_SIZE],
                    "conflicts_truncated": max(0, len(report.conflicts) - _CONFLICT_SAMPLE_SIZE),
                    "disagreements": len(report.disagreements),
                    "skipped": len(report.skipped_reservations),
                    "waiting": report.waiting,
                    "unclassified": report.unclassified,
                }
            )

        counts = upgrade_counts()
        total.unowned_objects = counts.unowned_objects
        total.waiting_objects = counts.waiting_objects
        self.logger.info(
            f"Kea IPAM sync complete — servers={len(summary)}"
            f" created={total.created} updated={total.updated}"
            f" errors={total.errors} prefix_errors={total.prefix_errors}"
            f" conflicts={total_conflicts} disagreements={total_disagreements} skipped={len(total.skipped_reservations)}"
            f" unowned={total.unowned} waiting={total.waiting} unclassified={total.unclassified}"
        )
        return total.errors > 0 or total.prefix_errors > 0

    def _run_scheduled_imports(self, started: dict[int, str]) -> bool:
        """Run the DHCP Import of each Server that the integration runs for, when the setting is on.

        Return whether the import of a Server failed. A failure of one Server does not stop the others.
        *started* gets each Server before its import starts.
        """
        from .integrations import dhcp_plugin
        from .models import DhcpIntegrationConfig, Server

        switch = DhcpIntegrationConfig.get()
        if not switch.scheduled_import_enabled:
            return False
        servers = []
        for server in Server.objects.all():
            if refusal := dhcp_plugin.integration_refusal(server, switch):
                self.logger.info(f"Scheduled DHCP Import of Server {server.name} skipped: {refusal}")
            else:
                servers.append(server)
        failed = 0
        for server in servers:
            started[server.pk] = server.name
            failed += not self._import_one(server)
        self.logger.info(f"Scheduled DHCP Import complete: servers={len(servers)} failed={failed}")
        return failed > 0

    def _import_one(self, server: Server) -> bool:
        """Run the scheduled DHCP Import of *server*, log its result per family, and return whether it succeeded.

        The import stores its own result with the trigger "scheduled", also when it fails after its first read.
        """
        from .dhcp_mapping_lifecycle import MetadataBusy
        from .integrations.dhcp_import import (
            ImportRunning,
            UnsupportedPluginVersion,
            enabled_versions,
            run_dhcp_plugin_import,
        )
        from .integrations.dhcp_import_report import Outcome
        from .integrations.dhcp_plugin import ImportSummary
        from .models import DhcpImportTrigger

        run = f"Scheduled DHCP Import of Server {server.name}"
        # The type check sees a TextChoices member as its (value, label) tuple; at runtime it is the member.
        trigger = cast("DhcpImportTrigger", DhcpImportTrigger.SCHEDULED)
        try:
            results = run_dhcp_plugin_import(server, trigger)
        except ImportRunning as error:
            self.logger.warning(f"{run} skipped: {error.message}")
            return True
        except (MetadataBusy, UnsupportedPluginVersion) as error:
            self.logger.error(f"{run} failed: {error.message}")  # noqa: TRY400 - a typed refusal, no traceback
            return False
        except event_scope.EventDispatchError:
            self.logger.error(  # noqa: TRY400 - NetBox records the traceback of the raised error
                f"{run} saved its changes, but NetBox could not dispatch their events. The job stops."
            )
            raise
        except Exception as exc:
            # The job log keeps only the message, so the traceback goes to the module logger.
            logger.exception("Scheduled DHCP Import failed for server %s", server.name)
            self.logger.error(  # noqa: TRY400 - the module logger above has the traceback
                f"{run} failed: {type(exc).__name__}: {exc}; the worker log has the traceback"
            )
            return False

        succeeded = True
        for family, result in results:
            if isinstance(result, ImportSummary):
                counts = " ".join(
                    f"{outcome.value}={sum(entry.outcome == outcome for entry in result.entries)}"
                    for outcome in Outcome
                )
                failed = _failed_facts(result)
                line = f"{run}, DHCPv{family}: {counts} failed={failed}"
                if failed:
                    self.logger.error(line)
                    succeeded = False
                else:
                    self.logger.info(line)
            else:
                self.logger.error(f"{run}, DHCPv{family}: {' '.join(result.lines)}")
                succeeded = False
        for family in sorted(set(enabled_versions(server)) - {family for family, _ in results}):
            self.logger.error(f"{run}, DHCPv{family}: the configuration could not be parsed")
            succeeded = False
        return succeeded
