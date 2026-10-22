# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The periodic sync job runs the scheduled DHCP Import: the real job and the real import, Kea stubbed at the transport."""

from __future__ import annotations

import re
import unittest
from unittest.mock import MagicMock, patch

from core.exceptions import JobFailed
from django.apps import apps
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings

from netbox_kea import event_scope
from netbox_kea.dhcp_mapping_lifecycle import _METADATA_LOCK, ImportEventsNotDispatched
from netbox_kea.jobs import KeaIpamSyncJob
from netbox_kea.models import DhcpImportEntry, DhcpImportRun, DhcpImportTrigger, DhcpIntegrationConfig

from .kea_stub import _sync_responses, complete_lease, lease_pages, stub_kea
from .test_dhcp_import import _recorded_config
from .test_dhcp_import_result import _held_elsewhere, _lock_key, _new_session
from .test_event_scope import _FAILING_PIPELINE, NESTED_TRACKING
from .test_jobs import _make_job
from .test_kea_recordings import _recording
from .utils import (
    _make_db_server,
    imported_dhcp_server,
    with_dhcp_integration_config,
    with_sync_config,
    without_dhcp_plugin,
)

DHCP_PLUGIN = "netbox_dhcp"


def _kea(**options) -> dict:
    """Answer the import reads of each Server with the recorded replies of both families, and the IPAM sync with no lease."""
    responses = _sync_responses({4: _recorded_config(4), 6: _recorded_config(6)}, **options)
    for family in (4, 6):
        responses[f"subnet{family}-list"] = _recording(family)[f"subnet{family}-list"]
        responses[f"lease{family}-get-page"] = lease_pages([])
    return responses


#: A per-family result line that counts at least one failed fact.
_FAILED_FAMILY = re.compile(r"DHCPv4: .* failed=[1-9]")


def _server(name: str, **fields):
    """Return a DHCPv4 Server with the DHCP plugin flag on and its IPAM sync off, unless *fields* say otherwise."""
    values = {"dhcp6": False, "sync_dhcp_plugin_enabled": True, "sync_enabled": False, **fields}
    return _make_db_server(name=name, ca_url=f"https://{name}.example.invalid", **values)


def _job_log(job: MagicMock) -> list[str]:
    """Return the job log entries as NetBox renders them."""
    from core.dataclasses import JobLogEntry

    return [JobLogEntry.from_logrecord(call.args[0]).message for call in job.log.call_args_list]


def _scheduled_lines(job: MagicMock) -> list[str]:
    return [message for message in _job_log(job) if "Scheduled DHCP Import" in message]


class ScheduledImportSettingTest(TestCase):
    """The setting is off on a new install. Without the DHCP plugin the job runs no import and does not fail."""

    def test_the_setting_is_off_by_default(self):
        self.assertIs(DhcpIntegrationConfig.get().scheduled_import_enabled, False)

    @without_dhcp_plugin()
    @with_dhcp_integration_config(scheduled_import_enabled=True)
    def test_without_the_dhcp_plugin_the_job_runs_no_import_and_does_not_fail(self):
        _server("no-plugin")
        job = _make_job()

        with stub_kea({}) as kea:
            KeaIpamSyncJob(job).run()

        self.assertEqual(kea.commands(), [])
        self.assertFalse(DhcpImportRun.objects.exists())


class _ScheduledImportTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def _run(self, **kwargs) -> MagicMock:
        """Run the job once and return the job stand-in. A failed job raises JobFailed, so the test fails."""
        job = _make_job()
        with stub_kea(_kea()):
            KeaIpamSyncJob(job).run(**kwargs)
        return job

    def _run_failed(self, responses: dict) -> MagicMock:
        """Run the job once with *responses*, require it to fail, and return the job stand-in."""
        job = _make_job()
        with stub_kea(responses), self.assertRaises(JobFailed):
            KeaIpamSyncJob(job).run()
        return job


class ScheduledImportOffTest(_ScheduledImportTestCase):
    """With the setting off, the periodic job runs no DHCP Import."""

    def test_with_the_setting_off_the_job_runs_no_import(self):
        _server("off")

        with stub_kea(_kea()) as kea:
            KeaIpamSyncJob(_make_job()).run()

        self.assertEqual(kea.commands(), [])
        self.assertFalse(DhcpImportRun.objects.exists())


@with_dhcp_integration_config(scheduled_import_enabled=True)
class ScheduledImportTest(_ScheduledImportTestCase):
    """With the setting on, the job imports each Server that the integration runs for, with trigger "scheduled"."""

    def test_the_job_imports_each_server_whose_dhcp_plugin_flag_is_on_and_skips_the_others(self):
        imported = _server("imported")
        skipped = _server("skipped", sync_dhcp_plugin_enabled=False)

        job = self._run()

        run = DhcpImportRun.objects.get(server=imported)
        self.assertEqual(run.trigger, DhcpImportTrigger.SCHEDULED)
        self.assertTrue(DhcpImportEntry.objects.filter(run=run, kind="server", outcome="created").exists())
        self.assertIsNotNone(imported_dhcp_server(imported, 4))
        self.assertFalse(DhcpImportRun.objects.filter(server=skipped).exists())
        lines = _scheduled_lines(job)
        self.assertTrue(
            any(line.startswith("Scheduled DHCP Import of Server imported, DHCPv4: created=") for line in lines)
        )
        self.assertIn(
            "Scheduled DHCP Import of Server skipped skipped: Enable 'Sync to DHCP plugin' on this server first.", lines
        )
        self.assertEqual(lines[-1], "Scheduled DHCP Import complete: servers=1 failed=0")

    def test_the_import_runs_after_the_ipam_sync_of_the_same_server(self):
        server = _server("both", sync_enabled=True)

        job = self._run()

        self.assertEqual(DhcpImportRun.objects.get(server=server).trigger, DhcpImportTrigger.SCHEDULED)
        log = _job_log(job)
        ipam = next(index for index, message in enumerate(log) if message.startswith("Server both: created="))
        scheduled = next(
            index for index, message in enumerate(log) if "Scheduled DHCP Import of Server both" in message
        )
        self.assertLess(ipam, scheduled)

    @with_dhcp_integration_config(enabled=False)
    def test_clearing_the_global_switch_stops_every_scheduled_import(self):
        _server("first")
        _server("second")

        with stub_kea(_kea()) as kea:
            KeaIpamSyncJob(_make_job()).run()

        self.assertEqual(kea.commands(), [])
        self.assertFalse(DhcpImportRun.objects.exists())

    def test_a_run_now_of_one_server_runs_no_scheduled_import(self):
        server = _server("run-now", sync_enabled=True)

        self._run(server_pk=server.pk)

        self.assertFalse(DhcpImportRun.objects.exists())

    def test_one_failed_server_is_recorded_and_the_next_server_still_runs(self):
        broken = _server("a-broken")
        healthy = _server("b-healthy")
        table = apps.get_model(DHCP_PLUGIN, "DHCPServer")._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute(
                "CREATE FUNCTION refuse_broken() RETURNS trigger AS $$ BEGIN "
                "IF NEW.name LIKE 'a-broken%' THEN RAISE EXCEPTION 'dhcp server storage is down'; END IF; "
                "RETURN NEW; END $$ LANGUAGE plpgsql"
            )
            cursor.execute(
                f"CREATE TRIGGER refuse_broken BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION refuse_broken()"
            )

        job = _make_job()
        with stub_kea(_kea()), self.assertRaises(JobFailed):
            KeaIpamSyncJob(job).run()

        failed = DhcpImportRun.objects.get(server=broken)
        self.assertEqual(failed.trigger, DhcpImportTrigger.SCHEDULED)
        self.assertEqual(
            set(failed.entries.values_list("kind", "outcome", "reason", "kea_path")),
            {("server", "skipped", "write_failed", "Dhcp4")},
        )
        self.assertEqual(DhcpImportRun.objects.get(server=healthy).trigger, DhcpImportTrigger.SCHEDULED)
        self.assertIsNotNone(imported_dhcp_server(healthy, 4))
        lines = _scheduled_lines(job)
        self.assertTrue(
            any(
                "Scheduled DHCP Import of Server a-broken failed: ProgrammingError: dhcp server storage is down" in line
                for line in lines
            ),
            lines,
        )
        self.assertTrue(any("Scheduled DHCP Import of Server b-healthy, DHCPv4: created=" in line for line in lines))
        self.assertIn("Scheduled DHCP Import complete: servers=2 failed=1", lines[-1])

    def test_a_failed_kea_read_is_recorded_in_the_run_and_the_job_log(self):
        server = _server("unreachable")
        responses = _kea()
        responses["config-get"] = {"result": 1, "text": "config-get refused"}

        job = _make_job()
        with stub_kea(responses), self.assertRaises(JobFailed):
            KeaIpamSyncJob(job).run()

        run = DhcpImportRun.objects.get(server=server)
        self.assertEqual(run.trigger, DhcpImportTrigger.SCHEDULED)
        self.assertEqual(set(run.entries.values_list("kind", "reason")), {("server", "read_failed")})
        self.assertTrue(
            any("Scheduled DHCP Import of Server unreachable, DHCPv4: " in line for line in _scheduled_lines(job))
        )

    def test_a_configuration_that_cannot_be_parsed_is_recorded_in_the_run_and_the_job_log(self):
        server = _server("unparsable")
        config = _recorded_config(4)
        config["client-classes"] = None

        job = _make_job()
        with stub_kea(_sync_responses({4: config})), self.assertRaises(JobFailed):
            KeaIpamSyncJob(job).run()

        run = DhcpImportRun.objects.get(server=server)
        self.assertEqual(run.trigger, DhcpImportTrigger.SCHEDULED)
        self.assertEqual(set(run.entries.values_list("kind", "reason")), {("server", "invalid_kea_data")})
        self.assertIn(
            "Scheduled DHCP Import of Server unparsable, DHCPv4: the configuration could not be parsed",
            _scheduled_lines(job),
        )

    def test_a_server_that_another_import_holds_is_skipped_and_the_job_does_not_fail(self):
        busy = _server("busy")
        holder = _new_session()
        try:
            with holder.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(%s, %s)", _lock_key(busy))
            job = _make_job()
            with stub_kea(_kea()) as kea:
                KeaIpamSyncJob(job).run()
        finally:
            holder.close()

        self.assertEqual(kea.commands(), [])
        self.assertFalse(DhcpImportRun.objects.exists())
        self.assertFalse(_held_elsewhere(busy))
        self.assertTrue(
            any(
                "Scheduled DHCP Import of Server busy skipped: Another DHCP Import of this Server is running" in line
                for line in _scheduled_lines(job)
            )
        )

    @with_sync_config(sync_enabled=False)
    def test_the_ipam_sync_kill_switch_does_not_stop_the_scheduled_import(self):
        server = _server("kill-switch", sync_enabled=True)

        self._run()

        self.assertEqual(DhcpImportRun.objects.get(server=server).trigger, DhcpImportTrigger.SCHEDULED)

    @with_sync_config(
        sync_leases_enabled=False,
        sync_reservations_enabled=False,
        sync_prefixes_enabled=False,
        sync_ip_ranges_enabled=False,
    )
    def test_the_scheduled_import_runs_with_every_ipam_sync_type_off(self):
        server = _server("no-types", sync_enabled=True)

        self._run()

        self.assertEqual(DhcpImportRun.objects.get(server=server).trigger, DhcpImportTrigger.SCHEDULED)

    def test_a_dual_family_server_imports_both_families(self):
        server = _server("dual", dhcp6=True)

        job = self._run()

        self.assertIsNotNone(imported_dhcp_server(server, 4))
        self.assertIsNotNone(imported_dhcp_server(server, 6))
        families = {
            entry[:5] for entry in DhcpImportRun.objects.get(server=server).entries.values_list("kea_path", flat=True)
        }
        self.assertEqual(families, {"Dhcp4", "Dhcp6"})
        lines = _scheduled_lines(job)
        for family in (4, 6):
            self.assertTrue(
                any(
                    line.startswith(f"Scheduled DHCP Import of Server dual, DHCPv{family}: created=") for line in lines
                ),
                lines,
            )

    def test_a_failed_reservation_read_fails_the_server_and_the_job(self):
        server = _server("no-reservations")

        job = self._run_failed(_kea(reservations_available=False))

        run = DhcpImportRun.objects.get(server=server)
        self.assertIn(("reservation", "read_failed"), set(run.entries.values_list("kind", "reason")))
        lines = _scheduled_lines(job)
        self.assertTrue(any(_FAILED_FAMILY.search(line) for line in lines), lines)
        self.assertEqual(lines[-1], "Scheduled DHCP Import complete: servers=1 failed=1")

    def test_an_option_definition_write_failure_fails_the_server_and_the_job(self):
        server = _server("clash")
        dhcp_server = apps.get_model(DHCP_PLUGIN, "DHCPServer").objects.create(name=server.name)
        # The plugin keeps definition names unique per DHCP server, so Kea's code 231 with this name fails.
        apps.get_model(DHCP_PLUGIN, "OptionDefinition").objects.create(
            name="site-opt", family=4, space="dhcp4", code=230, type="string", standard=False, dhcp_server=dhcp_server
        )
        config = {
            "option-def": [{"name": "site-opt", "code": 231, "type": "string", "space": "dhcp4"}],
            "subnet4": [{"id": 1, "subnet": "198.18.1.0/24"}],
        }

        job = self._run_failed(_sync_responses({4: config}))

        run = DhcpImportRun.objects.get(server=server)
        self.assertIn(("option_definition", "write_failed"), set(run.entries.values_list("kind", "reason")))
        lines = _scheduled_lines(job)
        self.assertTrue(any(_FAILED_FAMILY.search(line) for line in lines), lines)
        self.assertEqual(lines[-1], "Scheduled DHCP Import complete: servers=1 failed=1")

    def test_a_mapping_lock_refusal_after_the_reads_fails_the_server_and_the_job(self):
        server = _server("mapping-busy")
        holder = _new_session()
        try:
            with holder.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(%s, %s)", _METADATA_LOCK)
            job = self._run_failed(_kea())
        finally:
            holder.close()

        run = DhcpImportRun.objects.get(server=server)
        self.assertEqual(
            set(run.entries.values_list("kind", "outcome", "reason", "kea_path")),
            {("server", "skipped", "write_failed", "Dhcp4")},
        )
        lines = _scheduled_lines(job)
        self.assertTrue(any(line.startswith("Scheduled DHCP Import of Server mapping-busy failed: ") for line in lines))
        self.assertEqual(lines[-1], "Scheduled DHCP Import complete: servers=1 failed=1")

    def test_an_unsupported_plugin_version_is_logged_and_fails_the_job(self):
        _server("old-plugin")

        job = _make_job()
        with (
            patch.object(apps.get_app_config(DHCP_PLUGIN), "version", "0.1.9"),
            stub_kea(_kea()) as kea,
            self.assertRaises(JobFailed),
        ):
            KeaIpamSyncJob(job).run()

        self.assertEqual(kea.commands(), [])
        self.assertTrue(
            any("needs netbox-plugin-dhcp 0.2.0 or later" in line for line in _scheduled_lines(job)),
            _scheduled_lines(job),
        )


@unittest.skipUnless(NESTED_TRACKING, "Units need the nestable event_tracking of NetBox 4.6.9")
@override_settings(EVENTS_PIPELINE=[_FAILING_PIPELINE])
class ScheduledImportEventsTest(TransactionTestCase):
    """An import whose events NetBox cannot dispatch stops the job: the pipeline fails for every Server."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    @with_dhcp_integration_config(scheduled_import_enabled=True)
    def test_events_that_cannot_be_dispatched_stop_the_job_after_the_run_is_stored(self):
        first = _server("a-first")
        second = _server("b-second")
        conf = {4: {"subnet4": [{"id": 1, "subnet": "10.79.0.0/24"}]}}

        job = _make_job()
        with stub_kea(_sync_responses(conf)), self.assertRaises(ImportEventsNotDispatched):
            KeaIpamSyncJob(job).run()

        stored = DhcpImportRun.objects.get(server=first)
        self.assertEqual(stored.trigger, DhcpImportTrigger.SCHEDULED)
        self.assertIn(("subnet", "created"), set(stored.entries.values_list("kind", "outcome")))
        self.assertFalse(DhcpImportRun.objects.filter(server=second).exists())
        self.assertEqual(
            _scheduled_lines(job)[-1],
            "Scheduled DHCP Import of Server a-first saved its changes, but NetBox could not dispatch their events."
            " The job stops.",
        )

    @with_dhcp_integration_config(scheduled_import_enabled=True)
    def test_events_of_the_ipam_sync_that_cannot_be_dispatched_stop_the_job_before_the_import(self):
        _server("ipam-events", sync_enabled=True)
        conf = {4: {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        responses = _sync_responses(conf)
        lease = {"ip-address": "10.0.0.1", "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "host1", "subnet-id": 1}
        responses["lease4-get-page"] = lease_pages([complete_lease(lease)])

        job = _make_job()
        with stub_kea(responses), self.assertRaises(event_scope.EventDispatchError):
            KeaIpamSyncJob(job).run()

        self.assertFalse(DhcpImportRun.objects.exists())
        self.assertEqual(_scheduled_lines(job), [])
