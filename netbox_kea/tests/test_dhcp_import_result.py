# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Each DHCP Import run stores its result: the run, and one entry per Kea fact with its Kea path and reason.

The runs go through the real "Sync to DHCP plugin now" view with Kea stubbed at the transport.
"""

from __future__ import annotations

import threading
import unittest
from datetime import timedelta
from typing import Any

from bs4 import BeautifulSoup
from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.messages import ERROR, get_messages
from django.db import connection, connections
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from netbox_kea import kea_paths
from netbox_kea.dhcp_options import DHCPOption
from netbox_kea.integrations.dhcp_import import store_run
from netbox_kea.integrations.dhcp_import_report import (
    REASON_OUTCOME,
    Capability,
    ImportEntry,
    Kind,
    Outcome,
    Reason,
    not_written,
    written,
)
from netbox_kea.models import DhcpImportEntry, DhcpImportRun, DhcpImportTrigger, Server

from .kea_stub import _subnet_list, stub_kea
from .test_views_dhcp_plugin import _sync_responses
from .utils import _grant, _make_db_server

DHCP_PLUGIN = "netbox_dhcp"

_CONFIG: dict[int, dict[str, Any]] = {
    4: {
        "option-def": [{"name": "no-code", "type": "string"}],
        "client-classes": [{"name": "voip", "option-data": [{"csv-format": True}]}],
        "subnet4": [
            {
                "id": 20,
                "subnet": "192.0.2.0/24",
                "pools": [{"pool": "192.0.2.10-192.0.2.20"}],
                "option-data": [
                    {"code": 3, "data": "192.0.2.1"},
                    {"space": "vendor-x", "code": 1, "data": "x"},
                ],
            },
        ],
        "shared-networks": [{"name": "office", "subnet4": [{"id": 30, "subnet": "198.51.100.0/24"}]}],
    }
}
_HOSTS = {
    4: [
        {"subnet-id": 20, "hw-address": "02:00:00:00:00:01", "ip-address": "192.0.2.50"},
        {"subnet-id": 20, "hw-address": "not-a-mac", "ip-address": "192.0.2.51"},
    ]
}
_SUBNET = "Dhcp4/subnet4[id=20]"
# (kind, outcome, reason, Kea path) of each fact of the first run of _CONFIG and _HOSTS.
_FIRST_RUN = {
    ("option_definition", "not_imported", "invalid_kea_data", "Dhcp4/option-def[0]"),
    ("option", "not_imported", "invalid_kea_data", "Dhcp4/client-classes[name=voip]/option-data[0]"),
    ("client_class", "created", "", "Dhcp4/client-classes[name=voip]"),
    ("server", "created", "", "Dhcp4"),
    ("server", "unsupported", "plugin_gap", "Dhcp4"),
    ("shared_network", "not_imported", "not_in_scope", "Dhcp4/shared-networks[name=office]"),
    ("subnet", "created", "", _SUBNET),
    ("subnet", "created", "", "Dhcp4/subnet4[id=30]"),
    ("option", "created", "", f"{_SUBNET}/option-data[code=3]"),
    ("option", "unsupported", "plugin_gap", f"{_SUBNET}/option-data[space=vendor-x,code=1]"),
    ("pool", "created", "", f"{_SUBNET}/pools[pool=192.0.2.10-192.0.2.20]"),
    ("reservation", "created", "", f"{_SUBNET}/reservations[hw-address=02:00:00:00:00:01]"),
    ("reservation", "not_imported", "invalid_kea_data", "Dhcp4/reservation-get-page/hosts[1].hw-address"),
}
# A second run of the same Kea data writes nothing, so only the facts that were not written remain.
_SECOND_RUN = {entry for entry in _FIRST_RUN if entry[1] != "created"}


def _kea() -> dict:
    """Answer the sync reads of _CONFIG and _HOSTS. Kea lists only the Subnets that have a CIDR."""
    responses = _sync_responses(_CONFIG, _HOSTS)
    subnets = [_CONFIG[4]["subnet4"][0], _CONFIG[4]["shared-networks"][0]["subnet4"][0]]
    responses["subnet4-list"] = _subnet_list(4, subnets)
    return responses


def _option(*, code=None, name=None, space=None) -> DHCPOption:
    return DHCPOption(code, name, space, "x", None, None, None)


def _entries(run: DhcpImportRun) -> set[tuple[str, str, str, str]]:
    return set(DhcpImportEntry.objects.filter(run=run).values_list("kind", "outcome", "reason", "kea_path"))


class _ImportRunTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name="import-result", sync_dhcp_plugin_enabled=True, dhcp6=False)
        self.client.force_login(get_user_model().objects.create_superuser("import-result"))

    def _run(self):
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[self.server.pk])
        with stub_kea(_kea()):
            return self.client.post(url)


class StoredResultTest(_ImportRunTestCase):
    """A run through the real import entry stores one result row with its entries, and counts only entries."""

    def test_a_run_stores_one_result_with_an_entry_for_each_fact(self):
        before = timezone.now()

        self._run()

        run = DhcpImportRun.objects.get(server=self.server)
        self.assertEqual(run.trigger, DhcpImportTrigger.MANUAL)
        self.assertLessEqual(before, run.started)
        self.assertLessEqual(run.started, run.finished)
        self.assertEqual(_entries(run), _FIRST_RUN)
        self.assertEqual(DhcpImportEntry.objects.filter(run=run).count(), len(_FIRST_RUN))
        self.assertEqual(
            DhcpImportEntry.objects.get(run=run, kea_path=f"{_SUBNET}/option-data[space=vendor-x,code=1]").detail,
            "No matching Option Definition.",
        )

    def test_a_second_run_of_unchanged_data_records_no_written_fact(self):
        self._run()
        self._run()

        latest, first = DhcpImportRun.objects.filter(server=self.server)
        self.assertEqual(_entries(first), _FIRST_RUN)
        self.assertEqual(_entries(latest), _SECOND_RUN)

    def test_a_subnet_without_a_cidr_is_an_entry_and_makes_the_reservation_read_incomplete(self):
        config = {4: {"subnet4": [{"id": 21}, {"subnet": "203.0.113.0/24"}]}}
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[self.server.pk])

        with stub_kea(_sync_responses(config)):
            self.client.post(url)

        self.assertEqual(
            _entries(DhcpImportRun.objects.get(server=self.server)),
            {
                ("subnet", "not_imported", "invalid_kea_data", "Dhcp4/subnet4[id=21]"),
                ("subnet", "created", "", "Dhcp4/subnet4[subnet=203.0.113.0/24]"),
                ("server", "created", "", "Dhcp4"),
                ("server", "unsupported", "plugin_gap", "Dhcp4"),
                ("reservation", "skipped", "read_failed", "Dhcp4/reservations"),
            },
        )

    def test_a_storage_failure_never_fails_the_import(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "CREATE FUNCTION refuse_entry() RETURNS trigger AS $$ "
                "BEGIN RAISE EXCEPTION 'entry storage is down'; END $$ LANGUAGE plpgsql"
            )
            cursor.execute(
                "CREATE TRIGGER refuse_entry BEFORE INSERT ON netbox_kea_dhcpimportentry "
                "FOR EACH ROW EXECUTE FUNCTION refuse_entry()"
            )

        with self.assertLogs("netbox_kea.integrations.dhcp_import", level="ERROR") as logs:
            response = self._run()

        self.assertIn("the result of the run could not be stored", logs.output[0])
        self.assertNotIn(ERROR, [message.level for message in get_messages(response.wsgi_request)])
        self.assertTrue(apps.get_model(DHCP_PLUGIN, "Subnet").objects.filter(prefix__prefix="192.0.2.0/24").exists())
        self.assertFalse(DhcpImportRun.objects.exists())


class RetentionTest(TestCase):
    """Storing a run keeps the latest runs of its Server and deletes the older ones, with their entries."""

    def test_storing_a_run_keeps_the_retained_latest_runs_of_its_server(self):
        server = _make_db_server(name="retention")
        other = _make_db_server(name="retention-other")
        start = timezone.now()
        entry = written(4, Kind.SUBNET, "Dhcp4/subnet4[id=1]", Outcome.CREATED)
        store_run(other, DhcpImportTrigger.MANUAL, start, [entry])
        for minute in range(DhcpImportRun.RETAINED_RUNS + 2):
            store_run(server, DhcpImportTrigger.MANUAL, start + timedelta(minutes=minute), [entry])

        kept = list(DhcpImportRun.objects.filter(server=server))
        self.assertEqual(len(kept), DhcpImportRun.RETAINED_RUNS)
        self.assertEqual(kept[-1].started, start + timedelta(minutes=2))
        self.assertEqual(DhcpImportRun.objects.filter(server=other).count(), 1)
        self.assertEqual(DhcpImportEntry.objects.count(), DhcpImportRun.RETAINED_RUNS + 1)


class ConcurrentStorageTest(TransactionTestCase):
    """Two runs of one Server store one after the other, so retention never keeps one run too many."""

    def test_storing_waits_for_another_transaction_that_holds_the_server(self):
        server = _make_db_server(name="retention-lock")
        holder = connection.Database.connect(**connection.get_connection_params())
        holder.autocommit = False
        done = threading.Event()

        def store():
            try:
                store_run(server, DhcpImportTrigger.MANUAL, timezone.now(), [])
            finally:
                connections.close_all()
                done.set()

        try:
            with holder.cursor() as cursor:
                # NO KEY UPDATE lets the insert check its key, so only the explicit lock of store_run waits.
                cursor.execute("SELECT id FROM netbox_kea_server WHERE id = %s FOR NO KEY UPDATE", [server.pk])
            worker = threading.Thread(target=store)
            worker.start()
            self.assertFalse(done.wait(timeout=1))
            self.assertFalse(DhcpImportRun.objects.exists())
            holder.commit()
            self.assertTrue(done.wait(timeout=30))
            worker.join(timeout=30)
        finally:
            holder.close()
        self.assertEqual(DhcpImportRun.objects.filter(server=server).count(), 1)


class LatestRunPageTest(_ImportRunTestCase):
    """The Server's DHCP plugin page shows the latest run to a user who may view the Server, and only to them."""

    def _page(self):
        url = reverse("plugins:netbox_kea:server_dhcp_plugin", args=[self.server.pk])
        with stub_kea(_kea()):
            return self.client.get(url)

    def test_the_page_shows_the_counts_and_entries_of_the_latest_run(self):
        self._run()

        page = BeautifulSoup(self._page().content, "html.parser")

        card = page.select_one("#dhcp-import-latest-run")
        counts = {
            tuple(cell.get_text(strip=True) for cell in row.find_all(["th", "td"]))
            for row in card.select("table.dhcp-import-counts tbody tr")
        }
        self.assertIn(("DHCPv4", "Subnet", "2", "0", "0", "0", "0", "0"), counts)
        self.assertIn(("DHCPv4", "Reservation", "1", "0", "0", "0", "0", "1"), counts)
        self.assertIn(("DHCPv4", "DHCP Option", "1", "0", "0", "1", "0", "1"), counts)
        self.assertIn(("DHCPv4", "Shared Network", "0", "0", "0", "0", "0", "1"), counts)
        text = card.get_text(" ", strip=True)
        self.assertIn(f"{_SUBNET}/option-data[space=vendor-x,code=1]", text)
        self.assertIn("The DHCP plugin cannot hold it", text)

    def test_an_unsupported_fact_is_stored_and_shown_with_its_capability(self):
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        other = DHCPServer.objects.create(name="import-result-other")
        apps.get_model(DHCP_PLUGIN, "ClientClass").objects.create(name="voip", dhcp_server=other)
        path = "Dhcp4/client-classes[name=voip]"

        self._run()

        entry = DhcpImportEntry.objects.get(run__server=self.server, kea_path=path)
        self.assertEqual(
            (entry.outcome, entry.reason, entry.capability), ("unsupported", "plugin_gap", "name_per_server")
        )
        card = BeautifulSoup(self._page().content, "html.parser").select_one("#dhcp-import-latest-run")
        counts = {
            tuple(cell.get_text(strip=True) for cell in row.find_all(["th", "td"]))
            for row in card.select("table.dhcp-import-counts tbody tr")
        }
        # Created, updated, removed, unsupported, skipped, not imported.
        self.assertIn(("DHCPv4", "Client class", "0", "0", "0", "1", "0", "0"), counts)
        row = next(
            row
            for row in card.select("table.table tbody tr")
            if path in [cell.get_text(strip=True) for cell in row.find_all("td")]
        )
        self.assertIn("Name unique per DHCP server (#88 gap 3)", row.get_text(" ", strip=True))

    def test_the_page_says_when_no_run_is_stored(self):
        page = BeautifulSoup(self._page().content, "html.parser")

        self.assertIn(
            "No DHCP Import has run for this Server yet.", page.select_one("#dhcp-import-latest-run").get_text()
        )

    def test_a_user_who_may_view_the_server_sees_the_latest_run(self):
        self._run()
        viewer = get_user_model().objects.create_user("import-result-viewer")
        _grant([Server], ["view"], user=viewer)
        self.client.force_login(viewer)

        response = self._page()

        self.assertContains(response, "Dhcp4/shared-networks[name=office]")

    def test_a_user_without_view_permission_on_the_server_cannot_see_the_run(self):
        self._run()
        self.client.force_login(get_user_model().objects.create_user("import-result-outsider"))

        response = self._page()

        self.assertNotContains(response, "Dhcp4/shared-networks[name=office]", status_code=403)


class EntryVocabularyTest(SimpleTestCase):
    """The reason of an entry gives its outcome, and each Kea path names one object."""

    def test_the_reason_gives_the_outcome_of_a_fact_that_was_not_written(self):
        entry = not_written(4, Kind.SUBNET, "Dhcp4/subnet4[id=1]", Reason.SUBNET_ID_CLASH)

        self.assertEqual(entry.outcome, Outcome.UNSUPPORTED)
        self.assertEqual(set(REASON_OUTCOME), set(Reason))

    def test_only_a_plugin_gap_entry_names_a_capability(self):
        with self.assertRaises(ValueError):
            ImportEntry(
                4,
                Kind.SUBNET,
                "Dhcp4/subnet4[id=1]",
                Outcome.NOT_IMPORTED,
                Reason.NOT_IN_SCOPE,
                "",
                Capability.USER_CONTEXT,
            )

    def test_an_entry_refuses_an_outcome_that_disagrees_with_its_reason(self):
        for outcome, reason in ((Outcome.CREATED, Reason.WRITE_FAILED), (Outcome.SKIPPED, None)):
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                ImportEntry(4, Kind.SUBNET, "Dhcp4/subnet4[id=1]", outcome, reason)

    def test_kea_paths(self):
        subnet = kea_paths.subnet(6, 20, "2001:db8::/64")
        self.assertEqual(
            [
                subnet,
                kea_paths.subnet(4, None, "192.0.2.0/24"),
                kea_paths.option(subnet, _option(code=23), 6),
                kea_paths.option(subnet, _option(name="vendor-opt", space="vendor-x"), 6),
                kea_paths.option_definition(4, "dhcp4", 224),
                kea_paths.option_definition(4, "vendor-x", 1),
                kea_paths.reservation(4, None, "duid", "01:02"),
                kea_paths.reservation(6, 20, "hw-address", "02:00:00:00:00:01"),
            ],
            [
                "Dhcp6/subnet6[id=20]",
                "Dhcp4/subnet4[subnet=192.0.2.0/24]",
                "Dhcp6/subnet6[id=20]/option-data[code=23]",
                "Dhcp6/subnet6[id=20]/option-data[space=vendor-x,name=vendor-opt]",
                "Dhcp4/option-def[code=224]",
                "Dhcp4/option-def[space=vendor-x,code=1]",
                "Dhcp4/reservations[duid=01:02]",
                "Dhcp6/subnet6[id=20]/reservations[hw-address=02:00:00:00:00:01]",
            ],
        )


class ReviewedEntryTest(_ImportRunTestCase):
    """Each fact that a run does not write has exactly one entry, and IPAM ownership outcomes are not errors."""

    def _import(self, config: dict):
        from netbox_kea.integrations import dhcp_plugin
        from netbox_kea.mappers.kea_to_dhcp import parse_dhcp_config

        intent = parse_dhcp_config(config, 4)
        intent.configuration_complete = True
        return dhcp_plugin.import_server_config(self.server, intent, None)

    def _paths(self, summary, kind: Kind) -> list[tuple[str, Outcome, Reason | None]]:
        return [(entry.path, entry.outcome, entry.reason) for entry in summary.entries if entry.kind == kind]

    def test_a_pool_that_ipam_ownership_keeps_unchanged_is_skipped_and_is_not_an_error(self):
        pool = {"pool": "198.18.0.10-198.18.0.20"}
        summary = self._import(
            {
                "subnet4": [
                    {"id": 1, "subnet": "198.18.0.0/24", "pools": [pool]},
                    {"id": 2, "subnet": "198.18.0.0/25", "pools": [pool]},
                ]
            }
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(
            self._paths(summary, Kind.POOL),
            [
                (f"Dhcp4/subnet4[id={sid}]/pools[pool=198.18.0.10-198.18.0.20]", Outcome.SKIPPED, Reason.IPAM_OWNERSHIP)
                for sid in (1, 2)
            ],
        )

    def test_a_failed_option_definition_has_one_entry_and_its_options_are_skipped(self):
        OptionDefinition = apps.get_model(DHCP_PLUGIN, "OptionDefinition")
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        dhcp_server = DHCPServer.objects.create(name=self.server.name)
        # The plugin keeps definition names unique per server, so a second code with this name fails.
        OptionDefinition.objects.create(
            name="site-opt", family=4, space="dhcp4", code=230, type="string", standard=False, dhcp_server=dhcp_server
        )
        option = {"code": 231, "data": "x"}
        summary = self._import(
            {
                "option-def": [{"name": "site-opt", "code": 231, "type": "string", "space": "dhcp4"}],
                "option-data": [option],
                "subnet4": [{"id": 1, "subnet": "198.18.1.0/24", "option-data": [option]}],
            }
        )

        self.assertEqual(
            self._paths(summary, Kind.OPTION_DEFINITION),
            [("Dhcp4/option-def[code=231]", Outcome.SKIPPED, Reason.WRITE_FAILED)],
        )
        self.assertEqual(
            self._paths(summary, Kind.OPTION),
            [
                ("Dhcp4/option-data[code=231]", Outcome.SKIPPED, Reason.PARENT_NOT_IMPORTED),
                ("Dhcp4/subnet4[id=1]/option-data[code=231]", Outcome.SKIPPED, Reason.PARENT_NOT_IMPORTED),
            ],
        )

    def test_the_children_of_a_failed_subnet_are_skipped(self):
        summary = self._import(
            {
                "subnet4": [
                    {
                        "id": 1,
                        "subnet": "not-a-cidr",
                        "pools": [{"pool": "10.0.0.10-10.0.0.20", "option-data": [{"code": 3, "data": "10.0.0.1"}]}],
                        "option-data": [{"code": 6, "data": "10.0.0.2"}],
                    }
                ]
            }
        )

        subnet = "Dhcp4/subnet4[id=1]"
        pool = f"{subnet}/pools[pool=10.0.0.10-10.0.0.20]"
        self.assertEqual(
            [(entry.kind, entry.path, entry.reason) for entry in summary.entries if entry.kind != Kind.SERVER],
            [
                (Kind.SUBNET, subnet, Reason.WRITE_FAILED),
                (Kind.OPTION, f"{subnet}/option-data[code=6]", Reason.PARENT_NOT_IMPORTED),
                (Kind.POOL, pool, Reason.PARENT_NOT_IMPORTED),
                (Kind.OPTION, f"{pool}/option-data[code=3]", Reason.PARENT_NOT_IMPORTED),
                (Kind.RESERVATION, "Dhcp4/reservations", Reason.READ_FAILED),
            ],
        )

    def test_options_of_different_client_classes_have_different_paths(self):
        summary = self._import(
            {
                "subnet4": [
                    {
                        "id": 1,
                        "subnet": "198.18.2.0/24",
                        "option-data": [
                            {"code": 3, "data": "198.18.2.1", "client-classes": ["voip"]},
                            {"code": 3, "data": "198.18.2.2", "client-classes": ["printers", "lab"]},
                        ],
                    }
                ]
            }
        )

        self.assertEqual(
            [path for path, _outcome, _reason in self._paths(summary, Kind.OPTION)],
            [
                "Dhcp4/subnet4[id=1]/option-data[code=3,client-classes=voip]",
                "Dhcp4/subnet4[id=1]/option-data[code=3,client-classes=lab|printers]",
            ],
        )


class StoppedRunTest(_ImportRunTestCase):
    """A run that stops part way still stores the entries it has, and an entry for the family that stopped."""

    def test_a_run_refused_by_the_mapping_lock_stores_its_result(self):
        from netbox_kea.dhcp_mapping_lifecycle import _METADATA_LOCK

        holder = connection.Database.connect(**connection.get_connection_params())
        try:
            with holder.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(%s, %s)", _METADATA_LOCK)
            response = self._run()
        finally:
            holder.close()

        self.assertIn(ERROR, [message.level for message in get_messages(response.wsgi_request)])
        run = DhcpImportRun.objects.get(server=self.server)
        self.assertEqual(
            _entries(run),
            {("server", "skipped", "write_failed", "Dhcp4")},
        )
        self.assertIn("stopped", DhcpImportEntry.objects.get(run=run).detail)


class SettingEntryTest(_ImportRunTestCase):
    """A Kea value that the import cannot convert to its DHCP plugin field has an entry."""

    _import = ReviewedEntryTest._import

    def test_a_value_that_cannot_be_converted_is_unsupported(self):
        summary = self._import({"subnet4": [{"id": 1, "subnet": "198.18.3.0/24", "t1-percent": "not-a-number"}]})

        self.assertIn(
            not_written(
                4,
                Kind.SUBNET,
                "Dhcp4/subnet4[id=1]/t1-percent",
                Reason.PLUGIN_GAP,
                "The value cannot be converted to the DHCP plugin field.",
            ),
            summary.entries,
        )
