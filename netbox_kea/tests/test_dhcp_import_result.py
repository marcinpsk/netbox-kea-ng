# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Each DHCP Import run stores its result: the run, and one entry per Kea fact with its Kea path and reason.

The runs go through the real "Sync to DHCP plugin now" view with Kea stubbed at the transport.
"""

from __future__ import annotations

import contextlib
import copy
import threading
import unittest
from datetime import timedelta
from typing import Any, cast

from bs4 import BeautifulSoup
from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.messages import ERROR, get_messages
from django.db import DatabaseError, connection, connections, transaction
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
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

from .kea_stub import _subnet_list, _sync_responses, stub_kea
from .utils import DISPATCHED_EVENTS, _grant, _make_db_server, without_dhcp_plugin

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
    ("shared_network", "unsupported", "plugin_gap", "Dhcp4/shared-networks[name=office]"),
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
            DhcpImportEntry.objects.filter(run=run, kea_path=f"{_SUBNET}/option-data[space=vendor-x,code=1]")
            .values_list("detail", "capability")
            .get(),
            (
                "The DHCP plugin has no Option Definition for it and cannot hold an option without one.",
                Capability.OPTION_WITHOUT_DEFINITION.value,
            ),
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
        self.assertIn(("DHCPv4", "Shared Network", "0", "0", "0", "1", "0", "0"), counts)
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

    def test_the_entries_of_a_run_longer_than_one_page_are_reachable_page_by_page(self):
        # NetBox moves a last page of at most 5 rows onto the page before it, so the last page holds 6.
        paths = [f"Dhcp4/subnet4[id={subnet_id}]" for subnet_id in range(1, 12)]
        store_run(
            self.server,
            DhcpImportTrigger.MANUAL,
            timezone.now(),
            [written(4, Kind.SUBNET, path, Outcome.CREATED) for path in paths],
        )
        url = reverse("plugins:netbox_kea:server_dhcp_plugin", args=[self.server.pk])

        shown = []
        for page_number in (1, 2):
            with stub_kea(_kea()):
                response = self.client.get(url, {"per_page": 5, "page": page_number})
            card = BeautifulSoup(response.content, "html.parser").select_one("#dhcp-import-latest-run")
            cells = {cell.get_text(strip=True) for cell in card.select("td")}
            shown.append([path for path in paths if path in cells])
            links = {link["href"] for link in card.select("ul.pagination a")}
            self.assertTrue(any(f"page={3 - page_number}" in link for link in links), links)
        self.assertEqual(shown, [paths[:5], paths[5:]])

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


@without_dhcp_plugin()
class EntryVocabularyTest(SimpleTestCase):
    """The reason of an entry gives its outcome, and each Kea path names one object."""

    def test_the_reason_gives_the_outcome_of_a_fact_that_was_not_written(self):
        entry = not_written(4, Kind.SUBNET, "Dhcp4/subnet4[id=1]", Reason.SUBNET_ID_CLASH)

        self.assertEqual(entry.outcome, Outcome.UNSUPPORTED)
        self.assertEqual(set(REASON_OUTCOME), set(Reason))

    def test_only_an_unsupported_entry_names_a_capability(self):
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

    def test_setting_paths_are_distinct_from_object_paths(self):
        from netbox_kea.dhcp_options import option_identity

        root = kea_paths.daemon(4)
        subnet = kea_paths.subnet(4, 20)
        option = _option(code=3)
        names = (
            "office/evaluate-additional-classes[lab",
            "office]/client-classes[lab",
            "office/interfaces-config/interfaces[lab",
            "office/reservation-get-page/lab",
        )
        named_objects = tuple(
            path
            for name in names
            for path in (
                kea_paths.shared_network(4, name),
                kea_paths.client_class(4, name),
                kea_paths.option(subnet, _option(name=name), 4),
            )
        )
        objects = (
            root,
            subnet,
            kea_paths.subnet(4, None, "198.18.0.0/24"),
            kea_paths.subnet_entry(root, 4, 0),
            kea_paths.shared_network(4, "office"),
            kea_paths.shared_network_entry(4, 0),
            kea_paths.pool(subnet, "198.18.0.10-198.18.0.20"),
            kea_paths.pool_entry(subnet, 0),
            kea_paths.pd_pool(subnet, "2001:db8::/56", 64),
            kea_paths.pd_pool_entry(subnet, 0),
            kea_paths.client_class(4, "voip"),
            kea_paths.client_class_entry(4, 0),
            kea_paths.option_definition(4, "dhcp4", 224),
            kea_paths.option_definition_entry(4, 0),
            kea_paths.option(subnet, option, 4),
            kea_paths.option_of_identity(subnet, option_identity(option, 4), 4),
            kea_paths.option_entry(subnet, 0),
            kea_paths.reservation(4, 20, "hw-address", "02:00:00:00:00:01"),
            kea_paths.reservation_record(4, "hosts[1].hw-address"),
            kea_paths.every_entry(kea_paths.reservations(4)),
            *named_objects,
        )
        settings = (
            kea_paths.setting(root, kea_paths.SERVER_ID),
            kea_paths.setting(kea_paths.option(subnet, option, 4), "metadata"),
            kea_paths.setting(kea_paths.setting(root, kea_paths.SERVER_ID), "type"),
            kea_paths.class_reference(subnet, kea_paths.CLIENT_CLASSES, "missing"),
            kea_paths.class_reference(subnet, kea_paths.EVALUATE_ADDITIONAL_CLASSES, "missing"),
            kea_paths.interface(4, "eth0/198.18.0.1"),
            *(kea_paths.setting(path, "metadata") for path in named_objects),
            *(kea_paths.setting(path, "key[lab]") for path in named_objects),
            *(kea_paths.class_reference(path, kea_paths.CLIENT_CLASSES, "missing") for path in named_objects),
            *(
                kea_paths.class_reference(path, kea_paths.EVALUATE_ADDITIONAL_CLASSES, "missing")
                for path in named_objects
            ),
            *(kea_paths.interface(4, name) for name in names),
        )
        for path in objects:
            with self.subTest(object=path):
                self.assertIs(type(path), str)
                self.assertFalse(kea_paths.is_setting(path))
        for path in settings:
            with self.subTest(setting=path):
                self.assertTrue(kea_paths.is_setting(path))

    def test_every_object_counter_excludes_setting_entries(self):
        from netbox_kea.integrations.dhcp_plugin import ImportSummary, _Count

        for name, counter in vars(ImportSummary).items():
            if not isinstance(counter, _Count):
                continue
            match = counter.matches[0]
            path = kea_paths.setting(kea_paths.daemon(4), "metadata")
            entry = (
                written(4, counter.kind, path, match)
                if isinstance(match, Outcome) and match in (Outcome.CREATED, Outcome.UPDATED, Outcome.REMOVED)
                else not_written(4, counter.kind, path, match)
                if isinstance(match, Reason)
                else ImportEntry(4, counter.kind, path, match, Reason.PLUGIN_GAP)
            )
            summary = ImportSummary(entries=[entry])
            with self.subTest(counter=name):
                self.assertEqual(getattr(summary, name), 0)
                self.assertEqual(summary.count(counter.kind, match), 1)

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


def _new_session():
    """Open a second database session, outside the test transaction, for the other side of a lock."""
    return cast(Any, connection).Database.connect(**connection.get_connection_params())


def _lock_key(server: Server) -> tuple[int, int]:
    from netbox_kea.integrations.dhcp_import import IMPORT_LOCK_CLASS

    return IMPORT_LOCK_CLASS, server.pk


def _held_elsewhere(server: Server) -> bool:
    """Return whether another session holds the import lock of *server*: take it from a new session, then release it."""
    other = _new_session()
    try:
        with other.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", _lock_key(server))
            (taken,) = cursor.fetchone()
            if taken:
                cursor.execute("SELECT pg_advisory_unlock(%s, %s)", _lock_key(server))
    finally:
        other.close()
    return not taken


class ServerImportLockTest(_ImportRunTestCase):
    """Two DHCP Imports of one Server never interleave: a run holds a Server lock from its first Kea read to its result."""

    def _key(self) -> tuple[int, int]:
        return _lock_key(self.server)

    def _held_elsewhere(self) -> bool:
        return _held_elsewhere(self.server)

    def test_a_run_while_another_run_holds_the_lock_is_refused_before_any_kea_read(self):
        from netbox_kea.models import KeaDhcpLink

        holder = _new_session()
        try:
            with holder.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(%s, %s)", self._key())
            url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[self.server.pk])
            with stub_kea(_kea()) as kea:
                response = self.client.post(url)
        finally:
            holder.close()

        self.assertEqual(kea.commands(), [])
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            ["Another DHCP Import of this Server is running. Nothing changed. Retry this operation."],
        )
        self.assertFalse(DhcpImportRun.objects.filter(server=self.server).exists())
        self.assertFalse(KeaDhcpLink.objects.filter(server=self.server).exists())
        self.assertFalse(self._held_elsewhere())

    def test_a_run_releases_the_lock(self):
        self._run()

        self.assertTrue(DhcpImportRun.objects.filter(server=self.server).exists())
        self.assertFalse(self._held_elsewhere())

    def test_a_run_that_raises_releases_the_lock(self):
        from unittest.mock import patch

        from netbox_kea.integrations import dhcp_plugin

        with patch.object(dhcp_plugin, "import_server_config", autospec=True, side_effect=RuntimeError("boom")):
            response = self._run()

        self.assertIn(ERROR, [message.level for message in get_messages(response.wsgi_request)])
        self.assertFalse(self._held_elsewhere())

    def test_a_run_holds_the_lock_after_its_read_so_a_second_run_cannot_interleave(self) -> None:
        from netbox_kea.dhcp_mapping_lifecycle import MetadataBusy
        from netbox_kea.integrations.dhcp_import import run_dhcp_plugin_import

        refusals: list[str] = []
        responses = _kea()
        read_config = responses["config-get"]

        def second_run():
            try:
                run_dhcp_plugin_import(self.server, DhcpImportTrigger.MANUAL)
            except MetadataBusy as error:
                refusals.append(error.message)
            finally:
                connections.close_all()

        def config_get(body):
            # Run A has started its read; run B tries to start now, as in a read-then-apply interleaving.
            if not refusals:
                thread = threading.Thread(target=second_run)
                thread.start()
                thread.join()
            return read_config(body)

        responses["config-get"] = config_get
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[self.server.pk])
        with stub_kea(responses):
            self.client.post(url)

        self.assertEqual(
            refusals, ["Another DHCP Import of this Server is running. Nothing changed. Retry this operation."]
        )
        self.assertEqual(DhcpImportRun.objects.filter(server=self.server).count(), 1)
        self.assertFalse(self._held_elsewhere())


class ImportLockReleaseTest(TransactionTestCase):
    """The import lock is released, and the error of the run kept, also when the transaction of the run failed."""

    def test_a_failed_transaction_keeps_the_error_of_the_run_and_releases_the_lock(self):
        from netbox_kea.integrations.dhcp_import import _server_import_lock

        server = _make_db_server(name="lock-release")
        with self.assertRaisesMessage(RuntimeError, "the run failed"):
            with transaction.atomic(), _server_import_lock(server):
                with connection.cursor() as cursor, contextlib.suppress(DatabaseError):
                    cursor.execute("SELECT 1 / 0")
                raise RuntimeError("the run failed")

        self.assertFalse(_held_elsewhere(server))

    def test_a_lock_that_is_not_held_at_release_is_logged(self):
        from netbox_kea.integrations.dhcp_import import _server_import_lock

        server = _make_db_server(name="lock-lost")
        with self.assertLogs("netbox_kea.integrations.dhcp_import", "ERROR") as logs:
            with _server_import_lock(server), connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s, %s)", _lock_key(server))

        self.assertIn("was not held at release", logs.output[0])


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


_STALE_SUBNET = "Dhcp4/subnet4[id=41]"
_STALE_POOL = f"{_STALE_SUBNET}/pools[pool=192.0.2.10-192.0.2.20]"
_STALE_IN_SUBNET = f"{_STALE_SUBNET}/reservations[hw-address=02:00:00:00:00:41]"
_STALE_GLOBAL = "Dhcp4/reservations[duid=01:02:03:04:41]"


def _stale_config() -> dict[int, dict[str, Any]]:
    """Return a DHCPv4 configuration with one mapped row of each kind that a run can remove."""
    return {
        4: {
            "option-def": [{"name": "site-code", "code": 241, "type": "uint8", "space": "dhcp4"}],
            "client-classes": [{"name": "voip", "test": "option[60].hex == 'voip'"}],
            "subnet4": [
                {
                    "id": 41,
                    "subnet": "192.0.2.0/24",
                    "pools": [{"pool": "192.0.2.10-192.0.2.20", "option-data": [{"code": 241, "data": "5"}]}],
                },
                {"id": 42, "subnet": "198.51.100.0/24", "pools": [{"pool": "198.51.100.10-198.51.100.20"}]},
            ],
        }
    }


def _stale_hosts() -> dict[int, list[dict[str, Any]]]:
    return {
        4: [
            {"subnet-id": 41, "hw-address": "02:00:00:00:00:41", "ip-address": "192.0.2.50"},
            {"subnet-id": 0, "duid": "01:02:03:04:41"},
        ]
    }


class StaleRemovalTest(_ImportRunTestCase):
    """A Complete run removes each mapped row whose Kea source it no longer observes, and reports it."""

    def _sync(self, config: dict, hosts: dict) -> DhcpImportRun:
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[self.server.pk])
        with stub_kea(_sync_responses(config, hosts)):
            self.client.post(url)
        return DhcpImportRun.objects.filter(server=self.server)[0]

    def _removed(self, run: DhcpImportRun) -> set[tuple[str, str]]:
        return set(
            DhcpImportEntry.objects.filter(run=run)
            .filter(outcome=Outcome.REMOVED.value)
            .values_list("kind", "kea_path")
        )

    def _mapped(self, kind: Kind) -> list:
        from netbox_kea.models import KeaDhcpLink

        return [link.sys4_object for link in KeaDhcpLink.objects.filter(server=self.server, kind=kind.value)]

    def setUp(self):
        super().setUp()
        self.config, self.hosts = _stale_config(), _stale_hosts()
        first = self._sync(self.config, self.hosts)
        self.assertFalse(first.entries.filter(reason=Reason.WRITE_FAILED.value).exists())
        self.assertEqual(len(self._mapped(Kind.RESERVATION)), 2)

    def test_a_subnet_that_kea_no_longer_reports_is_removed_with_its_pool_and_the_ipam_objects_stay(self):
        from ipam.models import IPRange, Prefix

        subnet = next(row for row in self._mapped(Kind.SUBNET) if row.subnet_id == 42)
        prefix, ip_range = subnet.prefix_id, subnet.child_pools.get().ip_range_id
        del self.config[4]["subnet4"][1]

        run = self._sync(self.config, self.hosts)

        self.assertEqual(
            self._removed(run),
            {
                ("subnet", "Dhcp4/subnet4[id=42]"),
                ("pool", "Dhcp4/subnet4[id=42]/pools[pool=198.51.100.10-198.51.100.20]"),
            },
        )
        self.assertEqual([row.subnet_id for row in self._mapped(Kind.SUBNET)], [41])
        self.assertEqual(len(self._mapped(Kind.POOL)), 1)
        self.assertFalse(apps.get_model(DHCP_PLUGIN, "Subnet").objects.filter(pk=subnet.pk).exists())
        self.assertTrue(Prefix.objects.filter(pk=prefix).exists())
        self.assertTrue(IPRange.objects.filter(pk=ip_range).exists())

    def test_a_pool_whose_range_changed_is_removed_and_the_new_pool_is_created(self):
        from ipam.models import IPRange

        old = next(row for row in self._mapped(Kind.POOL) if row.subnet.subnet_id == 42)
        self.config[4]["subnet4"][1]["pools"] = [{"pool": "198.51.100.30-198.51.100.40"}]

        run = self._sync(self.config, self.hosts)

        subnet = "Dhcp4/subnet4[id=42]"
        self.assertEqual(self._removed(run), {("pool", f"{subnet}/pools[pool=198.51.100.10-198.51.100.20]")})
        self.assertIn(("pool", "created", "", f"{subnet}/pools[pool=198.51.100.30-198.51.100.40]"), _entries(run))
        self.assertFalse(apps.get_model(DHCP_PLUGIN, "Pool").objects.filter(pk=old.pk).exists())
        self.assertTrue(IPRange.objects.filter(pk=old.ip_range_id).exists())
        self.assertEqual(len(self._mapped(Kind.POOL)), 2)

    def test_reservations_that_kea_no_longer_reports_are_removed_and_their_addresses_stay(self):
        from ipam.models import IPAddress

        in_subnet = next(row for row in self._mapped(Kind.RESERVATION) if row.subnet_id is not None)
        address = in_subnet.ipv4_address_id
        self.assertIsNotNone(address)

        run = self._sync(self.config, {4: []})

        self.assertEqual(self._removed(run), {("reservation", _STALE_IN_SUBNET), ("reservation", _STALE_GLOBAL)})
        self.assertEqual(self._mapped(Kind.RESERVATION), [])
        self.assertTrue(IPAddress.objects.filter(pk=address).exists())

    def test_a_client_class_that_kea_no_longer_defines_is_removed(self):
        self.config[4]["client-classes"] = []

        run = self._sync(self.config, self.hosts)

        self.assertEqual(self._removed(run), {("client_class", "Dhcp4/client-classes[name=voip]")})
        self.assertEqual(self._mapped(Kind.CLIENT_CLASS), [])

    def test_an_option_definition_is_removed_once_the_removal_of_its_pool_removes_the_last_option(self):
        self.config[4]["option-def"] = []
        self.config[4]["subnet4"][0]["pools"] = [{"pool": "192.0.2.30-192.0.2.40"}]

        run = self._sync(self.config, self.hosts)

        self.assertEqual(
            self._removed(run),
            {
                ("pool", _STALE_POOL),
                ("option", f"{_STALE_POOL}/option-data[code=241]"),
                ("option_definition", "Dhcp4/option-def[code=241]"),
            },
        )
        self.assertEqual(self._mapped(Kind.OPTION_DEFINITION), [])

    def test_an_option_definition_that_an_option_still_uses_is_kept_and_reported(self):
        self.config[4]["option-def"] = []

        run = self._sync(self.config, self.hosts)

        self.assertEqual(self._removed(run), set())
        self.assertEqual(len(self._mapped(Kind.OPTION_DEFINITION)), 1)
        entry = DhcpImportEntry.objects.filter(run=run).get(
            kind=Kind.OPTION_DEFINITION.value, reason=Reason.REMOVAL_BLOCKED.value
        )
        self.assertEqual((entry.outcome, entry.kea_path), (Outcome.SKIPPED.value, "Dhcp4/option-def[code=241]"))
        self.assertEqual(entry.detail, "It is kept while it is in use by 1 Option.")

    @override_settings(EVENTS_PIPELINE=["netbox_kea.tests.utils.record_dispatched_events"])
    def test_a_blocked_class_removal_dispatches_no_event_for_the_options_of_the_class(self):
        from netbox_kea.models import KeaDhcpLink

        Option = apps.get_model(DHCP_PLUGIN, "Option")
        boot = {
            "name": "boot",
            "test": "option[93].hex == 0x0007",
            "option-def": [{"name": "boot-flag", "code": 231, "space": "dhcp4", "type": "uint8"}],
            "option-data": [{"code": 231, "data": "1"}],
        }
        with_boot = copy.deepcopy(self.config)
        with_boot[4]["client-classes"].append(boot)
        with_boot[4]["option-data"] = [{"code": 15, "data": "boot.example.org", "client-classes": ["boot"]}]
        self._sync(with_boot, self.hosts)
        own = Option.objects.get(definition__code=231)
        # An operator takes over both Options: without a mapping, an Option is never stale on its own.
        naming = Option.objects.get(definition__code=15)
        option_type = ContentType.objects.get_for_model(Option)
        KeaDhcpLink.objects.filter(object_type=option_type, object_id__in=[own.pk, naming.pk]).delete()
        DISPATCHED_EVENTS.clear()
        self.addCleanup(DISPATCHED_EVENTS.clear)

        # Kea drops the class and the option that names it, so the operator's global Option keeps the class.
        run = self._sync(self.config, self.hosts)

        entry = DhcpImportEntry.objects.get(run=run, kea_path="Dhcp4/client-classes[name=boot]")
        self.assertEqual(entry.reason, Reason.REMOVAL_BLOCKED.value)
        self.assertTrue(Option.objects.filter(pk=own.pk).exists())
        deleted = [
            (event["object_type"].app_label, event["object_type"].model, event["object_id"])
            for event in DISPATCHED_EVENTS
            if event["event_type"] == "object_deleted"
        ]
        self.assertNotIn((DHCP_PLUGIN, "option", own.pk), deleted)

    def test_a_removal_is_change_logged_for_the_target_and_its_mapping(self):
        from core.models import ObjectChange

        from netbox_kea.models import KeaDhcpLink

        subnet = next(row for row in self._mapped(Kind.SUBNET) if row.subnet_id == 42)
        del self.config[4]["subnet4"][1]

        self._sync(self.config, self.hosts)

        deletions = ObjectChange.objects.filter(action="delete")
        target = deletions.get(
            changed_object_type=ContentType.objects.get_for_model(subnet), changed_object_id=subnet.pk
        )
        mapping = deletions.get(
            changed_object_type=ContentType.objects.get_for_model(KeaDhcpLink),
            prechange_data__kind="subnet",
            prechange_data__kea_subnet_id=42,
        )
        # Native revert and squash group history by request (ADR 0008), so both deletions share one.
        self.assertEqual(mapping.request_id, target.request_id)
        self.assertEqual(mapping.prechange_data["object_id"], subnet.pk)

    def test_an_unmapped_pool_in_a_stale_subnet_keeps_the_subnet_and_the_run_counts_it(self):
        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        mapped = next(row for row in self._mapped(Kind.POOL) if row.subnet.subnet_id == 42)
        from ipam.models import IPRange
        from netaddr import IPNetwork

        operator_range = IPRange.objects.create(
            start_address=IPNetwork("198.51.100.200/24"), end_address=IPNetwork("198.51.100.210/24")
        )
        Pool.objects.create(name="operator pool", subnet=mapped.subnet, ip_range=operator_range)
        del self.config[4]["subnet4"][1]

        run = self._sync(self.config, self.hosts)

        self.assertEqual(self._removed(run), {("pool", "Dhcp4/subnet4[id=42]/pools[pool=198.51.100.10-198.51.100.20]")})
        entry = DhcpImportEntry.objects.filter(run=run).get(kind=Kind.SUBNET.value, reason=Reason.REMOVAL_BLOCKED.value)
        self.assertEqual(entry.kea_path, "Dhcp4/subnet4[id=42]")
        self.assertEqual(entry.detail, "It is kept because its removal would also remove 1 Pool.")
        self.assertEqual(sorted(row.subnet_id for row in self._mapped(Kind.SUBNET)), [41, 42])
        # A Server viewer reads the run, and may not view the Pool, so the run must not name it.
        viewer = get_user_model().objects.create_user("stale-removal-viewer")
        _grant([Server], ["view"], user=viewer)
        self.client.force_login(viewer)
        page = self.client.get(reverse("plugins:netbox_kea:server_dhcp_plugin", args=[self.server.pk]))
        self.assertContains(page, "would also remove 1 Pool")
        self.assertNotContains(page, "operator pool")

    def test_a_stale_subnet_keeps_a_mapped_reservation_that_an_incomplete_observation_cannot_judge(self):
        del self.config[4]["subnet4"][0]

        # The Reservation of Subnet 41 now names a Subnet that Kea does not have, so the Snapshot quarantines it.
        run = self._sync(self.config, self.hosts)

        # The Option of the Pool is judged by the Pool observation, which is Complete.
        self.assertEqual(
            self._removed(run), {("pool", _STALE_POOL), ("option", f"{_STALE_POOL}/option-data[code=241]")}
        )
        entry = DhcpImportEntry.objects.filter(run=run).get(kind=Kind.SUBNET.value, reason=Reason.REMOVAL_BLOCKED.value)
        self.assertEqual(entry.kea_path, _STALE_SUBNET)
        self.assertIn("host reservation", entry.detail.lower())
        self.assertEqual(sorted(row.subnet_id for row in self._mapped(Kind.SUBNET)), [41, 42])
        self.assertEqual(len(self._mapped(Kind.RESERVATION)), 2)

    def test_an_incomplete_configuration_keeps_every_configuration_row_and_reports_the_suppression(self):
        # A Subnet without a CIDR is a Subnet diagnostic, and the Subnet Catalogue cannot verify it either.
        self.config[4] = {"subnet4": [{"id": 43}]}

        run = self._sync(self.config, self.hosts)

        self.assertEqual(self._removed(run), set())
        self.assertEqual(len(self._mapped(Kind.SUBNET)), 2)
        self.assertEqual(len(self._mapped(Kind.POOL)), 2)
        self.assertEqual(len(self._mapped(Kind.CLIENT_CLASS)), 1)
        self.assertEqual(len(self._mapped(Kind.OPTION_DEFINITION)), 1)
        suppressed = {
            (entry.kind, entry.kea_path): entry.detail
            for entry in DhcpImportEntry.objects.filter(run=run).filter(reason=Reason.INCOMPLETE_OBSERVATION.value)
        }
        self.assertEqual(
            set(suppressed),
            {
                ("subnet", "Dhcp4/subnet4[*]"),
                ("pool", "Dhcp4/subnet4[*]/pools[*]"),
                ("client_class", "Dhcp4/client-classes[*]"),
                ("option_definition", "Dhcp4/option-def[*]"),
                ("option", "Dhcp4/option-data[*]"),
                ("reservation", "Dhcp4/reservations[*]"),
            },
        )
        self.assertEqual(
            suppressed[("subnet", "Dhcp4/subnet4[*]")],
            "The Server Configuration was not read in full. "
            "The configuration has 1 Subnet entry that is not valid. 2 mapped Subnet rows were kept.",
        )
        self.assertEqual(
            {
                entry.outcome
                for entry in DhcpImportEntry.objects.filter(run=run).filter(reason=Reason.INCOMPLETE_OBSERVATION.value)
            },
            {Outcome.SKIPPED.value},
        )

    def _assert_reservations_kept(self, run: DhcpImportRun, reason: str) -> None:
        self.assertEqual(self._removed(run), set())
        self.assertEqual(len(self._mapped(Kind.RESERVATION)), 2)
        entry = DhcpImportEntry.objects.filter(run=run).get(reason=Reason.INCOMPLETE_OBSERVATION.value)
        self.assertEqual((entry.kind, entry.kea_path), ("reservation", "Dhcp4/reservations[*]"))
        self.assertIn(reason, entry.detail)

    def test_a_failed_reservation_read_keeps_every_reservation(self):
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[self.server.pk])
        with stub_kea(_sync_responses(self.config, reservations_available=False)):
            self.client.post(url)

        self._assert_reservations_kept(DhcpImportRun.objects.filter(server=self.server)[0], "could not be read")

    def test_an_incomplete_subnet_catalogue_keeps_every_reservation(self):
        responses = _sync_responses(self.config)
        # subnet4-list and config-get disagree on the CIDR of Subnet 41, so the Catalogue is not consistent.
        responses["subnet4-list"] = _subnet_list(
            4, [{"id": 41, "subnet": "203.0.113.0/24"}, self.config[4]["subnet4"][1]]
        )
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[self.server.pk])
        with stub_kea(responses):
            self.client.post(url)

        # The read step refuses an Incomplete Catalogue before it reads the Reservation Snapshot.
        self._assert_reservations_kept(DhcpImportRun.objects.filter(server=self.server)[0], "could not be read")

    def test_a_quarantined_reservation_record_keeps_every_reservation(self):
        run = self._sync(self.config, {4: [{"subnet-id": 41, "hw-address": "not-a-mac"}]})

        self._assert_reservations_kept(run, "1 Reservation record could not be parsed")

    def _assert_kept_with_suppression(self, run: DhcpImportRun, kind: Kind, count: int) -> None:
        self.assertEqual(self._removed(run), set())
        self.assertEqual(len(self._mapped(kind)), count)
        entry = DhcpImportEntry.objects.filter(run=run).get(kind=kind.value, reason=Reason.INCOMPLETE_OBSERVATION.value)
        self.assertEqual(entry.outcome, Outcome.SKIPPED.value)

    def test_a_null_option_definition_collection_keeps_the_mapped_definitions(self):
        # The Pool that holds the Option goes, so only the Incomplete collection keeps the definition.
        self.config[4]["option-def"] = None
        self.config[4]["subnet4"][0]["pools"] = [{"pool": "192.0.2.10-192.0.2.20"}]
        del self.config[4]["subnet4"][1]["pools"]

        run = self._sync(self.config, self.hosts)

        self.assertEqual(len(self._mapped(Kind.OPTION_DEFINITION)), 1)
        entry = DhcpImportEntry.objects.filter(run=run).get(
            kind=Kind.OPTION_DEFINITION.value, reason=Reason.INCOMPLETE_OBSERVATION.value
        )
        self.assertEqual(entry.kea_path, "Dhcp4/option-def[*]")

    def test_a_null_pool_collection_keeps_the_mapped_pools(self):
        self.config[4]["subnet4"][1]["pools"] = None

        run = self._sync(self.config, self.hosts)

        self._assert_kept_with_suppression(run, Kind.POOL, 2)

    def test_a_client_class_whose_name_is_not_text_keeps_the_mapped_classes(self):
        self.config[4]["client-classes"] = [{"name": ["bad"]}]

        run = self._sync(self.config, self.hosts)

        self._assert_kept_with_suppression(run, Kind.CLIENT_CLASS, 1)
        self.assertTrue(
            DhcpImportEntry.objects.filter(
                run=run, kind=Kind.CLIENT_CLASS.value, reason=Reason.INVALID_KEA_DATA.value
            ).exists()
        )

    def test_a_null_client_class_collection_imports_nothing_and_removes_nothing(self):
        self.config[4]["client-classes"] = None

        run = self._sync(self.config, self.hosts)

        self.assertEqual(self._removed(run), set())
        self.assertEqual(len(self._mapped(Kind.CLIENT_CLASS)), 1)
        self.assertEqual(_entries(run), {("server", "not_imported", "invalid_kea_data", "Dhcp4")})

    def test_a_pool_range_that_overlaps_the_old_one_replaces_the_old_pool(self):
        subnet = "Dhcp4/subnet4[id=42]"
        for new in ("198.51.100.10-198.51.100.30", "198.51.100.15-198.51.100.25"):
            with self.subTest(new=new):
                old = next(row for row in self._mapped(Kind.POOL) if row.subnet.subnet_id == 42)
                old_text = f"{old.ip_range.start_address.ip}-{old.ip_range.end_address.ip}"
                self.config[4]["subnet4"][1]["pools"] = [{"pool": new}]

                run = self._sync(self.config, self.hosts)

                self.assertEqual(self._removed(run), {("pool", f"{subnet}/pools[pool={old_text}]")})
                self.assertIn(("pool", "created", "", f"{subnet}/pools[pool={new}]"), _entries(run))
                self.assertFalse(DhcpImportEntry.objects.filter(run=run, kind="pool", outcome="skipped").exists())
                pool = next(row for row in self._mapped(Kind.POOL) if row.subnet.subnet_id == 42)
                self.assertEqual(f"{pool.ip_range.start_address.ip}-{pool.ip_range.end_address.ip}", new)

    def test_an_older_read_never_removes_a_row_that_a_newer_import_mapped(self):
        from netbox_kea.integrations import dhcp_plugin
        from netbox_kea.integrations.dhcp_import import FamilyRead, read_family

        # Import A reads Kea, which has no Subnet 43 yet, and pauses before its apply.
        with stub_kea(_sync_responses(self.config, self.hosts)):
            older = read_family(self.server, 4)
        self.assertIsInstance(older, FamilyRead)
        # Kea gains Subnet 43, and import B reads and imports it.
        newer = {4: {**self.config[4], "subnet4": [*self.config[4]["subnet4"], {"id": 43, "subnet": "203.0.113.0/24"}]}}
        self._sync(newer, self.hosts)
        self.assertIn(43, [row.subnet_id for row in self._mapped(Kind.SUBNET)])

        summary = dhcp_plugin.import_server_config(self.server, older.config, older.reservations)

        self.assertEqual([entry for entry in summary.entries if entry.outcome == Outcome.REMOVED], [])
        self.assertIn(43, [row.subnet_id for row in self._mapped(Kind.SUBNET)])


_V6_CONFIG = {
    "subnet6": [
        {"id": 61, "subnet": "2001:db8:61::/64", "pools": [{"pool": "2001:db8:61::10-2001:db8:61::20"}]},
        {"id": 62, "subnet": "2001:db8:62::/64"},
    ]
}
_V6_HOSTS = [{"subnet-id": 61, "duid": "01:02:03:04:61", "ip-addresses": ["2001:db8:61::50"]}]


class StaleRemovalScopeTest(_ImportRunTestCase):
    """A run removes only the stale rows of its own Server and family."""

    def _sync(self, server: Server, config: dict, hosts: dict) -> DhcpImportRun:
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[server.pk])
        with stub_kea(_sync_responses(config, hosts)):
            self.client.post(url)
        return DhcpImportRun.objects.filter(server=server)[0]

    def _mapped(self, server: Server, family: int) -> set[tuple[str, int | None, str | None]]:
        from netbox_kea.models import KeaDhcpLink

        links = KeaDhcpLink.objects.filter(server=server, family=family).exclude(kind=Kind.SERVER.value)
        return set(links.values_list("kind", "kea_subnet_id", "kea_identity"))

    def setUp(self):
        super().setUp()
        Server.objects.filter(pk=self.server.pk).update(dhcp6=True)
        self.server.refresh_from_db()
        self.v4 = {"subnet4": [{"id": 71, "subnet": "192.0.2.0/24", "pools": [{"pool": "192.0.2.10-192.0.2.20"}]}]}
        self._sync(self.server, {4: self.v4, 6: _V6_CONFIG}, {4: [], 6: _V6_HOSTS})
        self.other = _make_db_server(name="import-result-other", sync_dhcp_plugin_enabled=True, dhcp6=False)
        other_v4 = {"subnet4": [{"id": 81, "subnet": "198.51.100.0/24"}]}
        self._sync(self.other, {4: other_v4}, {4: []})
        self.before = {family: self._mapped(self.server, family) for family in (4, 6)}
        self.other_before = self._mapped(self.other, 4)
        self.assertEqual(len(self.before[6]), 4)

    def test_a_dhcpv6_subnet_that_kea_no_longer_reports_is_removed_with_its_pool_and_reservation(self):
        run = self._sync(self.server, {4: self.v4, 6: {"subnet6": _V6_CONFIG["subnet6"][1:]}}, {4: [], 6: []})

        subnet = "Dhcp6/subnet6[id=61]"
        self.assertEqual(
            set(DhcpImportEntry.objects.filter(run=run, outcome="removed").values_list("family", "kind", "kea_path")),
            {
                (6, "subnet", subnet),
                (6, "pool", f"{subnet}/pools[pool=2001:db8:61::10-2001:db8:61::20]"),
                (6, "reservation", f"{subnet}/reservations[duid=01:02:03:04:61]"),
            },
        )
        self.assertEqual(self._mapped(self.server, 6), {("subnet", 62, None)})
        self.assertEqual(self._mapped(self.server, 4), self.before[4])
        self.assertEqual(self._mapped(self.other, 4), self.other_before)

    def test_a_dhcpv4_run_removes_nothing_of_dhcpv6_or_of_another_server(self):
        Server.objects.filter(pk=self.server.pk).update(dhcp6=False)

        run = self._sync(self.server, {4: {"subnet4": []}}, {4: []})

        self.assertEqual(
            set(DhcpImportEntry.objects.filter(run=run, outcome="removed").values_list("family", "kind")),
            {(4, "subnet"), (4, "pool")},
        )
        self.assertEqual(self._mapped(self.server, 4), set())
        self.assertEqual(self._mapped(self.server, 6), self.before[6])
        self.assertEqual(self._mapped(self.other, 4), self.other_before)
