# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The display cache module: records rotation around Kea writes, TTLs from the settings row, settings generation."""

from collections.abc import Callable
from dataclasses import dataclass

import requests
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

import netbox_kea
from netbox_kea import display_cache, server_configuration, subnet_catalogue
from netbox_kea.constants import Family
from netbox_kea.kea import KeaCommand
from netbox_kea.models import DisplayCacheConfig, Server

from .kea_stub import _catalogue_responses_for_subnets, stub_kea
from .utils import _make_db_server, _ViewTestBase, with_display_cache_config, with_kea_client_config

_RESERVATION = {"subnet-id": 1, "identifier-type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff"}
_DELETED = {"result": 0, "text": "Host deleted."}


@dataclass(frozen=True)
class _Read:
    """A display read result that the cache stores when it is settled."""

    number: int
    settled: bool = True


class RecordsGenerationTest(TestCase):
    """``KeaClient.command()`` rotates the records generation of its target family around each write command."""

    def setUp(self):
        self.server = _make_db_server()

    def _records(self, family: Family) -> str:
        return display_cache._generation(self.server, family, "records")

    def _answer_and_observe(self, reply: object) -> tuple[Callable[[dict], object], list[str]]:
        """Return a stub answer that records the DHCPv4 records generation when the transport receives the command."""
        observed: list[str] = []

        def answer(body: dict) -> object:
            observed.append(self._records(4))
            if isinstance(reply, Exception):
                raise reply
            return reply

        return answer, observed

    def test_a_write_command_rotates_the_records_generation_before_and_after_the_send(self):
        before = self._records(4)
        answer, at_send = self._answer_and_observe(_DELETED)

        with stub_kea({"reservation-del": answer}) as kea:
            self.server.get_client(version=4).command(KeaCommand.RESERVATION_DEL, 4, arguments=_RESERVATION)

        self.assertEqual(kea.commands(), ["reservation-del"])
        self.assertNotEqual(at_send, [before], "the generation rotates before the send")
        self.assertNotEqual(self._records(4), at_send[0], "the generation rotates after the reply")

    def test_a_write_whose_reply_is_lost_rotates_the_records_generation_after_the_send(self):
        answer, at_send = self._answer_and_observe(requests.ConnectionError("reply lost"))

        with stub_kea({"reservation-del": answer}), self.assertRaises(requests.ConnectionError):
            self.server.get_client(version=4).command(KeaCommand.RESERVATION_DEL, 4, arguments=_RESERVATION)

        self.assertEqual(len(at_send), 1)
        self.assertNotEqual(self._records(4), at_send[0], "Kea can apply a write whose reply is lost")

    def test_a_write_rotates_only_the_records_generation_of_its_target_family(self):
        before = (self._records(4), self._records(6))

        with stub_kea({"reservation-del": _DELETED}):
            self.server.get_client(version=6).command(KeaCommand.RESERVATION_DEL, 6, arguments=_RESERVATION)

        self.assertEqual(self._records(4), before[0])
        self.assertNotEqual(self._records(6), before[1])

    def test_a_write_with_no_family_target_rotates_both_families(self):
        before = (self._records(4), self._records(6))

        with stub_kea({"dhcp-disable": {"result": 0}}):
            self.server.get_client().command(KeaCommand.DHCP_DISABLE, None)

        self.assertNotEqual(self._records(4), before[0])
        self.assertNotEqual(self._records(6), before[1])

    def test_a_read_command_keeps_the_records_generation(self):
        before = self._records(4)

        with stub_kea({"config-get": {"result": 0, "arguments": {"Dhcp4": {}}}}):
            self.server.get_client(version=4).command(KeaCommand.CONFIG_GET, 4)

        self.assertEqual(self._records(4), before)

    def test_a_rotation_failure_is_logged_and_the_write_is_sent(self):
        unsaved = Server(name="unsaved", ca_url="https://kea.example.com", has_control_agent=True)

        with (
            stub_kea({"reservation-del": _DELETED}) as kea,
            self.assertLogs("netbox_kea.kea", "ERROR") as logs,
        ):
            reply = unsaved.get_client(version=4).command(KeaCommand.RESERVATION_DEL, 4, arguments=_RESERVATION)

        self.assertEqual(reply, [_DELETED])
        self.assertEqual(kea.commands(), ["reservation-del"])
        self.assertEqual(
            [record.getMessage() for record in logs.records],
            [f"The display cache rotation {when} Kea command reservation-del failed" for when in ("before", "after")],
        )


class ConfigurationWriteTest(TestCase):
    """A configuration mutation rotates the configuration generation and the records generation around its send."""

    def setUp(self):
        self.server = _make_db_server()

    def _generations(self) -> tuple[str, str]:
        return display_cache._generation(self.server, 4, "configuration"), display_cache._generation(
            self.server, 4, "records"
        )

    def test_a_configuration_mutation_rotates_both_generations_before_and_after_the_send(self):
        before = self._generations()
        at_send = []

        def answer(body: dict) -> object:
            at_send.append(self._generations())
            return {"result": 0, "text": "Subnet deleted."}

        with stub_kea({"subnet4-del": answer}) as kea:
            self.server.get_client(version=4).subnet_del(4, 1)

        self.assertEqual(kea.commands(), ["subnet4-del"])
        after = self._generations()
        for index, name in enumerate(("configuration", "records")):
            with self.subTest(generation=name):
                self.assertNotEqual(at_send[0][index], before[index], "rotated before the send")
                self.assertNotEqual(after[index], at_send[0][index], "rotated after the reply")

    def test_a_configuration_mutation_from_a_client_without_a_family_rotates_its_family(self):
        before = display_cache._generation(self.server, 6, "configuration")

        with stub_kea({"subnet6-del": {"result": 0, "text": "Subnet deleted."}}):
            self.server.get_client().subnet_del(6, 1)

        self.assertNotEqual(display_cache._generation(self.server, 6, "configuration"), before)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class DisplayCacheSettingsTest(TestCase):
    """Each TTL comes from the DisplayCacheConfig row, and a save of the row makes every entry unused."""

    def setUp(self):
        self.server = _make_db_server()
        self.responses = _catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.1.0/24"}])

    def _read_display(self) -> list[str]:
        with stub_kea(self.responses) as kea:
            server_configuration.display(self.server, 4)
            subnet_catalogue.display(self.server, 4)
        return kea.commands()

    def _entries(self):
        return cache.keys(f"{display_cache.KEY_PREFIX}entry:*")

    def _assert_warm(self) -> list[str]:
        live = self._read_display()
        self.assertIn("config-get", live)
        self.assertEqual(self._read_display(), [], "the second read is cached")
        return live

    @with_display_cache_config(configuration_ttl=0)
    def test_a_ttl_of_0_sends_every_display_read_to_kea(self):
        live = self._read_display()

        self.assertEqual(self._read_display(), live)
        self.assertEqual(self._entries(), [])

    @with_display_cache_config(configuration_ttl=123)
    def test_the_configuration_ttl_of_the_settings_row_reaches_the_cache(self):
        self._read_display()

        entries = self._entries()
        self.assertEqual(len(entries), 2, "one Server Configuration and one Catalogue entry")
        for key in entries:
            with self.subTest(key=key):
                self.assertTrue(100 < cache.ttl(key) <= 123, cache.ttl(key))

    def test_a_save_of_the_settings_row_with_the_same_values_makes_a_warm_entry_miss(self):
        live = self._assert_warm()

        DisplayCacheConfig.get().save()

        self.assertEqual(self._read_display(), live)

    def test_a_save_of_one_field_of_the_settings_row_makes_a_warm_entry_miss(self):
        live = self._assert_warm()

        row = DisplayCacheConfig.get()
        row.leases_ttl = 60
        row.save(update_fields=["leases_ttl"])

        self.assertEqual(self._read_display(), live)

    def test_a_rotation_of_the_configuration_generation_makes_a_warm_entry_miss(self):
        live = self._assert_warm()

        display_cache.rotate_configuration(self.server, 4)

        self.assertEqual(self._read_display(), live)

    def test_a_failed_configuration_read_is_read_again_on_the_next_call(self):
        failed = {"config-get": {"result": 1, "text": "failed"}}
        for _ in range(2):
            with self.subTest(read=_), stub_kea(failed) as kea:
                snapshot = server_configuration.display(self.server, 4)
            self.assertFalse(snapshot.settled)
            self.assertEqual(kea.commands(), ["config-get"])
        self.assertEqual(self._entries(), [])

    def test_an_unsettled_catalogue_is_read_again_on_the_next_call(self):
        failed = {**self.responses, "subnet4-list": {"result": 1, "text": "failed"}}
        for _ in range(2):
            with self.subTest(read=_), stub_kea(failed) as kea:
                snapshot = subnet_catalogue.display(self.server, 4)
            self.assertFalse(snapshot.settled)
            self.assertEqual(kea.commands(), ["subnet4-list", "config-get"])
        self.assertEqual(self._entries(), [])

    def test_a_settings_row_without_last_updated_refuses_the_display_read(self):
        DisplayCacheConfig.objects.filter(pk=1).update(last_updated=None)

        with stub_kea(self.responses) as kea, self.assertRaisesMessage(RuntimeError, "no last_updated"):
            server_configuration.display(self.server, 4)
        self.assertEqual(kea.commands(), [])

    def test_a_generation_that_is_not_a_string_refuses_the_display_read(self):
        cache.set(display_cache._generation_key(self.server, 4, "configuration"), 7, None)

        with stub_kea(self.responses) as kea, self.assertRaisesMessage(RuntimeError, "not a generation"):
            server_configuration.display(self.server, 4)
        self.assertEqual(kea.commands(), [])

    def test_a_plain_write_keeps_the_configuration_entries(self):
        self._assert_warm()

        with stub_kea({"reservation-del": {"result": 0, "text": "Host deleted."}}):
            self.server.get_client(version=4).command(
                KeaCommand.RESERVATION_DEL,
                4,
                arguments={"subnet-id": 1, "identifier-type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff"},
            )

        self.assertEqual(self._read_display(), [])

    def test_a_rotation_of_the_records_generation_keeps_the_configuration_entries(self):
        self._assert_warm()

        display_cache.rotate_after_write(self.server, 4, configuration=False)

        self.assertEqual(self._read_display(), [])


class DisplayCacheSettingsPageTest(_ViewTestBase):
    """A save of the Display Cache section on the Settings page makes every cached entry unused."""

    def test_a_save_of_the_section_makes_a_warm_entry_miss(self):
        responses = _catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.1.0/24"}])
        with stub_kea(responses):
            subnet_catalogue.display(self.server, 4)
        with stub_kea({}) as kea:
            subnet_catalogue.display(self.server, 4)
        self.assertEqual(kea.commands(), [], "the second read is cached")

        response = self.client.post(
            reverse("plugins:netbox_kea:settings_section", args=["display-cache"]),
            {
                "display-cache-configuration_ttl": 300,
                "display-cache-reservations_ttl": 300,
                "display-cache-leases_ttl": 30,
                "display-cache-status_ttl": 15,
            },
            follow=True,
        )

        self.assertContains(response, "Display Cache saved.")
        with stub_kea(responses) as kea:
            subnet_catalogue.display(self.server, 4)
        self.assertIn("subnet4-list", kea.commands())


@with_display_cache_config(configuration_ttl=300, reservations_ttl=77)
class RecordsKindTest(TestCase):
    """A records kind takes its own TTL, and its key holds the records and the configuration generation."""

    def setUp(self):
        self.server = _make_db_server()
        self.reads = 0

    def _read(self, settled: bool = True) -> _Read:
        self.reads += 1
        return _Read(self.reads, settled)

    def _reservations(self, query: tuple = ("page",), *, refresh: bool = False, settled: bool = True) -> _Read:
        return display_cache.cached(
            self.server, 4, "reservations", lambda: self._read(settled), query=query, refresh=refresh
        )

    def test_the_key_holds_the_plugin_version(self):
        key = display_cache._entry_key(self.server, 4, "reservations", DisplayCacheConfig.get(), ("page",))

        self.assertIn(netbox_kea.__version__, key.split(":"))

    def test_a_display_read_for_an_unsaved_server_names_the_display_cache_key(self):
        self.server.pk = None

        with self.assertRaisesMessage(ValueError, "display cache key requires a persisted Server"):
            self._reservations()

    def test_the_reservations_ttl_of_the_settings_row_reaches_the_cache(self):
        self._reservations()

        [key] = cache.keys(f"{display_cache.KEY_PREFIX}entry:*")
        self.assertTrue(60 < cache.ttl(key) <= 77, cache.ttl(key))

    def test_a_rotation_of_either_generation_makes_a_warm_entry_miss(self):
        for rotate in (
            lambda: display_cache.rotate_after_write(self.server, 4, configuration=False),
            lambda: display_cache.rotate_configuration(self.server, 4),
        ):
            first = self._reservations()
            self.assertEqual(self._reservations(), first, "the second read is cached")
            rotate()
            self.assertNotEqual(self._reservations(), first)

    def test_each_query_has_its_own_entry(self):
        first = self._reservations(("page", None))

        self.assertNotEqual(self._reservations(("page", "")), first)
        self.assertEqual(self._reservations(("page", None)), first)

    def test_a_refresh_replaces_the_entry_and_an_unsettled_refresh_removes_it(self):
        self._reservations()

        refreshed = self._reservations(refresh=True)
        self.assertEqual(self._reservations(), refreshed)

        self._reservations(refresh=True, settled=False)
        self.assertEqual(self._reservations(), _Read(self.reads), "the next read is live")
