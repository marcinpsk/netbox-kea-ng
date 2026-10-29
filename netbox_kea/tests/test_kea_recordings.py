# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Parse configuration replies recorded from a real Kea, not hand-written stubs.

The recordings come from scripts/record_kea_config_get.py, which runs the coverage
configurations in kea_recordings/ on the Compose harness Kea version. The Control Agent
replies come from Kea 3.0, the last release series that has a Control Agent.
"""

import copy
import ipaddress
import json
import re
from pathlib import Path

from django.test import TestCase

from netbox_kea import server_configuration
from netbox_kea.kea import KeaException
from netbox_kea.subnet_catalogue import CatalogueUnavailable, CompleteCatalogueSnapshot, display, for_synchronization
from netbox_kea.subnet_settings import DeclaredReservationFlags, ReservationFlags
from netbox_kea.tests.kea_stub import _network_absent, _network_present, kea_client, queued, stub_kea
from netbox_kea.tests.utils import _make_db_server, with_kea_client_config

_RECORDINGS = Path(__file__).with_name("kea_recordings")
_COMPOSE_OVERRIDE = Path(__file__).resolve().parents[2] / "tests" / "docker" / "docker-compose.override.yml"


def _recording(family: int) -> dict:
    return json.loads((_RECORDINGS / f"dhcp{family}.json").read_text())


def _accepted_keys() -> dict:
    return json.loads((_RECORDINGS / "accepted-keys.json").read_text())


def test_recordings_come_from_the_harness_kea_version():
    harness = re.findall(r"kea-dhcp[46]:\$\{KEA_VERSION:-([^}]+)\}", _COMPOSE_OVERRIDE.read_text())
    assert len(harness) == 2, harness
    recorded = {_recording(4)["kea-version"], _recording(6)["kea-version"], _accepted_keys()["kea-version"]}
    assert recorded == set(harness)


def test_the_targeted_shared_network_read_parses_both_recorded_replies():
    for family in (4, 6):
        recorded = _recording(family)[f"network{family}-get"]
        with stub_kea({f"network{family}-get": queued(recorded["present"], recorded["absent"])}) as kea:
            client = kea_client("http://kea.example.com", send_service=False)
            assert client.shared_network_exists(family, "office") is True
            assert client.shared_network_exists(family, "absent") is False
        assert [body["arguments"] for body in kea.bodies(f"network{family}-get")] == [
            {"name": "office"},
            {"name": "absent"},
        ]


def test_the_shared_network_stub_replies_match_the_recorded_ones():
    for family in (4, 6):
        recorded = _recording(family)[f"network{family}-get"]
        assert _network_absent("absent") == recorded["absent"]
        present = _network_present(family, "office")
        assert present["text"] == recorded["present"]["text"]
        assert present["arguments"]["shared-networks"][0]["name"] == "office"
        assert set(present["arguments"]["shared-networks"][0]) <= set(
            recorded["present"]["arguments"]["shared-networks"][0]
        )


def test_the_control_agent_forwarding_failure_is_recognized_only_through_an_agent():
    recording = json.loads((_RECORDINGS / "control-agent.json").read_text())
    assert recording["kea-version"].startswith("3.0.")
    agent = kea_client("http://kea.example.com", send_service=True)
    daemon = kea_client("http://kea.example.com", send_service=False)
    for family in (4, 6):
        other = 6 if family == 4 else 4
        for command in (f"network{family}-add", f"network{family}-del"):
            failure = KeaException(recording[command])
            assert agent.forwarding_failed(failure, family)
            assert not agent.forwarding_failed(failure, other)
            assert not daemon.forwarding_failed(failure, family)


def test_the_accepted_keys_cover_every_key_kea_returned():
    for family in (4, 6):
        daemon = _recording(family)["config-get"]["arguments"][f"Dhcp{family}"]
        networks = daemon["shared-networks"]
        subnets = [
            *daemon[f"subnet{family}"],
            *(subnet for network in networks for subnet in network[f"subnet{family}"]),
        ]
        accepted = _accepted_keys()[f"dhcp{family}"]
        assert {key for network in networks for key in network} <= set(accepted["shared-networks"])
        assert {key for subnet in subnets for key in subnet} <= set(accepted[f"subnet{family}"])
        assert "description" not in accepted["shared-networks"]


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestRecordedKeaConfiguration(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def _snapshot(self, family: int) -> server_configuration.ServerConfigurationSnapshot:
        with stub_kea({"config-get": _recording(family)["config-get"]}):
            return server_configuration.for_verification(self.server, family)

    def test_every_recorded_fact_parses_without_a_diagnostic(self):
        for family in (4, 6):
            with self.subTest(family=family):
                snapshot = self._snapshot(family)
                self.assertEqual(snapshot.diagnostics, ())
                self.assertTrue(snapshot.available)
                self.assertTrue(snapshot.complete)
                self.assertTrue(snapshot.global_options_complete)
                self.assertTrue(snapshot.shared_networks_complete)
                self.assertTrue(all(subnet.complete for subnet in snapshot.subnets))
                self.assertTrue(all(network.complete for network in snapshot.shared_networks))

    def test_recorded_facts_keep_their_values(self):
        cases = {
            4: ("192.0.2.0/24", "198.51.100.1", 10, ("uint8", "string")),
            6: ("2001:db8:1::/64", "2001:db8:ffff::1", 10, ("uint16", "string")),
        }
        for family, (cidr, relay, global_options, record_types) in cases.items():
            with self.subTest(family=family):
                snapshot = self._snapshot(family)
                self.assertEqual(
                    [(subnet.declared_subnet_id, subnet.shared_network_name) for subnet in snapshot.subnets],
                    [(10, None), (20, "office"), (21, "office")],
                )
                standalone = snapshot.subnets[0]
                self.assertEqual(standalone.declared_cidr, cidr)
                self.assertEqual(len(standalone.configuration.pools), 2)
                settings = standalone.configuration.settings
                self.assertEqual(settings.relay_addresses, (ipaddress.ip_address(relay),))
                self.assertEqual(settings.client_classes, ("voip",))
                self.assertEqual(settings.require_client_classes, ("printers",))
                self.assertEqual(settings.allocator, "random")
                self.assertEqual(settings.ddns_qualifying_suffix, "")
                self.assertEqual(
                    [
                        (network.name, network.description, len(network.member_cidrs))
                        for network in snapshot.shared_networks
                    ],
                    [("empty-network", None, 0), ("office", "Office floors", 2)],
                )
                self.assertEqual(len(snapshot.global_options), global_options)
                self.assertIn(record_types, [definition.record_types for definition in snapshot.option_definitions])

    def test_the_recorded_catalogue_is_complete_for_synchronization(self):
        for family in (4, 6):
            with self.subTest(family=family):
                recording = _recording(family)
                with stub_kea(
                    {"config-get": recording["config-get"], f"subnet{family}-list": recording[f"subnet{family}-list"]}
                ):
                    snapshot = for_synchronization(self.server, family)
                self.assertIsInstance(snapshot, CompleteCatalogueSnapshot)
                self.assertEqual([subnet.identity.subnet_id for subnet in snapshot.subnets], [10, 20, 21])


class TestRecordedQualifyingSuffix(TestCase):
    """Kea applies the DDNS qualifying suffix of the Subnet, then of its Shared Network, then the global one."""

    # A DHCPv4 and a DHCPv6 address in Subnet 21, in Subnet 20, and outside every recorded Subnet.
    _ADDRESSES = {
        4: ("198.51.100.130", "198.51.100.20", "203.0.113.5"),
        6: ("2001:db8:3::5", "2001:db8:2::20", "2001:db8:ffff::5"),
    }

    def setUp(self):
        self.server = _make_db_server()

    def _config_get(self, family: int, edit=None) -> dict:
        reply = copy.deepcopy(_recording(family)["config-get"])
        if edit is not None:
            edit(reply["arguments"][f"Dhcp{family}"])
        return reply

    def _snapshot(self, family: int, edit=None) -> server_configuration.ServerConfigurationSnapshot:
        with stub_kea({"config-get": self._config_get(family, edit)}):
            return server_configuration.for_verification(self.server, family)

    def _effective(self, snapshot) -> dict[int | None, str | None]:
        return {
            subnet.declared_subnet_id: server_configuration.effective_qualifying_suffix(snapshot, subnet)
            for subnet in snapshot.subnets
        }

    def test_the_recorded_suffixes_and_their_inheritance(self):
        for family in (4, 6):
            with self.subTest(family=family):
                snapshot = self._snapshot(family)
                self.assertEqual(snapshot.ddns_qualifying_suffix, "dhcp.example.com")
                self.assertEqual(
                    {network.name: network.ddns_qualifying_suffix for network in snapshot.shared_networks},
                    {"empty-network": None, "office": "office.example.net"},
                )
                # Subnet 10 sets an empty suffix, Subnet 20 sets none, and Subnet 21 sets its own.
                self.assertEqual(
                    self._effective(snapshot), {10: "", 20: "office.example.net", 21: "office.example.org."}
                )

    def test_a_subnet_without_a_suffix_on_its_path_takes_the_global_one(self):
        def drop(configuration):
            del configuration[f"subnet{family}"][0]["ddns-qualifying-suffix"]
            office = next(network for network in configuration["shared-networks"] if network["name"] == "office")
            del office["ddns-qualifying-suffix"]

        for family in (4, 6):
            with self.subTest(family=family):
                snapshot = self._snapshot(family, drop)
                self.assertEqual(
                    self._effective(snapshot),
                    {10: "dhcp.example.com", 20: "dhcp.example.com", 21: "office.example.org."},
                )

    def test_kea_default_global_suffix_is_empty(self):
        def drop(configuration):
            del configuration["ddns-qualifying-suffix"]

        self.assertEqual(self._snapshot(4, drop).ddns_qualifying_suffix, "")

    def test_an_invalid_suffix_on_the_path_makes_the_effective_suffix_unknown(self):
        def invalid_global(configuration):
            configuration["ddns-qualifying-suffix"] = 7
            del configuration["subnet4"][0]["ddns-qualifying-suffix"]

        def invalid_network(configuration):
            office = next(network for network in configuration["shared-networks"] if network["name"] == "office")
            office["ddns-qualifying-suffix"] = ["office.example.net"]

        snapshot = self._snapshot(4, invalid_global)
        self.assertIsNone(snapshot.ddns_qualifying_suffix)
        self.assertFalse(snapshot.complete)
        self.assertIsNone(self._effective(snapshot)[10])
        self.assertIsNone(self._effective(self._snapshot(4, invalid_network))[20])

    def test_the_catalogue_carries_the_effective_suffixes(self):
        for family in (4, 6):
            with self.subTest(family=family):
                recording = _recording(family)
                with stub_kea(
                    {"config-get": recording["config-get"], f"subnet{family}-list": recording[f"subnet{family}-list"]}
                ):
                    catalogue = for_synchronization(self.server, family)
                self.assertEqual(
                    [subnet.qualifying_suffix for subnet in catalogue.subnets],
                    ["", "office.example.net", "office.example.org."],
                )
                self.assertEqual(catalogue.global_qualifying_suffix, "dhcp.example.com")
                in_21, in_20, outside = (ipaddress.ip_address(address) for address in self._ADDRESSES[family])
                self.assertEqual(
                    catalogue.subnet_qualifying_suffix(catalogue.subnets[2].identity, in_21), "office.example.org."
                )
                self.assertEqual(catalogue.address_qualifying_suffix(in_21), "office.example.org.")
                self.assertEqual(catalogue.address_qualifying_suffix(in_20), "office.example.net")
                self.assertEqual(catalogue.address_qualifying_suffix(outside), "dhcp.example.com")
                self.assertEqual(catalogue.address_qualifying_suffix(None), "dhcp.example.com")

    def test_a_pool_suffix_applies_to_an_address_in_the_pool(self):
        # Subnet 21 has one Pool that sets its own suffix; Kea takes it from the Pool of the leased address.
        in_pool = {4: "198.51.100.210", 6: "2001:db8:3::150"}
        for family in (4, 6):
            with self.subTest(family=family):
                snapshot = self._snapshot(family)
                subnet_21 = snapshot.subnets[2]
                self.assertEqual(
                    [(pool.range, suffix) for pool, suffix in subnet_21.configuration.pool_qualifying_suffixes],
                    [(subnet_21.configuration.pools[0].range, "pool.example.org")],
                )
                recording = _recording(family)
                with stub_kea(
                    {"config-get": recording["config-get"], f"subnet{family}-list": recording[f"subnet{family}-list"]}
                ):
                    catalogue = for_synchronization(self.server, family)
                identity = catalogue.subnets[2].identity
                in_21 = ipaddress.ip_address(self._ADDRESSES[family][0])
                pool_address = ipaddress.ip_address(in_pool[family])
                self.assertEqual(catalogue.subnet_qualifying_suffix(identity, pool_address), "pool.example.org")
                self.assertEqual(catalogue.address_qualifying_suffix(pool_address), "pool.example.org")
                self.assertEqual(catalogue.subnet_qualifying_suffix(identity, in_21), "office.example.org.")
                # Without an address, the Pool of the dynamic lease decides, so the suffix is unknown.
                with self.assertRaises(CatalogueUnavailable):
                    catalogue.subnet_qualifying_suffix(identity, None)
                # A Subnet without a Pool suffix needs no address.
                self.assertEqual(
                    catalogue.subnet_qualifying_suffix(catalogue.subnets[1].identity, None), "office.example.net"
                )

    def test_an_invalid_pool_suffix_makes_the_subnet_suffix_unknown(self):
        def invalid_pool(configuration):
            office = next(network for network in configuration["shared-networks"] if network["name"] == "office")
            office[f"subnet{family}"][1]["pools"][0]["ddns-qualifying-suffix"] = 7

        family = 4
        snapshot = self._snapshot(family, invalid_pool)
        self.assertFalse(snapshot.complete)
        self.assertIsNone(self._effective(snapshot)[21])

    def test_an_address_in_a_subnet_the_sources_disagree_on_has_no_known_suffix(self):
        recording = _recording(4)
        listed = recording["subnet4-list"]["arguments"]["subnets"]
        (subnet_21,) = (subnet for subnet in listed if subnet["id"] == 21)
        subnet_21["id"] = 99
        with stub_kea({"config-get": recording["config-get"], "subnet4-list": recording["subnet4-list"]}):
            catalogue = display(self.server, 4)
        self.assertFalse(catalogue.consistent)
        with self.assertRaises(CatalogueUnavailable):
            catalogue.address_qualifying_suffix(ipaddress.ip_address(self._ADDRESSES[4][0]))

    def test_an_identity_only_catalogue_does_not_know_a_suffix(self):
        recording = _recording(4)
        with stub_kea({"config-get": RuntimeError("config-get failed"), "subnet4-list": recording["subnet4-list"]}):
            catalogue = display(self.server, 4)
        self.assertIsNone(catalogue.global_qualifying_suffix)
        with self.assertRaises(CatalogueUnavailable):
            catalogue.subnet_qualifying_suffix(catalogue.subnets[0].identity, None)
        with self.assertRaises(CatalogueUnavailable):
            catalogue.address_qualifying_suffix(ipaddress.ip_address("203.0.113.5"))
        with self.assertRaises(CatalogueUnavailable):
            catalogue.address_qualifying_suffix(None)


class TestRecordedReservationFlags(TestCase):
    """Kea applies each reservation flag of the Subnet, then of its Shared Network, then the global one."""

    _DEFAULTS = ReservationFlags(global_=False, in_subnet=True, out_of_pool=False)
    # Subnet 10 sets reservations-in-subnet, the office network reservations-global, and Subnet 21 out-of-pool.
    _RECORDED = {
        10: ReservationFlags(global_=False, in_subnet=False, out_of_pool=False),
        20: ReservationFlags(global_=True, in_subnet=True, out_of_pool=False),
        21: ReservationFlags(global_=True, in_subnet=True, out_of_pool=True),
    }

    def setUp(self):
        self.server = _make_db_server()

    def _snapshot(self, family: int, edit=None) -> server_configuration.ServerConfigurationSnapshot:
        reply = copy.deepcopy(_recording(family)["config-get"])
        if edit is not None:
            edit(reply["arguments"][f"Dhcp{family}"], family)
        with stub_kea({"config-get": reply}):
            return server_configuration.for_verification(self.server, family)

    def _effective(self, snapshot) -> dict[int | None, ReservationFlags | None]:
        return {
            subnet.declared_subnet_id: server_configuration.effective_reservation_flags(
                snapshot,
                subnet,
                membership_complete=subnet.declared_subnet_id is not None
                and snapshot.subnet_with_membership(subnet.declared_subnet_id) is subnet,
            )
            for subnet in snapshot.subnets
        }

    def test_the_recorded_flags_and_their_inheritance(self):
        for family in (4, 6):
            with self.subTest(family=family):
                snapshot = self._snapshot(family)
                # Kea sends each global flag, also at its default value.
                self.assertEqual(
                    snapshot.reservation_flags,
                    DeclaredReservationFlags(global_=False, in_subnet=True, out_of_pool=False),
                )
                self.assertEqual(
                    {network.name: network.reservation_flags for network in snapshot.shared_networks},
                    {"empty-network": DeclaredReservationFlags(), "office": DeclaredReservationFlags(global_=True)},
                )
                self.assertEqual(self._effective(snapshot), self._RECORDED)

    def test_a_flag_of_the_subnet_comes_before_its_shared_network_and_the_global_flag(self):
        def edit(configuration, family):
            configuration["reservations-global"] = True
            configuration[f"subnet{family}"][0]["reservations-global"] = False
            office = _office(configuration)
            office["reservations-in-subnet"] = False
            office["reservations-out-of-pool"] = True
            office[f"subnet{family}"][1]["reservations-in-subnet"] = True

        for family in (4, 6):
            with self.subTest(family=family):
                self.assertEqual(
                    self._effective(self._snapshot(family, edit)),
                    {
                        10: ReservationFlags(global_=False, in_subnet=False, out_of_pool=False),
                        20: ReservationFlags(global_=True, in_subnet=False, out_of_pool=True),
                        21: ReservationFlags(global_=True, in_subnet=True, out_of_pool=True),
                    },
                )

    def test_kea_defaults_apply_when_no_level_sets_a_flag(self):
        def drop(configuration, family):
            office = _office(configuration)
            levels = (configuration, office, configuration[f"subnet{family}"][0], *office[f"subnet{family}"])
            for level in levels:
                for key in ("reservations-global", "reservations-in-subnet", "reservations-out-of-pool"):
                    level.pop(key, None)

        snapshot = self._snapshot(4, drop)

        self.assertEqual(snapshot.reservation_flags, DeclaredReservationFlags())
        self.assertEqual(self._effective(snapshot), {10: self._DEFAULTS, 20: self._DEFAULTS, 21: self._DEFAULTS})

    def test_a_flag_that_is_not_a_bool_is_a_diagnostic_and_makes_the_flags_on_its_path_unknown(self):
        def invalid_global(configuration, _family):
            configuration["reservations-global"] = "true"

        def invalid_network(configuration, _family):
            _office(configuration)["reservations-in-subnet"] = 1

        def invalid_subnet(configuration, family):
            configuration[f"subnet{family}"][0]["reservations-out-of-pool"] = None

        def invalid_network_name(configuration, _family):
            _office(configuration)["name"] = 7

        cases = (
            (invalid_global, ("invalid-setting", "Dhcp4.reservations-global"), {10: None, 20: None, 21: None}),
            (
                invalid_network,
                ("invalid-setting", "shared-networks[1].reservations-in-subnet"),
                {**self._RECORDED, 20: None, 21: None},
            ),
            (invalid_subnet, ("invalid-setting", "subnet4[0].reservations-out-of-pool"), {**self._RECORDED, 10: None}),
            # The members lose the network name, and the flags of the network still apply to them.
            (
                invalid_network_name,
                ("invalid-shared-network", "shared-networks[1].name"),
                {**self._RECORDED, 20: None, 21: None},
            ),
        )
        for edit, diagnostic, effective in cases:
            with self.subTest(diagnostic):
                snapshot = self._snapshot(4, edit)
                self.assertFalse(snapshot.complete)
                self.assertIn(diagnostic, [(item.code, item.path) for item in snapshot.diagnostics])
                self.assertEqual(self._effective(snapshot), effective)
        self.assertIsNone(self._snapshot(4, invalid_global).reservation_flags)

    def test_the_catalogue_carries_the_effective_flags_only_when_the_configuration_shows_them(self):
        for family in (4, 6):
            recording = _recording(family)
            listing = {f"subnet{family}-list": recording[f"subnet{family}-list"]}
            with self.subTest(family=family):
                with stub_kea({"config-get": recording["config-get"], **listing}):
                    catalogue = for_synchronization(self.server, family)
                self.assertEqual(
                    {subnet.subnet_id: subnet.reservation_flags for subnet in catalogue.subnets}, self._RECORDED
                )
                with stub_kea({"config-get": RuntimeError("config-get failed"), **listing}):
                    identity_only = display(self.server, family)
                self.assertEqual([subnet.reservation_flags for subnet in identity_only.subnets], [None] * 3)


def _office(configuration: dict) -> dict:
    return next(network for network in configuration["shared-networks"] if network["name"] == "office")
