# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import ast
import itertools
import json
from dataclasses import replace
from datetime import datetime, timezone
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import get_args

import yaml
from django.test import SimpleTestCase, TestCase

from netbox_kea import kea, server_configuration
from netbox_kea.dhcp_options import DHCPOptionChange, DHCPOptionEdit, parse_dhcp_options
from netbox_kea.kea import KeaCommand
from netbox_kea.reservations import (
    MAX_IDENTITY_LENGTH,
    ClearValue,
    ExcludedPrefix,
    Family,
    GlobalReservationScope,
    InSubnetReservationScope,
    IPv4Reservation,
    IPv6Reservation,
    MalformedReservation,
    ReservationCapabilities,
    ReservationChange,
    ReservationIdentity,
    ReservationSnapshot,
    ReservationSynchronizationState,
    SetValue,
    SynchronizationLabel,
    apply_reservation_change,
    reservation_fingerprint,
    reservation_identifier_types,
    reservation_match,
)
from netbox_kea.server_configuration import SubnetConfiguration
from netbox_kea.subnet_catalogue import (
    CatalogueSnapshot,
    ConfiguredSubnet,
    IdentityOnlyCatalogueSnapshot,
    SubnetIdentity,
    VerifiedSubnet,
)
from netbox_kea.subnet_settings import SubnetSettings

from .kea_stub import (
    _host_cmds_hooks,
    _res_get,
    _res_page,
    _typed_reservation,
    kea_client,
    lease_record,
    observed_configuration,
    queued,
    stub_kea,
    typed_lease,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
#: The statements that bind the name in their ``name`` attribute.
_NAMED_BINDINGS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler, ast.MatchAs, ast.MatchStar)


def _catalogue(family: Family, subnet_id: int, cidr: str) -> CatalogueSnapshot:
    subnet = VerifiedSubnet(
        identity=SubnetIdentity(subnet_id=subnet_id, network=ip_network(cidr)),
        declared_cidr=cidr,
        configuration=None,
        shared_network=None,
        membership_known=True,
        qualifying_suffix=None,
        reservation_flags=None,
    )
    # Identity-only: the fixture carries no configuration, which is all a Reservation
    # Scope needs verified.
    return IdentityOnlyCatalogueSnapshot(
        server_id=1,
        family=family,
        observed_at=datetime.now(timezone.utc),
        subnets=(subnet,),
        configured_subnets=(),
        diagnostics=(),
        identity_available=True,
        configuration_available=False,
        identity_complete=True,
        configuration_complete=False,
        consistent=True,
        configuration_hash=None,
        global_qualifying_suffix=None,
    )


class TestReservationSnapshotGlossary(SimpleTestCase):
    def test_snapshot_definition_distinguishes_page_reads_from_parsing_failures(self):
        context = (Path(__file__).resolve().parents[2] / "CONTEXT.md").read_text(encoding="utf-8")
        definition = " ".join(
            context.split("**Reservation Snapshot**:\n", 1)[1].split("\n_Avoid_:", 1)[0].split()
        ).lower()

        for statement in (
            "failed or bounded page reads can make it incomplete without a record diagnostic",
            "parsing failures identify records that could not be interpreted",
        ):
            with self.subTest(statement=statement):
                self.assertIn(statement, definition)


class TestReservationIdentifierTypes(SimpleTestCase):
    def test_the_shared_lookup_rejects_a_family_that_is_not_an_integer(self):
        """`4.0 == 4`, so an equality-only membership test accepts a float family.

        This lookup is the shared entry point every caller reaches, so the guard
        belongs here rather than at each call site, where the copies would drift.
        """
        for family in (4.0, 6.0, "4", True, None):
            with self.subTest(family=family), self.assertRaisesMessage(ValueError, "family must be 4 or 6"):
                reservation_identifier_types(family)

    def test_the_shared_lookup_still_accepts_both_real_families(self):
        for family in (4, 6):
            with self.subTest(family=family):
                self.assertTrue(reservation_identifier_types(family))


class TestReservationIdentity(SimpleTestCase):
    def test_the_identity_length_bound_covers_every_identifier_type(self):
        """KeaDhcpLink sizes its identity column from this bound, so it must hold."""
        longest = {
            "hw-address": "ab" * 20,
            "duid": "ab" * 128,
            "client-id": "ab" * 128,
            "circuit-id": "c" * 255,
            "flex-id": "f" * 255,
        }

        for identifier_type, value in longest.items():
            with self.subTest(identifier_type=identifier_type):
                identity = ReservationIdentity(identifier_type, value)
                self.assertLessEqual(len(f"{identity.identifier_type}:{identity.value}"), MAX_IDENTITY_LENGTH)

        widest = ReservationIdentity("client-id", longest["client-id"])
        self.assertEqual(len(f"{widest.identifier_type}:{widest.value}"), MAX_IDENTITY_LENGTH)

    def test_normalizes_hex_identifiers_to_lowercase_colon_notation(self):
        self.assertEqual(ReservationIdentity("hw-address", "AA-BB-CC-DD-EE-FF").value, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(ReservationIdentity("duid", "00010203").value, "00:01:02:03")
        self.assertEqual(ReservationIdentity("client-id", "01.AA.BB").value, "01:aa:bb")

    def test_reads_each_separated_group_as_one_octet_like_kea(self):
        self.assertEqual(ReservationIdentity("hw-address", "a:b:c:d:e:f").value, "0a:0b:0c:0d:0e:0f")
        self.assertEqual(ReservationIdentity("hw-address", "0-1B-2-3-4-5").value, "00:1b:02:03:04:05")
        for value in ("aabb:ccdd:eeff", "aa::bb:cc", "aa:bb:", ":aa:bb", "aa:bbb:cc", "aa-b-ccc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ReservationIdentity("client-id", value)

    def test_preserves_opaque_identifiers_exactly(self):
        self.assertEqual(ReservationIdentity("circuit-id", " Circuit/A ").value, " Circuit/A ")
        self.assertEqual(ReservationIdentity("flex-id", "Relay:Class-A").value, "Relay:Class-A")

    def test_rejects_oversized_opaque_identifiers(self):
        for identifier_type in ("circuit-id", "flex-id"):
            with self.subTest(identifier_type=identifier_type):
                with self.assertRaisesRegex(ValueError, "255"):
                    ReservationIdentity(identifier_type, "x" * 256)

    def test_enforces_hex_identifier_octet_bounds(self):
        max_duid = ":".join(["ab"] * 128)
        self.assertEqual(ReservationIdentity("duid", max_duid).value, max_duid)
        with self.assertRaises(ValueError):
            ReservationIdentity("duid", ":".join(["ab"] * 129))
        with self.assertRaises(ValueError):
            ReservationIdentity("client-id", "ab")

    def test_rejects_empty_and_oversized_hardware_addresses(self):
        for value in ("", "ab" * 21):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ReservationIdentity("hw-address", value)

    def test_rejects_unsupported_and_empty_identifiers(self):
        for identifier_type, value in (("remote-id", "relay"), ("flex-id", ""), ("duid", "not-hex")):
            with self.subTest(identifier_type=identifier_type, value=value):
                with self.assertRaises(ValueError):
                    ReservationIdentity(identifier_type, value)


class TestReservationValues(SimpleTestCase):
    def setUp(self):
        self.scope4 = InSubnetReservationScope(SubnetIdentity(20, ip_network("198.18.0.0/24")))
        self.scope6 = InSubnetReservationScope(SubnetIdentity(10, ip_network("2001:db8::/64")))
        self.identity4 = ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff")
        self.identity6 = ReservationIdentity("duid", "00:01:02:03")

    def test_rejects_invalid_reservation_invariants(self):
        cases = (
            (
                "v6 identifier from another family",
                lambda: IPv6Reservation(
                    scope=self.scope6,
                    identity=ReservationIdentity("client-id", "01:02"),
                    addresses=(),
                    delegated_prefixes=(),
                ),
            ),
            (
                "v4 reservation in a v6 scope",
                lambda: IPv4Reservation(scope=self.scope6, identity=self.identity4, addresses=()),
            ),
            (
                "hostname is not a string",
                lambda: IPv4Reservation(scope=self.scope4, identity=self.identity4, addresses=(), hostname=1),
            ),
            (
                "duplicate v4 address",
                lambda: IPv4Reservation(
                    scope=self.scope4,
                    identity=self.identity4,
                    addresses=(ip_address("198.18.0.20"), ip_address("198.18.0.20")),
                ),
            ),
            (
                "v6 address in a v4 reservation",
                lambda: IPv4Reservation(
                    scope=self.scope4,
                    identity=self.identity4,
                    addresses=(ip_address("2001:db8::20"),),
                ),
            ),
            (
                "v4 address outside its scope subnet",
                lambda: IPv4Reservation(
                    scope=self.scope4,
                    identity=self.identity4,
                    addresses=(ip_address("198.18.1.20"),),
                ),
            ),
            (
                "more than one v4 address",
                lambda: IPv4Reservation(
                    scope=self.scope4,
                    identity=self.identity4,
                    addresses=(ip_address("198.18.0.20"), ip_address("198.18.0.21")),
                ),
            ),
            (
                "v4 reservation delegates a prefix",
                lambda: IPv4Reservation(
                    scope=self.scope4,
                    identity=self.identity4,
                    addresses=(),
                    delegated_prefixes=(ip_network("2001:db8:100::/56"),),
                ),
            ),
            (
                "duplicate delegated prefix",
                lambda: IPv6Reservation(
                    scope=self.scope6,
                    identity=self.identity6,
                    addresses=(),
                    delegated_prefixes=(ip_network("2001:db8:100::/56"), ip_network("2001:db8:100::/56")),
                ),
            ),
            (
                "v4 prefix delegated by a v6 reservation",
                lambda: IPv6Reservation(
                    scope=self.scope6,
                    identity=self.identity6,
                    addresses=(),
                    delegated_prefixes=(ip_network("198.18.0.0/24"),),
                ),
            ),
            (
                "option is not a mapping",
                lambda: IPv4Reservation(scope=self.scope4, identity=self.identity4, addresses=(), options=(object(),)),
            ),
        )
        for name, build in cases:
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    build()

    def test_synchronization_state_factories_cover_all_aggregate_states(self):
        self.assertEqual(ReservationSynchronizationState.from_counts(0, 2).label, "Not Synchronized")
        self.assertEqual(ReservationSynchronizationState.from_counts(1, 2).label, "Partially Synchronized")
        self.assertEqual(ReservationSynchronizationState.from_counts(2, 2).label, "Synchronized")
        self.assertEqual(ReservationSynchronizationState.not_applicable("Global").reason, "Global")
        self.assertEqual(ReservationSynchronizationState.unknown(2, "lookup failed").label, "Unknown")
        with self.assertRaises(ValueError):
            ReservationSynchronizationState.from_counts(3, 2)

    def test_dhcp_option_collection_must_be_a_list_at_the_adapter_boundary(self):
        with self.assertRaisesRegex(ValueError, "must be a list"):
            parse_dhcp_options({})


class TestReservationPage(SimpleTestCase):
    def setUp(self):
        self.kea = kea_client(url="http://kea.example.invalid", send_service=False)

    def test_quarantines_configured_subnet_without_verified_identity(self):
        catalogue = _catalogue(4, 20, "198.18.0.0/24")
        configured = ConfiguredSubnet(
            candidate_identity=catalogue.subnets[0].identity,
            configuration=SubnetConfiguration(
                pools=(), options=(), settings=SubnetSettings(), pool_qualifying_suffixes=()
            ),
            shared_network=None,
            qualifying_suffix="",
        )
        catalogue = replace(catalogue, subnets=(), configured_subnets=(configured,))
        raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}

        with stub_kea({"reservation-get-page": _res_page([raw])}):
            snapshot = self.kea.reservation_page(4, catalogue)

        self.assertEqual(snapshot.records, ())
        self.assertEqual([diagnostic.code for diagnostic in snapshot.diagnostics], ["unverified-scope"])

    def test_a_page_records_the_aware_time_at_which_its_read_started(self):
        before = datetime.now(timezone.utc)
        with stub_kea({"reservation-get-page": _res_page([])}):
            snapshot = self.kea.reservation_page(4, _catalogue(4, 20, "198.18.0.0/24"))

        self.assertTrue(before <= snapshot.read_started <= datetime.now(timezone.utc))

    def test_a_snapshot_refuses_a_naive_read_time(self):
        with self.assertRaisesMessage(ValueError, "aware read time"):
            ReservationSnapshot(4, (), (), True, None, datetime(2026, 1, 1))  # noqa: DTZ001

    def test_returns_typed_snapshot_and_quarantines_one_malformed_record(self):
        page = _res_page(
            [
                {
                    "subnet-id": 10,
                    "duid": "00-01-02-03",
                    "ip-addresses": ["2001:db8::20", "2001:db8::10"],
                    "prefixes": ["2001:db8:100::/56"],
                    "hostname": "host.example.invalid",
                    "option-data": [
                        {
                            "code": 23,
                            "space": "dhcp6",
                            "data": "2001:db8::53",
                            "csv-format": True,
                            "always-send": False,
                            "never-send": False,
                        }
                    ],
                },
                {
                    "subnet-id": 10,
                    "remote-id": "relay-value",
                    "ip-addresses": ["2001:db8::30"],
                },
            ],
            next_from=2,
            next_source=1,
        )

        with stub_kea({"reservation-get-page": page}) as kea:
            snapshot = self.kea.reservation_page(6, _catalogue(6, 10, "2001:db8::/64"), limit=2)

        self.assertIsInstance(snapshot, ReservationSnapshot)
        self.assertFalse(snapshot.complete)
        self.assertEqual(len(snapshot.records), 1)
        reservation = snapshot.records[0]
        self.assertEqual(reservation.identity, ReservationIdentity("duid", "00:01:02:03"))
        self.assertEqual(
            reservation.scope,
            InSubnetReservationScope(SubnetIdentity(10, ip_network("2001:db8::/64"))),
        )
        self.assertEqual(
            reservation.addresses,
            (ip_address("2001:db8::20"), ip_address("2001:db8::10")),
        )
        self.assertEqual(reservation.delegated_prefixes, (ip_network("2001:db8:100::/56"),))
        self.assertEqual(reservation.hostname, "host.example.invalid")
        self.assertEqual(reservation.options[0].code, 23)
        self.assertEqual(snapshot.diagnostics[0].code, "unsupported-identifier")
        self.assertEqual(snapshot.diagnostics[0].source_position, "hosts[1].remote-id")
        self.assertNotIn("relay-value", snapshot.diagnostics[0].message)
        self.assertIsInstance(snapshot.next_cursor, str)
        self.assertNotEqual(snapshot.next_cursor, "1:2")
        self.assertEqual(
            kea.bodies("reservation-get-page")[0]["arguments"],
            {"source-index": 0, "from": 0, "limit": 2},
        )

    def test_uses_the_opaque_cursor_for_the_next_bounded_page(self):
        hosts = [{"subnet-id": 10, "hw-address": f"aa:bb:cc:dd:ee:{index:02x}"} for index in range(25)]
        first_page = _res_page(hosts, next_from=17, next_source=2)

        with stub_kea({"reservation-get-page": first_page}):
            first = self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"), limit=25)

        with stub_kea({"reservation-get-page": _res_page([])}) as kea:
            self.kea.reservation_page(
                4,
                _catalogue(4, 10, "198.18.0.0/24"),
                cursor=first.next_cursor,
                limit=25,
            )

        self.assertEqual(
            kea.bodies("reservation-get-page")[0]["arguments"],
            {"source-index": 2, "from": 17, "limit": 25},
        )

    def test_fills_one_bounded_page_across_short_backend_source_pages(self):
        configured = [{"subnet-id": 10, "hw-address": f"aa:bb:cc:dd:ee:{index:02x}"} for index in range(6)]
        database = [{"subnet-id": 10, "hw-address": "aa:bb:cc:dd:ef:01"}]
        responses = queued(
            _res_page(configured, next_from=6, next_source=0),
            _res_page(database, next_from=10, next_source=1),
            {"result": 3},
        )

        with stub_kea({"reservation-get-page": responses}) as kea:
            snapshot = self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"), limit=10)

        self.assertEqual(len(snapshot.records), 7)
        self.assertIsNone(snapshot.next_cursor)
        self.assertEqual(
            [body["arguments"] for body in kea.bodies("reservation-get-page")],
            [
                {"source-index": 0, "from": 0, "limit": 10},
                {"source-index": 0, "from": 6, "limit": 4},
                {"source-index": 1, "from": 10, "limit": 3},
            ],
        )

    def test_rejects_a_malformed_response_envelope(self):
        with stub_kea({"reservation-get-page": []}):
            with self.assertRaisesRegex(RuntimeError, "one valid result"):
                self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"))

    def test_rejects_a_malformed_page_cursor(self):
        page = {
            "result": 0,
            "arguments": {
                "hosts": [],
                "next": {"source-index": "source", "from": 1},
            },
        }
        with stub_kea({"reservation-get-page": page}):
            with self.assertRaisesRegex(RuntimeError, "malformed next cursor"):
                self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"))

    def test_preserves_a_global_addressless_reservation(self):
        page = _res_page([{"subnet-id": 0, "circuit-id": "opaque value"}])

        with stub_kea({"reservation-get-page": page}):
            snapshot = self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"))

        reservation = snapshot.records[0]
        self.assertEqual(reservation.scope, GlobalReservationScope())
        self.assertEqual(reservation.identity, ReservationIdentity("circuit-id", "opaque value"))
        self.assertEqual(reservation.addresses, ())
        self.assertEqual(reservation.delegated_prefixes, ())

    def test_preserves_hardware_addresses_of_supported_lengths(self):
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            for octets in (1, 6, 8, 20):
                with self.subTest(family=family, octets=octets):
                    raw = {"subnet-id": 10, "hw-address": "AB" * octets}
                    with stub_kea({"reservation-get-page": _res_page([raw])}):
                        snapshot = self.kea.reservation_page(family, _catalogue(family, 10, cidr))

                    self.assertEqual(snapshot.diagnostics, ())
                    self.assertEqual(len(snapshot.records), 1)
                    self.assertEqual(snapshot.records[0].identity.identifier_type, "hw-address")
                    self.assertEqual(snapshot.records[0].identity.value, ":".join(["ab"] * octets))

    def test_the_fixture_helper_scopes_subnet_id_zero_like_the_parser(self):
        """A subnet-id 0 fixture must not enter the in-subnet path the parser rejects."""
        raw = {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.9"}
        page = _res_page([raw])

        with stub_kea({"reservation-get-page": page}):
            snapshot = self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"))

        self.assertEqual(_typed_reservation(raw).scope, snapshot.records[0].scope)

    def test_quarantines_malformed_ipv6_records_independently(self):
        valid_identity = {"subnet-id": 10, "duid": "00:01:02:03"}
        hosts = [
            None,
            {"duid": "00:01:02:03"},
            {"subnet-id": 11, "duid": "00:01:02:03"},
            {"subnet-id": 10, "flex-id": 42},
            {**valid_identity, "ip-address": "2001:db8::20"},
            {**valid_identity, "ip-addresses": {}},
            {**valid_identity, "ip-addresses": [1]},
            {**valid_identity, "ip-addresses": ["invalid"]},
            {**valid_identity, "ip-addresses": ["2001:db8::20", "2001:db8::20"]},
            {**valid_identity, "prefixes": {}},
            {**valid_identity, "prefixes": ["invalid"]},
            {**valid_identity, "prefixes": ["2001:db8:100::/56", "2001:db8:100::/56"]},
            {**valid_identity, "hostname": 42},
            {**valid_identity, "option-data": [42]},
        ]

        with stub_kea({"reservation-get-page": _res_page(hosts)}):
            snapshot = self.kea.reservation_page(6, _catalogue(6, 10, "2001:db8::/64"))

        self.assertEqual(snapshot.records, ())
        self.assertEqual(len(snapshot.diagnostics), len(hosts))
        self.assertIn("unverified-scope", {diagnostic.code for diagnostic in snapshot.diagnostics})

    def test_quarantines_an_identifier_from_the_other_family(self):
        hosts = [
            {
                "subnet-id": 10,
                "duid": "00:01:02:03",
                "ip-addresses": ["2001:db8::20"],
            },
            {
                "subnet-id": 10,
                "duid": "00:01:02:04",
                "client-id": "01:02",
                "ip-addresses": ["2001:db8::21"],
            },
        ]

        with stub_kea({"reservation-get-page": _res_page(hosts)}):
            snapshot = self.kea.reservation_page(6, _catalogue(6, 10, "2001:db8::/64"))

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(snapshot.records[0].identity, ReservationIdentity("duid", "00:01:02:03"))
        self.assertEqual(snapshot.diagnostics[0].code, "invalid-family-identifier")
        self.assertEqual(snapshot.diagnostics[0].source_position, "hosts[1].client-id")

    def test_quarantines_an_oversized_opaque_identifier(self):
        hosts = [
            {"subnet-id": 10, "duid": "00:01:02:03"},
            {"subnet-id": 10, "flex-id": "x" * 256},
        ]

        with stub_kea({"reservation-get-page": _res_page(hosts)}):
            snapshot = self.kea.reservation_page(6, _catalogue(6, 10, "2001:db8::/64"))

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(snapshot.records[0].identity, ReservationIdentity("duid", "00:01:02:03"))
        self.assertEqual(snapshot.diagnostics[0].code, "invalid-identifier")
        self.assertEqual(snapshot.diagnostics[0].source_position, "hosts[1].flex-id")

    def test_quarantines_non_string_delegated_prefixes(self):
        hosts = [
            {"subnet-id": 10, "duid": "00:01:02:03", "prefixes": ["2001:db8:100::/56"]},
            {"subnet-id": 10, "duid": "00:01:02:04", "prefixes": [42]},
            {"subnet-id": 10, "duid": "00:01:02:05", "prefixes": [True]},
        ]

        with stub_kea({"reservation-get-page": _res_page(hosts)}):
            snapshot = self.kea.reservation_page(6, _catalogue(6, 10, "2001:db8::/64"))

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(snapshot.records[0].identity, ReservationIdentity("duid", "00:01:02:03"))
        self.assertEqual(
            [(diagnostic.code, diagnostic.source_position) for diagnostic in snapshot.diagnostics],
            [
                ("invalid-prefix", "hosts[1].prefixes[0]"),
                ("invalid-prefix", "hosts[2].prefixes[0]"),
            ],
        )

    def test_quarantines_ipv4_collection_and_prefix_fields(self):
        hosts = [
            {"subnet-id": 10, "hw-address": "aa:bb:cc:dd:ee:01", "ip-addresses": []},
            {
                "subnet-id": 10,
                "hw-address": "aa:bb:cc:dd:ee:02",
                "prefixes": ["2001:db8:100::/56"],
            },
        ]
        with stub_kea({"reservation-get-page": _res_page(hosts)}):
            snapshot = self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"))

        self.assertEqual(snapshot.records, ())
        self.assertEqual({item.code for item in snapshot.diagnostics}, {"invalid-addresses", "invalid-prefixes"})

    def test_quarantines_an_address_outside_the_verified_scope(self):
        hosts = [
            {
                "subnet-id": 10,
                "hw-address": "aa:bb:cc:dd:ee:01",
                "ip-address": "198.18.0.20",
            },
            {
                "subnet-id": 10,
                "hw-address": "aa:bb:cc:dd:ee:02",
                "ip-address": "198.18.1.20",
            },
        ]

        with stub_kea({"reservation-get-page": _res_page(hosts)}):
            snapshot = self.kea.reservation_page(4, _catalogue(4, 10, "198.18.0.0/24"))

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(snapshot.records[0].identity, ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:01"))
        self.assertEqual(snapshot.diagnostics[0].code, "invalid-address")
        self.assertEqual(snapshot.diagnostics[0].source_position, "hosts[1].ip-address")


class TestReservationExactIdentity(SimpleTestCase):
    def setUp(self):
        self.kea = kea_client(url="http://kea.example.invalid", send_service=False)
        self.catalogue = _catalogue(4, 20, "198.18.0.0/24")
        self.scope = InSubnetReservationScope(SubnetIdentity(20, ip_network("198.18.0.0/24")))

    def test_returns_the_one_typed_target_for_normalized_identity(self):
        identity = ReservationIdentity("client-id", "01:aa:bb:cc:dd:ee:ff")
        response = _res_get(
            {
                "subnet-id": 20,
                "client-id": "01-AA-BB-CC-DD-EE-FF",
                "ip-address": "198.18.0.20",
            }
        )

        with stub_kea({"reservation-get": response}) as kea:
            reservation = self.kea.reservation_by_identity(4, self.catalogue, self.scope, identity)

        self.assertEqual(reservation.identity, identity)
        self.assertEqual(reservation.addresses, (ip_address("198.18.0.20"),))
        self.assertEqual(
            kea.bodies("reservation-get")[0]["arguments"],
            {
                "subnet-id": 20,
                "identifier-type": "client-id",
                "identifier": "01:aa:bb:cc:dd:ee:ff",
            },
        )

    def test_fails_closed_when_the_target_has_multiple_identifiers(self):
        response = _res_get(
            {
                "subnet-id": 20,
                "client-id": "01:aa:bb:cc:dd:ee:ff",
                "hw-address": "aa:bb:cc:dd:ee:ff",
            }
        )

        with stub_kea({"reservation-get": response}):
            with self.assertRaisesRegex(MalformedReservation, "exactly one"):
                self.kea.reservation_by_identity(
                    4,
                    self.catalogue,
                    self.scope,
                    ReservationIdentity("client-id", "01:aa:bb:cc:dd:ee:ff"),
                )

    def test_result_zero_host_not_found_returns_none(self):
        identity = ReservationIdentity("client-id", "01:aa:bb:cc:dd:ee:ff")

        with stub_kea({"reservation-get": {"result": 0, "text": "Host not found."}}):
            reservation = self.kea.reservation_by_identity(4, self.catalogue, self.scope, identity)

        self.assertIsNone(reservation)

    def test_result_zero_without_not_found_text_stays_malformed(self):
        identity = ReservationIdentity("client-id", "01:aa:bb:cc:dd:ee:ff")

        with stub_kea({"reservation-get": {"result": 0, "text": "Host lookup completed."}}):
            with self.assertRaisesRegex(RuntimeError, "malformed arguments"):
                self.kea.reservation_by_identity(4, self.catalogue, self.scope, identity)


class TestReservationScopedPrefix(SimpleTestCase):
    """A delegated prefix resolves to the Reservation of exactly that prefix, also outside the Subnet CIDR."""

    def setUp(self):
        self.kea = kea_client(url="http://kea.example.invalid", send_service=False)
        self.catalogue = _catalogue(6, 10, "2001:db8:1::/64")
        self.scope = InSubnetReservationScope(SubnetIdentity(10, ip_network("2001:db8:1::/64")))

    def _host(self, prefix: str) -> dict:
        # The shape of the host that Kea 3.2.0 returned for the base address of a reserved prefix.
        return {
            "subnet-id": 10,
            "duid": "00:01:00:01:2c:4f:00:01:aa:bb:cc:00:00:09",
            "hostname": "pdres",
            "ip-addresses": [],
            "prefixes": [prefix],
        }

    def test_kea_finds_the_host_by_the_base_address_of_its_prefix(self):
        with stub_kea({"reservation-get": _res_get(self._host("2001:db8:100:800::/56"))}) as kea:
            reservation = self.kea.reservation_by_prefix(
                self.catalogue, self.scope, ip_network("2001:db8:100:800::/56")
            )

        self.assertEqual(reservation.delegated_prefixes, (ip_network("2001:db8:100:800::/56"),))
        self.assertEqual(
            kea.bodies("reservation-get")[0]["arguments"], {"subnet-id": 10, "ip-address": "2001:db8:100:800::"}
        )

    def test_a_host_that_reserves_another_length_at_the_base_fails_closed(self):
        with stub_kea({"reservation-get": _res_get(self._host("2001:db8:100:800::/60"))}):
            with self.assertRaisesRegex(ValueError, "scoped target 2001:db8:100:800::/56"):
                self.kea.reservation_by_prefix(self.catalogue, self.scope, ip_network("2001:db8:100:800::/56"))

    def test_no_host_is_none(self):
        with stub_kea({"reservation-get": {"result": 3, "text": "Host not found."}}):
            self.assertIsNone(
                self.kea.reservation_by_prefix(self.catalogue, self.scope, ip_network("2001:db8:100:800::/56"))
            )


class TestReservationScopedAddress(SimpleTestCase):
    def setUp(self):
        self.kea = kea_client(url="http://kea.example.invalid", send_service=False)
        self.catalogue = _catalogue(4, 20, "198.18.0.0/24")
        self.scope = InSubnetReservationScope(SubnetIdentity(20, ip_network("198.18.0.0/24")))

    def test_resolves_an_address_to_the_canonical_typed_identity(self):
        response = _res_get(
            {
                "subnet-id": 20,
                "hw-address": "AA-BB-CC-DD-EE-FF",
                "ip-address": "198.18.0.20",
            }
        )

        with stub_kea({"reservation-get": response}) as kea:
            reservation = self.kea.reservation_by_address(
                4,
                self.catalogue,
                self.scope,
                "198.18.0.20",
            )

        self.assertEqual(reservation.identity, ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff"))
        self.assertEqual(
            kea.bodies("reservation-get")[0]["arguments"],
            {"subnet-id": 20, "ip-address": "198.18.0.20"},
        )

    def test_rejects_address_discovery_in_global_scope_without_a_request(self):
        with stub_kea({}) as kea:
            with self.assertRaisesRegex(ValueError, "In-Subnet"):
                self.kea.reservation_by_address(
                    4,
                    self.catalogue,
                    GlobalReservationScope(),
                    "198.18.0.20",
                )

        self.assertEqual(kea.commands(), [])

    def test_result_zero_host_not_found_returns_none(self):
        with stub_kea({"reservation-get": {"result": 0, "text": "Host not found."}}):
            reservation = self.kea.reservation_by_address(
                4,
                self.catalogue,
                self.scope,
                "198.18.0.20",
            )

        self.assertIsNone(reservation)


class TestReservationHostname(SimpleTestCase):
    def test_returns_all_valid_matches_and_quarantines_a_malformed_match(self):
        client = kea_client(url="http://kea.example.invalid", send_service=False)
        response = {
            "result": 0,
            "arguments": {
                "hosts": [
                    {
                        "subnet-id": 10,
                        "duid": "00:01:02:03",
                        "ip-addresses": ["2001:db8::10"],
                        "hostname": "host.example.invalid",
                    },
                    {
                        "subnet-id": 10,
                        "duid": "00:01:02:04",
                        "hw-address": "aa:bb:cc:dd:ee:ff",
                        "hostname": "host.example.invalid",
                    },
                ]
            },
        }

        with stub_kea({"reservation-get-by-hostname": response}) as kea:
            snapshot = client.reservations_by_hostname(
                6,
                _catalogue(6, 10, "2001:db8::/64"),
                "host.example.invalid",
            )

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(snapshot.records[0].identity, ReservationIdentity("duid", "00:01:02:03"))
        self.assertFalse(snapshot.complete)
        self.assertEqual(snapshot.diagnostics[0].code, "ambiguous-identifier")
        self.assertIsNone(snapshot.next_cursor)
        self.assertEqual(
            kea.bodies("reservation-get-by-hostname")[0]["arguments"],
            {"hostname": "host.example.invalid"},
        )

    def test_quarantines_results_that_do_not_match_the_requested_hostname(self):
        client = kea_client(url="http://kea.example.invalid", send_service=False)
        response = {
            "result": 0,
            "arguments": {
                "hosts": [
                    {
                        "subnet-id": 10,
                        "duid": "00:01:02:03",
                        "hostname": "host.example.invalid",
                    },
                    {
                        "subnet-id": 10,
                        "duid": "00:01:02:04",
                        "hostname": "different.example.invalid",
                    },
                    {"subnet-id": 10, "duid": "00:01:02:05"},
                ]
            },
        }

        with stub_kea({"reservation-get-by-hostname": response}):
            snapshot = client.reservations_by_hostname(
                6,
                _catalogue(6, 10, "2001:db8::/64"),
                "host.example.invalid",
            )

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(snapshot.records[0].identity, ReservationIdentity("duid", "00:01:02:03"))
        self.assertEqual(
            [(diagnostic.code, diagnostic.source_position) for diagnostic in snapshot.diagnostics],
            [
                ("target-mismatch", "hosts[1].hostname"),
                ("target-mismatch", "hosts[2].hostname"),
            ],
        )
        self.assertFalse(snapshot.complete)


class TestReservationIteration(SimpleTestCase):
    def test_raw_page_cap_preserves_a_short_or_empty_page_cursor(self):
        for hosts in ([], [{"subnet-id": 20, "flex-id": "printer"}]):
            with (
                self.subTest(hosts=hosts),
                stub_kea(
                    {
                        "reservation-get-page": queued(_res_page(hosts, next_from=7, next_source=1), _res_page([])),
                    }
                ) as kea,
            ):
                client = kea_client(url="http://kea:8000")
                snapshot = client.reservation_page(4, _catalogue(4, 20, "198.18.0.0/24"), max_raw_pages=1)
                self.assertEqual(len(kea.bodies("reservation-get-page")), 1)
                self.assertIsNotNone(snapshot.next_cursor)
                client.reservation_page(
                    4, _catalogue(4, 20, "198.18.0.0/24"), cursor=snapshot.next_cursor, max_raw_pages=1
                )
                self.assertEqual(kea.bodies("reservation-get-page")[-1]["arguments"]["from"], 7)

    def test_rejects_an_unsupported_snapshot_family(self):
        client = kea_client(url="http://kea.example.invalid", send_service=False)

        with self.assertRaisesRegex(ValueError, "version must be 4 or 6"):
            client.reservation_snapshot(5, _catalogue(4, 20, "198.18.0.0/24"))

    def test_combines_bounded_pages_and_preserves_incomplete_diagnostics(self):
        first = _res_page(
            [
                {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.20"},
                {"subnet-id": 20, "remote-id": "relay-value"},
            ],
            next_from=2,
            next_source=1,
        )
        final = _res_page([{"subnet-id": 20, "client-id": "01:aa:bb:cc:dd:ee:02", "ip-address": "198.18.0.21"}])
        client = kea_client(url="http://kea.example.invalid", send_service=False)

        with stub_kea({"reservation-get-page": queued(first, final)}) as kea:
            snapshot = client.reservation_snapshot(4, _catalogue(4, 20, "198.18.0.0/24"), page_size=2)

        self.assertEqual(len(snapshot.records), 2)
        self.assertEqual(len(snapshot.diagnostics), 1)
        self.assertFalse(snapshot.complete)
        self.assertIsNone(snapshot.next_cursor)
        self.assertEqual(len(kea.bodies("reservation-get-page")), 2)

    def test_rejects_a_cursor_that_does_not_advance(self):
        stalled = _res_page([], next_from=2, next_source=1)
        client = kea_client(url="http://kea.example.invalid", send_service=False)

        with stub_kea({"reservation-get-page": stalled}):
            with self.assertRaisesRegex(RuntimeError, "did not advance"):
                client.reservation_snapshot(4, _catalogue(4, 20, "198.18.0.0/24"), page_size=2)

    def test_bounds_empty_pages_whose_cursor_keeps_advancing(self):
        """Stop a backend that answers empty pages forever with a new cursor each time.

        Only a non-empty page moves the traversal towards its limit, and the repeated
        cursor check never fires while the cursor keeps changing, so the request loop
        needs its own bound.
        """
        advancing = queued(*(_res_page([], next_from=index, next_source=1) for index in range(2, 12)))
        client = kea_client(url="http://kea.example.invalid", send_service=False)

        with stub_kea({"reservation-get-page": advancing}) as kea:
            with self.assertRaisesRegex(RuntimeError, "only empty pages"):
                client.reservation_page(4, _catalogue(4, 20, "198.18.0.0/24"), limit=2)

        self.assertEqual(len(kea.bodies("reservation-get-page")), 9)

    def test_an_empty_page_between_real_ones_does_not_exhaust_the_bound(self):
        """A source transition answers empty, so it must not count towards the stall bound.

        The counter used to accumulate over a whole call, so a sparse but healthy backend
        failed with "returned only empty pages" after nine transitions, having read plenty.
        """
        interleaved = queued(
            *[
                page
                for index in range(10)
                for page in (
                    _res_page([], next_from=2 * index + 1, next_source=1),
                    _res_page(
                        [{"subnet-id": 20, "hw-address": f"aa:bb:cc:dd:00:{index:02x}"}],
                        next_from=2 * index + 2,
                        next_source=1,
                    ),
                )
            ]
        )
        client = kea_client(url="http://kea.example.invalid", send_service=False)

        with stub_kea({"reservation-get-page": interleaved}):
            page = client.reservation_page(4, _catalogue(4, 20, "198.18.0.0/24"), limit=10)

        self.assertEqual(len(page.records), 10)
        self.assertEqual(page.diagnostics, ())

    def test_bounds_a_traversal_whose_cursor_never_repeats(self):
        """A backend that always answers a full page with a fresh cursor must not run on.

        Neither the exhausted-cursor check nor the repeat check fires, so the record list
        and the seen-cursor set would grow without end.
        """
        from netbox_kea.kea import _MAX_RESERVATION_SNAPSHOT_PAGES

        counter = itertools.count(1)

        def always_more(body):
            index = next(counter)
            return _res_page(
                [
                    {
                        "subnet-id": 20,
                        "hw-address": f"aa:bb:cc:{index // 65536 % 256:02x}:{index // 256 % 256:02x}:{index % 256:02x}",
                    }
                ],
                next_from=index,
                next_source=1,
            )

        client = kea_client(url="http://kea.example.invalid", send_service=False)

        with stub_kea({"reservation-get-page": always_more}):
            snapshot = client.reservation_snapshot(4, _catalogue(4, 20, "198.18.0.0/24"), page_size=1)

        self.assertFalse(snapshot.complete)
        self.assertTrue(snapshot.traversal_truncated)
        self.assertEqual([d.code for d in snapshot.diagnostics], ["page-limit-reached"])
        self.assertEqual(len(snapshot.records), _MAX_RESERVATION_SNAPSHOT_PAGES)

    def test_preserves_records_and_reports_a_cursor_cycle_across_pages(self):
        pages = queued(
            _res_page([{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01"}], next_from=1, next_source=1),
            _res_page([{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:02"}], next_from=2, next_source=1),
            _res_page([{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:03"}], next_from=1, next_source=1),
        )
        client = kea_client(url="http://kea.example.invalid", send_service=False)

        with stub_kea({"reservation-get-page": pages}):
            snapshot = client.reservation_snapshot(4, _catalogue(4, 20, "198.18.0.0/24"), page_size=1)

        self.assertEqual(len(snapshot.records), 3)
        self.assertFalse(snapshot.complete)
        self.assertEqual(snapshot.diagnostics[-1].code, "pagination-stalled")
        self.assertEqual(snapshot.diagnostics[-1].source_position, "pages[2].next")


def _capabilities(family: Family, configuration: dict) -> ReservationCapabilities | None:
    """Return the Reservation capabilities that the parsed *configuration* shows."""
    return server_configuration.reservation_capabilities(observed_configuration(family, configuration))


class TestReservationCapabilities(TestCase):
    def test_uses_the_family_configuration_and_the_flex_id_hook(self):
        capabilities = _capabilities(
            4,
            {
                "host-reservation-identifiers": ["hw-address", "flex-id", "remote-id"],
                "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_flex_id.so"}, *_host_cmds_hooks()],
            },
        )

        self.assertIsInstance(capabilities, ReservationCapabilities)
        self.assertEqual(capabilities.family, 4)
        self.assertEqual(capabilities.identifiers, ("hw-address", "flex-id"))
        self.assertTrue(capabilities.mutation_available)
        self.assertEqual(capabilities.explanation, "")
        self.assertIn(
            ("duid", "This identifier is not enabled in host-reservation-identifiers."),
            capabilities.unavailable_identifiers,
        )

    def test_without_the_host_cmds_hook_mutation_is_unavailable(self):
        capabilities = _capabilities(6, {"host-reservation-identifiers": ["duid", "flex-id"]})

        self.assertFalse(capabilities.mutation_available)
        self.assertEqual(capabilities.identifiers, ("duid",))
        self.assertEqual(capabilities.explanation, "The host_cmds hook is not loaded.")
        self.assertIn(("flex-id", "The Flex ID hook is not configured."), capabilities.unavailable_identifiers)

    def test_a_hook_is_matched_by_its_library_name_not_by_its_path(self):
        for library in ("/opt/libdhcp_host_cmds/libdhcp_lease_cmds.so", "/usr/lib/kea/hooks/libdhcp_host_cmds_old.so"):
            with self.subTest(library=library):
                capabilities = _capabilities(4, {"hooks-libraries": [{"library": library}]})
                self.assertFalse(capabilities.mutation_available)
                self.assertEqual(capabilities.explanation, "The host_cmds hook is not loaded.")
        flex_directory = {"library": "/opt/libdhcp_flex_id/libdhcp_lease_cmds.so"}
        capabilities = _capabilities(
            4, {"host-reservation-identifiers": ["flex-id"], "hooks-libraries": [flex_directory, *_host_cmds_hooks()]}
        )
        self.assertEqual(capabilities.identifiers, ())
        loaded = _capabilities(4, {"hooks-libraries": [{"library": "libdhcp_host_cmds.so"}]})
        self.assertTrue(loaded.mutation_available)

    def test_an_invalid_reservation_fact_leaves_the_capabilities_unconfirmed(self):
        for configuration in (
            {"host-reservation-identifiers": None, "hooks-libraries": _host_cmds_hooks()},
            {"hooks-libraries": "libdhcp_host_cmds.so"},
            {"hooks-libraries": [*_host_cmds_hooks(), {"library": 1}]},
        ):
            with self.subTest(configuration=configuration):
                snapshot = observed_configuration(4, configuration)
                self.assertIsNone(server_configuration.reservation_capabilities(snapshot))
                # The other pages show no Notice for a fact that only the Reservation capabilities read.
                self.assertTrue(snapshot.complete)
                self.assertEqual(snapshot.diagnostics, ())
                self.assertEqual(len(snapshot.reservation_diagnostics), 1)

    def test_uses_family_defaults_when_host_reservation_identifiers_are_absent(self):
        capabilities = _capabilities(6, {"hooks-libraries": _host_cmds_hooks()})

        self.assertEqual(capabilities.identifiers, ("duid", "hw-address"))
        self.assertTrue(capabilities.mutation_available)


class TestApplyReservationChange(SimpleTestCase):
    """One ReservationChange serves both families, so each apply must stay family-safe."""

    def _v4(self, **overrides) -> IPv4Reservation:
        defaults = {
            "scope": InSubnetReservationScope(subnet=SubnetIdentity(subnet_id=20, network=ip_network("198.18.0.0/24"))),
            "identity": ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff"),
            "addresses": (ip_address("198.18.0.10"),),
            "hostname": "host-v4",
        }
        return IPv4Reservation(**{**defaults, **overrides})

    def _v6(self, **overrides) -> IPv6Reservation:
        defaults = {
            "scope": InSubnetReservationScope(subnet=SubnetIdentity(subnet_id=30, network=ip_network("2001:db8::/64"))),
            "identity": ReservationIdentity("duid", "00:01:02:03"),
            "addresses": (ip_address("2001:db8::10"),),
            "delegated_prefixes": (),
            "hostname": "host-v6",
        }
        return IPv6Reservation(**{**defaults, **overrides})

    def test_a_v4_address_change_keeps_the_v4_record(self):
        applied = apply_reservation_change(
            self._v4(), ReservationChange(addresses=SetValue((ip_address("198.18.0.11"),)))
        )

        self.assertIsInstance(applied, IPv4Reservation)
        self.assertEqual(applied.addresses, (ip_address("198.18.0.11"),))
        self.assertEqual(applied.delegated_prefixes, ())

    def test_a_v6_change_lands_both_addresses_and_delegated_prefixes(self):
        change = ReservationChange(
            addresses=SetValue((ip_address("2001:db8::11"),)),
            delegated_prefixes=SetValue((ip_network("2001:db8:1::/48"),)),
        )

        applied = apply_reservation_change(self._v6(), change)

        self.assertIsInstance(applied, IPv6Reservation)
        self.assertEqual(applied.addresses, (ip_address("2001:db8::11"),))
        self.assertEqual(applied.delegated_prefixes, (ip_network("2001:db8:1::/48"),))

    def test_a_delegated_prefix_on_a_v4_record_is_still_rejected(self):
        """The narrowing casts must not swallow what __post_init__ rejects."""
        change = ReservationChange(delegated_prefixes=SetValue((ip_network("2001:db8:1::/48"),)))

        with self.assertRaisesRegex(ValueError, "does not support delegated prefixes"):
            apply_reservation_change(self._v4(), change)

    def test_a_v6_address_on_a_v4_record_is_still_rejected(self):
        change = ReservationChange(addresses=SetValue((ip_address("2001:db8::10"),)))

        with self.assertRaisesRegex(ValueError, "must use the Reservation family"):
            apply_reservation_change(self._v4(), change)

    def test_clearing_the_hostname_leaves_the_other_facts_alone(self):
        applied = apply_reservation_change(self._v6(), ReservationChange(hostname=ClearValue()))

        self.assertEqual(applied.hostname, "")
        self.assertEqual(applied.addresses, (ip_address("2001:db8::10"),))

    def test_an_option_edit_is_refused_because_only_the_raw_record_merge_keeps_live_keys(self):
        option = parse_dhcp_options([{"name": "domain-name", "data": "example.com"}])[0]
        change = ReservationChange(options=DHCPOptionEdit((), (DHCPOptionChange(None, option),)))

        with self.assertRaisesRegex(ValueError, "FreshReservation.updated"):
            apply_reservation_change(self._v4(), change)


class TestSynchronizationLabel(SimpleTestCase):
    def test_every_label_carries_a_code(self):
        """The label Literal and the code map are one fact; a label without a code raises."""
        for label in get_args(SynchronizationLabel):
            with self.subTest(label=label):
                self.assertTrue(ReservationSynchronizationState(label=label, synchronized=0, total=0).code)


class TestRawRecordBoundary(SimpleTestCase):
    """Guard the boundary ADR 0004 records: only the adapters see raw Kea records.

    The OpenGrep rule states the same invariant but runs from pre-commit, so this
    reads the rule's own allowed paths and enforces them in CI rather than
    restating them.
    """

    RULE_ID = "kea-reservation-command-outside-adapter"
    PREFIX = "reservation-"

    def _allowed_paths(self) -> list[str]:
        ruleset = yaml.safe_load((_REPOSITORY_ROOT / ".opengrep" / "kea-rules.yaml").read_text(encoding="utf-8"))
        rules = [rule for rule in ruleset["rules"] if rule["id"] == self.RULE_ID]
        self.assertEqual(len(rules), 1, f"{self.RULE_ID} is missing from the OpenGrep ruleset.")
        # The whole `paths` mapping is pinned, not just `exclude`: one line added to the
        # ruleset would otherwise switch off the OpenGrep rule and this CI guard together,
        # silently, and an `include:` narrows OpenGrep just as an `exclude:` widens it.
        # Moving the boundary is a decision, so make it edit this test too.
        self.assertEqual(
            {key: sorted(value) for key, value in rules[0]["paths"].items()},
            {"exclude": ["**/migrations/**", "**/tests/**", "netbox_kea/kea.py"]},
            "The reservation boundary moved. Only netbox_kea/kea.py may read raw Kea "
            "reservation records; see docs/adr/0004 before changing this rule's paths.",
        )
        return rules[0]["paths"]["exclude"]

    @staticmethod
    def _is_command_call(call: ast.Call) -> bool:
        return isinstance(call.func, ast.Attribute) and call.func.attr == "command"

    @staticmethod
    def _command_argument(call: ast.Call) -> ast.expr | None:
        """Return the expression *call* sends as the command, positionally or as ``command=``."""
        named = next((keyword.value for keyword in call.keywords if keyword.arg == "command"), None)
        return call.args[0] if call.args else named

    @classmethod
    def _known_prefix(cls, node: ast.expr | None) -> tuple[str, bool]:
        """Return how much of *node*'s string value the call site shows, and whether that is all of it.

        The expression alone, never a name: resolving one needs scope analysis, and a
        name map that ignores scope reads a parameter or a loop variable as some
        unrelated assignment, which is how a guard like this fails open.  ``("", False)``
        means nothing is known, which every unsupported form returns.
        """
        if isinstance(node, ast.Constant):
            return (node.value, True) if isinstance(node.value, str) else ("", False)
        if isinstance(node, ast.JoinedStr):
            known = ""
            for part in node.values:
                prefix, exact = cls._known_prefix(part)
                known += prefix
                if not exact:
                    return known, False
            return known, True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, exact = cls._known_prefix(node.left)
            if not exact:
                return left, False
            right, exact = cls._known_prefix(node.right)
            return left + right, exact
        return "", False

    @staticmethod
    def _kea_imports(tree: ast.AST) -> set[str]:
        """Return the names that only a module-level ``from ...kea import NAME`` binds in *tree*."""
        imported: set[str] = set()
        rebound: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node in getattr(tree, "body", [])
                and node.module
                and (node.module == "kea" or node.module.endswith(".kea"))
            ):
                imported.update(alias.name for alias in node.names if alias.asname is None)
                rebound.update(alias.asname for alias in node.names if alias.asname)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                rebound.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
            elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                rebound.add(node.id)
            elif isinstance(node, ast.arg):
                rebound.add(node.arg)
            elif isinstance(node, _NAMED_BINDINGS) and node.name:
                rebound.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                rebound.add(node.rest)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                rebound.update(node.names)
        return imported - rebound

    @staticmethod
    def _members(node: ast.expr, kea_names: set[str]) -> list[str] | None:
        """Return the wire names that a ``KeaCommand.X`` or a ``kea`` per-family ``NAME[family]`` can send, else None."""
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "KeaCommand":
            known = "KeaCommand" in kea_names and node.attr in KeaCommand.__members__
            return [KeaCommand[node.attr].value] if known else None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in kea_names:
            by_family = getattr(kea, node.value.id, None)
            if isinstance(by_family, dict) and all(isinstance(member, KeaCommand) for member in by_family.values()):
                return [member.value for member in by_family.values()]
        return None

    @classmethod
    def _reservation_commands(cls, tree: ast.AST) -> list[str]:
        """Return every command call in *tree* that can send a ``reservation-*`` command.

        Fails closed: a command this cannot read at the call site could name anything, so
        it is reported rather than skipped.  ``client.command(f"reservation-{op}")`` and
        ``client.command(chosen)`` are both cases a literal-only scanner missed.
        """
        found: list[str] = []
        kea_names = cls._kea_imports(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and cls._is_command_call(node)):
                continue
            argument = cls._command_argument(node)
            if argument is not None and (members := cls._members(argument, kea_names)) is not None:
                if any(member.startswith(cls.PREFIX) for member in members):
                    found.append(f"{ast.unparse(argument)} (line {node.lineno})")
                continue
            prefix, exact = cls._known_prefix(argument)
            if exact:
                if prefix.startswith(cls.PREFIX):
                    found.append(f"{prefix} (line {node.lineno})")
            elif prefix.startswith(cls.PREFIX) or cls.PREFIX.startswith(prefix):
                shown = ast.unparse(argument) if argument is not None else "<no command argument>"
                found.append(f"{shown} (line {node.lineno})")
        return found

    def test_only_the_adapter_sends_a_reservation_command(self) -> None:
        allowed = self._allowed_paths()
        offenders: list[str] = []
        for source in sorted((_REPOSITORY_ROOT / "netbox_kea").rglob("*.py")):
            relative = source.relative_to(_REPOSITORY_ROOT).as_posix()
            # fnmatch, not Path.full_match: that arrived in 3.13 and this package
            # supports 3.10. fnmatch's "*" spans "/", which is what these globs want.
            if any(fnmatch(relative, pattern) for pattern in allowed):
                continue
            offenders.extend(
                f"{relative}: {command}"
                for command in self._reservation_commands(ast.parse(source.read_text(encoding="utf-8")))
            )

        self.assertEqual(
            offenders,
            [],
            "A reservation-* command outside the adapters hands raw Kea records to a consumer that "
            "cannot read their keys. A command this cannot read at the call site is reported too: "
            "write the name as a literal or an f-string whose leading text is visible. "
            f"See docs/adr/0004 and the {self.RULE_ID} OpenGrep rule. Found: {offenders}",
        )

    def test_the_scanner_sees_a_reservation_command_built_at_run_time(self) -> None:
        """A literal-only scanner let ``f"reservation-{op}"`` through the CI guard."""
        source = (
            'client.command(f"reservation-{operation}", service=["dhcp4"])\n'
            'client.command("reservation-" + operation)\n'
            'name = f"reservation-{operation}"\n'
            "client.command(name)\n"
        )

        self.assertEqual(
            self._reservation_commands(ast.parse(source)),
            [
                "f'reservation-{operation}' (line 1)",
                "'reservation-' + operation (line 2)",
                "name (line 4)",
            ],
        )

    def test_the_scanner_reports_a_command_it_cannot_resolve(self) -> None:
        """An unresolved command could be any command, so the guard fails closed."""
        source = "client.command(chosen_command, service=['dhcp4'])\nclient.command(f'{prefix}-get')\n"

        self.assertEqual(
            self._reservation_commands(ast.parse(source)),
            ["chosen_command (line 1)", "f'{prefix}-get' (line 2)"],
        )

    def test_the_scanner_leaves_a_resolvable_non_reservation_command_alone(self) -> None:
        """Fail-closed must not mean flagging every f-string: these cannot be reservation-*."""
        source = (
            'client.command(f"subnet{version}-list")\n'
            'client.command(f"stat-lease{version}-get")\n'
            'client.command("lease" + str(version) + "-del")\n'
        )

        self.assertEqual(self._reservation_commands(ast.parse(source)), [])

    def test_the_scanner_reads_no_name_through_an_assignment(self) -> None:
        """Resolving a name needs scope analysis; a map that skips it fails open.

        Every binding below puts a reservation command in ``command`` at run time while
        an unrelated module-level ``command = "config-get"`` is in scope. A scanner that
        answered from that assignment map cleared all five.
        """
        for label, binding in (
            ("parameter", "def send(client, command):\n    client.command(command)\n"),
            ("for target", "for command in ops:\n    client.command(command)\n"),
            ("with as", "with chosen() as command:\n    client.command(command)\n"),
            ("walrus", "if (command := ops[0]):\n    client.command(command)\n"),
            ("tuple", "command, service = ops\nclient.command(command)\n"),
        ):
            with self.subTest(label):
                source = 'command = "config-get"\n' + binding

                self.assertEqual(len(self._reservation_commands(ast.parse(source))), 1, label)

    def test_the_scanner_reads_a_command_name_only_through_its_kea_import(self) -> None:
        """A parameter or a local named like a kea map or ``KeaCommand`` is not that object."""
        imports = "from netbox_kea.kea import LEASE_GET_ALL, KeaCommand\n"
        for label, binding in (
            ("map parameter", "def send(client, LEASE_GET_ALL):\n    client.command(LEASE_GET_ALL[4], 4)\n"),
            ("map assignment", "LEASE_GET_ALL = ops\nclient.command(LEASE_GET_ALL[4], 4)\n"),
            ("map, no import", "client.command(LEASE_GET_ALL[4], 4)\n"),
            (
                "map, mapping capture",
                "match ops:\n    case {**LEASE_GET_ALL}:\n        client.command(LEASE_GET_ALL[4], 4)\n",
            ),
            ("enum parameter", "def send(client, KeaCommand):\n    client.command(KeaCommand.CONFIG_GET, 4)\n"),
            ("enum non-member", "client.command(KeaCommand.chosen, 4)\n"),
        ):
            with self.subTest(label):
                source = binding if label.endswith("no import") else imports + binding

                self.assertEqual(len(self._reservation_commands(ast.parse(source))), 1, label)

    def test_the_boundary_scanner_sees_both_command_spellings(self) -> None:
        """The scanner must find either spelling, and ignore the calls it must not."""
        source = (
            "from ..kea import LEASE_GET_ALL, KeaCommand\n"
            "client.command(KeaCommand.RESERVATION_GET_PAGE, 4)\n"
            "client.command(command=KeaCommand.RESERVATION_GET, target=4)\n"
            "client.command(KeaCommand.CONFIG_GET, 4)\n"
            "client.command(command=LEASE_GET_ALL[family], target=family)\n"
        )

        self.assertEqual(
            self._reservation_commands(ast.parse(source)),
            ["KeaCommand.RESERVATION_GET_PAGE (line 2)", "KeaCommand.RESERVATION_GET (line 3)"],
        )


class TestSingleServiceReadsNeedOneReply(SimpleTestCase):
    """A single-service read refuses a reply with more than one entry instead of reading the first."""

    def setUp(self):
        self.kea = kea_client(url="http://kea.example.invalid", send_service=False)
        self.catalogue = _catalogue(4, 20, "198.18.0.0/24")
        self.scope = InSubnetReservationScope(SubnetIdentity(20, ip_network("198.18.0.0/24")))

    def test_two_entry_replies_are_malformed(self):
        identity = ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff")
        host = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        subnet = {"id": 20, "subnet": "198.18.0.0/24"}
        cases = (
            ("reservation-get-page", _res_page([host]), lambda: self.kea.reservation_page(4, self.catalogue)),
            (
                "reservation-get-by-hostname",
                {"result": 0, "arguments": {"hosts": [host]}},
                lambda: self.kea.reservations_by_hostname(4, self.catalogue, "printer"),
            ),
            (
                "reservation-get",
                _res_get(host),
                lambda: self.kea.reservation_by_identity(4, self.catalogue, self.scope, identity),
            ),
            (
                "reservation-get",
                _res_get(host),
                lambda: self.kea.reservation_by_address(4, self.catalogue, self.scope, "198.18.0.20"),
            ),
            ("subnet4-get", {"result": 0, "arguments": {"subnet4": [subnet]}}, lambda: self.kea.subnet_get(4, 20)),
        )
        for command, entry, call in cases:
            with self.subTest(command=command), stub_kea({command: [entry, entry]}):
                with self.assertRaisesRegex(kea.MalformedReply, "one valid result"):
                    call()


class TestReservationMatchContract(SimpleTestCase):
    """The Reservation Match refuses facts that do not fit the Lease: its Subnet, Shared Network and Global lookup."""

    _lease = typed_lease(lease_record("198.18.0.20", subnet_id=20))
    _subnet = _catalogue(4, 20, "198.18.0.0/24").subnets[0]
    _other = _catalogue(4, 21, "198.18.1.0/24").subnets[0]

    def test_a_subnet_that_is_not_the_subnet_of_the_lease_is_refused(self):
        with self.assertRaisesRegex(ValueError, "needs the Subnet of the Lease"):
            reservation_match(self._lease, self._other, None, None, global_reservation=None)

    def test_a_shared_network_that_does_not_hold_the_subnet_of_the_lease_is_refused(self):
        with self.assertRaisesRegex(ValueError, "must hold the Subnet of the Lease"):
            reservation_match(self._lease, self._subnet, None, (self._other,), global_reservation=None)

    def test_a_global_reservation_where_kea_does_not_try_one_is_refused(self):
        global_reservation = _typed_reservation({"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ff"})
        with self.assertRaisesRegex(ValueError, "only where Kea tries it"):
            reservation_match(self._lease, self._subnet, None, None, global_reservation=global_reservation)


def _recorded_host(family: Family) -> dict:
    """Return the In-Subnet host that the coverage configuration of *family* reserves, as Kea 3.2 returned it."""
    recording = json.loads((Path(__file__).with_name("kea_recordings") / f"dhcp{family}.json").read_text())
    office = recording["config-get"]["arguments"][f"Dhcp{family}"]["shared-networks"][1]
    # reservation-get returns the host of config-get with its subnet-id.
    return {**office[f"subnet{family}"][1]["reservations"][0], "subnet-id": 21}


#: Kea's next-server of a host that sets none, not an address to bind.
_UNSET_NEXT_SERVER = "0.0.0.0"  # noqa: S104


class TestWidenedReservationKeys(SimpleTestCase):
    """The adapter reads every host reservation key that the DHCP Import needs, as Kea 3.2 returns it."""

    def setUp(self):
        self.kea = kea_client(url="http://kea.example.invalid", send_service=False)

    def _read(self, family: Family, raw: dict, cidr: str):
        catalogue = _catalogue(family, raw["subnet-id"], cidr)
        scope = InSubnetReservationScope(SubnetIdentity(raw["subnet-id"], ip_network(cidr)))
        identity = next(
            ReservationIdentity(key, raw[key]) for key in reservation_identifier_types(family) if key in raw
        )
        with stub_kea({"reservation-get": _res_get(raw)}):
            return self.kea.reservation_by_identity(family, catalogue, scope, identity)

    def test_the_recorded_dhcpv4_host_keeps_its_classes_boot_fields_and_user_context(self):
        reservation = self._read(4, _recorded_host(4), "198.51.100.128/25")

        self.assertEqual(reservation.client_classes, ("voip",))
        self.assertEqual(reservation.next_server, ip_address("192.0.2.5"))
        self.assertEqual(reservation.server_hostname, "boot.example.org")
        self.assertEqual(reservation.boot_file_name, "host.efi")
        self.assertEqual(reservation.user_context, {"asset": 42})

    def test_the_unset_boot_fields_that_kea_returns_are_empty(self):
        raw = {**_recorded_host(4), "next-server": _UNSET_NEXT_SERVER, "server-hostname": "", "boot-file-name": ""}
        raw.pop("user-context")

        reservation = self._read(4, raw, "198.51.100.128/25")

        self.assertIsNone(reservation.next_server)
        self.assertEqual((reservation.server_hostname, reservation.boot_file_name), ("", ""))
        self.assertIsNone(reservation.user_context)

    def test_the_recorded_dhcpv6_host_pairs_its_excluded_prefix_with_its_delegated_prefix(self):
        reservation = self._read(6, _recorded_host(6), "2001:db8:3::/64")

        self.assertEqual(reservation.client_classes, ("voip",))
        self.assertEqual(
            reservation.excluded_prefixes,
            (ExcludedPrefix(ip_network("2001:db8:400:100::/56"), ip_network("2001:db8:400:100:ff::/80")),),
        )
        self.assertEqual(reservation.user_context, {"asset": 42})

    def test_an_empty_entry_is_a_delegated_prefix_without_an_excluded_prefix(self):
        # Kea 3.2 returns one entry for each prefix, and an empty one for a prefix that excludes nothing.
        raw = {
            **_recorded_host(6),
            "prefixes": ["2001:db8:500::/56", "2001:db8:600::/56"],
            "excluded-prefixes": ["", "2001:db8:600:ff::/64"],
        }

        reservation = self._read(6, raw, "2001:db8:3::/64")

        self.assertEqual(
            reservation.excluded_prefixes,
            (ExcludedPrefix(ip_network("2001:db8:600::/56"), ip_network("2001:db8:600:ff::/64")),),
        )

    def test_records_that_kea_would_refuse_are_quarantined(self):
        v4, v6 = _recorded_host(4), _recorded_host(6)
        cases = (
            (4, {**v4, "client-classes": "voip"}, "client-classes"),
            (4, {**v4, "client-classes": ["voip", "voip"]}, "client-classes"),
            (4, {**v4, "client-classes": [""]}, "client-classes"),
            (4, {**v4, "next-server": "2001:db8::1"}, "next-server"),
            (4, {**v4, "next-server": "255.255.255.255"}, "next-server"),
            (4, {**v4, "server-hostname": "s" * 64}, "server-hostname"),
            (4, {**v4, "boot-file-name": "b" * 128}, "boot-file-name"),
            (4, {**v4, "excluded-prefixes": ["2001:db8::/64"]}, "excluded-prefixes"),
            (6, {**v6, "excluded-prefixes": []}, "excluded-prefixes"),
            (6, {**v6, "excluded-prefixes": ["2001:db8:400:100:ff::/80", ""]}, "excluded-prefixes"),
            (6, {**v6, "excluded-prefixes": ["2001:db8:700:ff::/64"]}, "excluded-prefixes"),
            (6, {**v6, "excluded-prefixes": ["2001:db8:400::/48"]}, "excluded-prefixes"),
            (6, {**v6, "excluded-prefixes": ["2001:db8:400:100:ff::1/80"]}, "excluded-prefixes"),
            (6, {**v6, "next-server": "192.0.2.1"}, "next-server"),
            (6, {**v6, "boot-file-name": "pxe.efi"}, "boot-file-name"),
        )
        for family, raw, field in cases:
            cidr = "198.51.100.128/25" if family == 4 else "2001:db8:3::/64"
            with self.subTest(family=family, raw={key: raw[key] for key in raw if key == field}):
                with self.assertRaises(MalformedReservation) as raised:
                    self._read(family, raw, cidr)
                # An entry error names its position, such as excluded-prefixes[0].
                self.assertEqual(raised.exception.field.split("[")[0], field)

    def test_an_add_sends_each_widened_key_in_the_form_that_kea_reads(self):
        scope4 = InSubnetReservationScope(SubnetIdentity(21, ip_network("198.51.100.128/25")))
        scope6 = InSubnetReservationScope(SubnetIdentity(21, ip_network("2001:db8:3::/64")))
        delegated = (ip_network("2001:db8:500::/56"), ip_network("2001:db8:600::/56"))
        cases = (
            (
                IPv4Reservation(
                    scope=scope4,
                    identity=ReservationIdentity("hw-address", "aa:bb:cc:00:01:00"),
                    addresses=(),
                    client_classes=("voip", "boot"),
                    next_server=ip_address("192.0.2.5"),
                    server_hostname="boot.example.org",
                    boot_file_name="host.efi",
                    user_context={"asset": 42},
                ),
                {
                    "subnet-id": 21,
                    "hw-address": "aa:bb:cc:00:01:00",
                    "client-classes": ["voip", "boot"],
                    "next-server": "192.0.2.5",
                    "server-hostname": "boot.example.org",
                    "boot-file-name": "host.efi",
                    "user-context": {"asset": 42},
                },
            ),
            (
                IPv6Reservation(
                    scope=scope6,
                    identity=ReservationIdentity("duid", "00:01:02:03"),
                    addresses=(),
                    delegated_prefixes=delegated,
                    client_classes=("voip",),
                    excluded_prefixes=(ExcludedPrefix(delegated[1], ip_network("2001:db8:600:ff::/64")),),
                ),
                {
                    "subnet-id": 21,
                    "duid": "00:01:02:03",
                    "prefixes": ["2001:db8:500::/56", "2001:db8:600::/56"],
                    "excluded-prefixes": ["", "2001:db8:600:ff::/64"],
                    "client-classes": ["voip"],
                },
            ),
        )
        for reservation, expected in cases:
            with self.subTest(family=reservation.family), stub_kea({"reservation-add": {"result": 0}}) as kea:
                self.kea.reservation_add(reservation)
            self.assertEqual(kea.bodies("reservation-add")[0]["arguments"]["reservation"], expected)

    def test_the_fingerprint_covers_each_editable_key_and_not_the_user_context(self):
        recorded = self._read(4, _recorded_host(4), "198.51.100.128/25")
        fingerprint = reservation_fingerprint(recorded)
        for changed in (
            {"client_classes": ("voip", "boot")},
            {"next_server": ip_address("192.0.2.6")},
            {"server_hostname": "other.example.org"},
            {"boot_file_name": "other.efi"},
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(reservation_fingerprint(replace(recorded, **changed)), fingerprint)
        self.assertEqual(reservation_fingerprint(replace(recorded, user_context={"asset": 43})), fingerprint)
        v6 = self._read(6, _recorded_host(6), "2001:db8:3::/64")
        moved = ExcludedPrefix(v6.delegated_prefixes[0], ip_network("2001:db8:400:100:fe::/80"))
        self.assertNotEqual(
            reservation_fingerprint(replace(v6, excluded_prefixes=(moved,))), reservation_fingerprint(v6)
        )

    def test_the_model_refuses_values_that_kea_refuses(self):
        v4 = self._read(4, _recorded_host(4), "198.51.100.128/25")
        v6 = self._read(6, _recorded_host(6), "2001:db8:3::/64")
        other = ExcludedPrefix(ip_network("2001:db8:900::/56"), ip_network("2001:db8:900:ff::/64"))
        for reservation, changed in (
            (v4, {"client_classes": ("voip", "voip")}),
            (v4, {"client_classes": (" voip",)}),
            (v4, {"next_server": ip_address(_UNSET_NEXT_SERVER)}),
            (v4, {"next_server": ip_address("255.255.255.255")}),
            (v4, {"server_hostname": "s" * 64}),
            (v4, {"boot_file_name": "b" * 128}),
            (v6, {"excluded_prefixes": (other,)}),
            (v6, {"excluded_prefixes": (*v6.excluded_prefixes, *v6.excluded_prefixes)}),
            (v6, {"boot_file_name": "pxe.efi"}),
        ):
            with self.subTest(family=reservation.family, changed=changed), self.assertRaises(ValueError):
                replace(reservation, **changed)
        with self.assertRaisesRegex(ValueError, "longer prefix inside"):
            ExcludedPrefix(ip_network("2001:db8:900::/56"), ip_network("2001:db8:900::/48"))
