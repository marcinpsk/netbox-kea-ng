# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Reservation Match of a Lease: the lookup walk and the rule, with an in-memory Reservation lookup.

The Subnet Catalogue of each case is parsed from Kea replies. Only the Reservation lookups are in memory.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from django.test import SimpleTestCase, TestCase

from netbox_kea import subnet_catalogue
from netbox_kea.constants import Family
from netbox_kea.reservations import (
    HostOnlyReservation,
    IgnoredReservation,
    IgnoredReservationReason,
    InSubnetReservationScope,
    OtherKindReservation,
    PendingAddressChange,
    Reservation,
    ReservationIdentity,
    ReservationKey,
    ReservationMatch,
    ReservationMatchUnknown,
    ReservationScope,
    Reserved,
    StaleMac,
    UnknownReservationMatch,
    Unreserved,
    reservation_match,
)
from netbox_kea.subnet_catalogue import CatalogueSnapshot, SubnetIdentity, VerifiedSubnet

from .kea_stub import _catalogue_responses_for_subnets, _typed_reservation, lease_record, stub_kea, typed_lease
from .utils import _make_db_server, with_display_cache_config

_SUBNETS = {4: [{"id": 20, "subnet": "198.18.0.0/24"}], 6: [{"id": 30, "subnet": "2001:db8::/64"}]}
_MAC = "aa:bb:cc:dd:ee:ff"
_DUID = "00:01:02:03:04:05"
_PREFIX = "2001:db8:100::/56"
_LONG_CLIENT_ID = ":".join(["01"] * 129)
#: The global flag that lets each Subnet apply Global Reservations; Kea's default is false.
_GLOBAL_RESERVATIONS = {"reservations-global": True}


class FakeReservationLookup:
    """A ``ReservationLookup`` that answers by exact scope and key from typed Reservations, and records each lookup."""

    def __init__(self, *reservations: Reservation) -> None:
        self._reservations = reservations
        self.calls: list[tuple[ReservationScope, ReservationKey]] = []

    def find(self, scope: ReservationScope, key: ReservationKey) -> Reservation | None:
        self.calls.append((scope, key))
        return next((reservation for reservation in self._reservations if _holds(reservation, scope, key)), None)

    def walk(self) -> list[tuple[int, str]]:
        """Return each lookup as (Subnet ID, address, prefix or identifier type), in order; 0 is the Global scope."""
        return [
            (
                scope.subnet.subnet_id if isinstance(scope, InSubnetReservationScope) else 0,
                key.identifier_type if isinstance(key, ReservationIdentity) else str(key),
            )
            for scope, key in self.calls
        ]


def _holds(reservation: Reservation, scope: ReservationScope, key: ReservationKey) -> bool:
    if reservation.scope != scope:
        return False
    if isinstance(key, ReservationIdentity):
        return reservation.identity == key
    if isinstance(key, ipaddress.IPv6Network):
        return key in reservation.delegated_prefixes
    return key in reservation.addresses


def _address_lease(address: str = "198.18.0.20", *, subnet_id: int = 20, **changes: Any) -> dict:
    """Return a DHCPv4 Lease that carries the hardware address *_MAC* and no client ID."""
    return lease_record(address, subnet_id=subnet_id, drop=("client-id",), **{"hw_address": _MAC, **changes})


def _prefix_lease(prefix: str = _PREFIX) -> dict:
    address, length = prefix.split("/")
    return lease_record(address, type="IA_PD", prefix_len=int(length), subnet_id=30, duid=_DUID, drop=("hw-address",))


def _allocation(text: str) -> Any:
    return ipaddress.ip_network(text) if "/" in text else ipaddress.ip_address(text)


def _pending(*allocations: str) -> Callable[[Reservation], ReservationMatch]:
    """Return the Pending Address Change of a Reservation to *allocations*."""
    return lambda reservation: PendingAddressChange(reservation, tuple(map(_allocation, allocations)))


def _unknown_shared_network(_reservation: Reservation) -> ReservationMatch:
    return ReservationMatchUnknown(UnknownReservationMatch.UNKNOWN_SHARED_NETWORK)


def _flags_unknown(_reservation: Reservation) -> ReservationMatch:
    return ReservationMatchUnknown(UnknownReservationMatch.RESERVATION_FLAGS_UNKNOWN)


def _pools_unknown(_reservation: Reservation) -> ReservationMatch:
    return ReservationMatchUnknown(UnknownReservationMatch.POOLS_UNKNOWN)


def _ignored(reason: IgnoredReservationReason) -> Callable[[Reservation], ReservationMatch]:
    return lambda reservation: IgnoredReservation(reservation, reason)


def _address6(address: str) -> dict:
    return lease_record(address, subnet_id=30, duid=_DUID, drop=("hw-address",))


# Each case reads its own Catalogue, with the reservation flags that it sets.
@with_display_cache_config(configuration_ttl=0)
class ReservationMatchTest(TestCase):
    """The Reservation Match of one Lease, from the Reservations that the lookups of the walk find."""

    def setUp(self):
        self.server = _make_db_server()

    def _catalogue(self, family: Family, responses: dict | None = None) -> CatalogueSnapshot:
        replies = {
            **_catalogue_responses_for_subnets(family, _SUBNETS[family], global_settings=_GLOBAL_RESERVATIONS),
            **(responses or {}),
        }
        with stub_kea(replies):
            return subnet_catalogue.display(self.server, family)

    def _walk(
        self, lease: dict, *hosts: dict, family: Family = 4, responses: dict | None = None
    ) -> tuple[ReservationMatch, FakeReservationLookup]:
        catalogue = self._catalogue(family, responses)
        typed = typed_lease(lease)
        subnet = catalogue.find_by_id(typed.subnet_id)
        assert isinstance(subnet, VerifiedSubnet)
        lookup = FakeReservationLookup(*(_typed_reservation(host) for host in hosts))
        return reservation_match(typed, subnet, catalogue.shared_network_subnets(subnet), lookup), lookup

    def _match(self, lease: dict, *hosts: dict, family: Family = 4, responses: dict | None = None) -> ReservationMatch:
        match, _lookup = self._walk(lease, *hosts, family=family, responses=responses)
        return match

    def test_only_the_allocations_of_a_global_reservation_in_the_lease_subnet_count(self):
        address6 = _address6("2001:db8::20")
        nothing = {"hostname": "global", "ip-addresses": [], "prefixes": []}
        cases = (
            (4, _address_lease(), {"ip-address": "198.18.0.21"}, _pending("198.18.0.21")),
            (4, _address_lease(), {"hostname": "global"}, HostOnlyReservation),
            (4, _address_lease(), {"ip-address": "198.19.0.21"}, HostOnlyReservation),
            (4, _address_lease(), {"ip-address": "198.18.0.20"}, Reserved),
            (6, address6, {"ip-addresses": ["2001:db8::21"]}, _pending("2001:db8::21")),
            (6, address6, nothing, HostOnlyReservation),
            (6, address6, {"ip-addresses": ["2001:db8:1::21"]}, HostOnlyReservation),
            (6, address6, {"ip-addresses": ["2001:db8::20"]}, Reserved),
            (6, address6, {"ip-addresses": ["2001:db8:1::21", "2001:db8::21"]}, _pending("2001:db8::21")),
            (6, address6, {"ip-addresses": ["2001:db8:1::21", "2001:db8::20"]}, Reserved),
            (6, address6, {"ip-addresses": ["2001:db8:1::21"], "prefixes": [_PREFIX]}, OtherKindReservation),
            (6, _prefix_lease(), {"prefixes": ["2001:db8:100:700::/56"]}, _pending("2001:db8:100:700::/56")),
            (6, _prefix_lease(), nothing, HostOnlyReservation),
            (6, _prefix_lease(), {"ip-addresses": ["2001:db8:1::21"]}, HostOnlyReservation),
            (6, _prefix_lease(), {"prefixes": [_PREFIX]}, Reserved),
        )
        for family, lease, allocations, outcome in cases:
            identifier = {"hw-address": _MAC} if family == 4 else {"duid": _DUID}
            host = {"subnet-id": 0, **identifier, **allocations}
            with self.subTest(family=family, host=host):
                self.assertEqual(self._match(lease, host, family=family), outcome(_typed_reservation(host)))

    def test_a_reserved_prefix_counts_in_every_subnet(self):
        """Kea delegates a prefix of a Global Reservation in any Subnet: it checks only an address against a Subnet."""
        host = {"subnet-id": 0, "duid": _DUID, "prefixes": ["2001:db9:700::/56"]}

        match = self._match(_prefix_lease(), host, family=6)

        self.assertEqual(match, _pending("2001:db9:700::/56")(_typed_reservation(host)))

    def test_a_global_address_in_a_sibling_subnet_counts_only_when_its_flags_show_that_kea_gives_it(self):
        """DHCPv4 needs reservations-global and no class filter on the sibling; DHCPv6 needs reservations-global."""
        address6 = _address6("2001:db8::20")
        shared = {
            4: [{"id": 21, "subnet": "198.18.1.0/24"}, {"id": 22, "subnet": "198.19.0.0/24"}],
            6: [{"id": 31, "subnet": "2001:db8:1::/64"}, {"id": 32, "subnet": "2001:db9::/64"}],
        }
        disabled = {"reservations-global": False}
        classes = {"client-classes": ["voip"]}
        cases = (
            (4, _address_lease(), {}, {"hw-address": _MAC, "ip-address": "198.18.1.21"}, _pending("198.18.1.21")),
            (4, _address_lease(), disabled, {"hw-address": _MAC, "ip-address": "198.18.1.21"}, _unknown_shared_network),
            (4, _address_lease(), classes, {"hw-address": _MAC, "ip-address": "198.18.1.21"}, _unknown_shared_network),
            (4, _address_lease(), {}, {"hw-address": _MAC, "ip-address": "198.19.0.21"}, HostOnlyReservation),
            (6, address6, {}, {"duid": _DUID, "ip-addresses": ["2001:db8:1::21"]}, _pending("2001:db8:1::21")),
            # DHCPv6 walks the siblings by range, so a class filter does not stop it.
            (6, address6, classes, {"duid": _DUID, "ip-addresses": ["2001:db8:1::21"]}, _pending("2001:db8:1::21")),
            (6, address6, disabled, {"duid": _DUID, "ip-addresses": ["2001:db8:1::21"]}, _unknown_shared_network),
            (
                6,
                address6,
                {},
                {"duid": _DUID, "ip-addresses": ["2001:db8:1::21", "2001:db8::21"]},
                _pending("2001:db8:1::21", "2001:db8::21"),
            ),
            (
                6,
                address6,
                disabled,
                {"duid": _DUID, "ip-addresses": ["2001:db8:1::21", "2001:db8::21"]},
                _unknown_shared_network,
            ),
            (6, address6, {}, {"duid": _DUID, "ip-addresses": ["2001:db9::21"]}, HostOnlyReservation),
            (6, address6, disabled, {"duid": _DUID, "ip-addresses": ["2001:db8:1::21", "2001:db8::20"]}, Reserved),
        )
        for family, lease, sibling_settings, allocations, outcome in cases:
            [subnet] = _SUBNETS[family]
            sibling, other = shared[family]
            catalogue = _catalogue_responses_for_subnets(
                family,
                [subnet, {**sibling, **sibling_settings}, other],
                shared_networks=[{"name": "shared"}],
                members={subnet["id"]: "shared", sibling["id"]: "shared"},
                global_settings=_GLOBAL_RESERVATIONS,
            )
            host = {"subnet-id": 0, **allocations}
            with self.subTest(host=host, sibling=sibling_settings):
                match = self._match(lease, host, family=family, responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(host)))

    def test_a_sibling_whose_flags_or_classes_are_not_shown_leaves_its_address_possible(self):
        """An invalid sibling flag also hides the Shared Network flags of the Lease's Subnet, so the facts are edited."""
        [subnet] = _SUBNETS[4]
        catalogue = _catalogue_responses_for_subnets(
            4,
            [subnet, {"id": 21, "subnet": "198.18.1.0/24"}],
            shared_networks=[{"name": "shared"}],
            members={20: "shared", 21: "shared"},
            global_settings=_GLOBAL_RESERVATIONS,
        )
        own, sibling = self._catalogue(4, catalogue).subnets
        host = {"subnet-id": 0, "hw-address": _MAC, "ip-address": "198.18.1.21"}
        reservation, lease = _typed_reservation(host), typed_lease(_address_lease())
        for label, hidden in (
            ("flags", replace(sibling, reservation_flags=None)),
            ("classes", replace(sibling, configuration=None)),
        ):
            with self.subTest(label):
                match = reservation_match(lease, own, (own, hidden), FakeReservationLookup(reservation))
                self.assertEqual(match, _unknown_shared_network(reservation))
        # The control: the facts as Kea shows them let the address count.
        self.assertEqual(
            reservation_match(lease, own, (own, sibling), FakeReservationLookup(reservation)),
            _pending("198.18.1.21")(reservation),
        )

    def test_without_the_shared_network_an_address_outside_the_subnet_is_unknown_only_when_it_can_change_the_match(
        self,
    ):
        """A Subnet list entry that does not parse hides which Subnets the Shared Network of the Lease holds."""
        address6 = _address6("2001:db8::20")
        outside4, outside6 = "198.19.0.21", "2001:db8:1::21"
        cases = (
            (4, _address_lease(), {"subnet-id": 0, "ip-address": outside4}, _unknown_shared_network),
            (4, _address_lease(), {"subnet-id": 0, "ip-address": "198.18.0.21"}, _pending("198.18.0.21")),
            (4, _address_lease(), {"subnet-id": 20, "ip-address": "198.18.0.21"}, _pending("198.18.0.21")),
            (6, address6, {"subnet-id": 0, "ip-addresses": ["2001:db8::20", outside6]}, Reserved),
            (6, address6, {"subnet-id": 0, "ip-addresses": ["2001:db8::21", outside6]}, _unknown_shared_network),
            (6, _prefix_lease(), {"subnet-id": 0, "ip-addresses": [outside6], "prefixes": [_PREFIX]}, Reserved),
            (6, _prefix_lease(), {"subnet-id": 0, "ip-addresses": [outside6]}, _unknown_shared_network),
        )
        for family, lease, allocations, outcome in cases:
            [subnet] = _SUBNETS[family]
            catalogue = _catalogue_responses_for_subnets(
                family,
                [subnet],
                shared_networks=[{"name": "shared"}],
                members={subnet["id"]: "shared"},
                global_settings=_GLOBAL_RESERVATIONS,
            )
            catalogue[f"subnet{family}-list"]["arguments"]["subnets"].append({"id": "x", "subnet": "unparsed"})
            host = {"hw-address": _MAC, **allocations} if family == 4 else {"duid": _DUID, **allocations}
            with self.subTest(host=host):
                match = self._match(lease, host, family=family, responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(host)))

    def test_a_reservation_of_a_scope_that_the_subnet_disables_is_ignored(self):
        in_subnet = {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.20"}
        global_ = {"subnet-id": 0, "hw-address": _MAC, "ip-address": "198.18.0.20"}
        no_in_subnet = {"reservations-in-subnet": False}
        cases = (
            # Kea's default: reservations-global is false.
            ({}, (global_,), _ignored(IgnoredReservationReason.GLOBAL_RESERVATIONS_DISABLED), global_),
            ({}, (in_subnet, global_), Reserved, in_subnet),
            (no_in_subnet, (in_subnet,), _ignored(IgnoredReservationReason.IN_SUBNET_RESERVATIONS_DISABLED), in_subnet),
            # An enabled scope comes first, and a disabled one only when the enabled scopes hold no Reservation.
            ({**no_in_subnet, **_GLOBAL_RESERVATIONS}, (in_subnet, global_), Reserved, global_),
            (
                no_in_subnet,
                (in_subnet, global_),
                _ignored(IgnoredReservationReason.IN_SUBNET_RESERVATIONS_DISABLED),
                in_subnet,
            ),
        )
        for settings, hosts, outcome, found in cases:
            catalogue = _catalogue_responses_for_subnets(4, _SUBNETS[4], global_settings=settings)
            with self.subTest(settings=settings, hosts=hosts):
                match = self._match(_address_lease(), *hosts, responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(found)))

    def test_with_out_of_pool_an_in_subnet_address_in_a_pool_does_not_count(self):
        """Kea gives an In-Subnet reserved address only outside the Pools (AllocEngine hasAddressReservation)."""
        pool = {"pools": [{"pool": "198.18.0.100 - 198.18.0.200"}]}
        out_of_pool = {"reservations-out-of-pool": True, **_GLOBAL_RESERVATIONS}

        def host(address: str | None, subnet_id: int = 20, mac: str = _MAC) -> dict:
            return {"subnet-id": subnet_id, "hw-address": mac, **({"ip-address": address} if address else {})}

        ignored = _ignored(IgnoredReservationReason.OUT_OF_POOL)
        other_mac = "aa:bb:cc:dd:ee:01"
        cases = (
            (out_of_pool, _address_lease(), host("198.18.0.150"), ignored),
            # Kea renews the Lease of the reserved address: it is in a Pool, and it is not reserved for another client.
            (out_of_pool, _address_lease("198.18.0.150"), host("198.18.0.150"), Reserved),
            (
                out_of_pool,
                _address_lease("198.18.0.150"),
                host("198.18.0.150", mac=other_mac),
                lambda reservation: StaleMac(reservation, _MAC),
            ),
            (out_of_pool, _address_lease(), host("198.18.0.50"), _pending("198.18.0.50")),
            (out_of_pool, _address_lease(), host(None), HostOnlyReservation),
            # Kea checks only an In-Subnet address against the Pools.
            (out_of_pool, _address_lease(), host("198.18.0.150", subnet_id=0), _pending("198.18.0.150")),
            (_GLOBAL_RESERVATIONS, _address_lease(), host("198.18.0.150"), _pending("198.18.0.150")),
        )
        for settings, lease, reserved, outcome in cases:
            catalogue = _catalogue_responses_for_subnets(4, [{**_SUBNETS[4][0], **pool}], global_settings=settings)
            with self.subTest(settings=settings, host=reserved):
                match = self._match(lease, reserved, responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(reserved)))

    def test_with_out_of_pool_a_reserved_prefix_is_unknown_only_for_a_prefix_lease_that_it_can_change(self):
        """Kea also checks a prefix against the PD Pools, which the configuration facts do not hold.

        An address Lease does not depend on them: Kea allocates each IA by itself (AllocEngine allocateReservedLeases6).
        """
        address6, held6 = _address6("2001:db8::20"), _address6("2001:db8::150")
        pool = {"pools": [{"pool": "2001:db8::100 - 2001:db8::200"}]}
        out_of_pool = {"reservations-out-of-pool": True}
        cases = (
            (
                address6,
                {"ip-addresses": ["2001:db8::150"], "prefixes": [_PREFIX]},
                _ignored(IgnoredReservationReason.OUT_OF_POOL),
            ),
            (address6, {"ip-addresses": ["2001:db8::20"], "prefixes": [_PREFIX]}, Reserved),
            # Kea keeps an existing Lease of a reserved allocation before it checks the Pools.
            (held6, {"ip-addresses": ["2001:db8::150"], "prefixes": [_PREFIX]}, Reserved),
            (_prefix_lease(), {"prefixes": [_PREFIX]}, Reserved),
            (_prefix_lease(), {"ip-addresses": ["2001:db8::20"], "prefixes": [_PREFIX]}, Reserved),
            (_prefix_lease(), {"prefixes": ["2001:db8:200::/56"]}, _pools_unknown),
        )
        for lease, allocations, outcome in cases:
            catalogue = _catalogue_responses_for_subnets(6, [{**_SUBNETS[6][0], **pool}], global_settings=out_of_pool)
            host = {"subnet-id": 30, "duid": _DUID, **allocations}
            with self.subTest(lease=lease["ip-address"], host=host):
                match = self._match(lease, host, family=6, responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(host)))

    def test_pools_that_the_configuration_does_not_show_leave_an_in_subnet_address_unknown_when_they_change_it(self):
        [subnet] = _SUBNETS[4]
        catalogue = _catalogue_responses_for_subnets(4, [subnet], global_settings={"reservations-out-of-pool": True})
        [own] = self._catalogue(4, catalogue).subnets
        hidden = replace(own, configuration=None)
        reservation = _typed_reservation({"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.150"})
        cases = (
            (_address_lease(), _pools_unknown(reservation)),
            # A Lease of the reserved address is Reserved with or without the Pool check.
            (_address_lease("198.18.0.150"), Reserved(reservation)),
        )
        for lease, outcome in cases:
            with self.subTest(lease=lease["ip-address"]):
                match = reservation_match(typed_lease(lease), hidden, (hidden,), FakeReservationLookup(reservation))
                self.assertEqual(match, outcome)

    def test_dhcpv6_reads_no_global_reservation_when_a_local_allocation_of_the_lease_kind_counts(self):
        """allocateReservedLeases6 gives the local address outside the Pool and returns before the Global host."""
        settings = {"reservations-out-of-pool": True, **_GLOBAL_RESERVATIONS}
        pool6 = {"pools": [{"pool": "2001:db8::100 - 2001:db8::200"}]}
        catalogue = _catalogue_responses_for_subnets(6, [{**_SUBNETS[6][0], **pool6}], global_settings=settings)
        local = {"subnet-id": 30, "duid": _DUID, "ip-addresses": ["2001:db8::50"]}
        global_ = {"subnet-id": 0, "duid": _DUID, "ip-addresses": ["2001:db8::60"]}

        match, lookup = self._walk(_address6("2001:db8::160"), local, global_, family=6, responses=catalogue)

        self.assertEqual(match, _pending("2001:db8::50")(_typed_reservation(local)))
        self.assertNotIn(0, [subnet_id for subnet_id, _key in lookup.walk()], "no Global lookup")

    def test_kea_tries_the_global_reservation_when_the_in_subnet_one_gives_no_allocation_of_the_lease_kind(self):
        """DHCPv4 hasAddressReservation and DHCPv6 allocateReservedLeases6 go on to the Global Reservation."""
        pool4 = {"pools": [{"pool": "198.18.0.100 - 198.18.0.200"}]}
        shared4 = _catalogue_responses_for_subnets(
            4,
            [{**_SUBNETS[4][0], **pool4, "reservations-out-of-pool": True}, {"id": 21, "subnet": "198.18.1.0/24"}],
            shared_networks=[{"name": "shared"}],
            members={20: "shared", 21: "shared"},
            global_settings=_GLOBAL_RESERVATIONS,
        )
        out_of_pool6 = {"reservations-out-of-pool": True, **_GLOBAL_RESERVATIONS}
        pool6 = {"pools": [{"pool": "2001:db8::100 - 2001:db8::200"}]}
        subnet6 = _catalogue_responses_for_subnets(6, [{**_SUBNETS[6][0], **pool6}], global_settings=out_of_pool6)
        plain6 = _catalogue_responses_for_subnets(6, _SUBNETS[6], global_settings=_GLOBAL_RESERVATIONS)
        alone4 = _catalogue_responses_for_subnets(
            4, [{**_SUBNETS[4][0], **pool4, "reservations-out-of-pool": True}], global_settings=_GLOBAL_RESERVATIONS
        )
        hidden4 = _catalogue_responses_for_subnets(
            4,
            [{**_SUBNETS[4][0], **pool4, "reservations-out-of-pool": True}],
            shared_networks=[{"name": "shared"}],
            members={20: "shared"},
            global_settings=_GLOBAL_RESERVATIONS,
        )
        hidden4["subnet4-list"]["arguments"]["subnets"].append({"id": "x", "subnet": "unparsed"})
        shared6 = _catalogue_responses_for_subnets(
            6,
            [{**_SUBNETS[6][0], **pool6}, {"id": 31, "subnet": "2001:db8:1::/64"}],
            shared_networks=[{"name": "shared"}],
            members={30: "shared", 31: "shared"},
            global_settings=out_of_pool6,
        )
        lease4, held4 = _address_lease("198.18.0.160"), _address_lease("198.18.0.150")
        local4 = {"subnet-id": 0, "hw-address": _MAC, "ip-address": "198.18.0.50"}
        outside4 = {"subnet-id": 0, "hw-address": _MAC, "ip-address": "198.19.0.50"}
        lease6, held6 = _address6("2001:db8::160"), _address6("2001:db8::150")
        global4 = {"subnet-id": 0, "hw-address": _MAC, "ip-address": "198.18.1.50"}
        global6 = {"subnet-id": 0, "duid": _DUID, "ip-addresses": ["2001:db8::50"]}
        in_subnet4 = {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.150"}
        in_subnet6 = {"subnet-id": 30, "duid": _DUID, "ip-addresses": ["2001:db8::150"]}
        out_of_pool = _ignored(IgnoredReservationReason.OUT_OF_POOL)
        cases = (
            # An In-Subnet Reservation of a sibling Subnet comes before the Global one, and the plugin does not read it.
            ("v4 sibling", 4, shared4, lease4, in_subnet4, global4, global4, _unknown_shared_network),
            ("v4 held, sibling", 4, shared4, held4, in_subnet4, global4, global4, _unknown_shared_network),
            ("v4 membership not shown", 4, hidden4, lease4, in_subnet4, local4, global4, _unknown_shared_network),
            ("v6 sibling", 6, shared6, lease6, in_subnet6, global6, global6, _unknown_shared_network),
            # The Global address applies, and currentHost() is the In-Subnet host, so Kea gives the local address.
            ("v4 Global address here", 4, alone4, lease4, in_subnet4, local4, in_subnet4, _pending("198.18.0.150")),
            ("v4 held, Global address here", 4, alone4, held4, in_subnet4, local4, in_subnet4, Reserved),
            # A Global address outside the only eligible Subnet does not apply.
            ("v4 Global address outside", 4, alone4, lease4, in_subnet4, outside4, in_subnet4, out_of_pool),
            ("v4 held, Global address outside", 4, alone4, held4, in_subnet4, outside4, in_subnet4, Reserved),
            (
                "v4 no Global address",
                4,
                shared4,
                lease4,
                in_subnet4,
                {**global4, "ip-address": None},
                in_subnet4,
                out_of_pool,
            ),
            # A dynamic Subnet Reservation stops the walk: it overrides a Global reserved address.
            (
                "v4 Host-Only",
                4,
                shared4,
                lease4,
                {**in_subnet4, "ip-address": None},
                global4,
                None,
                HostOnlyReservation,
            ),
            ("v6 out-of-pool", 6, subnet6, lease6, in_subnet6, global6, global6, _pending("2001:db8::50")),
            # The address IA does not use the prefix, so the prefix does not stop the walk.
            (
                "v6 excluded address and a prefix",
                6,
                subnet6,
                lease6,
                {**in_subnet6, "prefixes": [_PREFIX]},
                global6,
                global6,
                _pending("2001:db8::50"),
            ),
            # DHCPv6 keeps an existing Lease of the In-Subnet Reservation before it looks at the Global one.
            ("v6 held", 6, subnet6, held6, in_subnet6, global6, in_subnet6, Reserved),
            # An In-Subnet Reservation of no allocation stops the walk.
            (
                "v6 Host-Only",
                6,
                subnet6,
                lease6,
                {"subnet-id": 30, "duid": _DUID, "hostname": "h", "ip-addresses": []},
                global6,
                None,
                HostOnlyReservation,
            ),
            # Without out-of-pool, an In-Subnet Reservation of only prefixes gives no address either.
            (
                "v6 only a prefix",
                6,
                plain6,
                lease6,
                {"subnet-id": 30, "duid": _DUID, "prefixes": [_PREFIX]},
                global6,
                global6,
                _pending("2001:db8::50"),
            ),
        )
        for label, family, catalogue, lease, in_subnet, global_, found, outcome in cases:
            hosts = [{key: value for key, value in host.items() if value is not None} for host in (in_subnet, global_)]
            with self.subTest(label):
                match, lookup = self._walk(lease, *hosts, family=family, responses=catalogue)
                if found is None:
                    self.assertEqual(match, outcome(_typed_reservation(hosts[0])))
                    self.assertNotIn(0, [subnet_id for subnet_id, _key in lookup.walk()], "no Global lookup")
                else:
                    self.assertEqual(
                        match,
                        outcome(_typed_reservation({key: value for key, value in found.items() if value is not None})),
                    )

    def test_flags_that_the_configuration_does_not_show_leave_a_found_reservation_unknown(self):
        host = {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.20"}
        invalid = _catalogue_responses_for_subnets(4, _SUBNETS[4], global_settings={"reservations-global": "yes"})
        cases = (
            ("config-get failed", {"config-get": {"result": 1, "text": "down"}}),
            ("a flag is not a bool", invalid),
            (
                "a Subnet flag is not a bool",
                _catalogue_responses_for_subnets(
                    4, [{**_SUBNETS[4][0], "reservations-in-subnet": 1}], global_settings=_GLOBAL_RESERVATIONS
                ),
            ),
        )
        for label, responses in cases:
            with self.subTest(label):
                found = self._match(_address_lease(), host, responses=responses)
                none = self._match(
                    _address_lease("198.18.0.30", hw_address="aa:bb:cc:dd:ee:01"), host, responses=responses
                )
                self.assertEqual(found, _flags_unknown(_typed_reservation(host)))
                # No Reservation in any scope does not depend on a flag.
                self.assertIsInstance(none, Unreserved)

    def test_a_reserved_address_of_another_hardware_address_is_a_stale_mac(self):
        host = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.20"}

        self.assertEqual(self._match(_address_lease(), host), StaleMac(_typed_reservation(host), _MAC))

    def test_a_reserved_address_of_another_identifier_type_is_reserved(self):
        host = {"subnet-id": 20, "client-id": "01:aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.20"}

        self.assertEqual(self._match(_address_lease(), host), Reserved(_typed_reservation(host)))

    def test_an_in_subnet_reservation_of_other_allocations_of_the_kind_is_a_pending_change(self):
        cases = (
            (
                4,
                _address_lease(),
                {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.21"},
                (ipaddress.ip_address("198.18.0.21"),),
            ),
            (
                6,
                _prefix_lease(),
                {"subnet-id": 30, "duid": _DUID, "prefixes": ["2001:db8:100:700::/56", "2001:db8:100:800::/56"]},
                (ipaddress.ip_network("2001:db8:100:700::/56"), ipaddress.ip_network("2001:db8:100:800::/56")),
            ),
        )
        for family, lease, host, reserved in cases:
            with self.subTest(family=family):
                match = self._match(lease, host, family=family)
                self.assertEqual(match, PendingAddressChange(_typed_reservation(host), reserved))

    def test_an_in_subnet_reservation_of_no_address_and_no_prefix_is_host_only(self):
        host = {"subnet-id": 20, "hw-address": _MAC, "hostname": "classified"}

        self.assertEqual(self._match(_address_lease(), host), HostOnlyReservation(_typed_reservation(host)))

    def test_a_reservation_of_only_the_other_kind_is_an_other_kind_reservation(self):
        cases = (
            (_address6("2001:db8::20"), {"subnet-id": 30, "duid": _DUID, "prefixes": [_PREFIX]}),
            (_prefix_lease(), {"subnet-id": 30, "duid": _DUID, "ip-addresses": ["2001:db8::99"]}),
        )
        for lease, host in cases:
            with self.subTest(host=host):
                match = self._match(lease, host, family=6)
                self.assertEqual(match, OtherKindReservation(_typed_reservation(host)))

    def test_no_reservation_in_the_subnet_or_the_global_scope_is_unreserved_in_the_verified_subnet(self):
        match = self._match(_address_lease())

        self.assertIsInstance(match, Unreserved)
        assert isinstance(match, Unreserved)
        self.assertEqual((match.subnet.subnet_id, match.subnet.cidr), (20, "198.18.0.0/24"))

    def test_a_lease_with_an_identifier_no_reservation_can_hold_is_unknown_only_without_a_match(self):
        foreign = _address_lease(hw_address="", client_id=_LONG_CLIENT_ID)
        host = {"subnet-id": 20, "flex-id": "port-7", "ip-address": "198.18.0.20"}
        for hosts, expected in (
            ((), ReservationMatchUnknown(UnknownReservationMatch.FOREIGN_IDENTIFIER)),
            ((host,), Reserved(_typed_reservation(host))),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(self._match(foreign, *hosts), expected)

    def test_the_walk_tries_the_scopes_that_the_flags_enable_first(self):
        in_subnet_lookups = [(20, "198.18.0.20"), (20, "hw-address")]
        cases = (
            ({}, [*in_subnet_lookups, (0, "hw-address")]),
            ({"reservations-in-subnet": False, **_GLOBAL_RESERVATIONS}, [(0, "hw-address"), *in_subnet_lookups]),
            ({"reservations-in-subnet": False}, [*in_subnet_lookups, (0, "hw-address")]),
        )
        for settings, lookups in cases:
            catalogue = _catalogue_responses_for_subnets(4, _SUBNETS[4], global_settings=settings)
            with self.subTest(settings=settings):
                match, lookup = self._walk(_address_lease(), responses=catalogue)
                self.assertIsInstance(match, Unreserved)
                self.assertEqual(lookup.walk(), lookups)

    def test_the_walk_runs_by_allocation_then_by_identity_in_the_subnet_then_globally(self):
        _match, lookup = self._walk(_address_lease(client_id="01:aa:bb:cc:dd:ee:ff"))

        self.assertEqual(
            lookup.walk(),
            [(20, "198.18.0.20"), (20, "hw-address"), (20, "client-id"), (0, "hw-address"), (0, "client-id")],
        )

    def test_the_first_reservation_found_ends_the_walk(self):
        in_subnet = {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.21"}
        cases = (
            ({"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.20"}, [(20, "198.18.0.20")]),
            (in_subnet, [(20, "198.18.0.20"), (20, "hw-address")]),
        )
        for first, lookups in cases:
            with self.subTest(first=first):
                match, lookup = self._walk(_address_lease(), first, in_subnet, {"subnet-id": 0, "hw-address": _MAC})
                self.assertEqual(getattr(match, "reservation", None), _typed_reservation(first))
                self.assertEqual(lookup.walk(), lookups)

    def test_a_dhcpv6_prefix_lease_walks_by_its_prefix_in_the_subnet(self):
        match, lookup = self._walk(_prefix_lease(), family=6)

        self.assertIsInstance(match, Unreserved)
        self.assertEqual(lookup.walk(), [(30, _PREFIX), (30, "duid"), (0, "duid")])


class ReservationMatchContractTest(SimpleTestCase):
    """The Reservation Match refuses facts that do not fit the Lease: its Subnet and its Shared Network."""

    _lease = typed_lease(lease_record("198.18.0.20", subnet_id=20))
    _subnet = VerifiedSubnet(
        identity=SubnetIdentity(subnet_id=20, network=ipaddress.ip_network("198.18.0.0/24")),
        declared_cidr="198.18.0.0/24",
        configuration=None,
        shared_network=None,
        membership_known=True,
        qualifying_suffix=None,
        reservation_flags=None,
    )
    _other = replace(_subnet, identity=SubnetIdentity(subnet_id=21, network=ipaddress.ip_network("198.18.1.0/24")))

    def test_a_subnet_that_is_not_the_subnet_of_the_lease_is_refused(self):
        lookup = FakeReservationLookup()
        with self.assertRaisesRegex(ValueError, "needs the Subnet of the Lease"):
            reservation_match(self._lease, self._other, None, lookup)
        self.assertEqual(lookup.calls, [], "a refused match looks up nothing")

    def test_a_shared_network_that_does_not_hold_the_subnet_of_the_lease_is_refused(self):
        lookup = FakeReservationLookup()
        with self.assertRaisesRegex(ValueError, "must hold the Subnet of the Lease"):
            reservation_match(self._lease, self._subnet, (self._other,), lookup)
        self.assertEqual(lookup.calls, [], "a refused match looks up nothing")
