# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Current Lease Presence of a Reservation: the Lease query it sends and the rule, with in-memory Current Leases."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping

from django.test import SimpleTestCase

from netbox_kea.reservations import (
    CurrentLeaseFacts,
    IdentityLeases,
    InSubnetReservationScope,
    LeaseAbsent,
    LeasePresenceUnknown,
    LeasePresent,
    LeaseQuery,
    Reservation,
    ReservationIdentity,
    SubnetLeases,
    UnknownLeasePresence,
    current_lease_presence,
)
from netbox_kea.subnet_catalogue import SubnetIdentity

from .kea_stub import _typed_reservation

_RESERVED = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
_MAC = ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff")


class FakeCurrentLeases:
    """A ``CurrentLeases`` that returns the facts that a test gives for each query, and records each one."""

    def __init__(self, facts: Mapping[LeaseQuery, CurrentLeaseFacts]) -> None:
        self._facts = dict(facts)
        self.calls: list[LeaseQuery] = []

    def current_leases(self, query: LeaseQuery) -> CurrentLeaseFacts:
        self.calls.append(query)
        return self._facts[query]


class _ReadFailed(Exception):
    """The failure of a fake read."""


class FailingCurrentLeases:
    """A ``CurrentLeases`` whose every read fails."""

    def current_leases(self, query: LeaseQuery) -> CurrentLeaseFacts:
        raise _ReadFailed(query)


def _facts(
    addresses: Iterable[str] = (),
    identities: Iterable[ReservationIdentity] = (),
    gap: UnknownLeasePresence | None = None,
) -> CurrentLeaseFacts:
    return CurrentLeaseFacts(frozenset(map(ipaddress.ip_address, addresses)), frozenset(identities), gap)


def _subnet_leases(reservation: Reservation) -> SubnetLeases:
    """Return the Leases of the Subnet of an In-Subnet *reservation*, in the state that its family queries."""
    assert isinstance(reservation.scope, InSubnetReservationScope)
    return SubnetLeases(reservation.scope.subnet, "assigned" if reservation.family == 4 else None)


def _presence(raw: dict, facts: CurrentLeaseFacts) -> LeasePresenceUnknown | LeasePresent | LeaseAbsent:
    """Return the presence of the Reservation *raw* when its Lease query finds *facts*."""
    reservation = _typed_reservation(raw)
    if isinstance(reservation.scope, InSubnetReservationScope):
        query: LeaseQuery = _subnet_leases(reservation)
    else:
        query = IdentityLeases(reservation.identity)
    return current_lease_presence(reservation, FakeCurrentLeases({query: facts}))


class CurrentLeasePresenceTest(SimpleTestCase):
    """One Current Lease Presence per Reservation, from the Current Leases that its Lease query finds."""

    def test_each_reservation_queries_the_leases_that_can_show_its_client(self):
        """DHCPv4 queries assigned Leases only; a registered DHCPv6 Lease is current, so DHCPv6 queries each state."""
        subnet4 = SubnetIdentity(20, ipaddress.ip_network("198.18.0.0/24"))
        subnet6 = SubnetIdentity(30, ipaddress.ip_network("2001:db8::/64"))
        duid = ReservationIdentity("duid", "00:01:02:03")
        client_id = ReservationIdentity("client-id", "01:aa:bb:cc:dd:ee:ff")
        cases = (
            (_RESERVED, SubnetLeases(subnet4, "assigned")),
            ({"subnet-id": 30, "duid": duid.value, "ip-addresses": ["2001:db8::20"]}, SubnetLeases(subnet6, None)),
            ({"subnet-id": 0, "hw-address": _MAC.value}, IdentityLeases(_MAC)),
            ({"subnet-id": 0, "client-id": client_id.value}, IdentityLeases(client_id)),
            ({"subnet-id": 0, "duid": duid.value, "ip-addresses": ["2001:db8::20"]}, IdentityLeases(duid)),
        )
        for raw, query in cases:
            with self.subTest(reservation=raw):
                leases = FakeCurrentLeases({query: _facts()})
                self.assertEqual(current_lease_presence(_typed_reservation(raw), leases), LeaseAbsent())
                self.assertEqual(leases.calls, [query])

    def test_a_current_lease_of_the_reserved_identity_is_present_without_an_address(self):
        reservation = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff"}

        presence = _presence(reservation, _facts(["198.18.0.77"], [_MAC]))

        self.assertEqual(presence, LeasePresent(None))

    def test_a_multi_address_reservation_reports_the_address_that_holds_the_lease(self):
        reservation = {"subnet-id": 30, "duid": "00:01:02:03", "ip-addresses": ["2001:db8::20", "2001:db8::21"]}
        holder = ReservationIdentity("duid", "00:01:02:04")

        presence = _presence(reservation, _facts(["2001:db8::21"], [holder]))

        self.assertEqual(presence, LeasePresent(ipaddress.ip_address("2001:db8::21")))

    def test_a_complete_empty_subnet_is_absent_also_for_an_identity_that_no_lease_carries(self):
        for identifier_type in ("hw-address", "flex-id", "circuit-id"):
            with self.subTest(identifier_type=identifier_type):
                reservation = {"subnet-id": 20, identifier_type: "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
                self.assertEqual(_presence(reservation, _facts()), LeaseAbsent())

    def test_an_identity_that_no_lease_carries_still_matches_by_address(self):
        reservation = {"subnet-id": 20, "flex-id": "port-7", "ip-address": "198.18.0.20"}
        other = ReservationIdentity("hw-address", "aa:bb:cc:00:00:01")

        presence = _presence(reservation, _facts(["198.18.0.20"], [other]))

        self.assertEqual(presence, LeasePresent(ipaddress.ip_address("198.18.0.20")))

    def test_the_same_identity_in_another_subnet_is_absent(self):
        reservation = _typed_reservation(_RESERVED)
        other_subnet = _typed_reservation({**_RESERVED, "subnet-id": 21, "ip-address": "198.18.1.20"})
        leases = FakeCurrentLeases(
            {_subnet_leases(other_subnet): _facts(["198.18.1.20"], [_MAC]), _subnet_leases(reservation): _facts()}
        )

        presence = current_lease_presence(reservation, leases)

        self.assertEqual(presence, LeaseAbsent())
        self.assertEqual(leases.calls, [_subnet_leases(reservation)])

    def test_a_global_reservation_matches_by_its_identity_and_never_by_its_address(self):
        reservation = {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        cases = ((_facts(["198.18.1.20"], [_MAC]), LeasePresent(None)), (_facts(["198.18.0.20"]), LeaseAbsent()))
        for facts, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(_presence(reservation, facts), expected)

    def test_facts_that_cannot_confirm_a_missing_lease_leave_only_an_unmatched_reservation_unknown(self):
        for gap in (UnknownLeasePresence.INCOMPLETE_SNAPSHOT, UnknownLeasePresence.FOREIGN_IDENTIFIER):
            with self.subTest(gap=gap):
                self.assertEqual(_presence(_RESERVED, _facts(gap=gap)), LeasePresenceUnknown(gap))
                matched = _presence(_RESERVED, _facts(["198.18.0.20"], gap=gap))
                self.assertEqual(matched, LeasePresent(ipaddress.ip_address("198.18.0.20")))

    def test_an_identity_that_kea_cannot_search_is_unknown(self):
        cases = (
            (4, {"subnet-id": 0, "flex-id": "port-7"}),
            (6, {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-addresses": ["2001:db8::20"]}),
            (4, {"subnet-id": 20, "duid": "00:01:02:03"}),
            (4, {"subnet-id": 20, "circuit-id": "port-7"}),
            (4, {"subnet-id": 20, "flex-id": "port-7"}),
            # A delegated prefix makes the fixture a DHCPv6 Reservation without an address.
            (6, {"subnet-id": 30, "flex-id": "port-7", "prefixes": ["2001:db8:100::/56"]}),
        )
        for family, raw in cases:
            with self.subTest(family=family, reservation=raw):
                reservation = _typed_reservation(raw)
                self.assertEqual(reservation.family, family)
                in_subnet = isinstance(reservation.scope, InSubnetReservationScope)
                leases = FakeCurrentLeases({_subnet_leases(reservation): _facts()} if in_subnet else {})
                presence = current_lease_presence(reservation, leases)
                self.assertEqual(presence, LeasePresenceUnknown(UnknownLeasePresence.UNSEARCHABLE_IDENTIFIER))
                if not in_subnet:
                    self.assertEqual(leases.calls, [], "a Global identity that Kea cannot search reads nothing")

    def test_a_failed_read_raises_through_the_rule(self):
        with self.assertRaises(_ReadFailed):
            current_lease_presence(_typed_reservation(_RESERVED), FailingCurrentLeases())
