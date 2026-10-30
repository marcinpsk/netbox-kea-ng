# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Current Lease Presence of Reservations and the Reservation Match of Leases.

They are read through the real KeaClient and the display cache.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch

import requests
from django.utils import timezone

from netbox_kea import kea as kea_module
from netbox_kea import subnet_catalogue
from netbox_kea.constants import Family
from netbox_kea.kea import KeaClient, KeaCommand
from netbox_kea.lease_reservation_reads import lease_presence, reservation_matches
from netbox_kea.models import Server
from netbox_kea.reservations import (
    CurrentLeasePresence,
    HostOnlyReservation,
    IgnoredReservation,
    IgnoredReservationReason,
    LeaseAbsent,
    LeasePresenceUnknown,
    LeasePresent,
    OtherKindReservation,
    PendingAddressChange,
    Reservation,
    ReservationMatch,
    ReservationMatchUnknown,
    Reserved,
    StaleMac,
    UnknownLeasePresence,
    UnknownReservationMatch,
    Unreserved,
    reservation_match,
)

from .kea_stub import (
    _catalogue_responses_for_subnets,
    _leases_per_subnet,
    _res_get,
    _subnet_stats,
    _typed_reservation,
    client_failure,
    complete_lease,
    lease_record,
    lease_reply,
    stub_kea,
    typed_lease,
)
from .utils import _ViewTestBase, save_key_without_certificate, with_display_cache_config, with_kea_client_config

_RESERVED = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
_LONG_CLIENT_ID = ":".join(["01"] * 129)


def _lease4(address: str, *, subnet_id: int = 20, hw_address: str = "aa:bb:cc:00:00:01", **changes: Any) -> dict:
    return lease_record(address, subnet_id=subnet_id, hw_address=hw_address, **changes)


def _unknown(reason: UnknownLeasePresence) -> LeasePresenceUnknown:
    return LeasePresenceUnknown(reason)


class LeasePresenceTest(_ViewTestBase):
    """One Current Lease Presence per Reservation, from the Lease lookups that Kea answers."""

    def _presence(
        self, reservations: list[dict], responses: dict, *, family: Family = 4, read_since: datetime | None = None
    ) -> tuple[tuple[CurrentLeasePresence, ...], Any]:
        typed = [_typed_reservation(raw) for raw in reservations]
        with stub_kea(responses) as kea:
            presences = lease_presence(self.server, family, typed, read_since=read_since or timezone.now())
        return presences, kea

    def test_a_current_lease_at_a_reserved_address_is_present_with_that_address(self):
        presences, kea = self._presence(
            [_RESERVED], {"lease4-get-by-state": _leases_per_subnet({20: [_lease4("198.18.0.20")]})}
        )

        self.assertEqual(presences, (LeasePresent(ipaddress.ip_address("198.18.0.20")),))
        self.assertEqual(kea.bodies("lease4-get-by-state")[0]["arguments"], {"subnet-id": 20, "state": 0})

    def test_a_current_lease_of_the_reserved_identity_is_present_without_an_address(self):
        reservation = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff"}
        lease = _lease4("198.18.0.77", hw_address="AA-BB-CC-DD-EE-FF")

        presences, _kea = self._presence([reservation], {"lease4-get-by-state": _leases_per_subnet({20: [lease]})})

        self.assertEqual(presences, (LeasePresent(None),))

    def test_a_multi_address_reservation_reports_the_address_that_holds_the_lease(self):
        reservation = {"subnet-id": 30, "duid": "00:01:02:03", "ip-addresses": ["2001:db8::20", "2001:db8::21"]}
        lease = complete_lease({"subnet-id": 30, "duid": "00:01:02:04", "ip-address": "2001:db8::21", "state": 0})

        presences, _kea = self._presence([reservation], {"lease6-get-all": _leases_per_subnet({30: [lease]})}, family=6)

        self.assertEqual(presences, (LeasePresent(ipaddress.ip_address("2001:db8::21")),))

    def test_a_registered_dhcpv6_lease_is_present(self):
        reservation = {"subnet-id": 10, "duid": "00:01:02:03:04:05", "ip-addresses": ["2001:db8:1::11"]}
        registered = lease_record("2001:db8:1::11", state=4)

        # Kea's assigned-state query does not return a registered lease; only the whole Subnet does.
        presences, kea = self._presence(
            [reservation], {"lease6-get-all": _leases_per_subnet({10: [registered]})}, family=6
        )

        self.assertEqual(presences, (LeasePresent(ipaddress.ip_address("2001:db8:1::11")),))
        self.assertEqual(kea.bodies("lease6-get-all")[0]["arguments"], {"subnets": [10]})

    def test_only_a_current_lease_is_present(self):
        cases = (
            (_lease4("198.18.0.20", cltt=int(time.time()) - 7200, valid_lft=3600), LeaseAbsent()),
            (_lease4("198.18.0.20", valid_lft=0xFFFFFFFF, cltt=1), LeasePresent(ipaddress.ip_address("198.18.0.20"))),
        )
        for lease, expected in cases:
            with self.subTest(expected=expected), with_display_cache_config(leases_ttl=0):
                presences, _kea = self._presence(
                    [_RESERVED], {"lease4-get-by-state": _leases_per_subnet({20: [lease]})}
                )
                self.assertEqual(presences, (expected,))

    def test_a_complete_empty_subnet_is_absent_also_for_an_identity_that_no_lease_carries(self):
        for identifier_type in ("hw-address", "flex-id", "circuit-id"):
            with self.subTest(identifier_type=identifier_type):
                reservation = {"subnet-id": 20, identifier_type: "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
                presences, _kea = self._presence([reservation], {"lease4-get-by-state": _leases_per_subnet({20: []})})
                self.assertEqual(presences, (LeaseAbsent(),))

    def test_an_identity_that_no_lease_carries_still_matches_by_address(self):
        reservation = {"subnet-id": 20, "flex-id": "port-7", "ip-address": "198.18.0.20"}

        presences, _kea = self._presence(
            [reservation], {"lease4-get-by-state": _leases_per_subnet({20: [_lease4("198.18.0.20")]})}
        )

        self.assertEqual(presences, (LeasePresent(ipaddress.ip_address("198.18.0.20")),))

    def test_the_same_identity_in_another_subnet_is_absent(self):
        lease = _lease4("198.18.1.20", subnet_id=21, hw_address="aa:bb:cc:dd:ee:ff")

        presences, _kea = self._presence([_RESERVED], {"lease4-get-by-state": _leases_per_subnet({21: [lease]})})

        self.assertEqual(presences, (LeaseAbsent(),))

    @with_display_cache_config(leases_ttl=0)
    def test_a_template_style_key_in_a_kea_record_is_not_an_identity(self):
        reservation = {"subnet-id": 20, "hw-address": "11:22:33:44:55:66"}
        for native, expected in (("aa:bb:cc:dd:ee:ff", LeaseAbsent()), ("11-22-33-44-55-66", LeasePresent(None))):
            with self.subTest(native=native):
                lease = {**_lease4("198.18.0.20", hw_address=native), "hw_address": "11:22:33:44:55:66"}
                presences, _kea = self._presence(
                    [reservation], {"lease4-get-by-state": _leases_per_subnet({20: [lease]})}
                )
                self.assertEqual(presences, (expected,))

    def test_a_global_reservation_matches_by_its_normalized_identity_and_never_by_its_address(self):
        reservation = {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        for leases, expected in (
            ([_lease4("198.18.1.20", subnet_id=21, hw_address="AA-BB-CC-DD-EE-FF")], LeasePresent(None)),
            ([], LeaseAbsent()),
        ):
            with self.subTest(expected=expected), with_display_cache_config(leases_ttl=0):
                presences, kea = self._presence([reservation], {"lease4-get-by-hw-address": lease_reply(*leases)})
                self.assertEqual(presences, (expected,))
                self.assertEqual(
                    [name for name in kea.commands() if name.startswith("lease4-")], ["lease4-get-by-hw-address"]
                )
                self.assertEqual(
                    kea.bodies("lease4-get-by-hw-address")[0]["arguments"], {"hw-address": "aa:bb:cc:dd:ee:ff"}
                )

    def test_reservations_of_one_subnet_share_one_lookup(self):
        reservations = [_RESERVED, {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:02", "ip-address": "198.18.0.21"}]

        presences, kea = self._presence(
            reservations, {"lease4-get-by-state": _leases_per_subnet({20: [_lease4("198.18.0.21")]})}
        )

        self.assertEqual(presences, (LeaseAbsent(), LeasePresent(ipaddress.ip_address("198.18.0.21"))))
        self.assertEqual(kea.commands().count("lease4-get-by-state"), 1)

    def test_a_snapshot_that_excluded_a_record_is_unknown(self):
        for label, broken in (
            ("hostname", _lease4("198.18.0.30", hostname=["private"])),
            ("identity", _lease4("198.18.0.30", hw_address="not-a-mac")),
            ("state", _lease4("198.18.0.30", state=99)),
            ("missing state", _lease4("198.18.0.30", drop=("state",))),
        ):
            with self.subTest(label=label), with_display_cache_config(leases_ttl=0):
                presences, _kea = self._presence(
                    [_RESERVED], {"lease4-get-by-state": _leases_per_subnet({20: [broken]})}
                )
                self.assertEqual(presences, (_unknown(UnknownLeasePresence.INCOMPLETE_SNAPSHOT),))

    def test_a_global_identity_lookup_that_cannot_confirm_a_missing_lease_is_unknown(self):
        reservation = {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ff"}
        for broken, reason in (
            (_lease4("198.18.1.30", subnet_id=21, state=99), UnknownLeasePresence.INCOMPLETE_SNAPSHOT),
            (
                _lease4("198.18.1.30", subnet_id=21, hw_address="", client_id=_LONG_CLIENT_ID),
                UnknownLeasePresence.FOREIGN_IDENTIFIER,
            ),
        ):
            with self.subTest(reason=reason), with_display_cache_config(leases_ttl=0):
                presences, _kea = self._presence([reservation], {"lease4-get-by-hw-address": lease_reply(broken)})
                self.assertEqual(presences, (_unknown(reason),))

    def test_a_current_lease_with_an_identifier_no_reservation_can_hold_is_unknown(self):
        lease = _lease4("198.18.0.60", hw_address="", client_id=_LONG_CLIENT_ID)

        presences, _kea = self._presence([_RESERVED], {"lease4-get-by-state": _leases_per_subnet({20: [lease]})})

        self.assertEqual(presences, (_unknown(UnknownLeasePresence.FOREIGN_IDENTIFIER),))

    @with_kea_client_config(lease_query_max_unpaged_leases=2)
    def test_a_subnet_lookup_that_the_query_guard_refuses_is_unknown(self):
        inactive = [
            lease_record("2001:db8:1::31", state=1, duid="00:00:00", drop=("hw-address",)),
            lease_record("2001:db8:1::32", state=3),
            lease_record("2001:db8:1::33", state=2),
        ]
        reservation = {"subnet-id": 10, "duid": "00:01:02:03:04:05", "ip-addresses": ["2001:db8:1::20"]}

        # Kea counts only assigned addresses and prefixes, so the measured Subnet looks small.
        presences, _kea = self._presence(
            [reservation],
            {
                "stat-lease6-get": _subnet_stats(6, 10, assigned=1),
                "lease6-get-all": _leases_per_subnet({10: inactive}),
            },
            family=6,
        )

        self.assertEqual(presences, (_unknown(UnknownLeasePresence.QUERY_GUARD),))

    def test_a_kea_or_transport_failure_is_unknown(self):
        for reply in ({"result": 1, "text": "lease database error"}, requests.ConnectionError("kea unreachable")):
            with self.subTest(reply=reply):
                presences, _kea = self._presence([_RESERVED], {"lease4-get-by-state": reply})
                self.assertEqual(presences, (_unknown(UnknownLeasePresence.KEA_ERROR),))

    def test_a_malformed_reply_is_unknown(self):
        presences, _kea = self._presence(
            [_RESERVED], {"lease4-get-by-state": {"result": 0, "arguments": {"leases": "not-a-list"}}}
        )

        self.assertEqual(presences, (_unknown(UnknownLeasePresence.MALFORMED_REPLY),))

    def test_a_read_across_a_backward_clock_step_is_not_a_failure(self):
        """The Snapshot of a read whose wall clock stepped back finishes when it starts."""
        stepped_back = threading.local()
        real_now = kea_module._now

        def now():
            if getattr(stepped_back, "pending", False):
                stepped_back.pending = False
                return real_now() - timedelta(hours=1)
            return real_now()

        def leases(body):
            stepped_back.pending = True
            return {"result": 3}

        with patch("netbox_kea.kea._now", autospec=True, side_effect=now):
            presences, _kea = self._presence(
                [{"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:01"}, _RESERVED],
                {"lease4-get-by-hw-address": lease_reply(), "lease4-get-by-state": leases},
            )

        self.assertEqual(presences, (LeaseAbsent(), LeaseAbsent()))

    def test_a_failed_lookup_leaves_only_its_own_reservations_unknown(self):
        def leases(body):
            if body["arguments"]["subnet-id"] == 20:
                return {"result": 1, "text": "lease database error"}
            return {"result": 3}

        presences, _kea = self._presence(
            [_RESERVED, {"subnet-id": 21, "hw-address": "aa:bb:cc:dd:ee:02", "ip-address": "198.18.1.20"}],
            {"lease4-get-by-state": leases},
        )

        self.assertEqual(presences, (_unknown(UnknownLeasePresence.KEA_ERROR), LeaseAbsent()))

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
        for family, reservation in cases:
            with self.subTest(family=family, reservation=reservation):
                presences, kea = self._presence(
                    [reservation],
                    {"lease4-get-by-state": _leases_per_subnet({}), "lease6-get-all": _leases_per_subnet({})},
                    family=family,
                )
                self.assertEqual(presences, (_unknown(UnknownLeasePresence.UNSEARCHABLE_IDENTIFIER),))
                if reservation["subnet-id"] == 0:
                    self.assertEqual(kea.commands(), [], "a Global identity that Kea cannot search reads nothing")

    def test_an_unknown_lease_command_makes_every_reservation_unknown(self):
        """A missing lease hook hides every relationship; any other Kea error hides only its own."""
        reservations = [{"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:01"}, _RESERVED]
        hook = _unknown(UnknownLeasePresence.LEASE_HOOK_UNAVAILABLE)
        for reply, expected in (
            ({"result": 2, "text": "unknown command"}, (hook, hook)),
            ({"result": 1, "text": "lease database error"}, (_unknown(UnknownLeasePresence.KEA_ERROR), LeaseAbsent())),
        ):
            with self.subTest(result=reply["result"]):
                presences, _kea = self._presence(
                    reservations,
                    {"lease4-get-by-hw-address": reply, "lease4-get-by-state": _leases_per_subnet({20: []})},
                )
                self.assertEqual(presences, expected)

    def test_an_unexpected_failure_raises(self):
        with (
            client_failure(KeaCommand.LEASE4_GET_BY_STATE, TypeError("unexpected worker failure")),
            self.assertRaises(TypeError),
        ):
            self._presence([_RESERVED], {})

    def test_a_reservation_of_another_family_is_refused(self):
        with self.assertRaises(ValueError):
            self._presence([_RESERVED], {}, family=6)

    def test_no_reservation_reads_nothing(self):
        presences, kea = self._presence([], {})

        self.assertEqual((presences, kea.commands()), ((), []))


class LeasePresenceLookupTest(_ViewTestBase):
    """Each Lease lookup is a display cache entry, read in a pool of one Kea client per worker thread."""

    def _presence(self, reservations: list[dict], responses: dict, *, read_since: datetime):
        typed = [_typed_reservation(raw) for raw in reservations]
        real_get_client = Server.get_client
        with (
            stub_kea(responses) as kea,
            patch.object(Server, "get_client", autospec=True, side_effect=real_get_client) as get_client,
        ):
            presences = lease_presence(self.server, 4, typed, read_since=read_since)
        return presences, kea.commands(), get_client.call_count

    def test_a_cache_hit_builds_no_kea_client(self):
        before = timezone.now()
        responses = {"lease4-get-by-state": _leases_per_subnet({20: [_lease4("198.18.0.20")]})}
        _first, commands, clients = self._presence([_RESERVED], responses, read_since=before)
        self.assertEqual((commands, clients), (["lease4-get-by-state"], 1))

        presences, commands, clients = self._presence([_RESERVED], {}, read_since=before)

        self.assertEqual((commands, clients), ([], 0))
        self.assertEqual(presences, (LeasePresent(ipaddress.ip_address("198.18.0.20")),))

    def test_a_lookup_read_before_the_table_is_read_again(self):
        self._presence(
            [_RESERVED],
            {"lease4-get-by-state": _leases_per_subnet({20: [_lease4("198.18.0.20")]})},
            read_since=timezone.now(),
        )

        # A Refresh reads the Reservation table live, so its read time is after the cached lookup.
        presences, commands, _clients = self._presence(
            [_RESERVED],
            {"lease4-get-by-state": _leases_per_subnet({20: []})},
            read_since=timezone.now() + timedelta(seconds=1),
        )

        self.assertEqual(commands, ["lease4-get-by-state"])
        self.assertEqual(presences, (LeaseAbsent(),))

    def test_each_worker_thread_builds_one_client_and_the_pool_closes_each(self) -> None:
        # Twice as many lookups as workers, so each worker reads two of them.
        subnet_ids = range(20, 40)
        reservations = [
            {
                "subnet-id": subnet_id,
                "hw-address": f"aa:bb:cc:dd:ee:{subnet_id:02x}",
                "ip-address": f"198.18.{subnet_id}.5",
            }
            for subnet_id in subnet_ids
        ]
        owners: dict[int, int] = {}
        built: list[KeaClient] = []
        closed: list[KeaClient] = []
        sent: list[tuple[int, int]] = []
        # Each lookup waits until ten lookups run at once, so the pool runs all ten workers.
        all_workers = threading.Barrier(10, timeout=10)
        respond = _leases_per_subnet({})

        def leases(body):
            all_workers.wait()
            return respond(body)

        real_get_client, real_command, real_close = Server.get_client, KeaClient.command, KeaClient.close

        def get_client(server, **kwargs):
            client = real_get_client(server, **kwargs)
            owners[id(client)] = threading.get_ident()
            built.append(client)
            return client

        def command(client, *args, **kwargs):
            sent.append((id(client), threading.get_ident()))
            return real_command(client, *args, **kwargs)

        def close(client):
            real_close(client)
            closed.append(client)

        with (
            stub_kea({"lease4-get-by-state": leases}),
            patch.object(Server, "get_client", autospec=True, side_effect=get_client),
            patch.object(KeaClient, "command", autospec=True, side_effect=command),
            patch.object(KeaClient, "close", autospec=True, side_effect=close),
        ):
            presences = lease_presence(
                self.server, 4, [_typed_reservation(raw) for raw in reservations], read_since=timezone.now()
            )

        self.assertEqual(presences, (LeaseAbsent(),) * len(subnet_ids))
        self.assertEqual(len(built), 10, "one client for each of the ten worker threads")
        self.assertEqual(len(set(owners.values())), 10)
        self.assertEqual(len(sent), len(subnet_ids))
        self.assertTrue(all(owners[client] == thread for client, thread in sent), "a thread used another's client")
        self.assertCountEqual([id(client) for client in closed], [id(client) for client in built])

    def test_a_failed_lookup_cancels_the_lookups_that_wait_for_a_worker(self) -> None:
        subnet_ids = range(20, 40)
        reservations = [
            {
                "subnet-id": subnet_id,
                "hw-address": f"aa:bb:cc:dd:ee:{subnet_id:02x}",
                "ip-address": f"198.18.{subnet_id}.5",
            }
            for subnet_id in subnet_ids
        ]
        asked: list[int] = []
        all_workers = threading.Barrier(10, timeout=10)
        release = threading.Event()

        class ReleaseAfterCancel(concurrent.futures.ThreadPoolExecutor):
            def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
                # The other workers finish only after the pool has cancelled the lookups that wait for a worker.
                super().shutdown(wait=False, cancel_futures=cancel_futures)
                release.set()
                super().shutdown(wait=wait)

        real_command = KeaClient.command

        # A real POST cannot raise a TypeError, so the unexpected failure comes from the client.
        def command(client, *args, **kwargs):
            subnet_id = kwargs["arguments"]["subnet-id"]
            asked.append(subnet_id)
            if subnet_id < 30:
                all_workers.wait()
            if subnet_id == 20:
                raise TypeError("unexpected worker failure")
            release.wait(timeout=10)
            return real_command(client, *args, **kwargs)

        with (
            stub_kea({"lease4-get-by-state": {"result": 3}}),
            patch.object(KeaClient, "command", autospec=True, side_effect=command),
            patch.object(concurrent.futures, "ThreadPoolExecutor", ReleaseAfterCancel),
            self.assertRaises(TypeError),
        ):
            lease_presence(self.server, 4, [_typed_reservation(raw) for raw in reservations], read_since=timezone.now())

        # The worker of the failed lookup can take one more lookup before the pool cancels the rest.
        self.assertLessEqual(set(asked), set(range(20, 31)), "a lookup that waited for a worker ran after the failure")
        self.assertGreaterEqual(set(asked), set(range(20, 30)))


# The Reservation Match of Lease rows.

_SUBNETS = {4: [{"id": 20, "subnet": "198.18.0.0/24"}], 6: [{"id": 30, "subnet": "2001:db8::/64"}]}
_MAC = "aa:bb:cc:dd:ee:ff"
_DUID = "00:01:02:03:04:05"
_PREFIX = "2001:db8:100::/56"
_NOT_FOUND = {"result": 3, "text": "Host not found."}
#: The global flag that lets each Subnet apply Global Reservations; Kea's default is false.
_GLOBAL_RESERVATIONS = {"reservations-global": True}


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


def _kea_hosts(*hosts: dict):
    """Answer each reservation-get as Kea does: by Subnet and address (a prefix by its base), or by identifier."""

    def answer(body):
        arguments = body["arguments"]
        for host in hosts:
            if host["subnet-id"] != arguments["subnet-id"]:
                continue
            if "ip-address" in arguments:
                held = [host.get("ip-address"), *host.get("ip-addresses", [])]
                held += [prefix.split("/")[0] for prefix in host.get("prefixes", [])]
                if arguments["ip-address"] in held:
                    return _res_get(host)
            elif host.get(arguments["identifier-type"]) == arguments["identifier"]:
                return _res_get(host)
        return _NOT_FOUND

    return answer


def _lookups(kea) -> list[tuple]:
    """Return each reservation-get that Kea answered, as (Subnet ID, address or identifier type), in order."""
    return [
        (body["arguments"]["subnet-id"], body["arguments"].get("ip-address") or body["arguments"]["identifier-type"])
        for body in kea.bodies("reservation-get")
    ]


def _match_unknown(reason: UnknownReservationMatch) -> ReservationMatchUnknown:
    return ReservationMatchUnknown(reason)


# Each case reads its own Catalogue, with the reservation flags that it sets.
@with_display_cache_config(configuration_ttl=0)
class ReservationMatchTest(_ViewTestBase):
    """One Reservation Match per Lease, from the Reservation lookups that Kea answers."""

    def _matches(
        self,
        leases: list[dict],
        reservation_get: Any,
        *,
        family: Family = 4,
        read_since: datetime | None = None,
        responses: dict | None = None,
    ) -> tuple[tuple[ReservationMatch, ...], Any]:
        replies = {
            **_catalogue_responses_for_subnets(family, _SUBNETS[family], global_settings=_GLOBAL_RESERVATIONS),
            "reservation-get": reservation_get,
            **(responses or {}),
        }
        with stub_kea(replies) as kea:
            matches = reservation_matches(
                self.server, family, [typed_lease(lease) for lease in leases], read_since=read_since or timezone.now()
            )
        return matches, kea

    def _match(self, lease: dict, *hosts: dict, family: Family = 4) -> ReservationMatch:
        with with_display_cache_config(leases_ttl=0):
            (match,), _kea = self._matches([lease], _kea_hosts(*hosts), family=family)
        return match

    def test_a_reservation_of_the_lease_allocation_is_reserved(self):
        cases = (
            (4, _address_lease(), {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.20"}),
            (6, _prefix_lease(), {"subnet-id": 30, "duid": _DUID, "prefixes": [_PREFIX]}),
            (4, _address_lease(), {"subnet-id": 0, "hw-address": _MAC, "ip-address": "198.18.0.20"}),
        )
        for family, lease, host in cases:
            with self.subTest(host=host):
                self.assertEqual(self._match(lease, host, family=family), Reserved(_typed_reservation(host)))

    def test_only_the_allocations_of_a_global_reservation_in_the_lease_subnet_count(self):
        address6 = lease_record("2001:db8::20", subnet_id=30, duid=_DUID, drop=("hw-address",))
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
        address6 = lease_record("2001:db8::20", subnet_id=30, duid=_DUID, drop=("hw-address",))
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
            with self.subTest(host=host, sibling=sibling_settings), with_display_cache_config(leases_ttl=0):
                (match,), _kea = self._matches([lease], _kea_hosts(host), family=family, responses=catalogue)
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
        with stub_kea(catalogue):
            own, sibling = subnet_catalogue.display(self.server, 4).subnets
        host = {"subnet-id": 0, "hw-address": _MAC, "ip-address": "198.18.1.21"}
        reservation, lease = _typed_reservation(host), typed_lease(_address_lease())
        for label, hidden in (
            ("flags", replace(sibling, reservation_flags=None)),
            ("classes", replace(sibling, configuration=None)),
        ):
            with self.subTest(label):
                match = reservation_match(lease, own, reservation, (own, hidden), global_reservation=None)
                self.assertEqual(match, _unknown_shared_network(reservation))
        # The control: the facts as Kea shows them let the address count.
        self.assertEqual(
            reservation_match(lease, own, reservation, (own, sibling), global_reservation=None),
            _pending("198.18.1.21")(reservation),
        )

    def test_without_the_shared_network_an_address_outside_the_subnet_is_unknown_only_when_it_can_change_the_match(
        self,
    ):
        """A Subnet list entry that does not parse hides which Subnets the Shared Network of the Lease holds."""
        address6 = lease_record("2001:db8::20", subnet_id=30, duid=_DUID, drop=("hw-address",))
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
            with self.subTest(host=host), with_display_cache_config(leases_ttl=0):
                (match,), _kea = self._matches([lease], _kea_hosts(host), family=family, responses=catalogue)
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
            with self.subTest(settings=settings, hosts=hosts), with_display_cache_config(leases_ttl=0):
                (match,), _kea = self._matches([_address_lease()], _kea_hosts(*hosts), responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(found)))

    def test_the_lookups_try_the_scopes_that_the_flags_enable_first(self):
        lease = _address_lease()
        in_subnet_lookups = [(20, "198.18.0.20"), (20, "hw-address")]
        cases = (
            ({}, [*in_subnet_lookups, (0, "hw-address")]),
            ({"reservations-in-subnet": False, **_GLOBAL_RESERVATIONS}, [(0, "hw-address"), *in_subnet_lookups]),
            ({"reservations-in-subnet": False}, [*in_subnet_lookups, (0, "hw-address")]),
        )
        for settings, lookups in cases:
            catalogue = _catalogue_responses_for_subnets(4, _SUBNETS[4], global_settings=settings)
            with self.subTest(settings=settings), with_display_cache_config(leases_ttl=0):
                (match,), kea = self._matches([lease], _NOT_FOUND, responses=catalogue)
                self.assertIsInstance(match, Unreserved)
                self.assertEqual(_lookups(kea), lookups)

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
            with self.subTest(settings=settings, host=reserved), with_display_cache_config(leases_ttl=0):
                (match,), _kea = self._matches([lease], _kea_hosts(reserved), responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(reserved)))

    def test_with_out_of_pool_a_reserved_prefix_is_unknown_only_for_a_prefix_lease_that_it_can_change(self):
        """Kea also checks a prefix against the PD Pools, which the configuration facts do not hold.

        An address Lease does not depend on them: Kea allocates each IA by itself (AllocEngine allocateReservedLeases6).
        """
        address6 = lease_record("2001:db8::20", subnet_id=30, duid=_DUID, drop=("hw-address",))
        held6 = lease_record("2001:db8::150", subnet_id=30, duid=_DUID, drop=("hw-address",))
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
            with self.subTest(lease=lease["ip-address"], host=host), with_display_cache_config(leases_ttl=0):
                (match,), _kea = self._matches([lease], _kea_hosts(host), family=6, responses=catalogue)
                self.assertEqual(match, outcome(_typed_reservation(host)))

    def test_pools_that_the_configuration_does_not_show_leave_an_in_subnet_address_unknown_when_they_change_it(self):
        [subnet] = _SUBNETS[4]
        catalogue = _catalogue_responses_for_subnets(4, [subnet], global_settings={"reservations-out-of-pool": True})
        with stub_kea(catalogue):
            [own] = subnet_catalogue.display(self.server, 4).subnets
        hidden = replace(own, configuration=None)
        reservation = _typed_reservation({"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.150"})
        cases = (
            (_address_lease(), _pools_unknown(reservation)),
            # A Lease of the reserved address is Reserved with or without the Pool check.
            (_address_lease("198.18.0.150"), Reserved(reservation)),
        )
        for lease, outcome in cases:
            with self.subTest(lease=lease["ip-address"]):
                match = reservation_match(typed_lease(lease), hidden, reservation, (hidden,), global_reservation=None)
                self.assertEqual(match, outcome)

    def test_dhcpv6_reads_no_global_reservation_when_a_local_allocation_of_the_lease_kind_counts(self):
        """allocateReservedLeases6 gives the local address outside the Pool and returns before the Global host."""
        settings = {"reservations-out-of-pool": True, **_GLOBAL_RESERVATIONS}
        pool6 = {"pools": [{"pool": "2001:db8::100 - 2001:db8::200"}]}
        catalogue = _catalogue_responses_for_subnets(6, [{**_SUBNETS[6][0], **pool6}], global_settings=settings)
        lease = lease_record("2001:db8::160", subnet_id=30, duid=_DUID, drop=("hw-address",))
        local = {"subnet-id": 30, "duid": _DUID, "ip-addresses": ["2001:db8::50"]}
        global_ = {"subnet-id": 0, "duid": _DUID, "ip-addresses": ["2001:db8::60"]}
        with with_display_cache_config(leases_ttl=0):
            (match,), kea = self._matches([lease], _kea_hosts(local, global_), family=6, responses=catalogue)
        self.assertEqual(match, _pending("2001:db8::50")(_typed_reservation(local)))
        self.assertNotIn(0, [subnet_id for subnet_id, _key in _lookups(kea)], "no Global lookup")

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
        lease6, held6 = (
            lease_record(address, subnet_id=30, duid=_DUID, drop=("hw-address",))
            for address in ("2001:db8::160", "2001:db8::150")
        )
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
            with self.subTest(label), with_display_cache_config(leases_ttl=0):
                (match,), kea = self._matches([lease], _kea_hosts(*hosts), family=family, responses=catalogue)
                if found is None:
                    self.assertEqual(match, outcome(_typed_reservation(hosts[0])))
                    self.assertNotIn(0, [subnet_id for subnet_id, _key in _lookups(kea)], "no Global lookup")
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
            with self.subTest(label), with_display_cache_config(leases_ttl=0, configuration_ttl=0):
                (found, none), _kea = self._matches(
                    [_address_lease(), _address_lease("198.18.0.30", hw_address="aa:bb:cc:dd:ee:01")],
                    _kea_hosts(host),
                    responses=responses,
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
        address_lease = lease_record("2001:db8::20", subnet_id=30, duid=_DUID, drop=("hw-address",))
        cases = (
            (address_lease, {"subnet-id": 30, "duid": _DUID, "prefixes": [_PREFIX]}),
            (_prefix_lease(), {"subnet-id": 30, "duid": _DUID, "ip-addresses": ["2001:db8::99"]}),
        )
        for lease, host in cases:
            with self.subTest(host=host):
                match = self._match(lease, host, family=6)
                self.assertEqual(match, OtherKindReservation(_typed_reservation(host)))

    def test_no_reservation_in_the_subnet_or_the_global_scope_is_unreserved_in_the_verified_subnet(self):
        (match,), _kea = self._matches([_address_lease()], _NOT_FOUND)

        self.assertIsInstance(match, Unreserved)
        assert isinstance(match, Unreserved)
        self.assertEqual((match.subnet.subnet_id, match.subnet.cidr), (20, "198.18.0.0/24"))

    def test_the_lookups_run_by_allocation_then_by_identity_in_the_subnet_then_globally(self):
        lease = _address_lease(client_id="01:aa:bb:cc:dd:ee:ff")

        _matches, kea = self._matches([lease], _NOT_FOUND)

        self.assertEqual(
            _lookups(kea),
            [(20, "198.18.0.20"), (20, "hw-address"), (20, "client-id"), (0, "hw-address"), (0, "client-id")],
        )

    def test_the_first_reservation_found_wins(self):
        in_subnet = {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.21"}
        cases = (
            ({"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.20"}, [(20, "198.18.0.20")]),
            (in_subnet, [(20, "198.18.0.20"), (20, "hw-address")]),
        )
        for first, lookups in cases:
            with self.subTest(first=first), with_display_cache_config(leases_ttl=0):
                hosts = _kea_hosts(first, in_subnet, {"subnet-id": 0, "hw-address": _MAC})
                (match,), kea = self._matches([_address_lease()], hosts)
                self.assertEqual(getattr(match, "reservation", None), _typed_reservation(first))
                self.assertEqual(_lookups(kea), lookups)

    def test_a_dhcpv6_prefix_lease_looks_up_its_prefix_base_in_the_subnet(self):
        (match,), kea = self._matches([_prefix_lease()], _NOT_FOUND, family=6)

        self.assertIsInstance(match, Unreserved)
        self.assertEqual(_lookups(kea), [(30, "2001:db8:100::"), (30, "duid"), (0, "duid")])

    def test_a_lease_outside_the_verified_subnets_is_unknown_without_a_lookup(self):
        unverified = _match_unknown(UnknownReservationMatch.UNVERIFIED_SUBNET)
        cases = (
            ("unknown Subnet ID", [_address_lease("198.18.1.20", subnet_id=99)], {}),
            ("configured only", [_address_lease()], {"subnet4-list": {"result": 2, "text": "unknown command"}}),
        )
        for label, leases, responses in cases:
            with self.subTest(label), with_display_cache_config(configuration_ttl=0):
                matches, kea = self._matches(leases, _NOT_FOUND, responses=responses)
                self.assertEqual(matches, (unverified,))
                self.assertNotIn("reservation-get", kea.commands())

    def test_a_kea_or_transport_failure_is_unknown(self):
        for reply in ({"result": 1, "text": "host database error"}, requests.ConnectionError("kea unreachable")):
            with self.subTest(reply=reply):
                matches, _kea = self._matches([_address_lease()], reply)
                self.assertEqual(matches, (_match_unknown(UnknownReservationMatch.KEA_ERROR),))

    def test_a_malformed_reply_is_unknown(self):
        matches, _kea = self._matches([_address_lease()], {"result": 0, "arguments": "not-a-host"})

        self.assertEqual(matches, (_match_unknown(UnknownReservationMatch.MALFORMED_REPLY),))

    def test_a_reservation_that_does_not_fit_the_lookup_is_unknown(self):
        """A host of a Subnet that the Catalogue does not verify does not parse into a Reservation."""
        host = {"subnet-id": 21, "hw-address": _MAC, "ip-address": "198.18.0.20"}

        matches, _kea = self._matches([_address_lease()], _res_get(host))

        self.assertEqual(matches, (_match_unknown(UnknownReservationMatch.MALFORMED_REPLY),))

    def test_invalid_server_settings_send_nothing_and_leave_each_lease_unknown(self):
        save_key_without_certificate(self.server)
        self.server.refresh_from_db()

        matches, kea = self._matches([_address_lease()], _NOT_FOUND)

        # The Catalogue read fails first, so no Subnet is verified.
        self.assertEqual(matches, (_match_unknown(UnknownReservationMatch.UNVERIFIED_SUBNET),))
        self.assertEqual(kea.commands(), [])

    def test_a_lease_with_an_identifier_no_reservation_can_hold_is_unknown_only_without_a_match(self):
        foreign = _address_lease(hw_address="", client_id=_LONG_CLIENT_ID)
        host = {"subnet-id": 20, "flex-id": "port-7", "ip-address": "198.18.0.20"}
        for hosts, expected in (
            ((), _match_unknown(UnknownReservationMatch.FOREIGN_IDENTIFIER)),
            ((host,), Reserved(_typed_reservation(host))),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(self._match(foreign, *hosts), expected)

    def test_an_unknown_reservation_command_makes_every_lease_unknown(self):
        """A missing host_cmds hook hides every match; any other Kea error hides only its own."""
        reserved = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:02", "ip-address": "198.18.0.21"}
        leases = [
            _address_lease(),
            _address_lease("198.18.0.21", hw_address="aa:bb:cc:dd:ee:02"),
            _address_lease("198.18.1.20", subnet_id=99),
        ]
        hook = _match_unknown(UnknownReservationMatch.RESERVATION_HOOK_UNAVAILABLE)
        for failure, expected in (
            ({"result": 2, "text": "unknown command"}, (hook, hook, hook)),
            (
                {"result": 1, "text": "host database error"},
                (
                    _match_unknown(UnknownReservationMatch.KEA_ERROR),
                    Reserved(_typed_reservation(reserved)),
                    _match_unknown(UnknownReservationMatch.UNVERIFIED_SUBNET),
                ),
            ),
        ):

            def reservation_get(body, failure=failure):
                if body["arguments"].get("ip-address") == "198.18.0.20":
                    return failure
                return _kea_hosts(reserved)(body)

            with self.subTest(result=failure["result"]), with_display_cache_config(leases_ttl=0):
                matches, _kea = self._matches(leases, reservation_get)
                self.assertEqual(matches, expected)

    def test_an_unexpected_failure_raises(self):
        with (
            client_failure(KeaCommand.RESERVATION_GET, TypeError("unexpected worker failure")),
            self.assertRaises(TypeError),
        ):
            self._matches([_address_lease()], _NOT_FOUND)

    def test_a_lease_of_another_family_is_refused(self):
        with self.assertRaises(ValueError):
            self._matches([_address_lease()], _NOT_FOUND, family=6)

    def test_no_lease_reads_nothing(self):
        matches, kea = self._matches([], _NOT_FOUND)

        self.assertEqual((matches, kea.commands()), ((), []))


class ReservationMatchLookupTest(_ViewTestBase):
    """Each Reservation lookup is a display cache entry, read once per call, in a pool of one client per thread."""

    def _matches(self, leases: list[dict], reservation_get: Any, *, read_since: datetime):
        real_get_client = Server.get_client
        with (
            stub_kea({**_catalogue_responses_for_subnets(4, _SUBNETS[4]), "reservation-get": reservation_get}) as kea,
            patch.object(Server, "get_client", autospec=True, side_effect=real_get_client) as get_client,
        ):
            matches = reservation_matches(
                self.server, 4, [typed_lease(lease) for lease in leases], read_since=read_since
            )
        return matches, kea.bodies("reservation-get"), get_client.call_count

    @with_display_cache_config(leases_ttl=0)
    def test_one_device_with_several_leases_is_probed_once_per_identity(self):
        leases = [_address_lease(f"198.18.0.{index}", client_id="01:aa:bb:cc:dd:ee:ff") for index in range(1, 6)]

        matches, lookups, _clients = self._matches(leases, _NOT_FOUND, read_since=timezone.now())

        self.assertTrue(all(isinstance(match, Unreserved) for match in matches))
        # One address probe per Lease, then one probe per identity in each of the two Scopes.
        self.assertEqual(len(lookups), 5 + 2 * 2)

    @with_display_cache_config(leases_ttl=0)
    def test_a_failed_lookup_runs_once_and_each_lease_that_needs_it_is_unknown(self):
        def reservation_get(body):
            if body["arguments"].get("identifier-type") == "hw-address":
                return {"result": 1, "text": "host database error"}
            return _NOT_FOUND

        leases = [_address_lease(f"198.18.0.{index}") for index in range(1, 4)]
        matches, lookups, _clients = self._matches(leases, reservation_get, read_since=timezone.now())

        self.assertEqual(matches, (_match_unknown(UnknownReservationMatch.KEA_ERROR),) * 3)
        self.assertEqual([body["arguments"].get("identifier-type") for body in lookups].count("hw-address"), 1)

    @with_display_cache_config(leases_ttl=0)
    def test_a_failed_lookup_raises_its_failure_once_for_the_leases_that_need_it(self):
        failure = requests.ConnectionError("Kea is not reachable")

        def reservation_get(body):
            if body["arguments"].get("identifier-type") == "hw-address":
                raise failure
            return _NOT_FOUND

        leases = [_address_lease(f"198.18.0.{index}") for index in range(1, 4)]
        matches, _lookups, _clients = self._matches(leases, reservation_get, read_since=timezone.now())

        self.assertEqual(matches, (_match_unknown(UnknownReservationMatch.KEA_ERROR),) * 3)
        # Each raise of one exception object adds its frames to its traceback, so one read adds one attempt().
        frames = [frame.f_code.co_name for frame, _line in traceback.walk_tb(failure.__traceback__)]
        self.assertEqual(frames.count("attempt"), 1)

    def test_a_cache_hit_builds_no_kea_client(self):
        before = timezone.now()
        _first, lookups, clients = self._matches([_address_lease()], _NOT_FOUND, read_since=before)
        self.assertEqual(len(lookups), 3)
        self.assertGreater(clients, 0)

        matches, lookups, clients = self._matches([_address_lease()], {}, read_since=before)

        self.assertEqual((lookups, clients), ([], 0))
        self.assertIsInstance(matches[0], Unreserved)

    def test_a_lookup_read_before_the_table_is_read_again(self):
        host = {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.20"}
        self._matches([_address_lease()], _res_get(host), read_since=timezone.now())

        # A Refresh reads the Lease table live, so its read time is after the cached lookup.
        matches, lookups, _clients = self._matches(
            [_address_lease()], _NOT_FOUND, read_since=timezone.now() + timedelta(seconds=1)
        )

        self.assertEqual(len(lookups), 3)
        self.assertIsInstance(matches[0], Unreserved)

    def test_a_close_failure_keeps_every_match(self):
        host = {"subnet-id": 20, "hw-address": _MAC, "ip-address": "198.18.0.20"}
        with patch.object(KeaClient, "close", autospec=True, side_effect=OSError("connection already gone")):
            matches, _lookups, _clients = self._matches([_address_lease()], _res_get(host), read_since=timezone.now())

        self.assertEqual(matches, (Reserved(_typed_reservation(host)),))

    def test_each_worker_thread_builds_one_client_and_the_pool_closes_each(self) -> None:
        # Twice as many Leases as workers, so each worker reads two of them.
        leases = [_address_lease(f"198.18.0.{index}", hw_address=f"aa:bb:cc:dd:ee:{index:02x}") for index in range(20)]
        owners: dict[int, int] = {}
        built: list[KeaClient] = []
        closed: list[KeaClient] = []
        sent: list[tuple[int, int]] = []
        registry = threading.Lock()
        first_lookups = 0
        # The first ten lookups wait until all ten run at once, so the pool runs all ten workers.
        all_workers = threading.Barrier(10, timeout=10)

        def reservation_get(body):
            nonlocal first_lookups
            with registry:
                first_lookups += 1
                wait = first_lookups <= 10
            if wait:
                all_workers.wait()
            return _NOT_FOUND

        real_get_client, real_command, real_close = Server.get_client, KeaClient.command, KeaClient.close

        def get_client(server, **kwargs):
            client = real_get_client(server, **kwargs)
            with registry:
                owners[id(client)] = threading.get_ident()
                built.append(client)
            return client

        def command(client, *args, **kwargs):
            with registry:
                sent.append((id(client), threading.get_ident()))
            return real_command(client, *args, **kwargs)

        def close(client):
            real_close(client)
            closed.append(client)

        # The Catalogue is cached first, so only the lookups build clients below.
        with stub_kea(_catalogue_responses_for_subnets(4, _SUBNETS[4])):
            subnet_catalogue.display(self.server, 4)
        with (
            stub_kea({"reservation-get": reservation_get}),
            patch.object(Server, "get_client", autospec=True, side_effect=get_client),
            patch.object(KeaClient, "command", autospec=True, side_effect=command),
            patch.object(KeaClient, "close", autospec=True, side_effect=close),
        ):
            matches = reservation_matches(
                self.server, 4, [typed_lease(lease) for lease in leases], read_since=timezone.now()
            )

        self.assertTrue(all(isinstance(match, Unreserved) for match in matches))
        self.assertEqual(len(built), 10, "one client for each of the ten worker threads")
        self.assertEqual(len(set(owners.values())), 10)
        self.assertEqual(len(sent), 3 * len(leases))
        self.assertTrue(all(owners[client] == thread for client, thread in sent), "a thread used another's client")
        self.assertCountEqual([id(client) for client in closed], [id(client) for client in built])
