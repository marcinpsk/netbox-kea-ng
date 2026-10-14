# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Current Lease Presence of Reservations, read through the real KeaClient and the display cache."""

from __future__ import annotations

import ipaddress
import threading
import time
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch

import requests
from django.utils import timezone

from netbox_kea import kea as kea_module
from netbox_kea.constants import Family
from netbox_kea.kea import KeaClient
from netbox_kea.lease_reservation_reads import lease_presence
from netbox_kea.models import Server
from netbox_kea.reservations import (
    CurrentLeasePresence,
    LeaseAbsent,
    LeasePresenceUnknown,
    LeasePresent,
    UnknownLeasePresence,
)

from .kea_stub import (
    _leases_per_subnet,
    _subnet_stats,
    _typed_reservation,
    complete_lease,
    lease_record,
    lease_reply,
    stub_kea,
)
from .utils import _ViewTestBase, with_display_cache_config, with_kea_client_config

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

    def test_a_snapshot_that_fails_validation_leaves_only_its_own_reservations_unknown(self):
        """A Snapshot read across a backward clock step finishes before it starts, so the reader refuses it."""
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

        self.assertEqual(presences, (LeaseAbsent(), _unknown(UnknownLeasePresence.INVALID_READ)))

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
        with self.assertRaises(TypeError):
            self._presence([_RESERVED], {"lease4-get-by-state": TypeError("unexpected worker failure")})

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
