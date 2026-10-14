# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0

from unittest import mock

import requests
from django.db import OperationalError
from django.test import SimpleTestCase
from django.urls import reverse

from netbox_kea.models import PinnedSettings
from netbox_kea.reservations import LeaseIdentities, ReservationIdentity, lease_identifier_types, lease_identities

from .kea_stub import (
    _catalogue_responses_for_subnets,
    _leases_per_subnet,
    _res_page,
    complete_lease,
    lease_record,
    stub_kea,
    typed_lease,
)
from .utils import _ViewTestBase, with_display_cache_config

_SUBNETS4 = [{"id": 20, "subnet": "198.18.0.0/24"}, {"id": 21, "subnet": "198.18.1.0/24"}]
_SUBNETS6 = [{"id": 30, "subnet": "2001:db8::/64"}]


class TestSharedLeaseIdentityRules(SimpleTestCase):
    """Lease enrichment and Reservation enrichment read the identities of one typed Lease."""

    def test_a_lease_yields_its_normalized_identities_in_match_order(self):
        lease = typed_lease({**lease_record("198.18.0.20"), "hw-address": "AA-BB-CC-DD-EE-FF", "client-id": "01:AA:BB"})

        self.assertEqual(
            lease_identities(lease),
            LeaseIdentities(
                (ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff"), ReservationIdentity("client-id", "01:aa:bb")),
                foreign=False,
            ),
        )

    def test_the_identifier_order_of_each_lease_kind_is_the_published_order(self):
        for record in (lease_record("198.18.0.20"), lease_record("2001:db8:1::10")):
            lease = typed_lease(record)
            with self.subTest(family=lease.family):
                types = [identity.identifier_type for identity in lease_identities(lease).identities]
                self.assertEqual(tuple(types), lease_identifier_types(lease.family))

    def test_empty_identifiers_are_no_identity(self):
        """Kea's empty DUID of a declined DHCPv6 lease is no identity, so it matches nothing."""
        declined = typed_lease(lease_record("2001:db8::12", duid="00:00:00", state=1, drop=("hw-address",)))
        self.assertEqual(lease_identities(declined), LeaseIdentities((), foreign=False))

    def test_an_identifier_that_no_reservation_can_hold_is_reported_not_dropped(self):
        long_client_id = ":".join(["01"] * 129)
        lease = typed_lease(lease_record("198.18.0.20", client_id=long_client_id))
        carried = lease_identities(lease)
        self.assertEqual(carried.identities, (ReservationIdentity("hw-address", "aa:bb:cc:00:00:10"),))
        self.assertTrue(carried.foreign)

    def test_lease_identifier_types_validate_the_family(self):
        self.assertEqual(lease_identifier_types(4), ("hw-address", "client-id"))
        self.assertEqual(lease_identifier_types(6), ("duid", "hw-address"))
        for family in (True, False, 4.0, 6.0, "4", 5):
            with self.subTest(family=family), self.assertRaises(ValueError):
                lease_identifier_types(family)


class TestReservationLeaseRelationship(_ViewTestBase):
    """The Reservation table reports one lease relationship per complete Reservation."""

    def _url(self, version: int = 4) -> str:
        return reverse(f"plugins:netbox_kea:server_reservations{version}", args=[self.server.pk])

    def _rows(self, responses, version: int = 4, subnets=None):
        merged = _catalogue_responses_for_subnets(version, subnets or _SUBNETS4)
        merged.update(responses)
        with stub_kea(merged) as kea:
            response = self.client.get(self._url(version))
        self.assertEqual(response.status_code, 200)
        return response, response.context["table"].data.data, kea

    def test_an_unreadable_lease_observation_reports_no_relationship(self):
        """A failed lease query is unknown, not a confirmed absence of a lease."""
        response, rows, _kea = self._rows(
            {
                "reservation-get-page": _res_page(
                    [{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}]
                ),
                "lease4-get-by-state": requests.ConnectionError("kea unreachable"),
            }
        )

        self.assertIsNone(rows[0]["has_active_lease"])
        self.assertNotContains(response, "No Lease")
        self.assertNotContains(response, "Active Lease")

    def test_a_complete_observation_without_a_lease_shows_no_lease(self):
        response, rows, _kea = self._rows(
            {
                "reservation-get-page": _res_page(
                    [{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}]
                ),
                "lease4-get-by-state": _leases_per_subnet({20: []}),
            }
        )

        self.assertIs(rows[0]["has_active_lease"], False)
        self.assertContains(response, '<span class="badge text-bg-secondary">No Lease</span>')

    def test_an_observation_that_cannot_confirm_a_missing_lease_shows_lease_unknown_with_its_reason(self):
        cases = (
            (lease_record("198.18.0.30", subnet_id=20, hostname=["private"]), "lease records that could not be read"),
            (
                lease_record("198.18.0.30", subnet_id=20, hw_address="", client_id=":".join(["01"] * 129)),
                "a client identifier that no Reservation can hold",
            ),
        )
        for lease, reason in cases:
            with self.subTest(reason=reason), with_display_cache_config(leases_ttl=0):
                response, rows, _kea = self._rows(
                    {
                        "reservation-get-page": _res_page(
                            [{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}]
                        ),
                        "lease4-get-by-state": _leases_per_subnet({20: [lease]}),
                    }
                )
                self.assertIsNone(rows[0]["has_active_lease"])
                self.assertContains(response, ">Lease Unknown</span>")
                self.assertContains(response, reason)
                self.assertNotContains(response, "No Lease")

    def test_an_unexpected_worker_failure_is_logged_at_exception_level(self):
        """An unexpected enrichment failure is visible without DEBUG logging."""
        with self.assertLogs("netbox_kea.views.reservations", level="ERROR") as logs:
            response, rows, _kea = self._rows(
                {
                    "reservation-get-page": _res_page(
                        [{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}]
                    ),
                    "lease4-get-by-state": TypeError("unexpected worker failure"),
                }
            )

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(rows[0]["has_active_lease"])
        self.assertIn("Reservation lease enrichment failed", logs.output[0])

    def test_a_database_error_while_pinning_the_badge_settings_leaves_the_badges_unknown(self):
        """The Reservation page still renders when the settings read of its badge workers fails."""
        failure = OperationalError("server closed the connection unexpectedly")
        with (
            mock.patch.object(PinnedSettings, "read", autospec=True, side_effect=failure),
            self.assertLogs("netbox_kea.views.reservations", level="ERROR") as logs,
        ):
            response, rows, _kea = self._rows(
                {
                    "reservation-get-page": _res_page(
                        [{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}]
                    ),
                    "lease4-get-by-state": _leases_per_subnet({20: []}),
                }
            )

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(rows[0]["has_active_lease"])
        self.assertIn("Reservation lease enrichment failed", logs.output[0])

    def test_a_global_reservation_links_the_lease_search_by_its_identity(self):
        """Global Scope has no Subnet, so the identity selects the route."""
        response, rows, _kea = self._rows(
            {
                "reservation-get-page": _res_page([{"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ff"}]),
                "lease4-get-by-hw-address": {
                    "result": 0,
                    "arguments": {
                        "leases": [
                            complete_lease(
                                {
                                    "subnet-id": 21,
                                    "hw-address": "AA-BB-CC-DD-EE-FF",
                                    "ip-address": "198.18.1.20",
                                    "state": 0,
                                }
                            )
                        ]
                    },
                },
            }
        )

        self.assertIs(rows[0]["has_active_lease"], True)
        self.assertIn("by=hw", rows[0]["lease_url"])
        self.assertIn("q=aa%3Abb%3Acc%3Add%3Aee%3Aff", rows[0]["lease_url"])
        self.assertContains(response, 'class="badge text-bg-success text-decoration-none">Active Lease</a>')

    def test_an_addressless_reservation_links_the_lease_search_by_identity(self):
        """An addressless Reservation has no address, so the identity selects the route."""
        _response, rows, _kea = self._rows(
            {
                "reservation-get-page": _res_page([{"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff"}]),
                "lease4-get-by-state": _leases_per_subnet(
                    {
                        20: [
                            complete_lease(
                                {
                                    "subnet-id": 20,
                                    "hw-address": "aa:bb:cc:dd:ee:ff",
                                    "ip-address": "198.18.0.77",
                                    "state": 0,
                                }
                            )
                        ]
                    }
                ),
            }
        )

        self.assertIs(rows[0]["has_active_lease"], True)
        self.assertIn("by=hw", rows[0]["lease_url"])
        self.assertNotIn("by=ip", rows[0]["lease_url"])

    def test_a_multi_address_reservation_links_the_address_that_holds_the_lease(self):
        """No address is the primary one, so the link follows the address that matched."""
        _response, rows, _kea = self._rows(
            {
                "reservation-get-page": _res_page(
                    [
                        {
                            "subnet-id": 30,
                            "duid": "00:01:02:03",
                            "ip-addresses": ["2001:db8::20", "2001:db8::21"],
                        }
                    ]
                ),
                "lease6-get-all": _leases_per_subnet(
                    {
                        30: [
                            complete_lease(
                                {
                                    "subnet-id": 30,
                                    "duid": "00:01:02:04",
                                    "ip-address": "2001:db8::21",
                                    "state": 0,
                                }
                            )
                        ]
                    }
                ),
            },
            version=6,
            subnets=_SUBNETS6,
        )

        self.assertIs(rows[0]["has_active_lease"], True)
        self.assertIn("q=2001%3Adb8%3A%3A21", rows[0]["lease_url"])
