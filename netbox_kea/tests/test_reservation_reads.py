# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The three reads of one Reservation by its identity, each through its own Catalogue authority."""

from django.test import TestCase

from netbox_kea.reservation_reads import read_by_identity, read_change_target, read_sync_target
from netbox_kea.reservations import InSubnetReservationScope, ReservationIdentity
from netbox_kea.subnet_catalogue import CatalogueUnavailable, SubnetUnconfirmed

from .kea_stub import _catalogue_responses, _res_get, _res_page, stub_kea
from .utils import _make_db_server, read_display_entries

_IDENTITY = ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff")
_RECORD = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.10", "hostname": "host"}
_GONE = {"result": 3, "text": "Host not found."}


def _responses(reservation: dict) -> dict:
    return {
        **_catalogue_responses(4, 20, "198.18.0.0/24"),
        "reservation-get": reservation,
        "reservation-get-page": _res_page([]),
    }


class TestReadByIdentity(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def test_it_reads_through_the_cached_display_catalogue(self):
        with stub_kea(_responses(_res_get(_RECORD))) as kea:
            first = read_by_identity(self.server, 4, 20, _IDENTITY)
            second = read_by_identity(self.server, 4, 20, _IDENTITY)

        self.assertEqual(first, second)
        self.assertIsInstance(first.scope, InSubnetReservationScope)
        self.assertEqual(first.scope.subnet.subnet_id, 20)
        self.assertEqual(kea.commands(), ["subnet4-list", "config-get", "reservation-get", "reservation-get"])

    def test_a_reservation_that_kea_does_not_hold_is_none(self):
        with stub_kea(_responses(_GONE)):
            self.assertIsNone(read_by_identity(self.server, 4, 20, _IDENTITY))


class TestReadChangeTarget(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def test_it_reads_the_subnet_list_only_and_fills_no_cache(self):
        with stub_kea(_responses(_res_get(_RECORD))) as kea:
            reservation = read_change_target(self.server, 4, 20, _IDENTITY)
            read_change_target(self.server, 4, 20, _IDENTITY)

        self.assertEqual(reservation.scope.subnet.subnet_id, 20)
        self.assertEqual(kea.commands(), ["subnet4-list", "reservation-get"] * 2)

    def test_absence_is_none(self):
        for name, subnet_id, reply in (("subnet", 21, _res_get(_RECORD)), ("reservation", 20, _GONE)):
            with self.subTest(name), stub_kea(_responses(reply)) as kea:
                self.assertIsNone(read_change_target(self.server, 4, subnet_id, _IDENTITY))
                self.assertEqual(kea.commands().count("reservation-get"), int(name == "reservation"))

    def test_a_subnet_list_that_cannot_confirm_absence_raises_with_its_catalogue(self):
        responses = {**_responses(_res_get(_RECORD)), "subnet4-list": {"result": 1, "text": "busy"}}
        with stub_kea(responses) as kea, self.assertLogs("netbox_kea.read_failure", "WARNING"):
            with self.assertRaises(SubnetUnconfirmed) as raised:
                read_change_target(self.server, 4, 20, _IDENTITY)

        self.assertIsInstance(raised.exception, CatalogueUnavailable)
        self.assertFalse(raised.exception.snapshot.identity_available)
        self.assertEqual(kea.commands(), ["subnet4-list"])


class TestReadSyncTarget(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def test_it_reads_identity_and_configuration_facts_live(self):
        with stub_kea(_responses(_res_get(_RECORD))) as kea:
            loaded = read_sync_target(self.server, 4, 20, _IDENTITY)

        reservation, catalogue = loaded
        self.assertEqual(reservation.identity, _IDENTITY)
        self.assertTrue(catalogue.configuration_available)
        self.assertEqual(catalogue.find_by_id(20).identity, reservation.scope.subnet)
        self.assertEqual(kea.commands(), ["subnet4-list", "config-get", "reservation-get"])

    def test_it_keeps_the_cached_display_entries(self):
        responses = _responses(_res_get(_RECORD))
        with stub_kea(responses):
            read_display_entries(self.server, 4)
            read_sync_target(self.server, 4, 20, _IDENTITY)
        with stub_kea(responses) as kea:
            read_display_entries(self.server, 4)

        self.assertEqual(kea.commands(), [])

    def test_absence_is_none(self):
        for name, subnet_id, reply in (("subnet", 21, _res_get(_RECORD)), ("reservation", 20, _GONE)):
            with self.subTest(name), stub_kea(_responses(reply)):
                self.assertIsNone(read_sync_target(self.server, 4, subnet_id, _IDENTITY))

    def test_a_subnet_list_that_cannot_confirm_absence_raises_with_its_catalogue(self):
        responses = {**_responses(_res_get(_RECORD)), "subnet4-list": {"result": 1, "text": "busy"}}
        with stub_kea(responses) as kea, self.assertLogs("netbox_kea.read_failure", "WARNING"):
            with self.assertRaises(SubnetUnconfirmed) as raised:
                read_sync_target(self.server, 4, 20, _IDENTITY)

        self.assertTrue(raised.exception.snapshot.configuration_available)
        self.assertNotIn("reservation-get", kea.commands())

    def test_a_failed_config_get_returns_the_reservation_with_a_catalogue_that_records_it(self):
        responses = {**_responses(_res_get(_RECORD)), "config-get": {"result": 1, "text": "busy"}}
        with stub_kea(responses) as kea, self.assertLogs("netbox_kea", "WARNING"):
            reservation, catalogue = read_sync_target(self.server, 4, 20, _IDENTITY)

        self.assertEqual(reservation.identity, _IDENTITY)
        self.assertFalse(catalogue.configuration_available)
        self.assertEqual(kea.commands(), ["subnet4-list", "config-get", "reservation-get"])
