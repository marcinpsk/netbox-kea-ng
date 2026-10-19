# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Reservation form semantics through public edit operations, real ORM and Kea transport."""

from dataclasses import replace
from ipaddress import IPv6Network, ip_address
from unittest.mock import patch

import requests
from django.test import TestCase

from netbox_kea import reservation_edit, subnet_catalogue
from netbox_kea.change_outcome import ChangeRejected
from netbox_kea.reservations import InSubnetReservationScope, ReservationConflict, ReservationIdentity

from .kea_stub import _catalogue_responses_for_subnets, _res_get, queued, stub_kea
from .utils import _make_db_server, with_kea_client_config

_IDENTITY = ReservationIdentity("hw-address", "02:00:00:00:00:20")
_CIDR = {4: "198.18.0.0/24", 6: "2001:db8::/64"}
_ADDRESS = {4: "198.18.0.20", 6: "2001:db8::20"}
_OK = {"result": 0}


def _responses(family=4, *, suffix="old.example.org", pool_suffix=None, raw=None):
    subnet = {"id": 20, "subnet": _CIDR[family], "ddns-qualifying-suffix": suffix}
    if pool_suffix is not None:
        subnet["pools"] = [
            {
                "pool": "198.18.0.10-198.18.0.99" if family == 4 else "2001:db8::10-2001:db8::99",
                "ddns-qualifying-suffix": pool_suffix,
            }
        ]
    responses = _catalogue_responses_for_subnets(family, [subnet])
    responses.update({"config-test": _OK, "config-write": _OK, "reservation-add": _OK, "reservation-update": _OK})
    if raw is not None:
        responses["reservation-get"] = _res_get(raw)
    return responses


def _raw(family=4, *, hostname="host", address=True):
    raw = {"subnet-id": 20, "hw-address": _IDENTITY.value}
    if hostname:
        raw["hostname"] = hostname
    if address:
        raw.update({"ip-address": _ADDRESS[family]} if family == 4 else {"ip-addresses": [_ADDRESS[family]]})
    return raw


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ReservationEditTests(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def _shown(self, family=4, *, raw=None, **configuration):
        raw = _raw(family) if raw is None else raw
        with stub_kea(_responses(family, raw=raw, **configuration)):
            catalogue = subnet_catalogue.for_verification(self.server, family)
            scope = InSubnetReservationScope(catalogue.find_by_id(20).identity)
            with self.server.get_client(version=family) as client:
                reservation = client.reservation_by_identity(family, catalogue, scope, _IDENTITY)
        return reservation, reservation_edit.form_state(reservation, catalogue)

    def test_invalid_expired_and_other_identity_tokens_are_refused_before_any_kea_command(self):
        current, state = self._shown()
        token = state.initial["managed_fingerprint"]
        values = reservation_edit.SubmittedValues(current.addresses, hostname="changed")
        other = ReservationIdentity("hw-address", "02:00:00:00:00:21")
        for supplied, identity in (("tampered", _IDENTITY), (token, other)):
            with self.subTest(identity=identity, token=supplied), stub_kea({}) as kea:
                with self.assertRaises(ReservationConflict):
                    reservation_edit.save_edit(self.server, 4, 20, identity, supplied, values)
                self.assertEqual(kea.commands(), [])
        # The clock is the external boundary. The real signer and signature remain in use.
        with patch("django.core.signing.time.time", return_value=0):
            _, expired = self._shown()
        with stub_kea({}) as kea, self.assertRaisesRegex(ReservationConflict, "expired"):
            reservation_edit.save_edit(self.server, 4, 20, _IDENTITY, expired.initial["managed_fingerprint"], values)
        self.assertEqual(kea.commands(), [])

    def test_changed_managed_facts_are_rejected_by_the_locked_write(self):
        current, state = self._shown()
        live = _raw(hostname="concurrent")
        with stub_kea(_responses(raw=live)) as kea, self.assertRaises(ChangeRejected) as raised:
            reservation_edit.save_edit(
                self.server,
                4,
                20,
                _IDENTITY,
                state.initial["managed_fingerprint"],
                reservation_edit.SubmittedValues(current.addresses, hostname="edited"),
            )
        self.assertEqual(raised.exception.reason, "target-changed")
        self.assertIn("reservation-get", kea.commands())
        self.assertNotIn("reservation-update", kea.commands())

    def test_a_suffix_change_returns_live_form_state_for_a_successful_retry(self):
        current, state = self._shown()
        values = reservation_edit.SubmittedValues(current.addresses, hostname="renamed.old.example.org")
        responses = _responses(suffix="new.example.org", raw=_raw())
        with stub_kea(responses) as kea, self.assertRaises(reservation_edit.EditConflict) as raised:
            reservation_edit.save_edit(self.server, 4, 20, _IDENTITY, state.initial["managed_fingerprint"], values)
        conflict = raised.exception
        self.assertEqual(
            conflict.message,
            "The qualifying suffix differs from the one shown (old.example.org → new.example.org). "
            "Check the name and save again.",
        )
        self.assertNotIn("reservation-update", kea.commands())
        refreshed = conflict.live_state.initial["managed_fingerprint"]
        self.assertEqual(reservation_edit.check_token(refreshed, 4, 20, _IDENTITY).qualifying_suffix, "new.example.org")
        final = {**_raw(), "hostname": "renamed"}
        with stub_kea({**responses, "reservation-get": queued(_res_get(_raw()), _res_get(final))}) as kea:
            outcome = reservation_edit.save_edit(
                self.server, 4, 20, _IDENTITY, refreshed, replace(values, hostname="renamed.new.example.org")
            )
        self.assertEqual(outcome.application, "applied")
        self.assertEqual(kea.bodies("reservation-update")[0]["arguments"]["reservation"]["hostname"], "renamed")

    def test_an_unknown_live_suffix_is_a_hostname_field_conflict(self):
        current, state = self._shown()
        responses = _responses(raw=_raw())
        responses["config-get"] = requests.ConnectionError("unavailable")
        with stub_kea(responses) as kea, self.assertRaises(reservation_edit.EditConflict) as raised:
            reservation_edit.save_edit(
                self.server,
                4,
                20,
                _IDENTITY,
                state.initial["managed_fingerprint"],
                reservation_edit.SubmittedValues(current.addresses, hostname="edited"),
            )
        self.assertEqual(raised.exception.field, "hostname")
        self.assertNotIn("reservation-update", kea.commands())

    def test_adding_a_name_to_an_addressless_reservation_requires_saving_the_address_first(self):
        for family in (4, 6):
            raw = _raw(family, hostname="", address=False)
            _current, state = self._shown(family, raw=raw, pool_suffix="pool.example.org")
            values = reservation_edit.SubmittedValues((ip_address(_ADDRESS[family]),), hostname="host")
            with (
                self.subTest(family=family),
                stub_kea(_responses(family, raw=raw, pool_suffix="pool.example.org")) as kea,
            ):
                with self.assertRaisesRegex(ReservationConflict, "Save an address first"):
                    reservation_edit.save_edit(
                        self.server, family, 20, _IDENTITY, state.initial["managed_fingerprint"], values
                    )
                self.assertNotIn("reservation-update", kea.commands())

    def test_form_state_shows_the_published_name_and_authenticated_identity(self):
        for family in (4, 6):
            for stored, shown in (
                ("host", "host.old.example.org"),
                ("host.example.net", "host.example.net.old.example.org"),
                ("Host.Example.net.", "host.example.net"),
            ):
                with self.subTest(family=family, stored=stored):
                    current, state = self._shown(family, raw=_raw(family, hostname=stored))
                    self.assertEqual(state.initial["hostname"], shown)
                    self.assertEqual(state.initial["subnet_cidr"], _CIDR[family])
                    checked = reservation_edit.check_token(state.initial["managed_fingerprint"], family, 20, _IDENTITY)
                    self.assertEqual(checked.qualifying_suffix, "old.example.org")
                    self.assertEqual(state.initial["identifier"], current.identity.value)

    def test_an_unchanged_published_name_keeps_the_stored_hostname(self):
        for family in (4, 6):
            for hostname in ("Host", "host.example.net", "Host.Old.Example.org."):
                raw = _raw(family, hostname=hostname)
                current, state = self._shown(family, raw=raw)
                with self.subTest(family=family, hostname=hostname), stub_kea(_responses(family, raw=raw)) as kea:
                    outcome = reservation_edit.save_edit(
                        self.server,
                        family,
                        20,
                        _IDENTITY,
                        state.initial["managed_fingerprint"],
                        reservation_edit.SubmittedValues(current.addresses, hostname=state.initial["hostname"]),
                    )
                self.assertEqual(outcome.application, "applied")
                self.assertEqual(kea.bodies("reservation-update")[0]["arguments"]["reservation"]["hostname"], hostname)

    def test_moving_to_a_pool_keeps_the_entered_published_name(self):
        for family in (4, 6):
            raw = _raw(family)
            outside = "198.18.0.200" if family == 4 else "2001:db8::200"
            raw.update({"ip-address": outside} if family == 4 else {"ip-addresses": [outside]})
            _current, state = self._shown(family, raw=raw, pool_suffix="pool.example.org")
            values = reservation_edit.SubmittedValues(
                (ip_address(_ADDRESS[family]),), hostname=state.initial["hostname"]
            )
            with (
                self.subTest(family=family),
                stub_kea(_responses(family, raw=raw, pool_suffix="pool.example.org")) as kea,
            ):
                reservation_edit.save_edit(
                    self.server, family, 20, _IDENTITY, state.initial["managed_fingerprint"], values
                )
            self.assertEqual(
                kea.bodies("reservation-update")[0]["arguments"]["reservation"]["hostname"], "host.old.example.org."
            )

    def test_an_edited_published_name_is_stored_under_its_live_suffix(self):
        for family in (4, 6):
            current, state = self._shown(family)
            for entered, stored in (
                ("db.old.example.org", "db"),
                ("DB.Old.Example.org.", "DB"),
                ("db.example.net", "db.example.net."),
                ("db", "db"),
                ("", None),
            ):
                with (
                    self.subTest(family=family, entered=entered),
                    stub_kea(_responses(family, raw=_raw(family))) as kea,
                ):
                    reservation_edit.save_edit(
                        self.server,
                        family,
                        20,
                        _IDENTITY,
                        state.initial["managed_fingerprint"],
                        reservation_edit.SubmittedValues(current.addresses, hostname=entered),
                    )
                self.assertEqual(
                    kea.bodies("reservation-update")[0]["arguments"]["reservation"].get("hostname"), stored
                )

    def test_addressless_stored_name_is_kept_but_a_changed_name_requires_an_address_first(self):
        for family in (4, 6):
            raw = _raw(family, address=False)
            _current, state = self._shown(family, raw=raw, pool_suffix="pool.example.org")
            for entered in ("host", "changed"):
                with (
                    self.subTest(family=family, entered=entered),
                    stub_kea(_responses(family, raw=raw, pool_suffix="pool.example.org")) as kea,
                ):
                    if entered == "host":
                        outcome = reservation_edit.save_edit(
                            self.server,
                            family,
                            20,
                            _IDENTITY,
                            state.initial["managed_fingerprint"],
                            reservation_edit.SubmittedValues(hostname=entered),
                        )
                        self.assertEqual(outcome.intended.hostname, "host")
                    else:
                        with self.assertRaisesRegex(ReservationConflict, "Save an address first"):
                            reservation_edit.save_edit(
                                self.server,
                                family,
                                20,
                                _IDENTITY,
                                state.initial["managed_fingerprint"],
                                reservation_edit.SubmittedValues(hostname=entered),
                            )
                        self.assertNotIn("reservation-update", kea.commands())

    def test_unknown_suffix_keeps_the_stored_name_when_another_field_changes(self):
        current, state = self._shown()
        responses = _responses(raw=_raw())
        responses["config-get"] = requests.ConnectionError("unavailable")
        with stub_kea(responses):
            catalogue = subnet_catalogue.for_verification(self.server, 4)
        state = reservation_edit.form_state(current, catalogue)
        with stub_kea(responses) as kea:
            outcome = reservation_edit.save_edit(
                self.server,
                4,
                20,
                _IDENTITY,
                state.initial["managed_fingerprint"],
                reservation_edit.SubmittedValues((ip_address("198.18.0.21"),), hostname="host"),
            )
        self.assertEqual(outcome.application, "applied")
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual((sent["hostname"], sent["ip-address"]), ("host", "198.18.0.21"))

    def test_add_builds_both_families_and_returns_pool_overlap_facts(self):
        for family in (4, 6):
            prefixes = () if family == 4 else (IPv6Network("2001:db8:1::/80"),)
            values = reservation_edit.SubmittedValues(
                (ip_address(_ADDRESS[family]),),
                prefixes,
                hostname="host.pool.example.org",
                option_rows=(reservation_edit.OptionRow("custom", "value"),),
            )
            with (
                self.subTest(family=family),
                stub_kea(_responses(family, raw=_raw(family), pool_suffix="pool.example.org")) as kea,
            ):
                outcome = reservation_edit.save_add(self.server, family, _CIDR[family], _IDENTITY, values)
            self.assertEqual(outcome.application, "applied")
            sent = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
            self.assertEqual(sent["hostname"], "host")
            self.assertEqual(sent["option-data"], [{"name": "custom", "data": "value"}])
            self.assertEqual(
                sent["ip-address"] if family == 4 else sent["ip-addresses"],
                _ADDRESS[family] if family == 4 else [_ADDRESS[family]],
            )
            if family == 6:
                self.assertEqual(sent["prefixes"], ["2001:db8:1::/80"])
            (warning,) = outcome.warnings
            self.assertIsInstance(warning, reservation_edit.PoolOverlap)
            self.assertEqual(warning.address, ip_address(_ADDRESS[family]))
            self.assertEqual(
                warning.pool.range, "198.18.0.10-198.18.0.99" if family == 4 else "2001:db8::10-2001:db8::99"
            )

    def test_add_without_configuration_returns_warning_only_for_an_address(self):
        for has_address in (False, True):
            values = reservation_edit.SubmittedValues((ip_address(_ADDRESS[4]),) if has_address else ())
            responses = _responses(raw=_raw(hostname="", address=has_address))
            responses["config-get"] = requests.ConnectionError("unavailable")
            with self.subTest(has_address=has_address), stub_kea(responses):
                outcome = reservation_edit.save_add(self.server, 4, _CIDR[4], _IDENTITY, values)
            self.assertEqual(
                outcome.warnings, (reservation_edit.PoolCheckUnavailable(_CIDR[4]),) if has_address else ()
            )

    def test_add_name_without_address_under_a_pool_suffix_is_a_hostname_conflict(self):
        with stub_kea(_responses(pool_suffix="pool.example.org")) as kea:
            with self.assertRaises(reservation_edit.EditConflict) as raised:
                reservation_edit.save_add(
                    self.server, 4, _CIDR[4], _IDENTITY, reservation_edit.SubmittedValues(hostname="host")
                )
        self.assertEqual(raised.exception.field, "hostname")
        self.assertNotIn("reservation-add", kea.commands())

    def test_option_rows_keep_their_existing_private_replacement_rules(self):
        first = {
            "code": 222,
            "space": "vendor-lab",
            "data": "opaque",
            "csv-format": False,
            "never-send": True,
            "client-classes": ["lab"],
        }
        second = {"name": "custom", "space": "vendor-other", "data": "other", "always-send": True}
        raw = {**_raw(), "option-data": [first, second], "user-context": {"owner": "lab"}}
        current, state = self._shown(raw=raw)
        self.assertEqual([row["original_index"] for row in state.options_initial], [0, 1])
        values = reservation_edit.SubmittedValues(
            current.addresses,
            hostname=state.initial["hostname"],
            option_rows=(
                reservation_edit.OptionRow("custom", "other", True, original_index=1),
                reservation_edit.OptionRow("222", "new", original_index=0),
            ),
        )
        with stub_kea(_responses(raw=raw)) as kea:
            reservation_edit.save_edit(self.server, 4, 20, _IDENTITY, state.initial["managed_fingerprint"], values)
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(sent["option-data"], [second, {**first, "data": "new"}])
        self.assertEqual(sent["user-context"], {"owner": "lab"})

    def test_add_stores_the_name_that_publishes_the_submitted_value(self):
        for family in (4, 6):
            for entered, expected in (
                ("host.old.example.org", "host"),
                ("Host.Old.Example.org.", "Host"),
                ("web.example.net", "web.example.net."),
                ("printer", "printer"),
                ("", None),
            ):
                values = reservation_edit.SubmittedValues((ip_address(_ADDRESS[family]),), hostname=entered)
                with (
                    self.subTest(family=family, entered=entered),
                    stub_kea(_responses(family, raw=_raw(family))) as kea,
                ):
                    reservation_edit.save_add(self.server, family, _CIDR[family], _IDENTITY, values)
                self.assertEqual(kea.bodies("reservation-add")[0]["arguments"]["reservation"].get("hostname"), expected)

    def test_renamed_and_deleted_option_rows_do_not_reuse_old_metadata(self):
        first = {"name": "custom", "space": "vendor-lab", "data": "old", "csv-format": False, "never-send": True}
        for rows in (
            (reservation_edit.OptionRow("renamed", "new", original_index=0),),
            (
                reservation_edit.OptionRow("custom", "old", delete=True, original_index=0),
                reservation_edit.OptionRow("custom", "new"),
            ),
        ):
            raw = {**_raw(), "option-data": [first]}
            current, state = self._shown(raw=raw)
            with self.subTest(rows=rows), stub_kea(_responses(raw=raw)) as kea:
                reservation_edit.save_edit(
                    self.server,
                    4,
                    20,
                    _IDENTITY,
                    state.initial["managed_fingerprint"],
                    reservation_edit.SubmittedValues(
                        current.addresses, hostname=state.initial["hostname"], option_rows=rows
                    ),
                )
            self.assertEqual(
                kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"],
                [{"name": rows[-1].name, "data": "new"}],
            )

    def test_duplicate_option_names_keep_their_source_positions_and_spaces(self):
        options = [
            {"name": "custom", "space": "vendor-a", "data": "one", "never-send": True},
            {"name": "custom", "space": "vendor-b", "data": "two", "csv-format": False},
        ]
        raw = {**_raw(), "option-data": options}
        current, state = self._shown(raw=raw)
        with stub_kea(_responses(raw=raw)) as kea:
            reservation_edit.save_edit(
                self.server,
                4,
                20,
                _IDENTITY,
                state.initial["managed_fingerprint"],
                reservation_edit.SubmittedValues(
                    current.addresses,
                    hostname=state.initial["hostname"],
                    option_rows=(
                        reservation_edit.OptionRow("custom", "two", original_index=1),
                        reservation_edit.OptionRow("custom", "one", original_index=0),
                    ),
                ),
            )
        self.assertEqual(
            kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"], [options[1], options[0]]
        )
