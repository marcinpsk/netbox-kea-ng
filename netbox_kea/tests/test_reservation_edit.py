# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Reservation form semantics through public edit operations, real ORM and Kea transport."""

from dataclasses import replace
from ipaddress import IPv6Network, ip_address
from unittest.mock import patch

import requests
from django.test import TestCase

from netbox_kea import config_write, reservation_edit, subnet_catalogue
from netbox_kea.change_outcome import ChangeRejected
from netbox_kea.dhcp_options import DHCPOptionChange, DHCPOptionEdit, parse_dhcp_option
from netbox_kea.reservations import (
    InSubnetReservationScope,
    ReservationChange,
    ReservationConflict,
    ReservationIdentity,
    reservation_fingerprint,
)

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

    def test_option_rows_keep_live_order_classes_and_unknown_fields(self):
        first = {
            "code": 222,
            "space": "vendor-lab",
            "data": "aabb",
            "csv-format": False,
            "never-send": True,
            "client-classes": ["lab"],
        }
        second = {"name": "custom", "space": "vendor-other", "data": "other", "always-send": True}
        raw = {**_raw(), "option-data": [first, second], "user-context": {"owner": "lab"}}
        current, state = self._shown(raw=raw)
        self.assertEqual([row["original_option"] for row in state.options_initial], [first, second])
        values = reservation_edit.SubmittedValues(
            current.addresses,
            hostname=state.initial["hostname"],
            option_rows=(
                reservation_edit.OptionRow("custom", "other", True, original_option=current.options[1]),
                reservation_edit.OptionRow("", "aabc", original_option=current.options[0], client_classes=("lab",)),
            ),
        )
        with stub_kea(_responses(raw=raw)) as kea:
            reservation_edit.save_edit(self.server, 4, 20, _IDENTITY, state.initial["managed_fingerprint"], values)
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(
            sent["option-data"],
            [{**first, "data": "aabc"}, second],
        )
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
        first = {"name": "custom", "space": "vendor-lab", "data": "aabb", "csv-format": False, "never-send": True}
        raw = {**_raw(), "option-data": [first]}
        current, state = self._shown(raw=raw)
        for rows in (
            (reservation_edit.OptionRow("renamed", "aabc", original_option=current.options[0]),),
            (
                reservation_edit.OptionRow("custom", "aabb", delete=True, original_option=current.options[0]),
                reservation_edit.OptionRow("custom", "new"),
            ),
        ):
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
                (
                    [
                        {
                            "name": "renamed",
                            "space": "vendor-lab",
                            "data": "aabc",
                            "csv-format": False,
                            "never-send": True,
                        }
                    ]
                    if len(rows) == 1
                    else [{"name": "custom", "data": "new"}]
                ),
            )

    def test_duplicate_option_names_in_different_spaces_keep_live_order(self):
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
                        reservation_edit.OptionRow("custom", "two", original_option=current.options[1]),
                        reservation_edit.OptionRow("custom", "one", original_option=current.options[0]),
                    ),
                ),
            )
        self.assertEqual(kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"], options)

    def test_a_concurrently_added_option_is_a_named_reservation_conflict(self):
        raw = {**_raw(), "option-data": [{"name": "routers", "data": "198.18.0.1"}]}
        current, state = self._shown(raw=raw)
        live = {**raw, "option-data": [*raw["option-data"], {"code": 42, "data": "198.18.0.123"}]}
        values = reservation_edit.SubmittedValues(
            current.addresses,
            hostname=state.initial["hostname"],
            option_rows=(reservation_edit.OptionRow("routers", "198.18.0.2", original_option=current.options[0]),),
        )
        with stub_kea(_responses(raw=live)) as kea:
            with self.assertRaisesRegex(ReservationConflict, "ntp-servers"):
                reservation_edit.save_edit(self.server, 4, 20, _IDENTITY, state.initial["managed_fingerprint"], values)
            self.assertNotIn("reservation-update", kea.commands())

    def test_a_malformed_option_intent_is_a_named_reservation_conflict(self):
        raw = {**_raw(), "option-data": [{"name": "routers", "data": "198.18.0.1"}]}
        current, state = self._shown(raw=raw)
        values = reservation_edit.SubmittedValues(
            current.addresses,
            hostname=state.initial["hostname"],
            option_rows=(
                reservation_edit.OptionRow(
                    "routers", "198.18.0.2", original_option=parse_dhcp_option({"name": "routers", "data": "not-shown"})
                ),
            ),
        )
        with stub_kea(_responses(raw=raw)) as kea:
            with self.assertRaisesRegex(ReservationConflict, "routers"):
                reservation_edit.save_edit(self.server, 4, 20, _IDENTITY, state.initial["managed_fingerprint"], values)
            self.assertNotIn("reservation-update", kea.commands())

    def test_an_option_without_space_does_not_take_foreign_space_metadata(self):
        foreign = {"name": "routers", "space": "vendor-lab", "data": "opaque", "user-context": {"owner": "vendor"}}
        raw = {**_raw(), "option-data": [foreign]}
        current, _state = self._shown(raw=raw)
        added = parse_dhcp_option({"name": "routers", "data": "198.18.0.1"})
        change = ReservationChange(options=DHCPOptionEdit(current.options, (DHCPOptionChange(None, added),)))
        with stub_kea(_responses(raw=raw)) as kea:
            config_write.edit_reservation(
                self.server, 4, 20, _IDENTITY, reservation_fingerprint(current), lambda _live, _catalogue: change
            )
        self.assertEqual(
            kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"],
            [foreign, {"name": "routers", "data": "198.18.0.1"}],
        )

    def test_incomplete_option_definitions_refuse_changed_options_but_keep_other_edits(self):
        raw = {**_raw(hostname=""), "option-data": [{"name": "custom", "data": "old"}]}
        current, state = self._shown(raw=raw)
        rows = (reservation_edit.OptionRow("custom", "new", original_option=current.options[0]),)
        malformed = _responses(raw=raw)["config-get"]
        malformed["arguments"]["Dhcp4"]["option-def"] = [{"name": "custom", "code": "invalid"}]
        for configuration in (malformed, requests.ConnectionError("offline")):
            responses = {**_responses(raw=raw), "config-get": configuration}
            with self.subTest(configuration=type(configuration).__name__), stub_kea(responses) as kea:
                with self.assertRaisesRegex(ReservationConflict, "custom.*definitions.*unavailable"):
                    reservation_edit.save_edit(
                        self.server,
                        4,
                        20,
                        _IDENTITY,
                        state.initial["managed_fingerprint"],
                        reservation_edit.SubmittedValues(current.addresses, option_rows=rows),
                    )
                self.assertNotIn("reservation-update", kea.commands())
            unchanged = replace(rows[0], data="old")
            with stub_kea(responses) as kea:
                outcome = reservation_edit.save_edit(
                    self.server,
                    4,
                    20,
                    _IDENTITY,
                    state.initial["managed_fingerprint"],
                    reservation_edit.SubmittedValues((ip_address("198.18.0.21"),), option_rows=(unchanged,)),
                )
            sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
            self.assertEqual(sent["option-data"], raw["option-data"])
            self.assertEqual(sent["ip-address"], "198.18.0.21")
            self.assertEqual(outcome.application, "applied")

    def test_changed_assignments_keep_classes_metadata_and_live_order_beside_untouched_duplicates(self):
        for family, name, code, data in ((4, "routers", 3, "198.18.0.1"), (6, "dns-servers", 23, "2001:db8::53")):
            classed = {"name": name, "data": data, "client-classes": ["voip"]}
            duplicate = {"name": "untouched", "data": "  padded  ", "csv-format": False}
            target = {"code": code, "space": f"dhcp{family}", "data": data, "never-send": True, "csv-format": True}
            class_target = {
                "name": "custom",
                "data": "aabb",
                "client-classes": ["lab"],
                "user-context": {"owner": "external"},
                "csv-format": False,
            }
            foreign = {"name": name, "space": "vendor-lab", "data": "foreign"}
            options = [classed, duplicate, target, class_target, foreign, duplicate]
            raw = {**_raw(family), "option-data": options}
            current, state = self._shown(family, raw=raw)
            rows = [
                reservation_edit.OptionRow(
                    option.name or "",
                    option.data,
                    bool(option.always_send),
                    original_option=option,
                    client_classes=option.client_classes,
                )
                for option in current.options
            ]
            rows[2] = replace(rows[2], data="new")
            rows[3] = replace(rows[3], data="aabc")
            values = reservation_edit.SubmittedValues(
                current.addresses,
                hostname=state.initial["hostname"],
                option_rows=(*reversed(rows), reservation_edit.OptionRow("added", "last")),
            )
            with self.subTest(family=family), stub_kea(_responses(family, raw=raw)) as kea:
                reservation_edit.save_edit(
                    self.server, family, 20, _IDENTITY, state.initial["managed_fingerprint"], values
                )
            self.assertEqual(
                kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"],
                [
                    classed,
                    duplicate,
                    {**target, "data": "new"},
                    {**class_target, "data": "aabc"},
                    foreign,
                    duplicate,
                    {"name": "added", "data": "last"},
                ],
            )

    def test_name_code_and_custom_aliases_use_the_same_live_definitions_for_edit_and_verification(self):
        for family, name, code in (
            (4, "routers", 3),
            (6, "dns-servers", 23),
            (4, "unknown", None),
            (6, "unknown", None),
        ):
            shown_options = [
                {"name": name, "data": "old"},
                {"name": "custom", "space": "vendor-lab", "data": "old", "client-classes": ["one", "two"]},
            ]
            raw = {**_raw(family), "option-data": shown_options}
            current, state = self._shown(family, raw=raw)
            live_options = [
                {**({"code": code} if code is not None else {"name": name}), "space": f"dhcp{family}", "data": "old"},
                {
                    "code": 222,
                    "space": "vendor-lab",
                    "data": "old",
                    "client-classes": ["two", "one"],
                    "user-context": {"owner": "live"},
                },
            ]
            responses = _responses(family, raw={**raw, "option-data": live_options})
            responses["config-get"]["arguments"][f"Dhcp{family}"]["option-def"] = [
                {"code": 222, "name": "custom", "space": "vendor-lab", "type": "string"}
            ]
            observed = {**raw, "option-data": [{**option, "data": "new"} for option in shown_options]}
            responses["reservation-get"] = queued(_res_get({**raw, "option-data": live_options}), _res_get(observed))
            values = reservation_edit.SubmittedValues(
                current.addresses,
                hostname=state.initial["hostname"],
                option_rows=tuple(
                    reservation_edit.OptionRow(
                        option.name, "new", original_option=option, client_classes=option.client_classes
                    )
                    for option in current.options
                ),
            )
            with self.subTest(family=family), stub_kea(responses) as kea:
                outcome = reservation_edit.save_edit(
                    self.server, family, 20, _IDENTITY, state.initial["managed_fingerprint"], values
                )
            self.assertEqual(
                kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"],
                [{**option, "data": "new"} for option in live_options],
            )
            self.assertEqual(outcome.verification, "verified")
            self.assertEqual(
                kea.commands(),
                [
                    f"subnet{family}-list",
                    "config-get",
                    "reservation-get",
                    "reservation-update",
                    "config-get",
                    "config-test",
                    "config-write",
                    "reservation-get",
                ],
            )

    def test_each_changed_or_removed_snapshot_value_names_its_option(self):
        option = {
            "name": "routers",
            "data": "198.18.0.1",
            "always-send": False,
            "never-send": False,
            "csv-format": True,
        }
        raw = {**_raw(), "option-data": [option]}
        current, state = self._shown(raw=raw)
        values = reservation_edit.SubmittedValues(
            current.addresses,
            hostname=state.initial["hostname"],
            option_rows=(reservation_edit.OptionRow("routers", "198.18.0.2", original_option=current.options[0]),),
        )
        for changed in (
            None,
            {"data": "198.18.0.3"},
            {"always-send": True},
            {"never-send": True},
            {"csv-format": False},
        ):
            live = {**raw, "option-data": [] if changed is None else [{**option, **changed}]}
            with self.subTest(changed=changed), stub_kea(_responses(raw=live)) as kea:
                with self.assertRaisesRegex(ReservationConflict, "routers"):
                    reservation_edit.save_edit(
                        self.server, 4, 20, _IDENTITY, state.initial["managed_fingerprint"], values
                    )
                self.assertNotIn("reservation-update", kea.commands())
                self.assertNotIn("config-test", kea.commands())

    def test_targeted_duplicates_and_coded_renames_are_named_conflicts(self):
        for options, name in (
            ([{"name": "routers", "data": "old"}] * 2, "routers"),
            ([{"name": "routers", "code": 3, "data": "old"}], "domain-name-servers"),
        ):
            raw = {**_raw(), "option-data": options}
            current, state = self._shown(raw=raw)
            rows = tuple(
                reservation_edit.OptionRow(
                    name if index == 0 else option.name, "new" if index == 0 else option.data, original_option=option
                )
                for index, option in enumerate(current.options)
            )
            with self.subTest(options=options), stub_kea(_responses(raw=raw)) as kea:
                with self.assertRaisesRegex(ReservationConflict, "routers"):
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
                self.assertNotIn("reservation-update", kea.commands())

    def test_a_malformed_typed_option_change_keeps_its_named_conflict_at_config_write(self):
        raw = {**_raw(), "option-data": [{"name": "routers", "data": "old"}]}
        current, _state = self._shown(raw=raw)
        change = ReservationChange(options=DHCPOptionEdit(current.options, (DHCPOptionChange(None, None),)))
        with stub_kea(_responses(raw=raw)) as kea:
            with self.assertRaisesRegex(ReservationConflict, "routers.*intent"):
                config_write.edit_reservation(
                    self.server, 4, 20, _IDENTITY, reservation_fingerprint(current), lambda _current, _catalogue: change
                )
            self.assertNotIn("reservation-update", kea.commands())


_DELEGATED = ("2001:db8:500::/56", "2001:db8:600::/56")


def _widened_raw(family):
    """Return a Reservation of Subnet 20 that sets every widened key, as Kea 3.2 returns it."""
    raw = {**_raw(family), "client-classes": ["voip", "boot"], "user-context": {"asset": 42, "tags": ["a", None]}}
    if family == 4:
        raw.update({"next-server": "192.0.2.5", "server-hostname": "boot.example.org", "boot-file-name": "host.efi"})
    else:
        raw.update({"prefixes": list(_DELEGATED), "excluded-prefixes": ["2001:db8:500:ff::/64", ""]})
    return raw


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class WidenedReservationEditTests(TestCase):
    """The widened Reservation facts through the public add and edit operations, with Kea stubbed at the transport."""

    def setUp(self):
        self.server = _make_db_server()

    def _shown(self, family, raw):
        with stub_kea(_responses(family, raw=raw)):
            catalogue = subnet_catalogue.for_verification(self.server, family)
            scope = InSubnetReservationScope(catalogue.find_by_id(20).identity)
            with self.server.get_client(version=family) as client:
                reservation = client.reservation_by_identity(family, catalogue, scope, _IDENTITY)
        return reservation, reservation_edit.form_state(reservation, catalogue)

    def _save_edit(self, family, raw, values, *, live=None):
        _current, state = self._shown(family, raw)
        with stub_kea(_responses(family, raw=raw if live is None else live)) as kea:
            outcome = reservation_edit.save_edit(
                self.server, family, 20, _IDENTITY, state.initial["managed_fingerprint"], values
            )
        return outcome, kea

    def _values(self, current, **changes):
        """Return the values that the form submits unchanged for *current*, with *changes*."""
        values = reservation_edit.SubmittedValues(
            current.addresses,
            current.delegated_prefixes,
            current.hostname,
            client_classes=current.client_classes,
            next_server=current.next_server,
            server_hostname=current.server_hostname,
            boot_file_name=current.boot_file_name,
            excluded_prefixes=tuple(pair.excluded for pair in current.excluded_prefixes),
        )
        return replace(values, **changes)

    def test_add_sets_each_widened_field(self):
        cases = (
            (
                4,
                {
                    "client_classes": ("voip",),
                    "next_server": ip_address("192.0.2.5"),
                    "server_hostname": "boot.example.org",
                    "boot_file_name": "host.efi",
                },
                {
                    "client-classes": ["voip"],
                    "next-server": "192.0.2.5",
                    "server-hostname": "boot.example.org",
                    "boot-file-name": "host.efi",
                },
            ),
            (
                6,
                {
                    "client_classes": ("voip",),
                    "delegated_prefixes": tuple(IPv6Network(prefix) for prefix in _DELEGATED),
                    "excluded_prefixes": (IPv6Network("2001:db8:600:ff::/64"),),
                },
                {
                    "client-classes": ["voip"],
                    "prefixes": list(_DELEGATED),
                    "excluded-prefixes": ["", "2001:db8:600:ff::/64"],
                },
            ),
        )
        for family, submitted, expected in cases:
            values = reservation_edit.SubmittedValues((ip_address(_ADDRESS[family]),), **submitted)
            added = {**_raw(family, hostname=""), **expected}
            with self.subTest(family=family), stub_kea(_responses(family, raw=added)) as kea:
                outcome = reservation_edit.save_add(self.server, family, _CIDR[family], _IDENTITY, values)
            self.assertEqual(outcome.application, "applied")
            sent = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
            self.assertEqual({key: sent[key] for key in expected}, expected)
            self.assertNotIn("user-context", sent)

    def test_edit_sets_and_clears_each_widened_field_and_keeps_the_user_context(self):
        for family in (4, 6):
            raw = _widened_raw(family)
            current, _state = self._shown(family, raw)
            if family == 4:
                set_values = {
                    "client_classes": ("printers",),
                    "next_server": ip_address("192.0.2.9"),
                    "server_hostname": "tftp.example.org",
                    "boot_file_name": "pxe.efi",
                }
                set_sent = {
                    "client-classes": ["printers"],
                    "next-server": "192.0.2.9",
                    "server-hostname": "tftp.example.org",
                    "boot-file-name": "pxe.efi",
                }
                cleared = {"client_classes": (), "next_server": None, "server_hostname": "", "boot_file_name": ""}
            else:
                set_values = {
                    "client_classes": ("printers",),
                    "excluded_prefixes": (IPv6Network("2001:db8:600:fe::/64"),),
                }
                set_sent = {"client-classes": ["printers"], "excluded-prefixes": ["", "2001:db8:600:fe::/64"]}
                cleared = {"client_classes": (), "excluded_prefixes": ()}
            for label, changes, expected, absent in (
                ("set", set_values, set_sent, ()),
                ("clear", cleared, {}, tuple(set_sent)),
            ):
                with self.subTest(family=family, change=label):
                    outcome, kea = self._save_edit(family, raw, self._values(current, **changes))
                    self.assertEqual(outcome.application, "applied")
                    sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
                    self.assertEqual({key: sent[key] for key in expected}, expected)
                    self.assertEqual([key for key in absent if key in sent], [])
                    self.assertEqual(sent["user-context"], raw["user-context"])

    def test_an_edit_of_another_field_keeps_each_widened_key(self):
        for family in (4, 6):
            raw = _widened_raw(family)
            current, _state = self._shown(family, raw)
            with self.subTest(family=family):
                _outcome, kea = self._save_edit(family, raw, self._values(current, hostname="renamed"))
                sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
                unchanged = {key: value for key, value in raw.items() if key != "hostname"}
                self.assertEqual({key: value for key, value in sent.items() if key != "hostname"}, unchanged)

    def test_a_delegated_prefix_change_keeps_each_excluded_prefix_with_the_prefix_that_holds_it(self):
        raw = _widened_raw(6)
        current, _state = self._shown(6, raw)
        swapped = tuple(reversed(current.delegated_prefixes))
        outcome, kea = self._save_edit(6, raw, self._values(current, delegated_prefixes=swapped))
        self.assertEqual(outcome.application, "applied")
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(sent["prefixes"], ["2001:db8:600::/56", "2001:db8:500::/56"])
        self.assertEqual(sent["excluded-prefixes"], ["", "2001:db8:500:ff::/64"])
        wider = (IPv6Network("2001:db8:500::/48"), current.delegated_prefixes[1])
        _outcome, kea = self._save_edit(6, raw, self._values(current, delegated_prefixes=wider))
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(sent["excluded-prefixes"], ["2001:db8:500:ff::/64", ""])

    def test_an_excluded_prefix_without_one_delegated_prefix_that_holds_it_refuses_the_edit(self):
        raw = _widened_raw(6)
        current, _state = self._shown(6, raw)
        other = IPv6Network("2001:db8:600::/56")
        for label, changes, message in (
            (
                "its delegated prefix is removed",
                {"delegated_prefixes": (other,)},
                "2001:db8:500:ff::/64 is not inside a delegated prefix",
            ),
            (
                "two delegated prefixes hold a new one",
                {
                    "delegated_prefixes": (IPv6Network("2001:db8:500::/48"), current.delegated_prefixes[0]),
                    "excluded_prefixes": (IPv6Network("2001:db8:500:fe::/64"),),
                },
                "2001:db8:500:fe::/64 is inside more than one delegated prefix",
            ),
            (
                "one delegated prefix would exclude two",
                {"excluded_prefixes": (IPv6Network("2001:db8:500:ff::/64"), IPv6Network("2001:db8:500:fe::/64"))},
                "2001:db8:500::/56 can exclude one prefix only",
            ),
            (
                "it is the delegated prefix",
                {"excluded_prefixes": (IPv6Network("2001:db8:600::/56"),)},
                "2001:db8:600::/56 is not inside a delegated prefix",
            ),
        ):
            with self.subTest(label), stub_kea(_responses(6, raw=raw)) as kea:
                with self.assertRaises(reservation_edit.EditConflict) as raised:
                    reservation_edit.save_edit(
                        self.server,
                        6,
                        20,
                        _IDENTITY,
                        self._shown(6, raw)[1].initial["managed_fingerprint"],
                        self._values(current, **changes),
                    )
                self.assertEqual(raised.exception.field, "excluded_prefixes")
                self.assertIn(message, raised.exception.message)
                self.assertNotIn("reservation-update", kea.commands())

    def test_a_concurrent_change_to_a_widened_field_is_a_fingerprint_conflict(self):
        for family, changed in (
            (4, {"client-classes": ["voip"]}),
            (4, {"next-server": "192.0.2.6"}),
            (4, {"server-hostname": "other.example.org"}),
            (4, {"boot-file-name": "other.efi"}),
            (6, {"client-classes": []}),
            (6, {"excluded-prefixes": ["2001:db8:500:fe::/64", ""]}),
        ):
            raw = _widened_raw(family)
            current, _state = self._shown(family, raw)
            with self.subTest(family=family, changed=changed), self.assertRaises(ChangeRejected) as raised:
                self._save_edit(family, raw, self._values(current, hostname="renamed"), live={**raw, **changed})
            self.assertEqual(raised.exception.reason, "target-changed")

    def test_a_concurrent_user_context_change_is_kept_and_is_no_conflict(self):
        raw = _widened_raw(4)
        current, _state = self._shown(4, raw)
        # Kea 3.2 keeps any JSON value, also null, and returns it as stored.
        for context in (["changed", {"by": "another writer"}], None):
            live = {**raw, "user-context": context}
            with self.subTest(context=context):
                outcome, kea = self._save_edit(4, raw, self._values(current, hostname="renamed"), live=live)
                self.assertEqual(outcome.application, "applied")
                sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
                self.assertIn("user-context", sent)
                self.assertEqual(sent["user-context"], context)

    def test_option_rows_set_and_clear_the_client_classes_of_an_option(self):
        classed = {"name": "domain-name", "data": "lab.example.org", "client-classes": ["lab"]}
        raw = {**_raw(), "option-data": [classed]}
        current, _state = self._shown(4, raw)
        (option,) = current.options
        for classes, expected in ((("lab", "voip"), ["lab", "voip"]), ((), None)):
            row = reservation_edit.OptionRow(option.name, option.data, original_option=option, client_classes=classes)
            with self.subTest(classes=classes):
                _outcome, kea = self._save_edit(4, raw, self._values(current, option_rows=(row,)))
                (sent,) = kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"]
                self.assertEqual(sent.get("client-classes"), expected)
        added = reservation_edit.OptionRow("domain-name", "voip.example.org", client_classes=("voip",))
        kept = reservation_edit.OptionRow(option.name, option.data, original_option=option, client_classes=("lab",))
        _outcome, kea = self._save_edit(4, raw, self._values(current, option_rows=(kept, added)))
        self.assertEqual(
            kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"],
            [classed, {"name": "domain-name", "data": "voip.example.org", "client-classes": ["voip"]}],
        )

    def test_a_class_field_drops_empty_names_and_keeps_repeated_ones_for_the_check(self):
        self.assertEqual(reservation_edit.class_names(" voip, ,printers, voip "), ("voip", "printers", "voip"))

    def test_a_changed_class_field_refuses_a_repeated_name(self):
        raw = {**_raw(), "client-classes": ["voip"]}
        current, _state = self._shown(4, raw)
        with stub_kea(_responses(raw=raw)) as kea, self.assertRaises(reservation_edit.EditConflict) as raised:
            reservation_edit.save_edit(
                self.server,
                4,
                20,
                _IDENTITY,
                self._shown(4, raw)[1].initial["managed_fingerprint"],
                self._values(current, client_classes=reservation_edit.class_names("voip, printers, voip")),
            )
        self.assertEqual(raised.exception.field, "client_classes")
        self.assertIn("once", raised.exception.message)
        self.assertNotIn("reservation-update", kea.commands())

    def test_a_class_field_cannot_change_live_names_that_its_text_cannot_show(self):
        # A comma in a name makes the text ambiguous: an added or removed name would split or keep another one.
        option = {"name": "domain-name", "data": "lab.example.org", "client-classes": ["a,b"]}
        for live, entered in ((["a,b"], "a,b, new"), (["x,y", "x"], "x,y")):
            raw = {**_raw(), "client-classes": live, "option-data": [option]}
            current, state = self._shown(4, raw)
            row = reservation_edit.OptionRow(
                option["name"],
                option["data"],
                original_option=current.options[0],
                client_classes=reservation_edit.class_names(state.options_initial[0]["client_classes"]),
            )
            changes = (
                ("client_classes", {"client_classes": reservation_edit.class_names(entered), "option_rows": (row,)}),
                (None, {"option_rows": (replace(row, client_classes=reservation_edit.class_names("a,b, new")),)}),
            )
            for field, change in changes:
                with self.subTest(live=live, field=field), stub_kea(_responses(raw=raw)) as kea:
                    with self.assertRaises(reservation_edit.EditConflict) as raised:
                        reservation_edit.save_edit(
                            self.server,
                            4,
                            20,
                            _IDENTITY,
                            state.initial["managed_fingerprint"],
                            self._values(current, **change),
                        )
                    self.assertEqual(raised.exception.field, field)
                    self.assertIn("comma", raised.exception.message)
                    self.assertNotIn("reservation-update", kea.commands())

    def test_an_unchanged_class_field_keeps_live_names_that_the_text_cannot_show(self):
        # Kea keeps a comma in a class name, and untrimmed names of an option. "x" repeats a part of "x,y".
        option = {"name": "domain-name", "data": "lab.example.org", "client-classes": ["a,b", " c "]}
        raw = {**_raw(), "client-classes": ["x,y", "x"], "option-data": [option]}
        current, state = self._shown(4, raw)
        self.assertEqual(state.initial["client_classes"], "x,y, x")
        self.assertEqual(state.options_initial[0]["client_classes"], "a,b,  c ")
        shown_option = current.options[0]
        row = reservation_edit.OptionRow(
            shown_option.name,
            "changed.example.org",
            original_option=shown_option,
            client_classes=reservation_edit.class_names(state.options_initial[0]["client_classes"]),
        )
        values = self._values(
            current,
            client_classes=reservation_edit.class_names(state.initial["client_classes"]),
            option_rows=(row,),
        )
        _outcome, kea = self._save_edit(4, raw, values)
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(sent["client-classes"], ["x,y", "x"])
        self.assertEqual(sent["option-data"], [{**option, "data": "changed.example.org"}])

    def test_a_concurrent_change_to_the_client_classes_of_an_option_is_a_conflict(self):
        option = {"name": "domain-name", "data": "lab.example.org", "client-classes": ["lab"]}
        raw = {**_raw(), "option-data": [option]}
        current, _state = self._shown(4, raw)
        live = {**raw, "option-data": [{**option, "client-classes": ["voip"]}]}
        row = reservation_edit.OptionRow(
            "domain-name", "changed.example.org", original_option=current.options[0], client_classes=("lab",)
        )
        with self.assertRaisesRegex(ReservationConflict, "domain-name"):
            self._save_edit(4, raw, self._values(current, option_rows=(row,)), live=live)

    def test_an_edit_keeps_a_live_pair_that_two_delegated_prefixes_could_hold(self):
        # A /48 and a /56 inside it both hold the excluded prefix; Kea pairs it with the /56 by position.
        raw = {
            **_raw(6),
            "prefixes": ["2001:db8:500::/48", "2001:db8:500:100::/56"],
            "excluded-prefixes": ["", "2001:db8:500:100:ff::/80"],
        }
        current, _state = self._shown(6, raw)
        outcome, kea = self._save_edit(6, raw, self._values(current, hostname="renamed"))
        self.assertEqual(outcome.application, "applied")
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(sent["excluded-prefixes"], ["", "2001:db8:500:100:ff::/80"])

    def test_a_change_of_a_repeated_excluded_prefix_that_fits_two_delegations_is_refused(self):
        both = ["2001:db8:500:100:ff::/80", "2001:db8:500:100:ff::/80"]
        raw = {**_raw(6), "prefixes": ["2001:db8:500::/48", "2001:db8:500:100::/56"], "excluded-prefixes": both}
        current, state = self._shown(6, raw)
        # One exclusion goes, and the field cannot say which delegation keeps its own.
        values = self._values(current, excluded_prefixes=(IPv6Network(both[0]),))
        with stub_kea(_responses(6, raw=raw)) as kea, self.assertRaises(reservation_edit.EditConflict) as raised:
            reservation_edit.save_edit(self.server, 6, 20, _IDENTITY, state.initial["managed_fingerprint"], values)
        self.assertEqual(raised.exception.field, "excluded_prefixes")
        self.assertIn("Change it in Kea", raised.exception.message)
        self.assertNotIn("reservation-update", kea.commands())

    def test_a_repeated_excluded_prefix_follows_the_delegation_that_an_edit_keeps(self):
        both = ["2001:db8:500:100:ff::/80", "2001:db8:500:100:ff::/80"]
        raw = {**_raw(6), "prefixes": ["2001:db8:500::/48", "2001:db8:500:100::/56"], "excluded-prefixes": both}
        current, _state = self._shown(6, raw)
        wide, narrow = current.delegated_prefixes
        other = IPv6Network("2001:db8:900::/56")
        for label, delegated, excluded, expected in (
            ("reordered", (narrow, wide), both, both),
            ("one delegation removed with its exclusion", (narrow,), both[:1], both[:1]),
            ("an unrelated delegation added", (wide, narrow, other), both, [*both, ""]),
        ):
            values = self._values(
                current,
                delegated_prefixes=delegated,
                excluded_prefixes=tuple(IPv6Network(prefix) for prefix in excluded),
            )
            with self.subTest(label):
                _outcome, kea = self._save_edit(6, raw, values)
                sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
                self.assertEqual(sent["excluded-prefixes"], expected)

    def test_an_edit_keeps_one_excluded_prefix_that_two_delegations_exclude(self):
        # Kea 3.2 stores an exclusion for each delegation, so a /48 and a /56 inside it can exclude the same prefix.
        both = ["2001:db8:500:100:ff::/80", "2001:db8:500:100:ff::/80"]
        raw = {**_raw(6), "prefixes": ["2001:db8:500::/48", "2001:db8:500:100::/56"], "excluded-prefixes": both}
        current, state = self._shown(6, raw)
        self.assertEqual(state.initial["excluded_prefixes"], ",".join(both))
        outcome, kea = self._save_edit(6, raw, self._values(current, hostname="renamed"))
        self.assertEqual(outcome.application, "applied")
        self.assertEqual(kea.bodies("reservation-update")[0]["arguments"]["reservation"]["excluded-prefixes"], both)
