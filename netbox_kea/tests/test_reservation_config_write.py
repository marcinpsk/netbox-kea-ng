# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Reservation writes as Configuration Changes of ``config_write`` (ADR 0012), through a real Server and ``KeaClient``.

Only ``requests.Session.post`` is stubbed. Each test asserts the commands that reached Kea.
"""

from dataclasses import replace
from ipaddress import IPv4Address, ip_address, ip_network

import requests
from django.test import TestCase

from netbox_kea import config_write
from netbox_kea.change_outcome import ChangeRejected
from netbox_kea.config_write import SUBNET_LIST_UNCONFIRMED
from netbox_kea.dhcp_options import DHCPOption, DHCPOptionChange, DHCPOptionEdit
from netbox_kea.reservations import (
    ClearValue,
    InSubnetReservationScope,
    IPv4Reservation,
    ReservationChange,
    ReservationConflict,
    ReservationIdentity,
    SetValue,
    reservation_fingerprint,
)
from netbox_kea.subnet_catalogue import CatalogueSnapshot, SubnetIdentity, VerifiedSubnet

from .kea_stub import _catalogue_responses_for_subnets, _res_get, queued, stub_kea
from .utils import _make_db_server, with_kea_client_config

_OK = {"result": 0, "text": "ok"}
_SCOPE = ["subnet4-list", "config-get"]
_PERSIST = ["config-get", "config-test", "config-write"]
_CIDR = "198.18.0.0/24"
_IDENTITY = ReservationIdentity("hw-address", "aa:bb:cc:dd:ee:ff")
_LOST = "Kea's reply to the change was lost or unreadable."
_OPTION = {
    "code": 6,
    "name": "domain-name-servers",
    "space": "dhcp4",
    "data": "198.18.0.53",
    "csv-format": True,
    "always-send": False,
    "never-send": False,
}
_RAW = {
    "subnet-id": 20,
    "hw-address": "aa:bb:cc:dd:ee:ff",
    "ip-address": "198.18.0.20",
    "hostname": "old.example.invalid",
    "option-data": [_OPTION],
}


def _responses(**overrides) -> dict:
    """Answer the scope read of Subnet 20, the persist step, and *overrides*."""
    responses = {
        **_catalogue_responses_for_subnets(4, [{"id": 20, "subnet": _CIDR}]),
        "config-test": _OK,
        "config-write": _OK,
    }
    responses.update(overrides)
    return responses


def _reservation(subnet: VerifiedSubnet, **changes) -> IPv4Reservation:
    reservation = IPv4Reservation(
        scope=InSubnetReservationScope(subnet.identity),
        identity=_IDENTITY,
        addresses=(IPv4Address("198.18.0.20"),),
        hostname="old.example.invalid",
        options=(
            DHCPOption(
                code=6,
                name="domain-name-servers",
                space="dhcp4",
                data="198.18.0.53",
                csv_format=True,
                always_send=False,
                never_send=False,
            ),
        ),
    )
    return replace(reservation, **changes)


def _build(subnet: VerifiedSubnet, _catalogue: CatalogueSnapshot) -> IPv4Reservation:
    return _reservation(subnet)


def _shown() -> IPv4Reservation:
    """The Reservation of _RAW as the edit form showed it."""
    return _reservation(_verified())


def _verified() -> VerifiedSubnet:
    return VerifiedSubnet(
        identity=SubnetIdentity(subnet_id=20, network=ip_network(_CIDR)),
        declared_cidr=_CIDR,
        configuration=None,
        shared_network=None,
        membership_known=True,
        qualifying_suffix=None,
        reservation_flags=None,
    )


def _by_name(subnet: VerifiedSubnet, _catalogue: CatalogueSnapshot) -> IPv4Reservation:
    """The Reservation an operator submits: an Option named, with no resolved metadata."""
    option = DHCPOption(
        code=None,
        name="domain-name-servers",
        space=None,
        data="198.18.0.53",
        csv_format=None,
        always_send=None,
        never_send=None,
    )
    return _reservation(subnet, options=(option,))


class _BuilderError(Exception):
    """An error of the caller's builder, which the operation must not translate."""


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ReservationAddTests(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def _add(self, build=_build):
        return config_write.add_reservation(self.server, 4, _CIDR, build)

    def test_an_add_sends_the_managed_facts_persists_and_verifies(self):
        seen = []

        def build(subnet, catalogue):
            seen.append((subnet, catalogue))
            return _reservation(subnet)

        with stub_kea(_responses(**{"reservation-add": _OK, "reservation-get": _res_get(_RAW)})) as kea:
            outcome = self._add(build)
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-add", *_PERSIST, "reservation-get"])
        self.assertEqual(kea.bodies("reservation-add")[0]["arguments"], {"reservation": _RAW})
        ((subnet, catalogue),) = seen
        self.assertEqual((subnet.subnet_id, subnet.cidr), (20, _CIDR))
        self.assertIs(outcome.catalogue, catalogue)
        self.assertEqual(
            (outcome.application, outcome.persistence, outcome.verification, outcome.diagnostics),
            ("applied", "persisted", "verified", ()),
        )
        self.assertIsNone(outcome.previous)
        self.assertEqual(outcome.intended, _reservation(subnet))

    def test_a_subnet_that_the_scope_read_does_not_hold_changed_nothing(self):
        with stub_kea(_responses()) as kea, self.assertRaises(ChangeRejected) as raised:
            config_write.add_reservation(self.server, 4, "198.18.1.0/24", _build)
        self.assertEqual(raised.exception.reason, "target-changed")
        self.assertEqual(
            raised.exception.diagnostics,
            ("Subnet 198.18.1.0/24 is not in the Subnet list of Kea. Reload the page and try again.",),
        )
        self.assertEqual(kea.commands(), _SCOPE)

    def test_a_scope_read_that_cannot_confirm_the_subnet_list_is_not_sent(self):
        responses = _responses(**{"subnet4-list": requests.ConnectionError("down")})
        responses["config-get"] = {"result": 1, "text": "busy"}
        with stub_kea(responses) as kea, self.assertRaises(ChangeRejected) as raised:
            config_write.add_reservation(self.server, 4, "198.18.1.0/24", _build)
        self.assertEqual(raised.exception.reason, "not-sent")
        self.assertEqual(raised.exception.diagnostics, (SUBNET_LIST_UNCONFIRMED,))
        self.assertNotIn("reservation-add", kea.commands())

    def test_an_error_of_the_builder_propagates_unchanged_and_sends_nothing(self):
        def build(_subnet, _catalogue):
            raise _BuilderError("hostname suffix unknown")

        with stub_kea(_responses()) as kea, self.assertRaises(_BuilderError):
            self._add(build)
        self.assertEqual(kea.commands(), _SCOPE)

    def test_result_2_is_a_rejection_without_a_persist_step(self):
        reply = {"result": 2, "text": "'reservation-add' command not supported."}
        with stub_kea(_responses(**{"reservation-add": reply})) as kea, self.assertRaises(ChangeRejected) as raised:
            self._add()
        self.assertEqual(raised.exception.reason, "kea-rejected")
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-add"])

    def test_result_1_is_unknown_with_keas_text_persisted_and_not_verified(self):
        reply = {"result": 1, "text": "Host already exists."}
        with stub_kea(_responses(**{"reservation-add": reply})) as kea:
            outcome = self._add()
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-add", *_PERSIST])
        self.assertEqual(
            (outcome.application, outcome.persistence, outcome.verification, outcome.diagnostics),
            ("unknown", "persisted", "not-run", ("Kea replied: Host already exists.",)),
        )

    def test_a_lost_or_malformed_reply_is_unknown_and_still_persisted(self):
        for name, reply in (
            ("read timeout", requests.ReadTimeout("read timed out")),
            ("empty reply", []),
            ("two entries", [_OK, _OK]),
        ):
            with self.subTest(name), stub_kea(_responses(**{"reservation-add": reply})) as kea:
                outcome = self._add()
            self.assertEqual(kea.commands(), [*_SCOPE, "reservation-add", *_PERSIST])
            self.assertEqual(
                (outcome.application, outcome.verification, outcome.diagnostics), ("unknown", "not-run", (_LOST,))
            )

    def test_verification_accepts_the_option_metadata_that_kea_resolves(self):
        with stub_kea(_responses(**{"reservation-add": _OK, "reservation-get": _res_get(_RAW)})):
            outcome = self._add(_by_name)
        self.assertEqual(outcome.verification, "verified")

    def test_verification_fails_when_kea_stored_another_value_or_nothing(self):
        other = {**_RAW, "option-data": [{**_OPTION, "data": "198.18.0.54"}]}
        for name, reply in (("other value", _res_get(other)), ("absent", {"result": 3})):
            with self.subTest(name), stub_kea(_responses(**{"reservation-add": _OK, "reservation-get": reply})):
                outcome = self._add(_by_name)
            self.assertEqual((outcome.application, outcome.verification), ("applied", "failed"))

    def test_a_failed_persist_step_keeps_the_applied_state(self):
        for name, failure, diagnostic in (
            (
                "config-write",
                {"config-write": {"result": 1, "text": "write failed"}},
                "config-write failed: write failed",
            ),
            (
                "config-test",
                {"config-test": {"result": 1, "text": "invalid pool"}},
                "config-test rejected the running configuration: invalid pool",
            ),
        ):
            responses = _responses(**{"reservation-add": _OK, "reservation-get": _res_get(_RAW), **failure})
            with self.subTest(name), stub_kea(responses):
                outcome = self._add()
            self.assertEqual(
                (outcome.application, outcome.persistence, outcome.verification, outcome.diagnostics),
                ("applied", "failed", "verified", (diagnostic,)),
            )

    def test_without_persistence_no_persist_step_is_sent(self):
        self.server.persist_config = False
        with stub_kea(_responses(**{"reservation-add": _OK, "reservation-get": _res_get(_RAW)})) as kea:
            outcome = self._add()
        self.assertEqual(outcome.persistence, "not-requested")
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-add", "reservation-get"])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ReservationEditTests(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def _edit(self, change, *, shown=None, build=None):
        shown = shown or _shown()
        return config_write.edit_reservation(
            self.server,
            4,
            20,
            _IDENTITY,
            reservation_fingerprint(shown),
            build or (lambda _current, _catalogue: change),
        )

    def test_an_update_keeps_unknown_fields_and_applies_each_clear_and_set(self):
        # Since #102 user-context is the only host key that NetBox does not manage.
        current = {**_RAW, "user-context": {"owner": "external-system"}}
        intended = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.21",
            "user-context": {"owner": "external-system"},
        }
        change = ReservationChange(
            addresses=SetValue((ip_address("198.18.0.21"),)),
            hostname=ClearValue(),
            options=DHCPOptionEdit(
                _shown().options, tuple(DHCPOptionChange(option, None) for option in _shown().options)
            ),
        )
        seen = []

        def build(live, catalogue):
            seen.append(live)
            return change

        responses = _responses(
            **{"reservation-get": queued(_res_get(current), _res_get(intended)), "reservation-update": _OK}
        )
        with stub_kea(responses) as kea:
            outcome = self._edit(change, build=build)
        self.assertEqual(
            kea.commands(), [*_SCOPE, "reservation-get", "reservation-update", *_PERSIST, "reservation-get"]
        )
        self.assertEqual(kea.bodies("reservation-update")[0]["arguments"], {"reservation": intended})
        self.assertEqual(seen, [_shown()])
        self.assertEqual(outcome.previous, _shown())
        self.assertEqual(outcome.intended.addresses, (ip_address("198.18.0.21"),))
        self.assertEqual((outcome.application, outcome.verification), ("applied", "verified"))

    def test_a_name_only_option_change_keeps_the_unknown_option_fields(self):
        current = {**_RAW, "option-data": [{**_OPTION, "user-context": {"owner": "external-system"}}]}
        change = ReservationChange(options=DHCPOptionEdit(_shown().options, ()))
        responses = _responses(**{"reservation-get": _res_get(current), "reservation-update": _OK})
        with stub_kea(responses) as kea:
            outcome = self._edit(change)
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]["option-data"][0]
        self.assertEqual(sent["user-context"], {"owner": "external-system"})
        self.assertEqual(outcome.verification, "verified")

    def test_default_space_aliases_cannot_target_one_duplicate(self):
        """Kea may omit `space`, and a space-less Option must not absorb another space's intent."""
        space_less = {key: value for key, value in _OPTION.items() if key != "space"}
        space_less["user-context"] = {"owner": "space-less"}
        in_space = {**space_less, "space": "dhcp4", "user-context": {"owner": "dhcp4"}}
        current = {**_RAW, "option-data": [space_less, in_space]}
        options = (
            DHCPOption(6, "domain-name-servers", None, "198.18.0.53", True, False, False),
            DHCPOption(6, "domain-name-servers", "dhcp4", "198.18.0.53", True, False, False),
        )
        shown = _reservation(_verified(), options=options)
        responses = _responses(**{"reservation-get": _res_get(current), "reservation-update": _OK})
        with stub_kea(responses) as kea, self.assertRaisesRegex(ReservationConflict, "domain-name-servers"):
            self._edit(
                ReservationChange(options=DHCPOptionEdit(options, (DHCPOptionChange(options[0], None),))), shown=shown
            )
        self.assertNotIn("reservation-update", kea.commands())

    def test_a_changed_fingerprint_changed_nothing_and_sends_no_update(self):
        changed = {**_RAW, "hostname": "changed.example.invalid"}
        built = []
        responses = _responses(**{"reservation-get": _res_get(changed), "reservation-update": _OK})
        with stub_kea(responses) as kea, self.assertRaises(ChangeRejected) as raised:
            self._edit(None, build=lambda live, _catalogue: built.append(live))
        self.assertEqual(raised.exception.reason, "target-changed")
        self.assertEqual(
            raised.exception.diagnostics, ("It changed after the edit form was opened. Reload the form and try again.",)
        )
        self.assertEqual(built, [])
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get"])

    def test_a_reservation_that_is_gone_changed_nothing(self):
        with (
            stub_kea(_responses(**{"reservation-get": {"result": 3}})) as kea,
            self.assertRaises(ChangeRejected) as raised,
        ):
            self._edit(ReservationChange(hostname=SetValue("new.example.invalid")))
        self.assertEqual(raised.exception.reason, "target-changed")
        self.assertEqual(raised.exception.diagnostics, ("Kea no longer holds it.", "The edit did not create it again."))
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get"])

    def test_a_subnet_that_is_gone_changed_nothing(self):
        responses = _responses(**_catalogue_responses_for_subnets(4, [{"id": 21, "subnet": "198.18.1.0/24"}]))
        with stub_kea(responses) as kea, self.assertRaises(ChangeRejected) as raised:
            self._edit(ReservationChange())
        self.assertEqual(raised.exception.reason, "target-changed")
        self.assertEqual(kea.commands(), _SCOPE)

    def test_a_failed_read_before_the_change_is_not_sent(self):
        for name, reply in (("transport", requests.ConnectionError("reset")), ("failure", {"result": 1, "text": "x"})):
            with self.subTest(name), stub_kea(_responses(**{"reservation-get": reply})) as kea:
                with self.assertRaises(ChangeRejected) as raised:
                    self._edit(ReservationChange())
            self.assertEqual(raised.exception.reason, "not-sent")
            self.assertNotIn("reservation-update", kea.commands())

    def test_a_record_whose_options_cannot_be_read_is_not_sent(self):
        current = {**_RAW, "option-data": "not a list"}
        shown = _reservation(_verified(), options=())
        with stub_kea(_responses(**{"reservation-get": _res_get(current)})):
            with self.assertRaises(ChangeRejected) as raised:
                self._edit(ReservationChange(hostname=SetValue("new.example.invalid")), shown=shown)
        self.assertEqual(raised.exception.reason, "not-sent")

    def test_an_error_of_the_builder_propagates_unchanged_and_sends_no_update(self):
        def build(_live, _catalogue):
            raise _BuilderError("ambiguous option")

        with stub_kea(_responses(**{"reservation-get": _res_get(_RAW)})) as kea, self.assertRaises(_BuilderError):
            self._edit(None, build=build)
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get"])

    def test_result_1_is_unknown_with_keas_text_and_still_persisted(self):
        responses = _responses(
            **{"reservation-get": _res_get(_RAW), "reservation-update": {"result": 1, "text": "db error"}}
        )
        with stub_kea(responses) as kea:
            outcome = self._edit(ReservationChange(hostname=SetValue("new.example.invalid")))
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get", "reservation-update", *_PERSIST])
        self.assertEqual(
            (outcome.application, outcome.verification, outcome.diagnostics),
            ("unknown", "not-run", ("Kea replied: db error",)),
        )

    def test_result_2_is_a_rejection_without_a_persist_step(self):
        reply = {"result": 2, "text": "'reservation-update' command not supported."}
        responses = _responses(**{"reservation-get": _res_get(_RAW), "reservation-update": reply})
        with stub_kea(responses) as kea, self.assertRaises(ChangeRejected) as raised:
            self._edit(ReservationChange(hostname=SetValue("new.example.invalid")))
        self.assertEqual(raised.exception.reason, "kea-rejected")
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get", "reservation-update"])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ReservationDeleteTests(TestCase):
    def setUp(self):
        self.server = _make_db_server()

    def _delete(self):
        return config_write.delete_reservation(self.server, 4, 20, _IDENTITY)

    def test_a_delete_sends_the_identity_and_verifies_the_absence(self):
        for name, absent in (("result 3", {"result": 3}), ("result 0", {"result": 0, "text": "Host not found."})):
            responses = _responses(**{"reservation-get": queued(_res_get(_RAW), absent), "reservation-del": _OK})
            with self.subTest(name), stub_kea(responses) as kea:
                outcome = self._delete()
            self.assertEqual(
                kea.commands(), [*_SCOPE, "reservation-get", "reservation-del", *_PERSIST, "reservation-get"]
            )
            self.assertEqual(
                kea.bodies("reservation-del")[0]["arguments"],
                {"subnet-id": 20, "identifier-type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff"},
            )
            self.assertEqual(outcome.previous, _shown())
            self.assertIsNone(outcome.intended)
            self.assertEqual((outcome.application, outcome.verification), ("applied", "verified"))

    def test_result_3_changed_nothing_and_runs_no_persist_step(self):
        responses = _responses(**{"reservation-get": _res_get(_RAW), "reservation-del": {"result": 3, "text": "gone"}})
        with stub_kea(responses) as kea, self.assertRaises(ChangeRejected) as raised:
            self._delete()
        self.assertEqual(raised.exception.reason, "target-changed")
        self.assertEqual(raised.exception.diagnostics, ("Kea reports that no host data source holds it.",))
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get", "reservation-del"])

    def test_a_reservation_that_is_gone_before_the_send_changed_nothing(self):
        with (
            stub_kea(_responses(**{"reservation-get": {"result": 3}})) as kea,
            self.assertRaises(ChangeRejected) as raised,
        ):
            self._delete()
        self.assertEqual(raised.exception.reason, "target-changed")
        self.assertEqual(raised.exception.diagnostics, ("Kea no longer holds it.",))
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get"])

    def test_result_1_is_unknown_with_keas_text_and_still_persisted(self):
        responses = _responses(
            **{"reservation-get": _res_get(_RAW), "reservation-del": {"result": 1, "text": "db error"}}
        )
        with stub_kea(responses) as kea:
            outcome = self._delete()
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get", "reservation-del", *_PERSIST])
        self.assertEqual(
            (outcome.application, outcome.verification, outcome.diagnostics),
            ("unknown", "not-run", ("Kea replied: db error",)),
        )

    def test_result_2_is_a_rejection_without_a_persist_step(self):
        reply = {"result": 2, "text": "'reservation-del' command not supported."}
        responses = _responses(**{"reservation-get": _res_get(_RAW), "reservation-del": reply})
        with stub_kea(responses) as kea, self.assertRaises(ChangeRejected) as raised:
            self._delete()
        self.assertEqual(raised.exception.reason, "kea-rejected")
        self.assertEqual(kea.commands(), [*_SCOPE, "reservation-get", "reservation-del"])

    def test_a_persist_step_whose_configuration_read_fails_writes_nothing(self):
        responses = _responses(**{"reservation-get": queued(_res_get(_RAW), {"result": 3}), "reservation-del": _OK})
        responses["config-get"] = queued(responses["config-get"], {"result": 1, "text": "config-get failed"})
        with stub_kea(responses) as kea:
            outcome = self._delete()
        self.assertEqual((outcome.application, outcome.persistence), ("applied", "failed"))
        self.assertIn("running configuration", outcome.diagnostics[0])
        self.assertNotIn("config-write", kea.commands())
