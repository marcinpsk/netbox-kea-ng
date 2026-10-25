# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Reservation import permission, claim and pool facts through real writes and ORM."""

import json
from contextlib import contextmanager
from dataclasses import replace
from ipaddress import ip_address, ip_network

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.db.models.signals import pre_save
from django.test import TestCase
from extras.models import JournalEntry
from ipam.models import IPAddress
from users.models import ObjectPermission

from netbox_kea import reservation_edit
from netbox_kea.ipam_reconciliation import RESERVATION, ClaimResult, claim_permissions
from netbox_kea.reservation_transfer import (
    ReservationImportProposal,
    export_reservation_document,
    parse_reservation_document,
)
from netbox_kea.reservations import (
    ExcludedPrefix,
    InSubnetReservationScope,
    IPv4Reservation,
    IPv6Reservation,
    ReservationIdentity,
)
from netbox_kea.signals import reservation_created
from netbox_kea.subnet_catalogue import SubnetIdentity

from .kea_stub import _catalogue_responses_for_subnets, _res_get, stub_kea
from .utils import _make_db_server, with_kea_client_config

_CIDR = {4: "198.18.0.0/24", 6: "2001:db8::/64"}


def _proposal(family=4, number=20, *, addresses=None, hostname="host"):
    return ReservationImportProposal(
        family,
        _CIDR[family],
        ReservationIdentity("hw-address", f"02:00:00:00:00:{number:02x}"),
        tuple(ip_address(address) for address in addresses)
        if addresses is not None
        else (ip_address(f"198.18.0.{number}" if family == 4 else f"2001:db8::{number}"),),
        (),
        hostname,
        (),
    )


@contextmanager
def _import_kea(family=4, *, pools=(), unknown=False, missing_configuration=False, subnets=None):
    stored = {}

    def add(body):
        raw = body["arguments"]["reservation"]
        stored[raw["hw-address"]] = raw
        return {"result": 1, "text": "not confirmed"} if unknown else {"result": 0}

    responses = {
        **_catalogue_responses_for_subnets(
            family,
            subnets
            or [
                {
                    "id": 20,
                    "subnet": _CIDR[family],
                    "pools": list(pools),
                    "ddns-qualifying-suffix": "lab.example.invalid",
                }
            ],
        ),
        "reservation-add": add,
        "reservation-get": lambda body: _res_get(stored[body["arguments"]["identifier"]]),
        "config-test": {"result": 0},
        "config-write": {"result": 0},
    }
    if missing_configuration:
        responses["config-get"] = {"result": 1, "text": "configuration unavailable"}
    with stub_kea(responses) as kea:
        yield kea


def _grant_claim(user):
    for name in claim_permissions(RESERVATION):
        app, permission = name.split(".")
        action, model = permission.split("_", 1)
        grant = ObjectPermission.objects.create(name=name, actions=[action])
        grant.object_types.add(ContentType.objects.get(app_label=app, model=model))
        grant.users.add(user)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ReservationImportTests(TestCase):
    def setUp(self):
        self.server = _make_db_server()
        self.user = get_user_model().objects.create_user(username="reservation-import")

    def test_permission_preflight_is_read_once_and_reused_for_every_claim(self):
        _grant_claim(self.user)
        permission_reads = []

        def record(execute, sql, params, many, context):
            if 'FROM "users_objectpermission"' in sql:
                permission_reads.append(sql)
            return execute(sql, params, many, context)

        with connection.execute_wrapper(record):
            context = reservation_edit.prepare_import(self.server, self.user, sync_to_netbox=True)
            with _import_kea() as kea:
                for number in (20, 21):
                    outcome = reservation_edit.save_import(self.server, _proposal(number=number))
                    facts = reservation_edit.after_apply(self.server, outcome, self.user, import_context=context)
                    self.assertIsInstance(facts.claim, ClaimResult)
                    self.assertTrue(facts.claim.addresses[f"198.18.0.{number}"].synchronized)
        self.assertEqual(len(permission_reads), 1)
        self.assertEqual(kea.commands().count("reservation-add"), 2)
        self.assertEqual(IPAddress.objects.count(), 2)

    def test_missing_permissions_refuse_the_import_before_any_kea_call(self):
        with stub_kea({}) as kea, self.assertRaises(reservation_edit.ImportSyncRefused) as raised:
            reservation_edit.prepare_import(self.server, self.user, sync_to_netbox=True)
        self.assertIn("Manual Sync needs unconstrained", raised.exception.message)
        self.assertEqual(kea.commands(), [])
        self.assertFalse(JournalEntry.objects.exists())

    def test_opt_out_reads_no_permissions_and_attempts_no_claim(self):
        attempts = []
        reads = []

        def trap(sender, instance, **kwargs):
            attempts.append(instance)
            raise AssertionError("Opt-out must not save an IP address.")

        def record(execute, sql, params, many, context):
            if 'FROM "users_objectpermission"' in sql:
                reads.append(sql)
            return execute(sql, params, many, context)

        pre_save.connect(trap, sender=IPAddress)
        try:
            with connection.execute_wrapper(record):
                context = reservation_edit.prepare_import(self.server, self.user)
                with _import_kea():
                    outcome = reservation_edit.save_import(self.server, _proposal())
                facts = reservation_edit.after_apply(self.server, outcome, self.user, import_context=context)
        finally:
            pre_save.disconnect(trap, sender=IPAddress)
        self.assertEqual(facts.claim, reservation_edit.ClaimSkipped("not-requested"))
        self.assertEqual((reads, attempts), ([], []))
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "succeeded"))

    def test_a_checked_context_cannot_authorize_another_user_or_server(self):
        user = get_user_model().objects.create_superuser(username="import-owner")
        context = reservation_edit.prepare_import(self.server, user, sync_to_netbox=True)
        other = _make_db_server(name="other-server")
        with _import_kea():
            outcome = reservation_edit.save_import(self.server, _proposal())
        for server, actor in ((other, user), (self.server, self.user)):
            with self.subTest(server=server.pk, user=actor.pk), self.assertNumQueries(0), self.assertRaises(ValueError):
                reservation_edit.after_apply(server, outcome, actor, import_context=context)
        self.assertFalse(JournalEntry.objects.exists())
        self.assertFalse(IPAddress.objects.exists())

    def test_addressless_and_ipv6_multiaddress_entries_keep_typed_claim_results(self):
        user = get_user_model().objects.create_superuser(username="import-ipv6")
        context = reservation_edit.prepare_import(self.server, user, sync_to_netbox=True)
        with _import_kea(6):
            addressless = reservation_edit.save_import(self.server, _proposal(6, addresses=()))
            multiple = reservation_edit.save_import(
                self.server, _proposal(6, number=21, addresses=("2001:db8::20", "2001:db8::21"))
            )
        empty = reservation_edit.after_apply(self.server, addressless, user, import_context=context)
        self.assertEqual(empty.claim, reservation_edit.ClaimSkipped("nothing-to-sync"))
        facts = reservation_edit.after_apply(self.server, multiple, user, import_context=context)
        self.assertEqual(set(facts.claim.addresses), {"2001:db8::20", "2001:db8::21"})
        self.assertTrue(all(row.synchronized for row in facts.claim.addresses.values()))

    def test_a_partial_claim_keeps_each_address_result_and_does_not_block_a_later_entry(self):
        user = get_user_model().objects.create_superuser(username="import-partial")
        context = reservation_edit.prepare_import(self.server, user, sync_to_netbox=True)
        IPAddress.objects.bulk_create([IPAddress(address="2001:db8::20/64"), IPAddress(address="2001:db8::20/64")])
        with _import_kea(6):
            first = reservation_edit.save_import(self.server, _proposal(6, addresses=("2001:db8::20", "2001:db8::21")))
            partial = reservation_edit.after_apply(self.server, first, user, import_context=context)
            later = reservation_edit.save_import(self.server, _proposal(6, number=22))
            continued = reservation_edit.after_apply(self.server, later, user, import_context=context)
        self.assertIsInstance(partial.claim, ClaimResult)
        self.assertEqual(partial.claim.addresses["2001:db8::20"].outcome, "error")
        self.assertTrue(partial.claim.addresses["2001:db8::21"].synchronized)
        self.assertTrue(continued.claim.addresses["2001:db8::22"].synchronized)

    def test_unknown_application_runs_no_side_effects_even_with_checked_context(self):
        user = get_user_model().objects.create_superuser(username="import-unknown")
        context = reservation_edit.prepare_import(self.server, user, sync_to_netbox=True)
        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        with _import_kea(unknown=True):
            outcome = reservation_edit.save_import(self.server, _proposal())
        reservation_created.connect(receiver)
        try:
            with self.assertNumQueries(0):
                facts = reservation_edit.after_apply(self.server, outcome, user, import_context=context)
        finally:
            reservation_created.disconnect(receiver)
        self.assertEqual(facts.claim, reservation_edit.ClaimSkipped("not-applied"))
        self.assertEqual(received, [])
        self.assertFalse(JournalEntry.objects.exists())

    def test_pool_summary_counts_an_identity_once_for_multiple_addresses_and_pools(self):
        pools = [{"pool": "2001:db8::10-2001:db8::20"}, {"pool": "2001:db8::21-2001:db8::30"}]
        with _import_kea(6, pools=pools):
            first = reservation_edit.save_import(self.server, _proposal(6, addresses=("2001:db8::20", "2001:db8::21")))
            second = reservation_edit.save_import(self.server, _proposal(6, number=22))
            outside = reservation_edit.save_import(self.server, _proposal(6, number=40))
        self.assertEqual(len(first.warnings), 2)
        summary = reservation_edit.pool_overlap_summary((first, first, second, outside), limit=1)
        self.assertEqual(summary.identities, (first.intended.identity,))
        self.assertEqual(summary.remaining, 1)

    def test_pool_summary_counts_the_same_identity_in_two_subnets_as_two_entries(self):
        subnets = [
            {"id": 20, "subnet": "198.18.0.0/24", "pools": [{"pool": "198.18.0.10-198.18.0.30"}]},
            {"id": 21, "subnet": "198.18.1.0/24", "pools": [{"pool": "198.18.1.10-198.18.1.30"}]},
        ]
        with _import_kea(subnets=subnets):
            first = reservation_edit.save_import(self.server, _proposal())
            second = reservation_edit.save_import(
                self.server, replace(_proposal(), subnet_cidr="198.18.1.0/24", addresses=(ip_address("198.18.1.20"),))
            )
        summary = reservation_edit.pool_overlap_summary((first, second), limit=1)
        self.assertEqual(summary.identities, (first.intended.identity,))
        self.assertEqual(summary.remaining, 1)

    def test_unknown_add_retains_pool_facts_and_an_unavailable_check_is_explicit(self):
        with _import_kea(pools=[{"pool": "198.18.0.10-198.18.0.30"}], unknown=True):
            unknown = reservation_edit.save_import(self.server, _proposal())
        self.assertEqual(unknown.application, "unknown")
        self.assertTrue(unknown.warnings)
        self.assertEqual(reservation_edit.pool_overlap_summary((unknown,)).identities, ())
        with _import_kea(missing_configuration=True):
            unavailable = reservation_edit.save_import(self.server, _proposal())
        self.assertEqual(unavailable.warnings, (reservation_edit.PoolCheckUnavailable(_CIDR[4]),))

    def test_transfer_round_trip_writes_the_exact_stored_hostname_in_both_families(self):
        for family, record_type in ((4, IPv4Reservation), (6, IPv6Reservation)):
            record = record_type(
                scope=InSubnetReservationScope(SubnetIdentity(20, ip_network(_CIDR[family]))),
                identity=_proposal(family).identity,
                addresses=_proposal(family).addresses,
                **({"delegated_prefixes": ()} if family == 6 else {}),
            )
            for syntax in ("json", "yaml"):
                for hostname in ("Host", "Mixed.Lab.Example.Invalid", "Absolute.example.invalid.", "  Padded  ", ""):
                    with self.subTest(family=family, syntax=syntax, hostname=hostname):
                        document = export_reservation_document((replace(record, hostname=hostname),), syntax)
                        parsed = parse_reservation_document(document, syntax)
                        self.assertEqual(parsed.diagnostics, ())
                        self.assertEqual(parsed.proposals[0].hostname, hostname)
                        with _import_kea(family) as kea:
                            outcome = reservation_edit.save_import(self.server, parsed.proposals[0])
                        self.assertEqual(outcome.intended.hostname, hostname)
                        sent = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
                        self.assertEqual(sent.get("hostname", ""), hostname)

    def test_a_document_creates_each_widened_fact_but_not_its_user_context(self):
        delegated = (ip_network("2001:db8:500::/56"), ip_network("2001:db8:600::/56"))
        records = {
            4: IPv4Reservation(
                scope=InSubnetReservationScope(SubnetIdentity(20, ip_network(_CIDR[4]))),
                identity=ReservationIdentity("hw-address", "02:00:00:00:00:20"),
                addresses=(ip_address("198.18.0.20"),),
                client_classes=("voip",),
                next_server=ip_address("192.0.2.5"),
                server_hostname="boot.example.org",
                boot_file_name="host.efi",
                user_context={"asset": 42},
            ),
            6: IPv6Reservation(
                scope=InSubnetReservationScope(SubnetIdentity(20, ip_network(_CIDR[6]))),
                identity=ReservationIdentity("hw-address", "02:00:00:00:00:21"),
                addresses=(),
                delegated_prefixes=delegated,
                client_classes=("voip",),
                excluded_prefixes=(ExcludedPrefix(delegated[0], ip_network("2001:db8:500:ff::/64")),),
                user_context=["opaque"],
            ),
        }
        expected = {
            4: {
                "client-classes": ["voip"],
                "next-server": "192.0.2.5",
                "server-hostname": "boot.example.org",
                "boot-file-name": "host.efi",
                "user-context": None,
            },
            6: {
                "client-classes": ["voip"],
                "prefixes": ["2001:db8:500::/56", "2001:db8:600::/56"],
                "excluded-prefixes": ["2001:db8:500:ff::/64", ""],
                "user-context": None,
            },
        }
        for family, record in records.items():
            (proposal,) = parse_reservation_document(export_reservation_document((record,), "yaml"), "yaml").proposals
            with self.subTest(family=family), _import_kea(family) as kea:
                outcome = reservation_edit.save_import(self.server, proposal)
            self.assertEqual((outcome.application, outcome.verification), ("applied", "verified"))
            sent = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
            self.assertEqual({key: sent.get(key) for key in expected[family]}, expected[family])

    def test_null_boot_texts_parse_and_import_for_each_family(self):
        for family in (4, 6):
            for format_name in ("yaml", "json"):
                with self.subTest(family=family, format=format_name):
                    reservation = (
                        IPv4Reservation(
                            scope=InSubnetReservationScope(SubnetIdentity(20, ip_network(_CIDR[family]))),
                            identity=ReservationIdentity("hw-address", "02:00:00:00:00:20"),
                            addresses=(),
                        )
                        if family == 4
                        else IPv6Reservation(
                            scope=InSubnetReservationScope(SubnetIdentity(20, ip_network(_CIDR[family]))),
                            identity=ReservationIdentity("hw-address", "02:00:00:00:00:20"),
                            addresses=(),
                            delegated_prefixes=(),
                        )
                    )
                    document = json.loads(export_reservation_document((reservation,), "json"))
                    document["reservations"][0].update(server_hostname=None, boot_file_name=None)
                    parsed = parse_reservation_document(json.dumps(document), format_name)
                    self.assertEqual(parsed.diagnostics, ())
                    with _import_kea(family) as kea:
                        outcome = reservation_edit.save_import(self.server, parsed.proposals[0])
                        self.assertEqual((outcome.application, outcome.verification), ("applied", "verified"))
                        sent = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
                        self.assertNotIn("server-hostname", sent)
                        self.assertNotIn("boot-file-name", sent)
