# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""After-apply facts through real Reservation writes, journal rows, signals and IPAM claims."""

import uuid
from contextlib import contextmanager
from ipaddress import ip_address

from dcim.models import Site
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import OperationalError, connection
from django.db.models.signals import post_save, pre_save
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings
from extras.models import JournalEntry
from ipam.models import IPAddress
from netbox.context_managers import event_tracking

from netbox_kea import config_write, event_scope, reservation_edit
from netbox_kea.event_scope import _NESTED_TRACKING
from netbox_kea.ipam_reconciliation import ClaimResult
from netbox_kea.reservation_transfer import ReservationImportProposal
from netbox_kea.reservations import ReservationChange, ReservationIdentity, SetValue, reservation_fingerprint
from netbox_kea.signals import reservation_created, reservation_deleted, reservation_updated

from .kea_stub import _catalogue_responses_for_subnets, _res_get, queued, stub_kea
from .utils import _make_db_server, with_kea_client_config

_CIDR = {4: "198.18.0.0/24", 6: "2001:db8::/64"}
_ADDRESS = {4: "198.18.0.20", 6: "2001:db8::20"}
_IDENTITY = ReservationIdentity("hw-address", "02:00:00:00:00:20")


def _outcome(
    server,
    family=4,
    *,
    action="created",
    address=True,
    unknown=False,
    persistence_failed=False,
    verification_failed=False,
):
    addresses = (
        tuple(ip_address(value) for value in address)
        if isinstance(address, tuple)
        else (ip_address(_ADDRESS[family]),)
        if address
        else ()
    )
    proposal = ReservationImportProposal(family, _CIDR[family], _IDENTITY, addresses, (), "host", ())
    raw = {"subnet-id": 20, "hw-address": _IDENTITY.value, "hostname": "host"}
    if address:
        raw.update(
            {"ip-address": str(addresses[0])} if family == 4 else {"ip-addresses": [str(value) for value in addresses]}
        )
    responses = {
        **_catalogue_responses_for_subnets(
            family, [{"id": 20, "subnet": _CIDR[family], "ddns-qualifying-suffix": "lab.example.org"}]
        ),
        "reservation-add": {"result": 1} if unknown else {"result": 0},
        "reservation-get": {"result": 3} if verification_failed else _res_get(raw),
        "reservation-update": {"result": 0},
        "reservation-del": {"result": 0},
        "config-test": {"result": 0},
        "config-write": {"result": 1, "text": "read-only"} if persistence_failed else {"result": 0},
    }
    with stub_kea(responses):
        created = reservation_edit.save_import(server, proposal)
    if action == "created":
        return created
    current = created.intended
    if action == "updated":
        responses["reservation-get"] = queued(_res_get(raw), _res_get({**raw, "hostname": "edited"}))
        with stub_kea(responses):
            return config_write.edit_reservation(
                server,
                family,
                20,
                _IDENTITY,
                reservation_fingerprint(current),
                lambda _current, _catalogue: ReservationChange(hostname=SetValue("edited")),
            )
    responses["reservation-get"] = queued(_res_get(raw), {"result": 3})
    with stub_kea(responses):
        return config_write.delete_reservation(server, family, 20, _IDENTITY)


@contextmanager
def _receiver(signal, receiver, *, sender=None):
    signal.connect(receiver, sender=sender, weak=False)
    try:
        yield
    finally:
        signal.disconnect(receiver, sender=sender)


def fail_journal_dispatch(events):
    """Model an external event pipeline failure after the journal committed."""
    if any(event["object_type"].model == "journalentry" for event in events):
        raise RuntimeError("journal event pipeline unavailable")


def fail_site_dispatch(events):
    """Model a failed pipeline after a Reservation signal receiver saved a Site."""
    if any(event["object_type"].model == "site" for event in events):
        raise RuntimeError("signal receiver event pipeline unavailable")


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ReservationAfterApplyTests(TestCase):
    def setUp(self):
        self.server = _make_db_server()
        self.user = get_user_model().objects.create_superuser(username="reservation-after-apply")

    def test_a_failed_permission_read_is_a_claim_failure_after_journal_and_signal(self):
        user = get_user_model().objects.create_user(username="reservation-permission-read")
        outcome = _outcome(self.server)

        def permission_read_fails(execute, sql, params, many, context):
            # A failed DB query is the external boundary. The real permission lookup still constructs its query.
            if "users_objectpermission" in sql:
                raise OperationalError("permission database unavailable")
            return execute(sql, params, many, context)

        with connection.execute_wrapper(permission_read_fails):
            facts = reservation_edit.after_apply(self.server, outcome, user, sync_to_netbox=True)
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "succeeded"))
        self.assertEqual(facts.claim, reservation_edit.ClaimFailure("failed"))
        self.assertTrue(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())
        self.assertFalse(IPAddress.objects.exists())

    def test_a_journal_receiver_failure_does_not_stop_the_signal_or_claim(self):
        outcome = _outcome(self.server)

        def reject(sender, **kwargs):
            raise RuntimeError("journal receiver failed")

        post_save.connect(reject, sender=JournalEntry)
        try:
            facts = reservation_edit.after_apply(self.server, outcome, self.user, sync_to_netbox=True)
        finally:
            post_save.disconnect(reject, sender=JournalEntry)
        self.assertEqual((facts.journal, facts.signal), ("failed", "succeeded"))
        self.assertFalse(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)

    def test_create_edit_and_delete_record_the_actual_change_and_preserve_signal_arguments(self):
        for family in (4, 6):
            for action, signal in (
                ("created", reservation_created),
                ("updated", reservation_updated),
                ("deleted", reservation_deleted),
            ):
                received = []
                outcome = _outcome(self.server, family, action=action)
                request = object()

                def receiver(sender, received=received, **kwargs):
                    received.append((sender, kwargs))

                with self.subTest(family=family, action=action):
                    with _receiver(signal, receiver), stub_kea({}) as kea:
                        facts = reservation_edit.after_apply(
                            self.server, outcome, self.user, request=request, sync_to_netbox=True
                        )
                    self.assertEqual((facts.action, facts.journal, facts.signal), (action, "succeeded", "succeeded"))
                    self.assertEqual(kea.commands(), [])
                    self.assertEqual(len(received), 1)
                    sender, payload = received[0]
                    self.assertIsNone(sender)
                    self.assertIs(payload["server"], self.server)
                    self.assertIs(payload["request"], request)
                    self.assertEqual(
                        (payload["before"], payload["after"], payload["dhcp_version"]),
                        (outcome.previous, outcome.intended, family),
                    )
                    journal = JournalEntry.objects.filter(assigned_object_id=self.server.pk).latest("created")
                    self.assertEqual(journal.created_by, self.user)
                    self.assertEqual(journal.kind, "info")
                    self.assertEqual(
                        journal.comments, f"Reservation {action}: hw-address 02:00:00:00:00:20; {_ADDRESS[family]}"
                    )
                    if action == "deleted":
                        self.assertEqual(facts.claim, reservation_edit.ClaimSkipped("nothing-to-sync"))
                    else:
                        self.assertIsInstance(facts.claim, ClaimResult)
                        self.assertTrue(facts.claim.addresses[_ADDRESS[family]].synchronized)
                        self.assertEqual(
                            facts.claim.primary.dns_name,
                            "edited.lab.example.org" if action == "updated" else "host.lab.example.org",
                        )

    def test_unknown_application_does_not_read_permissions_or_run_any_side_effect(self):
        outcome = _outcome(self.server, unknown=True)
        self.assertEqual(outcome.application, "unknown")
        with self.assertNumQueries(0), stub_kea({}) as kea:
            facts = reservation_edit.after_apply(self.server, outcome, object(), sync_to_netbox=True)
        self.assertEqual(
            facts,
            reservation_edit.AfterApplyFacts(
                None, "not-applied", "not-applied", reservation_edit.ClaimSkipped("not-applied")
            ),
        )
        self.assertEqual(kea.commands(), [])
        self.assertFalse(JournalEntry.objects.exists())
        self.assertFalse(IPAddress.objects.exists())

    def test_unrequested_addressless_and_permission_refused_claims_have_distinct_facts(self):
        user = get_user_model().objects.create_user(username="reservation-no-write")
        for address, requested, actor, reason in (
            (True, False, self.user, "not-requested"),
            (False, True, self.user, "nothing-to-sync"),
            (True, True, user, "permission"),
        ):
            outcome = _outcome(self.server, address=address)
            facts = reservation_edit.after_apply(self.server, outcome, actor, sync_to_netbox=requested)
            self.assertEqual((facts.journal, facts.signal), ("succeeded", "succeeded"))
            self.assertEqual(facts.claim.reason, reason)
            if reason == "permission":
                self.assertIn("Manual Sync needs unconstrained", facts.claim.explanation)
        self.assertFalse(IPAddress.objects.exists())

    def test_applied_with_failed_persistence_or_verification_still_runs_all_requested_work(self):
        outcome = _outcome(self.server, persistence_failed=True, verification_failed=True)
        self.assertEqual(
            (outcome.application, outcome.persistence, outcome.verification), ("applied", "failed", "failed")
        )
        facts = reservation_edit.after_apply(self.server, outcome, self.user, sync_to_netbox=True)
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "succeeded"))
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)
        self.server.persist_config = False
        self.server.save()
        outcome = _outcome(self.server)
        self.assertEqual(outcome.persistence, "not-requested")
        facts = reservation_edit.after_apply(self.server, outcome, self.user, sync_to_netbox=True)
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)

    def test_a_real_database_journal_failure_leaves_the_signal_and_claim_usable(self):
        outcome = _outcome(self.server)
        observed_journals = []

        def invalidate(sender, instance, **kwargs):
            instance.kind = None

        def receiver(sender, **kwargs):
            observed_journals.append(JournalEntry.objects.filter(assigned_object_id=self.server.pk).count())

        with _receiver(pre_save, invalidate, sender=JournalEntry), _receiver(reservation_created, receiver):
            facts = reservation_edit.after_apply(self.server, outcome, self.user, sync_to_netbox=True)
        self.assertEqual((facts.journal, facts.signal), ("failed", "succeeded"))
        self.assertEqual(observed_journals, [0])
        self.assertFalse(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)

    def test_a_failed_robust_signal_receiver_does_not_stop_other_receivers_or_the_claim(self):
        outcome = _outcome(self.server)
        received = []

        def failing(sender, **kwargs):
            raise RuntimeError("receiver unavailable")

        def healthy(sender, **kwargs):
            received.append(JournalEntry.objects.filter(assigned_object_id=self.server.pk).count())

        with _receiver(reservation_created, failing), _receiver(reservation_created, healthy):
            facts = reservation_edit.after_apply(self.server, outcome, self.user, sync_to_netbox=True)
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "failed"))
        self.assertEqual(received, [1])
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)

    def test_a_claim_validation_failure_is_separate_from_successful_journal_and_signal(self):
        outcome = _outcome(self.server)

        def reject(sender, **kwargs):
            raise ValidationError("IPAM validation failed")

        with _receiver(pre_save, reject, sender=IPAddress):
            facts = reservation_edit.after_apply(self.server, outcome, self.user, sync_to_netbox=True)
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "succeeded"))
        self.assertEqual(facts.claim, reservation_edit.ClaimFailure("failed"))
        self.assertTrue(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())
        self.assertFalse(IPAddress.objects.exists())

    def test_a_partial_claim_returns_each_row_result(self):
        outcome = _outcome(self.server, 6, address=("2001:db8::20", "2001:db8::21"))
        IPAddress.objects.bulk_create([IPAddress(address="2001:db8::20/64"), IPAddress(address="2001:db8::20/64")])
        facts = reservation_edit.after_apply(self.server, outcome, self.user, sync_to_netbox=True)
        self.assertIsInstance(facts.claim, ClaimResult)
        self.assertEqual(facts.claim.addresses["2001:db8::20"].outcome, "error")
        self.assertTrue(facts.claim.addresses["2001:db8::21"].synchronized)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ReservationAfterApplyEventTests(TransactionTestCase):
    def test_a_failed_receiver_does_not_roll_back_other_receivers_or_block_the_next_receiver(self):
        user = get_user_model().objects.create_superuser(username="reservation-native-signals")
        server = _make_db_server()
        outcome = _outcome(server)
        observed = []

        def create_site(sender, **kwargs):
            Site.objects.create(name="Successful signal receiver", slug="successful-signal-receiver")

        def invalid_journal(sender, **kwargs):
            JournalEntry.objects.create(assigned_object=server, kind=None, comments="Rejected receiver write")

        def read_site(sender, **kwargs):
            observed.append(Site.objects.filter(slug="successful-signal-receiver").exists())

        self.assertTrue(connection.get_autocommit())
        with (
            _receiver(reservation_created, create_site),
            _receiver(reservation_created, invalid_journal),
            _receiver(reservation_created, read_site),
        ):
            facts = reservation_edit.after_apply(server, outcome, user, sync_to_netbox=True)
        self.assertEqual(observed, [True])
        self.assertTrue(Site.objects.filter(slug="successful-signal-receiver").exists())
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "failed"))
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)

    def test_a_committed_journal_with_failed_events_is_reported_as_written(self):
        if not _NESTED_TRACKING:
            self.skipTest("Before NetBox 4.6.9 nested event units are unavailable")
        user = get_user_model().objects.create_superuser(username="reservation-journal-events")
        server = _make_db_server()
        outcome = _outcome(server)
        request = RequestFactory().post("/plugins/kea/")
        request.user, request.id = user, uuid.uuid4()
        with (
            override_settings(EVENTS_PIPELINE=["netbox_kea.tests.test_reservation_after_apply.fail_journal_dispatch"]),
            event_tracking(request),
        ):
            facts = reservation_edit.after_apply(server, outcome, user, request=request, sync_to_netbox=True)
        self.assertEqual(facts.journal, "events-failed")
        self.assertEqual(facts.signal, "succeeded")
        self.assertTrue(JournalEntry.objects.filter(assigned_object_id=server.pk).exists())
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)
        self.assertTrue(IPAddress.objects.filter(address="198.18.0.20/24").exists())

    def test_a_committed_claim_with_failed_events_keeps_the_saved_ip(self):
        if not _NESTED_TRACKING:
            self.skipTest("Before NetBox 4.6.9 nested event units are unavailable")
        user = get_user_model().objects.create_superuser(username="reservation-claim-events")
        server = _make_db_server()
        outcome = _outcome(server)
        request = RequestFactory().post("/plugins/kea/")
        request.user, request.id = user, uuid.uuid4()
        with (
            override_settings(EVENTS_PIPELINE=["netbox_kea.tests.test_sync_views.fail_ip_address_dispatch"]),
            event_tracking(request),
        ):
            facts = reservation_edit.after_apply(server, outcome, user, request=request, sync_to_netbox=True)
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "succeeded"))
        self.assertEqual(facts.claim, reservation_edit.ClaimFailure("events-failed"))
        self.assertTrue(IPAddress.objects.filter(address="198.18.0.20/24").exists())

    def test_a_delivered_signal_with_failed_receiver_events_is_not_a_receiver_failure(self):
        if not _NESTED_TRACKING:
            self.skipTest("Before NetBox 4.6.9 nested event units are unavailable")
        user = get_user_model().objects.create_superuser(username="reservation-signal-events")
        server = _make_db_server()
        outcome = _outcome(server)
        request = RequestFactory().post("/plugins/kea/")
        request.user, request.id = user, uuid.uuid4()

        def receiver(sender, **kwargs):
            with event_scope.atomic():
                Site.objects.create(name="Reservation signal site", slug="reservation-signal-site")

        with (
            _receiver(reservation_created, receiver),
            override_settings(EVENTS_PIPELINE=["netbox_kea.tests.test_reservation_after_apply.fail_site_dispatch"]),
            event_tracking(request),
        ):
            facts = reservation_edit.after_apply(server, outcome, user, request=request, sync_to_netbox=True)
        self.assertEqual((facts.journal, facts.signal), ("succeeded", "events-failed"))
        self.assertTrue(Site.objects.filter(slug="reservation-signal-site").exists())
        self.assertTrue(facts.claim.addresses["198.18.0.20"].synchronized)
