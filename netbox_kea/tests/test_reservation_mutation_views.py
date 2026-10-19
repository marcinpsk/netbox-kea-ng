# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import patch
from urllib.parse import urlencode

import requests
from bs4 import BeautifulSoup
from django.contrib.messages import get_messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils.html import escape

from netbox_kea import constants, display_cache, server_configuration
from netbox_kea.subnet_catalogue import display
from netbox_kea.views.notices import HEADLINES

from .kea_stub import (
    READ_FAILURES,
    SUBNET_LIST_FAILURES,
    _host_cmds_hooks,
    _res_get,
    _res_page,
    _subnet_list,
    queued,
    stub_kea,
)
from .utils import _make_db_server, _ViewTestBase, active_tabs, with_kea_client_config


def _live_config(version: int, subnet_id: int, cidr: str, identifiers: list[str], pools: list | None = None) -> dict:
    return {
        "result": 0,
        "arguments": {
            f"Dhcp{version}": {
                f"subnet{version}": [{"id": subnet_id, "subnet": cidr, "pools": pools or []}],
                "host-reservation-identifiers": identifiers,
                "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_flex_id.so"}, *_host_cmds_hooks()],
            },
            "hash": "reservation-mutation-config",
        },
    }


def _mutation_responses(
    version: int, subnet_id: int, cidr: str, identifiers: list[str], pools: list | None = None
) -> dict:
    return {
        f"subnet{version}-list": _subnet_list(version, [{"id": subnet_id, "subnet": cidr}]),
        "config-get": _live_config(version, subnet_id, cidr, identifiers, pools),
        "config-test": {"result": 0},
        "config-write": {"result": 0},
    }


_PERSIST = ["config-get", "config-test", "config-write"]
_UNCONFIRMED_RESERVATION = (
    "Kea did not confirm the change. Check the server configuration before retrying."
    " NetBox recorded nothing for this change."
)


def _identity_query(identifier: str = "aa:bb:cc:dd:ee:ff", identifier_type: str = "hw-address") -> str:
    """The identity query string every reservation edit and delete route requires."""
    return urlencode({"identifier_type": identifier_type, "identifier": identifier})


def _open_edit_token(client, url, responses, current):
    """Open a valid form before injecting the read or capability failure under test."""
    with stub_kea({**responses, "reservation-get": _res_get(current)}):
        page = client.get(url)
    return page.context["form"].initial["managed_fingerprint"]


class TestReservationMutationViews(_ViewTestBase):
    def test_edit_and_delete_get_keep_both_display_snapshots(self):
        for version, cidr, identifier_type, identifier in (
            (4, "198.18.0.0/24", "hw-address", "02:00:00:00:00:01"),
            (6, "2001:db8::/64", "duid", "00:01:02:03"),
        ):
            for action in ("edit", "delete"):
                with self.subTest(version=version, action=action):
                    display_cache.rotate_configuration(self.server, version)
                    responses = _mutation_responses(version, 20, cidr, [identifier_type])
                    responses["reservation-get"] = _res_get({"subnet-id": 20, identifier_type: identifier})
                    url = reverse(f"plugins:netbox_kea:server_reservation{version}_{action}", args=[self.server.pk, 20])
                    with stub_kea(responses) as kea:
                        configuration = server_configuration.display(self.server, version)
                        catalogue = display(self.server, version)
                        response = self.client.get(f"{url}?{_identity_query(identifier, identifier_type)}")
                        self.assertEqual(response.status_code, 200)
                        commands_after_get = kea.commands()
                        self.assertEqual(server_configuration.display(self.server, version), configuration)
                        self.assertEqual(display(self.server, version), catalogue)
                        self.assertEqual(kea.commands(), commands_after_get)

    def test_edit_and_delete_post_invalidate_both_display_snapshots(self):
        for version, cidr, identifier_type, identifier in (
            (4, "198.18.0.0/24", "hw-address", "02:00:00:00:00:01"),
            (6, "2001:db8::/64", "duid", "00:01:02:03"),
        ):
            for action in ("edit", "delete"):
                with self.subTest(version=version, action=action):
                    display_cache.rotate_configuration(self.server, version)
                    current = {"subnet-id": 20, identifier_type: identifier, "hostname": "old.example.invalid"}
                    responses = _mutation_responses(version, 20, cidr, [identifier_type])
                    url = reverse(f"plugins:netbox_kea:server_reservation{version}_{action}", args=[self.server.pk, 20])
                    url = f"{url}?{_identity_query(identifier, identifier_type)}"
                    with stub_kea({**responses, "reservation-get": _res_get(current)}):
                        form_page = self.client.get(url)
                        self.assertEqual(form_page.status_code, 200)
                        configuration = server_configuration.display(self.server, version)
                        catalogue = display(self.server, version)
                    data = {}
                    command = "reservation-del"
                    final = {"result": 3}
                    if action == "edit":
                        data = {
                            "hostname": "new.example.invalid",
                            "managed_fingerprint": form_page.context["form"].initial["managed_fingerprint"],
                        }
                        command = "reservation-update"
                        final = _res_get({**current, "hostname": "new.example.invalid"})
                    responses.update(
                        {"reservation-get": queued(_res_get(current), _res_get(current), final), command: {"result": 0}}
                    )
                    with stub_kea(responses) as kea:
                        response = self.client.post(url, data)
                        self.assertEqual(response.status_code, 302)
                        self.assertEqual(kea.commands().count(command), 1)
                        self.assertNotEqual(server_configuration.display(self.server, version), configuration)
                        self.assertNotEqual(display(self.server, version), catalogue)

    def test_add_form_uses_live_identifier_choices_and_explains_relay_remote_id(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address", "flex-id"])
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])

        with stub_kea(responses):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "hw-address")
        self.assertContains(response, "flex-id")
        self.assertNotContains(response, 'value="remote-id"')
        help_text = BeautifulSoup(response.content, "html.parser").select_one("#id_identifier_type_helptext")
        self.assertIn("For relay remote ID, configure Kea flex-id.", " ".join(help_text.get_text().split()))
        self.assertEqual(help_text.a["href"], constants.FLEX_ID_DOCUMENTATION_URL)

    def test_a_post_reads_the_capabilities_live_with_a_warm_cache(self):
        from django.contrib.messages import get_messages

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])
        with stub_kea(responses):
            self.assertTrue(self.client.get(url).context["mutation_available"])
        # Kea no longer loads host_cmds; only the cached Server Configuration still shows it.
        unloaded = _live_config(4, 20, "198.18.0.0/24", ["hw-address"])
        unloaded["arguments"]["Dhcp4"]["hooks-libraries"] = []
        data = {"subnet_cidr": "198.18.0.0/24", "identifier_type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff"}

        with stub_kea({**responses, "config-get": unloaded, "reservation-add": {"result": 0}}) as kea:
            response = self.client.post(url, data)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), ["config-get"])
        self.assertIn(
            "Reservation mutation capabilities are unavailable.",
            [str(message) for message in get_messages(response.wsgi_request)],
        )

    def test_capability_failure_leaves_the_add_form_visible_but_disables_save(self):
        responses = {
            "config-get": RuntimeError("configuration read failed"),
            "subnet4-list": _subnet_list(4, [{"id": 20, "subnet": "198.18.0.0/24"}]),
        }
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])

        with stub_kea(responses):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Mutation is unavailable")
        # Assert the save control itself: a bare "disabled" also matches CSS class
        # names and unrelated markup, so it passed even with the button enabled.
        self.assertContains(
            response,
            '<button type="submit" class="btn btn-primary" disabled aria-disabled="true">',
        )

    def test_live_capabilities_leave_the_save_control_enabled(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])

        with stub_kea(responses):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<button type="submit" class="btn btn-primary">')
        self.assertNotContains(
            response,
            '<button type="submit" class="btn btn-primary" disabled aria-disabled="true">',
        )

    def test_add_form_warns_when_configuration_persistence_is_disabled(self):
        self.server.persist_config = False
        self.server.save(update_fields=("persist_config",))
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])

        with stub_kea(responses):
            response = self.client.get(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Configuration persistence is disabled.")

    def test_create_warns_when_the_pool_overlap_check_cannot_run(self):
        """A Subnet with no configuration facts gets one warning, not a silent skip."""
        from django.contrib import messages
        from django.contrib.messages import get_messages

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        # An invalid declaration makes the configuration incomplete, so Subnet 20 keeps its identity only.
        responses["config-get"]["arguments"]["Dhcp4"]["subnet4"] = [{"id": 21, "subnet": "invalid"}]
        raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": raw["ip-address"],
                    "identifier_type": "hw-address",
                    "identifier": "AA-BB-CC-DD-EE-FF",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("reservation-add", kea.commands())
        self.assertNotIn("subnet4-get", kea.commands())
        warnings = [
            str(message)
            for message in get_messages(response.wsgi_request)
            if message.level == messages.WARNING and "pool overlap check did not run" in str(message)
        ]
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn("198.18.0.0/24", warnings[0])

    def test_create_without_an_address_skips_the_pool_overlap_check(self):
        """An addressless Reservation cannot overlap a pool, so no configuration is needed."""
        from django.contrib import messages
        from django.contrib.messages import get_messages

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["config-get"]["arguments"]["Dhcp4"]["subnet4"] = [{"id": 21, "subnet": "invalid"}]
        raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff"}
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {"subnet_cidr": "198.18.0.0/24", "identifier_type": "hw-address", "identifier": "AA-BB-CC-DD-EE-FF"},
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("reservation-add", kea.commands())
        self.assertNotIn("ip-address", kea.bodies("reservation-add")[0]["arguments"]["reservation"])
        warnings = [
            str(message) for message in get_messages(response.wsgi_request) if message.level == messages.WARNING
        ]
        self.assertFalse(any("pool overlap check did not run" in warning for warning in warnings), warnings)

    def test_create_reads_each_separated_group_as_one_octet_like_kea(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {"subnet-id": 20, "hw-address": "0a:0b:0c:0d:0e:0f"}
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {"subnet_cidr": "198.18.0.0/24", "identifier_type": "hw-address", "identifier": "a:b:c:d:e:f"},
            )

        self.assertEqual(response.status_code, 302)
        sent = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
        self.assertEqual(sent["hw-address"], "0a:0b:0c:0d:0e:0f")

    def test_create_refuses_a_separated_group_that_kea_refuses(self):
        for identifier in ("aabb:ccdd:eeff", "aa::bb:cc:dd:ee", "aa:bb:cc:dd:ee:fff", "aa-bbb-cc-dd-ee-ff"):
            with self.subTest(identifier=identifier):
                responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
                responses["reservation-add"] = {"result": 0}
                with stub_kea(responses) as kea:
                    response = self.client.post(
                        reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                        {"subnet_cidr": "198.18.0.0/24", "identifier_type": "hw-address", "identifier": identifier},
                    )

                self.assertEqual(response.status_code, 200)
                self.assertNotIn("reservation-add", kea.commands())

    def test_create_uses_the_typed_operation_and_emits_one_typed_signal(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
            "hostname": "host.example.invalid",
        }
        responses.update(
            {
                "reservation-add": {"result": 0},
                "reservation-get": _res_get(raw),
            }
        )
        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        def failing_receiver(sender, **kwargs):
            raise RuntimeError("optional signal receiver failed")

        from netbox_kea.signals import reservation_created

        reservation_created.connect(receiver)
        reservation_created.connect(failing_receiver)
        try:
            with stub_kea(responses) as kea:
                response = self.client.post(
                    reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                    {
                        "subnet_cidr": "198.18.0.0/24",
                        "ip_address": "198.18.0.20",
                        "identifier_type": "hw-address",
                        "identifier": "AA-BB-CC-DD-EE-FF",
                        "hostname": "host.example.invalid",
                    },
                )
        finally:
            reservation_created.disconnect(receiver)
            reservation_created.disconnect(failing_receiver)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        from django.contrib.messages import get_messages

        self.assertIn(
            "Kea applied the change, but a receiver of the reservation_created signal failed; see server logs.",
            [str(message) for message in get_messages(response.wsgi_request)],
        )
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["server"], self.server)
        self.assertIs(received[0]["request"], response.wsgi_request)
        self.assertEqual(received[0]["dhcp_version"], 4)
        self.assertIsNone(received[0]["before"])
        self.assertEqual(received[0]["after"].identity.value, "aa:bb:cc:dd:ee:ff")
        from extras.models import JournalEntry

        journal = JournalEntry.objects.get(assigned_object_id=self.server.pk)
        self.assertIn("Reservation created", journal.comments)
        self.assertIn("aa:bb:cc:dd:ee:ff", journal.comments)

    def test_create_with_overlapping_pool_succeeds_with_warning(self):
        from django.contrib import messages
        from django.contrib.messages import get_messages

        responses = _mutation_responses(
            4, 20, "198.18.0.0/24", ["hw-address"], pools=[{"pool": "198.18.0.10-198.18.0.30"}]
        )
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
        }
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                },
            )

        self.assertEqual(response.status_code, 302)
        feedback = list(get_messages(response.wsgi_request))
        self.assertTrue(any(message.level == messages.SUCCESS for message in feedback))
        self.assertTrue(
            any(
                message.level == messages.WARNING
                and "198.18.0.20 is within existing pool 198.18.0.10-198.18.0.30" in str(message)
                for message in feedback
            )
        )
        self.assertNotIn("subnet4-get", kea.commands())

    def test_create_warns_for_an_address_inside_a_cidr_pool(self):
        from django.contrib import messages
        from django.contrib.messages import get_messages

        pools = [{"pool": "198.18.0.16/28"}, {"pool": "198.18.0.100-198.18.0.110"}]
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"], pools=pools)
        raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        warnings = [str(m) for m in get_messages(response.wsgi_request) if m.level == messages.WARNING]
        self.assertEqual(
            warnings,
            [
                (
                    "IP 198.18.0.20 is within existing pool 198.18.0.16-198.18.0.31. "
                    "Kea allows this. Reservations take priority over pool allocation."
                )
            ],
        )

    def test_a_malformed_pool_entry_does_not_stop_the_overlap_check(self):
        from django.contrib import messages
        from django.contrib.messages import get_messages

        for malformed in ({"pool": "invalid"}, "not-a-pool", {"pool": 7}, {"pool": "198.18.0.30-198.18.0.10"}):
            with self.subTest(malformed=malformed):
                self._fresh_client()
                pools = [malformed, {"pool": "198.18.0.10-198.18.0.30"}]
                responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"], pools=pools)
                raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
                responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})
                with stub_kea(responses), self.assertNoLogs("netbox_kea.views.reservation_mutations", "ERROR"):
                    response = self.client.post(
                        reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                        {
                            "subnet_cidr": "198.18.0.0/24",
                            "ip_address": "198.18.0.20",
                            "identifier_type": "hw-address",
                            "identifier": "aa:bb:cc:dd:ee:ff",
                        },
                    )

                self.assertEqual(response.status_code, 302)
                self.assertEqual(
                    [
                        str(message)
                        for message in get_messages(response.wsgi_request)
                        if message.level == messages.WARNING
                    ],
                    [
                        (
                            "IP 198.18.0.20 is within existing pool 198.18.0.10-198.18.0.30. "
                            "Kea allows this. Reservations take priority over pool allocation."
                        )
                    ],
                )

    def test_a_journal_validation_error_does_not_lose_the_applied_creation(self):
        """A save signal can raise ValidationError, which is not a ValueError the view catches."""
        from django.contrib.messages import get_messages
        from django.core.exceptions import ValidationError
        from django.db.models.signals import post_save
        from extras.models import JournalEntry

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})

        def reject(sender, **kwargs):
            raise ValidationError("journal rejected by a save signal")

        post_save.connect(reject, sender=JournalEntry)
        try:
            with stub_kea(responses) as kea:
                response = self.client.post(
                    reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                    {
                        "subnet_cidr": "198.18.0.0/24",
                        "ip_address": "198.18.0.20",
                        "identifier_type": "hw-address",
                        "identifier": "aa:bb:cc:dd:ee:ff",
                    },
                )
        finally:
            post_save.disconnect(reject, sender=JournalEntry)

        # Kea applied the create, so the operator must be told it happened.
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        self.assertEqual(response.status_code, 302)
        self.assertIn("Reservation created.", [str(message) for message in get_messages(response.wsgi_request)])

    def test_create_reports_failed_persistence_after_confirmed_application(self):
        from django.contrib.messages import get_messages
        from extras.models import JournalEntry

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
        }
        responses.update(
            {
                "reservation-add": {"result": 0},
                "reservation-get": _res_get(raw),
                "config-test": {"result": 0},
                "config-write": {"result": 1, "text": "write failed"},
            }
        )
        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        from netbox_kea.signals import reservation_created

        reservation_created.connect(receiver)
        try:
            with stub_kea(responses) as kea:
                response = self.client.post(
                    reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                    {
                        "subnet_cidr": "198.18.0.0/24",
                        "ip_address": "198.18.0.20",
                        "identifier_type": "hw-address",
                        "identifier": "aa:bb:cc:dd:ee:ff",
                    },
                )
        finally:
            reservation_created.disconnect(receiver)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        self.assertEqual(kea.commands().count("config-write"), 1)
        self.assertIn(
            "Reservation created. It is live, but it may not survive a Kea restart, because Kea did not save it to"
            " disk. config-write failed: write failed",
            [str(message) for message in get_messages(response.wsgi_request)],
        )
        self.assertEqual(len(received), 1)
        self.assertIsNone(received[0]["before"])
        self.assertIsNotNone(received[0]["after"])
        self.assertTrue(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())

    def test_create_skips_immediate_ipam_sync_without_ipam_write_permission(self):
        from django.contrib.auth import get_user_model
        from django.contrib.contenttypes.models import ContentType
        from ipam.models import IPAddress
        from users.models import ObjectPermission

        limited = get_user_model().objects.create_user(username="reservation_no_ipam", password="x")
        permission = ObjectPermission.objects.create(
            name="change-server-reservation-no-ipam",
            actions=["view", "change"],
        )
        permission.object_types.add(ContentType.objects.get_for_model(type(self.server)))
        permission.users.add(limited)
        self.client.force_login(limited)
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
        }
        responses.update(
            {
                "reservation-add": {"result": 0},
                "reservation-get": _res_get(raw),
            }
        )

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "sync_to_netbox": "on",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        self.assertFalse(IPAddress.objects.filter(address="198.18.0.20/24").exists())

    def test_create_redirects_and_warns_when_ipam_validation_fails(self):
        from django.contrib.messages import get_messages
        from django.core.exceptions import ValidationError

        def fail_sync(_server, _family, _records, *, force, catalogue):
            raise ValidationError("IPAM validation failed")

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
        }
        responses.update(
            {
                "reservation-add": {"result": 0},
                "reservation-get": _res_get(raw),
            }
        )

        with (
            patch("netbox_kea.views.reservation_mutations.claim", new=fail_sync),
            stub_kea(responses) as kea,
        ):
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "sync_to_netbox": "on",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        self.assertIn(
            "The Reservation changed, but NetBox IPAM synchronization failed.",
            [str(message) for message in get_messages(response.wsgi_request)],
        )

    def test_create_warns_when_ownership_claim_returns_a_row_error(self):
        from dcim.models import MACAddress
        from django.contrib.messages import get_messages

        MACAddress.objects.create(mac_address="aa:bb:cc:dd:ee:ff")
        MACAddress.objects.create(mac_address="aa:bb:cc:dd:ee:ff")

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
        }
        responses.update(
            {
                "reservation-add": {"result": 0},
                "reservation-get": _res_get(raw),
            }
        )

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "sync_to_netbox": "on",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        self.assertIn(
            "The Reservation changed, but NetBox IPAM synchronization failed.",
            [str(message) for message in get_messages(response.wsgi_request)],
        )

    def test_edit_rejects_a_stale_managed_fingerprint_without_an_update(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        original = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
            "hostname": "old.example.invalid",
        }
        changed = {**original, "hostname": "changed.example.invalid"}
        url = reverse(
            "plugins:netbox_kea:server_reservation4_edit",
            args=[self.server.pk, 20],
        )
        query = _identity_query()

        with stub_kea({**responses, "reservation-get": _res_get(original)}):
            form_page = self.client.get(f"{url}?{query}")
        fingerprint = form_page.context["form"].initial["managed_fingerprint"]

        with stub_kea({**responses, "reservation-get": _res_get(changed)}) as kea:
            response = self.client.post(
                f"{url}?{query}",
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.21",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "hostname": "new.example.invalid",
                    "managed_fingerprint": fingerprint,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "changed after the edit form was opened")
        self.assertNotIn("reservation-update", kea.commands())

    def test_edit_invalidates_a_catalogue_cached_during_the_mutation(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        current = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "hostname": "old.example.invalid",
        }
        intended = {**current, "hostname": "new.example.invalid"}
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        query = _identity_query()

        with stub_kea({**responses, "reservation-get": _res_get(current)}):
            form_page = self.client.get(f"{url}?{query}")
        fingerprint = form_page.context["form"].initial["managed_fingerprint"]
        reservation_reads = 0

        def reservation_get(_body):
            nonlocal reservation_reads
            reservation_reads += 1
            if reservation_reads == 2:
                display(self.server, 4)
            return _res_get(intended if reservation_reads == 3 else current)

        responses.update(
            {
                "reservation-get": reservation_get,
                "reservation-update": {"result": 0},
            }
        )
        with stub_kea(responses) as kea:
            response = self.client.post(
                f"{url}?{query}",
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "hostname": "new.example.invalid",
                    "managed_fingerprint": fingerprint,
                },
            )
            display(self.server, 4)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("config-get"), 5, kea.commands())

    def test_canonical_identity_route_rejects_missing_unsupported_and_malformed_identity(self):
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        queries = (
            "",
            "identifier_type=remote-id&identifier=relay",
            "identifier_type=hw-address&identifier=not-a-mac",
        )
        with stub_kea({}) as kea:
            for query in queries:
                with self.subTest(query=query):
                    response = self.client.get(f"{url}?{query}")
                    self.assertEqual(response.status_code, 400)
        self.assertEqual(kea.commands(), [])

    def test_edit_returns_not_found_for_an_unknown_subnet_or_identity(self):
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        query = _identity_query()
        no_subnet = _mutation_responses(4, 21, "198.18.1.0/24", ["hw-address"])
        with stub_kea(no_subnet):
            response = self.client.get(f"{url}?{query}")
        self.assertEqual(response.status_code, 404)

        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["reservation-get"] = {"result": 3}
        with stub_kea(responses):
            response = self.client.get(f"{url}?{query}")
        self.assertEqual(response.status_code, 404)

    def test_create_ipv6_preserves_all_addresses_prefixes_and_options(self):
        responses = _mutation_responses(6, 10, "2001:db8::/64", ["duid"])
        raw = {
            "subnet-id": 10,
            "duid": "00:01:02:03",
            "ip-addresses": ["2001:db8::20", "2001:db8::21"],
            "prefixes": ["2001:db8:100::/56"],
            "hostname": "host6.example.invalid",
            "option-data": [{"name": "dns-servers", "data": "2001:db8::53", "always-send": True}],
        }
        responses.update(
            {
                "reservation-add": {"result": 0},
                "reservation-get": _res_get(raw),
            }
        )

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation6_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "2001:db8::/64",
                    "ip_addresses": "2001:db8::20,2001:db8::21",
                    "prefixes": "2001:db8:100::/56",
                    "identifier_type": "duid",
                    "identifier": "00:01:02:03",
                    "hostname": "host6.example.invalid",
                    "options-TOTAL_FORMS": "1",
                    "options-INITIAL_FORMS": "0",
                    "options-MIN_NUM_FORMS": "0",
                    "options-MAX_NUM_FORMS": "1000",
                    "options-0-name": "dns-servers",
                    "options-0-data": "2001:db8::53",
                    "options-0-always_send": "on",
                },
            )

        self.assertEqual(response.status_code, 302)
        sent = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
        self.assertEqual(sent, raw)

    def test_create_keeps_the_form_visible_when_kea_rejects_the_mutation(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["reservation-add"] = {"result": 2, "text": "'reservation-add' command not supported."}

        with stub_kea(responses) as kea:
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Kea rejected the change.")
        self.assertContains(response, "The required hook library may not be loaded")
        self.assertNotIn("config-write", kea.commands())

    def test_a_failure_result_on_each_write_is_unconfirmed_with_keas_text_and_records_nothing(self):
        """A failure result can follow a change that one host data source applied, so it is unknown (ADR 0012)."""
        from django.contrib.messages import get_messages
        from extras.models import JournalEntry

        current = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "old.example.invalid"}
        cases = {
            "add": ("reservation-add", self._post_add),
            "edit": ("reservation-update", self._post_edit),
            "delete": ("reservation-del", self._post_delete),
        }
        for name, (command, post) in cases.items():
            with self.subTest(name):
                self._fresh_client()
                responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
                responses.update({"reservation-get": _res_get(current), command: {"result": 1, "text": "db error"}})
                with stub_kea(responses) as kea:
                    response = post(responses, current)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(kea.commands().count(command), 1)
                # The persist step runs after unknown; no verification read follows the change.
                self.assertEqual(kea.commands()[kea.commands().index(command) + 1 :], _PERSIST)
                shown = [str(message) for message in get_messages(response.wsgi_request)]
                self.assertEqual(len(shown), 1, shown)
                self.assertIn("Kea did not confirm the change.", shown[0])
                self.assertIn("NetBox recorded nothing for this change.", shown[0])
                self.assertIn("Kea replied: db error", shown[0])
                self.assertFalse(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())

    def test_a_lost_reply_on_each_write_is_unconfirmed_with_no_journal_entry_and_no_claim(self):
        from django.contrib.messages import get_messages
        from extras.models import JournalEntry
        from ipam.models import IPAddress

        current = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        cases = {
            "add": ("reservation-add", self._post_add),
            "edit": ("reservation-update", self._post_edit),
            "delete": ("reservation-del", self._post_delete),
        }
        for name, (command, post) in cases.items():
            with self.subTest(name):
                self._fresh_client()
                responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
                responses.update(
                    {"reservation-get": _res_get(current), command: requests.ReadTimeout("read timed out")}
                )
                with stub_kea(responses) as kea:
                    response = post(responses, current, sync=True)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(kea.commands()[kea.commands().index(command) + 1 :], _PERSIST)
                self.assertEqual(
                    [str(message) for message in get_messages(response.wsgi_request)],
                    [
                        (
                            f"Reservation hw-address aa:bb:cc:dd:ee:ff: {_UNCONFIRMED_RESERVATION}"
                            " Kea's reply to the change was lost or unreadable."
                        )
                    ],
                )
                self.assertFalse(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())
                self.assertFalse(IPAddress.objects.filter(address__net_host="198.18.0.20").exists())

    def _post_add(self, _responses, _current, *, sync=False):
        data = {
            "subnet_cidr": "198.18.0.0/24",
            "ip_address": "198.18.0.20",
            "identifier_type": "hw-address",
            "identifier": "aa:bb:cc:dd:ee:ff",
        }
        if sync:
            data["sync_to_netbox"] = "on"
        return self.client.post(reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]), data)

    def _post_edit(self, _responses, current, *, sync=False):
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        url = f"{url}?{_identity_query()}"
        form_page = self.client.get(url)
        data = {
            "ip_address": "198.18.0.21",
            "hostname": "new.example.invalid",
            "managed_fingerprint": form_page.context["form"].initial["managed_fingerprint"],
        }
        if sync:
            data["sync_to_netbox"] = "on"
        return self.client.post(url, data)

    def _post_delete(self, _responses, _current, *, sync=False):
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        return self.client.post(f"{url}?{_identity_query()}")

    def test_result_3_on_a_delete_changed_nothing_and_records_nothing(self):
        from django.contrib import messages
        from django.contrib.messages import get_messages
        from extras.models import JournalEntry

        current = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff"}
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses.update({"reservation-get": _res_get(current), "reservation-del": {"result": 3, "text": "not found"}})
        with stub_kea(responses) as kea:
            response = self._post_delete(responses, current)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("config-write", kea.commands())
        self.assertEqual(
            [(message.level, str(message)) for message in get_messages(response.wsgi_request)],
            [
                (
                    messages.WARNING,
                    (
                        "Reservation hw-address aa:bb:cc:dd:ee:ff: This request changed nothing."
                        " Kea reports that no host data source holds it."
                    ),
                )
            ],
        )
        self.assertFalse(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())

    def test_edit_ipv6_updates_mutable_facts_and_emits_typed_signal(self):
        responses = _mutation_responses(6, 10, "2001:db8::/64", ["duid"])
        current = {
            "subnet-id": 10,
            "duid": "00:01:02:03",
            "ip-addresses": ["2001:db8::20"],
            "prefixes": ["2001:db8:100::/56"],
            "hostname": "old6.example.invalid",
        }
        intended = {
            **current,
            "ip-addresses": ["2001:db8::21", "2001:db8::22"],
            "prefixes": ["2001:db8:200::/56"],
            "hostname": "new6.example.invalid",
        }
        url = reverse("plugins:netbox_kea:server_reservation6_edit", args=[self.server.pk, 10])
        query = _identity_query("00:01:02:03", "duid")
        with stub_kea({**responses, "reservation-get": _res_get(current)}):
            form_page = self.client.get(f"{url}?{query}")
        fingerprint = form_page.context["form"].initial["managed_fingerprint"]
        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        from netbox_kea.signals import reservation_updated

        reservation_updated.connect(receiver)
        try:
            with stub_kea(
                {
                    **responses,
                    "reservation-get": queued(_res_get(current), _res_get(current), _res_get(intended)),
                    "reservation-update": {"result": 0},
                }
            ):
                response = self.client.post(
                    f"{url}?{query}",
                    {
                        "subnet_cidr": "2001:db8::/64",
                        "ip_addresses": "2001:db8::21,2001:db8::22",
                        "prefixes": "2001:db8:200::/56",
                        "identifier_type": "duid",
                        "identifier": "00:01:02:03",
                        "hostname": "new6.example.invalid",
                        "managed_fingerprint": fingerprint,
                    },
                )
        finally:
            reservation_updated.disconnect(receiver)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["server"], self.server)
        self.assertIs(received[0]["request"], response.wsgi_request)
        self.assertEqual(received[0]["dhcp_version"], 6)
        self.assertIsNotNone(received[0]["before"])
        self.assertEqual([str(address) for address in received[0]["after"].addresses], intended["ip-addresses"])

    def test_edit_preserves_unexposed_dhcp_option_metadata(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        option = {
            "code": 224,
            "space": "vendor-example",
            "data": "opaque-value",
            "csv-format": False,
            "always-send": False,
            "never-send": True,
            "user-context": {"source": "external"},
        }
        current = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "hostname": "old.example.invalid",
            "option-data": [option],
        }
        intended = {**current, "hostname": "new.example.invalid"}
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        query = _identity_query()
        with stub_kea({**responses, "reservation-get": _res_get(current)}):
            form_page = self.client.get(f"{url}?{query}")
        fingerprint = form_page.context["form"].initial["managed_fingerprint"]

        with stub_kea(
            {
                **responses,
                "reservation-get": queued(_res_get(current), _res_get(current), _res_get(intended)),
                "reservation-update": {"result": 0},
            }
        ) as kea:
            response = self.client.post(
                f"{url}?{query}",
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "hostname": "new.example.invalid",
                    "managed_fingerprint": fingerprint,
                    "options-TOTAL_FORMS": "2",
                    "options-INITIAL_FORMS": "1",
                    "options-MIN_NUM_FORMS": "0",
                    "options-MAX_NUM_FORMS": "1000",
                    "options-0-name": "224",
                    "options-0-data": "opaque-value",
                    "options-1-name": "",
                    "options-1-data": "",
                },
            )

        self.assertEqual(response.status_code, 302)
        sent = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(sent["option-data"], [option])

    def test_edit_rejects_a_tampered_signed_fingerprint(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        current = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
        }
        responses["reservation-get"] = _res_get(current)
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        query = _identity_query()

        with stub_kea(responses) as kea:
            response = self.client.post(
                f"{url}?{query}",
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.21",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "managed_fingerprint": "tampered",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "invalid or expired")
        self.assertEqual(kea.commands(), [])

    def test_delete_confirmation_and_post_use_canonical_identity(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.0.20",
        }
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        query = _identity_query()

        with stub_kea({**responses, "reservation-get": _res_get(raw)}):
            confirmation = self.client.get(f"{url}?{query}")
        self.assertEqual(confirmation.status_code, 200)
        self.assertContains(confirmation, "hw-address aa:bb:cc:dd:ee:ff")

        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        from netbox_kea.signals import reservation_deleted

        reservation_deleted.connect(receiver)
        try:
            with stub_kea(
                {
                    **responses,
                    "reservation-get": queued(_res_get(raw), _res_get(raw), {"result": 3}),
                    "reservation-del": {"result": 0},
                }
            ) as kea:
                response = self.client.post(f"{url}?{query}")
        finally:
            reservation_deleted.disconnect(receiver)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-del"), 1)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["server"], self.server)
        self.assertIs(received[0]["request"], response.wsgi_request)
        self.assertEqual(received[0]["dhcp_version"], 4)
        self.assertIsNotNone(received[0]["before"])
        self.assertIsNone(received[0]["after"])

    def test_delete_returns_to_the_reservation_search(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        reservations = reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk])
        search = f"{reservations}?q=aa%3Abb&cursor=next"

        def target(return_url):
            return f"{url}?{_identity_query()}&{urlencode({'return_url': return_url})}"

        with stub_kea({**responses, "reservation-get": _res_get(raw)}):
            confirmation = self.client.get(target(search))
        self.assertContains(confirmation, f'href="{escape(search)}" class="btn btn-secondary me-2">Cancel</a>')

        for return_url, expected in ((search, search), ("https://evil.example/", reservations)):
            with self.subTest(return_url=return_url):
                deleting = {
                    **responses,
                    "reservation-get": queued(_res_get(raw), _res_get(raw), {"result": 3}),
                    "reservation-del": {"result": 0},
                }
                with stub_kea(deleting):
                    response = self.client.post(target(return_url))
                self.assertRedirects(response, expected, fetch_redirect_response=False)

    def test_delete_invalidates_a_catalogue_cached_during_the_mutation(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        current = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "hostname": "old.example.invalid",
        }
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        query = _identity_query()
        reservation_reads = 0

        def reservation_get(_body):
            nonlocal reservation_reads
            reservation_reads += 1
            # Read 1 runs under the lock, between the scope read and the delete.
            if reservation_reads == 1:
                display(self.server, 4)
            return {"result": 3} if reservation_reads == 2 else _res_get(current)

        responses.update(
            {
                "reservation-get": reservation_get,
                "reservation-del": {"result": 0},
            }
        )
        with stub_kea(responses) as kea:
            response = self.client.post(f"{url}?{query}")
            display(self.server, 4)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("config-get"), 5, kea.commands())

    def test_delete_confirmation_redirects_when_kea_is_unreachable(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["subnet4-list"] = requests.ConnectionError("Kea unavailable")
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        query = _identity_query()

        with stub_kea(responses):
            response = self.client.get(f"{url}?{query}")

        self.assertRedirects(
            response,
            reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk]),
            fetch_redirect_response=False,
        )

    def test_delete_confirmation_returns_not_found_for_an_unknown_identity(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["reservation-get"] = {"result": 3}
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        query = _identity_query()

        with stub_kea(responses):
            response = self.client.get(f"{url}?{query}")

        self.assertEqual(response.status_code, 404)

    def test_delete_fails_closed_when_mutation_capabilities_are_incomplete(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["config-get"]["arguments"]["Dhcp4"]["hooks-libraries"] = []
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        query = _identity_query()

        with stub_kea(responses) as kea:
            response = self.client.post(f"{url}?{query}")

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("reservation-del", kea.commands())


class TestReservationDocumentImport(_ViewTestBase):
    def _url(self):
        return reverse("plugins:netbox_kea:server_reservation4_bulk_import", args=[self.server.pk])

    def test_the_import_page_selects_the_reservations_tab(self):
        for version in (4, 6):
            url = reverse(f"plugins:netbox_kea:server_reservation{version}_bulk_import", args=[self.server.pk])
            with self.subTest(version=version, method="GET"):
                self.assertEqual(active_tabs(self.client.get(url)), ["Reservations"])
            with self.subTest(version=version, method="POST"), stub_kea({}):
                self.assertEqual(
                    active_tabs(self.client.post(url, {"format": "yaml", "document": ""})), ["Reservations"]
                )

    def test_validation_reports_all_errors_before_any_live_request(self):
        document = """version: 1
reservations:
  - family: 4
    scope: {type: in-subnet, subnet: {cidr: 198.18.0.0/24}}
    identity: {type: hw-address, value: invalid}
    addresses: [2001:db8::1]
    delegated_prefixes: []
    hostname: 42
    options: []
"""

        with stub_kea({}) as kea:
            response = self.client.post(self._url(), {"format": "yaml", "document": document})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "reservations[0].identity.value")
        self.assertContains(response, "reservations[0].addresses[0]")
        self.assertContains(response, "reservations[0].hostname")
        self.assertEqual(kea.commands(), [])

    def test_validation_reports_wrong_family_with_other_document_errors(self):
        document = """version: 1
reservations:
  - family: 6
    scope: {type: in-subnet, subnet: {cidr: 2001:db8::/64}}
    identity: {type: duid, value: "00:01:02:03"}
    addresses: []
    delegated_prefixes: []
    hostname: ""
    options: []
  - family: 4
    scope: {type: in-subnet, subnet: {cidr: 198.18.0.0/24}}
    identity: {type: hw-address, value: "aa:bb:cc:dd:ee:01"}
    addresses: []
    delegated_prefixes: []
    hostname: 42
    options: []
"""

        with stub_kea({}) as kea:
            response = self.client.post(self._url(), {"format": "yaml", "document": document})

        self.assertEqual(response.status_code, 200)
        diagnostics = response.context["result"]["diagnostics"]
        self.assertEqual(
            {(diagnostic.code, diagnostic.source_position) for diagnostic in diagnostics},
            {
                ("wrong-family", "reservations[0].family"),
                ("invalid-hostname", "reservations[1].hostname"),
            },
        )
        self.assertEqual(kea.commands(), [])

    def test_json_upload_uses_typed_creation_side_effects_without_ipam_sync(self):
        from extras.models import JournalEntry
        from ipam.models import IPAddress

        option = {
            "code": None,
            "name": "domain-name",
            "space": None,
            "data": "example.invalid",
            "csv_format": False,
            "always_send": True,
            "never_send": False,
        }
        document = {
            "version": 1,
            "reservations": [
                {
                    "family": 4,
                    "scope": {"type": "in-subnet", "subnet": {"cidr": "198.18.0.0/24"}},
                    "identity": {"type": "hw-address", "value": "aa:bb:cc:dd:ee:01"},
                    "addresses": ["198.18.0.20"],
                    "delegated_prefixes": [],
                    "hostname": "upload.example.invalid",
                    "options": [option],
                }
            ],
        }
        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:01",
            "ip-address": "198.18.0.20",
            "hostname": "upload.example.invalid",
            "option-data": [
                {
                    "name": "domain-name",
                    "data": "example.invalid",
                    "csv-format": False,
                    "always-send": True,
                    "never-send": False,
                }
            ],
        }
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})
        upload = SimpleUploadedFile(
            "reservations.json",
            json.dumps(document).encode(),
            content_type="application/json",
        )

        with stub_kea(responses) as kea:
            response = self.client.post(self._url(), {"format": "json", "document_file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_import_counts(response), {"created": 1, "unconfirmed": 0, "not-applied": 0, "not-sent": 0})
        created = kea.bodies("reservation-add")[0]["arguments"]["reservation"]
        self.assertEqual(created, raw)
        self.assertEqual(
            JournalEntry.objects.get(assigned_object_id=self.server.pk).comments,
            "Reservation created: hw-address aa:bb:cc:dd:ee:01; 198.18.0.20",
        )
        self.assertFalse(IPAddress.objects.filter(address="198.18.0.20/24").exists())

    def test_a_failing_journal_entry_still_reports_the_applied_creation(self):
        """The Reservation is already in Kea when the journal entry fails, so it counts as created."""
        from django.contrib.messages import get_messages
        from django.core.exceptions import ValidationError
        from django.db.models.signals import post_save
        from extras.models import JournalEntry

        raw = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:01",
            "ip-address": "198.18.0.20",
            "hostname": "applied.example.invalid",
        }
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(raw)})

        def reject(sender, **kwargs):
            raise ValidationError("journal entry rejected")

        post_save.connect(reject, sender=JournalEntry)
        try:
            with stub_kea(responses) as kea:
                response = self.client.post(self._url(), {"format": "yaml", "document": _document(1)})
        finally:
            post_save.disconnect(reject, sender=JournalEntry)

        self.assertEqual(response.status_code, 200)
        self.assertIn("reservation-add", kea.commands())
        self.assertEqual(_import_counts(response), {"created": 1, "unconfirmed": 0, "not-applied": 0, "not-sent": 0})
        self.assertIn(
            "Kea applied the change, but NetBox could not write the journal entry; see server logs.",
            [str(message) for message in get_messages(response.wsgi_request)],
        )

    def test_import_stops_at_an_unconfirmed_entry_and_records_only_the_applied_entries(self):
        first = {
            "subnet-id": 20,
            "hw-address": "aa:bb:cc:dd:ee:01",
            "ip-address": "198.18.0.20",
            "hostname": "host1.example.invalid",
        }
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses.update(
            {
                "reservation-add": queued({"result": 0}, {"result": 1, "text": "conflict"}),
                "reservation-get": _res_get(first),
            }
        )
        received = []

        def receiver(sender, **kwargs):
            received.append(kwargs)

        from netbox_kea.signals import reservation_created

        reservation_created.connect(receiver)
        try:
            with stub_kea(responses) as kea:
                response = self.client.post(self._url(), {"format": "yaml", "document": _document(3)})
        finally:
            reservation_created.disconnect(receiver)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_import_counts(response), {"created": 1, "unconfirmed": 1, "not-applied": 0, "not-sent": 1})
        self.assertEqual(kea.commands().count("reservation-add"), 2)
        self.assertEqual(len(received), 1)
        self.assertEqual(
            _import_rows(response),
            {
                "created": ("Entries that Kea created", [("reservations[0]", "hw-address aa:bb:cc:dd:ee:01")]),
                "unconfirmed": (
                    "Entry that Kea did not confirm",
                    [
                        (
                            "reservations[1]",
                            "hw-address aa:bb:cc:dd:ee:02",
                            (
                                "Kea did not confirm the change. Check the server configuration before retrying."
                                " NetBox recorded nothing for this change. Kea replied: conflict"
                            ),
                        )
                    ],
                ),
                "not-sent": (
                    "Entries that NetBox did not send",
                    [
                        (
                            "reservations[2]",
                            "hw-address aa:bb:cc:dd:ee:03",
                            "NetBox stopped at an earlier entry and did not send this entry.",
                        )
                    ],
                ),
            },
        )
        self.assertContains(response, "Kea did not confirm one entry, so NetBox stopped there.")

    def test_import_stops_at_a_rejected_entry(self):
        first = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.20"}
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses.update(
            {
                "reservation-add": queued({"result": 0}, {"result": 2, "text": "not supported"}),
                "reservation-get": _res_get(first),
            }
        )

        with stub_kea(responses) as kea:
            response = self.client.post(self._url(), {"format": "yaml", "document": _document(3)})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_import_counts(response), {"created": 1, "unconfirmed": 0, "not-applied": 1, "not-sent": 1})
        self.assertEqual(kea.commands().count("reservation-add"), 2)
        heading, rows = _import_rows(response)["not-applied"]
        self.assertEqual(heading, "Entries that Kea did not apply")
        self.assertEqual(rows[0][:2], ("reservations[1]", "hw-address aa:bb:cc:dd:ee:02"))
        self.assertIn("Kea rejected the change.", rows[0][2])
        self.assertNotContains(response, "Kea did not confirm one entry")
        self.assertContains(
            response, "NetBox stopped at the entry that was not applied and did not send the entries after it."
        )

    def test_a_created_entry_that_kea_did_not_save_or_verify_carries_a_note(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses.update(
            {
                "reservation-add": {"result": 0},
                "reservation-get": {"result": 3},
                "config-write": {"result": 1, "text": "read-only file"},
            }
        )

        with stub_kea(responses):
            response = self.client.post(self._url(), {"format": "yaml", "document": _document(1)})

        _heading, rows = _import_rows(response)["created"]
        self.assertEqual(
            rows,
            [
                (
                    "reservations[0]",
                    "hw-address aa:bb:cc:dd:ee:01",
                    (
                        "It is live, but it may not survive a Kea restart, because Kea did not save it to disk."
                        " config-write failed: read-only file"
                        " Kea applied the change, but NetBox Kea could not verify the final Reservation."
                    ),
                )
            ],
        )


def _document(entries: int) -> str:
    """Return a YAML Reservation document with *entries* DHCPv4 entries in 198.18.0.0/24."""
    lines = ["version: 1", "reservations:"]
    for index in range(1, entries + 1):
        lines += [
            "  - family: 4",
            "    scope: {type: in-subnet, subnet: {cidr: 198.18.0.0/24}}",
            f'    identity: {{type: hw-address, value: "aa:bb:cc:dd:ee:{index:02x}"}}',
            f"    addresses: [198.18.0.{19 + index}]",
            "    delegated_prefixes: []",
            f"    hostname: host{index}.example.invalid",
            "    options: []",
        ]
    return "\n".join(lines) + "\n"


def _import_counts(response) -> dict[str, int]:
    """Return the number of entries of each status of an import report."""
    return {group.status: len(group.rows) for group in response.context["result"]["groups"]}


def _import_rows(response) -> dict[str, tuple[str, list[tuple[str, ...]]]]:
    """Return the heading and the table rows of each rendered section of an import report."""
    page = BeautifulSoup(response.content, "html.parser")
    report = {}
    for section in page.select("section[data-import-status]"):
        heading = section.find("h6")
        rows = [tuple(cell.get_text(strip=True) for cell in row.select("td")) for row in section.select("tbody tr")]
        report[str(section["data-import-status"])] = (heading.get_text(strip=True) if heading else "", rows)
    return report


_IMPORT_DOCUMENT = """version: 1
reservations:
  - family: 4
    scope: {type: in-subnet, subnet: {cidr: 198.18.0.0/24}}
    identity: {type: hw-address, value: "aa:bb:cc:dd:ee:01"}
    addresses: [198.18.0.10]
    delegated_prefixes: []
    hostname: ""
    options: []
"""


class TestReservationTargetReadFailures(_ViewTestBase):
    """An exact Reservation load that fails shows the shared Reservation headline and Kea's answer, never a 500."""

    _CURRENT = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "old.example.invalid"}

    def _url(self, action: str) -> str:
        url = reverse(f"plugins:netbox_kea:server_reservation4_{action}", args=[self.server.pk, 20])
        return f"{url}?{_identity_query()}"

    def _messages(self, response) -> list[str]:
        return [str(message) for message in get_messages(response.wsgi_request)]

    def _expected(self, line: str | None) -> list[str]:
        return [HEADLINES["reservation_target"], *([line] if line else [])]

    def test_the_edit_and_delete_pages_show_the_reservation_notice(self):
        for action in ("edit", "delete"):
            for name, reply, line in READ_FAILURES:
                with self.subTest(action=action, failure=name):
                    self._fresh_client()
                    responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
                    with stub_kea({**responses, "reservation-get": reply}):
                        response = self.client.get(self._url(action))
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(self._messages(response), self._expected(line))

    def test_the_edit_save_shows_the_reservation_notice_and_sends_no_change(self):
        for name, reply, line in READ_FAILURES:
            with self.subTest(failure=name):
                self._fresh_client()
                responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
                token = _open_edit_token(self.client, self._url("edit"), responses, self._CURRENT)
                with stub_kea({**responses, "reservation-get": reply}) as kea:
                    response = self.client.post(
                        self._url("edit"), {"hostname": "new.example.invalid", "managed_fingerprint": token}
                    )
                self.assertEqual(response.status_code, 302)
                self.assertNotIn("reservation-update", kea.commands())
                self.assertEqual(self._messages(response), self._expected(line))

    def test_a_failed_subnet_list_read_shows_the_catalogue_notice(self):
        """The Subnet of the Reservation cannot be confirmed, so the page shows the Catalogue Notice with Kea's text."""
        for action, method in (("edit", "get"), ("edit", "post"), ("delete", "get")):
            for name, reply, _line in READ_FAILURES:
                with self.subTest(action=action, method=method, failure=name):
                    self._fresh_client()
                    responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
                    data = {}
                    if method == "post":
                        data["managed_fingerprint"] = _open_edit_token(
                            self.client, self._url(action), responses, self._CURRENT
                        )
                    responses.update({"subnet4-list": reply, "reservation-get": _res_get(self._CURRENT)})
                    with stub_kea(responses) as kea:
                        response = getattr(self.client, method)(self._url(action), data)
                    self.assertEqual(response.status_code, 302)
                    self.assertNotIn("reservation-get", kea.commands())
                    self.assertEqual(self._messages(response), [HEADLINES["catalogue"], SUBNET_LIST_FAILURES[name]])

    def test_a_reservation_record_that_cannot_be_read_is_a_malformed_reply(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        malformed = _res_get({**self._CURRENT, "hostname": 42})
        for action in ("edit", "delete"):
            with self.subTest(action=action):
                self._fresh_client()
                with stub_kea({**responses, "reservation-get": malformed}):
                    response = self.client.get(self._url(action))
                self.assertEqual(response.status_code, 302)
                self.assertEqual(self._messages(response), self._expected(None))


class TestReservationImportReadFailures(_ViewTestBase):
    """The live reads that validate an import show the shared Notice as form errors."""

    def _post(self, responses: dict):
        url = reverse("plugins:netbox_kea:server_reservation4_bulk_import", args=[self.server.pk])
        with stub_kea(responses) as kea:
            response = self.client.post(url, {"format": "yaml", "document": _IMPORT_DOCUMENT})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([command for command in kea.commands() if command.startswith("reservation-")], [])
        return list(response.context["form"].non_field_errors())

    def test_a_failed_configuration_read_shows_the_configuration_notice(self):
        for name, reply, line in READ_FAILURES:
            with self.subTest(name):
                errors = self._post({"config-get": reply})
                self.assertEqual(errors[0], HEADLINES["configuration"])
                if line:
                    self.assertEqual(errors[1:], [f"Kea configuration facts are unavailable. {line}"])

    def test_a_failed_subnet_list_read_shows_the_catalogue_notice(self):
        for name, reply, _line in READ_FAILURES:
            with self.subTest(name):
                responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
                errors = self._post({**responses, "subnet4-list": reply})
                self.assertEqual(errors, [HEADLINES["catalogue"], SUBNET_LIST_FAILURES[name]])

    def test_a_server_without_host_cmds_names_the_missing_hook(self):
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["config-get"]["arguments"]["Dhcp4"]["hooks-libraries"] = []
        self.assertEqual(self._post(responses), ["The host_cmds hook is not loaded."])


class TestMutationCapabilityGate(_ViewTestBase):
    """A direct POST must never reach Kea when no mutation capability is confirmed.

    Each handler must redirect before it validates a form or reads a mutation target.
    These tests also assert that no ``reservation-*`` mutation command is issued, so a
    replayed or hand-built POST cannot slip past the disabled save control.
    """

    def _responses_without_mutation(self, subnet_id=20, cidr="198.18.0.0/24"):
        responses = _mutation_responses(4, subnet_id, cidr, ["hw-address"])
        # The host_cmds hook is not loaded.
        responses["config-get"]["arguments"]["Dhcp4"]["hooks-libraries"] = []
        # The rejection redirects to the reservation list, which renders on follow.
        responses["reservation-get-page"] = _res_page([])
        responses["lease4-get-by-state"] = {"result": 0, "arguments": {"leases": []}}
        return responses

    def _add_payload(self):
        return {
            "subnet_cidr": "198.18.0.0/24",
            "ip_address": "198.18.0.20",
            "identifier_type": "hw-address",
            "identifier": "aa:bb:cc:dd:ee:ff",
            "hostname": "host.example.invalid",
        }

    def test_add_post_is_rejected_without_mutation_capabilities(self):
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])
        return_url = reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk])

        with stub_kea(self._responses_without_mutation()) as kea:
            response = self.client.post(url, self._add_payload(), follow=True)

        self.assertRedirects(response, return_url)
        self.assertNotIn("reservation-add", kea.commands())
        self.assertContains(response, "Reservation mutation capabilities are unavailable.")

    def test_add_post_is_rejected_when_the_capability_read_fails(self):
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])
        return_url = reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk])
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses.update(
            {
                "config-get": queued(RuntimeError("capability read failed"), responses["config-get"]),
                "reservation-get-page": _res_page([]),
                "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
            }
        )

        with stub_kea(responses) as kea:
            response = self.client.post(url, self._add_payload(), follow=True)

        self.assertRedirects(response, return_url)
        self.assertNotIn("reservation-add", kea.commands())
        self.assertContains(response, "Reservation mutation capabilities are unavailable.")

    def test_edit_post_is_rejected_without_mutation_capabilities(self):
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        return_url = reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk])
        query = _identity_query()
        responses = self._responses_without_mutation()
        good = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        token = _open_edit_token(
            self.client,
            f"{url}?{query}",
            good,
            {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"},
        )

        with stub_kea(responses) as kea:
            response = self.client.post(
                f"{url}?{query}",
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "hostname": "new.example.invalid",
                    "managed_fingerprint": token,
                },
                follow=True,
            )

        self.assertRedirects(response, return_url)
        self.assertNotIn("reservation-get", kea.commands())
        self.assertNotIn("reservation-update", kea.commands())
        self.assertContains(response, "Reservation mutation capabilities are unavailable.")

    def test_delete_post_stays_rejected_without_mutation_capabilities(self):
        url = reverse("plugins:netbox_kea:server_reservation4_delete", args=[self.server.pk, 20])
        query = _identity_query()

        with stub_kea(self._responses_without_mutation()) as kea:
            response = self.client.post(f"{url}?{query}", follow=True)

        self.assertNotIn("reservation-del", kea.commands())
        self.assertContains(response, "Reservation mutation capabilities are unavailable.")


class TestReservationFormFieldHelp(_ViewTestBase):
    """The Reservation form explains identifiers and IPAM sync in field help, not in alert boxes."""

    def _add_page(self, identifiers: list[str]) -> BeautifulSoup:
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])
        with stub_kea(_mutation_responses(4, 20, "198.18.0.0/24", identifiers)):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.content, "html.parser")

    def test_no_info_alerts_remain(self):
        page = self._add_page(["hw-address"])
        alerts = " ".join(alert.get_text() for alert in page.select(".alert"))
        for text in ("Relay remote ID", "host-reservation-identifiers", "Automatic IPAM sync is"):
            self.assertNotIn(text, alerts)
        self.assertIn("Automatic IPAM sync is", page.select_one("#id_sync_to_netbox_helptext").get_text())
        self.assertIn("host-reservation-identifiers", page.select_one("#id_identifier_type_helptext").get_text())

    def test_unavailable_identifiers_add_a_keyboard_reachable_tooltip(self):
        tip = self._add_page(["hw-address"]).select_one("#id_identifier_type_helptext button")
        self.assertEqual(tip["type"], "button")
        self.assertEqual(tip["data-bs-toggle"], "tooltip")
        expected = "Disabled types are not in the live host-reservation-identifiers configuration."
        self.assertEqual(tip["data-bs-title"], expected)
        self.assertEqual(tip.select_one(".visually-hidden").get_text(), expected)

    def test_all_identifiers_available_show_no_tooltip(self):
        page = self._add_page(["hw-address", "duid", "circuit-id", "client-id", "flex-id"])
        self.assertIsNone(page.select_one("#id_identifier_type_helptext button"))
        self.assertIsNotNone(page.select_one("#id_identifier_type_helptext a"))

    def test_sync_help_states_whether_automatic_ipam_sync_is_on(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                self.server.sync_enabled = enabled
                self.server.sync_reservations_enabled = True
                self.server.save()
                help_text = self._add_page(["hw-address"]).select_one("#id_sync_to_netbox_helptext")
                state = "enabled" if enabled else "disabled"
                self.assertIn(f"Automatic IPAM sync is {state} for this Server.", help_text.get_text())
                tip = help_text.select_one("button")["data-bs-title"]
                self.assertIn("A Reservation with no address is skipped.", tip)
                self.assertEqual("The next scheduled sync run records a fixed address." in tip, enabled)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestReservationSideEffectAfterApplied(TransactionTestCase):
    """A side effect runs after Kea applied the Reservation, so its failure never reads as a Kea failure (ADR 0012)."""

    def test_an_applied_add_whose_ipam_sync_events_fail_reports_the_reservation_and_a_separate_error(self):
        from django.contrib import messages
        from django.contrib.auth import get_user_model
        from django.contrib.messages import get_messages
        from extras.models import JournalEntry
        from ipam.models import IPAddress

        from netbox_kea.event_scope import _NESTED_TRACKING

        if not _NESTED_TRACKING:
            self.skipTest("Before NetBox 4.6.9 a claim row is a plain transaction and dispatches with the request")
        user = get_user_model().objects.create_superuser(username="reservation-dispatch", password="dispatch-pass")
        self.client.force_login(user)
        server = _make_db_server()
        raw = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.0.20"}
        responses = {
            **_mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"]),
            "reservation-add": {"result": 0},
            "reservation-get": _res_get(raw),
        }
        with (
            override_settings(EVENTS_PIPELINE=["netbox_kea.tests.test_sync_views.fail_ip_address_dispatch"]),
            stub_kea(responses) as kea,
            self.assertLogs("netbox_kea.views", "ERROR") as logs,
        ):
            response = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[server.pk]),
                {
                    "subnet_cidr": "198.18.0.0/24",
                    "ip_address": "198.18.0.20",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:ff",
                    "sync_to_netbox": "on",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("reservation-add"), 1)
        self.assertTrue(IPAddress.objects.filter(address__net_host="198.18.0.20").exists())
        self.assertTrue(JournalEntry.objects.filter(assigned_object_id=server.pk).exists())
        shown = [(message.level, str(message)) for message in get_messages(response.wsgi_request)]
        self.assertIn((messages.SUCCESS, "Reservation created."), shown)
        self.assertIn(
            (
                messages.ERROR,
                (
                    "Reservation created, and NetBox IPAM sync saved it, but NetBox could not dispatch the events of"
                    " the sync; see server logs."
                ),
            ),
            shown,
        )
        self.assertFalse(any("could not be created" in text for _level, text in shown), shown)
        self.assertIn("EventDispatchError", "\n".join(logs.output))
