# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A connection change makes the cached Server Configuration and Catalogue Snapshots unreachable."""

from django.db import transaction
from django.urls import reverse
from rest_framework.test import APIClient

from netbox_kea import server_configuration, subnet_catalogue
from netbox_kea.models import Server

from .kea_stub import _catalogue_responses_for_subnets, stub_kea
from .utils import _ViewTestBase

_OLD_URL = "https://old-kea.example.invalid"
_NEW_URL = "https://new-kea.example.invalid"
_THIRD_URL = "https://third-kea.example.invalid"
_VERSION_GET = {"version-get": {"result": 0, "arguments": {"extended": "3.2.0"}}}
# The Subnets page reads lease statistics; a daemon without the stat hook answers this.
_NO_STAT_HOOK = {"stat-lease4-get": {"result": 2, "text": "unknown command"}}


class ServerSaveCacheTest(_ViewTestBase):
    def setUp(self):
        super().setUp()
        self.server.dhcp4_url = _OLD_URL
        self.server.dhcp6 = False
        self.server.save()
        self.responses = {
            **_catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.1.0/24"}]),
            **_VERSION_GET,
        }

    def _edit(self) -> dict:
        return {
            "name": self.server.name,
            "ca_url": self.server.ca_url,
            "dhcp4_url": _NEW_URL,
            "dhcp4": True,
            "dhcp6": False,
            "ssl_verify": True,
            "has_control_agent": True,
        }

    def _read_display(self, server: Server, responses: dict, family: int = 4):
        with stub_kea(responses) as kea:
            subnet_catalogue.display(server, family)
            server_configuration.display(server, family)
        return kea

    def _fill_display_cache(self, family: int = 4, responses: dict | None = None) -> None:
        responses = self.responses if responses is None else responses
        self.assertEqual(set(self._read_display(self.server, responses, family).urls()), {_OLD_URL})
        self.assertEqual(self._read_display(self.server, {}, family).requests, [], "the second read is cached")

    def test_a_connection_edit_makes_the_next_display_read_reach_the_new_url(self):
        self._fill_display_cache()

        with stub_kea(self.responses) as kea, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_edit", args=[self.server.pk]), self._edit())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.urls(), [_NEW_URL], "the edit checks the new connection")

        self.server.refresh_from_db()
        kea = self._read_display(self.server, self.responses)
        self.assertEqual(kea.commands(), ["subnet4-list", "config-get", "config-get"])
        self.assertEqual(set(kea.urls()), {_NEW_URL})

    def test_a_url_edit_makes_the_subnets_page_show_the_subnets_of_the_new_daemon(self):
        page = reverse("plugins:netbox_kea:server_subnets4", args=[self.server.pk])
        old_daemon = {**self.responses, **_NO_STAT_HOOK}
        new_daemon = {
            **old_daemon,
            **_catalogue_responses_for_subnets(4, [{"id": 2, "subnet": "198.18.2.0/24"}]),
        }
        with stub_kea(old_daemon) as kea:
            self.assertContains(self.client.get(page), "198.18.1.0/24")
            self.assertContains(self.client.get(page), "198.18.1.0/24")
        self.assertEqual(kea.commands().count("subnet4-list"), 1, "the second page load reads the cached Catalogue")

        with stub_kea(_VERSION_GET), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_edit", args=[self.server.pk]), self._edit())
        self.assertEqual(response.status_code, 302)

        with stub_kea(new_daemon) as kea:
            response = self.client.get(page)
        self.assertContains(response, "198.18.2.0/24")
        self.assertNotContains(response, "198.18.1.0/24")
        self.assertIn("subnet4-list", kea.commands())
        self.assertIn("config-get", kea.commands())
        self.assertEqual(set(kea.urls()), {_NEW_URL})

    def test_a_ca_url_change_through_the_rest_api_makes_the_next_read_of_both_families_reach_the_new_url(self):
        Server.objects.filter(pk=self.server.pk).update(ca_url=_OLD_URL, dhcp4_url="", dhcp6=True)
        self.server.refresh_from_db()
        responses = {
            family: {**_catalogue_responses_for_subnets(family, [{"id": 1, "subnet": subnet}]), **_VERSION_GET}
            for family, subnet in ((4, "198.18.1.0/24"), (6, "2001:db8:1::/64"))
        }
        for family in (4, 6):
            self._fill_display_cache(family, responses[family])

        api = APIClient()
        api.force_authenticate(user=self.user)
        with stub_kea(_VERSION_GET):
            response = api.patch(
                reverse("plugins-api:netbox_kea-api:server-detail", args=[self.server.pk]),
                {"ca_url": _NEW_URL},
                format="json",
            )
        self.assertEqual(response.status_code, 200, response.data)

        self.server.refresh_from_db()
        for family in (4, 6):
            with self.subTest(family=family):
                kea = self._read_display(self.server, responses[family], family)
                self.assertEqual(kea.commands(), [f"subnet{family}-list", "config-get", "config-get"])
                self.assertEqual(set(kea.urls()), {_NEW_URL})

    def test_a_rolled_back_url_save_keeps_the_entry_of_the_committed_url(self):
        self._fill_display_cache()

        with self.assertRaises(RuntimeError), transaction.atomic():
            uncommitted = Server.objects.get(pk=self.server.pk)
            uncommitted.dhcp4_url = _NEW_URL
            uncommitted.save()
            with stub_kea(self.responses) as kea:
                subnet_catalogue.display(uncommitted, 4)
            self.assertEqual(set(kea.urls()), {_NEW_URL}, "the uncommitted URL reads its own endpoint")
            raise RuntimeError("roll back")

        self.server.refresh_from_db()
        self.assertEqual(self.server.dhcp4_url, _OLD_URL)
        kea = self._read_display(self.server, {})
        self.assertEqual(kea.requests, [], "the committed URL keeps the entry read from it")

    def test_a_queryset_update_of_the_url_makes_the_next_display_read_reach_the_new_url(self):
        self._fill_display_cache()

        Server.objects.filter(pk=self.server.pk).update(dhcp4_url=_NEW_URL)

        self.server.refresh_from_db()
        kea = self._read_display(self.server, self.responses)
        self.assertEqual(set(kea.urls()), {_NEW_URL})

    def test_a_server_loaded_before_the_edit_cannot_fill_the_entry_of_the_new_url(self):
        stale = Server.objects.get(pk=self.server.pk)
        with stub_kea(self.responses), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_edit", args=[self.server.pk]), self._edit())
        self.assertEqual(response.status_code, 302)

        with stub_kea(self.responses) as kea:
            subnet_catalogue.display(stale, 4)
        self.assertEqual(set(kea.urls()), {_OLD_URL})

        self.server.refresh_from_db()
        with stub_kea(self.responses) as kea:
            subnet_catalogue.display(self.server, 4)
        self.assertEqual(set(kea.urls()), {_NEW_URL})

    def test_a_server_saved_after_the_edit_from_an_old_load_cannot_fill_the_entry_of_the_new_url(self):
        stale = Server.objects.get(pk=self.server.pk)
        with stub_kea(self.responses), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_edit", args=[self.server.pk]), self._edit())
        self.assertEqual(response.status_code, 302)
        stale.name = "renamed from an old load"
        stale.save(update_fields=["name"])

        kea = self._read_display(stale, self.responses)
        self.assertEqual(set(kea.urls()), {_OLD_URL})

        self.server.refresh_from_db()
        kea = self._read_display(self.server, self.responses)
        self.assertEqual(set(kea.urls()), {_NEW_URL})

    def test_an_edit_that_changes_no_connection_setting_keeps_the_cached_entry(self):
        self._fill_display_cache()
        edit = {**self._edit(), "dhcp4_url": _OLD_URL, "name": "renamed"}

        with stub_kea({}) as kea, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_edit", args=[self.server.pk]), edit)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.requests, [], "the edit changes no connection, so it sends no connection check")

        self.server.refresh_from_db()
        self.assertEqual(self.server.name, "renamed")
        kea = self._read_display(self.server, {})
        self.assertEqual(kea.requests, [])

    def test_a_save_that_names_a_connection_field_makes_the_next_display_read_reach_the_new_url(self):
        self._fill_display_cache()
        saves = (
            (lambda: self.server, _NEW_URL, lambda server: server.save(update_fields=["dhcp4_url"])),
            (lambda: Server.objects.only("pk", "dhcp4_url").get(pk=self.server.pk), _THIRD_URL, Server.save),
        )
        for load, url, save in saves:
            with self.subTest(url=url):
                server = load()
                server.dhcp4_url = url
                save(server)

                self.server.refresh_from_db()
                kea = self._read_display(self.server, self.responses)
                self.assertEqual(set(kea.urls()), {url})

    def test_each_connection_setting_changes_the_display_generation(self):
        own_v6_url = {"dhcp6_url": _THIRD_URL}
        cases = (
            ("ca_url", _NEW_URL, 6, {}),
            ("ca_username", "operator", 4, {}),
            ("ca_password", "new-secret", 4, {}),
            ("dhcp6_url", _NEW_URL, 6, {}),
            ("dhcp6_username", "operator", 6, own_v6_url),
            ("dhcp6_password", "new-secret", 6, own_v6_url),
            ("dhcp4_url", _NEW_URL, 4, {}),
            ("dhcp4_username", "operator", 4, {}),
            ("dhcp4_password", "new-secret", 4, {}),
            ("ssl_verify", False, 4, {}),
            ("ca_file_path", "/etc/ssl/kea-ca.pem", 4, {}),
            ("client_cert_path", "/etc/ssl/client.pem", 4, {}),
            ("client_key_path", "/etc/ssl/client.key", 4, {}),
            ("has_control_agent", False, 4, {}),
        )
        for field, value, family, base in cases:
            with self.subTest(field=field):
                server = Server.objects.get(pk=self.server.pk)
                for name, setting in base.items():
                    setattr(server, name, setting)
                before = server_configuration.display_generation(server, family)
                setattr(server, field, value)
                self.assertNotEqual(server_configuration.display_generation(server, family), before)

    def test_a_sync_enabled_toggle_keeps_the_cached_entry(self):
        self._fill_display_cache()

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk]))
        self.assertEqual(response.status_code, 302)

        self.server.refresh_from_db()
        self.assertFalse(self.server.sync_enabled)
        kea = self._read_display(self.server, {})
        self.assertEqual(kea.requests, [])

    def test_a_receipt_only_save_keeps_the_cached_entry(self):
        self._fill_display_cache()

        with self.captureOnCommitCallbacks(execute=True):
            self.server.ipam_initial_observations = {"leases": True}
            self.server.save(update_fields=["ipam_initial_observations", "ipam_first_complete_at"])

        kea = self._read_display(self.server, {})
        self.assertEqual(kea.requests, [])
