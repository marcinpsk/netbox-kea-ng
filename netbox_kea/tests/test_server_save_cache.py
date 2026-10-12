# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A connection change makes the cached Server Configuration and Catalogue Snapshots unreachable."""

from django.test import override_settings
from django.urls import reverse

from netbox_kea import server_configuration, subnet_catalogue
from netbox_kea.models import Server

from .kea_stub import _catalogue_responses_for_subnets, stub_kea
from .utils import _PLUGINS_CONFIG, _ViewTestBase

_OLD_URL = "https://old-v4.example.invalid"
_NEW_URL = "https://new-v4.example.invalid"
_THIRD_URL = "https://third-v4.example.invalid"


@override_settings(PLUGINS_CONFIG=_PLUGINS_CONFIG)
class ServerSaveCacheTest(_ViewTestBase):
    def setUp(self):
        super().setUp()
        self.server.dhcp4_url = _OLD_URL
        self.server.dhcp6 = False
        self.server.save()
        self.responses = {
            **_catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.1.0/24"}]),
            "version-get": {"result": 0, "arguments": {"extended": "3.2.0"}},
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

    def _fill_display_cache(self) -> None:
        with stub_kea(self.responses) as kea:
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
            sent = len(kea.requests)
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
        self.assertEqual(set(kea.urls()), {_OLD_URL})
        self.assertEqual(len(kea.requests), sent, "the second display read comes from the cache")

    def test_a_connection_edit_makes_the_next_display_read_reach_the_new_url(self):
        self._fill_display_cache()

        with stub_kea(self.responses) as kea, self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_edit", args=[self.server.pk]), self._edit())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.urls(), [_NEW_URL], "the edit checks the new connection")

        self.server.refresh_from_db()
        with stub_kea(self.responses) as kea:
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
        self.assertEqual(kea.commands(), ["subnet4-list", "config-get", "config-get"])
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

        with stub_kea(self.responses) as kea:
            subnet_catalogue.display(stale, 4)
            server_configuration.display(stale, 4)
        self.assertEqual(set(kea.urls()), {_OLD_URL})

        self.server.refresh_from_db()
        with stub_kea(self.responses) as kea:
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
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
        with stub_kea({}) as kea:
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
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
                with stub_kea(self.responses) as kea:
                    subnet_catalogue.display(self.server, 4)
                    server_configuration.display(self.server, 4)
                self.assertEqual(set(kea.urls()), {url})

    def test_each_connection_setting_changes_the_display_generation(self):
        changes = {
            "dhcp4_url": _NEW_URL,
            "dhcp4_username": "operator",
            "dhcp4_password": "new-secret",
            "ssl_verify": False,
            "ca_file_path": "/etc/ssl/kea-ca.pem",
            "client_cert_path": "/etc/ssl/client.pem",
            "client_key_path": "/etc/ssl/client.key",
            "has_control_agent": False,
        }
        before = server_configuration.display_generation(self.server, 4)
        for field, value in changes.items():
            with self.subTest(field=field):
                server = Server.objects.get(pk=self.server.pk)
                setattr(server, field, value)
                self.assertNotEqual(server_configuration.display_generation(server, 4), before)

    def test_a_sync_enabled_toggle_keeps_the_cached_entry(self):
        self._fill_display_cache()

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk]))
        self.assertEqual(response.status_code, 302)

        self.server.refresh_from_db()
        self.assertFalse(self.server.sync_enabled)
        with stub_kea({}) as kea:
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
        self.assertEqual(kea.requests, [])

    def test_a_receipt_only_save_keeps_the_cached_entry(self):
        self._fill_display_cache()

        with self.captureOnCommitCallbacks(execute=True):
            self.server.ipam_initial_observations = {"leases": True}
            self.server.save(update_fields=["ipam_initial_observations", "ipam_first_complete_at"])

        with stub_kea({}) as kea:
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
        self.assertEqual(kea.requests, [])
