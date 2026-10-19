# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A Server whose Kea client cannot be built names its client settings on every page that acts on Kea.

A Runtime Change gives the rejection of the shared mapper instead, as a Configuration Change does.

``Server.get_client()`` sends nothing, so its ``ValueError`` is a Server setting error, never a connection failure, a
Kea reply error or an internal error. Each test saves a client key without a certificate with ``.update()``, drives
the real view, and checks that no Kea command was sent.
"""

from django.contrib.messages import get_messages
from django.urls import reverse
from django.utils.html import escape

from netbox_kea.models import Server
from netbox_kea.views.notices import HEADLINES

from .kea_stub import (
    LeaseDaemon,
    _catalogue_responses_for_subnets,
    _host_cmds_hooks,
    _res_get,
    redirect_to_netrc_host,
    stub_kea,
)
from .test_lease_actions import _address4, _inputs
from .utils import INVALID_SERVER_SETTINGS, _ViewTestBase, save_key_without_certificate

_IDENTITY = {"identifier_type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff"}


def _messages(response) -> list[str]:
    return [str(message) for message in get_messages(response.wsgi_request)]


class CredentialEncodingTest(_ViewTestBase):
    """Credentials that requests cannot encode are a transport failure of the read, never a 500 reply.

    The Server form refuses them in its connectivity check, but a row can hold them from another path.
    """

    def setUp(self):
        super().setUp()
        # No stub: requests encodes the Basic Auth header before it opens a connection.
        Server.objects.filter(pk=self.server.pk).update(
            ca_url="http://127.0.0.1:1/", ca_username="kea", ca_password="pass\u20ac"
        )

    def _url(self, name: str, *args) -> str:
        return reverse(f"plugins:netbox_kea:{name}", args=[self.server.pk, *args])

    def test_the_lease_reads_show_the_lease_notice(self):
        for name, url, kind in (
            ("export all", self._url("server_leases4") + "?export_all=1", "lease"),
            ("edit", self._url("server_lease4_edit", "192.0.2.40"), "lease_target"),
        ):
            with self.subTest(name):
                self._fresh_client()
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(_messages(response), [HEADLINES[kind]])

    def test_an_encode_failure_after_the_send_is_the_transport_notice_of_the_read(self):
        Server.objects.filter(pk=self.server.pk).update(ca_url="http://kea.example.invalid/", ca_password="ascii")
        with redirect_to_netrc_host() as sent:
            response = self.client.get(self._url("server_lease4_edit", "192.0.2.40"))
        self.assertEqual(len(sent), 1)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(_messages(response), [HEADLINES["lease_target"]])

    def test_the_reservation_export_is_a_502_reply_with_the_reservation_notice(self):
        response = self.client.get(self._url("server_reservations4"), {"export": "yaml"})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.content.decode(), HEADLINES["reservation"])


class ClientSettingsErrorTest(_ViewTestBase):
    def _url(self, name: str, *args) -> str:
        return reverse(f"plugins:netbox_kea:{name}", args=[self.server.pk, *args])

    def test_runtime_changes_are_not_sent_with_invalid_server_settings(self):
        """A Runtime Change gives the rejection of the shared mapper, as a Configuration Change does (ADR 0011)."""
        for name, data in (("server_dhcp4_enable", {}), ("server_dhcp4_disable", {"confirm": "True"})):
            with self.subTest(name):
                self._fresh_client()
                save_key_without_certificate(self.server)
                with stub_kea({}) as kea:
                    response = self.client.post(self._url(name), data)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(kea.commands(), [])
                self.assertEqual(_messages(response), [INVALID_SERVER_SETTINGS])

    def test_the_export_of_all_leases_names_the_client_settings(self):
        expected = save_key_without_certificate(self.server)
        with stub_kea({}) as kea:
            response = self.client.get(self._url("server_leases4"), {"export_all": "1"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), [])
        self.assertEqual(_messages(response), [expected])

    def test_the_lease_edit_page_names_the_client_settings(self):
        expected = save_key_without_certificate(self.server)
        with stub_kea({}) as kea:
            response = self.client.get(self._url("server_lease4_edit", "192.0.2.40"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), [])
        self.assertEqual(_messages(response), [expected])

    def test_a_lease_edit_save_is_not_sent_with_invalid_server_settings(self):
        url = self._url("server_lease4_edit", "192.0.2.40")
        with stub_kea(LeaseDaemon(4, _address4()).responses()):
            form = _inputs(self.client.get(url))
        save_key_without_certificate(self.server)
        with stub_kea({}) as kea:
            response = self.client.post(url, {**form, "hostname": "renamed.example.org"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), [])
        self.assertEqual(_messages(response), [f"Lease 192.0.2.40: {INVALID_SERVER_SETTINGS}"])

    def test_a_lease_add_is_not_sent_with_invalid_server_settings(self):
        save_key_without_certificate(self.server)
        with stub_kea({}) as kea:
            response = self.client.post(
                self._url("server_lease4_add"), {"ip_address": "192.0.2.50", "hw_address": "aa:bb:cc:00:00:50"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertEqual(_messages(response), [f"Lease 192.0.2.50: {INVALID_SERVER_SETTINGS}"])

    def test_a_lease_sync_row_names_the_client_settings(self):
        expected = save_key_without_certificate(self.server)
        with stub_kea({}) as kea:
            response = self.client.post(self._url("server_lease4_sync"), {"ip_address": "192.0.2.40"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertContains(response, escape(expected))

    def test_a_reservation_import_names_the_client_settings(self):
        document = """version: 1
reservations:
  - family: 4
    scope: {type: in-subnet, subnet: {cidr: 198.18.0.0/24}}
    identity: {type: hw-address, value: "aa:bb:cc:dd:ee:01"}
    addresses: [198.18.0.10]
    delegated_prefixes: []
    hostname: ""
    options: []
"""
        expected = save_key_without_certificate(self.server)
        with stub_kea({}) as kea:
            response = self.client.post(
                self._url("server_reservation4_bulk_import"), {"format": "yaml", "document": document}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertContains(response, escape(expected))

    def test_reservation_add_edit_and_delete_name_the_client_settings(self):
        query = "?identifier_type=hw-address&identifier=aa:bb:cc:dd:ee:ff"
        cases = {
            "add": self._url("server_reservation4_add"),
            "edit": self._url("server_reservation4_edit", 20) + query,
            "delete": self._url("server_reservation4_delete", 20) + query,
        }
        responses = _catalogue_responses_for_subnets(
            4,
            [{"id": 20, "subnet": "198.18.0.0/24"}],
            global_settings={
                "host-reservation-identifiers": ["hw-address"],
                "hooks-libraries": _host_cmds_hooks(),
            },
        )
        responses["reservation-get"] = _res_get({"subnet-id": 20, "hw-address": _IDENTITY["identifier"]})
        with stub_kea(responses):
            page = self.client.get(cases["edit"])
        self.assertEqual(page.status_code, 200)
        token = page.context["form"].initial["managed_fingerprint"]
        for name, url in cases.items():
            with self.subTest(name):
                self._fresh_client()
                expected = save_key_without_certificate(self.server)
                data = {"subnet_cidr": "198.18.0.0/24", **_IDENTITY}
                if name == "edit":
                    data["managed_fingerprint"] = token
                with stub_kea({}) as kea:
                    response = self.client.post(url, data)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(kea.commands(), [])
                self.assertEqual(_messages(response), [expected])

    def test_reservation_add_pages_name_the_client_settings(self):
        for family in (4, 6):
            with self.subTest(family):
                self._fresh_client()
                expected = save_key_without_certificate(self.server)
                with stub_kea({}) as kea:
                    response = self.client.get(self._url(f"server_reservation{family}_add"))
                self.assertEqual(kea.commands(), [])
                self.assertContains(response, escape(expected))
                self.assertContains(
                    response, '<button type="submit" class="btn btn-primary" disabled aria-disabled="true">'
                )

    def test_reservation_edit_and_delete_pages_name_the_client_settings(self):
        for family, action in ((4, "edit"), (6, "edit"), (4, "delete"), (6, "delete")):
            with self.subTest(family=family, action=action):
                self._fresh_client()
                expected = save_key_without_certificate(self.server)
                query = "?identifier_type=hw-address&identifier=aa:bb:cc:dd:ee:ff"
                with stub_kea({}) as kea:
                    response = self.client.get(self._url(f"server_reservation{family}_{action}", 20) + query)
                self.assertEqual(kea.commands(), [])
                self.assertEqual(_messages(response), [expected])
                self.assertRedirects(response, self._url(f"server_reservations{family}"), fetch_redirect_response=False)
