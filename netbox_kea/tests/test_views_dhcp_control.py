# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""DHCP enable/disable control-view tests for the netbox_kea plugin.

Covers ``ServerDHCP{4,6}EnableView`` and ``ServerDHCP{4,6}DisableView``.

These tests drive the **real** ``KeaClient``; only the HTTP boundary is stubbed
via ``kea_stub.stub_kea``, so the request payloads the views actually send to Kea
are asserted:

* enable  → ``dhcp-enable``  (``service=["dhcp{v}"]``)
* disable → ``dhcp-disable`` (``service=["dhcp{v}"]``; ``{"max-period": N}`` only
  when a period is supplied — omitted otherwise)

Error paths run through the real client and ``runtime_change`` (ADR 0011): a ``{"result": 1}`` response is a
rejection that shows Kea's text, and a lost or malformed reply is unconfirmed. No Python exception text reaches
the page. The tests that follow the redirect land on the status tab, which itself issues
``status-get``/``version-get``/``config-get``, registered benign so the landing page renders.
"""

import requests
from django.contrib import messages as django_messages
from django.urls import reverse

from .kea_stub import stub_kea
from .utils import _make_db_server, _ViewTestBase, active_tabs

_UNCONFIRMED = "Kea did not confirm the change. Check the Server before you try again."
_FORWARD_FAILURE = {"result": 1, "text": "unable to forward command to the dhcp4 service: Connection refused"}


def _messages(response) -> list[str]:
    return [str(message) for message in django_messages.get_messages(response.wsgi_request)]


def _config_get_empty(body):
    """A benign ``config-get`` payload for the status-tab landing (global options)."""
    svc = (body.get("service") or [""])[0]
    version = 6 if svc == "dhcp6" else 4
    key = f"Dhcp{version}"
    return {"result": 0, "arguments": {key: {"option-data": [], f"subnet{version}": [], "shared-networks": []}}}


def _control_stub(**overrides):
    """Register dhcp-enable/-disable plus the status-tab landing commands (all benign)."""
    base = {
        "dhcp-enable": {"result": 0},
        "dhcp-disable": {"result": 0},
        "status-get": {"result": 0, "arguments": {"pid": 1, "uptime": 1, "reload": 0}},
        "version-get": {"result": 0, "arguments": {"extended": "2.5"}},
        "config-get": _config_get_empty,
    }
    base.update(overrides)
    return stub_kea(base)


class TestServerDHCP4EnableView(_ViewTestBase):
    """Tests for ServerDHCP4EnableView (GET confirmation + POST enable)."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_dhcp4_enable", args=[self.server.pk])

    def test_get_returns_confirmation_page(self):
        """GET must render the enable confirmation page with dhcp_version=4 (no Kea)."""
        with stub_kea({}) as kea:
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "4")
        self.assertEqual(kea.commands(), [])

    def test_post_calls_dhcp_enable_and_redirects(self):
        """POST must issue dhcp-enable to the dhcp4 service and redirect to the status tab."""
        with _control_stub() as kea:
            response = self.client.post(self._url())
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)
        self.assertEqual(kea.bodies("dhcp-enable")[0]["service"], ["dhcp4"])

    def test_post_on_kea_exception_shows_the_rejection_with_kea_text(self):
        """A failure result changed nothing in Kea memory: a rejection with Kea's own text, and no read after it."""
        with _control_stub(**{"dhcp-enable": {"result": 1, "text": "the service is busy"}}) as kea:
            response = self.client.post(self._url())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(_messages(response), ["Kea rejected the change. Kea replied: the service is busy"])
        self.assertEqual(kea.commands(), ["dhcp-enable"])

    def test_post_on_a_lost_reply_is_unconfirmed_without_exception_text(self):
        """A reply that was lost after the send can follow an applied change, so the message asks for a check."""
        marker = "kea_secret_transport_marker=https://kea.internal/"
        for name, reply in (
            ("lost", requests.RequestException(marker)),
            ("malformed", ["kea_secret_reply_marker"]),
            ("forward failure", _FORWARD_FAILURE),
        ):
            self._fresh_client()
            with self.subTest(name), _control_stub(**{"dhcp-enable": reply}):
                response = self.client.post(self._url(), follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("kea_secret", response.content.decode())
            (message,) = _messages(response)
            self.assertTrue(message.startswith(_UNCONFIRMED), message)

    def test_get_requires_login(self):
        """Unauthenticated GET must redirect to login."""
        self.client.logout()
        response = self.client.get(self._url())
        self.assertIn(response.status_code, (302, 403))

    def test_post_requires_login(self):
        """Unauthenticated POST must redirect to login."""
        self.client.logout()
        response = self.client.post(self._url())
        self.assertIn(response.status_code, (302, 403))


class TestServerDHCPEnableMissingTLSFile(_ViewTestBase):
    """A CA file removed after the Server was saved gives the error message of the view, not HTTP 500."""

    def test_post_with_a_missing_ca_file_shows_the_error_message(self):
        # No stub: requests itself refuses the missing file before it opens a connection.
        server = _make_db_server(
            name="missing-ca", ca_url="https://127.0.0.1:9/", ca_file_path="/nonexistent/kea-ca.pem", ssl_verify=True
        )
        response = self.client.post(reverse("plugins:netbox_kea:server_dhcp4_enable", args=[server.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            _messages(response),
            [
                (
                    "The change was not sent to Kea, because the Server settings are not valid. "
                    "A TLS certificate, key or CA file of the Server could not be found."
                )
            ],
        )


class TestServerDHCP6EnableView(_ViewTestBase):
    """Tests for ServerDHCP6EnableView — verifies v6 variant uses the dhcp6 service."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_dhcp6_enable", args=[self.server.pk])

    def test_post_calls_dhcp_enable_v6(self):
        """POST must issue dhcp-enable to the dhcp6 service."""
        with _control_stub() as kea:
            response = self.client.post(self._url())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.bodies("dhcp-enable")[0]["service"], ["dhcp6"])


class TestServerDHCP4DisableView(_ViewTestBase):
    """Tests for ServerDHCP4DisableView (GET form + POST disable with optional max_period)."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_dhcp4_disable", args=[self.server.pk])

    def test_get_returns_form_page(self):
        """GET must render the disable form with max_period field (no Kea)."""
        with stub_kea({}) as kea:
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "max_period")
        self.assertEqual(kea.commands(), [])

    def test_the_confirmation_pages_select_overview(self):
        """The daemon controls belong to Overview."""
        with stub_kea({}) as kea:
            for action in ("enable", "disable"):
                for version in (4, 6):
                    url = reverse(f"plugins:netbox_kea:server_dhcp{version}_{action}", args=[self.server.pk])
                    with self.subTest(action=action, version=version):
                        self.assertEqual(active_tabs(self.client.get(url)), ["Overview"])
            with self.subTest("invalid disable form"):
                self.assertEqual(active_tabs(self.client.post(self._url(), {"max_period": "0"})), ["Overview"])
        self.assertEqual(kea.commands(), [])

    def test_post_without_max_period_calls_disable_no_period(self):
        """POST without max_period must issue dhcp-disable with no max-period argument."""
        with _control_stub() as kea:
            response = self.client.post(self._url(), {"confirm": "1"})
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)
        body = kea.bodies("dhcp-disable")[0]
        self.assertEqual(body["service"], ["dhcp4"])
        self.assertNotIn("arguments", body)

    def test_post_with_max_period_passes_value(self):
        """POST with max_period=300 must send {"max-period": 300} to dhcp-disable."""
        with _control_stub() as kea:
            response = self.client.post(self._url(), {"confirm": "1", "max_period": "300"})
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)
        body = kea.bodies("dhcp-disable")[0]
        self.assertEqual(body["service"], ["dhcp4"])
        self.assertEqual(body["arguments"], {"max-period": 300})

    def test_an_applied_disable_is_a_warning_because_the_service_is_down(self):
        for data, text in (
            ({"confirm": "1"}, f"DHCPv4 disabled on {self.server}."),
            ({"confirm": "1", "max_period": "300"}, f"DHCPv4 disabled on {self.server} for up to 300s."),
        ):
            self._fresh_client()
            with self.subTest(data=data), _control_stub():
                response = self.client.post(self._url(), data)
            levels = [(message.level, str(message)) for message in django_messages.get_messages(response.wsgi_request)]
            self.assertEqual(levels, [(django_messages.WARNING, text)])

    def test_post_with_invalid_max_period_rerenders_form(self):
        """POST with non-integer max_period must re-render the form (no Kea call)."""
        with stub_kea({}) as kea:
            response = self.client.post(self._url(), {"confirm": "1", "max_period": "not-a-number"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("dhcp-disable", kea.commands())

    def test_post_on_kea_exception_shows_the_rejection_with_kea_text(self):
        """A failure result changed nothing in Kea memory: a rejection with Kea's own text, and no read after it."""
        with _control_stub(**{"dhcp-disable": {"result": 1, "text": "the service is busy"}}) as kea:
            response = self.client.post(self._url(), {"confirm": "1"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(_messages(response), ["Kea rejected the change. Kea replied: the service is busy"])
        self.assertEqual(kea.commands(), ["dhcp-disable"])

    def test_post_on_a_lost_reply_is_unconfirmed_without_exception_text(self):
        """A reply that was lost after the send can follow an applied change, so the message asks for a check."""
        marker = "kea_secret_transport_marker=https://kea.internal/"
        for name, reply in (
            ("lost", requests.RequestException(marker)),
            ("malformed", ["kea_secret_reply_marker"]),
            ("forward failure", _FORWARD_FAILURE),
        ):
            self._fresh_client()
            with self.subTest(name), _control_stub(**{"dhcp-disable": reply}):
                response = self.client.post(self._url(), {"confirm": "1"}, follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("kea_secret", response.content.decode())
            (message,) = _messages(response)
            self.assertTrue(message.startswith(_UNCONFIRMED), message)

    def test_get_requires_login(self):
        """Unauthenticated GET must redirect to login."""
        self.client.logout()
        response = self.client.get(self._url())
        self.assertIn(response.status_code, (302, 403))

    def test_post_requires_login(self):
        """Unauthenticated POST must redirect to login."""
        self.client.logout()
        response = self.client.post(self._url())
        self.assertIn(response.status_code, (302, 403))


class TestServerDHCP6DisableView(_ViewTestBase):
    """Tests for ServerDHCP6DisableView — verifies v6 variant uses the dhcp6 service."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_dhcp6_disable", args=[self.server.pk])

    def test_post_calls_dhcp_disable_v6(self):
        """POST must issue dhcp-disable to the dhcp6 service with no max-period argument."""
        with _control_stub() as kea:
            response = self.client.post(self._url(), {"confirm": "1"})
        self.assertEqual(response.status_code, 302)
        body = kea.bodies("dhcp-disable")[0]
        self.assertEqual(body["service"], ["dhcp6"])
        self.assertNotIn("arguments", body)
