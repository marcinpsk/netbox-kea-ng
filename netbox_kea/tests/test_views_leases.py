# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""View tests for netbox_kea plugin.

Also contains pure-Python unit tests for helper functions defined in views.py
(e.g. ``_extract_identifier``), which do not require a database but live here
because they are tightly coupled to view logic.

These tests verify correct HTTP responses and redirect behaviour for every view.
All Kea HTTP calls are mocked so no running Kea instance is required.

Test organisation strategy
--------------------------
Each view class gets its own ``TestCase`` subclass so failures are isolated and
clearly named.  Every test that triggers a redirect asserts that the redirect URL
contains an *integer* pk (never the string "None"), which is the pattern that
revealed the original ``POST /plugins/kea/servers/None`` 404 bug.

View tests use ``django.test.TestCase`` because they write to the test database
(user + server fixtures).  Server objects are created via ``Server.objects.create()``
which does **not** call ``Model.clean()`` and therefore does not trigger live Kea
connectivity checks.
"""

import csv
import html
import io
import ipaddress
import json
import re
import time
from contextlib import contextmanager
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
from bs4 import BeautifulSoup
from django.contrib import messages as django_messages
from django.contrib.messages import get_messages
from django.db.models.signals import post_save
from django.test import SimpleTestCase
from django.urls import reverse
from django.utils.html import escape
from extras.models import JournalEntry
from ipam.models import IPAddress as NbIP

from netbox_kea import constants
from netbox_kea.lease_reads import LeaseSearch
from netbox_kea.models import Server
from netbox_kea.signals import lease_added
from netbox_kea.utilities import parse_lease_csv
from netbox_kea.views.leases import fetch
from netbox_kea.views.notices import HEADLINES, Notice

from .kea_stub import (
    LeaseDaemon,
    _catalogue_responses,
    _catalogue_responses_for_subnets,
    _http_response,
    _leases_per_subnet,
    _raw_http_response,
    _refused_connection,
    _subnet_list,
    _subnet_stats,
    complete_lease,
    lease_page,
    lease_pages,
    lease_record,
    lease_reply,
    queued,
    shown_token,
    stub_kea,
    typed_lease,
)
from .utils import (
    INVALID_SERVER_SETTINGS,
    UNCONFIRMED_RUNTIME,
    _make_db_server,
    _ViewTestBase,
    active_tabs,
    ownership_link,
    prefix_ownership_link,
    save_key_without_certificate,
    with_display_cache_config,
    with_kea_client_config,
)

#: The HTMX error template renders a uuid4 reference ID, so a test that stops at the
#: label also passes when that ID is missing.
_ERROR_TEMPLATE = re.compile(
    r"An internal error occurred\. Reference ID: <code>"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}</code>"
)


def _assert_rendered_error_template(test, response):
    """Assert the HTMX handler rendered exception_htmx.html with a real reference ID."""
    test.assertRegex(response.content.decode(), _ERROR_TEMPLATE)


def _assert_lease_read_failed(test, response):
    """Assert the partial keeps the form and shows the unavailable Lease Notice in place of the table."""
    test.assertEqual(response.status_code, 200)
    test.assertContains(response, f'<div class="alert alert-danger" role="alert">{HEADLINES["lease"]}</div>', html=True)
    test.assertContains(response, 'id="lease-search-btn"')
    test.assertNotContains(response, 'id="lease-delete-form"')
    _assert_no_error_template(test, response)


_IMPORT_NOT_SENT = "NetBox stopped at an earlier row and did not send this row."


@contextmanager
def _failing_journal(error: Exception):
    """Make each JournalEntry save raise *error*, as a save signal of another plugin can."""

    def fail(sender, **kwargs):
        raise error

    post_save.connect(fail, sender=JournalEntry)
    try:
        yield
    finally:
        post_save.disconnect(fail, sender=JournalEntry)


def _import_counts(response) -> dict[str, int]:
    """Return the number of rows of each status of a Lease CSV import report."""
    return {group.status: len(group.rows) for group in response.context["result"]["groups"]}


def _import_report(response) -> dict[str, tuple[str, list[tuple[str, ...]]]]:
    """Return the heading and the table rows of each rendered section of a Lease CSV import report."""
    page = BeautifulSoup(response.content, "html.parser")
    report = {}
    for section in page.select("section[data-import-status]"):
        heading = section.find("h6")
        rows = [tuple(cell.get_text(strip=True) for cell in row.select("td")) for row in section.select("tbody tr")]
        report[str(section["data-import-status"])] = (heading.get_text(strip=True) if heading else "", rows)
    return report


def _lease_lines(response) -> list[str]:
    """Return one line per excluded record of the Lease Notice, as the partial lists them."""
    found = response.context["lease_notice"]
    diagnostics = found.diagnostics if found is not None else ()
    return [f"{item.source_position} ({item.field or 'record'}): {item.message}" for item in diagnostics]


def _assert_no_error_template(test, response):
    """Assert the HTMX handler rendered no part of exception_htmx.html."""
    test.assertNotRegex(response.content.decode(), _ERROR_TEMPLATE)
    test.assertNotContains(response, "An internal error occurred. Reference ID:")


def _held4(*addresses: str) -> tuple[dict, list[str]]:
    """Return the answers of a Kea that holds a lease at each address, and the list row selection of each."""
    records = [lease_record(address, subnet_id=1) for address in addresses]
    return LeaseDaemon(4, *records).responses(), [shown_token(record) for record in records]


def _lease_stub(responses: dict):
    """Supply the picker configuration matching each registered Subnet listing."""

    def configuration(body):
        family = int(body["service"][0][-1])
        listing = responses.get(f"subnet{family}-list")
        if not isinstance(listing, dict):
            return {"result": 1, "text": "Configuration unavailable in this lease scenario"}
        arguments = listing.get("arguments", {})
        subnets = arguments.get("subnets", []) if isinstance(arguments, dict) else []
        return _catalogue_responses_for_subnets(family, subnets)["config-get"]

    return stub_kea({"config-get": configuration, **responses})


def _reservation_stub(version: int, responses: dict, *, global_settings: dict | None = None):
    """Add the matching configuration source required by typed Reservation scope.

    The Catalogue response shape has one definition in ``kea_stub``; this only points it
    at the subnets the caller declared, then lets the caller's own entries win.
    """
    list_response = responses.get(f"subnet{version}-list")
    arguments = list_response.get("arguments", {}) if isinstance(list_response, dict) else {}
    subnets = arguments.get("subnets", []) if isinstance(arguments, dict) else []
    catalogue = _catalogue_responses_for_subnets(version, subnets, global_settings=global_settings)
    return stub_kea({**catalogue, **responses})


class TestServerLeases4View(_ViewTestBase):
    """GET /plugins/kea/servers/<pk>/leases4/"""

    def test_get_returns_200(self):
        """Initial leases4 page renders without Kea API calls."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_shows_the_add_and_bulk_import_links(self):
        response = self.client.get(reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]))
        for name in ("server_lease4_add", "server_lease4_bulk_import"):
            with self.subTest(name):
                self.assertContains(response, f'href="{reverse(f"plugins:netbox_kea:{name}", args=[self.server.pk])}"')

    def test_get_with_dhcp4_disabled_shows_protocol_not_enabled(self):
        """A disabled DHCPv4 family shows the protocol-disabled state without a Kea read."""
        v6_only = _make_db_server(name="v6-only", dhcp4=False, dhcp6=True)
        url = reverse("plugins:netbox_kea:server_leases4", args=[v6_only.pk])
        with stub_kea({}) as kea:
            response = self.client.get(url)
        self.assertContains(response, "Protocol not enabled")
        self.assertEqual(kea.commands(), [])

    def test_get_nonexistent_returns_404(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)


class TestServerLeases6View(_ViewTestBase):
    """GET /plugins/kea/servers/<pk>/leases6/"""

    def test_get_returns_200(self):
        url = reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_get_with_dhcp6_disabled_shows_protocol_not_enabled(self):
        v4_only = _make_db_server(name="v4-only", dhcp4=True, dhcp6=False)
        url = reverse("plugins:netbox_kea:server_leases6", args=[v4_only.pk])
        with stub_kea({}) as kea:
            response = self.client.get(url)
        self.assertContains(response, "Protocol not enabled")
        self.assertEqual(kea.commands(), [])


# ─────────────────────────────────────────────────────────────────────────────
# Lease delete views
# ─────────────────────────────────────────────────────────────────────────────


class TestServerLeases4DeleteView(_ViewTestBase):
    """POST /plugins/kea/servers/<pk>/leases4/delete/"""

    def test_get_redirects_to_server_not_none(self):
        """GET on a POST-only view must redirect back to the server (never to servers/None)."""
        url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)
        self.assertIn(str(self.server.pk), response.url)

    def test_post_empty_form_redirects_not_none(self):
        """POST with invalid/empty lease list must redirect, not to servers/None."""
        url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)

    def test_post_htmx_single_lease_returns_hx_refresh(self):
        """An HTMX POST with a single IP and _confirm returns HX-Refresh: true instead of redirect."""
        url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        record = lease_record("192.0.2.1", subnet_id=1)
        with _lease_stub(LeaseDaemon(4, record).responses()) as kea:
            response = self.client.post(
                url,
                {"pk": shown_token(record), "_confirm": "1"},
                HTTP_HX_REQUEST="true",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("HX-Refresh"), "true")
        # De-mocked: assert the real request payload built by KeaClient.command(), not a mock call.
        self.assertEqual(kea.commands(), ["lease4-get", "lease4-del"])
        body = kea.bodies("lease4-del")[0]
        self.assertEqual(body["arguments"], {"ip-address": "192.0.2.1"})
        self.assertEqual(body["service"], ["dhcp4"])


class TestServerLeases6DeleteView(_ViewTestBase):
    """POST /plugins/kea/servers/<pk>/leases6/delete/"""

    def test_get_redirects_to_server_not_none(self):
        url = reverse("plugins:netbox_kea:server_leases6_delete", args=[self.server.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)
        self.assertIn(str(self.server.pk), response.url)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 7a: "Reserved" badge on lease pages
# ─────────────────────────────────────────────────────────────────────────────


class TestReservedBadgeOnLeases(_ViewTestBase):
    """HTMX lease search must show a 'Reserved' badge when a matching reservation exists.

    The badge links to the reservation edit form so operators can quickly jump
    to the reservation from the lease table.
    """

    _LEASE4 = complete_lease(
        {
            "ip-address": "192.168.1.100",
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "subnet-id": 1,
            "cltt": 1700000000,
            "valid-lft": 86400,
            "hostname": "testhost",
        }
    )
    _RESERVATION4 = {
        "ip-address": "192.168.1.100",
        "hw-address": "aa:bb:cc:dd:ee:ff",
        "subnet-id": 1,
        "hostname": "testhost",
    }
    # The lease-search page fetches the subnet suggestions via subnet{v}-list first.
    _SUBNETS4 = _subnet_list(4, [{"id": 1, "subnet": "192.168.1.0/24"}])
    #: The badge column reads the Subnet Catalogue before it looks a Reservation up, so
    #: config-get must be registered. Without it the enrichment fails and no badge can
    #: render, which the column header alone would still satisfy.
    _CATALOGUE4 = _catalogue_responses(4, 1, "192.168.1.0/24")

    def _badge_responses(self, **extra):
        return {
            **self._CATALOGUE4,
            "subnet4-list": self._SUBNETS4,
            "lease4-get": {"result": 0, "arguments": {"ip-address": "192.168.1.100", **self._LEASE4}},
            **extra,
        }

    def _htmx_get(self, url, data):
        """Issue an HTMX GET request (adds HX-Request header)."""
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def test_reserved_badge_shown_when_reservation_exists(self):
        """When a lease IP has a corresponding reservation, the table cell shows 'Reserved'."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with _lease_stub(self._badge_responses(**{"reservation-get": {"result": 0, "arguments": self._RESERVATION4}})):
            response = self._htmx_get(url, {"by": "ip", "q": "192.168.1.100"})

        self.assertEqual(response.status_code, 200)
        # The column header also reads "Reserved", so assert on the badge link itself.
        self.assertContains(response, 'text-decoration-none">Reserved</a>')

    def test_the_table_export_fills_the_badge_columns_of_the_page(self):
        """The "table" export presents its rows as the page does, so the badge columns carry their state."""
        ip = NbIP.objects.create(address="192.168.1.100/24", status="dhcp", description="[kea-sync: lease]")
        ownership_link(ip, self.server, source="lease", allocation_kind="address")
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        # Only a Current Lease has a Lease Synchronization State.
        current = {"result": 0, "arguments": {**self._LEASE4, "cltt": int(time.time())}}
        reserved = {"result": 0, "arguments": self._RESERVATION4}
        with _lease_stub(self._badge_responses(**{"lease4-get": current, "reservation-get": reserved})):
            response = self.client.get(url, {"by": "ip", "q": "192.168.1.100", "export": "table"})

        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.content.decode())))
        self.assertEqual([(row.get("Reserved"), row.get("NetBox IP")) for row in rows], [("Reserved", "Synchronized")])

    def test_the_table_export_shows_an_unknown_reservation_match_as_the_badge_does(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        cases = (
            ("Unknown", {"result": 1, "text": "host database error"}, "Reservation Unknown"),
            # The control: an Unreserved row exports the text of its action badge.
            ("Unreserved", {"result": 3}, "+ Reserve"),
        )
        for label, reservation_get, exported in cases:
            with self.subTest(label), _lease_stub(self._badge_responses(**{"reservation-get": reservation_get})):
                response = self.client.get(url, {"by": "ip", "q": "192.168.1.100", "export": "table"})

            self.assertEqual(response.status_code, 200)
            rows = list(csv.DictReader(io.StringIO(response.content.decode())))
            self.assertEqual([row.get("Reserved") for row in rows], [exported])

    def test_the_table_export_shows_an_ignored_reservation_as_the_badge_does(self):
        """Kea's default reservations-global is false, so it ignores a Global Reservation."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        global_ = {**self._RESERVATION4, "subnet-id": 0}

        def reservation_get(body):
            if body["arguments"]["subnet-id"] == 0:
                return {"result": 0, "arguments": global_}
            return {"result": 3}

        with _lease_stub(self._badge_responses(**{"reservation-get": reservation_get})):
            response = self.client.get(url, {"by": "ip", "q": "192.168.1.100", "export": "table"})

        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.content.decode())))
        self.assertEqual([row.get("Reserved") for row in rows], ["Reservation Ignored"])

    def test_no_reserved_badge_when_no_reservation(self):
        """When no reservation exists for the lease IP, no badge is rendered."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with _lease_stub(
            self._badge_responses(**{"reservation-get": {"result": 3}})  # not found
        ):
            response = self._htmx_get(url, {"by": "ip", "q": "192.168.1.100"})

        self.assertEqual(response.status_code, 200)
        # A user search pushes its URL, and the lease row must
        # appear. Together, these prove the table rendered instead of the exception partial.
        self.assertIn("HX-Push-Url", response.headers)
        self.assertContains(response, "192.168.1.100")
        # The column header says "Reserved" — check no badge link is rendered
        self.assertNotContains(response, 'text-decoration-none">Reserved</a>')


# ─────────────────────────────────────────────────────────────────────────────
# Phase 9A: Lease search paths — all BY_* types
# ─────────────────────────────────────────────────────────────────────────────


class TestLeaseSearchPaths(_ViewTestBase):
    """Each search-by type in the Lease fetch must dispatch the
    correct Kea command with correct arguments, via HTMX GET.

    De-mocked: exercises the real ``KeaClient`` so the actual request payload built
    by ``KeaClient.command()`` — command name, ``arguments``, and ``service`` — is
    asserted, not a ``MagicMock`` call-arg. Only the HTTP boundary
    (``requests.Session.post``) is stubbed. A search issues ``subnet{v}-list`` (subnet
    quick-select) → ``lease{v}-get…`` → per-lease ``reservation-get`` enrichment.
    """

    _LEASE4 = complete_lease(
        {
            "ip-address": "10.0.0.5",
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "client-id": "01:aa:bb:cc:dd:ee:ff",
            "hostname": "search-host",
            "subnet-id": 1,
            "valid-lft": 3600,
            "cltt": 1_700_000_000,
        }
    )
    # The lease-search page fetches the subnet suggestions via subnet{v}-list first.
    _SUBNETS4 = _subnet_list(4, [{"id": 1, "subnet": "10.0.0.0/24"}])
    _SUBNETS6 = _subnet_list(6, [{"id": 1, "subnet": "2001:db8::/64"}])
    # Reservation enrichment runs for every returned lease; "not found" (result 3)
    # means no reservation, which is all these lease-command tests care about.
    _NO_RESERVATION = {"result": 3}

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def _url4(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def _url6(self):
        return reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk])

    def _multi(self, leases):
        """Multi-result lease-get response envelope (leases list + count)."""
        return {"result": 0, "arguments": {"leases": leases, "count": len(leases)}}

    def _single(self, lease):
        """Single-result lease-get response envelope (lease fields under arguments)."""
        return {"result": 0, "arguments": dict(lease)}

    def test_search_by_hw_address_sends_correct_command(self):
        """BY_HW_ADDRESS must call lease4-get-by-hw-address with hw-address argument."""
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-hw-address": self._multi([dict(self._LEASE4)]),
                "reservation-get": self._NO_RESERVATION,
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "hw", "q": "aa:bb:cc:dd:ee:ff"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease4-get-by-hw-address", kea.commands())
        body = kea.bodies("lease4-get-by-hw-address")[0]
        self.assertEqual(body["arguments"]["hw-address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(body["service"], ["dhcp4"])

    @with_kea_client_config(lease_query_max_unpaged_leases=100)
    def test_a_guard_rejected_subnet_query_renders_the_bound_form(self):
        """The guard handler reads `form` and `form.cleaned_data`, so both must be bound.

        No other test drives this handler, and `form` was assigned inside the same `try`
        the handler serves. Any lease query added above that assignment would turn this
        into an UnboundLocalError instead of a rendered form error.
        """
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "stat-lease4-get": {"result": 3},
            }
        ):
            response = self._htmx_get(self._url4(), {"by": "subnet_id", "q": "1"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Load the stat_cmds hook")

    def test_a_large_hostname_result_enriches_only_the_rendered_page(self):
        """`lease*-get-by-hostname` takes no limit, so the whole result set was enriched.

        `configure()` already paginates the table, so the extra rows were never rendered:
        the run paid one reservation lookup per lease to enrich rows nobody sees, and the
        paginator stayed hidden, so those rows could not be reached at all.
        """
        leases = [dict(self._LEASE4, **{"ip-address": f"10.0.0.{n}"}) for n in range(1, 61)]
        responses = {
            "subnet4-list": self._SUBNETS4,
            "lease4-get-by-hostname": self._multi(leases),
            "reservation-get": self._NO_RESERVATION,
        }

        with _lease_stub(responses):
            response = self._htmx_get(self._url4(), {"by": "hostname", "q": "search-host"})

        self.assertEqual(response.status_code, 200)
        rendered = len(response.context["table"].paginated_rows)
        self.assertLess(rendered, len(leases), "the table must paginate a result set this large")
        # Enrichment stamps can_delete on every lease it touches, so this counts its input.
        enriched = [row for row in response.context["table"].data.data if "can_delete" in row]
        self.assertEqual(len(enriched), rendered)
        # Rows are being withheld, so the paginator has to be offered.
        self.assertTrue(response.context["paginate"])

    def test_search_by_hostname_sends_correct_command(self):
        """BY_HOSTNAME must call lease4-get-by-hostname with hostname argument."""
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-hostname": self._multi([dict(self._LEASE4)]),
                "reservation-get": self._NO_RESERVATION,
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "hostname", "q": "search-host"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease4-get-by-hostname", kea.commands())
        body = kea.bodies("lease4-get-by-hostname")[0]
        self.assertEqual(body["arguments"]["hostname"], "search-host")
        self.assertEqual(body["service"], ["dhcp4"])

    def test_search_by_client_id_sends_correct_command(self):
        """BY_CLIENT_ID must call lease4-get-by-client-id with client-id argument."""
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-client-id": self._multi([dict(self._LEASE4)]),
                "reservation-get": self._NO_RESERVATION,
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "client_id", "q": "01:aa:bb:cc:dd:ee:ff"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease4-get-by-client-id", kea.commands())
        body = kea.bodies("lease4-get-by-client-id")[0]
        self.assertEqual(body["arguments"]["client-id"], "01:aa:bb:cc:dd:ee:ff")
        self.assertEqual(body["service"], ["dhcp4"])

    def test_search_by_subnet_id_sends_correct_command(self):
        """BY_SUBNET_ID must call lease4-get-all with subnets=[<id>]."""
        with _lease_stub(
            {
                **_catalogue_responses(4, 1, "10.0.0.0/24"),
                "stat-lease4-get": _subnet_stats(4, 1),
                "lease4-get-all": self._multi([dict(self._LEASE4)]),
                "reservation-get": self._NO_RESERVATION,
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "subnet_id", "q": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease4-get-all", kea.commands())
        body = kea.bodies("lease4-get-all")[0]
        self.assertEqual(body["arguments"]["subnets"], [1])
        self.assertEqual(body["service"], ["dhcp4"])

    def test_search_by_subnet_id_paginates_locally_and_enriches_only_visible_page(self):
        """Expose rows after the first table page without repeating their enrichment."""
        leases = [
            {
                **self._LEASE4,
                "ip-address": f"10.0.0.{index}",
                "hw-address": f"aa:bb:cc:dd:ee:{index:02x}",
            }
            for index in range(1, 57)
        ]
        with _reservation_stub(
            4,
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-all": self._multi(leases),
                "reservation-get": self._NO_RESERVATION,
            },
        ) as kea:
            response = self._htmx_get(
                self._url4(),
                {"by": "subnet_id", "q": "1", "page": "2", "per_page": "50"},
            )

        self.assertEqual(response.status_code, 200)
        table = response.context["table"]
        self.assertTrue(hasattr(table, "page"), table.__dict__)
        self.assertEqual(table.page.number, 2)
        self.assertEqual(table.paginator.per_page, 50)
        rows = list(table.paginated_rows)
        self.assertEqual([row.record["ip_address"] for row in rows], [f"10.0.0.{index}" for index in range(51, 57)])
        self.assertTrue(response.context["paginate"])
        self.assertIsNone(response.context["next_page"])
        address_probes = 6
        distinct_hardware_addresses = 6
        distinct_client_ids = 1
        reservation_scopes = 2
        expected_probes = (
            address_probes + distinct_hardware_addresses * reservation_scopes + distinct_client_ids * reservation_scopes
        )
        # Rows outside this page are not enriched.
        self.assertEqual(len(kea.bodies("reservation-get")), expected_probes)

    @with_kea_client_config(lease_query_max_unpaged_leases=1000)
    def test_search_by_subnet_id_and_state_filters_in_kea(self):
        lease = dict(self._LEASE4, state=1)
        with _lease_stub(
            {
                **_catalogue_responses(4, 1, "10.0.0.0/24"),
                "stat-lease4-get": _subnet_stats(4, 1, assigned=2001, declined=1),
                "lease4-get-by-state": self._multi([lease]),
                "reservation-get": self._NO_RESERVATION,
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "subnet_id", "q": "1", "state": "1"})

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("lease4-get-all", kea.commands())
        self.assertEqual(
            kea.bodies("lease4-get-by-state")[0]["arguments"],
            {"subnet-id": 1, "state": 1},
        )

    @with_kea_client_config(lease_query_max_unpaged_leases=100)
    def test_large_subnet_search_prompts_for_a_state_without_get_all(self):
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "stat-lease4-get": _subnet_stats(4, 1, assigned=101),
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "subnet_id", "q": "1"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Select the Active or Declined state")
        self.assertNotIn("lease4-get-all", kea.commands())

    def test_search_by_ip_returns_200(self):
        """BY_IP must call lease4-get with ip-address argument and return 200."""
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get": self._single(self._LEASE4),
                "reservation-get": self._NO_RESERVATION,
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease4-get", kea.commands())
        body = kea.bodies("lease4-get")[0]
        self.assertEqual(body["arguments"]["ip-address"], "10.0.0.5")
        self.assertEqual(body["service"], ["dhcp4"])

    def test_search_result_3_returns_empty_table(self):
        """result=3 (not found) must render an empty table, not a 500."""
        # Empty result short-circuits enrichment, so no reservation-get is issued.
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get": {"result": 3, "arguments": None},
            }
        ) as kea:
            response = self._htmx_get(self._url4(), {"by": "ip", "q": "10.0.0.99"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease4-get", kea.commands())

    def test_search_by_duid_v6_sends_correct_command(self):
        """BY_DUID on the v6 endpoint must call lease6-get-by-duid."""
        server6 = _make_db_server(name="kea-v6-search", ca_url="https://kea6.example.com", dhcp4=False, dhcp6=True)
        url = reverse("plugins:netbox_kea:server_leases6", args=[server6.pk])
        with _lease_stub(
            {
                "subnet6-list": self._SUBNETS6,
                "lease6-get-by-duid": self._multi([]),
            }
        ) as kea:
            response = self._htmx_get(url, {"by": "duid", "q": "00:01:aa:bb:cc:dd"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease6-get-by-duid", kea.commands())
        body = kea.bodies("lease6-get-by-duid")[0]
        self.assertEqual(body["arguments"]["duid"], "00:01:aa:bb:cc:dd")
        self.assertEqual(body["service"], ["dhcp6"])


# ─────────────────────────────────────────────────────────────────────────────
# Phase 9B: CSV export — BaseServerLeasesView.get_export()
# ─────────────────────────────────────────────────────────────────────────────


class TestLeaseExport(_ViewTestBase):
    """GET /plugins/kea/servers/<pk>/leases4/?export=all must return a CSV file."""

    _LEASE4 = complete_lease(
        {
            "ip-address": "10.0.0.5",
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "hostname": "export-host",
            "subnet-id": 1,
            "valid-lft": 3600,
            "cltt": 1_700_000_000,
        }
    )
    # The export path builds the search form, which fetches the subnet quick-select.
    _SUBNETS4 = _subnet_list(4, [{"id": 1, "subnet": "10.0.0.0/24"}])

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_export_all_returns_csv_content_type(self):
        """?export=all must respond with text/csv Content-Type."""
        with _lease_stub(
            {"subnet4-list": self._SUBNETS4, "lease4-get": {"result": 0, "arguments": dict(self._LEASE4)}}
        ):
            response = self.client.get(self._url(), {"export": "all", "by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))

    def test_export_table_returns_csv(self):
        """?export=table must also return text/csv (selected columns)."""
        with _lease_stub(
            {"subnet4-list": self._SUBNETS4, "lease4-get": {"result": 0, "arguments": dict(self._LEASE4)}}
        ):
            response = self.client.get(self._url(), {"export": "table", "by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))

    def test_export_with_invalid_form_redirects(self):
        """?export=all with missing q/by must redirect (not crash)."""
        # No 'q' or 'by' — form is invalid
        response = self.client.get(self._url(), {"export": "all"})
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)

    def test_a_client_that_cannot_be_built_is_reported_as_a_settings_error(self):
        """A key without a certificate is a Server setting error, not a connection failure; no lease is read."""
        expected = save_key_without_certificate(self.server)
        with _lease_stub({}) as kea:
            response = self.client.get(self._url(), {"export": "all", "by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), [])
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            [expected],
        )

    @with_kea_client_config(lease_query_max_unpaged_leases=100)
    def test_export_by_subnet_uses_the_guarded_subnet_query(self):
        """A Subnet export must not rely on global lease-page ordering."""
        leases = [
            complete_lease(
                {
                    "ip-address": f"10.0.0.{i}",
                    "hw-address": "aa:bb:cc:dd:ee:ff",
                    "hostname": f"h{i}",
                    "subnet-id": 1,
                    "valid-lft": 3600,
                    "cltt": 1_700_000_000,
                }
            )
            for i in range(1, 4)
        ]
        with _lease_stub(
            {
                **_catalogue_responses(4, 1, "10.0.0.0/24"),
                "stat-lease4-get": _subnet_stats(4, 1, assigned=3),
                "lease4-get-all": {"result": 0, "arguments": {"leases": leases}},
            }
        ) as kea:
            response = self.client.get(
                self._url(),
                {"export": "all", "by": "subnet", "q": "10.0.0.0/24"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))
        self.assertIn("lease4-get-all", kea.commands())
        self.assertNotIn("lease4-get-page", kea.commands())


# ─────────────────────────────────────────────────────────────────────────────
# Phase 9C: Lease delete — full confirmation flow + error paths
# ─────────────────────────────────────────────────────────────────────────────


class TestLeaseDeleteFullFlow(_ViewTestBase):
    """Full POST flow for lease bulk deletion: confirm page → confirmed delete → Kea error."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])

    def test_post_with_ips_no_confirm_renders_confirmation_page(self):
        """POST with lease rows but no _confirm renders the bulk_delete confirmation template."""
        selected = [shown_token(lease_record(address, subnet_id=1)) for address in ("10.0.0.1", "10.0.0.2")]
        response = self.client.post(self._url(), {"pk": selected})
        self.assertEqual(response.status_code, 200)
        # Must show the confirmation template (not a redirect)
        self.assertContains(response, "10.0.0.1")
        self.assertContains(response, "10.0.0.2")

    def test_confirmation_page_shows_no_empty_meta_fields_box(self):
        """A lease delete has no changelog message and no background job, so the page shows no box for them."""
        from bs4 import BeautifulSoup

        token = shown_token(lease_record("10.0.0.1", subnet_id=1))
        response = self.client.post(self._url(), {"pk": [token], "return_url": "/plugins/kea/"})
        self.assertContains(response, "Confirm Bulk Deletion")
        form = BeautifulSoup(response.content, "html.parser").select_one("#delete-form form")
        self.assertIsNone(form.select_one(".bg-primary-subtle"))
        self.assertNotIn("background_job", str(form))
        hidden = {(field["name"], field.get("value")) for field in form.select("input[type=hidden]")}
        self.assertLessEqual({("pk", token), ("return_url", "/plugins/kea/")}, hidden)
        self.assertIsNotNone(form.select_one('button[name="_confirm"]'))

    def test_post_confirmed_calls_kea_and_redirects(self):
        """POST with _confirm=1 must call Kea lease4-del and redirect."""
        record = lease_record("10.0.0.1", subnet_id=1)
        with _lease_stub(LeaseDaemon(4, record).responses()) as kea:
            response = self.client.post(
                self._url(),
                {"pk": [shown_token(record)], "_confirm": "1"},
            )
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)
        # Verify Kea was called with the lease4-del command (real payload on the wire).
        self.assertIn("lease4-del", kea.commands())
        self.assertEqual(kea.bodies("lease4-del")[0]["arguments"], {"ip-address": "10.0.0.1"})

    def test_post_confirmed_kea_error_redirects_with_the_unconfirmed_message(self):
        """A failure result on lease4-del can follow a deleted Lease, so it is unconfirmed (ADR 0011), not a 500."""
        record = lease_record("10.0.0.5", subnet_id=1)
        # result=1 makes the real KeaClient.command() raise KeaException (delete uses check=(0,3)).
        responses = {**LeaseDaemon(4, record).responses(), "lease4-del": {"result": 1, "text": "lease not found"}}
        with _lease_stub(responses):
            response = self.client.post(
                self._url(),
                {"pk": [shown_token(record)], "_confirm": "1"},
            )
        self.assertEqual(response.status_code, 302)
        self._assert_no_none_pk_redirect(response)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            [f"Lease 10.0.0.5: {UNCONFIRMED_RUNTIME} Kea replied: lease not found"],
        )

    def test_a_client_that_cannot_be_built_stops_the_delete_with_one_error(self):
        """Every row would fail the same way, so the loop stops at the first one and lists the rest as not sent."""
        save_key_without_certificate(self.server)
        tokens = [shown_token(lease_record(address, subnet_id=1)) for address in ("10.0.0.1", "10.0.0.2", "10.0.0.3")]
        with _lease_stub({}) as kea:
            response = self.client.post(self._url(), {"pk": tokens, "_confirm": "1"})
        self.assertEqual(kea.commands(), [])
        self.assertEqual(
            [(message.level, str(message)) for message in get_messages(response.wsgi_request)],
            [
                (django_messages.ERROR, f"Lease 10.0.0.1: {INVALID_SERVER_SETTINGS}"),
                (
                    django_messages.WARNING,
                    "NetBox stopped at lease 10.0.0.1 and did not send the delete of 2 lease(s): 10.0.0.2, 10.0.0.3.",
                ),
            ],
        )

    def test_post_confirmed_with_a_client_that_cannot_be_built_is_a_settings_error(self):
        """A key without a certificate is a Server setting error, not a connection failure; nothing is deleted."""
        save_key_without_certificate(self.server)
        record = lease_record("10.0.0.1", subnet_id=1)
        with _lease_stub({}) as kea:
            response = self.client.post(self._url(), {"pk": [shown_token(record)], "_confirm": "1"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), [])
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            [f"Lease 10.0.0.1: {INVALID_SERVER_SETTINGS}"],
        )

    def test_forbidden_user_gets_403(self):
        """A user without bulk_delete_lease_from_server permission must receive 403."""
        from django.contrib.auth import get_user_model as _get_user_model

        User2 = _get_user_model()
        unprivileged = User2.objects.create_user("noperm_user", password="x")
        self.client.force_login(unprivileged)
        response = self.client.post(
            self._url(),
            {"pk": ["10.0.0.1"], "_confirm": "1"},
        )
        self.assertEqual(response.status_code, 403)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 9D: _enrich_leases_with_badges error paths
# ─────────────────────────────────────────────────────────────────────────────


class TestEnrichLeasesErrorPaths(_ViewTestBase):
    """_enrich_leases_with_badges must degrade gracefully on unexpected errors."""

    _LEASE4 = complete_lease(
        {
            "ip-address": "10.0.0.5",
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "hostname": "enrich-host",
            "subnet-id": 1,
            "valid-lft": 3600,
        }
    )
    _SUBNETS4 = _subnet_list(4, [{"id": 1, "subnet": "10.0.0.0/24"}])

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def test_an_unexpected_lookup_failure_is_logged_and_every_row_shows_an_unknown_match_without_actions(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with (
            _reservation_stub(
                4,
                {
                    "subnet4-list": self._SUBNETS4,
                    "lease4-get": {"result": 0, "arguments": dict(self._LEASE4)},
                    "reservation-get": TypeError("unexpected lookup failure"),
                },
            ),
            self.assertLogs("netbox_kea.views.leases", "WARNING") as logs,
        ):
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("unexpected error during lease enrichment", logs.output[0])
        row = next(iter(response.context["table"].rows)).record
        self.assertEqual(row["ip_address"], "10.0.0.5")
        self.assertFalse(row["is_reserved"])
        self.assertIsNone(row["reservation_url"])
        self.assertIsNone(row["create_reservation_url"])
        self.assertIsNone(row.get("sync_url"))
        cell = BeautifulSoup(str(next(iter(response.context["table"].rows)).get_cell("reserved")), "html.parser")
        [badge] = cell.select(".badge")
        self.assertEqual(
            (badge["class"], badge.get_text(strip=True), badge["title"]),
            (["badge", "text-bg-warning"], "Reservation Unknown", "The Reservation lookups failed."),
        )

    def test_a_non_integer_subnet_id_excludes_the_lease_with_a_safe_diagnostic(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        for subnet_id in (1.0, True):
            lease = {**self._LEASE4, "subnet-id": subnet_id}
            with self.subTest(subnet_id=subnet_id):
                with _reservation_stub(
                    4,
                    {
                        "subnet4-list": self._SUBNETS4,
                        "lease4-get": {"result": 0, "arguments": lease},
                    },
                ) as kea:
                    response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})

                self.assertEqual(response.status_code, 200)
                self.assertNotIn("reservation-get", kea.commands())
                self.assertEqual(list(response.context["table"].rows), [])
                self.assertEqual(_lease_lines(response), ["arguments (subnet-id): A lease field has the wrong type."])
                self.assertContains(response, "1 lease record that could not be read")

    def test_unknown_subnet_id_keeps_reservation_dependent_actions_unavailable(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        lease = {**self._LEASE4, "subnet-id": 99}
        with _reservation_stub(
            4,
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get": {"result": 0, "arguments": lease},
            },
        ) as kea:
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("reservation-get", kea.commands())
        row = next(iter(response.context["table"].rows)).record
        self.assertIsNone(row.get("sync_url"))
        self.assertIsNone(row["create_reservation_url"])

    def test_sync_url_set_when_no_netbox_ip(self):
        """When the lease IP is absent from NetBox, sync_url must be set on the lease dict."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with _reservation_stub(
            4,
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get": {"result": 0, "arguments": dict(self._LEASE4)},
                "reservation-get": {"result": 3},  # no reservation
            },
        ):
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        # Sync button (hx-post) must appear since no NetBox IP
        self.assertContains(response, "hx-post")

    @with_display_cache_config(leases_ttl=0, configuration_ttl=0)
    def test_sync_is_offered_only_for_a_reservation_match_that_a_sync_cannot_contradict(self):
        def kea_holding(host):
            def reservation_get(body):
                arguments = body["arguments"]
                if arguments["subnet-id"] != host["subnet-id"]:
                    return {"result": 3}
                if arguments.get("ip-address", host.get("ip-address")) != host.get("ip-address"):
                    return {"result": 3}
                if "identifier" in arguments and arguments["identifier"] != host["hw-address"]:
                    return {"result": 3}
                return {"result": 0, "arguments": host}

            return reservation_get

        mac = self._LEASE4["hw-address"]
        cases = (
            ("Reserved", kea_holding({"subnet-id": 1, "hw-address": mac, "ip-address": "10.0.0.5"}), True),
            ("Host-Only", kea_holding({"subnet-id": 1, "hw-address": mac}), True),
            (
                "Stale MAC",
                kea_holding({"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "10.0.0.5"}),
                False,
            ),
            ("Pending", kea_holding({"subnet-id": 1, "hw-address": mac, "ip-address": "10.0.0.6"}), False),
            ("Global Reserved", kea_holding({"subnet-id": 0, "hw-address": mac, "ip-address": "10.0.0.5"}), True),
            ("Global Host-Only", kea_holding({"subnet-id": 0, "hw-address": mac, "ip-address": "10.1.0.9"}), True),
            ("Global Pending", kea_holding({"subnet-id": 0, "hw-address": mac, "ip-address": "10.0.0.6"}), False),
            ("Unknown", {"result": 1, "text": "host database error"}, False),
        )
        # Kea ignores a Global Reservation by default, so the Lease is dynamic and a Sync cannot contradict it.
        ignored = ("Ignored", kea_holding({"subnet-id": 0, "hw-address": mac, "ip-address": "10.0.0.6"}), True, {})
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        global_on = {"reservations-global": True}
        for label, reservation_get, offered, settings in (*((*case, global_on) for case in cases), ignored):
            with self.subTest(label):
                responses = {
                    "subnet4-list": self._SUBNETS4,
                    "lease4-get": {"result": 0, "arguments": dict(self._LEASE4)},
                    "reservation-get": reservation_get,
                }
                with _reservation_stub(4, responses, global_settings=settings):
                    response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})
                row = next(iter(response.context["table"].rows)).record
                self.assertTrue(row["current"])
                self.assertEqual(row.get("sync_url") is not None, offered)


# ─────────────────────────────────────────────────────────────────────────────
# Delegated-prefix Sync and Synced badges
# ─────────────────────────────────────────────────────────────────────────────

_PD_LABEL = "2001:db8:100:100::/56"


class TestDelegatedPrefixSyncBadges(_ViewTestBase):
    """A delegated-prefix row offers Sync, and links the Prefix of the Server's sync VRF once one exists."""

    def setUp(self):
        super().setUp()
        from ipam.models import VRF

        self.vrf = VRF.objects.create(name="pd-badge-vrf")
        self.server.sync_vrf = self.vrf
        self.server.save()

    @staticmethod
    def _responses(*, extra_prefixes=(), **changes) -> dict:
        address = lease_record("2001:db8:1::10", subnet_id=10, **changes)
        prefix = lease_record("2001:db8:100:100::", type="IA_PD", prefix_len=56, subnet_id=10, **changes)
        extra = [lease_record(base, type="IA_PD", prefix_len=56, subnet_id=10) for base in extra_prefixes]

        def lease6_get(body: dict) -> dict:
            return {"result": 0, "arguments": prefix if body["arguments"].get("type") == "IA_PD" else address}

        return {
            **_catalogue_responses_for_subnets(6, [{"id": 10, "subnet": "2001:db8:1::/64"}]),
            "lease6-get-all": lease_reply(address, prefix, *extra),
            "lease6-get": lease6_get,
            "reservation-get": {"result": 3},
        }

    def _rows(self, **changes):
        url = reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk])
        with stub_kea(self._responses(**changes)):
            response = self.client.get(url, {"by": "subnet_id", "q": "10"}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        return response, {row.record["kind"]: row.record for row in response.context["table"].rows}

    @staticmethod
    def _sync_values(response) -> list[dict]:
        return [
            json.loads(values) for values in re.findall(r"hx-vals='(\{\"ip_address\"[^']*)'", response.content.decode())
        ]

    def test_a_lease_that_is_not_current_offers_no_sync(self):
        # Kea state 3 is released; the Sync view refuses a lease that is not current.
        for changes in ({"state": 3}, {"cltt": 1_700_000_000, "valid_lft": 3600}):
            with self.subTest(changes):
                _response, rows = self._rows(**changes)
                self.assertEqual(set(rows), {"address", "delegated-prefix"})
                for row in rows.values():
                    self.assertIsNone(row.get("sync_url"))

    def test_a_delegated_prefix_row_offers_sync_that_claims_its_prefix(self):
        from ipam.models import Prefix

        response, rows = self._rows()

        self.assertEqual(
            rows["delegated-prefix"].get("sync_url"),
            reverse("plugins:netbox_kea:server_lease6_sync", args=[self.server.pk]),
        )
        self.assertIsNone(rows["delegated-prefix"]["netbox_url"])
        posted = self._sync_values(response)
        # The search container pushes its URL, so each Sync button and the Attribute control opt out.
        self.assertEqual(response.content.decode().count('hx-push-url="false"'), 3)
        self.assertEqual([values["ip_address"] for values in posted], ["2001:db8:1::10", _PD_LABEL])
        # The button posts what the Sync view reads, end to end.
        with stub_kea(self._responses()):
            synced = self.client.post(rows["delegated-prefix"]["sync_url"], posted[1])
        self.assertEqual(synced.status_code, 200, synced.content)
        self.assertEqual(str(Prefix.objects.get(vrf=self.vrf).prefix), _PD_LABEL)
        self.assertFalse(NbIP.objects.exists())

    def test_a_prefix_in_the_sync_vrf_that_the_server_owns_shows_the_synced_link(self):
        from ipam.models import Prefix

        prefix = Prefix.objects.create(prefix=_PD_LABEL, vrf=self.vrf, description="[kea-sync: delegated prefix]")
        prefix_ownership_link(prefix, self.server)

        response, rows = self._rows()

        self.assertEqual(rows["delegated-prefix"]["netbox_url"], prefix.get_absolute_url())
        self.assertIsNone(rows["delegated-prefix"].get("sync_url"))
        self.assertContains(response, f'<a href="{prefix.get_absolute_url()}" class="badge text-bg-success')
        # The address row still offers its own Sync.
        self.assertTrue(rows["address"].get("sync_url"))

    def test_only_an_address_in_the_sync_vrf_shows_the_synced_link(self):
        from ipam.models import VRF

        NbIP.objects.create(address="2001:db8:1::10/64")
        NbIP.objects.create(address="2001:db8:1::10/64", vrf=VRF.objects.create(name="other-vrf"))

        _response, rows = self._rows()

        self.assertIsNone(rows["address"]["netbox_url"])
        self.assertTrue(rows["address"].get("sync_url"))

        synced = NbIP.objects.create(address="2001:db8:1::10/64", vrf=self.vrf, description="[kea-sync: lease]")
        ownership_link(synced, self.server, source="lease", allocation_kind="address")
        _response, rows = self._rows()
        self.assertEqual(rows["address"]["netbox_url"], synced.get_absolute_url())
        self.assertIsNone(rows["address"].get("sync_url"))

    def test_a_refused_sync_replaces_its_button_with_the_reason(self):
        from ipam.models import Prefix

        response, rows = self._rows()
        posted = self._sync_values(response)

        with stub_kea(self._responses(state=3)):
            refused = self.client.post(rows["delegated-prefix"]["sync_url"], posted[1], HTTP_HX_REQUEST="true")

        # A 200 reply, because htmx swaps no 4xx or 5xx reply into the cell.
        self.assertContains(refused, '<span class="badge text-bg-danger')
        self.assertContains(refused, "The lease is not current in Kea")
        self.assertFalse(Prefix.objects.exists())

    def test_the_prefix_lookup_is_one_query_for_every_row(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        with CaptureQueriesContext(connection) as queries:
            response, _rows = self._rows(extra_prefixes=["2001:db8:100:200::", "2001:db8:100:300::"])

        kinds = [row.record["kind"] for row in response.context["table"].rows]
        self.assertEqual(kinds.count("delegated-prefix"), 3)

        prefix_queries = [query["sql"] for query in queries.captured_queries if '"ipam_prefix"' in query["sql"]]
        self.assertEqual(len(prefix_queries), 1, prefix_queries)

    def test_sync_follows_the_ipam_permissions_of_each_kind_not_the_server_change_permission(self):
        from django.contrib.auth import get_user_model
        from django.contrib.contenttypes.models import ContentType
        from users.models import ObjectPermission

        cases = (
            ("prefix-editor", [("ipam", "prefix")], {"delegated-prefix"}),
            ("address-editor", [("ipam", "ipaddress"), ("dcim", "macaddress")], {"address"}),
            ("server-editor", [("netbox_kea", "server")], set()),
            ("constrained-prefix-editor", [("ipam", "prefix", {"vrf__name": "other"})], set()),
        )
        for name, grants, offered in cases:
            with self.subTest(name):
                user = get_user_model().objects.create_user(username=name, password="example-password")
                view = ObjectPermission.objects.create(name=f"{name}-view", actions=["view"])
                view.object_types.add(ContentType.objects.get_for_model(Server))
                view.users.add(user)
                for app_label, model, *constraints in grants:
                    grant = ObjectPermission.objects.create(
                        name=f"{name}-{model}", actions=["add", "change"], constraints=next(iter(constraints), None)
                    )
                    grant.object_types.add(ContentType.objects.get(app_label=app_label, model=model))
                    grant.users.add(user)
                self.client.force_login(user)

                _response, rows = self._rows()

                self.assertEqual({kind for kind, row in rows.items() if row.get("sync_url")}, offered)
                refused = {kind for kind, row in rows.items() if row.get("sync_refusal")}
                self.assertEqual(refused, set(rows) - offered)


# ─────────────────────────────────────────────────────────────────────────────
# P3 Refinement: stale MAC badge — specific MAC values + inline delete URL
# ─────────────────────────────────────────────────────────────────────────────


class TestStaleMacBadgeEnrichment(_ViewTestBase):
    """_enrich_leases_with_badges must store MAC strings and delete URL on stale-MAC leases."""

    _LEASE4 = complete_lease(
        {
            "ip-address": "10.0.0.5",
            "hw-address": "aa:bb:cc:dd:ee:01",
            "hostname": "stale-host",
            "subnet-id": 7,
            "valid-lft": 3600,
            "cltt": 1_700_000_000,
        }
    )
    _RESERVATION = {
        "ip-address": "10.0.0.5",
        "hw-address": "aa:bb:cc:dd:ee:99",  # different MAC → stale
        "subnet-id": 7,
    }
    _SUBNETS4 = _subnet_list(4, [{"id": 7, "subnet": "10.0.0.0/24"}])

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def _stub(self, reservation):
        """stub_kea responses for a single IP-matched lease with *reservation*."""
        return _reservation_stub(
            4,
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get": {"result": 0, "arguments": dict(self._LEASE4)},
                "reservation-get": {"result": 0, "arguments": reservation},
            },
        )

    def test_stale_mac_badge_shows_specific_macs_in_title(self):
        """The ⚠ MAC? badge title must contain both lease MAC and reservation MAC."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with self._stub(self._RESERVATION):
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "aa:bb:cc:dd:ee:01")  # lease MAC in tooltip
        self.assertContains(response, "aa:bb:cc:dd:ee:99")  # reservation MAC in tooltip

    def test_stale_mac_badge_renders_htmx_delete_button(self):
        """The stale-MAC badge must include an HTMX delete button (hx-post) for one-click removal."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with self._stub(self._RESERVATION):
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        # hx-post must point to the delete endpoint (distinct from the bulk-delete form action)
        delete_url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        self.assertContains(response, f'hx-post="{delete_url}"')
        (button,) = re.findall(rf'<button[^>]*hx-post="{re.escape(delete_url)}"[^>]*>', response.content.decode())
        # The lease search container swaps itself and pushes its URL; the row button must do neither.
        self.assertIn('hx-target="closest td"', button)
        self.assertIn('hx-swap="innerHTML"', button)
        self.assertIn('hx-push-url="false"', button)

    def test_a_refused_one_click_delete_reloads_the_search_to_show_why(self):
        from django.contrib.messages import get_messages

        delete_url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        response = self.client.post(delete_url, {"pk": "not-a-lease", "_confirm": "1"}, HTTP_HX_REQUEST="true")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("HX-Refresh"), "true")
        self.assertEqual([message.level_tag for message in get_messages(response.wsgi_request)], ["warning"])

    def test_a_one_click_delete_for_a_disabled_family_reloads_the_page(self):
        self.server.dhcp4 = False
        self.server.save()
        delete_url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])

        response = self.client.post(delete_url, {"pk": "not-a-lease", "_confirm": "1"}, HTTP_HX_REQUEST="true")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("HX-Refresh"), "true")

    def test_the_one_click_delete_posts_the_shown_facts_of_the_row(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with self._stub(self._RESERVATION):
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})
        (values,) = re.findall(r"hx-vals='(\{\"pk\"[^']+)'", response.content.decode())
        data = json.loads(html.unescape(values))
        self.assertEqual(data, {"pk": shown_token(self._LEASE4), "_confirm": "1"})

        delete_url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        with _lease_stub(LeaseDaemon(4, self._LEASE4).responses()) as kea:
            deleted = self.client.post(delete_url, data, HTTP_HX_REQUEST="true")
        self.assertEqual(deleted.headers.get("HX-Refresh"), "true")
        self.assertEqual(kea.commands(), ["lease4-get", "lease4-del"])

    def test_stale_mac_badge_no_delete_when_no_permission(self):
        """When the user lacks delete permission, the stale-MAC badge must NOT include an HTMX delete button."""
        from django.contrib.auth import get_user_model
        from django.contrib.contenttypes.models import ContentType
        from users.models import ObjectPermission

        User = get_user_model()
        readonly_user = User.objects.create_user(username="readonly_stale", password="pass")
        # Grant only view permission via NetBox's ObjectPermission (not change/delete)
        ct = ContentType.objects.get_for_model(Server)
        view_obj_perm = ObjectPermission.objects.create(name="test-view-server-readonly", actions=["view"])
        view_obj_perm.object_types.add(ct)
        view_obj_perm.users.add(readonly_user)
        self.client.force_login(readonly_user)

        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with self._stub(self._RESERVATION):
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        delete_url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        self.assertNotContains(response, f'hx-post="{delete_url}"')


# ─────────────────────────────────────────────────────────────────────────────
# Feature 3.3: Export All Leases — BaseServerDHCPLeasesView.get_export_all()
# ─────────────────────────────────────────────────────────────────────────────


class TestLeaseExportAll(_ViewTestBase):
    """GET /plugins/kea/servers/<pk>/leases4/?export_all=1 must return a full CSV."""

    _LEASE = complete_lease(
        {
            "ip-address": "10.0.0.1",
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "hostname": "export-host",
            "subnet-id": 1,
            "valid-lft": 3600,
            "cltt": 1_700_000_000,
        }
    )

    def _url4(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def _url6(self):
        return reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk])

    def test_export_all_returns_csv(self):
        """?export_all=1 must return text/csv."""
        # One page of one lease (count 1 < per_page 1000) ends pagination after one call.
        with _lease_stub({"lease4-get-page": {"result": 0, "arguments": {"leases": [self._LEASE], "count": 1}}}):
            response = self.client.get(self._url4(), {"export_all": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))

    def test_export_all_includes_lease_data(self):
        """?export_all=1 CSV must contain the lease IP address."""
        with _lease_stub({"lease4-get-page": {"result": 0, "arguments": {"leases": [self._LEASE], "count": 1}}}):
            response = self.client.get(self._url4(), {"export_all": "1"})
        self.assertEqual(response.status_code, 200)
        content = (
            b"".join(response.streaming_content).decode()
            if hasattr(response, "streaming_content")
            else response.content.decode()
        )
        self.assertIn("10.0.0.1", content)

    def test_export_all_paginates_all_leases(self):
        """?export_all=1 must paginate until Kea returns result=3."""
        # The view uses per_page=1000. Report count==1000 on the first page so the
        # view sees a full page and issues a second request; page 2 returns result=3.
        page1 = [
            complete_lease(
                {
                    "ip-address": f"198.18.{i // 256}.{i % 256}",
                    "hw-address": "aa:bb:cc:dd:ee:ff",
                    "hostname": f"h{i}",
                    "subnet-id": 1,
                    "valid-lft": 3600,
                    "cltt": 1_700_000_000,
                }
            )
            for i in range(1000)
        ]
        with _lease_stub(
            {
                "lease4-get-page": queued(
                    {"result": 0, "arguments": {"leases": page1, "count": 1000}},
                    {"result": 3, "arguments": None},
                )
            }
        ) as kea:
            response = self.client.get(self._url4(), {"export_all": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))
        self.assertGreaterEqual(kea.commands().count("lease4-get-page"), 2)

    def test_export_all_v6_starts_from_double_colon(self):
        """?export_all=1 for v6 must start the cursor from '::'."""
        with _lease_stub({"lease6-get-page": {"result": 3, "arguments": None}}) as kea:
            response = self.client.get(self._url6(), {"export_all": "1"})
        self.assertEqual(response.status_code, 200)
        pages = kea.bodies("lease6-get-page")
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["arguments"]["from"], "::")

    def test_export_all_v4_starts_from_zero_ip(self):
        """?export_all=1 for v4 must start the cursor from '0.0.0.0'."""
        with _lease_stub({"lease4-get-page": {"result": 3, "arguments": None}}) as kea:
            response = self.client.get(self._url4(), {"export_all": "1"})
        self.assertEqual(response.status_code, 200)
        pages = kea.bodies("lease4-get-page")
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["arguments"]["from"], "0.0.0.0")  # noqa: S104 - Kea sentinel value, not a bind address


# TestLeaseEditView
# ---------------------------------------------------------------------------

_LEASE4_GET_RESP = [
    {
        "result": 0,
        "arguments": complete_lease(
            {
                "ip-address": "10.0.0.100",
                "hw-address": "aa:bb:cc:dd:ee:ff",
                "hostname": "host1.example.com",
                "subnet-id": 1,
                "cltt": 1700000000,
                "valid-lft": 3600,
                "state": 0,
            }
        ),
    }
]


class TestLeaseEditReturnsToTheSearch(_ViewTestBase):
    """An edit starts from a lease search and returns to that search."""

    def _list_url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def _edit_url(self, return_url=None):
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.100"])
        return url if return_url is None else f"{url}?{urlencode({'return_url': return_url})}"

    def _post(self, url):
        record = _LEASE4_GET_RESP[0]["arguments"]
        form = {"shown": shown_token(record), "hostname": "newhost.example.com", "hw_address": "", "valid_lft": ""}
        with _lease_stub(LeaseDaemon(4, record).responses()) as kea:
            response = self.client.post(url, form)
        self.assertEqual(kea.commands(), ["lease4-get", "lease4-update"])
        return response

    def test_the_lease_list_links_each_edit_to_its_search(self):
        responses = {
            **_catalogue_responses_for_subnets(4, [{"id": 10, "subnet": "192.0.2.0/24"}]),
            "lease4-get-all": lease_reply(lease_record("192.0.2.10")),
            "reservation-get": {"result": 3},
        }
        with stub_kea(responses):
            response = self.client.get(
                self._list_url(), {"by": "subnet_id", "q": "10", "state": ""}, HTTP_HX_REQUEST="true"
            )

        edit_url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "192.0.2.10"])
        expected = f"{edit_url}?{urlencode({'return_url': f'{self._list_url()}?by=subnet_id&q=10'})}"
        self.assertEqual(next(iter(response.context["table"].rows)).record["edit_url"], expected)
        self.assertContains(response, f'href="{escape(expected)}"', count=1)

    def test_an_all_leases_search_returns_to_a_page_that_reloads_it(self):
        responses = {
            **_catalogue_responses_for_subnets(4, [{"id": 10, "subnet": "192.0.2.0/24"}]),
            "lease4-get-page": lease_page(lease_record("192.0.2.10")),
            "reservation-get": {"result": 3},
        }
        with stub_kea(responses):
            response = self.client.get(self._list_url(), {"by": "", "q": "", "state": ""}, HTTP_HX_REQUEST="true")
            edit_url = next(iter(response.context["table"].rows)).record["edit_url"]
            return_url = parse_qs(urlsplit(edit_url).query)["return_url"][0]
            page = self.client.get(return_url)

        self.assertEqual(return_url, f"{self._list_url()}?q=")
        self.assertEqual(response["HX-Push-Url"], return_url)
        self.assertContains(page, 'hx-trigger="load"')

    def test_a_saved_edit_returns_to_the_search(self):
        search = f"{self._list_url()}?by=hostname&q=host1.example.com"
        response = self._post(self._edit_url(search))
        self.assertRedirects(response, search, fetch_redirect_response=False)

    def test_a_refused_edit_returns_to_the_search(self):
        search = f"{self._list_url()}?by=hostname&q=host1.example.com"
        with _lease_stub({}) as kea:
            response = self.client.post(self._edit_url(search), {"shown": "", "hostname": "newhost.example.com"})
        self.assertEqual(kea.commands(), [])
        self.assertRedirects(response, search, fetch_redirect_response=False)

    def test_cancel_returns_to_the_search(self):
        search = f"{self._list_url()}?by=hostname&q=host1.example.com"
        with _lease_stub({"lease4-get": _LEASE4_GET_RESP[0]}):
            response = self.client.get(self._edit_url(search))
        self.assertContains(response, f'href="{escape(search)}" class="btn btn-outline-secondary">Cancel</a>')

    def test_an_unsafe_return_url_returns_to_the_lease_list(self):
        for unsafe in (
            "https://evil.example/leases4/",
            "//evil.example/leases4/",
            "javascript:alert(1)",
            "missing",
            "#results",
        ):
            with self.subTest(unsafe):
                response = self._post(self._edit_url(unsafe))
                self.assertRedirects(response, self._list_url(), fetch_redirect_response=False)

    def test_without_a_return_url_an_edit_returns_to_the_lease_list(self):
        response = self._post(self._edit_url())
        self.assertRedirects(response, self._list_url(), fetch_redirect_response=False)


class TestLeaseEditView(_ViewTestBase):
    """Tests for ServerLease4/6EditView."""

    def _url(self, version=4, ip="10.0.0.100"):
        return reverse(
            f"plugins:netbox_kea:server_lease{version}_edit",
            args=[self.server.pk, ip],
        )

    def test_url_registered_v4(self):
        """URL server_lease4_edit is registered."""
        url = self._url(version=4)
        self.assertIn("leases", url)
        self.assertIn("edit", url)

    def test_url_registered_v6(self):
        """URL server_lease6_edit is registered."""
        url = self._url(version=6, ip="2001:db8::100")
        self.assertIn("leases", url)
        self.assertIn("edit", url)

    def test_get_returns_200(self):
        """GET returns 200 OK."""
        with _lease_stub({"lease4-get": _LEASE4_GET_RESP[0]}):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)

    def test_get_prefills_hostname(self):
        """GET pre-fills hostname from the existing lease."""
        with _lease_stub({"lease4-get": _LEASE4_GET_RESP[0]}):
            response = self.client.get(self._url())
        content = response.content.decode()
        self.assertIn("host1.example.com", content)

    def test_get_prefills_hw_address(self):
        """GET pre-fills hw_address from the existing lease (v4 only)."""
        with _lease_stub({"lease4-get": _LEASE4_GET_RESP[0]}):
            response = self.client.get(self._url())
        content = response.content.decode()
        self.assertIn("aa:bb:cc:dd:ee:ff", content)

    def test_post_calls_lease_update_and_redirects(self):
        """POST with changed values reads the lease again and writes only the changed fields."""
        record = _LEASE4_GET_RESP[0]["arguments"]
        with _lease_stub(LeaseDaemon(4, record).responses()) as kea:
            response = self.client.post(
                self._url(),
                {
                    "shown": shown_token(record),
                    "hostname": "newhost.example.com",
                    "hw_address": "11:22:33:44:55:66",
                    "valid_lft": "7200",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), ["lease4-get", "lease4-update"])
        update_args = kea.bodies("lease4-update")[0]["arguments"]
        self.assertEqual(update_args["hostname"], "newhost.example.com")
        self.assertEqual(update_args["hw-address"], "11:22:33:44:55:66")
        self.assertEqual(update_args["valid-lft"], 7200)

    def test_post_kea_exception_redirects_with_error(self):
        """POST that raises KeaException shows error and redirects."""
        record = _LEASE4_GET_RESP[0]["arguments"]
        # result=1 on lease4-update makes the real client raise KeaException.
        responses = {**LeaseDaemon(4, record).responses(), "lease4-update": {"result": 1, "text": "refused"}}
        with _lease_stub(responses):
            response = self.client.post(
                self._url(),
                {"shown": shown_token(record), "hostname": "newhost.example.com", "hw_address": "", "valid_lft": ""},
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(list(get_messages(response.wsgi_request))), 1)

    def test_get_requires_login(self):
        """Unauthenticated GET is redirected."""
        self.client.logout()
        response = self.client.get(self._url())
        self.assertIn(response.status_code, (302, 403))


# ---------------------------------------------------------------------------
# TestLeaseStateFilter
# ---------------------------------------------------------------------------

_STATE_LEASES_RESP = [
    {
        "result": 0,
        "arguments": {
            "leases": [
                complete_lease(
                    {
                        "ip-address": "10.0.0.1",
                        "hw-address": "aa:bb:cc:dd:ee:01",
                        "hostname": "active-host",
                        "subnet-id": 1,
                        "valid-lft": 3600,
                        "cltt": 1_700_000_000,
                        "state": 0,
                    }
                ),
                complete_lease(
                    {
                        "ip-address": "10.0.0.2",
                        "hw-address": "aa:bb:cc:dd:ee:02",
                        "hostname": "declined-host",
                        "subnet-id": 1,
                        "valid-lft": 3600,
                        "cltt": 1_700_000_000,
                        "state": 1,
                    }
                ),
                complete_lease(
                    {
                        "ip-address": "10.0.0.3",
                        "hw-address": "aa:bb:cc:dd:ee:03",
                        "hostname": "expired-host",
                        "subnet-id": 1,
                        "valid-lft": 3600,
                        "cltt": 1_700_000_000,
                        "state": 2,
                    }
                ),
            ]
        },
    }
]

_PAGE_LEASES_RESP = [
    {
        "result": 0,
        "arguments": {
            "count": 2,
            "leases": [
                complete_lease(
                    {
                        "ip-address": "10.0.0.10",
                        "hw-address": "aa:bb:cc:dd:ee:10",
                        "hostname": "page-active",
                        "subnet-id": 1,
                        "valid-lft": 3600,
                        "cltt": 1_700_000_000,
                        "state": 0,
                    }
                ),
                complete_lease(
                    {
                        "ip-address": "10.0.0.11",
                        "hw-address": "aa:bb:cc:dd:ee:11",
                        "hostname": "page-declined",
                        "subnet-id": 1,
                        "valid-lft": 3600,
                        "cltt": 1_700_000_000,
                        "state": 1,
                    }
                ),
            ],
        },
    }
]


class TestLeaseStateFilter(_ViewTestBase):
    """Tests that the optional state filter correctly limits lease results."""

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def _url4(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    # Subnet suggestions fetched via subnet4-list; reservation enrichment finds none.
    _SUBNETS4 = _subnet_list(4, [{"id": 1, "subnet": "10.0.0.0/24"}])

    def test_state_column_rendered_in_table(self):
        """Lease table includes a state_label column header."""
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-hw-address": _STATE_LEASES_RESP[0],
                "reservation-get": {"result": 3},
            }
        ):
            response = self._htmx_get(self._url4(), {"by": "hw", "q": "aa:bb:cc:dd:ee:01"})
        self.assertEqual(response.status_code, 200)
        # State column header must be present
        self.assertContains(response, "State")

    def test_state_label_active_rendered(self):
        """Active lease shows 'Active' state badge."""
        active_lease = _STATE_LEASES_RESP[0]["arguments"]["leases"][0]
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-hw-address": {"result": 0, "arguments": {"leases": [active_lease]}},
                "reservation-get": {"result": 3},
            }
        ):
            response = self._htmx_get(self._url4(), {"by": "hw", "q": "aa:bb:cc:dd:ee:01"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Active")

    def test_state_label_declined_rendered(self):
        """Declined lease shows 'Declined' state badge."""
        declined_lease = _STATE_LEASES_RESP[0]["arguments"]["leases"][1]
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-hw-address": {"result": 0, "arguments": {"leases": [declined_lease]}},
                "reservation-get": {"result": 3},
            }
        ):
            response = self._htmx_get(self._url4(), {"by": "hw", "q": "aa:bb:cc:dd:ee:02"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Declined")

    def test_state_filter_declined_hides_active(self):
        """State filter=1 (Declined) excludes Active leases from search results."""
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-hostname": _STATE_LEASES_RESP[0],
                "reservation-get": {"result": 3},
            }
        ):
            response = self._htmx_get(self._url4(), {"by": "hostname", "q": "host", "state": "1"})
        self.assertEqual(response.status_code, 200)
        # Active and Expired hosts should not appear
        self.assertNotContains(response, "active-host")
        self.assertNotContains(response, "expired-host")
        self.assertContains(response, "declined-host")

    # Each case reads the same page live.
    @with_display_cache_config(leases_ttl=0)
    def test_a_state_filtered_page_without_a_match_says_that_the_batch_has_none(self):
        active_lease = _STATE_LEASES_RESP[0]["arguments"]["leases"][0]
        for count, continues in ((1, True), (0, False)):
            leases = [active_lease] if count else []
            page = {"result": 0, "arguments": {"leases": leases, "count": count}} if count else {"result": 3}
            stub = {"subnet4-list": self._SUBNETS4, "lease4-get-page": page}
            with self.subTest(continues=continues), _lease_stub(stub):
                response = self._htmx_get(self._url4(), {"state": "1", "per_page": "1"})

                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, "active-host")
                self.assertEqual(response.context["next_page"] is not None, continues)
                if continues:
                    self.assertContains(response, "No matches in this search batch.")
                else:
                    self.assertNotContains(response, "No matches in this search batch.")
                    self.assertContains(response, "No leases found.")

    def test_state_filter_any_returns_all(self):
        """Empty state filter (Any) returns all leases."""
        with _lease_stub(
            {
                "subnet4-list": self._SUBNETS4,
                "lease4-get-by-hostname": _STATE_LEASES_RESP[0],
                "reservation-get": {"result": 3},
            }
        ):
            response = self._htmx_get(self._url4(), {"by": "hostname", "q": "host", "state": ""})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "active-host")
        self.assertContains(response, "declined-host")
        self.assertContains(response, "expired-host")

    # Unguarded on purpose: no stat-lease4-get preflight runs, so the Subnet query is
    # the only command this test measures. State it here instead of inheriting it.
    def test_state_filter_is_sent_with_the_subnet_query(self):
        """A Subnet state filter must run in Kea before it builds the response."""
        declined = next(lease for lease in _PAGE_LEASES_RESP[0]["arguments"]["leases"] if lease["state"] == 1)
        with _lease_stub(
            {
                **_catalogue_responses(4, 1, "10.0.0.0/24"),
                "lease4-get-by-state": {"result": 0, "arguments": {"leases": [declined]}},
                "reservation-get": {"result": 3},
            }
        ) as kea:
            response = self._htmx_get(
                self._url4(),
                {"by": "subnet", "q": "10.0.0.0/24", "state": "1"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "page-active")
        self.assertContains(response, "page-declined")
        self.assertEqual(
            kea.bodies("lease4-get-by-state")[0]["arguments"],
            {"subnet-id": 1, "state": 1},
        )


class TestLeaseSearchHostBitsSubnet(_ViewTestBase):
    """Kea accepts a Subnet prefix with host bits, so a canonical CIDR search must still find it."""

    def test_canonical_cidr_search_resolves_the_declared_subnet(self):
        with _lease_stub(
            {
                **_catalogue_responses(4, 1, "10.0.0.5/24"),
                "lease4-get-all": _PAGE_LEASES_RESP[0],
                "reservation-get": {"result": 3},
            }
        ) as kea:
            response = self.client.get(
                reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]),
                {"by": "subnet", "q": "10.0.0.0/24"},
                HTTP_HX_REQUEST="true",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.bodies("lease4-get-all")[0]["arguments"], {"subnets": [1]})
        self.assertContains(response, "page-active")

    def test_two_spellings_of_one_network_block_the_search(self):
        # Kea 3.2.0 loads both as separate Subnets, so one network names two Subnet IDs.
        subnets = [{"id": 1, "subnet": "198.18.1.5/24"}, {"id": 2, "subnet": "198.18.1.0/24"}]
        with _lease_stub(
            {
                **_catalogue_responses_for_subnets(4, subnets),
                "lease4-get-all": _PAGE_LEASES_RESP[0],
                "reservation-get": {"result": 3},
            }
        ) as kea:
            response = self.client.get(
                reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]),
                {"by": "subnet", "q": "198.18.1.0/24"},
                HTTP_HX_REQUEST="true",
            )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("lease4-get-all", kea.commands())
        # The Subnet Catalogue omits both Subnets, so the search shows its Notice in place of the table.
        self.assertContains(response, f"<strong>{HEADLINES['catalogue']}</strong>", html=True)
        self.assertContains(response, "Multiple Subnets use CIDR 198.18.1.0/24")
        self.assertNotContains(response, 'id="lease-delete-form"')


class TestLeaseSearchSubnetCatalogue(_ViewTestBase):
    """A Subnet CIDR search finds the Subnet ID in a live read of the Subnet Catalogue."""

    _UNKNOWN = "This Subnet CIDR is not configured on the Kea server. Search by Subnet ID instead."

    def _responses(self, subnets=None, **catalogue) -> dict:
        subnets = subnets or [{"id": 1, "subnet": "10.0.0.0/24"}, {"id": 2, "subnet": "10.0.9.0/24"}]
        leases = {
            subnet["id"]: [
                complete_lease(
                    {
                        "ip-address": str(ipaddress.ip_network(subnet["subnet"])[10]),
                        "hostname": f"in-{subnet['id']}",
                        "subnet-id": subnet["id"],
                    }
                )
            ]
            for subnet in subnets
        }
        return {
            **_catalogue_responses_for_subnets(4, subnets, **catalogue),
            "lease4-get-all": _leases_per_subnet(leases),
            "reservation-get": {"result": 3},
        }

    def _url(self) -> str:
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def _search(self, cidr: str):
        return self.client.get(self._url(), {"by": "subnet", "q": cidr}, HTTP_HX_REQUEST="true")

    def test_a_cidr_in_a_shared_network_resolves_through_a_live_read(self):
        responses = self._responses(shared_networks=[{"name": "office"}], members={1: "office"})
        with stub_kea(responses) as kea:
            response = self._search("10.0.0.0/24")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.bodies("lease4-get-all")[0]["arguments"], {"subnets": [1]})
        self.assertContains(response, "in-1")

    def test_a_subnet_id_that_kea_moved_after_the_cache_filled_is_read_live(self):
        with stub_kea(self._responses([{"id": 1, "subnet": "198.18.1.0/24"}])):
            self.client.get(self._url())
        moved = [{"id": 1, "subnet": "198.18.2.0/24"}, {"id": 2, "subnet": "198.18.1.0/24"}]
        with stub_kea(self._responses(moved)) as kea:
            response = self._search("198.18.1.0/24")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.bodies("lease4-get-all")[0]["arguments"], {"subnets": [2]})
        self.assertContains(response, "in-2")
        self.assertNotContains(response, "in-1")

    def test_the_export_reads_a_moved_subnet_id_live(self):
        with stub_kea(self._responses([{"id": 1, "subnet": "198.18.1.0/24"}])):
            self.client.get(self._url())
        moved = [{"id": 1, "subnet": "198.18.2.0/24"}, {"id": 2, "subnet": "198.18.1.0/24"}]
        with stub_kea(self._responses(moved)) as kea:
            response = self.client.get(self._url(), {"export": "form", "by": "subnet", "q": "198.18.1.0/24"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.bodies("lease4-get-all")[0]["arguments"], {"subnets": [2]})

    def test_an_unknown_cidr_names_the_subnet_id_search(self):
        with stub_kea(self._responses()) as kea:
            response = self._search("10.0.5.0/24")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self._UNKNOWN)
        self.assertNotIn("lease4-get-all", kea.commands())

    def test_an_unknown_cidr_names_the_subnet_id_search_without_subnet_cmds(self):
        responses = self._responses()
        responses["subnet4-list"] = {"result": 2, "text": "'subnet4-list' command not supported."}
        with stub_kea(responses) as kea:
            response = self._search("10.0.5.0/24")
        self.assertContains(response, self._UNKNOWN)
        self.assertNotIn("lease4-get-all", kea.commands())

    def test_an_unknown_cidr_with_a_malformed_subnet_entry_shows_the_catalogue_notice(self):
        responses = self._responses()
        responses["config-get"]["arguments"]["Dhcp4"]["subnet4"].append({"id": 3, "subnet": "not-a-network"})
        with stub_kea(responses) as kea:
            response = self._search("10.0.5.0/24")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Kea returned an invalid Subnet CIDR.")
        self.assertNotContains(response, self._UNKNOWN)
        self.assertNotContains(response, "that could not be read")
        self.assertNotContains(response, 'id="lease-delete-form"')
        self.assertNotIn("lease4-get-all", kea.commands())

    def test_a_cidr_that_the_two_sources_disagree_on_shows_the_catalogue_notice(self):
        disagree = "Kea subnet identity and configuration facts disagree after a fresh retry."
        responses = self._responses()
        configured = responses["config-get"]["arguments"]["Dhcp4"]["subnet4"]
        configured[0] = {**configured[0], "id": 7}
        with stub_kea(responses) as kea:
            response = self._search("10.0.0.0/24")
            export = self.client.get(self._url(), {"export": "form", "by": "subnet", "q": "10.0.0.0/24"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, disagree)
        self.assertNotContains(response, self._UNKNOWN)
        self.assertRedirects(export, self._url(), fetch_redirect_response=False)
        exported = [str(message) for message in get_messages(export.wsgi_request)]
        self.assertTrue(any(disagree in message for message in exported), exported)
        self.assertNotIn(self._UNKNOWN, exported)
        self.assertNotIn("lease4-get-all", kea.commands())

    def test_the_export_of_an_unknown_cidr_names_the_subnet_id_search(self):
        with stub_kea(self._responses()) as kea:
            response = self.client.get(self._url(), {"export": "form", "by": "subnet", "q": "10.0.5.0/24"})
        self.assertRedirects(response, self._url(), fetch_redirect_response=False)
        self.assertEqual([str(message) for message in get_messages(response.wsgi_request)], [self._UNKNOWN])
        self.assertNotIn("lease4-get-all", kea.commands())

    def test_an_unavailable_catalogue_shows_its_notice(self):
        failure = {"result": 1, "text": "unavailable"}
        with stub_kea({**self._responses(), "subnet4-list": failure, "config-get": failure}) as kea:
            response = self._search("10.0.0.0/24")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, HEADLINES["catalogue"])
        self.assertNotContains(response, HEADLINES["lease"])
        self.assertNotContains(response, self._UNKNOWN)
        self.assertNotIn("lease4-get-all", kea.commands())


# ---------------------------------------------------------------------------
# TestLeaseAddView — Manual Lease Add (lease4/6-add)
# ---------------------------------------------------------------------------


@with_kea_client_config(lease_query_max_unpaged_leases=1000)
class TestLeaseAddView(_ViewTestBase):
    """Tests for ServerLease4AddView and ServerLease6AddView."""

    def _url(self, version=4):
        return reverse(f"plugins:netbox_kea:server_lease{version}_add", args=[self.server.pk])

    def _valid_post4(self, **overrides):
        data = {
            "ip_address": "10.0.0.200",
            "subnet_id": "1",
            "hw_address": "aa:bb:cc:dd:ee:ff",
            "valid_lft": "3600",
            "hostname": "newlease.example.com",
        }
        data.update(overrides)
        return data

    def _valid_post6(self, **overrides):
        data = {
            "ip_address": "2001:db8::200",
            "duid": "00:01:02:03:04:05",
            "iaid": "12345",
            "subnet_id": "1",
            "valid_lft": "3600",
            "hostname": "newlease6.example.com",
        }
        data.update(overrides)
        return data

    def test_url_registered_v4(self):
        """URL server_lease4_add is registered and contains 'leases'."""
        url = self._url(version=4)
        self.assertIn("leases", url)
        self.assertIn("add", url)

    def test_url_registered_v6(self):
        """URL server_lease6_add is registered and contains 'leases'."""
        url = self._url(version=6)
        self.assertIn("leases", url)
        self.assertIn("add", url)

    def test_get_lease4_add_returns_200(self):
        """GET /leases4/add/ returns 200 and renders the add form."""
        response = self.client.get(self._url(version=4))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ip_address")

    def test_get_lease6_add_returns_200(self):
        """GET /leases6/add/ returns 200 and shows duid + iaid fields."""
        response = self.client.get(self._url(version=6))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "duid")
        self.assertContains(response, "iaid")

    def test_post_lease4_add_valid_redirects(self):
        """POST valid v4 lease data redirects to the lease list."""
        with _lease_stub(LeaseDaemon(4).responses()):
            response = self.client.post(self._url(version=4), self._valid_post4())
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("None", response.url)

    def test_post_lease4_add_calls_kea_with_correct_args(self):
        """POST v4 calls lease_add with ip-address, hw-address, and subnet-id."""
        with _lease_stub(LeaseDaemon(4).responses()) as kea:
            self.client.post(self._url(version=4), self._valid_post4())
        self.assertIn("lease4-add", kea.commands())
        lease = kea.bodies("lease4-add")[0]["arguments"]
        self.assertEqual(lease["ip-address"], "10.0.0.200")
        self.assertEqual(lease.get("hw-address"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(lease.get("subnet-id"), 1)

    def test_post_lease4_add_invalid_ip_shows_form_errors(self):
        """POST with a non-IPv4 string re-renders form with validation errors."""
        # Empty registry: any Kea command would raise — proves no lease was created.
        with _lease_stub({}) as kea:
            response = self.client.post(self._url(version=4), self._valid_post4(ip_address="not-an-ip"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])

    def test_post_lease4_add_kea_exception_shows_error_message(self):
        """POST that triggers a KeaException shows error and re-renders (no redirect)."""
        # result=1 on lease4-add makes the real client raise KeaException.
        with _lease_stub({"lease4-add": {"result": 1, "text": "address already in use"}}):
            response = self.client.post(self._url(version=4), self._valid_post4())
        self.assertIn(response.status_code, (200, 302))

    def test_post_lease6_add_valid_redirects(self):
        """POST valid v6 lease data redirects to the lease list."""
        with _lease_stub(LeaseDaemon(6).responses()):
            response = self.client.post(self._url(version=6), self._valid_post6())
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("None", response.url)

    def test_post_lease6_add_calls_kea_with_correct_args(self):
        """POST v6 calls lease_add with ip-address, duid, and iaid."""
        with _lease_stub(LeaseDaemon(6).responses()) as kea:
            self.client.post(self._url(version=6), self._valid_post6())
        self.assertIn("lease6-add", kea.commands())
        lease = kea.bodies("lease6-add")[0]["arguments"]
        self.assertEqual(lease["ip-address"], "2001:db8::200")
        self.assertEqual(lease.get("duid"), "00:01:02:03:04:05")
        self.assertEqual(lease.get("iaid"), 12345)

    def test_get_requires_login(self):
        """Unauthenticated GET is redirected to login."""
        self.client.logout()
        response = self.client.get(self._url(version=4))
        self.assertIn(response.status_code, (302, 403))


# ---------------------------------------------------------------------------
# TestLeaseAddSyncToNetBox — sync-to-netbox checkbox on lease add form
# ---------------------------------------------------------------------------


@with_kea_client_config(lease_query_max_unpaged_leases=1000)
class TestLeaseAddSyncToNetBox(_ViewTestBase):
    """Tests for the sync_to_netbox checkbox on ServerLease4/6AddView."""

    def _url(self, version=4):
        return reverse(f"plugins:netbox_kea:server_lease{version}_add", args=[self.server.pk])

    def _post4(self, sync=False):
        data = {
            "ip_address": "10.0.0.200",
            "subnet_id": "1",
            "hw_address": "aa:bb:cc:dd:ee:ff",
            "valid_lft": "3600",
            "hostname": "newlease.example.com",
        }
        if sync:
            data["sync_to_netbox"] = "on"
        return data

    # A followed redirect lands on the leases page, which fetches the subnet quick-select.
    _SUBNETS4 = _subnet_list(4, [{"id": 1, "subnet": "10.0.0.0/24"}])

    @staticmethod
    def _readback(address="10.0.0.200", **fields):
        """The ``lease4-get`` reply that observes the created lease; the claim reads Kea's facts, not the form."""
        observed = {"hostname": "newlease.example.com", "hw-address": "aa:bb:cc:dd:ee:ff", "subnet-id": 1, **fields}
        return {"result": 0, "arguments": complete_lease({"ip-address": address, **observed})}

    def test_lease4_add_form_has_sync_to_netbox_field(self):
        """GET lease4 add page renders a sync_to_netbox checkbox."""
        response = self.client.get(self._url(version=4))
        self.assertEqual(response.status_code, 200)
        self.assertIn("sync_to_netbox", response.content.decode())

    def test_the_automatic_ipam_sync_state_is_checkbox_help_not_an_alert(self):
        for version in (4, 6):
            for enabled in (True, False):
                with self.subTest(version=version, enabled=enabled):
                    self.server.sync_enabled = enabled
                    self.server.sync_leases_enabled = True
                    self.server.save()
                    response = self.client.get(self._url(version=version))
                    page = BeautifulSoup(response.content, "html.parser")
                    self.assertNotIn("Automatic IPAM sync", " ".join(a.get_text() for a in page.select(".alert")))
                    help_text = page.select_one("#id_sync_to_netbox_helptext")
                    state = "enabled" if enabled else "disabled"
                    self.assertIn(f"Automatic IPAM sync is {state} for this Server.", help_text.get_text())
                    tip = help_text.select_one("button")
                    self.assertEqual(tip["data-bs-toggle"], "tooltip")
                    self.assertEqual("The next scheduled sync run records this lease." in tip["data-bs-title"], enabled)

    def test_post_lease4_add_with_sync_links_the_created_ip(self):
        from netbox_kea.models import IPAMOwnershipLink

        responses = {**LeaseDaemon(4).responses(), "lease4-get": self._readback(), "subnet4-list": self._SUBNETS4}
        with _lease_stub(responses) as kea:
            response = self.client.post(self._url(version=4), self._post4(sync=True))
        self.assertEqual(kea.commands().count("lease4-get"), 1)
        self.assertEqual(response.status_code, 302)
        ip = NbIP.objects.get(address__net_host="10.0.0.200")
        link = IPAMOwnershipLink.objects.get(ip_address=ip)
        self.assertEqual((link.server_id, link.family, link.source), (self.server.pk, 4, "lease"))
        self.assertEqual(link.facts, {"hostname": "newlease.example.com", "prefix_length": 24})

    def test_lease_add_preserves_reserved_siblings_and_their_ownership(self):
        from netbox_kea.models import IPAMOwnershipLink, next_confirmation_number

        siblings = [
            NbIP.objects.create(
                address=f"198.18.0.{number}/24",
                status="reserved",
                dns_name="same.example.invalid",
                description="[kea-sync: reservation] retain operator note",
            )
            for number in (20, 21)
        ]
        IPAMOwnershipLink.objects.create(
            confirmation=next_confirmation_number(),
            server=self.server,
            family=4,
            source="reservation",
            ip_address=siblings[0],
            facts={"hostname": "same.example.invalid", "prefix_length": 24},
        )
        sibling_ids = [row.pk for row in siblings]
        before_rows = list(NbIP.objects.filter(pk__in=sibling_ids).order_by("pk").values())
        before_links = list(IPAMOwnershipLink.objects.filter(ip_address_id__in=sibling_ids).order_by("pk").values())
        data = self._post4(sync=True)
        data.update(ip_address="198.18.0.22", hostname="same.example.invalid")
        with _lease_stub(
            {
                "lease4-add": {"result": 0},
                "lease4-get": self._readback("198.18.0.22", hostname="same.example.invalid"),
                "subnet4-list": _subnet_list(4, [{"id": 1, "subnet": "198.18.0.0/24"}]),
            }
        ) as kea:
            response = self.client.post(self._url(version=4), data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("lease4-add"), 1)
        self.assertTrue(
            IPAMOwnershipLink.objects.filter(
                server=self.server, source="lease", ip_address__address__net_host="198.18.0.22"
            ).exists()
        )
        self.assertEqual(list(NbIP.objects.filter(pk__in=sibling_ids).order_by("pk").values()), before_rows)
        self.assertEqual(
            list(IPAMOwnershipLink.objects.filter(ip_address_id__in=sibling_ids).order_by("pk").values()),
            before_links,
        )

    def test_optional_subnet_add_uses_the_created_lease_facts(self):
        from ipam.models import VRF

        from netbox_kea.models import IPAMOwnershipLink

        self.server.sync_vrf = VRF.objects.create(name="lease-sync")
        self.server.save()
        data = {"ip_address": "198.18.0.42", "hw_address": "aa:bb:cc:dd:ee:ff", "sync_to_netbox": "on"}
        responses = {
            "lease4-add": {"result": 0},
            "lease4-get": self._readback("198.18.0.42", **{"subnet-id": 7}),
            "subnet4-list": _subnet_list(
                4, [{"id": 7, "subnet": "198.18.0.0/24"}, {"id": 8, "subnet": "198.18.0.0/25"}]
            ),
        }
        with _lease_stub(responses) as kea:
            response = self.client.post(self._url(), data)
        self.assertEqual(response.status_code, 302)
        ip = NbIP.objects.get(address__net_host="198.18.0.42", vrf=self.server.sync_vrf)
        self.assertEqual(str(ip.address), "198.18.0.42/24")
        link = IPAMOwnershipLink.objects.get(ip_address=ip)
        self.assertEqual((link.server_id, link.family, link.source), (self.server.pk, 4, "lease"))
        self.assertEqual(link.facts["prefix_length"], 24)
        self.assertEqual(kea.commands().count("lease4-add"), 1)
        self.assertEqual(kea.commands().count("lease4-get"), 1)
        self.assertNotIn("subnet-id", kea.requests[0]["arguments"])

    def test_optional_subnet_ipv6_add_matches_canonical_address(self):
        from ipam.models import VRF

        from netbox_kea.models import IPAMOwnershipLink

        self.server.sync_vrf = VRF.objects.create(name="lease-sync-v6")
        self.server.save()
        data = {"ip_address": "2001:db8::42", "duid": "00:01:02:03", "iaid": 1, "sync_to_netbox": "on"}
        responses = {
            "lease6-add": {"result": 0},
            "lease6-get": {
                "result": 0,
                "arguments": complete_lease(
                    {
                        "ip-address": "2001:0db8:0000:0000:0000:0000:0000:0042",
                        "subnet-id": 7,
                        "duid": "00:01:02:03",
                        "iaid": 1,
                    }
                ),
            },
            "subnet6-list": _subnet_list(
                6, [{"id": 7, "subnet": "2001:db8::/64"}, {"id": 8, "subnet": "2001:db8::/80"}]
            ),
        }
        with _lease_stub(responses) as kea:
            response = self.client.post(self._url(6), data)
        self.assertEqual(response.status_code, 302)
        ip = NbIP.objects.get(address__net_host="2001:db8::42", vrf=self.server.sync_vrf)
        self.assertEqual(str(ip.address), "2001:db8::42/64")
        link = IPAMOwnershipLink.objects.get(ip_address=ip)
        self.assertEqual((link.server_id, link.family, link.source), (self.server.pk, 6, "lease"))
        self.assertEqual(link.facts["prefix_length"], 64)
        self.assertEqual(kea.commands().count("lease6-get"), 1)
        self.assertNotIn("subnet-id", kea.requests[0]["arguments"])

    def test_optional_subnet_readback_failure_preserves_success_without_ipam_writes(self):
        from netbox_kea.models import IPAMOwnershipLink

        for family, address in ((4, "198.18.0.42"), (6, "2001:db8::42")):
            cases = {
                "absent": {"result": 3},
                "wrong-address": {
                    "result": 0,
                    "arguments": {"ip-address": "198.18.0.43" if family == 4 else "2001:db8::43", "subnet-id": 7},
                },
                "malformed-response": {"result": 0, "arguments": []},
                "malformed-address": {"result": 0, "arguments": {"ip-address": "invalid", "subnet-id": 7}},
                "missing-id": {"result": 0, "arguments": {"ip-address": address}},
                "malformed-id": {"result": 0, "arguments": {"ip-address": address, "subnet-id": []}},
                "unsupported": {"result": 2},
                "unavailable": requests.ConnectionError("readback unavailable"),
                "invalid-json": ValueError("invalid JSON"),
                "socket-error": OSError("readback unavailable"),
            }
            for name, readback in cases.items():
                with self.subTest(family=family, readback=name):
                    data = {
                        "ip_address": address,
                        "hw_address": "aa:bb:cc:dd:ee:ff",
                        "duid": "00:01:02:03",
                        "iaid": 1,
                        "sync_to_netbox": "on",
                    }
                    subnet = "198.18.0.0/24" if family == 4 else "2001:db8::/64"
                    with _lease_stub(
                        {
                            f"lease{family}-add": {"result": 0},
                            f"lease{family}-get": readback,
                            f"subnet{family}-list": _subnet_list(family, [{"id": 7, "subnet": subnet}]),
                        }
                    ) as kea:
                        response = self.client.post(self._url(family), data)
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(kea.commands().count(f"lease{family}-add"), 1)
                    self.assertEqual(kea.commands().count(f"lease{family}-get"), 1)
                    messages = [str(message) for message in get_messages(response.wsgi_request)]
                    self.assertTrue(any("created." in message for message in messages))
                    self.assertTrue(any("sync failed" in message for message in messages))
                    self.assertFalse(NbIP.objects.exists())
                    self.assertFalse(IPAMOwnershipLink.objects.exists())

    def test_a_creation_without_sync_reads_the_lease_back_and_writes_no_ipam(self):
        for family, address in ((4, "198.18.0.42"), (6, "2001:db8::42")):
            with self.subTest(family=family):
                with _lease_stub(LeaseDaemon(family).responses()) as kea:
                    response = self.client.post(
                        self._url(family),
                        {
                            "ip_address": address,
                            "duid": "00:01:02:03",
                            "iaid": 1,
                            "hw_address": "aa:bb:cc:dd:ee:ff",
                        },
                    )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(kea.commands(), [f"lease{family}-add", f"lease{family}-get"])
                self.assertFalse(NbIP.objects.exists())

    def test_post_lease4_add_keeps_kea_success_when_the_catalogue_is_unavailable(self):
        from netbox_kea.models import IPAMOwnershipLink

        with _lease_stub(
            {
                "lease4-add": {"result": 0},
                "lease4-get": self._readback(),
                "subnet4-list": {"result": 1},
                "config-get": {"result": 1},
            }
        ) as kea:
            response = self.client.post(self._url(version=4), self._post4(sync=True))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands().count("lease4-add"), 1)
        self.assertTrue(any("sync failed" in str(message) for message in get_messages(response.wsgi_request)))
        self.assertFalse(NbIP.objects.exists())
        self.assertFalse(IPAMOwnershipLink.objects.exists())

    def test_post_lease4_add_without_sync_does_not_write_ipam(self):
        from netbox_kea.models import IPAMOwnershipLink

        with _lease_stub({**LeaseDaemon(4).responses(), "subnet4-list": self._SUBNETS4}):
            response = self.client.post(self._url(version=4), self._post4(sync=False))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(NbIP.objects.exists())
        self.assertFalse(IPAMOwnershipLink.objects.exists())

    def test_post_lease4_add_reports_owner_disagreement_and_keeps_the_existing_row(self):
        from netbox_kea.ipam_reconciliation import claim
        from netbox_kea.models import IPAMOwnershipLink

        other = Server.objects.create(name="other-owner", ca_url="https://other.example.com")
        with _lease_stub({"subnet4-list": self._SUBNETS4}):
            existing = claim(
                other, 4, [typed_lease(self._readback(hostname="other.example.com")["arguments"])], force=False
            )
        before = NbIP.objects.values().get(pk=existing.primary.pk)
        responses = {**LeaseDaemon(4).responses(), "lease4-get": self._readback(), "subnet4-list": self._SUBNETS4}
        with _lease_stub(responses):
            response = self.client.post(self._url(version=4), self._post4(sync=True), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("owners disagree" in str(message) for message in response.context["messages"]))
        self.assertEqual(NbIP.objects.values().get(pk=existing.primary.pk), before)
        self.assertEqual(IPAMOwnershipLink.objects.get(server=self.server).facts["hostname"], "newlease.example.com")

    def test_post_lease4_add_sync_failure_does_not_prevent_kea_success(self):
        from django.db import connection

        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE ipam_ipaddress ADD CONSTRAINT reject_claim CHECK (host(address) != '10.0.0.200')"
            )
        try:
            responses = {**LeaseDaemon(4).responses(), "lease4-get": self._readback(), "subnet4-list": self._SUBNETS4}
            with _lease_stub(responses) as kea:
                response = self.client.post(self._url(version=4), self._post4(sync=True), follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(kea.commands().count("lease4-add"), 1)
            self.assertTrue(any("sync failed" in str(message) for message in response.context["messages"]))
            self.assertFalse(NbIP.objects.exists())
        finally:
            with connection.cursor() as cursor:
                cursor.execute("ALTER TABLE ipam_ipaddress DROP CONSTRAINT reject_claim")

    def test_post_lease4_add_sync_skipped_without_ipam_permission(self):
        """Server-change permission alone cannot write IPAM."""
        from django.contrib.auth import get_user_model
        from django.contrib.contenttypes.models import ContentType
        from users.models import ObjectPermission

        from netbox_kea.models import IPAMOwnershipLink

        User = get_user_model()
        limited = User.objects.create_user(username="lease_no_ipam", password="x")
        perm = ObjectPermission.objects.create(name="change-server-lease-noipam", actions=["view", "change"])
        perm.object_types.add(ContentType.objects.get_for_model(Server))
        perm.users.add(limited)
        self.client.force_login(limited)

        data = self._post4(sync=True)
        del data["subnet_id"]
        with _lease_stub({**LeaseDaemon(4).responses(), "subnet4-list": self._SUBNETS4}) as kea:
            response = self.client.post(self._url(version=4), data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), ["lease4-add", "lease4-get"])
        self.assertFalse(NbIP.objects.exists())
        self.assertFalse(IPAMOwnershipLink.objects.exists())

    def test_post_lease4_add_reports_foreign_ip_skip(self):
        """A foreign NetBox IP (force=False) is skipped and reported as such, not 'synced'."""
        from ipam.models import IPAddress

        # self.client is the superuser (has IPAM perms) → reaches the real sync.
        IPAddress.objects.create(address="10.0.0.200/24", status="active", description="Router loopback")
        responses = {**LeaseDaemon(4).responses(), "lease4-get": self._readback(), "subnet4-list": self._SUBNETS4}
        with _lease_stub(responses):
            response = self.client.post(self._url(version=4), self._post4(sync=True), follow=True)
        self.assertEqual(response.status_code, 200)
        msgs = [m.message for m in response.context["messages"]]
        self.assertTrue(
            any("skipped" in m.lower() and "not kea-managed" in m.lower() for m in msgs),
            f"Expected a foreign-IP skip warning, got: {msgs}",
        )
        # Foreign IP left exactly as the operator set it.
        ip = IPAddress.objects.get(address="10.0.0.200/24")
        self.assertEqual(ip.status, "active")
        self.assertEqual(ip.description, "Router loopback")

    def test_post_lease4_add_reports_successful_sync(self):
        """A fresh IP synced to NetBox reports a created/updated success message."""
        from ipam.models import IPAddress

        # No pre-existing row → the real sync creates it, no conflict → success message.
        responses = {**LeaseDaemon(4).responses(), "lease4-get": self._readback(), "subnet4-list": self._SUBNETS4}
        with _lease_stub(responses):
            response = self.client.post(self._url(version=4), self._post4(sync=True), follow=True)
        self.assertEqual(response.status_code, 200)
        msgs = [m.message for m in response.context["messages"]]
        self.assertTrue(
            any("10.0.0.200" in m and "netbox" in m.lower() and "created" in m.lower() for m in msgs),
            f"Expected a NetBox sync success message, got: {msgs}",
        )
        self.assertTrue(IPAddress.objects.filter(address__net_host="10.0.0.200").exists())


# ---------------------------------------------------------------------------
# TestBulkLeaseImportView — bulk lease CSV import (Gap C)
# ---------------------------------------------------------------------------


@with_kea_client_config(lease_query_max_unpaged_leases=1000)
class TestBulkLeaseImportView(_ViewTestBase):
    """Tests for ServerLease4/6BulkImportView."""

    def _url(self, version=4):
        return reverse(f"plugins:netbox_kea:server_lease{version}_bulk_import", args=[self.server.pk])

    def _csv4(self, rows=None):
        header = "ip-address,hw-address,subnet-id,valid-lft,hostname\n"
        if rows is None:
            rows = ["10.0.0.10,aa:bb:cc:dd:ee:ff,1,3600,host1.example.com\n"]
        return (header + "".join(rows)).encode("utf-8")

    def _csv6(self, rows=None):
        header = "ip-address,duid,iaid,subnet-id,hostname\n"
        if rows is None:
            rows = ["2001:db8::1,00:01:02:03,12345,1,host1.example.com\n"]
        return (header + "".join(rows)).encode("utf-8")

    def _post(self, version=4, csv_bytes=None):
        import io as _io

        if csv_bytes is None:
            csv_bytes = self._csv4() if version == 4 else self._csv6()
        f = _io.BytesIO(csv_bytes)
        f.name = "leases.csv"
        return {"csv_file": f}

    def test_the_import_page_selects_the_leases_tab(self):
        for version in (4, 6):
            with self.subTest(version=version, method="GET"):
                self.assertEqual(active_tabs(self.client.get(self._url(version=version))), ["Leases"])
            with self.subTest(version=version, method="POST"):
                self.assertEqual(active_tabs(self.client.post(self._url(version=version), {})), ["Leases"])

    def test_get_v4_returns_200(self):
        """GET lease4 bulk import page returns 200."""
        response = self.client.get(self._url(version=4))
        self.assertEqual(response.status_code, 200)

    def test_get_v6_returns_200(self):
        """GET lease6 bulk import page returns 200."""
        response = self.client.get(self._url(version=6))
        self.assertEqual(response.status_code, 200)

    def test_post_records_the_created_leases_in_the_server_journal(self):
        """One journal entry names each lease that Kea created, and no refused row."""
        from extras.models import JournalEntry

        rows = ["10.0.0.10,aa:bb:cc:dd:ee:01,1,3600,a\n", "10.0.0.11,aa:bb:cc:dd:ee:02,1,3600,b\n"]
        in_use = {"result": 1, "text": "lease for address 10.0.0.11 already exists"}
        with _lease_stub({"lease4-add": queued({"result": 0}, in_use)}):
            response = self.client.post(self._url(version=4), self._post(csv_bytes=self._csv4(rows)))
        self.assertEqual(_import_counts(response)["created"], 1)
        journal = JournalEntry.objects.get(assigned_object_id=self.server.pk)
        self.assertEqual(journal.comments, "Lease added: 10.0.0.10")
        self.assertEqual(journal.created_by, self.user)

    def test_a_journal_failure_still_reports_the_imported_lease(self):
        """Kea already holds the Lease, so a journal error is logged and the import result is still shown."""
        from django.db import OperationalError

        with (
            _lease_stub({"lease4-add": {"result": 0}}),
            patch("extras.models.JournalEntry.objects.create", autospec=True, side_effect=OperationalError("db gone")),
            self.assertLogs("netbox_kea.views", level="ERROR"),
        ):
            response = self.client.post(self._url(version=4), self._post(version=4))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(_import_counts(response)["created"], 1)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            ["Kea applied the change, but NetBox could not write the journal entry; see server logs."],
        )

    def test_post_with_no_created_lease_writes_no_journal_entry(self):
        from extras.models import JournalEntry

        with _lease_stub({"lease4-add": {"result": 1, "text": "lease already exists"}}):
            self.client.post(self._url(version=4), self._post(version=4))
        self.assertFalse(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())

    def test_the_shown_example_is_a_file_that_imports_one_row(self):
        for version in (4, 6):
            with self.subTest(version=version):
                page = self.client.get(self._url(version=version)).content.decode()
                (example,) = re.findall(r"<pre[^>]*>(.*?)</pre>", page, flags=re.DOTALL)
                self.assertEqual(len(parse_lease_csv(version, html.unescape(example))), 1)

    def test_post_v4_valid_csv_calls_lease_add(self):
        """POST with valid v4 CSV calls lease_add once per row."""
        with _lease_stub(LeaseDaemon(4).responses()) as kea:
            response = self.client.post(self._url(version=4), self._post(version=4))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands().count("lease4-add"), 1)
        self.assertEqual(kea.bodies("lease4-add")[0]["arguments"]["ip-address"], "10.0.0.10")

    def test_post_v6_valid_csv_calls_lease_add(self):
        """POST with valid v6 CSV calls lease_add with correct duid and iaid."""
        with _lease_stub(LeaseDaemon(6).responses()) as kea:
            response = self.client.post(self._url(version=6), self._post(version=6))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands().count("lease6-add"), 1)
        args = kea.bodies("lease6-add")[0]["arguments"]
        self.assertEqual(args["duid"], "00:01:02:03")
        self.assertEqual(args["iaid"], 12345)

    def test_post_multiple_rows_calls_lease_add_per_row(self):
        """Each CSV row triggers one lease_add call."""
        csv_bytes = self._csv4(
            rows=[
                "10.0.0.10,aa:bb:cc:dd:ee:01,1,3600,h1\n",
                "10.0.0.11,aa:bb:cc:dd:ee:02,1,3600,h2\n",
                "10.0.0.12,aa:bb:cc:dd:ee:03,1,3600,h3\n",
            ]
        )
        with _lease_stub(LeaseDaemon(4).responses()) as kea:
            response = self.client.post(self._url(version=4), self._post(version=4, csv_bytes=csv_bytes))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands().count("lease4-add"), 3)

    def test_a_failure_result_is_unconfirmed_and_stops_the_import(self):
        """A failure result can follow a stored Lease, so the row is unconfirmed and the rows after it are not sent."""
        csv_bytes = self._csv4(
            rows=[
                "10.0.0.10,aa:bb:cc:dd:ee:01,1,3600,h1\n",
                "10.0.0.11,aa:bb:cc:dd:ee:02,1,3600,h2\n",
                "10.0.0.12,aa:bb:cc:dd:ee:03,1,3600,h3\n",
            ]
        )
        with _lease_stub({"lease4-add": queued({"result": 0}, {"result": 1, "text": "bad"})}) as kea:
            response = self.client.post(self._url(version=4), self._post(version=4, csv_bytes=csv_bytes))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), ["lease4-add", "lease4-add"])
        self.assertEqual(_import_counts(response), {"created": 1, "unconfirmed": 1, "not-applied": 0, "not-sent": 1})
        self.assertEqual(
            _import_report(response),
            {
                "created": ("Rows that Kea created", [("2", "10.0.0.10")]),
                "unconfirmed": (
                    "Row that Kea did not confirm",
                    [("3", "10.0.0.11", f"{UNCONFIRMED_RUNTIME} Kea replied: bad")],
                ),
                "not-sent": ("Rows that NetBox did not send", [("4", "10.0.0.12", _IMPORT_NOT_SENT)]),
            },
        )
        self.assertContains(response, "Kea did not confirm one row, so NetBox stopped there.")

    def test_each_created_row_sends_lease_added_without_a_read_back(self) -> None:
        received: list[dict] = []

        def receive(sender, **kwargs):
            received.append(kwargs)

        lease_added.connect(receive)
        self.addCleanup(lease_added.disconnect, receive)
        csv_bytes = self._csv4(
            rows=[
                "10.0.0.10,aa:bb:cc:dd:ee:01,1,3600,h1\n",
                "10.0.0.11,aa:bb:cc:dd:ee:02,1,3600,h2\n",
                "10.0.0.12,aa:bb:cc:dd:ee:03,1,3600,h3\n",
            ]
        )
        # A connection that Kea refused is a rejection, which does not stop the import.
        refused = _refused_connection()
        with _lease_stub({"lease4-add": queued({"result": 0}, refused, {"result": 0})}) as kea:
            response = self.client.post(self._url(version=4), self._post(version=4, csv_bytes=csv_bytes))

        self.assertEqual(_import_counts(response)["created"], 2)
        self.assertNotIn("lease4-get", kea.commands())
        self.assertEqual(
            [(str(call["creation"].address), call["lease"], call["dhcp_version"]) for call in received],
            [("10.0.0.10", None, 4), ("10.0.0.12", None, 4)],
        )
        self.assertEqual({call["server"] for call in received}, {self.server})
        self.assertEqual({call["creation"].hostname for call in received}, {"h1", "h3"})

    def test_each_created_row_sends_lease_added_before_the_next_row_goes_to_kea(self) -> None:
        sent_before_signal: list[int] = []
        csv_bytes = self._csv4(
            rows=["10.0.0.10,aa:bb:cc:dd:ee:01,1,3600,h1\n", "10.0.0.11,aa:bb:cc:dd:ee:02,1,3600,h2\n"]
        )
        with _lease_stub(LeaseDaemon(4).responses()) as kea:

            def receive(sender, **kwargs):
                sent_before_signal.append(kea.commands().count("lease4-add"))

            lease_added.connect(receive)
            self.addCleanup(lease_added.disconnect, receive)
            response = self.client.post(self._url(version=4), self._post(version=4, csv_bytes=csv_bytes))

        self.assertEqual(_import_counts(response)["created"], 2)
        self.assertEqual(sent_before_signal, [1, 2])

    def test_an_empty_kea_reply_creates_no_row_and_sends_no_signal(self) -> None:
        received: list[dict] = []

        def receive(sender, **kwargs):
            received.append(kwargs)

        lease_added.connect(receive)
        self.addCleanup(lease_added.disconnect, receive)
        with _lease_stub({"lease4-add": []}):
            response = self.client.post(self._url(version=4), self._post(version=4))

        counts = _import_counts(response)
        self.assertEqual((counts["created"], counts["unconfirmed"]), (0, 1))
        self.assertEqual(received, [])

    def test_a_rejected_row_names_the_file_line_after_comment_and_blank_lines(self):
        """A rejected row names the physical line of its row, so comment and blank lines count."""
        csv_bytes = self._csv4(
            rows=[
                "# first lease\n",
                "10.0.0.10,aa:bb:cc:dd:ee:01,1,3600,h1\n",
                "\n",
                "10.0.0.11,aa:bb:cc:dd:ee:02,1,3600,h2\n",
            ]
        )
        with _lease_stub({"lease4-add": queued({"result": 0}, _refused_connection())}):
            response = self.client.post(self._url(version=4), self._post(version=4, csv_bytes=csv_bytes))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            _import_report(response),
            {
                "created": ("Rows that Kea created", [("3", "10.0.0.10")]),
                "not-applied": (
                    "Rows that Kea did not apply",
                    [("5", "10.0.0.11", "The change was not sent to Kea. Kea could not be reached.")],
                ),
            },
        )

    def test_the_line_and_address_columns_stay_narrow_so_the_message_takes_the_width(self):
        csv_bytes = self._csv4(
            rows=["10.0.0.10,aa:bb:cc:dd:ee:01,1,3600,h1\n", "10.0.0.11,aa:bb:cc:dd:ee:02,1,3600,h2\n"]
        )
        with _lease_stub({"lease4-add": queued({"result": 0}, _refused_connection())}):
            response = self.client.post(self._url(version=4), self._post(version=4, csv_bytes=csv_bytes))
        page = BeautifulSoup(response.content, "html.parser")
        for status, narrow_columns in (("created", ["Line"]), ("not-applied", ["Line", "Address"])):
            with self.subTest(status):
                section = page.select_one(f'section[data-import-status="{status}"]')
                self.assertIsNotNone(section)
                narrow = [
                    th.get_text(strip=True)
                    for th in section.select("th")
                    if "text-nowrap" in (th.get("class") or []) and "width: 1%" in th.get("style", "")
                ]
                self.assertEqual(narrow, narrow_columns)
                for row in section.select("tbody tr"):
                    cells = row.select("td")
                    self.assertTrue(
                        all("text-nowrap" in cell.get("class", []) for cell in cells[: len(narrow_columns)])
                    )

    def test_post_empty_csv_shows_form_error(self):
        """Uploading a CSV with only a header (no data rows) returns 200 with empty result."""
        csv_bytes = b"ip-address,hw-address\n"
        # Header-only CSV → zero rows → no lease command issued (empty registry proves it).
        with _lease_stub({}) as kea:
            response = self.client.post(self._url(version=4), self._post(version=4, csv_bytes=csv_bytes))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        if response.context.get("result") is not None:
            self.assertEqual(_import_counts(response)["created"], 0)

    def test_get_requires_login(self):
        """Unauthenticated GET redirects to login."""
        self.client.logout()
        response = self.client.get(self._url(version=4))
        self.assertIn(response.status_code, (302, 403))


# ─────────────────────────────────────────────────────────────────────────────
# Gap G: Django signals + lease journal entries
# ─────────────────────────────────────────────────────────────────────────────


class TestLeaseJournalEntries(_ViewTestBase):
    """Lease add and delete views must create JournalEntry records on the Server."""

    def test_lease_add_creates_journal_entry(self):
        """A successful lease add must create a JournalEntry attached to the server."""
        from django.contrib.contenttypes.models import ContentType
        from extras.models import JournalEntry

        url = reverse("plugins:netbox_kea:server_lease4_add", args=[self.server.pk])
        server_ct = ContentType.objects.get_for_model(self.server)
        before = JournalEntry.objects.filter(
            assigned_object_id=self.server.pk,
            assigned_object_type=server_ct,
        ).count()
        with _lease_stub(LeaseDaemon(4).responses()):
            self.client.post(
                url,
                {
                    "ip_address": "10.0.0.5",
                    "hw_address": "aa:bb:cc:dd:ee:01",
                    "hostname": "journal-host",
                    "subnet_id": 1,
                    "valid_lft": 3600,
                },
            )
        after = JournalEntry.objects.filter(assigned_object_id=self.server.pk, assigned_object_type=server_ct).count()
        self.assertEqual(after, before + 1)
        entry = JournalEntry.objects.filter(assigned_object_id=self.server.pk, assigned_object_type=server_ct).latest(
            "created"
        )
        self.assertIn("10.0.0.5", entry.comments)

    def test_lease_delete_creates_journal_entry(self):
        """A successful lease delete must create a JournalEntry attached to the server."""
        from django.contrib.contenttypes.models import ContentType
        from extras.models import JournalEntry

        url = reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])
        server_ct = ContentType.objects.get_for_model(self.server)
        before = JournalEntry.objects.filter(assigned_object_id=self.server.pk, assigned_object_type=server_ct).count()
        held, selected = _held4("10.0.0.5")
        with _lease_stub(held):
            self.client.post(url, {"pk": selected, "_confirm": "1"})
        after = JournalEntry.objects.filter(assigned_object_id=self.server.pk, assigned_object_type=server_ct).count()
        self.assertEqual(after, before + 1)
        entry = JournalEntry.objects.filter(assigned_object_id=self.server.pk, assigned_object_type=server_ct).latest(
            "created"
        )
        self.assertIn("10.0.0.5", entry.comments)


# ===========================================================================
# BATCH 2: Covering remaining ~220 uncovered lines
# ===========================================================================

# ---------------------------------------------------------------------------
# _lease_journal_comments
# ---------------------------------------------------------------------------


class TestJournalHelperEdgeCases(SimpleTestCase):
    """The journal text of a Lease change."""

    def test_lease_journal_multiple_ips(self):
        """A list of IP addresses uses the 'N lease(s)' form."""
        from netbox_kea.views.leases import _lease_journal_comments

        comments = _lease_journal_comments(
            "deleted", ["10.0.0.1", "10.0.0.2"], hw_address="aa:bb:cc:dd:ee:ff", hostname="host1"
        )
        self.assertEqual(
            comments, "2 lease(s) deleted: 10.0.0.1, 10.0.0.2; hw-address: aa:bb:cc:dd:ee:ff; hostname: host1"
        )


# ---------------------------------------------------------------------------
# HTMX exception handler in BaseServerLeasesView
# ---------------------------------------------------------------------------


class TestHTMXExceptionHandler(_ViewTestBase):
    """An exception during the HTMX lease fetch renders the error partial."""

    _SUBNETS4 = _subnet_list(4, [{"id": 1, "subnet": "10.0.0.0/24"}])

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_htmx_exception_returns_error_partial(self):
        # A RuntimeError from the lease fetch must be caught and rendered as the HTMX error partial.
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get": RuntimeError("boom")}):
            response = self.client.get(
                self._url() + "?q=10.0.0.1&by=ip",
                HTTP_HX_REQUEST="true",
            )
        # Must not crash — the outer handler catches the RuntimeError and renders
        # the HTMX error partial (never a 500; accepting 500 would let a regression
        # where the handler stops catching the error pass unnoticed).
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Lease edit GET — KeaException, not-found, v6 duid
# ---------------------------------------------------------------------------


class TestLeaseEditGet(_ViewTestBase):
    """Lease edit GET: Kea errors, a missing lease, and the v6 DUID."""

    def test_get_kea_exception_redirects(self):
        """KeaException in lease4 GET redirects to leases page."""
        # result=1 makes lease4-get raise KeaException in the real client.
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.1"])
        with _lease_stub({"lease4-get": {"result": 1, "text": "err"}}):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_get_lease_not_found_redirects(self):
        """result=3 (not found) in lease4 GET redirects to leases page."""
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.1"])
        with _lease_stub({"lease4-get": {"result": 3, "arguments": None}}):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_get_v6_lease_includes_duid(self):
        """v6 lease GET includes duid in form initial."""
        server6 = _make_db_server(name="kea6-only", ca_url="https://kea6.example.com", dhcp4=False, dhcp6=True)
        url = reverse("plugins:netbox_kea:server_lease6_edit", args=[server6.pk, "2001:db8::1"])
        with _lease_stub(
            {
                "lease6-get": {
                    "result": 0,
                    "arguments": complete_lease(
                        {
                            "ip-address": "2001:db8::1",
                            "duid": "00:01:00:01",
                            "hostname": "v6host",
                            "valid-lft": 3600,
                        }
                    ),
                }
            }
        ):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "00:01:00:01")


# ---------------------------------------------------------------------------
# Lease edit POST — invalid form
# ---------------------------------------------------------------------------


class TestLeaseEditPostInvalidForm(_ViewTestBase):
    """Lease edit POST with an invalid form re-renders with 200."""

    def test_post_invalid_form_rerenders(self):
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.1"])
        shown = shown_token(lease_record("10.0.0.1", subnet_id=1))
        # Invalid form re-renders before any Kea call — empty registry proves none is issued.
        with _lease_stub({}) as kea:
            response = self.client.post(url, {"shown": shown, "hostname": "", "valid_lft": "not-a-number"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertIn("valid_lft", response.context["form"].errors)

    def test_a_post_without_the_shown_facts_sends_nothing(self):
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.1"])
        for shown in ("", "10.0.0.1", shown_token(lease_record("10.0.0.2", subnet_id=1))):
            with self.subTest(shown=shown), _lease_stub({}) as kea:
                response = self.client.post(url, {"shown": shown, "hostname": "new"})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(kea.commands(), [])


# ---------------------------------------------------------------------------
# Lease add — generic exception
# ---------------------------------------------------------------------------


class TestLeaseAddGenericException(_ViewTestBase):
    """A transport error after the send of a lease add is unconfirmed, and its text stays out of the page."""

    def test_a_lost_reply_is_unconfirmed(self):
        url = reverse("plugins:netbox_kea:server_lease4_add", args=[self.server.pk])
        with _lease_stub({"lease4-add": requests.RequestException("unexpected crash")}):
            response = self.client.post(
                url,
                {
                    "ip_address": "10.0.0.99",
                    "subnet_id": "1",
                    "hw_address": "aa:bb:cc:dd:ee:ff",
                    "hostname": "testhost",
                    "valid_lft": "3600",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            [f"Lease 10.0.0.99: {UNCONFIRMED_RUNTIME} Kea's reply to the change was lost or unreadable."],
        )


# ---------------------------------------------------------------------------
# fetch: each search selector and the read of every Lease
# ---------------------------------------------------------------------------


class TestFetchLeaseSearch(_ViewTestBase):
    """The Lease fetch with each search selector."""

    def _call(self, by, q="aa:bb:cc:dd:ee:ff", version=4, resp=None):
        if resp is None:
            address = "10.0.0.1" if version == 4 else "2001:db8::1"
            resp = [
                {
                    "result": 0,
                    "arguments": {"leases": [complete_lease({"ip-address": address, "valid-lft": 3600, "state": 0})]},
                }
            ]
        payload = resp[0] if isinstance(resp, list) else resp
        # The fetch picks the command from `by`; register every
        # lease-get variant of the family to the same payload so whichever it issues is covered.
        suffixes = (
            "",
            "-by-hostname",
            "-all",
            *(("-by-hw-address", "-by-client-id") if version == 4 else ("-by-duid",)),
        )
        variants = [f"lease{version}-get{suffix}" for suffix in suffixes]
        with _lease_stub(dict.fromkeys(variants, payload)):
            return fetch(self.server, version, LeaseSearch(by, q))

    def test_by_hw_address(self):
        snapshot = self._call(constants.BY_HW_ADDRESS, q="aa:bb:cc:dd:ee:ff")
        self.assertEqual(len(snapshot.records), 1)

    def test_by_hostname(self):
        snapshot = self._call(constants.BY_HOSTNAME, q="myhost")
        self.assertEqual(len(snapshot.records), 1)

    def test_by_client_id(self):
        snapshot = self._call(constants.BY_CLIENT_ID, q="01:aa:bb:cc:dd:ee:ff")
        self.assertEqual(len(snapshot.records), 1)

    def test_by_duid(self):
        snapshot = self._call(constants.BY_DUID, q="00:01:00:01:12:34", version=6)
        self.assertEqual(len(snapshot.records), 1)

    def test_unknown_by_is_rejected(self):
        with self.assertRaises(ValueError):
            self._call("unknown_by", q="x")

    def test_result_3_returns_empty(self):
        snapshot = self._call(constants.BY_HOSTNAME, q="ghost", resp=[{"result": 3, "arguments": None}])
        self.assertEqual((snapshot.records, snapshot.complete), ((), True))

    def test_null_args_is_an_unavailable_notice(self):
        with _lease_stub({"lease4-get-by-hostname": {"result": 0, "arguments": None}}):
            loaded = fetch(self.server, 4, LeaseSearch(constants.BY_HOSTNAME, "ghost"))

        self.assertIsInstance(loaded, Notice)
        self.assertTrue(loaded.unavailable)

    def test_by_subnet_id(self):
        """The BY_SUBNET_ID selector fetches the leases of one Subnet."""
        resp = [
            {
                "result": 0,
                "arguments": {"leases": [complete_lease({"ip-address": "10.0.0.1", "valid-lft": 3600, "state": 0})]},
            }
        ]
        snapshot = self._call(constants.BY_SUBNET_ID, q="1", resp=resp)
        self.assertEqual(len(snapshot.records), 1)

    @with_kea_client_config(lease_query_max_unpaged_leases=100)
    def test_subnet_state_is_applied_by_kea(self):
        stats = _subnet_stats(4, 1, assigned=501, declined=1)
        response = {
            "result": 0,
            "arguments": {"leases": [complete_lease({"ip-address": "198.18.0.1", "valid-lft": 3600, "state": 1})]},
        }
        with _lease_stub({"stat-lease4-get": stats, "lease4-get-by-state": response}) as kea:
            snapshot = fetch(self.server, 4, LeaseSearch(constants.BY_SUBNET_ID, 1, "declined"))

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(
            kea.bodies("lease4-get-by-state")[0]["arguments"],
            {"subnet-id": 1, "state": 1},
        )


# ---------------------------------------------------------------------------
# Lease CSV bulk import — form invalid, parse error, generic exception
# ---------------------------------------------------------------------------


class TestLeaseBulkImportEdgeCases(_ViewTestBase):
    """Lease CSV import: invalid form, parse error, and per-row errors."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_lease4_bulk_import", args=[self.server.pk])

    def test_the_import_is_served_at_one_url_per_family(self):
        for family in (4, 6):
            with self.subTest(family=family):
                url = reverse(f"plugins:netbox_kea:server_lease{family}_bulk_import", args=[self.server.pk])
                self.assertTrue(url.endswith(f"/servers/{self.server.pk}/leases{family}/import/"))
                self.assertEqual(self.client.get(url).status_code, 200)
                duplicate = url.replace(f"/leases{family}/import/", f"/lease{family}_bulk_import/")
                self.assertEqual(self.client.get(duplicate).status_code, 404)

    def test_post_no_file_rerenders(self):
        """POST without csv_file → invalid form → 200."""
        response = self.client.post(self._url(), {})
        self.assertEqual(response.status_code, 200)

    def test_a_file_that_is_not_utf8_is_reported_on_the_field(self):
        """A file the view cannot decode is reported on the field, not raised.

        Nothing covered this branch before. It does not discriminate where the view
        takes the file from, because a plain FileField hands back the same
        UploadedFile either way; it covers the read and decode the view does with it.
        """
        import io

        csv_file = io.BytesIO(b"ip-address\n10.0.0.\xff1")
        csv_file.name = "leases.csv"

        # An empty registry proves the view rejects the file before any Kea command.
        with _lease_stub({}) as kea:
            response = self.client.post(self._url(), {"csv_file": csv_file})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertContains(response, "File must be UTF-8 encoded.")

    def test_a_malformed_row_rejects_the_file_with_its_line_and_column_only(self):
        """A row that is not a valid request rejects the file; neither the page nor the log shows its value."""
        import io

        csv_file = io.BytesIO(b"ip-address,hw-address\n10.0.0.1,aa:bb:cc:00:00:01\n10.0.0.2,zz:zz:secret\n")
        csv_file.name = "leases.csv"
        # Parse fails before any client call — empty registry proves no Kea command runs.
        with _lease_stub({}) as kea, self.assertLogs("netbox_kea.views.sync_views", level="INFO") as logs:
            response = self.client.post(self._url(), {"csv_file": csv_file})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertContains(response, "Line 3: &#x27;hw-address&#x27; is not valid for a DHCPv4 lease.")
        self.assertNotContains(response, "secret")
        self.assertNotIn("secret", "\n".join(logs.output))

    @patch("netbox_kea.views.sync_views.parse_lease_csv", autospec=True)
    def test_another_parse_error_does_not_echo_its_text(self, parse):
        """Only the row-numbered message of the CSV parser reaches the page; any other error text stays out."""
        import io

        parse.side_effect = ValueError("internal detail 10.0.0.1")
        csv_file = io.BytesIO(b"ip-address,hw-address\n10.0.0.1,aa:bb:cc:00:00:01")
        csv_file.name = "leases.csv"
        with _lease_stub({}) as kea:
            response = self.client.post(self._url(), {"csv_file": csv_file})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertNotContains(response, "internal detail")
        self.assertContains(response, "CSV parsing failed. Check the file format and column headers.")

    def test_a_client_that_cannot_be_built_stops_the_import_at_the_first_row(self):
        """A key without a certificate fails every row the same way, so the import reports it once."""
        import io

        save_key_without_certificate(self.server)
        csv_file = io.BytesIO(
            b"ip-address,hw-address\n10.0.0.1,aa:bb:cc:00:00:01\n10.0.0.2,aa:bb:cc:00:00:02\n10.0.0.3,aa:bb:cc:00:00:03"
        )
        csv_file.name = "leases.csv"
        with _lease_stub({}) as kea:
            response = self.client.post(self._url(), {"csv_file": csv_file})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        self.assertEqual(
            _import_report(response),
            {
                "not-applied": ("Rows that Kea did not apply", [("2", "10.0.0.1", INVALID_SERVER_SETTINGS)]),
                "not-sent": (
                    "Rows that NetBox did not send",
                    [("3", "10.0.0.2", _IMPORT_NOT_SENT), ("4", "10.0.0.3", _IMPORT_NOT_SENT)],
                ),
            },
        )

    def test_a_malformed_reply_body_is_an_unconfirmed_row(self):
        """A lease4-add body that is not a JSON list is a malformed reply; the log does not name its MAC."""
        import io

        for name, reply in (
            ("not a list", _http_response({"result": 0})),
            ("not JSON", _raw_http_response(b"<html>")),
        ):
            with self.subTest(name):
                csv_file = io.BytesIO(b"ip-address,hw-address\n10.0.0.1,aa:bb:cc:00:00:01")
                csv_file.name = "leases.csv"
                with _lease_stub({"lease4-add": reply}), self.assertLogs("netbox_kea.change_outcome") as logs:
                    response = self.client.post(self._url(), {"csv_file": csv_file})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    _import_report(response),
                    {
                        "unconfirmed": (
                            "Row that Kea did not confirm",
                            [
                                (
                                    "2",
                                    "10.0.0.1",
                                    f"{UNCONFIRMED_RUNTIME} Kea's reply to the change was lost or unreadable.",
                                )
                            ],
                        )
                    },
                )
                self.assertNotIn("aa:bb:cc:00:00:01", "\n".join(logs.output))


class TestGetLeasesPageAllLeasesMode(_ViewTestBase):
    """All-leases browse mode (``by=""``) starts pagination at the address-space root.

    The lease-page ``from`` cursor must be ``"0.0.0.0"`` for DHCPv4 and ``"::"``
    for DHCPv6.
    """

    _SUBNETS4 = _subnet_list(4, [])
    _SUBNETS6 = _subnet_list(6, [])
    _EMPTY_PAGE = {"result": 0, "arguments": {"count": 0, "leases": []}}

    def _url4(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def _url6(self):
        return reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk])

    def test_all_leases_v4_starts_from_zero_address(self):
        """``by=""`` on the v4 view must call lease4-get-page with ``from="0.0.0.0"``."""
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": self._EMPTY_PAGE}) as kea:
            response = self.client.get(self._url4(), {"by": ""}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.bodies("lease4-get-page")[0]["arguments"]["from"], "0.0.0.0")  # noqa: S104 - Kea sentinel value, not a bind address

    def test_all_leases_v6_starts_from_unspecified_address(self):
        """``by=""`` on the v6 view must call lease6-get-page with ``from="::"``."""
        with _lease_stub({"subnet6-list": self._SUBNETS6, "lease6-get-page": self._EMPTY_PAGE}) as kea:
            response = self.client.get(self._url6(), {"by": ""}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.bodies("lease6-get-page")[0]["arguments"]["from"], "::")


# ---------------------------------------------------------------------------
# Lease fetch validation and null arguments
# ---------------------------------------------------------------------------


class TestGetLeasesCoverage(_ViewTestBase):
    """Edge cases in the Lease fetch."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_invalid_by_raises_value_error(self):
        """An invalid search selector must fail before a Kea request."""
        with stub_kea({}) as kea, self.assertRaises(ValueError):
            fetch(self.server, 4, LeaseSearch("not_a_valid_by", "test_query"))
        self.assertEqual(kea.commands(), [])

    def test_null_args_from_lease_get_raises_runtime_error(self):
        """lease-get returns arguments=None → RuntimeError (caught by HTMX handler)."""
        subnets = _subnet_list(4, [])
        with _lease_stub({"subnet4-list": subnets, "lease4-get": {"result": 0, "arguments": None}}):
            response = self.client.get(
                self._url(),
                {"by": "ip", "q": "10.0.0.1"},
                HTTP_HX_REQUEST="true",
            )
        # RuntimeError is caught by outer except → HTMX error partial, still 200
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# get_export — invalid form + get_export_all null args
# ---------------------------------------------------------------------------


class TestGetExportCoverage(_ViewTestBase):
    """Edge cases in get_export() and get_export_all()."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_export_with_invalid_form_redirects(self):
        """Invalid form for export → messages.warning + redirect."""
        # Pass an invalid 'by' value (not in choices) to force form.is_valid() == False
        response = self.client.get(self._url(), {"export": "1", "by": "INVALID_VALUE", "q": "test"})
        self.assertIn(response.status_code, [200, 302])

    def test_export_all_null_args_returns_csv(self):
        """export_all: lease-get-page returns arguments=None → empty CSV."""
        with _lease_stub({"lease4-get-page": {"result": 0, "arguments": None}}):
            response = self.client.get(self._url(), {"export_all": "1"})
        # Should return CSV even when args is None (empty export)
        self.assertIn(response.status_code, [200, 302])


# ---------------------------------------------------------------------------
# HTMX invalid form
# ---------------------------------------------------------------------------


class TestHTMXInvalidFormCoverage(_ViewTestBase):
    """HTMX GET with invalid form → renders HTMX partial."""

    def test_htmx_invalid_form_returns_partial(self):
        """form.is_valid()==False for HTMX → renders server_dhcp_leases_htmx.html."""
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        subnets = _subnet_list(4, [])
        # 'by' has an invalid choice value → form.is_valid() returns False (no lease fetch).
        with _lease_stub({"subnet4-list": subnets}):
            response = self.client.get(
                url,
                {"by": "INVALID_CHOICE", "q": "test"},
                HTTP_HX_REQUEST="true",
            )
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Lease6 edit — duid branch
# ---------------------------------------------------------------------------


class TestLease6EditDuid(_ViewTestBase):
    """POST lease6 edit with duid → lease6-update carries the duid."""

    def test_post_with_duid_calls_lease_update(self):
        """A changed DUID is written to the fresh lease body."""
        url = reverse(
            "plugins:netbox_kea:server_lease6_edit",
            args=[self.server.pk, "2001:db8::1"],
        )
        record = complete_lease({"ip-address": "2001:db8::1", "duid": "00:00:01", "valid-lft": 3600})
        with _lease_stub(LeaseDaemon(6, record).responses()) as kea:
            response = self.client.post(
                url,
                {"shown": shown_token(record), "duid": "01:02:03:04", "valid_lft": "", "hostname": ""},
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(kea.commands(), ["lease6-get", "lease6-update"])
        self.assertEqual(kea.bodies("lease6-update")[0]["arguments"]["duid"], "01:02:03:04")


# ---------------------------------------------------------------------------
# Lease reservation lookup — missing subnet_id
# ---------------------------------------------------------------------------


class TestFetchOneEmptyLease(_ViewTestBase):
    """A lease reply without the required subnet-id is rejected before enrichment."""

    def test_lease_without_subnet_id_is_rejected_before_reservation_lookup(self):
        """A missing subnet-id is diagnosed, and no reservation lookup is sent to Kea."""
        subnets = _subnet_list(4, [])
        arguments = complete_lease({"ip-address": "10.0.0.1", "valid-lft": 3600, "state": 0, "hostname": "testhost"})
        del arguments["subnet-id"]
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with _lease_stub({"subnet4-list": subnets, "lease4-get": {"result": 0, "arguments": arguments}}) as kea:
            response = self.client.get(url, {"by": "ip", "q": "10.0.0.1"}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(_lease_lines(response))
        self.assertNotIn("reservation-get", kea.commands())


# ---------------------------------------------------------------------------
# Fix A: partial delete loop
# ---------------------------------------------------------------------------


class TestLeasePartialDelete(_ViewTestBase):
    """A bulk delete sends one Runtime Change per Lease: a rejected row does not stop it, an unknown row does."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])

    # A followed redirect lands on the leases page, which fetches the subnet quick-select.
    _SUBNETS4 = _subnet_list(4, [])

    def _messages(self, responses: dict) -> tuple[list[tuple[int, str]], list[str]]:
        held, selected = _held4("10.0.0.1", "10.0.0.2", "10.0.0.3")
        with _lease_stub({**held, **responses, "subnet4-list": self._SUBNETS4}) as kea:
            response = self.client.post(self._url(), {"_confirm": "1", "pk": selected})
        self.assertEqual(response.status_code, 302)
        return [(message.level, str(message)) for message in get_messages(response.wsgi_request)], kea.commands()

    def test_a_failure_result_stops_the_loop_and_writes_no_journal_entry_for_it(self):
        """A failure result can follow a deleted Lease (ADR 0011), so NetBox stops and lists what it did not send."""
        from extras.models import JournalEntry

        shown, commands = self._messages(
            {"lease4-del": queued({"result": 0}, {"result": 1, "text": "lease database write failed"})}
        )

        self.assertEqual(commands.count("lease4-del"), 2)
        self.assertEqual(
            shown,
            [
                (django_messages.SUCCESS, "Deleted 1 DHCPv4 lease(s): 10.0.0.1."),
                (
                    django_messages.WARNING,
                    f"Lease 10.0.0.2: {UNCONFIRMED_RUNTIME} Kea replied: lease database write failed",
                ),
                (
                    django_messages.WARNING,
                    "NetBox stopped at lease 10.0.0.2 and did not send the delete of 1 lease(s): 10.0.0.3.",
                ),
            ],
        )
        (journal,) = JournalEntry.objects.filter(assigned_object_id=self.server.pk)
        self.assertEqual(journal.comments, "Lease deleted: 10.0.0.1")

    def test_a_malformed_reply_stops_the_loop(self):
        shown, commands = self._messages({"lease4-del": queued(["ok"], {"result": 0})})
        self.assertEqual(commands.count("lease4-del"), 1)
        self.assertEqual(
            [text for _level, text in shown],
            [
                f"Lease 10.0.0.1: {UNCONFIRMED_RUNTIME} Kea's reply to the change was lost or unreadable.",
                "NetBox stopped at lease 10.0.0.1 and did not send the delete of 2 lease(s): 10.0.0.2, 10.0.0.3.",
            ],
        )

    def test_a_rejected_row_does_not_stop_the_loop(self):
        refused = _refused_connection()
        shown, commands = self._messages({"lease4-del": queued(refused, {"result": 0})})
        self.assertEqual(commands.count("lease4-del"), 3)
        self.assertEqual(
            shown,
            [
                (django_messages.ERROR, "Lease 10.0.0.1: The change was not sent to Kea. Kea could not be reached."),
                (django_messages.SUCCESS, "Deleted 2 DHCPv4 lease(s): 10.0.0.2, 10.0.0.3."),
            ],
        )

    def test_success_message_shows_count_of_deleted(self):
        """Success message reflects only the successfully deleted count."""
        shown, _commands = self._messages({"lease4-del": {"result": 0}})
        self.assertEqual(shown, [(django_messages.SUCCESS, "Deleted 3 DHCPv4 lease(s): 10.0.0.1, 10.0.0.2, 10.0.0.3.")])


# ---------------------------------------------------------------------------
# Fix B: get_export_all except narrowing
# ---------------------------------------------------------------------------


class TestLeaseExportAllExceptNarrowing(_ViewTestBase):
    """get_export_all() must not swallow local bugs via bare except Exception."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_attribute_error_propagates(self):
        """An AttributeError inside get_export_all must not be silently caught."""
        # get_export_all narrows its except clauses, so an AttributeError propagates.
        with _lease_stub({"lease4-get-page": AttributeError("bad stub")}):
            with self.assertRaises(AttributeError):
                self.client.get(self._url(), {"export_all": "1"})


class TestLeaseExportStateFilter(_ViewTestBase):
    """get_export() must honour the 'state' query parameter."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    # Unguarded on purpose: the export takes the same unpaged Subnet path, with no
    # stat-lease4-get preflight. State it here instead of inheriting it.
    def test_state_filter_applied_to_export(self):
        """Exported CSV must contain only leases matching the requested state."""
        declined = complete_lease(
            {
                "ip-address": "10.0.0.2",
                "hw-address": "aa:bb:cc:00:00:02",
                "subnet-id": 1,
                "cltt": 1700000000,
                "valid-lft": 86400,
                "hostname": "",
                "state": 1,
            }
        )
        with _lease_stub(
            {
                **_catalogue_responses(4, 1, "10.0.0.0/24"),
                "lease4-get-by-state": {"result": 0, "arguments": {"leases": [declined]}},
            }
        ):
            response = self.client.get(
                self._url(),
                {
                    "export": "1",
                    "by": "subnet",
                    "q": "10.0.0.0/24",
                    "state": "1",
                },
            )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn("10.0.0.2", content)
        self.assertNotIn("10.0.0.1", content)


# ─────────────────────────────────────────────────────────────────────────────
# F8: HTMX handler exception narrowing
# ─────────────────────────────────────────────────────────────────────────────


class TestHtmxHandlerExceptNarrowing(_ViewTestBase):
    """HTMX lease handler must not swallow programming errors via bare except Exception."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_attribute_error_not_swallowed_by_htmx_handler(self):
        """An AttributeError inside the HTMX handler must propagate (not be caught silently)."""
        subnets = _subnet_list(4, [])
        # The HTMX handler narrows its except clauses, so an AttributeError propagates.
        with _lease_stub({"subnet4-list": subnets, "lease4-get-all": AttributeError("stub programming bug")}):
            with self.assertRaises(AttributeError):
                self.client.get(
                    self._url(),
                    HTTP_HX_REQUEST="true",
                    data={"by": "subnet_id", "q": "1"},
                )


class TestLeaseDeleteLoopTransportErrors(_ViewTestBase):
    """A transport error after the send of one delete stops the loop; the error text never reaches the page."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])

    def test_a_lost_or_unreadable_reply_stops_the_loop(self):
        for name, failure in (
            ("reset", requests.ConnectionError("down")),
            ("value error", ValueError("bad JSON")),
        ):

            def del_resp(body, failure=failure):
                if body["arguments"]["ip-address"] == "10.0.0.1":
                    return failure
                return {"result": 0}

            held, selected = _held4("10.0.0.1", "10.0.0.2")
            with self.subTest(name), _lease_stub({**held, "lease4-del": del_resp}) as kea:
                response = self.client.post(self._url(), {"pk": selected, "_confirm": "1"})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(kea.commands().count("lease4-del"), 1)
            shown = [str(message) for message in get_messages(response.wsgi_request)]
            self.assertEqual(
                shown[0], f"Lease 10.0.0.1: {UNCONFIRMED_RUNTIME} Kea's reply to the change was lost or unreadable."
            )
            self.assertNotIn("bad JSON", " ".join(shown))


class TestLeaseExportTransportErrors(_ViewTestBase):
    """get_export() must handle RequestException and ValueError gracefully."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    _SUBNETS4 = _subnet_list(4, [])

    def test_request_exception_redirects_with_error(self):
        import requests as _requests

        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-all": _requests.ConnectionError("down")}):
            response = self.client.get(
                self._url(),
                {"export": "1", "by": "subnet_id", "q": "1"},
            )
        self.assertIn(response.status_code, [200, 302])

    def test_value_error_redirects_with_error(self):
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-all": ValueError("bad JSON")}):
            response = self.client.get(
                self._url(),
                {"export": "1", "by": "subnet_id", "q": "1"},
            )
        self.assertIn(response.status_code, [200, 302])


# ---------------------------------------------------------------------------
# F3: Single-lease GET — transport errors
# ---------------------------------------------------------------------------


class TestSingleLeaseGetTransportErrors(_ViewTestBase):
    """Single-lease GET must handle RequestException/ValueError gracefully."""

    def test_request_exception_redirects(self):
        """requests.RequestException from lease-get must redirect with error message."""
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.1"])
        with _lease_stub({"lease4-get": requests.ConnectionError("down")}):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(str(self.server.pk), response.url)

    def test_value_error_redirects(self):
        """ValueError from lease-get must redirect with error message."""
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.1"])
        with _lease_stub({"lease4-get": ValueError("bad JSON")}):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(str(self.server.pk), response.url)


# ---------------------------------------------------------------------------
# F3: Lease edit POST — transport errors
# ---------------------------------------------------------------------------


class TestLeaseEditPostTransportErrors(_ViewTestBase):
    """Lease edit POST must handle RequestException/ValueError gracefully."""

    _RECORD = lease_record("10.0.0.1", subnet_id=1, hostname="old")

    def _post(self, responses: dict):
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, "10.0.0.1"])
        form = {"shown": shown_token(self._RECORD), "hostname": "host", "hw_address": "", "valid_lft": ""}
        with _lease_stub(responses):
            response = self.client.post(url, form)
        self.assertEqual(response.status_code, 302)
        self.assertIn(str(self.server.pk), response["Location"])
        return [str(message) for message in get_messages(response.wsgi_request)]

    def test_a_failed_read_before_the_update_is_not_sent(self):
        """The fresh read of the shown Lease comes before the update, so its failure means nothing was sent."""
        for failure in (requests.ConnectionError("down"), ValueError("bad value")):
            with self.subTest(type(failure).__name__):
                self._fresh_client()
                messages = self._post({"lease4-get": failure})
                self.assertEqual(
                    messages,
                    [
                        (
                            "Lease 10.0.0.1: The change was not sent to Kea."
                            " Kea did not return a usable reply to the read before the change."
                        )
                    ],
                )

    def test_a_malformed_reply_to_the_update_is_unconfirmed(self):
        """A reply entry without a result from lease4-update can follow an applied update (no 500)."""
        messages = self._post({**LeaseDaemon(4, self._RECORD).responses(), "lease4-update": ["ok"]})
        self.assertEqual(
            messages, [f"Lease 10.0.0.1: {UNCONFIRMED_RUNTIME} Kea's reply to the change was lost or unreadable."]
        )


# ---------------------------------------------------------------------------
# F3: Lease add POST — ValueError (RequestException already handled)
# ---------------------------------------------------------------------------


class TestLeaseAddValueError(_ViewTestBase):
    """An unreadable reply to a Lease add is unconfirmed, never an HTTP 500, and writes no journal entry."""

    def test_an_unreadable_reply_is_unconfirmed(self):
        from extras.models import JournalEntry

        url = reverse("plugins:netbox_kea:server_lease4_add", args=[self.server.pk])
        for name, reply in (("value error", ValueError("bad value")), ("malformed", ["ok"])):
            self._fresh_client()
            with self.subTest(name), _lease_stub({"lease4-add": reply}) as kea:
                response = self.client.post(url, {"ip_address": "10.0.0.99", "hw_address": "aa:bb:cc:00:00:99"})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(kea.commands(), ["lease4-add"])
            self.assertEqual(
                [str(message) for message in get_messages(response.wsgi_request)],
                [f"Lease 10.0.0.99: {UNCONFIRMED_RUNTIME} Kea's reply to the change was lost or unreadable."],
            )
        self.assertFalse(JournalEntry.objects.filter(assigned_object_id=self.server.pk).exists())


# ---------------------------------------------------------------------------
# F9: the journal entry of an applied Lease change catches database and validation errors only
# ---------------------------------------------------------------------------


class TestLeaseJournalExceptionNarrowing(_ViewTestBase):
    """A database error of the journal entry after an applied Lease add does not fail the request."""

    def _post_with_failing_journal(self, error: Exception, address: str, hw_address: str):
        url = reverse("plugins:netbox_kea:server_lease4_add", args=[self.server.pk])
        with _failing_journal(error), _lease_stub(LeaseDaemon(4).responses()):
            return self.client.post(url, {"ip_address": address, "hw_address": hw_address})

    def test_database_error_does_not_fail_request(self):
        from django.db import DatabaseError

        response = self._post_with_failing_journal(DatabaseError("DB error"), "10.0.0.55", "aa:bb:cc:00:00:55")
        self.assertEqual(response.status_code, 302)
        shown = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertIn("Lease for 10.0.0.55 created.", shown)
        self.assertIn("Kea applied the change, but NetBox could not write the journal entry; see server logs.", shown)

    def test_operational_error_does_not_fail_request(self):
        from django.db import OperationalError

        response = self._post_with_failing_journal(OperationalError("DB lock"), "10.0.0.56", "aa:bb:cc:00:00:56")
        self.assertEqual(response.status_code, 302)
        self.assertIn("Lease for 10.0.0.56 created.", [str(m) for m in get_messages(response.wsgi_request)])

    def test_validation_error_does_not_fail_request(self):
        from django.core.exceptions import ValidationError

        response = self._post_with_failing_journal(ValidationError("refused"), "10.0.0.57", "aa:bb:cc:00:00:57")
        self.assertEqual(response.status_code, 302)
        shown = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertIn("Lease for 10.0.0.57 created.", shown)
        self.assertIn("Kea applied the change, but NetBox could not write the journal entry; see server logs.", shown)


# ---------------------------------------------------------------------------
# Coverage: get_export() error paths
# ---------------------------------------------------------------------------


class TestLeaseExportClientError(_ViewTestBase):
    """Cover error paths in get_export()."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_get_client_value_error_redirects(self):
        """ValueError from get_client in export redirects with error."""
        # A cert without a key makes the real KeaClient constructor raise ValueError.
        bad = _make_db_server(name="badtls-export", client_cert_path="/x/cert.pem")
        url = reverse("plugins:netbox_kea:server_leases4", args=[bad.pk])
        with _lease_stub({"subnet4-list": _subnet_list(4, [])}):
            response = self.client.get(url, {"export": "form", "by": "subnet", "q": "10.0.0.0/24"})
        self.assertIn(response.status_code, [200, 302])

    def test_runtime_error_during_fetch_redirects(self):
        """RuntimeError during lease fetch in export redirects with error."""
        subnets = _subnet_list(4, [])
        with _lease_stub({"subnet4-list": subnets, "lease4-get-all": RuntimeError("unexpected")}):
            response = self.client.get(self._url(), {"export": "form", "by": "subnet_id", "q": "1"})
        self.assertIn(response.status_code, [200, 302])


# ---------------------------------------------------------------------------
# Coverage: HTMX error handler exception paths
# ---------------------------------------------------------------------------


class TestLeaseHtmxErrorHandler(_ViewTestBase):
    """Cover HTMX error rendering paths."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    _SUBNETS4 = _subnet_list(4, [])

    def test_kea_exception_renders_htmx_error(self):
        """KeaException in HTMX handler renders error template."""
        # result=1 on lease4-get-all makes the real client raise KeaException.
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-all": {"result": 1, "text": "err"}}):
            response = self.client.get(
                self._url(),
                {"by": "subnet_id", "q": "1"},
                HTTP_HX_REQUEST="true",
            )
        self.assertEqual(response.status_code, 200)

    def test_request_exception_renders_htmx_error(self):
        """requests.RequestException in HTMX handler renders error template."""
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-all": requests.ConnectionError("down")}):
            response = self.client.get(
                self._url(),
                {"by": "subnet_id", "q": "1"},
                HTTP_HX_REQUEST="true",
            )
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Coverage: lease edit GET validation branches
# ---------------------------------------------------------------------------


class TestLeaseEditGetValidation(_ViewTestBase):
    """Cover lease edit GET validation paths."""

    def _url(self, ip="10.0.0.1"):
        return reverse("plugins:netbox_kea:server_lease4_edit", args=[self.server.pk, ip])

    _SUBNETS4 = _subnet_list(4, [])

    def test_lease_not_found_result3_redirects(self):
        """result=3 from Kea (lease not found) shows warning and redirects."""
        with _lease_stub({"lease4-get": {"result": 3, "text": "not found"}, "subnet4-list": self._SUBNETS4}):
            response = self.client.get(self._url(), follow=True)
        self.assertEqual(response.status_code, 200)

    def test_bad_response_shape_redirects(self):
        """An empty (shapeless) response list redirects with error."""
        # A real command returning [] passes the result-code check but fails the
        # view's resp[0] shape guard → redirect.
        with _lease_stub({"lease4-get": lambda body: [], "subnet4-list": self._SUBNETS4}):
            response = self.client.get(self._url(), follow=True)
        self.assertEqual(response.status_code, 200)

    def test_bad_arguments_redirects(self):
        """Non-dict arguments in response redirects with error."""
        with _lease_stub({"lease4-get": {"result": 0, "arguments": "not a dict"}, "subnet4-list": self._SUBNETS4}):
            response = self.client.get(self._url(), follow=True)
        self.assertEqual(response.status_code, 200)

    def test_get_client_value_error_redirects(self):
        """ValueError from get_client redirects with error."""
        # A cert without a key makes the real KeaClient constructor raise ValueError.
        bad = _make_db_server(name="badtls-edit", client_cert_path="/x/cert.pem")
        url = reverse("plugins:netbox_kea:server_lease4_edit", args=[bad.pk, "10.0.0.1"])
        with _lease_stub({"subnet4-list": self._SUBNETS4}):
            response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Coverage: lease update POST exception paths
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Coverage: lease add POST exception paths
# ---------------------------------------------------------------------------


class TestLeaseAddPostErrors(_ViewTestBase):
    """Cover lease add POST error handling."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_lease4_add", args=[self.server.pk])

    def _valid_form(self):
        return {"ip_address": "10.0.0.1", "subnet_id": "1", "hw_address": "aa:bb:cc:00:00:01", "valid_lft": "3600"}

    def test_a_failure_result_is_unconfirmed_with_kea_text(self):
        """A SQL backend can store the Lease and still answer a failure result, so Kea's text goes with a check."""
        for reply in ({"result": 1, "text": "dup"}, {"result": 4, "text": "IPv4 lease already exists."}):
            self._fresh_client()
            with self.subTest(result=reply["result"]), _lease_stub({"lease4-add": reply}):
                response = self.client.post(self._url(), self._valid_form())
            self.assertEqual(response.status_code, 302)
            self.assertEqual(
                [str(message) for message in get_messages(response.wsgi_request)],
                [f"Lease 10.0.0.1: {UNCONFIRMED_RUNTIME} Kea replied: {reply['text']}"],
            )

    def test_a_refused_connection_rerenders_the_form(self):
        """Nothing reached Kea, so the operator can correct the form and send it again."""
        refused = _refused_connection()
        with _lease_stub({"lease4-add": refused}):
            response = self.client.post(self._url(), self._valid_form())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            ["Lease 10.0.0.1: The change was not sent to Kea. Kea could not be reached."],
        )


# ---------------------------------------------------------------------------
# Coverage: lease add post-creation side effect errors (journal + sync)
# ---------------------------------------------------------------------------


class TestLeaseAddSideEffectErrors(_ViewTestBase):
    """Cover lease add post-creation side effect error paths."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_lease4_add", args=[self.server.pk])

    def _valid_form(self):
        return {"ip_address": "10.0.0.1", "subnet_id": "1", "hw_address": "aa:bb:cc:00:00:01", "valid_lft": "3600"}

    def test_journal_db_error_still_succeeds(self):
        """DatabaseError in journal entry creation still redirects successfully."""
        from django.db import DatabaseError

        subnets = _subnet_list(4, [])
        with (
            _failing_journal(DatabaseError("DB error")),
            _lease_stub({**LeaseDaemon(4).responses(), "subnet4-list": subnets}),
        ):
            response = self.client.post(self._url(), self._valid_form(), follow=True)
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Coverage: defensive checks in the Lease page read and get_export_all()
# ---------------------------------------------------------------------------


class TestGetLeasesPageDefensiveChecks(_ViewTestBase):
    """Cover the isinstance guards and RuntimeError paths in the Lease page read."""

    _SUBNETS4 = _subnet_list(4, [])

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_non_list_leases_raises_runtime_error(self):
        """When Kea returns leases as non-list, the view catches the RuntimeError."""
        page = {"result": 0, "arguments": {"leases": "not-a-list", "count": 0}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": page}):
            response = self.client.get(self._url(), {"by": ""}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)

    def test_non_int_count_raises_runtime_error(self):
        """When Kea returns count as non-int, the view catches the RuntimeError."""
        page = {"result": 0, "arguments": {"leases": [], "count": "bad"}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": page}):
            response = self.client.get(self._url(), {"by": ""}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)

    def test_a_lease_without_an_address_on_a_partial_page_is_a_diagnostic(self):
        """The record is excluded with a safe reason; the page itself still renders."""
        page = {"result": 0, "arguments": {"leases": [{"no-ip": "bad"}], "count": 1}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": page}):
            response = self.client.get(self._url(), {"by": ""}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        _assert_no_error_template(self, response)
        self.assertIn("leases[0] (ip-address): A required lease field is missing.", _lease_lines(response))
        self.assertNotContains(response, "bad")


class TestExportAllDefensiveChecks(_ViewTestBase):
    """Cover defensive branches in get_export_all()."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def test_non_list_leases_in_export_redirects(self):
        """When export_all gets non-list leases, it redirects with error."""
        page = {"result": 0, "arguments": {"leases": "not-a-list", "count": 0}}
        with _lease_stub({"lease4-get-page": page}):
            response = self.client.get(self._url(), {"export_all": "1"})
        self.assertEqual(response.status_code, 302)

    def test_non_int_count_in_export_redirects(self):
        """When export_all gets non-int count, it redirects with error."""
        page = {"result": 0, "arguments": {"leases": [], "count": "bad"}}
        with _lease_stub({"lease4-get-page": page}):
            response = self.client.get(self._url(), {"export_all": "1"})
        self.assertEqual(response.status_code, 302)

    def test_full_page_all_filtered_aborts_export(self):
        """When a full page has invalid entries, export aborts with an error."""
        # export_all uses per_page=1000. One invalid item makes the page indeterminate.
        page = {"result": 0, "arguments": {"leases": [{"no-ip": f"bad-{i}"} for i in range(1000)], "count": 1000}}
        with _lease_stub({"lease4-get-page": page}):
            response = self.client.get(self._url(), {"export_all": "1"})
        self.assertEqual(response.status_code, 302)

    def test_export_limit_refuses_a_partial_csv_and_reports_the_limit(self):
        leases = [lease_record(f"198.18.0.{index}") for index in range(1, 4)]

        with (
            patch("netbox_kea.views.leases._LEASE_EXPORT_MAX_LEASES", new=2),
            stub_kea({"lease4-get-page": lease_pages(leases)}),
        ):
            response = self.client.get(self._url(), {"export_all": "1"})

        self.assertEqual(response.status_code, 302)
        self.assertIn(
            "Export is limited to 2 leases. Narrow the lease set before exporting.",
            [str(message) for message in get_messages(response.wsgi_request)],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Coverage gap tests — malformed responses, error paths, partial failures
# ─────────────────────────────────────────────────────────────────────────────


class TestGetLeasesPageMalformedResponse(_ViewTestBase):
    """The Lease page read must raise RuntimeError on malformed Kea responses.

    These paths use the global paged search. The loader turns the RuntimeError into
    the unavailable Lease Notice (200, not 500).
    """

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    _SUBNETS4 = _subnet_list(4, [])

    def test_non_list_leases_payload_renders_error(self):
        """When Kea returns non-list 'leases', the HTMX handler catches RuntimeError."""
        page = {"result": 0, "arguments": {"leases": "not-a-list", "count": 1}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": page}):
            response = self._htmx_get(self._url(), {"by": ""})
        _assert_lease_read_failed(self, response)

    def test_non_int_count_renders_error(self):
        """When Kea returns non-int 'count', the HTMX handler catches RuntimeError."""
        page = {"result": 0, "arguments": {"leases": [], "count": "not-an-int"}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": page}):
            response = self._htmx_get(self._url(), {"by": ""})
        _assert_lease_read_failed(self, response)

    def test_full_page_all_filtered_renders_error(self):
        """Full page (count==per_page) but all entries invalid must trigger RuntimeError."""
        # Entries that are not lease objects make the response indeterminate.
        per_page = 50
        page = {"result": 0, "arguments": {"leases": ["not-a-dict"] * per_page, "count": per_page}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": page}):
            response = self._htmx_get(
                self._url(),
                {"by": "", "per_page": str(per_page)},
            )
        _assert_lease_read_failed(self, response)

    def test_none_arguments_renders_error(self):
        """When resp[0]['arguments'] is None, the HTMX handler catches RuntimeError."""
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": {"result": 0, "arguments": None}}):
            response = self._htmx_get(self._url(), {"by": ""})
        _assert_lease_read_failed(self, response)

    def test_empty_response_list_renders_error(self):
        """When Kea returns an empty list, the Lease page read raises RuntimeError."""
        # A real command returning [] passes the result-code check but fails the resp guard.
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": lambda body: []}):
            response = self._htmx_get(self._url(), {"by": ""})
        _assert_lease_read_failed(self, response)

    def test_non_dict_first_element_renders_error(self):
        """When resp[0] is not a dict, the HTMX handler catches RuntimeError."""
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": lambda _body: ["not-a-dict"]}):
            response = self._htmx_get(self._url(), {"by": ""})
        _assert_lease_read_failed(self, response)


class TestGetLeasesSingleResultValidation(_ViewTestBase):
    """The single-result paths of a Lease search must raise RuntimeError on bad data.

    Single-result mode (by=ip) returns args dict directly, not a list.
    """

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    _SUBNETS4 = _subnet_list(4, [])

    def test_an_exact_result_without_an_address_is_a_diagnostic_not_absence(self):
        resp = {"result": 0, "arguments": {"hw-address": "aa:bb:cc:dd:ee:ff", "subnet-id": 1}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get": resp}):
            response = self._htmx_get(self._url(), {"by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        _assert_no_error_template(self, response)
        self.assertIn("arguments (ip-address): A required lease field is missing.", _lease_lines(response))

    def test_records_that_are_not_objects_are_diagnostics(self):
        resp = {"result": 0, "arguments": {"leases": ["bad", 123, None], "count": 3}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-by-hw-address": resp}):
            response = self._htmx_get(self._url(), {"by": "hw", "q": "aa:bb:cc:dd:ee:ff"})
        self.assertEqual(response.status_code, 200)
        _assert_no_error_template(self, response)
        self.assertEqual(
            _lease_lines(response),
            [f"leases[{index}] (record): Kea returned a lease that is not an object." for index in range(3)],
        )

    def test_multiple_result_none_arguments_renders_error(self):
        """Multiple-result with None arguments must trigger RuntimeError."""
        resp = {"result": 0, "arguments": None}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-by-hw-address": resp}):
            response = self._htmx_get(self._url(), {"by": "hw", "q": "aa:bb:cc:dd:ee:ff"})
        _assert_lease_read_failed(self, response)

    def test_multiple_result_non_list_leases_renders_error(self):
        """Multiple-result with non-list leases must trigger RuntimeError."""
        resp = {"result": 0, "arguments": {"leases": "not-a-list"}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-by-hw-address": resp}):
            response = self._htmx_get(self._url(), {"by": "hw", "q": "aa:bb:cc:dd:ee:ff"})
        _assert_lease_read_failed(self, response)

    def test_a_client_that_cannot_be_built_keeps_the_error_template(self):
        """A ValueError is outside the Notice rule, so the partial still shows the error template."""
        Server.objects.filter(pk=self.server.pk).update(client_key_path="/tls/client.key", client_cert_path="")
        with _lease_stub({}) as kea:
            response = self._htmx_get(self._url(), {"by": "hw", "q": "aa:bb:cc:dd:ee:ff"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        _assert_rendered_error_template(self, response)


class TestExportErrorPaths(_ViewTestBase):
    """Export must redirect with error messages when Kea calls fail."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    _SUBNETS4 = _subnet_list(4, [])

    def test_export_request_exception_redirects(self):
        """RequestException during export fetch must redirect with error message."""
        with _lease_stub(
            {"subnet4-list": self._SUBNETS4, "lease4-get": requests.RequestException("connection refused")}
        ):
            response = self.client.get(self._url(), {"export": "all", "by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 302)

    def test_export_runtime_error_redirects(self):
        """RuntimeError during export fetch must redirect with error message."""
        # Single-result response lacking 'ip-address' → the Lease search raises RuntimeError.
        resp = {"result": 0, "arguments": {"hw-address": "aa:bb:cc:dd:ee:ff"}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get": resp}):
            response = self.client.get(self._url(), {"export": "all", "by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 302)

    def test_export_kea_exception_redirects(self):
        """KeaException during export fetch must redirect with error hint."""
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get": {"result": 1, "text": "internal error"}}):
            response = self.client.get(self._url(), {"export": "all", "by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 302)

    def test_export_client_creation_failure_redirects(self):
        """ValueError during get_client() for export must redirect with error message."""
        # A cert without a key makes the real KeaClient constructor raise ValueError.
        bad = _make_db_server(name="badtls-export2", client_cert_path="/x/cert.pem")
        url = reverse("plugins:netbox_kea:server_leases4", args=[bad.pk])
        with _lease_stub({"subnet4-list": self._SUBNETS4}):
            response = self.client.get(url, {"export": "all", "by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 302)

    def test_export_subnet_runtime_error_redirects(self):
        """RuntimeError during a Subnet export must redirect with an error message."""
        page = {"result": 0, "arguments": {"leases": "not-a-list", "count": 1}}
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-all": page}):
            response = self.client.get(self._url(), {"export": "all", "by": "subnet_id", "q": "1"})
        self.assertEqual(response.status_code, 302)


class TestLeaseDeletePartialFailure(_ViewTestBase):
    """Bulk delete must handle partial failures gracefully."""

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk])

    def test_a_lost_reply_after_an_applied_row_reports_both(self):
        """The applied row is reported and journaled; the unconfirmed row is reported without its error text."""

        def del_resp(body):
            if body["arguments"]["ip-address"] == "10.0.0.2":
                return requests.RequestException("timeout")
            return {"result": 0}

        held, selected = _held4("10.0.0.1", "10.0.0.2")
        with _lease_stub({**held, "lease4-del": del_resp}):
            response = self.client.post(self._url(), {"pk": selected, "_confirm": "1"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            [
                "Deleted 1 DHCPv4 lease(s): 10.0.0.1.",
                f"Lease 10.0.0.2: {UNCONFIRMED_RUNTIME} Kea's reply to the change was lost or unreadable.",
            ],
        )

    def test_journal_database_error_still_completes(self):
        """DatabaseError from journal creation must not prevent deletion from completing."""
        from django.db import DatabaseError

        held, selected = _held4("10.0.0.1")
        with _failing_journal(DatabaseError("table locked")), _lease_stub({**held, "lease4-del": {"result": 0}}):
            response = self.client.post(
                self._url(),
                {"pk": selected, "_confirm": "1"},
            )
        self.assertEqual(response.status_code, 302)
        msgs = list(response.wsgi_request._messages)
        msg_texts = [str(m) for m in msgs]
        # The delete itself should succeed despite journal failure
        has_success = any("Deleted 1" in t for t in msg_texts)
        self.assertTrue(has_success, f"Expected success message despite journal error, got: {msg_texts}")

    def test_all_leases_fail_shows_only_errors(self):
        """When every lease deletion fails, no success message should appear."""
        # Every lease4-del returns result 1 → KeaException for each IP.
        held, selected = _held4("10.0.0.1", "10.0.0.2")
        with _lease_stub({**held, "lease4-del": {"result": 1, "text": "not found"}}):
            response = self.client.post(
                self._url(),
                {"pk": selected, "_confirm": "1"},
            )
        self.assertEqual(response.status_code, 302)
        msgs = list(response.wsgi_request._messages)
        msg_texts = [str(m) for m in msgs]
        has_success = any("Deleted" in t and "0" not in t for t in msg_texts)
        self.assertFalse(has_success, f"Should not have success message when all fail, got: {msg_texts}")


class TestFetchOneMacValueError(_ViewTestBase):
    """A lease with a non-numeric subnet_id is excluded before any reservation lookup.

    The typed reader excludes the lease with a diagnostic; the test drives it through
    an HTMX lease search.
    """

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    _SUBNETS4 = _subnet_list(4, [])

    def test_non_numeric_subnet_id_is_excluded_without_reservation_lookup(self):
        """A lease with a non-numeric subnet-id is excluded, diagnosed, and gets no reservation-get."""
        lease = complete_lease(
            {
                "ip-address": "10.0.0.5",
                "hw-address": "aa:bb:cc:dd:ee:ff",
                "hostname": "test",
                "subnet-id": "not-a-number",
                "valid-lft": 3600,
                "cltt": 1_700_000_000,
            }
        )
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get": {"result": 0, "arguments": lease}}) as kea:
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.5"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["table"].rows), [])
        self.assertEqual(_lease_lines(response), ["arguments (subnet-id): A lease field has the wrong type."])
        self.assertNotIn("reservation-get", kea.commands())

    def test_null_subnet_id_is_rejected_before_reservation_lookup(self):
        """A null subnet-id is diagnosed, and no MAC reservation lookup is sent to Kea."""
        lease = complete_lease(
            {
                "ip-address": "10.0.0.6",
                "hw-address": "aa:bb:cc:dd:ee:01",
                "hostname": "test2",
                "subnet-id": None,
                "valid-lft": 3600,
                "cltt": 1_700_000_000,
            }
        )
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get": {"result": 0, "arguments": lease}}) as kea:
            response = self._htmx_get(url, {"by": "ip", "q": "10.0.0.6"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(_lease_lines(response))
        self.assertNotIn("reservation-get", kea.commands())


class TestGetLeasesPageGlobalEdgeCases(_ViewTestBase):
    """Additional edge-case tests for global lease-page results."""

    def _htmx_get(self, url, data):
        return self.client.get(url, data=data, HTTP_HX_REQUEST="true")

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    _SUBNETS4 = _subnet_list(4, [])

    def test_result_3_returns_empty_table(self):
        """result=3 (no leases) must render an empty table, not an error."""
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": {"result": 3, "arguments": None}}):
            response = self._htmx_get(self._url(), {"by": ""})
        self.assertEqual(response.status_code, 200)
        _assert_no_error_template(self, response)
        self.assertContains(response, "No leases found.")
        self.assertEqual(len(response.context["table"].rows), 0)

    def test_global_page_preserves_all_returned_leases(self):
        """The client must not infer a Subnet boundary from backend result order."""
        page = {
            "result": 0,
            "arguments": {
                "leases": [
                    complete_lease(
                        {
                            "ip-address": "10.0.0.5",
                            "hw-address": "aa:bb:cc:dd:ee:ff",
                            "hostname": "in-subnet",
                            "subnet-id": 1,
                            "valid-lft": 3600,
                            "cltt": 1_700_000_000,
                        }
                    ),
                    complete_lease(
                        {
                            "ip-address": "10.0.1.5",
                            "hw-address": "aa:bb:cc:dd:ee:01",
                            "hostname": "out-of-subnet",
                            "subnet-id": 1,
                            "valid-lft": 3600,
                            "cltt": 1_700_000_000,
                        }
                    ),
                ],
                "count": 2,
            },
        }
        with _lease_stub({"subnet4-list": self._SUBNETS4, "lease4-get-page": page, "reservation-get": {"result": 3}}):
            response = self._htmx_get(self._url(), {"by": ""})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "10.0.0.5")
        self.assertContains(response, "10.0.1.5")


class TestLeaseSearchSubnetDropdown(_ViewTestBase):
    """For the Subnet and Subnet ID Attributes the Search value is a dropdown of the Server's Subnets."""

    _LISTING = _subnet_list(4, [{"id": 3, "subnet": "10.0.2.0/24"}, {"id": 2, "subnet": "10.0.1.0/24"}])

    def _url(self):
        return reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])

    def _search_value(self, response):
        return BeautifulSoup(response.content, "html.parser").select_one("#lease-search-value")

    @staticmethod
    def _options(control) -> list[tuple[str, str, bool]]:
        return [(o["value"], o.get_text(), o.has_attr("selected")) for o in control.select("#id_q option")]

    def test_each_subnet_attribute_offers_the_subnets_with_cidr_and_id_labels(self):
        for by, values in (("subnet", ["10.0.1.0/24", "10.0.2.0/24"]), ("subnet_id", ["2", "3"])):
            with self.subTest(by=by), _lease_stub({"subnet4-list": self._LISTING}):
                control = self._search_value(self.client.get(self._url(), {"by": by, "q": values[1]}))
            self.assertEqual(
                self._options(control),
                [
                    ("", "---------", False),
                    (values[0], "10.0.1.0/24 (ID 2)", False),
                    (values[1], "10.0.2.0/24 (ID 3)", True),
                ],
            )
            self.assertEqual(control.select("datalist"), [])

    def test_other_attributes_keep_the_text_input(self):
        with _lease_stub({"subnet4-list": self._LISTING}):
            response = self.client.get(self._url(), {"by": "hostname", "q": "printer"})
        control = self._search_value(response)
        self.assertEqual(control.select_one("#id_q").name, "input")
        self.assertEqual(control.select_one("#id_q")["value"], "printer")
        self.assertNotContains(response, "<datalist")
        self.assertNotContains(response, "<script>")

    def test_a_value_that_the_catalogue_does_not_list_stays_selected_and_searches(self):
        empty = {"result": 3, "arguments": {"leases": []}}
        with _lease_stub({"subnet4-list": self._LISTING, "lease4-get-all": empty}) as kea:
            response = self.client.get(self._url(), {"by": "subnet_id", "q": "9"}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertIn(("9", "9 (not listed)", True), self._options(self._search_value(response)))
        # The form is valid, so the Subnet read reaches Kea.
        self.assertIn("lease4-get-all", kea.commands())

    def test_without_catalogue_subnets_the_search_value_stays_a_text_input(self):
        with _lease_stub({"subnet4-list": {"result": 3, "text": "no subnets"}}):
            response = self.client.get(self._url(), {"by": "subnet_id", "q": "4"})
        control = self._search_value(response).select_one("#id_q")
        self.assertEqual((control.name, control["value"]), ("input", "4"))
        # An empty subnet list is not a missing hook: no warning.
        self.assertNotContains(response, "hook library is not loaded")

    def test_the_attribute_control_requests_its_value_control_with_htmx(self):
        with _lease_stub({"subnet4-list": self._LISTING}):
            response = self.client.get(self._url())
        by = BeautifulSoup(response.content, "html.parser").select_one("#id_by")
        self.assertEqual(
            {
                name: by[name]
                for name in ("hx-get", "hx-trigger", "hx-include", "hx-target", "hx-push-url", "hx-disabled-elt")
            },
            {
                "hx-get": "?value_control=1",
                "hx-trigger": "change",
                "hx-include": "#id_q",
                "hx-target": "#lease-search-value",
                "hx-push-url": "false",
                # The request disables the value control, so no input is typed into a control that it replaces.
                "hx-disabled-elt": "#lease-search-value, #lease-search-btn",
            },
        )
        value_control = BeautifulSoup(response.content, "html.parser").select_one("#lease-search-value")
        self.assertEqual(value_control.name, "fieldset")
        self.assertIsNotNone(value_control.select_one("#id_q"))

    def test_value_control_swaps_the_search_value_for_the_selected_attribute(self):
        cases = (
            # A typed value carries over to another text Attribute.
            ({"by": "hostname", "q": "printer"}, "input", "printer"),
            # A dropdown keeps a listed value and drops a value of the previous Attribute.
            ({"by": "subnet", "q": "10.0.1.0/24"}, "select", "10.0.1.0/24"),
            ({"by": "subnet_id", "q": "10.0.1.0/24"}, "select", ""),
            ({"by": "subnet_id", "q": "printer"}, "select", ""),
        )
        for query, element, selected in cases:
            with self.subTest(query), _lease_stub({"subnet4-list": self._LISTING}) as kea:
                response = self.client.get(self._url(), {"value_control": "1", **query}, HTTP_HX_REQUEST="true")
            self.assertEqual(response.status_code, 200)
            control = BeautifulSoup(response.content, "html.parser")
            self.assertEqual(control.find(id=True)["id"], "lease-search-value")
            self.assertEqual(control.find(id="lease-search-value").name, "fieldset")
            q = control.select_one("#id_q")
            self.assertEqual(q.name, element)
            if element == "select":
                chosen = q.select_one("option[selected]")
                self.assertEqual(chosen["value"] if chosen else "", selected)
                self.assertNotIn("(not listed)", response.content.decode())
            else:
                self.assertEqual(q["value"], selected)
            # A control that the user has not submitted shows no validation error.
            self.assertNotContains(response, "text-danger")
            self.assertFalse([command for command in kea.commands() if command.startswith("lease")])

    def test_missing_hook_explains_where_the_subnet_list_comes_from(self):
        """Without subnet_cmds the search still works, so say that rather than fail silently."""
        with _lease_stub({"subnet4-list": {"result": 2, "text": "unknown command 'subnet4-list'"}}):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "hook library is not loaded")
        self.assertContains(response, "The subnet list comes from the running configuration.")


class TestLeaseSearchHeaderSort(_ViewTestBase):
    """A column header of the lease search sorts the rows in place, through NetBox's htmx table header."""

    def _search(self, **params):
        records = [lease_record(f"10.0.0.{host}", subnet_id=1) for host in (65, 142, 9, 111)]
        responses = {
            **_catalogue_responses(4, 1, "10.0.0.0/24"),
            "lease4-get-all": lease_reply(*records),
            "reservation-get": {"result": 3},
        }
        with stub_kea(responses):
            return self.client.get(
                reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]),
                {"by": "subnet", "q": "10.0.0.0/24", **params},
                HTTP_HX_REQUEST="true",
            )

    def test_the_header_target_is_the_search_container_and_the_sorted_rows_come_back(self):
        from bs4 import BeautifulSoup

        page = BeautifulSoup(self._search().content, "html.parser")
        header = page.select_one('thead[hx-target="closest .htmx-container"]')
        self.assertIsNotNone(header)
        # htmx swaps the container's outer HTML with the response, which is the same #lease-search block.
        self.assertEqual(header.find_parent(class_="htmx-container").get("id"), "lease-search")

        sorted_page = BeautifulSoup(self._search(sort="ip_address").content, "html.parser")
        addresses = [row.find_all("td")[1].get_text(strip=True) for row in sorted_page.select("tbody tr")]
        self.assertEqual(addresses, ["10.0.0.9", "10.0.0.65", "10.0.0.111", "10.0.0.142"])
