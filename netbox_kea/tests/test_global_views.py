# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for combined Overview, Reservation, Subnet and Shared Network views.

The lease routes choose a Server without reading Kea. The other sections read
Snapshots through the real KeaClient, with only the HTTP boundary stubbed.
"""

import json
from unittest.mock import patch

import requests
import yaml
from django.test import TestCase
from django.urls import reverse
from ipam.models import IPAddress
from netaddr import IPNetwork

from netbox_kea.models import Server

from .kea_stub import _res_page, complete_lease, queued, stub_kea
from .utils import User, _make_db_server, with_display_cache_config, with_kea_client_config

# ---------------------------------------------------------------------------
# Kea response fixtures
# ---------------------------------------------------------------------------

_MOCK_RESERVATION_V4 = {
    "subnet-id": 1,
    "hw-address": "aa:bb:cc:dd:ee:ff",
    "ip-address": "10.0.0.100",
    "hostname": "host-v4",
}

_MOCK_RESERVATION_V6 = {
    "subnet-id": 1,
    "duid": "00:01:aa:bb",
    "ip-addresses": ["2001:db8::1"],
    "hostname": "host-v6",
}


_MOCK_CONFIG_V4 = [
    {
        "result": 0,
        "arguments": {
            "Dhcp4": {
                "subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}],
                "shared-networks": [],
            }
        },
    }
]

_MOCK_CONFIG_V6 = [
    {
        "result": 0,
        "arguments": {
            "Dhcp6": {
                "subnet6": [{"id": 1, "subnet": "2001:db8::/32"}],
                "shared-networks": [],
            }
        },
    }
]

_MOCK_SUBNET_LIST_V4 = {
    "result": 0,
    "arguments": {"subnets": [{"id": 1, "subnet": "10.0.0.0/24", "shared-network-name": None}]},
}

_MOCK_SUBNET_LIST_V6 = {
    "result": 0,
    "arguments": {"subnets": [{"id": 1, "subnet": "2001:db8::/32", "shared-network-name": None}]},
}

#: The two Subnets the filter tests search over. Both Catalogue sources read this one
#: list, so identity and configuration cannot drift apart when a test edits it.
_MOCK_TWO_SUBNETS_V4 = [{"id": 1, "subnet": "10.0.1.0/24"}, {"id": 2, "subnet": "192.168.0.0/24"}]

_MOCK_CONFIG_TWO_V4 = [
    {
        "result": 0,
        "arguments": {"Dhcp4": {"subnet4": _MOCK_TWO_SUBNETS_V4, "shared-networks": []}},
    }
]

_MOCK_SUBNET_LIST_TWO_V4 = {"result": 0, "arguments": {"subnets": _MOCK_TWO_SUBNETS_V4}}


# ---------------------------------------------------------------------------
# Stub response builders (real KeaClient + HTTP-boundary stub)
# ---------------------------------------------------------------------------


def _leases(entries):
    """A multi-lease response for ``lease{v}-get-*`` / ``lease{v}-get-page``."""
    entries = list(entries)
    return {"result": 0, "arguments": {"count": len(entries), "leases": entries}}


#: ``reservation-get-page`` with no hosts (source exhausted → empty reservation list).
_RES_EMPTY_PAGE = {"result": 3}
#: ``lease{v}-get-all`` / ``lease{v}-get`` with result 3 = no such lease.
_LEASE_NONE = {"result": 3}
#: ``stat-lease{v}-get`` with no result-set (utilisation stats absent, non-fatal).
_STAT_EMPTY = {"result": 0, "arguments": {}}


def _subnet_responses(version, *, config=None, subnets=None, stat=_STAT_EMPTY):
    """Return both Catalogue source responses and the optional utilization response."""
    if version == 4:
        config = _MOCK_CONFIG_V4 if config is None else config
        subnets = _MOCK_SUBNET_LIST_V4 if subnets is None else subnets
    else:
        config = _MOCK_CONFIG_V6 if config is None else config
        subnets = _MOCK_SUBNET_LIST_V6 if subnets is None else subnets
    return {
        f"subnet{version}-list": subnets,
        "config-get": config,
        f"stat-lease{version}-get": stat,
    }


def _reservation_stub(version, responses):
    """Stub a Reservation request with the required Subnet catalogue sources."""
    return stub_kea({**_subnet_responses(version), **responses})


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class _CombinedViewBase(TestCase):
    """Create superuser + one v4-only, one v6-only, one dual-stack server."""

    def setUp(self):
        self.user = User.objects.create_superuser(
            username="global_testuser",
            email="global@test.com",
            password="testpass",
        )
        self.client.force_login(self.user)
        self.v4_server = _make_db_server(name="v4-server", dhcp4=True, dhcp6=False, has_control_agent=False)
        self.v6_server = _make_db_server(name="v6-server", dhcp4=False, dhcp6=True, has_control_agent=False)
        self.dual_server = _make_db_server(name="dual-server", dhcp4=True, dhcp6=True, has_control_agent=False)


# ---------------------------------------------------------------------------
# CombinedDashboardView  GET /plugins/kea/combined/
# ---------------------------------------------------------------------------


class TestCombinedDashboardView(_CombinedViewBase):
    """GET /plugins/kea/combined/ — server overview with tab navigation."""

    def test_get_returns_200(self):
        url = reverse("plugins:netbox_kea:combined")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_redirects_to_login(self):
        self.client.logout()
        url = reverse("plugins:netbox_kea:combined")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_lists_all_servers_by_name(self):
        url = reverse("plugins:netbox_kea:combined")
        response = self.client.get(url)
        self.assertContains(response, "v4-server")
        self.assertContains(response, "v6-server")
        self.assertContains(response, "dual-server")

    def test_no_kea_api_calls_on_dashboard(self):
        """Dashboard must not call Kea API (would slow down the page for many servers)."""
        with stub_kea({}) as kea:
            url = reverse("plugins:netbox_kea:combined")
            self.client.get(url)
        self.assertEqual(kea.commands(), [])

    def test_context_contains_all_servers(self):
        url = reverse("plugins:netbox_kea:combined")
        response = self.client.get(url)
        self.assertIn("server_scope", response.context)
        self.assertEqual(len(response.context["server_scope"].all_servers), 3)

    def test_context_active_tab_is_overview(self):
        url = reverse("plugins:netbox_kea:combined")
        response = self.client.get(url)
        self.assertEqual(response.context["active_tab"], "overview")

    def test_tab_navigation_links_present(self):
        """The workspace links to six sections in the selected family."""
        for family in (4, 6):
            response = self.client.get(reverse(f"plugins:netbox_kea:combined_overview{family}"))
            for section in ("overview", "leases", "subnets", "reservations", "configuration", "sync"):
                self.assertContains(response, reverse(f"plugins:netbox_kea:combined_{section}{family}"))
            self.assertNotContains(response, "/combined/shared-networks4/")
            self.assertNotContains(response, "/combined/shared-networks6/")


# ---------------------------------------------------------------------------
# CombinedServerStatusBadgeView  GET /plugins/kea/combined/server-status-badge/<pk>/
# ---------------------------------------------------------------------------


class TestCombinedServerStatusBadge(_CombinedViewBase):
    """GET /plugins/kea/combined/server-status-badge/<pk>/ — HTMX status fragment."""

    def _url(self, server):
        return reverse("plugins:netbox_kea:combined_server_status_badge", args=[server.pk])

    def test_online_server_returns_200_with_online_text(self):
        """Reachable server should return 200 and contain 'Online'."""
        with stub_kea({"version-get": {"result": 0, "arguments": {"extended": "Kea DHCPv4/2.x"}}}):
            response = self.client.get(self._url(self.v4_server))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Online")

    # Two answers of one daemon, each read live.
    @with_display_cache_config(status_ttl=0)
    def test_badges_set_a_text_color_that_contrasts_with_their_background(self):
        """A bare bg-* badge keeps the body text color: grey on green in the light theme."""
        with stub_kea({"version-get": {"result": 0, "arguments": {"extended": "Kea DHCPv4/2.x"}}}):
            online = self.client.get(self._url(self.v4_server))
        with stub_kea({"version-get": requests.ConnectionError("connection refused")}):
            offline = self.client.get(self._url(self.v4_server))
        self.assertContains(online, "badge text-bg-success")
        self.assertContains(offline, "badge text-bg-danger")

    def test_offline_server_returns_200_with_offline_text(self):
        """Unreachable server should return 200 and contain 'Offline' (no 500)."""
        with stub_kea({"version-get": requests.ConnectionError("connection refused")}):
            response = self.client.get(self._url(self.v4_server))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Offline")

    def test_invalid_ca_path_returns_200_with_offline_text(self):
        """An invalid CA bundle path should show Offline instead of returning 500."""
        with stub_kea({"version-get": OSError("invalid CA bundle path")}):
            response = self.client.get(self._url(self.v4_server))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Offline")

    def test_malformed_reply_returns_200_with_offline_text(self):
        """A reply entry without a result should show Offline instead of returning 500."""
        with stub_kea({"version-get": ["ok"]}):
            response = self.client.get(self._url(self.v4_server))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Offline")

    def test_requires_auth(self):
        """Unauthenticated request must redirect to login."""
        self.client.logout()
        response = self.client.get(self._url(self.v4_server))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_v4_only_server_shows_v4_badge(self):
        """DHCPv4-only server should show DHCPv4 status badge only."""
        with stub_kea({"version-get": {"result": 0, "arguments": {"extended": "Kea DHCPv4/2.x"}}}):
            response = self.client.get(self._url(self.v4_server))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DHCPv4")
        self.assertNotContains(response, "DHCPv6")

    def test_v6_only_server_shows_v6_badge(self):
        """DHCPv6-only server should show DHCPv6 status badge only."""
        with stub_kea({"version-get": {"result": 0, "arguments": {"extended": "Kea DHCPv6/2.x"}}}):
            response = self.client.get(self._url(self.v6_server))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "DHCPv4")
        self.assertContains(response, "DHCPv6")

    def test_dual_stack_shows_both_badges(self):
        """Dual-stack server should show both DHCPv4 and DHCPv6 status badges."""
        with stub_kea({"version-get": {"result": 0, "arguments": {"extended": "Kea/2.x"}}}):
            response = self.client.get(self._url(self.dual_server))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DHCPv4")
        self.assertContains(response, "DHCPv6")

    def test_nonexistent_server_returns_404(self):
        """Request for a server that does not exist must return 404 (before any Kea call)."""
        url = reverse("plugins:netbox_kea:combined_server_status_badge", args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)


# ---------------------------------------------------------------------------
# CombinedReservations4View  GET /plugins/kea/combined/reservations4/
# ---------------------------------------------------------------------------


class TestCombinedReservations4View(_CombinedViewBase):
    """GET /plugins/kea/combined/reservations4/ — all DHCPv4 reservations."""

    def test_get_returns_200(self):
        with _reservation_stub(4, {"reservation-get-page": _RES_EMPTY_PAGE}):
            url = reverse("plugins:netbox_kea:combined_reservations4")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_redirects_to_login(self):
        self.client.logout()
        url = reverse("plugins:netbox_kea:combined_reservations4")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_queries_all_v4_servers(self):
        """Without a server filter, every dhcp4-enabled server is queried."""
        with _reservation_stub(
            4, {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V4)]), "lease4-get-by-state": _LEASE_NONE}
        ) as kea:
            url = reverse("plugins:netbox_kea:combined_reservations4")
            self.client.get(url)
        # v4_server + dual_server have dhcp4=True → at least 2 get-page calls
        self.assertGreaterEqual(kea.commands().count("reservation-get-page"), 2)

    def test_server_filter_limits_queried_servers(self):
        """An explicit selection reads only its Servers that serve the page's family."""
        with _reservation_stub(4, {"reservation-get-page": _RES_EMPTY_PAGE}) as kea:
            url = (
                reverse("plugins:netbox_kea:combined_reservations4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            self.client.get(url)
        self.assertEqual(kea.commands().count("reservation-get-page"), 1)

    def test_results_include_server_name(self):
        """Each row in the merged table must carry the originating server name."""
        with _reservation_stub(
            4, {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V4)]), "lease4-get-by-state": _LEASE_NONE}
        ):
            url = (
                reverse("plugins:netbox_kea:combined_reservations4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "v4-server")

    def test_unreachable_server_returns_200_with_warning(self):
        """A server that raises an exception must not cause a 500."""
        with _reservation_stub(4, {"reservation-get-page": requests.ConnectionError("refused")}):
            url = reverse("plugins:netbox_kea:combined_reservations4")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_page_diagnostic_uses_neutral_incomplete_snapshot_alert(self):
        hosts = [
            {"subnet-id": 0, "flex-id": f"global-{index}", "hostname": f"host-{index}.example.invalid"}
            for index in range(100)
        ]
        first_page = _res_page(
            hosts,
            next_from=100,
            next_source=1,
        )
        # A search with no match on the first page reads the next one, and that read fails.
        url = (
            reverse("plugins:netbox_kea:combined_reservations4")
            + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&q=needle"
        )

        with _reservation_stub(
            4,
            {
                "reservation-get-page": queued(first_page, requests.ConnectionError("page failed")),
            },
        ):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Snapshot is incomplete.")
        self.assertContains(response, "The Reservation Snapshot could not be read completely.")
        self.assertContains(response, "See the 1 diagnostic below.")
        self.assertContains(response, "page-fetch-failed")
        self.assertNotContains(response, "malformed Reservation")

    def test_no_v4_servers_returns_200_empty_table(self):
        """If no dhcp4-enabled servers exist, the view renders with an empty table (no Kea traffic)."""
        Server.objects.filter(dhcp4=True).update(dhcp4=False)
        with _reservation_stub(4, {}) as kea:
            url = reverse("plugins:netbox_kea:combined_reservations4")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])

    def test_context_active_tab(self):
        with _reservation_stub(4, {"reservation-get-page": _RES_EMPTY_PAGE}):
            url = reverse("plugins:netbox_kea:combined_reservations4")
            response = self.client.get(url)
        self.assertEqual(response.context["active_tab"], "reservations4")

    def test_export_returns_yaml(self):
        """?export=yaml returns a structured v4 Reservation document."""
        with _reservation_stub(
            4, {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V4)]), "lease4-get-by-state": _LEASE_NONE}
        ):
            url = reverse("plugins:netbox_kea:combined_reservations4") + f"?server={self.v4_server.pk}&export=yaml"
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/yaml", response.get("Content-Type", ""))
        # A serializer that emits an empty or wrong-shaped document passes a header check.
        document = yaml.safe_load(response.content.decode())
        self.assertEqual(document["version"], 1)
        self.assertEqual([record["hostname"] for record in document["reservations"]], ["host-v4"])
        self.assertEqual(document["reservations"][0]["addresses"], ["10.0.0.100"])

    def test_export_rejects_an_incomplete_snapshot(self):
        first_page = _res_page([dict(_MOCK_RESERVATION_V4)], next_from=1, next_source=1)
        url = reverse("plugins:netbox_kea:combined_reservations4")
        url += f"?server={self.v4_server.pk}&export=yaml"

        with _reservation_stub(
            4, {"reservation-get-page": queued(first_page, requests.ConnectionError("page failed"))}
        ) as kea:
            response = self.client.get(url)

        self.assertEqual(len(kea.bodies("reservation-get-page")), 2)

        self.assertEqual(response.status_code, 409)
        self.assertContains(response, "Snapshot is incomplete", status_code=409)

    def test_search_form_in_context(self):
        """Response context must contain search_form for the search card to render."""
        with _reservation_stub(4, {"reservation-get-page": _RES_EMPTY_PAGE}):
            url = reverse("plugins:netbox_kea:combined_reservations4")
            response = self.client.get(url)
        self.assertIn("search_form", response.context)

    def test_search_by_hostname_filters_results(self):
        """?q=host-v4 returns only records whose hostname matches."""
        rec_match = dict(_MOCK_RESERVATION_V4)  # hostname="host-v4"
        rec_nomatch = dict(_MOCK_RESERVATION_V4)
        rec_nomatch["hostname"] = "other-host"
        rec_nomatch["ip-address"] = "10.0.0.200"
        with _reservation_stub(
            4, {"reservation-get-page": _res_page([rec_match, rec_nomatch]), "lease4-get-by-state": _LEASE_NONE}
        ):
            url = (
                reverse("plugins:netbox_kea:combined_reservations4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&q=host-v4"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "10.0.0.100")
        self.assertNotContains(response, "10.0.0.200")

    def test_search_by_ip_filters_results(self):
        """?q=10.0.0.100 returns only the matching record."""
        rec = dict(_MOCK_RESERVATION_V4)
        rec2 = dict(_MOCK_RESERVATION_V4)
        rec2["ip-address"] = "10.0.0.200"
        rec2["hostname"] = "other"
        with _reservation_stub(4, {"reservation-get-page": _res_page([rec, rec2]), "lease4-get-by-state": _LEASE_NONE}):
            url = (
                reverse("plugins:netbox_kea:combined_reservations4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&q=10.0.0.100"
            )
            response = self.client.get(url)
        self.assertContains(response, "10.0.0.100")
        self.assertNotContains(response, "10.0.0.200")

    def test_search_by_subnet_id_filters_results(self):
        """?subnet_id=2 returns only records in subnet 2."""
        rec1 = dict(_MOCK_RESERVATION_V4)  # subnet-id=1
        rec2 = dict(_MOCK_RESERVATION_V4)
        rec2["subnet-id"] = 2
        rec2["ip-address"] = "10.0.0.200"
        # Both Catalogue sources share this list, so identity and configuration cannot drift apart.
        two_subnets = [{"id": 1, "subnet": "10.0.0.0/25"}, {"id": 2, "subnet": "10.0.0.128/25"}]
        subnets = {
            "result": 0,
            "arguments": {"subnets": [{**subnet, "shared-network-name": None} for subnet in two_subnets]},
        }
        config = [
            {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": two_subnets,
                        "shared-networks": [],
                    }
                },
            }
        ]
        with _reservation_stub(
            4,
            {
                "subnet4-list": subnets,
                "config-get": config,
                "reservation-get-page": _res_page([rec1, rec2]),
                "lease4-get-by-state": _LEASE_NONE,
            },
        ):
            url = (
                reverse("plugins:netbox_kea:combined_reservations4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&subnet_id=2"
            )
            response = self.client.get(url)
        self.assertNotContains(response, "10.0.0.100")
        self.assertContains(response, "10.0.0.200")

    def test_search_no_match_returns_empty_table(self):
        """?q=zzz with no matching records renders an empty table (no 500)."""
        with _reservation_stub(
            4, {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V4)]), "lease4-get-by-state": _LEASE_NONE}
        ):
            url = (
                reverse("plugins:netbox_kea:combined_reservations4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&q=zzz-no-match"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# CombinedReservations6View  GET /plugins/kea/combined/reservations6/
# ---------------------------------------------------------------------------


class TestCombinedReservations6View(_CombinedViewBase):
    """GET /plugins/kea/combined/reservations6/ — all DHCPv6 reservations."""

    def test_get_returns_200(self):
        with _reservation_stub(6, {"reservation-get-page": _RES_EMPTY_PAGE}):
            url = reverse("plugins:netbox_kea:combined_reservations6")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_redirects_to_login(self):
        self.client.logout()
        url = reverse("plugins:netbox_kea:combined_reservations6")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_queries_all_v6_servers(self):
        with _reservation_stub(
            6, {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V6)]), "lease6-get-by-state": _LEASE_NONE}
        ) as kea:
            url = reverse("plugins:netbox_kea:combined_reservations6")
            self.client.get(url)
        self.assertGreaterEqual(kea.commands().count("reservation-get-page"), 2)

    def test_server_filter_limits_queried_servers(self):
        with _reservation_stub(6, {"reservation-get-page": _RES_EMPTY_PAGE}) as kea:
            url = (
                reverse("plugins:netbox_kea:combined_reservations6")
                + f"?server={self.v6_server.pk}&server={self.v4_server.pk}"
            )
            self.client.get(url)
        self.assertEqual(kea.commands().count("reservation-get-page"), 1)

    def test_unreachable_server_returns_200_with_warning(self):
        with _reservation_stub(6, {"reservation-get-page": requests.ConnectionError("refused")}):
            url = reverse("plugins:netbox_kea:combined_reservations6")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_export_returns_json(self):
        """?export=json returns a structured v6 Reservation document."""
        with _reservation_stub(
            6, {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V6)]), "lease6-get-by-state": _LEASE_NONE}
        ):
            url = reverse("plugins:netbox_kea:combined_reservations6") + f"?server={self.v6_server.pk}&export=json"
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.get("Content-Type", ""))
        document = json.loads(response.content.decode())
        self.assertEqual(document["version"], 1)
        self.assertEqual([record["hostname"] for record in document["reservations"]], ["host-v6"])
        self.assertEqual(document["reservations"][0]["addresses"], ["2001:db8::1"])

    def test_search_form_in_context(self):
        """Response context must contain search_form."""
        with _reservation_stub(6, {"reservation-get-page": _RES_EMPTY_PAGE}):
            url = reverse("plugins:netbox_kea:combined_reservations6")
            response = self.client.get(url)
        self.assertIn("search_form", response.context)

    def test_search_by_hostname_filters_results(self):
        """?q=host-v6 returns only records whose hostname matches."""
        rec_match = dict(_MOCK_RESERVATION_V6)  # hostname="host-v6"
        rec_nomatch = {
            "subnet-id": 1,
            "duid": "00:01:aa:bb",
            "ip-addresses": ["2001:db8::2"],
            "hostname": "other-v6",
        }
        with _reservation_stub(
            6, {"reservation-get-page": _res_page([rec_match, rec_nomatch]), "lease6-get-by-state": _LEASE_NONE}
        ):
            url = (
                reverse("plugins:netbox_kea:combined_reservations6")
                + f"?server={self.v6_server.pk}&server={self.v4_server.pk}&q=host-v6"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "host-v6")
        self.assertNotContains(response, "other-v6")

    def test_search_by_duid_filters_results(self):
        """?q=00:01:aa:bb returns only the matching DUID record."""
        rec = dict(_MOCK_RESERVATION_V6)  # duid="00:01:aa:bb"
        rec2 = {
            "subnet-id": 1,
            "duid": "ff:ff:ff:ff",
            "ip-addresses": ["2001:db8::99"],
            "hostname": "other",
        }
        with _reservation_stub(6, {"reservation-get-page": _res_page([rec, rec2]), "lease6-get-by-state": _LEASE_NONE}):
            url = (
                reverse("plugins:netbox_kea:combined_reservations6")
                + f"?server={self.v6_server.pk}&server={self.v4_server.pk}&q=00:01:aa:bb"
            )
            response = self.client.get(url)
        self.assertContains(response, "00:01:aa:bb")
        self.assertNotContains(response, "ff:ff:ff:ff")


# ---------------------------------------------------------------------------
# CombinedSubnets4View  GET /plugins/kea/combined/subnets4/
# ---------------------------------------------------------------------------


class TestCombinedSubnets4View(_CombinedViewBase):
    """GET /plugins/kea/combined/subnets4/ — DHCPv4 subnets across all servers."""

    def test_get_returns_200(self):
        with stub_kea(_subnet_responses(4)):
            url = reverse("plugins:netbox_kea:combined_subnets4")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_redirects_to_login(self):
        self.client.logout()
        url = reverse("plugins:netbox_kea:combined_subnets4")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_queries_all_v4_servers(self):
        """Without a filter, every dhcp4-enabled server is queried for config-get."""
        with stub_kea(_subnet_responses(4)) as kea:
            url = reverse("plugins:netbox_kea:combined_subnets4")
            self.client.get(url)
        # v4_server + dual_server → at least 2 config-get calls
        self.assertGreaterEqual(kea.commands().count("config-get"), 2)

    def test_server_filter_limits_queried_servers(self):
        with stub_kea(_subnet_responses(4)) as kea:
            url = (
                reverse("plugins:netbox_kea:combined_subnets4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            self.client.get(url)
        # One server reads both Catalogue sources, then fetches utilization.
        self.assertEqual(kea.commands(), ["subnet4-list", "config-get", "stat-lease4-get"])

    def test_unreachable_server_returns_200_with_warning(self):
        with stub_kea(
            {
                "subnet4-list": requests.ConnectionError("refused"),
                "config-get": requests.ConnectionError("refused"),
            }
        ):
            url = reverse("plugins:netbox_kea:combined_subnets4")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_results_include_server_name(self):
        with stub_kea(_subnet_responses(4)):
            url = (
                reverse("plugins:netbox_kea:combined_subnets4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "v4-server")

    def test_results_include_ddns_qualifying_suffix(self):
        config = [
            {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [
                            {
                                "id": 1,
                                "subnet": "10.0.0.0/24",
                                "ddns-qualifying-suffix": "dhcp.example",
                            }
                        ],
                        "shared-networks": [],
                    }
                },
            }
        ]
        with stub_kea(_subnet_responses(4, config=config)):
            url = (
                reverse("plugins:netbox_kea:combined_subnets4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            response = self.client.get(url)
        self.assertContains(response, "DDNS: dhcp.example")

    def test_context_active_tab(self):
        with stub_kea(_subnet_responses(4)):
            url = reverse("plugins:netbox_kea:combined_subnets4")
            response = self.client.get(url)
        self.assertEqual(response.context["active_tab"], "subnets4")

    def test_export_returns_csv(self):
        """?export=table returns a CSV download of the subnet table."""
        with stub_kea(_subnet_responses(4)):
            url = reverse("plugins:netbox_kea:combined_subnets4") + f"?server={self.v4_server.pk}&export=table"
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))

    def test_search_form_in_context(self):
        """Response context must contain search_form."""
        with stub_kea(_subnet_responses(4)):
            url = reverse("plugins:netbox_kea:combined_subnets4")
            response = self.client.get(url)
        self.assertIn("search_form", response.context)

    def test_search_by_cidr_filters_results(self):
        """?q=10.0 returns subnets whose CIDR contains '10.0', excludes others."""
        with stub_kea(_subnet_responses(4, config=_MOCK_CONFIG_TWO_V4, subnets=_MOCK_SUBNET_LIST_TWO_V4)):
            url = (
                reverse("plugins:netbox_kea:combined_subnets4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&q=10.0"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "10.0.1.0/24")
        self.assertNotContains(response, "192.168.0.0/24")

    def test_search_by_subnet_id_filters_results(self):
        """?subnet_id=2 returns only the subnet with id=2."""
        with stub_kea(_subnet_responses(4, config=_MOCK_CONFIG_TWO_V4, subnets=_MOCK_SUBNET_LIST_TWO_V4)):
            url = (
                reverse("plugins:netbox_kea:combined_subnets4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&subnet_id=2"
            )
            response = self.client.get(url)
        self.assertNotContains(response, "10.0.1.0/24")
        self.assertContains(response, "192.168.0.0/24")

    def test_search_no_match_returns_empty_table(self):
        """?q=zzz with no matching subnets renders 200 with empty table."""
        with stub_kea(_subnet_responses(4)):
            url = (
                reverse("plugins:netbox_kea:combined_subnets4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}&q=zzz-no-match"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_configuration_only_subnet_does_not_offer_mutation_actions(self):
        """Configuration facts remain visible but cannot authorize an edit."""
        config = [
            {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [{"id": 7, "subnet": "198.18.7.0/24"}],
                        "shared-networks": [],
                    }
                },
            }
        ]
        subnets = {"result": 2, "text": "unknown command"}
        with stub_kea(_subnet_responses(4, config=config, subnets=subnets)):
            url = (
                reverse("plugins:netbox_kea:combined_subnets4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            response = self.client.get(url)
        edit_url = reverse(
            "plugins:netbox_kea:server_subnet4_edit",
            args=[self.v4_server.pk, 7],
        )
        self.assertContains(response, "198.18.7.0/24")
        self.assertNotContains(response, edit_url)


# ---------------------------------------------------------------------------
# CombinedSubnets6View  GET /plugins/kea/combined/subnets6/
# ---------------------------------------------------------------------------


class TestCombinedSubnets6View(_CombinedViewBase):
    """GET /plugins/kea/combined/subnets6/ — DHCPv6 subnets across all servers."""

    def test_get_returns_200(self):
        with stub_kea(_subnet_responses(6)):
            url = reverse("plugins:netbox_kea:combined_subnets6")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_redirects_to_login(self):
        self.client.logout()
        url = reverse("plugins:netbox_kea:combined_subnets6")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_queries_all_v6_servers(self):
        with stub_kea(_subnet_responses(6)) as kea:
            url = reverse("plugins:netbox_kea:combined_subnets6")
            self.client.get(url)
        self.assertGreaterEqual(kea.commands().count("config-get"), 2)

    def test_unreachable_server_returns_200_with_warning(self):
        with stub_kea(
            {
                "subnet6-list": requests.ConnectionError("refused"),
                "config-get": requests.ConnectionError("refused"),
            }
        ):
            url = reverse("plugins:netbox_kea:combined_subnets6")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_export_returns_csv(self):
        """?export=table returns a CSV download of the v6 subnet table."""
        with stub_kea(_subnet_responses(6)):
            url = reverse("plugins:netbox_kea:combined_subnets6") + f"?server={self.v6_server.pk}&export=table"
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))

    def test_search_form_in_context(self):
        """Response context must contain search_form."""
        with stub_kea(_subnet_responses(6)):
            url = reverse("plugins:netbox_kea:combined_subnets6")
            response = self.client.get(url)
        self.assertIn("search_form", response.context)

    def test_search_by_cidr_filters_results(self):
        """?q=2001:db8 returns only matching v6 subnets."""
        # Both Catalogue sources read this one list, so identity and configuration cannot
        # drift apart when a test edits it.
        two_subnets = [{"id": 1, "subnet": "2001:db8::/32"}, {"id": 2, "subnet": "fd00::/8"}]
        config_with_two_subnets = [
            {"result": 0, "arguments": {"Dhcp6": {"subnet6": two_subnets, "shared-networks": []}}}
        ]
        subnet_list = {"result": 0, "arguments": {"subnets": two_subnets}}
        with stub_kea(_subnet_responses(6, config=config_with_two_subnets, subnets=subnet_list)):
            url = (
                reverse("plugins:netbox_kea:combined_subnets6")
                + f"?server={self.v6_server.pk}&server={self.v4_server.pk}&q=2001:db8"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "2001:db8::/32")
        self.assertNotContains(response, "fd00::/8")


_MOCK_RESERVATION_ENRICHED = {
    "subnet-id": 1,
    "hw-address": "aa:bb:cc:dd:ee:01",
    "ip-address": "10.0.0.5",
    "hostname": "enriched-host",
}


def _own(ip: IPAddress, server: Server) -> None:
    """Link *ip* to the Reservations of *server*, so the Server owns it (ADR 0006)."""
    from netbox_kea.models import IPAMOwnershipLink, next_confirmation_number

    address = IPNetwork(str(ip.address))
    IPAMOwnershipLink.objects.create(
        server=server,
        family=address.version,
        source="reservation",
        ip_address=ip,
        facts={"hostname": "", "prefix_length": address.prefixlen},
        confirmation=next_confirmation_number(),
    )


class TestCombinedReservations4Enrichment(_CombinedViewBase):
    """Combined DHCPv4 reservation view must include the same badge enrichment as per-server."""

    def _url(self):
        return (
            reverse("plugins:netbox_kea:combined_reservations4")
            + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
        )

    def test_active_lease_badge_when_lease_exists(self):
        """A reservation with an active lease must show 'Active Lease' badge."""
        with _reservation_stub(
            4,
            {
                "reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]),
                "lease4-get-by-state": _leases([complete_lease({"ip-address": "10.0.0.5", "state": 0})]),
            },
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Active Lease")

    def test_no_lease_badge_when_no_active_lease(self):
        """A reservation without active lease must show 'No Lease' badge."""
        with _reservation_stub(
            4,
            {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]), "lease4-get-by-state": _leases([])},
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No Lease")

    def test_unknown_lease_badges_when_kea_cannot_confirm_a_missing_lease(self):
        """An incomplete Lease Snapshot shows Lease Unknown; a failed lookup shows no badge."""
        malformed = complete_lease({"ip-address": "10.0.0.9", "state": 0, "hostname": ["private"]})
        for reply, badge in (
            (_leases([malformed]), True),
            ({"result": 1, "text": "lease database error"}, False),
        ):
            with (
                self.subTest(badge=badge),
                with_display_cache_config(leases_ttl=0),
                # The enrichment did not fail as a whole, so each row shows its own result.
                self.assertNoLogs("netbox_kea.views.reservations", "ERROR"),
            ):
                with _reservation_stub(
                    4,
                    {
                        "reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]),
                        "lease4-get-by-state": reply,
                    },
                ):
                    response = self.client.get(self._url())
                self.assertEqual(response.status_code, 200)
                (self.assertContains if badge else self.assertNotContains)(response, ">Lease Unknown</span>")
                self.assertNotContains(response, "No Lease")
                self.assertNotContains(response, "Active Lease")

    def test_lease_column_header_present(self):
        """GlobalReservationTable4 must render a 'Lease' column header."""
        with _reservation_stub(4, {"reservation-get-page": _RES_EMPTY_PAGE}):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertIn("lease_status", response.context["table"].columns.names())

    def test_netbox_ip_synced_link_when_ip_in_netbox(self):
        """The combined table shows aggregate synchronization for the Reservation."""
        _own(IPAddress.objects.create(address="10.0.0.5/32", description="[kea-sync: reservation]"), self.v4_server)
        with _reservation_stub(
            4,
            {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]), "lease4-get-by-state": _leases([])},
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Synchronized 1/1")

    def test_only_a_managed_address_in_the_sync_vrf_counts_as_synchronized(self):
        from ipam.models import VRF

        sync_vrf = VRF.objects.create(name="reservation-sync-vrf")
        self.v4_server.sync_vrf = sync_vrf
        self.v4_server.save()
        IPAddress.objects.create(address="10.0.0.5/32", description="[kea-sync: reservation]")
        other = VRF.objects.create(name="reservation-other-vrf")
        IPAddress.objects.create(address="10.0.0.5/32", vrf=other, description="[kea-sync: reservation]")
        stub = {
            "reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]),
            "lease4-get-by-state": _leases([]),
        }
        with _reservation_stub(4, stub):
            response = self.client.get(self._url())
        self.assertContains(response, "Not Synchronized 0/1")

        synced = IPAddress.objects.create(address="10.0.0.5/32", vrf=sync_vrf, description="[kea-sync: reservation]")
        _own(synced, self.v4_server)
        with _reservation_stub(4, stub):
            response = self.client.get(self._url())
        self.assertContains(response, "Synchronized 1/1")
        self.assertContains(response, f'href="{synced.get_absolute_url()}"')

    def test_an_unreadable_ipam_state_is_unknown(self):
        from django.db import DatabaseError

        stub = {
            "reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]),
            "lease4-get-by-state": _leases([]),
        }
        with (
            _reservation_stub(4, stub),
            patch(
                "netbox_kea.views.reservations.address_ownership",
                autospec=True,
                side_effect=DatabaseError("read failed"),
            ),
            self.assertLogs("netbox_kea.views.reservations", level="ERROR"),
        ):
            response = self.client.get(self._url())

        row = next(iter(response.context["table"].rows)).record
        self.assertEqual(row["sync_state"].code, "unknown")
        self.assertEqual(row["sync_state"].reason, "NetBox IPAM state could not be read.")

    def test_blank_description_row_is_not_synchronized_and_stays_unchanged(self):
        from netbox_kea.models import IPAMOwnershipLink

        ip = IPAddress.objects.create(address="10.0.0.5/32", status="active", description="")
        before_row = IPAddress.objects.values().get(pk=ip.pk)
        before_links = list(IPAMOwnershipLink.objects.filter(ip_address=ip).order_by("pk").values())
        with _reservation_stub(
            4,
            {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]), "lease4-get-by-state": _leases([])},
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<span class="badge text-bg-secondary">Not Synchronized 0/1</span>', html=True)
        self.assertNotContains(response, "Synchronized 1/1")
        row = next(iter(response.context["table"].rows)).record
        self.assertEqual(row["sync_state"].code, "not-synchronized")
        self.assertEqual(IPAddress.objects.values().get(pk=ip.pk), before_row)
        self.assertEqual(list(IPAMOwnershipLink.objects.filter(ip_address=ip).order_by("pk").values()), before_links)

    def test_edit_action_links_use_server_pk(self):
        """Each combined reservation row must have an edit link pointing to the correct server."""
        with _reservation_stub(
            4,
            {"reservation-get-page": _res_page([dict(_MOCK_RESERVATION_ENRICHED)]), "lease4-get-by-state": _leases([])},
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        expected = f"/plugins/kea/servers/{self.v4_server.pk}/reservations4/"
        self.assertContains(response, expected)


# ---------------------------------------------------------------------------
# Badge enrichment parity: DHCPv6 combined views  (issue #10)
# ---------------------------------------------------------------------------


_MOCK_RESERVATION_V6_ENRICHED = {
    "subnet-id": 1,
    "duid": "00:01:aa:bb",
    "ip-addresses": ["2001:db8::5"],
    "hostname": "enriched-host-v6",
}


class TestCombinedReservations6Enrichment(_CombinedViewBase):
    """Combined DHCPv6 reservation view must include the same badge enrichment as DHCPv4."""

    def _url(self):
        return (
            reverse("plugins:netbox_kea:combined_reservations6")
            + f"?server={self.v6_server.pk}&server={self.v4_server.pk}"
        )

    def test_active_lease_badge_when_lease_exists(self):
        """A v6 reservation with an active lease must show 'Active Lease' badge."""
        with _reservation_stub(
            6,
            {
                "reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V6_ENRICHED)]),
                "lease6-get-all": _leases([complete_lease({"ip-address": "2001:db8::5", "state": 0})]),
            },
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Active Lease")

    def test_no_lease_badge_when_no_active_lease(self):
        """A v6 reservation without active lease must show 'No Lease' badge."""
        with _reservation_stub(
            6,
            {
                "reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V6_ENRICHED)]),
                "lease6-get-all": _leases([]),
            },
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No Lease")

    def test_edit_action_links_use_server_pk(self):
        """Each combined v6 reservation row must have an edit link pointing to the correct server."""
        with _reservation_stub(
            6,
            {
                "reservation-get-page": _res_page([dict(_MOCK_RESERVATION_V6_ENRICHED)]),
                "lease6-get-all": _leases([]),
            },
        ):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        expected = f"/plugins/kea/servers/{self.v6_server.pk}/reservations6/"
        self.assertContains(response, expected)


# ---------------------------------------------------------------------------
# Kea config fixture with shared networks
# ---------------------------------------------------------------------------

_MOCK_CONFIG_WITH_SHARED_NET_V4 = [
    {
        "result": 0,
        "arguments": {
            "Dhcp4": {
                "subnet4": [],
                "shared-networks": [
                    {
                        "name": "test-shared-net-v4",
                        "user-context": {"comment": "v4 shared network"},
                        "subnet4": [{"id": 2, "subnet": "10.1.0.0/24"}],
                    }
                ],
            }
        },
    }
]

_MOCK_CONFIG_WITH_SHARED_NET_V6 = [
    {
        "result": 0,
        "arguments": {
            "Dhcp6": {
                "subnet6": [],
                "shared-networks": [
                    {
                        "name": "test-shared-net-v6",
                        "user-context": {"comment": "v6 shared network"},
                        "subnet6": [{"id": 3, "subnet": "2001:db8:1::/48"}],
                    }
                ],
            }
        },
    }
]


# ---------------------------------------------------------------------------
# CombinedSharedNetworks4View  GET /plugins/kea/combined/shared-networks4/
# ---------------------------------------------------------------------------


class TestCombinedSharedNetworks4View(_CombinedViewBase):
    """GET /plugins/kea/combined/shared-networks4/ — DHCPv4 shared networks across all servers."""

    def test_get_returns_200(self):
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V4}):
            url = reverse("plugins:netbox_kea:combined_shared_networks4")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_redirects_to_login(self):
        self.client.logout()
        url = reverse("plugins:netbox_kea:combined_shared_networks4")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_queries_all_v4_servers(self):
        """Without a filter, every dhcp4-enabled server is queried for config-get."""
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V4}) as kea:
            url = reverse("plugins:netbox_kea:combined_shared_networks4")
            self.client.get(url)
        # v4_server + dual_server → at least 2 config-get calls
        self.assertGreaterEqual(kea.commands().count("config-get"), 2)

    def test_unreachable_server_returns_200_with_warning(self):
        with stub_kea({"config-get": requests.ConnectionError("refused")}):
            url = reverse("plugins:netbox_kea:combined_shared_networks4")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_results_include_server_name(self):
        """Shared network rows must include the server name they came from."""
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V4}):
            url = (
                reverse("plugins:netbox_kea:combined_shared_networks4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "v4-server")

    def test_context_active_tab(self):
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V4}):
            url = reverse("plugins:netbox_kea:combined_shared_networks4")
            response = self.client.get(url)
        self.assertEqual(response.context["active_tab"], "shared_networks4")

    def test_shared_network_name_in_response(self):
        """The shared network name must appear in the rendered table."""
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V4}):
            url = (
                reverse("plugins:netbox_kea:combined_shared_networks4")
                + f"?server={self.v4_server.pk}&server={self.v6_server.pk}"
            )
            response = self.client.get(url)
        self.assertContains(response, "test-shared-net-v4")

    def test_export_returns_csv(self):
        """?export=table returns a CSV download of shared network data."""
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V4}):
            url = reverse("plugins:netbox_kea:combined_shared_networks4") + f"?server={self.v4_server.pk}&export=table"
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.get("Content-Type", ""))


# ---------------------------------------------------------------------------
# CombinedSharedNetworks6View  GET /plugins/kea/combined/shared-networks6/
# ---------------------------------------------------------------------------


class TestCombinedSharedNetworks6View(_CombinedViewBase):
    """GET /plugins/kea/combined/shared-networks6/ — DHCPv6 shared networks across all servers."""

    def test_get_returns_200(self):
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V6}):
            url = reverse("plugins:netbox_kea:combined_shared_networks6")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_unauthenticated_redirects_to_login(self):
        self.client.logout()
        url = reverse("plugins:netbox_kea:combined_shared_networks6")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_queries_all_v6_servers(self):
        """Without a filter, every dhcp6-enabled server is queried."""
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V6}) as kea:
            url = reverse("plugins:netbox_kea:combined_shared_networks6")
            self.client.get(url)
        self.assertGreaterEqual(kea.commands().count("config-get"), 2)

    def test_unreachable_server_returns_200_with_warning(self):
        with stub_kea({"config-get": requests.ConnectionError("refused")}):
            url = reverse("plugins:netbox_kea:combined_shared_networks6")
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_context_active_tab(self):
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V6}):
            url = reverse("plugins:netbox_kea:combined_shared_networks6")
            response = self.client.get(url)
        self.assertEqual(response.context["active_tab"], "shared_networks6")

    def test_shared_network_name_in_response(self):
        """The v6 shared network name must appear in the rendered table."""
        with stub_kea({"config-get": _MOCK_CONFIG_WITH_SHARED_NET_V6}):
            url = (
                reverse("plugins:netbox_kea:combined_shared_networks6")
                + f"?server={self.v6_server.pk}&server={self.v4_server.pk}"
            )
            response = self.client.get(url)
        self.assertContains(response, "test-shared-net-v6")
