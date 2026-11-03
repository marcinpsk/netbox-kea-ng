# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Every Workspace Section keeps one filter set through each scope and family change."""

from urllib.parse import parse_qs, urlsplit

from bs4 import BeautifulSoup
from django.urls import reverse

from netbox_kea.views.workspace import WORKSPACE_SECTIONS

from .kea_stub import _catalogue_responses_for_subnets, _res_page, stub_kea
from .utils import _make_db_server, _ViewTestBase

# The routes of each section, written apart from the registry, so that a wrong registry route fails.
_SERVER_ROUTES = {
    "overview": {4: "server", 6: "server"},
    "leases": {4: "server_leases4", 6: "server_leases6"},
    "subnets": {4: "server_subnets4", 6: "server_subnets6"},
    "shared_networks": {4: "server_shared_networks4", 6: "server_shared_networks6"},
    "reservations": {4: "server_reservations4", 6: "server_reservations6"},
    "configuration": {4: "server_option_def4", 6: "server_option_def6"},
    "options": {4: "server_dhcp4_options_edit", 6: "server_dhcp6_options_edit"},
    "sync": {4: "server_sync_status", 6: "server_sync_status"},
}
# The two routes that serve both families take the family as a query field.
_FAMILY_IN_QUERY = {"server", "server_sync_status"}
_COMBINED_ROUTES = {
    "overview": {4: "combined_overview4", 6: "combined_overview6"},
    "leases": {4: "combined_leases4", 6: "combined_leases6"},
    "subnets": {4: "combined_subnets4", 6: "combined_subnets6"},
    "shared_networks": {4: "combined_shared_networks4", 6: "combined_shared_networks6"},
    "reservations": {4: "combined_reservations4", 6: "combined_reservations6"},
    "configuration": {4: "combined_configuration4", 6: "combined_configuration6"},
    "options": None,
    "sync": {4: "combined_sync4", 6: "combined_sync6"},
}
# The section that a scope change opens: DHCP Options has no combined page.
_SCOPE_SECTION = {"options": "configuration"}

# A table can sort by several columns, so each value of sort stays.
_TABLE = {"sort": ["name", "id"], "per_page": ["25"]}
# The search of each section; a Subnet ID is Subnet-bound.
_SEARCH = {
    "overview": {},
    "leases": {"q": ["printer"], "by": ["hostname"], "state": ["0"]},
    "subnets": {"q": ["198.18"], "subnet_id": ["7"]},
    "shared_networks": {},
    "reservations": {"q": ["printer"], "subnet_id": ["7"], "scope": ["in-subnet"]},
    "configuration": {},
    "options": {},
    "sync": {},
}
_SUBNET_BOUND = {"subnet_id"}
_CIDR = {4: "198.18.0.0/24", 6: "2001:db8::/64"}


def _filters(url: str) -> dict[str, list[str]]:
    """Return the query fields of *url* that are not navigation state."""
    query = parse_qs(urlsplit(url).query)
    for name in ("family", "return_url"):
        query.pop(name, None)
    return query


class TestWorkspaceSectionFilters(_ViewTestBase):
    def setUp(self):
        super().setUp()
        self.target = _make_db_server(name="second-server")

    def _responses(self, family):
        return {
            **_catalogue_responses_for_subnets(family, [{"id": 7, "subnet": _CIDR[family]}]),
            "reservation-get-page": _res_page([]),
            f"stat-lease{family}-get": {"result": 2, "text": f"unknown command 'stat-lease{family}-get'"},
        }

    def _assert_opens(self, url: str, route: str, pk: int, family: int) -> None:
        """Assert that *url* opens *route* of Server *pk* for *family*."""
        parts = urlsplit(url)
        self.assertEqual(parts.path, reverse(f"plugins:netbox_kea:{route}", args=[pk]))
        self.assertEqual(parse_qs(parts.query).get("family"), [str(family)] if route in _FAMILY_IN_QUERY else None)

    def test_every_section_and_family_keeps_its_filters_and_drops_page(self):
        self.assertEqual(set(_SEARCH), set(WORKSPACE_SECTIONS))
        for key in WORKSPACE_SECTIONS:
            scoped = _SCOPE_SECTION.get(key, key)
            for family, other in ((4, 6), (6, 4)):
                query = {**_TABLE, **_SEARCH[key], "page": "2", "unrelated": "drop", "family": str(family)}
                kept = {**_TABLE, **_SEARCH[key]}
                other_family = {name: value for name, value in kept.items() if name not in _SUBNET_BOUND}
                with self.subTest(section=key, family=family):
                    route = _SERVER_ROUTES[key][family]
                    with stub_kea(self._responses(family)):
                        response = self.client.get(reverse(f"plugins:netbox_kea:{route}", args=[self.server.pk]), query)
                    self.assertEqual(response.status_code, 200)
                    shell = BeautifulSoup(response.content, "html.parser").select_one("#kea-workspace-shell")
                    current = shell.select_one('[aria-label="DHCP family"] [aria-current="page"]')
                    self.assertEqual(current.text, f"DHCPv{family}")

                    switches = {link.text: link["href"] for link in shell.select('nav[aria-label="Switch Server"] a')}
                    self.assertEqual(
                        urlsplit(switches["All Servers"]).path,
                        reverse(f"plugins:netbox_kea:{_COMBINED_ROUTES[scoped][family]}"),
                    )
                    self.assertEqual(_filters(switches["All Servers"]), kept)

                    toggle = shell.select('[aria-label="DHCP family"] a')[1 if family == 4 else 0]
                    self._assert_opens(toggle["href"], _SERVER_ROUTES[key][other], self.server.pk, other)
                    self.assertEqual(_filters(toggle["href"]), other_family)

                    # The target confirms Subnet 7, so the switch keeps the Subnet-bound fields too.
                    with stub_kea(self._responses(family)):
                        switched = self.client.get(switches[self.target.name])
                    self.assertEqual(switched.status_code, 302)
                    self._assert_opens(switched.url, _SERVER_ROUTES[scoped][family], self.target.pk, family)
                    self.assertEqual(_filters(switched.url), kept)

                    if _COMBINED_ROUTES[key] is None:
                        self.assertIsNone(WORKSPACE_SECTIONS[key].combined_route)
                        continue
                    combined = reverse(f"plugins:netbox_kea:{_COMBINED_ROUTES[key][family]}")
                    with stub_kea({}) as kea:
                        redirect = self.client.get(combined, {**query, "server": self.server.pk})
                    self.assertEqual(redirect.status_code, 302)
                    self._assert_opens(redirect.url, route, self.server.pk, family)
                    self.assertEqual(_filters(redirect.url), kept)
                    self.assertEqual(kea.commands(), [])

    def test_the_server_switch_opens_the_parent_of_a_subsection_without_a_combined_page(self):
        for key, parent in _SCOPE_SECTION.items():
            with self.subTest(section=key):
                with stub_kea({}) as kea:
                    response = self.client.get(
                        reverse("plugins:netbox_kea:server_switch", args=[self.server.pk]),
                        {"target": self.target.pk, "section": key, "family": "6"},
                    )
                self._assert_opens(response.url, _SERVER_ROUTES[parent][6], self.target.pk, 6)
                self.assertEqual(kea.commands(), [])
