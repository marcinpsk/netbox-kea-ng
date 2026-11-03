# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Every Workspace Section keeps one filter set through each scope and family change."""

from urllib.parse import parse_qs, urlsplit

from bs4 import BeautifulSoup
from django.urls import reverse

from netbox_kea.views.workspace import WORKSPACE_SECTIONS

from .kea_stub import _catalogue_responses_for_subnets, _res_page, stub_kea
from .utils import _make_db_server, _ViewTestBase

_TABLE = {"sort": "name", "per_page": "25"}
# The search of each section, with the values that one test request sends; a Subnet ID is Subnet-bound.
_SEARCH = {
    "overview": {},
    "leases": {"q": "printer", "by": "hostname", "state": "0"},
    "subnets": {"q": "198.18", "subnet_id": "7"},
    "shared_networks": {},
    "reservations": {"q": "printer", "subnet_id": "7", "scope": "in-subnet"},
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

    def test_every_section_and_family_keeps_its_filters_and_drops_page(self):
        self.assertEqual(set(_SEARCH), set(WORKSPACE_SECTIONS))
        for key, section in WORKSPACE_SECTIONS.items():
            for family in (4, 6):
                query = {**_TABLE, **_SEARCH[key], "page": "2", "unrelated": "drop"}
                kept = {name: [value] for name, value in {**_TABLE, **_SEARCH[key]}.items()}
                other_family = {name: value for name, value in kept.items() if name not in _SUBNET_BOUND}
                with self.subTest(section=key, family=family):
                    with stub_kea(self._responses(family)):
                        response = self.client.get(section.server_url(self.server.pk, family), query)
                    self.assertEqual(response.status_code, 200)
                    shell = BeautifulSoup(response.content, "html.parser").select_one("#kea-workspace-shell")
                    switches = {link.text: link["href"] for link in shell.select('nav[aria-label="Switch Server"] a')}
                    self.assertEqual(_filters(switches["All Servers"]), kept)
                    toggle = shell.select('[aria-label="DHCP family"] a')[1 if family == 4 else 0]
                    self.assertEqual(_filters(toggle["href"]), other_family)
                    # The target confirms Subnet 7, so the switch keeps the Subnet-bound fields too.
                    with stub_kea(self._responses(family)):
                        switched = self.client.get(switches[self.target.name])
                    self.assertEqual(switched.status_code, 302)
                    self.assertEqual(_filters(switched.url), kept)
                    if section.combined_route is None:
                        continue
                    with stub_kea({}) as kea:
                        redirect = self.client.get(section.combined_url(family), {"server": self.server.pk, **query})
                    self.assertEqual(redirect.status_code, 302)
                    self.assertEqual(
                        urlsplit(redirect.url).path, urlsplit(section.server_url(self.server.pk, family)).path
                    )
                    self.assertEqual(_filters(redirect.url), kept)
                    self.assertEqual(kea.commands(), [])

    def test_the_server_switch_opens_the_parent_of_a_subsection_without_a_combined_page(self):
        for key, section in WORKSPACE_SECTIONS.items():
            if section.combined_route is not None:
                continue
            with self.subTest(section=key):
                with stub_kea({}) as kea:
                    response = self.client.get(
                        reverse("plugins:netbox_kea:server_switch", args=[self.server.pk]),
                        {"target": self.target.pk, "section": key, "family": "4"},
                    )
                self.assertEqual(
                    urlsplit(response.url).path,
                    urlsplit(WORKSPACE_SECTIONS[section.parent].server_url(self.target.pk, 4)).path,
                )
                self.assertEqual(kea.commands(), [])
