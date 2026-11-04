# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Subnet and Shared Network lists show the same rows and controls on the Server tab and the combined page."""

import csv
import io
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from users.models import ObjectPermission

from netbox_kea.models import Server

from .kea_stub import _catalogue_responses_for_subnets, stub_kea
from .utils import _make_db_server, _ViewTestBase

_DNS = {"name": "domain-name-servers", "code": 6, "space": "dhcp4", "data": "192.0.2.53", "csv-format": True}
_SUBNETS = [
    {"id": 1, "subnet": "192.0.2.0/24", "pools": [{"pool": "192.0.2.10-192.0.2.20"}], "option-data": [_DNS]},
    {"id": 2, "subnet": "198.51.100.0/24", "pools": []},
]
_STAT = {
    "result": 0,
    "arguments": {
        "result-set": {
            "columns": ["subnet-id", "total-addresses", "assigned-addresses", "declined-addresses"],
            "rows": [[1, 100, 25, 0], [2, 50, 50, 0]],
        }
    },
}
_NETWORK = {"name": "clients", "user-context": {"comment": "Client network"}}


def _responses(*, verified: bool = True) -> dict:
    responses = {
        **_catalogue_responses_for_subnets(4, _SUBNETS, shared_networks=[_NETWORK], members={2: "clients"}),
        "stat-lease4-get": _STAT,
    }
    if not verified:
        responses["subnet4-list"] = {"result": 2, "text": "unknown command 'subnet4-list'"}
    return responses


def _cells(table, server_pk: int, *, record_column: str) -> list[dict[str, tuple[str, list[str]]]]:
    """Return the text and the link paths of each cell of the rows of one Server, without the Server column.

    The record link column keeps its text only: the Server tab links to a Lease search, the combined page to the tab.
    """
    rows = []
    for row in table.rows:
        if row.record["server_pk"] != server_pk:
            continue
        cells = {}
        for column in table.columns:
            if column.name == "server":
                continue
            soup = BeautifulSoup(str(row.get_cell(column.name)), "html.parser")
            links = (
                []
                if column.name == record_column
                else sorted(urlsplit(str(a["href"])).path for a in soup.find_all("a"))
            )
            cells[column.name] = (" ".join(soup.get_text().split()), links)
        rows.append(cells)
    return rows


class _ListParity(_ViewTestBase):
    """One list on the Server tab and on a combined page of two Servers. Subclasses name the routes."""

    server_route: str
    combined_route: str
    record_column: str
    #: The route and arguments of a link that only a user who may change the Server sees.
    change_route: tuple[str, dict]

    def setUp(self):
        super().setUp()
        self.user.is_superuser = False
        self.user.save()
        self.other = _make_db_server(name="other-kea")
        self._grant("view-servers", ["view"])

    def _grant(self, name: str, actions: list[str], constraints: dict | None = None) -> None:
        permission = ObjectPermission.objects.create(name=name, actions=actions, constraints=constraints)
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.user)

    def _pages(self, responses: dict):
        with stub_kea(responses):
            server_tab = self.client.get(
                reverse(f"plugins:netbox_kea:{self.server_route}", kwargs={"pk": self.server.pk, "family": 4})
            )
            combined = self.client.get(reverse(f"plugins:netbox_kea:{self.combined_route}"))
        self.assertEqual(server_tab.status_code, 200)
        self.assertEqual(combined.status_code, 200)
        self.assertEqual(
            {row.record["server_pk"] for row in combined.context["table"].rows}, {self.server.pk, self.other.pk}
        )
        return (
            _cells(server_tab.context["table"], self.server.pk, record_column=self.record_column),
            _cells(combined.context["table"], self.server.pk, record_column=self.record_column),
            _cells(combined.context["table"], self.other.pk, record_column=self.record_column),
        )

    def _assert_parity(self, responses: dict, *, controls: bool) -> list[dict[str, tuple[str, list[str]]]]:
        server_tab, combined, other = self._pages(responses)
        self.assertTrue(server_tab)
        self.assertEqual(server_tab, combined)
        route, kwargs = self.change_route
        change = reverse(f"plugins:netbox_kea:{route}", kwargs={"pk": self.server.pk, "family": 4, **kwargs})
        self.assertEqual(any(change in links for row in server_tab for _text, links in row.values()), controls)
        # The permission on the first Server gives no control on the other Server's rows.
        other_change = reverse(f"plugins:netbox_kea:{route}", kwargs={"pk": self.other.pk, "family": 4, **kwargs})
        self.assertTrue(other)
        self.assertFalse(any(other_change in links for row in other for _text, links in row.values()))
        return server_tab

    def _grant_change(self) -> None:
        # Only the first Server is writable, so the combined page must decide the controls for each Server.
        self._grant("change-one-server", ["change"], {"id": self.server.pk})


class TestSubnetListParity(_ListParity):
    server_route = "server_subnets"
    combined_route = "combined_subnets4"
    record_column = "subnet"
    change_route = ("server_subnet_edit", {"subnet_id": 1})

    def test_a_view_only_user_sees_the_same_rows_without_change_controls(self):
        self._assert_parity(_responses(), controls=False)

    def test_a_change_user_sees_the_same_rows_and_change_controls(self):
        self._grant_change()
        rows = self._assert_parity(_responses(), controls=True)
        self.assertEqual([row["utilization"][0] for row in rows], ["25%", "100%"])

    def test_a_subnet_that_kea_did_not_verify_offers_no_change_on_either_page(self):
        self._grant_change()
        self._assert_parity(_responses(verified=False), controls=False)


class TestSharedNetworkListParity(_ListParity):
    server_route = "server_shared_networks"
    combined_route = "combined_shared_networks4"
    record_column = "name"
    change_route = ("server_shared_network_edit", {"network_name": "clients"})

    def test_a_view_only_user_sees_the_same_rows_without_change_controls(self):
        self._assert_parity(_responses(), controls=False)

    def test_a_change_user_sees_the_same_rows_and_change_controls(self):
        self._grant_change()
        self._assert_parity(_responses(), controls=True)


class TestCombinedChangePermissionRead(_ViewTestBase):
    """A combined list reads the change permission once for the page, not once for each Server."""

    def _query_count(self, route: str) -> int:
        """Return the number of queries of one request."""
        with stub_kea(_responses()), CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse(f"plugins:netbox_kea:{route}"))
        self.assertEqual(response.status_code, 200)
        return len(queries)

    def test_another_server_adds_no_query(self):
        self.user.is_superuser = False
        self.user.save()
        permission = ObjectPermission.objects.create(name="change-servers", actions=["view", "change"])
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.user)
        _make_db_server(name="second-kea")
        for route in ("combined_subnets4", "combined_shared_networks4"):
            with self.subTest(route=route):
                self._query_count(route)
                two = self._query_count(route)
                _make_db_server(name=f"third-kea-{route}")
                self.assertEqual(self._query_count(route), two)


_SUBNET_COLUMNS = ["ID", "Subnet", "Pool(s)", "Utilization", "Options", "Shared Network"]
_NETWORK_COLUMNS = ["Name", "Description", "Subnets", "Subnet CIDRs"]


class TestListExports(_ViewTestBase):
    """Every Subnet and Shared Network list offers Current View (the selected columns) and All Data."""

    # Route, whether it takes the Server pk, table name, selected columns, and one exported row of them.
    _LISTS = (
        ("server_subnets", True, "SubnetTable", ["subnet"], ["192.0.2.0/24"]),
        ("combined_subnets4", False, "GlobalSubnetTable4", ["server", "subnet"], ["test-kea", "192.0.2.0/24"]),
        ("server_shared_networks", True, "SharedNetworkTable", ["name"], ["clients"]),
        ("combined_shared_networks4", False, "GlobalSharedNetworkTable", ["server", "name"], ["test-kea", "clients"]),
    )
    _HEADERS = {
        "subnet": "Subnet",
        "name": "Name",
        "server": "Server",
    }
    _EVERY = {
        "server_subnets": _SUBNET_COLUMNS,
        "combined_subnets4": ["Server", *_SUBNET_COLUMNS],
        "server_shared_networks": _NETWORK_COLUMNS,
        "combined_shared_networks4": ["Server", *_NETWORK_COLUMNS],
    }

    def _url(self, route: str, server_pk: bool) -> str:
        return reverse(f"plugins:netbox_kea:{route}", kwargs={"pk": self.server.pk, "family": 4} if server_pk else {})

    def _csv(self, url: str, export: str) -> list[list[str]]:
        with stub_kea(_responses()):
            response = self.client.get(url, {"export": export})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response["Content-Type"])
        return list(csv.reader(io.StringIO(response.content.decode())))

    def test_current_view_writes_the_selected_columns_and_all_data_every_column(self):
        for route, server_pk, table, columns, row in self._LISTS:
            with self.subTest(route=route):
                self.user.config.set(f"tables.{table}.columns", columns, commit=True)
                url = self._url(route, server_pk)
                header, *rows = self._csv(url, "table")
                self.assertEqual(header, [self._HEADERS[column] for column in columns])
                self.assertIn(row, rows)
                # All Data writes every column, with the selected columns first.
                self.assertCountEqual(self._csv(url, "")[0], self._EVERY[route])

    def test_each_list_links_both_exports_with_its_query(self):
        for route, server_pk, *_rest in self._LISTS:
            with self.subTest(route=route), stub_kea(_responses()):
                response = self.client.get(self._url(route, server_pk), {"per_page": "25"})
                page = BeautifulSoup(response.content, "html.parser")
                links = {
                    link.get_text(strip=True): link["href"] for link in page.select("a.dropdown-item[href*='export']")
                }
                expected = {"Current View": "?per_page=25&export=table", "All Data (CSV)": "?per_page=25&export"}
                self.assertEqual(links, expected)


class TestTableRefreshTargets(_ViewTestBase):
    """Each out-of-band swap of a Server list's table refresh has its target on the page."""

    @staticmethod
    def _oob_selectors(content: bytes) -> list[str]:
        """Return the target selector of each out-of-band element: ``strategy:selector``, or the element's own id."""
        selectors = []
        for element in BeautifulSoup(content, "html.parser").select("[hx-swap-oob]"):
            swap = str(element["hx-swap-oob"])
            selectors.append(swap.split(":", 1)[1] if ":" in swap else f"#{element['id']}")
        return selectors

    def test_each_out_of_band_swap_has_its_target(self):
        for route in ("server_subnets", "server_shared_networks"):
            with self.subTest(route=route), stub_kea(_responses()):
                url = reverse(f"plugins:netbox_kea:{route}", kwargs={"pk": self.server.pk, "family": 4})
                page = BeautifulSoup(self.client.get(url).content, "html.parser")
                selectors = self._oob_selectors(self.client.get(url, {"sort": "-name"}, HTTP_HX_REQUEST="true").content)
                self.assertIn("#list-notice", selectors)
                self.assertEqual([selector for selector in selectors if not page.select(selector)], [])
