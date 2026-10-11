# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Exercise combined workspace navigation through real requests and templates."""

from urllib.parse import parse_qs, urlsplit

from bs4 import BeautifulSoup
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from users.models import ObjectPermission

from netbox_kea.models import Server

from .kea_stub import stub_kea
from .test_views_sync_jobs import _make_job
from .utils import _make_db_server, _ViewTestBase


class TestCombinedWorkspace(_ViewTestBase):
    def setUp(self):
        super().setUp()
        self.second = _make_db_server(name="second-server")
        self.selection = {"server": [self.server.pk, self.second.pk]}

    def test_overview_has_one_scope_and_family_bar_and_six_sections(self):
        with stub_kea({}) as kea:
            response = self.client.get(reverse("plugins:netbox_kea:combined"), self.selection)
        page = BeautifulSoup(response.content, "html.parser")
        shell = page.select_one("#kea-workspace-shell")
        self.assertIsNotNone(shell)
        self.assertIn("2 Servers selected", shell.get_text())
        self.assertIn("DHCPv4", shell.get_text())
        sections = shell.select('[aria-label="Workspace sections"] a')
        self.assertEqual(
            [link.get_text(strip=True) for link in sections],
            ["Overview", "Leases", "Subnets", "Reservations", "Configuration", "Sync"],
        )
        for link in sections:
            self.assertEqual(
                parse_qs(urlsplit(link["href"]).query), {"server": list(map(str, self.selection["server"]))}
            )
        self.assertEqual(len(shell.select('[aria-label="DHCP family"] a')), 2)
        self.assertEqual(kea.commands(), [])
        self.assertContains(response, "2 Servers selected · Overview · DHCPv4")
        breadcrumb = page.select_one('[aria-label="Breadcrumb"]')
        self.assertIn("2 Servers selected", breadcrumb.get_text())

    def test_valid_lease_family_switch_preserves_search_and_never_reads_kea(self):
        filters = {"q": "printer", "by": "hostname", "state": "0"}
        with stub_kea({}) as kea:
            response = self.client.get(reverse("plugins:netbox_kea:combined_leases4"), {**self.selection, **filters})
            page = BeautifulSoup(response.content, "html.parser")
            link = page.select('[aria-label="DHCP family"] a')[1]
            switched = self.client.get(link["href"])
        self.assertContains(switched, "Choose a Server for DHCPv6 leases")
        self.assertContains(switched, "printer")
        self.assertEqual(
            parse_qs(urlsplit(link["href"]).query),
            {"server": list(map(str, self.selection["server"])), **{key: [value] for key, value in filters.items()}},
        )
        self.assertEqual(kea.commands(), [])

    def test_readonly_configuration_chooses_a_readable_server_page(self):
        self.user.is_superuser = False
        self.user.save()
        permission = ObjectPermission.objects.create(name="workspace-view", actions=["view"])
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.user)
        self.client.force_login(self.user)
        response = self.client.get(reverse("plugins:netbox_kea:combined_configuration4"), self.selection)
        page = BeautifulSoup(response.content, "html.parser")
        links = page.select(".list-group a")
        self.assertEqual(len(links), 2)
        for link in links:
            with stub_kea({"config-get": {"result": 0, "arguments": {"Dhcp4": {}}}}):
                target = self.client.get(link["href"])
            self.assertEqual(target.status_code, 200)

    def test_sync_without_a_recorded_job_shows_unknown_counts(self):
        response = self.client.get(reverse("plugins:netbox_kea:combined_sync4"), self.selection)
        page = BeautifulSoup(response.content, "html.parser")
        rows = page.select(".table tbody tr")
        self.assertEqual(len(rows), 2)
        for row in rows:
            cells = [cell.get_text(strip=True) for cell in row.select("td")]
            self.assertEqual(cells[3:], ["Unknown", "Unknown", "Unknown", "Unknown", "Unknown"])

    def test_job_without_a_summary_keeps_counts_unknown(self):
        _make_job(object_type=ContentType.objects.get_for_model(Server), object_id=self.server.pk, data={})
        response = self.client.get(reverse("plugins:netbox_kea:combined_sync4"), self.selection)
        rows = BeautifulSoup(response.content, "html.parser").select(".table tbody tr")
        for row in rows:
            cells = [cell.get_text(strip=True) for cell in row.select("td")]
            self.assertEqual(cells[3:], ["Unknown", "Unknown", "Unknown", "Unknown", "Unknown"])

    def test_new_sections_report_unsupported_families_and_offer_the_other_family(self):
        Server.objects.filter(pk=self.server.pk).update(dhcp6=False)
        for section in ("overview", "configuration", "sync"):
            response = self.client.get(reverse(f"plugins:netbox_kea:combined_{section}6"), {"server": self.server.pk})
            self.assertContains(response, f"{self.server.name}: DHCPv6 is not enabled on this Server.")
            page = BeautifulSoup(response.content, "html.parser")
            enabled = page.select('[aria-label="DHCP family"] a')[0]
            redirected = self.client.get(enabled["href"])
            self.assertEqual(redirected.status_code, 302)

    def test_family_switch_keeps_selection_section_and_compatible_filters(self):
        for section, filters in (
            ("leases", {"q": "printer", "by": "hostname", "state": "0", "sort": "hostname", "per_page": "25"}),
            ("subnets", {"q": "needle", "subnet_id": "7", "sort": "subnet", "per_page": "25"}),
            (
                "reservations",
                {"q": "printer", "subnet_id": "7", "scope": "global", "sort": "hostname", "per_page": "25"},
            ),
            ("shared_networks", {"sort": "name", "per_page": "25"}),
            ("overview", {}),
            ("configuration", {}),
            ("sync", {}),
        ):
            for family, other in ((4, 6), (6, 4)):
                with self.subTest(section=section, family=family):
                    # An invalid scope still renders navigation and never reads Kea.
                    response = self.client.get(
                        reverse(f"plugins:netbox_kea:combined_{section}{family}"),
                        {"server": ["invalid", ""], **filters, "page": "2", "export": "table", "unrelated": "drop"},
                    )
                    page = BeautifulSoup(response.content, "html.parser")
                    link = page.select('[aria-label="DHCP family"] a')[0 if other == 4 else 1]
                    target = urlsplit(link["href"])
                    self.assertEqual(target.path, reverse(f"plugins:netbox_kea:combined_{section}{other}"))
                    self.assertEqual(
                        parse_qs(target.query, keep_blank_values=True),
                        {"server": ["invalid", ""], **{key: [value] for key, value in filters.items()}},
                    )

    def test_new_sections_honor_object_permissions_and_invalid_selections(self):
        hidden = _make_db_server(name="hidden-server")
        self.user.is_superuser = False
        self.user.save()
        permission = ObjectPermission.objects.create(
            name="workspace-selected-view", actions=["view"], constraints={"pk__in": self.selection["server"]}
        )
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.user)
        self.client.force_login(self.user)
        for section in ("overview", "configuration", "sync"):
            for family in (4, 6):
                url = reverse(f"plugins:netbox_kea:combined_{section}{family}")
                for selection in ({}, self.selection):
                    with self.subTest(section=section, family=family, selection=selection), stub_kea({}) as kea:
                        response = self.client.get(url, selection)
                        self.assertContains(response, self.server.name)
                        self.assertContains(response, self.second.name)
                        self.assertNotContains(response, hidden.name)
                        self.assertTemplateUsed(response, "netbox_kea/inc/combined_notices.html")
                        self.assertEqual(kea.commands(), [])
                for selection in ({"server_selection": "1"}, {"server": [self.server.pk, hidden.pk]}):
                    response = self.client.get(url, selection)
                    self.assertContains(response, "Invalid Server selection")
                    self.assertNotContains(response, hidden.name)
                    self.assertNotContains(response, 'class="table table-striped"')

    def test_configuration_and_sync_single_selection_open_the_canonical_server(self):
        for family in (4, 6):
            for section, target in (
                ("configuration", f"server_option_def{family}"),
                ("sync", "server_sync_status"),
            ):
                response = self.client.get(
                    reverse(f"plugins:netbox_kea:combined_{section}{family}"),
                    {"server": self.server.pk, "page": "2", "q": "drop", "export": "table"},
                )
                self.assertRedirects(
                    response,
                    reverse(f"plugins:netbox_kea:{target}", args=[self.server.pk])
                    + (f"?family={family}" if section == "sync" else ""),
                    fetch_redirect_response=False,
                )

    def test_sync_keeps_each_servers_result_and_real_zero_counts(self):
        hidden = _make_db_server(name="unselected-server")
        _make_job(
            data={
                "summary": [
                    {"pk": self.server.pk, "created": 0, "updated": 7, "errors": 0},
                    {"pk": self.second.pk, "created": 2, "updated": 3, "errors": 1, "conflicts": 4},
                    {"pk": hidden.pk, "created": 9999, "updated": 9999, "errors": 9999},
                ]
            }
        )
        response = self.client.get(reverse("plugins:netbox_kea:combined_sync6"), self.selection)
        rows = BeautifulSoup(response.content, "html.parser").select(".table tbody tr")
        counts = {
            row.select_one("td").get_text(strip=True): [cell.get_text(strip=True) for cell in row.select("td")[3:]]
            for row in rows
        }
        self.assertEqual(
            counts,
            {
                self.server.name: ["0", "7", "0", "Unknown", "Unknown"],
                self.second.name: ["2", "3", "1", "Unknown", "4"],
            },
        )
        self.assertNotContains(response, "9999")

    def test_sync_reports_prefix_and_range_failures_separately_from_address_failures(self):
        job = _make_job(data={"summary": [{"pk": self.server.pk, "errors": 0, "prefix_errors": 1}]})
        job.status = "failed"
        job.save(update_fields=["status"])
        response = self.client.get(reverse("plugins:netbox_kea:combined_sync4"), self.selection)
        table = BeautifulSoup(response.content, "html.parser").select_one(".table")
        headings = [cell.get_text(strip=True) for cell in table.select("thead th")]
        self.assertIn("Address Errors", headings)
        self.assertIn("Prefix/Range Errors", headings)
        row = next(
            row for row in table.select("tbody tr") if row.select_one("td").get_text(strip=True) == self.server.name
        )
        cells = [cell.get_text(strip=True) for cell in row.select("td")]
        self.assertEqual(cells[headings.index("Address Errors")], "0")
        self.assertEqual(cells[headings.index("Prefix/Range Errors")], "1")

    def test_shared_networks_are_a_subsection_of_subnets(self):
        response = self.client.get(reverse("plugins:netbox_kea:combined_shared_networks6"), {"server": "invalid"})
        page = BeautifulSoup(response.content, "html.parser")
        self.assertEqual(page.select_one('[aria-label="Workspace sections"] a.active').get_text(strip=True), "Subnets")
        self.assertEqual(
            page.select_one('[aria-label="Subnet subsections"] a.active').get_text(strip=True), "Shared Networks"
        )
