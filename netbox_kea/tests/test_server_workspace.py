# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Exercise the Server workspace through real requests and rendered navigation."""

from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests
from bs4 import BeautifulSoup
from django.contrib.contenttypes.models import ContentType
from django.contrib.messages import get_messages
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from users.models import ObjectPermission

from netbox_kea.models import Server

from .kea_stub import LeaseDaemon, _catalogue_responses_for_subnets, stub_kea
from .test_views_server import _status_stub
from .utils import _make_db_server, _ViewTestBase


class TestServerWorkspace(_ViewTestBase):
    def test_dhcp_controls_keep_the_route_family_on_success_and_error_redirects(self):
        for action in ("enable", "disable"):
            for result in ({"result": 0}, requests.ConnectionError("Unavailable")):
                with self.subTest(action=action, result=result), stub_kea({f"dhcp-{action}": result}) as kea:
                    response = self.client.post(
                        reverse(f"plugins:netbox_kea:server_dhcp6_{action}", args=[self.server.pk]),
                        {"confirm": "1", "max_period": 300},
                    )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(parse_qs(urlsplit(response.url).query).get("family"), ["6"])
                destination = BeautifulSoup(self.client.get(response.url).content, "html.parser")
                self.assertEqual(
                    destination.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6"
                )
                self.assertEqual(kea.commands(), [f"dhcp-{action}"])

    def test_sync_controls_keep_family_from_emitted_form_actions_through_redirects(self):
        from core.models import Job

        page = BeautifulSoup(
            self.client.get(
                reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk]), {"family": 6}
            ).content,
            "html.parser",
        )
        paths = {
            reverse(f"plugins:netbox_kea:server_sync_{action}", args=[self.server.pk]) for action in ("now", "toggle")
        }
        controls = [form for form in page.select('form[method="post"]') if urlsplit(form["action"]).path in paths]
        self.assertEqual(len(controls), 2)
        for form in controls:
            with self.subTest(action=form["action"]), stub_kea({}) as kea:
                jobs_before = Job.objects.filter(object_id=self.server.pk).count()
                response = self.client.post(form["action"])
                if "sync-now" in form["action"]:
                    self.assertEqual(Job.objects.filter(object_id=self.server.pk).count(), jobs_before + 1)
                    self.assertTrue(
                        any("Sync job enqueued" in str(message) for message in get_messages(response.wsgi_request))
                    )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(parse_qs(urlsplit(form["action"]).query).get("family"), ["6"])
                self.assertEqual(parse_qs(urlsplit(response.url).query).get("family"), ["6"])
                destination = BeautifulSoup(self.client.get(response.url).content, "html.parser")
                self.assertEqual(
                    destination.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6"
                )
                self.assertEqual(kea.commands(), [])

    def test_native_object_tab_links_keep_family_through_the_leases_return_link(self):
        with stub_kea(_catalogue_responses_for_subnets(6, [])):
            response = self.client.get(reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk]))
        page = BeautifulSoup(response.content, "html.parser")
        tabs = page.select('[aria-label="Server object tabs"] a')
        self.assertTrue(tabs)
        for tab in tabs:
            with self.subTest(label=tab.text.strip()), stub_kea({}) as kea:
                target = tab["href"]
                self.assertEqual(parse_qs(urlsplit(target).query).get("family"), ["6"])
                destination = self.client.get(target)
                destination_page = BeautifulSoup(destination.content, "html.parser")
                leases = next(
                    link
                    for link in destination_page.select('[aria-label="Workspace sections"] a')
                    if link.text == "Leases"
                )
                self.assertEqual(
                    urlsplit(leases["href"]).path,
                    reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk]),
                )
                self.assertEqual(kea.commands(), [])
            with stub_kea(_catalogue_responses_for_subnets(6, [])):
                returned = self.client.get(leases["href"])
            returned_page = BeautifulSoup(returned.content, "html.parser")
            self.assertEqual(returned.status_code, 200)
            self.assertEqual(
                returned_page.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6"
            )

    def test_sync_override_configuration_link_retains_the_selected_family(self):
        url = reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk])
        with stub_kea({}) as kea:
            response = self.client.get(url, {"family": 6})
        page = BeautifulSoup(response.content, "html.parser")
        override = next(node for node in page.select("p") if "Server overrides" in node.text)
        target = override.select_one("a")["href"]
        self.assertEqual(urlsplit(target).path, reverse("plugins:netbox_kea:server_edit", args=[self.server.pk]))
        self.assertEqual(parse_qs(urlsplit(target).query).get("family"), ["6"])
        form = BeautifulSoup(self.client.get(target).content, "html.parser")
        self.assertEqual(form.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6")
        self.assertEqual(kea.commands(), [])

    def test_htmx_lease_search_refreshes_the_family_switch_with_current_filters(self):
        responses = {
            **_catalogue_responses_for_subnets(4, []),
            "lease4-get-by-hostname": {"result": 0, "arguments": {"leases": []}},
        }
        with stub_kea(responses):
            response = self.client.get(
                reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]),
                {"q": "printer", "by": "hostname"},
                HTTP_HX_REQUEST="true",
            )
        page = BeautifulSoup(response.content, "html.parser")
        shell = page.select_one('#kea-workspace-shell[hx-swap-oob="true"]')
        self.assertIsNotNone(shell)
        target = shell.select('[aria-label="DHCP family"] a')[1]
        self.assertEqual(parse_qs(urlsplit(target["href"]).query), {"q": ["printer"], "by": ["hostname"]})
        self.assertIsNotNone(page.select_one("#lease-search"))
        self.assertIsNone(page.select_one("html"))

    def test_combined_overview_and_sync_handoff_preserves_requested_family(self):
        for section, target in (("overview", "server"), ("sync", "server_sync_status")):
            with self.subTest(section=section):
                response = self.client.get(
                    reverse(f"plugins:netbox_kea:combined_{section}6"), {"server": self.server.pk}
                )
                self.assertRedirects(
                    response,
                    reverse(f"plugins:netbox_kea:{target}", args=[self.server.pk]) + "?family=6",
                    fetch_redirect_response=False,
                )

    def test_status_partial_shows_failed_and_incomplete_configuration_notices_inline(self):
        self.server.dhcp6 = False
        self.server.save()
        partial = _catalogue_responses_for_subnets(
            4, [], global_options=({"code": 15, "name": "domain-name", "data": "example.invalid"}, {"data": "x"})
        )["config-get"]
        for config, marker in (
            (requests.ConnectionError("Unavailable"), "Failed to load the Server Configuration from Kea."),
            (partial, "Kea returned an invalid DHCP Option."),
        ):
            with self.subTest(marker=marker), _status_stub(**{"config-get": config}):
                response = self.client.get(
                    reverse("plugins:netbox_kea:server_status_data", args=[self.server.pk]), HTTP_HX_REQUEST="true"
                )
            self.assertContains(response, marker)
            self.assertContains(response, 'role="alert"')
            self.assertNotContains(response, "kea-workspace-shell")
            self.assertEqual(list(get_messages(response.wsgi_request)), [])

    @override_settings(LOGIN_REQUIRED=False, EXEMPT_VIEW_PERMISSIONS=["netbox_kea.server"])
    def test_permitted_anonymous_reader_sees_disabled_family_without_kea_requests(self):
        self.server.dhcp6 = False
        self.server.save()
        self.client.logout()
        for route in ("server_subnets6", "server_leases6", "server_reservations6", "server_option_def6"):
            with self.subTest(route=route), stub_kea({}) as kea:
                response = self.client.get(reverse(f"plugins:netbox_kea:{route}", args=[self.server.pk]))
                self.assertContains(response, "Protocol not enabled")
                self.assertEqual(kea.commands(), [])

    def test_valid_lease_creation_cannot_write_a_disabled_family(self):
        payload = {
            "ip_address": "2001:db8::1",
            "duid": "00:01:00:01:01:02:03:04:05:06",
            "iaid": 1,
            "subnet_id": 7,
            "valid_lft": 3600,
            "preferred_lft": 1800,
            "type": "IA_NA",
        }
        url = reverse("plugins:netbox_kea:server_lease6_add", args=[self.server.pk])
        daemon = LeaseDaemon(6, subnet_id=7)
        responses = {
            **_catalogue_responses_for_subnets(6, [{"id": 7, "subnet": "2001:db8::/64"}]),
            **daemon.responses(),
        }
        with stub_kea(responses) as kea:
            enabled = self.client.post(url, payload)
        self.assertEqual(enabled.status_code, 302)
        self.assertIn("lease6-add", kea.commands())
        self.assertIsNotNone(daemon.lease("2001:db8::1"))
        self.server.dhcp6 = False
        self.server.save()
        with stub_kea({}) as kea:
            response = self.client.post(url, payload)
        self.assertContains(response, "Protocol not enabled")
        self.assertEqual(kea.commands(), [])

    def test_native_delete_modal_contains_scope_and_keeps_selected_family_on_submission(self):
        url = reverse("plugins:netbox_kea:server_delete", args=[self.server.pk]) + "?family=6"
        with stub_kea({}) as kea:
            response = self.client.get(url, HTTP_HX_REQUEST="true")
        page = BeautifulSoup(response.content, "html.parser")
        form = page.select_one("form")
        self.assertIsNotNone(form.select_one("#kea-modal-workspace-shell"))
        self.assertEqual(form.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6")
        self.assertEqual(parse_qs(urlsplit(form["action"]).query).get("family"), ["6"])
        self.assertEqual(kea.commands(), [])

    def test_native_delete_modal_preserves_native_permission_and_object_constraints(self):
        self.user.is_superuser = False
        self.user.save()
        self.client.force_login(self.user)
        url = reverse("plugins:netbox_kea:server_delete", args=[self.server.pk]) + "?family=6"
        with stub_kea({}) as kea:
            denied = self.client.get(url, HTTP_HX_REQUEST="true")
        self.assertEqual(denied.status_code, 403)
        self.assertNotContains(denied, "kea-modal-workspace-shell", status_code=403)
        self.assertEqual(kea.commands(), [])
        hidden = _make_db_server(name="hidden-server")
        permission = ObjectPermission.objects.create(
            name="server-delete-scope", actions=["delete"], constraints={"pk": hidden.pk}
        )
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.user)
        self.client.force_login(self.user)
        with stub_kea({}) as kea:
            restricted = self.client.get(url, HTTP_HX_REQUEST="true")
        self.assertEqual(restricted.status_code, 404)
        self.assertNotContains(restricted, "kea-modal-workspace-shell", status_code=404)
        self.assertEqual(kea.commands(), [])

    def test_native_edit_and_delete_links_keep_the_family_of_the_server_section(self):
        with stub_kea(_catalogue_responses_for_subnets(6, [])):
            response = self.client.get(reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk]))
        page = BeautifulSoup(response.content, "html.parser")
        for action in ("edit", "delete"):
            path = reverse(f"plugins:netbox_kea:server_{action}", args=[self.server.pk])
            link = next(
                link for link in page.select("a[href]") if urlsplit(link.get("hx-get", link["href"])).path == path
            )
            target = link.get("hx-get", link["href"])
            self.assertEqual(parse_qs(urlsplit(target).query).get("family"), ["6"])
            form = BeautifulSoup(self.client.get(target).content, "html.parser")
            self.assertEqual(form.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6")

    def test_extra_object_tabs_render_the_workspace_without_reading_kea(self):
        for section in ("journal", "changelog", "jobs"):
            with self.subTest(section=section), stub_kea({}) as kea:
                response = self.client.get(
                    reverse(f"plugins:netbox_kea:server_{section}", args=[self.server.pk]), {"family": 6}
                )
                page = BeautifulSoup(response.content, "html.parser")
                self.assertContains(response, self.server.name)
                self.assertIsNotNone(page.select_one("#kea-workspace-shell"))
                self.assertEqual(page.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6")
                self.assertEqual(kea.commands(), [])

    def test_disabled_family_honors_view_and_change_object_constraints(self):
        hidden = _make_db_server(name="hidden-server", dhcp6=False)
        self.server.dhcp6 = False
        self.server.save()
        self.user.is_superuser = False
        self.user.save()
        for action, constraints in (("view", {"pk": self.server.pk}), ("change", {"pk": hidden.pk})):
            permission = ObjectPermission.objects.create(
                name=f"workspace-{action}", actions=[action], constraints=constraints
            )
            permission.object_types.add(ContentType.objects.get_for_model(Server))
            permission.users.add(self.user)
        self.client.force_login(self.user)
        for route, method in (("server_leases6", "get"), ("server_lease6_add", "get"), ("server_lease6_add", "post")):
            with self.subTest(route=route, method=method), stub_kea({}) as kea:
                forbidden = getattr(self.client, method)(reverse(f"plugins:netbox_kea:{route}", args=[hidden.pk]))
                self.assertEqual(forbidden.status_code, 404)
                self.assertNotIn(hidden.name, forbidden.content.decode())
                if "add" in route:
                    refusal = getattr(self.client, method)(
                        reverse(f"plugins:netbox_kea:{route}", args=[self.server.pk])
                    )
                    self.assertEqual(refusal.status_code, 403)
                    self.assertNotIn("Protocol not enabled", refusal.content.decode())
                self.assertEqual(kea.commands(), [])

    def test_enabled_mutation_forms_render_the_parent_section_and_one_family_switch(self):
        for family in (4, 6):
            for route, section in (
                ("lease{family}_add", "Leases"),
                ("lease{family}_bulk_import", "Leases"),
                ("reservation{family}_bulk_import", "Reservations"),
                ("subnet{family}_add", "Subnets"),
                ("shared_network{family}_add", "Subnets"),
                ("dhcp{family}_enable", "Overview"),
                ("dhcp{family}_disable", "Overview"),
                ("dhcp{family}_options_edit", "Configuration"),
                ("option_def{family}_add", "Configuration"),
            ):
                with self.subTest(family=family, route=route), stub_kea(_catalogue_responses_for_subnets(family, [])):
                    response = self.client.get(
                        reverse("plugins:netbox_kea:server_" + route.format(family=family), args=[self.server.pk])
                    )
                page = BeautifulSoup(response.content, "html.parser")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    page.select_one('[aria-label="Workspace sections"] [aria-current="page"]').text, section
                )
                self.assertEqual(len(page.select('[aria-label="DHCP family"]')), 1)
                self.assertEqual(
                    page.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, f"DHCPv{family}"
                )

    def test_overview_and_sync_show_explicit_disabled_query_family(self):
        self.server.dhcp6 = False
        self.server.save()
        for route in ("server", "server_sync_status"):
            with self.subTest(route=route), stub_kea({}) as kea:
                response = self.client.get(reverse(f"plugins:netbox_kea:{route}", args=[self.server.pk]), {"family": 6})
                self.assertContains(response, "Protocol not enabled")
                page = BeautifulSoup(response.content, "html.parser")
                target = page.select_one("#kea-protocol-disabled a")
                self.assertEqual(
                    target["href"], reverse(f"plugins:netbox_kea:{route}", args=[self.server.pk]) + "?family=4"
                )
                self.assertEqual(kea.commands(), [])

    def test_family_switch_preserves_lease_filters_and_drops_cursor_and_exports(self):
        with stub_kea(_catalogue_responses_for_subnets(4, [])):
            response = self.client.get(
                reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]),
                {"q": "printer", "by": "hostname", "state": "0", "page": "2", "per_page": "25"},
            )
        page = BeautifulSoup(response.content, "html.parser")
        target = page.select('[aria-label="DHCP family"] a')[1]
        self.assertIn("q=printer", target["href"])
        self.assertIn("by=hostname", target["href"])
        self.assertIn("state=0", target["href"])
        self.assertIn("per_page=25", target["href"])
        self.assertNotIn("page", parse_qs(urlsplit(target["href"]).query))

    def test_native_edit_and_delete_keep_family_and_style_above_form_tabs(self):
        for action in ("edit", "delete"):
            response = self.client.get(
                reverse(f"plugins:netbox_kea:server_{action}", args=[self.server.pk]), {"family": 6}
            )
            page = BeautifulSoup(response.content, "html.parser")
            shell = page.select_one("#kea-workspace-shell")
            self.assertIsNotNone(shell)
            self.assertEqual(shell.select_one('[aria-label="DHCP family"] [aria-current="page"]').text, "DHCPv6")
            self.assertIsNotNone(page.select_one('link[href$="netbox_kea/css/workspace.css"]'))
            if action == "edit":
                self.assertGreater(
                    response.content.find(b'id="edit-form-tab"'), response.content.find(b"kea-workspace-shell")
                )

    def test_disabled_family_preserves_action_permission_refusals(self):
        self.server.dhcp6 = False
        self.server.save()
        self.user.is_superuser = False
        self.user.save()
        permission = ObjectPermission.objects.create(
            name="workspace-view", actions=["view"], constraints={"pk": self.server.pk}
        )
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.user)
        self.client.force_login(self.user)
        for name, data in (
            ("server_leases6_delete", {}),
            ("server_reservation6_bulk_sync", {}),
        ):
            with self.subTest(name=name), stub_kea({}) as kea:
                response = self.client.post(reverse(f"plugins:netbox_kea:{name}", args=[self.server.pk]), data)
                self.assertEqual(response.status_code, 403)
                self.assertNotContains(response, "Protocol not enabled", status_code=403)
                self.assertEqual(kea.commands(), [])

    def test_disabled_family_refuses_sections_and_mutations_without_kea_requests(self):
        routes = (
            ("leases{family}", {}),
            ("reservations{family}", {}),
            ("subnets{family}", {}),
            ("shared_networks{family}", {}),
            ("option_def{family}", {}),
            ("lease{family}_add", {}),
            ("lease{family}_edit", {"ip_address": "2001:db8::1"}),
            ("leases{family}_delete", {}),
            ("lease{family}_sync", {}),
            ("lease{family}_bulk_import", {}),
            ("reservation{family}_add", {}),
            ("reservation{family}_edit", {"subnet_id": 7}),
            ("reservation{family}_delete", {"subnet_id": 7}),
            ("reservation{family}_sync", {"subnet_id": 7}),
            ("reservation{family}_bulk_sync", {}),
            ("reservation{family}_bulk_import", {}),
            ("reservation{family}_published_name", {}),
            ("subnet{family}_add", {}),
            ("subnet{family}_edit", {"subnet_id": 7}),
            ("subnet{family}_delete", {"subnet_id": 7}),
            ("subnet{family}_wipe_leases", {"subnet_id": 7}),
            ("subnet{family}_pool_add", {"subnet_id": 7}),
            ("subnet{family}_pool_delete", {"subnet_id": 7, "pool": "2001:db8::/120"}),
            ("subnet{family}_options_edit", {"subnet_id": 7}),
            ("shared_network{family}_add", {}),
            ("shared_network{family}_edit", {"network_name": "example-network"}),
            ("shared_network{family}_delete", {"network_name": "example-network"}),
            ("dhcp{family}_enable", {}),
            ("dhcp{family}_disable", {}),
            ("dhcp{family}_options_edit", {}),
            ("option_def{family}_add", {}),
            ("option_def{family}_delete", {"code": 222, "space": "example-space"}),
        )
        for family in (4, 6):
            self.server.dhcp4, self.server.dhcp6 = family != 4, family != 6
            self.server.save()
            for name, arguments in routes:
                url = reverse(
                    "plugins:netbox_kea:server_" + name.format(family=family),
                    kwargs={"pk": self.server.pk, **arguments},
                )
                for method in ("get", "post"):
                    with self.subTest(family=family, route=name, method=method), stub_kea({}) as kea:
                        response = getattr(self.client, method)(url)
                        self.assertContains(response, "Protocol not enabled")
                        page = BeautifulSoup(response.content, "html.parser")
                        self.assertIsNotNone(page.select_one("#kea-protocol-disabled"))
                        self.assertIn(self.server.name, page.select_one("#kea-workspace-shell").get_text())
                        self.assertEqual(kea.commands(), [])

    def test_overview_has_shared_navigation_and_loads_daemon_status_with_htmx(self):
        with stub_kea({}) as kea:
            response = self.client.get(self.server.get_absolute_url())
        page = BeautifulSoup(response.content, "html.parser")
        shell = page.select_one("#kea-workspace-shell")
        self.assertIsNotNone(shell)
        self.assertIn(self.server.name, shell.get_text())
        self.assertEqual(
            [link.get_text(strip=True) for link in shell.select('[aria-label="Workspace sections"] a')],
            ["Overview", "Leases", "Subnets", "Reservations", "Configuration", "Sync"],
        )
        self.assertEqual(len(shell.select('[aria-label="DHCP family"] a')), 2)
        status = page.select_one("#kea-server-status")
        self.assertEqual(status["hx-trigger"], "load")
        self.assertEqual(kea.commands(), [])
        tabs = [link.get_text(strip=True) for link in page.select('[aria-label="Server object tabs"] a')]
        self.assertIn("Journal", tabs)
        self.assertIn("Changelog", tabs)
        self.assertIn("Jobs", tabs)
        self.assertNotIn("Status", tabs)
        self.assertTrue(set(tabs).isdisjoint({"Leases", "Subnets", "Reservations", "Configuration", "Sync"}))
        self.assertEqual(len(page.select('[aria-label="DHCP family"]')), 1)
        self.assertEqual(len(page.select('[aria-label="Workspace sections"]')), 1)

    def test_legacy_status_redirects_to_overview_without_reading_kea(self):
        with stub_kea({}) as kea:
            response = self.client.get(reverse("plugins:netbox_kea:server_status", args=[self.server.pk]))
        self.assertRedirects(response, self.server.get_absolute_url(), fetch_redirect_response=False)
        self.assertEqual(kea.commands(), [])


class TestWorkspaceTabRow(_ViewTestBase):
    """Native object tabs share the workspace tab row, and DHCP Plugin is a Sync subsection."""

    def _page(self, name: str, **query) -> BeautifulSoup:
        with stub_kea({}) as kea:
            response = self.client.get(reverse(f"plugins:netbox_kea:{name}", args=[self.server.pk]), query)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands(), [])
        return BeautifulSoup(response.content, "html.parser")

    def test_native_tabs_are_at_the_end_of_the_workspace_tab_row(self):
        page = self._page("server_sync_status", family=4)
        shell = page.select_one("#kea-workspace-shell")
        object_tabs = shell.select_one('[aria-label="Server object tabs"]')
        self.assertIs(object_tabs.parent, shell.select_one('[aria-label="Workspace sections"]').parent)
        self.assertIsNone(object_tabs.find_next_sibling())
        labels = [" ".join(a.get_text().split()) for a in object_tabs.select("a")]
        self.assertEqual([label.split()[0] for label in labels], ["Journal", "Changelog", "Jobs"])
        # One row: no tab list outside the workspace shell above the page content.
        self.assertEqual(len(page.select('[aria-label="Server object tabs"]')), 1)
        for link in object_tabs.select("a"):
            self.assertEqual(parse_qs(urlsplit(link["href"]).query)["family"], ["4"])

    def test_a_native_tab_page_marks_only_its_own_tab_current(self):
        page = self._page("server_journal", family=4)
        self.assertEqual(page.select('[aria-label="Workspace sections"] [aria-current="page"]'), [])
        current = page.select('[aria-label="Server object tabs"] [aria-current="page"]')
        self.assertEqual([a.get_text().split()[0] for a in current], ["Journal"])

    def test_the_dhcp_plugin_subsection_follows_the_import_enable_rule(self):
        from netbox_kea.views import dhcp_plugin_sync

        for available, enabled, shown in ((True, True, True), (True, False, False), (False, True, False)):
            with self.subTest(available=available, enabled=enabled):
                self.server.sync_dhcp_plugin_enabled = enabled
                self.server.save()
                with patch.object(dhcp_plugin_sync.dhcp_plugin, "is_available", return_value=available, autospec=True):
                    page = self._page("server_sync_status", family=4)
                subsections = [a.get_text() for a in page.select('[aria-label="Sync subsections"] a')]
                self.assertEqual(subsections, ["IPAM", "DHCP Plugin"] if shown else [])
                self.assertNotIn("DHCP Plugin", page.select_one('[aria-label="Server object tabs"]').get_text())
                if shown:
                    current = page.select('[aria-label="Sync subsections"] [aria-current="page"]')
                    self.assertEqual([a.get_text() for a in current], ["IPAM"])

    def test_the_dhcp_plugin_page_keeps_sync_current_without_the_plugin(self):
        from netbox_kea.views import dhcp_plugin_sync

        with patch.object(dhcp_plugin_sync.dhcp_plugin, "is_available", return_value=False, autospec=True):
            page = self._page("server_dhcp_plugin", family=4)
        current = page.select('[aria-label="Workspace sections"] [aria-current="page"]')
        self.assertEqual([a.get_text() for a in current], ["Sync"])
        self.assertIn("is not installed", page.get_text())

    def test_the_recent_runs_header_spaces_its_link_with_flex(self):
        header = next(
            h
            for h in self._page("server_sync_status", family=4).select(".card-header")
            if "Recent Runs" in h.get_text()
        )
        # NetBox makes a card header a flex container, where float-end has no effect.
        self.assertTrue({"d-flex", "justify-content-between"} <= set(header["class"]))
        self.assertNotIn("float-end", header.a["class"])


class TestCardHeaderBadges(SimpleTestCase):
    """A card header with a badge keeps a gap to the badge and wraps it below the title on a narrow screen."""

    def test_each_header_badge_has_a_gap_and_wraps(self):
        templates = Path(__file__).resolve().parents[1] / "templates"
        checked = 0
        for template in sorted(templates.rglob("*.html")):
            for header in BeautifulSoup(template.read_text(), "html.parser").select(".card-header"):
                for badge in header.select(".badge"):
                    checked += 1
                    with self.subTest(template=template.name, badge=badge.get_text(" ", strip=True)):
                        self.assertTrue({"flex-wrap", "gap-2"} <= set(header["class"]))
                        # A data badge (a CIDR, an address, a name) can be longer than the card is wide.
                        if "font-monospace" in badge["class"]:
                            self.assertTrue({"text-wrap", "text-break"} <= set(badge["class"]))
        self.assertGreaterEqual(checked, 6)
