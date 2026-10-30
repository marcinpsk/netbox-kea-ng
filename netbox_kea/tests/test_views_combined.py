# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""View tests for netbox_kea plugin.

Also contains pure-Python unit tests for helper functions defined in views.py
(e.g. ``_extract_identifier``), which do not require a database but live here
because they are tightly coupled to view logic.

These tests drive the **real** ``KeaClient``; only the HTTP boundary is stubbed
via ``kea_stub.stub_kea``, so the combined multi-server fetch helpers exercise the
real request/response path.
"""

import threading
from enum import Enum
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
from bs4 import BeautifulSoup
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.urls import clear_script_prefix, reverse, set_script_prefix
from users.models import ObjectPermission

from netbox_kea.models import Server
from netbox_kea.views.notices import HEADLINES
from netbox_kea.views.reservations import _RESERVATION_PAGE_SIZE, ReservationQuery, fetch

from .kea_stub import (
    _catalogue_responses,
    _catalogue_responses_for_subnets,
    _res_page,
    queued,
    stub_kea,
)
from .utils import _make_db_server, _ViewTestBase, with_display_cache_config, with_kea_client_config

# ---------------------------------------------------------------------------
# Lease Server chooser
# ---------------------------------------------------------------------------


class TestLeaseServerChooser(_ViewTestBase):
    def test_chooser_never_reads_leases_even_with_search_state(self):
        for family in (4, 6):
            for search in (
                {},
                {"q": "198.18.0.1" if family == 4 else "2001:db8::1", "by": "ip", "state": "0"},
                {"state": "0"},
            ):
                with self.subTest(family=family, search=search), stub_kea({}) as kea:
                    response = self.client.get(reverse(f"plugins:netbox_kea:combined_leases{family}"), search)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(kea.commands(), [])
                    self.assertContains(
                        response, reverse(f"plugins:netbox_kea:server_leases{family}", args=[self.server.pk])
                    )

    def test_search_state_is_explained_and_carried_to_each_server(self):
        second = _make_db_server(name="another-server")
        search = {"q": '<script>" & host</script>', "by": "unvalidated-selector", "state": "unknown"}
        for family in (4, 6):
            for selection in ({}, {"server": [self.server.pk, second.pk]}):
                with self.subTest(family=family, selection=selection), stub_kea({}) as kea:
                    response = self.client.get(
                        reverse(f"plugins:netbox_kea:combined_leases{family}"),
                        {**selection, **search, "page": "2", "export": "table", "unrelated": "drop"},
                    )
                    self.assertEqual(response.status_code, 200)
                    page = BeautifulSoup(response.content, "html.parser")
                    explanation = page.select_one(".alert-info")
                    self.assertIsNotNone(explanation)
                    self.assertIn(search["q"], explanation.get_text())
                    self.assertIn("Choose a Server", explanation.get_text())
                    self.assertNotContains(response, '<script>" & host</script>')
                    links = page.select(".list-group a")
                    self.assertEqual([link.get_text(strip=True) for link in links], [second.name, self.server.name])
                    for server, link in zip((second, self.server), links, strict=True):
                        target = urlsplit(link["href"])
                        self.assertEqual(
                            target.path, reverse(f"plugins:netbox_kea:server_leases{family}", args=[server.pk])
                        )
                        query = parse_qs(target.query)
                        self.assertEqual(query.pop("return_url"), [response.wsgi_request.get_full_path()])
                        self.assertEqual(query, {key: [value] for key, value in search.items()})
                    self.assertEqual(page.select('a[href*="export="]'), [])
                    self.assertEqual(kea.commands(), [])

    def test_one_server_redirect_ignores_export_and_keeps_compatible_fields(self):
        search = {"q": "host & spaces", "by": "hostname", "state": "1", "sort": "-hostname", "per_page": "50"}
        for family in (4, 6):
            for htmx in (False, True):
                with self.subTest(family=family, htmx=htmx), stub_kea({}) as kea:
                    response = self.client.get(
                        reverse(f"plugins:netbox_kea:combined_leases{family}"),
                        {"server": self.server.pk, **search, "export": "table", "page": "2", "other": "drop"},
                        headers={"HX-Request": "true"} if htmx else {},
                    )
                    self.assertEqual(response.status_code, 200 if htmx else 302)
                    target = urlsplit(response["HX-Redirect" if htmx else "Location"])
                    self.assertEqual(
                        target.path, reverse(f"plugins:netbox_kea:server_leases{family}", args=[self.server.pk])
                    )
                    self.assertEqual(parse_qs(target.query), {key: [value] for key, value in search.items()})
                    self.assertEqual(kea.commands(), [])

    def test_export_is_ignored_when_a_selected_server_lacks_the_family(self):
        for family in (4, 6):
            Server.objects.filter(pk=self.server.pk).update(**{f"dhcp{family}": False})
            with self.subTest(family=family), stub_kea({}) as kea:
                response = self.client.get(
                    reverse(f"plugins:netbox_kea:combined_leases{family}"),
                    {"server": self.server.pk, "export": "table"},
                    follow=True,
                )
                self.assertContains(response, "Protocol not enabled")
                self.assertNotContains(response, "Export refused")
                self.assertEqual(kea.commands(), [])

    def test_each_search_field_alone_explains_the_pending_search(self):
        for field, value, text in (
            ("q", "needle", "Search: <strong>needle</strong>"),
            ("by", "hostname", "Attribute: <strong>Hostname</strong>"),
            ("state", "1", "State: <strong>Declined</strong>"),
        ):
            with self.subTest(field=field, value=value), stub_kea({}):
                response = self.client.get(reverse("plugins:netbox_kea:combined_leases4"), {field: value})
                self.assertContains(response, "Choose a Server to run it.")
                self.assertContains(response, text)

    def test_a_repeated_search_field_keeps_its_last_value(self):
        query = "state=1&state=&by=ip&by=hostname&q=first&q=last"
        with stub_kea({}):
            chooser = self.client.get(f"{reverse('plugins:netbox_kea:combined_leases4')}?{query}")
            redirect = self.client.get(
                f"{reverse('plugins:netbox_kea:combined_leases4')}?server={self.server.pk}&{query}"
            )
        link = BeautifulSoup(chooser.content, "html.parser").select_one(".list-group a")
        target = parse_qs(urlsplit(link["href"]).query)
        self.assertEqual(target.pop("return_url"), [chooser.wsgi_request.get_full_path()])
        self.assertEqual(target, {"by": ["hostname"], "q": ["last"]})
        explanation = BeautifulSoup(chooser.content, "html.parser").select_one(".alert-info").get_text()
        self.assertNotIn("Declined", explanation)
        self.assertContains(chooser, "Attribute: <strong>Hostname</strong>")
        self.assertNotIn("first", explanation)
        target = parse_qs(urlsplit(redirect["Location"]).query, keep_blank_values=True)
        self.assertEqual((target["state"][-1], target["by"][-1], target["q"][-1]), ("", "hostname", "last"))

    def test_an_empty_search_field_is_not_a_pending_search(self):
        with stub_kea({}):
            response = self.client.get(reverse("plugins:netbox_kea:combined_leases4"), {"q": "", "state": ""})
        self.assertNotContains(response, "Choose a Server to run it.")
        link = BeautifulSoup(response.content, "html.parser").select_one(".list-group a")
        self.assertEqual(
            parse_qs(urlsplit(link["href"]).query), {"return_url": [response.wsgi_request.get_full_path()]}
        )

    def test_an_anonymous_user_is_sent_to_login(self):
        self.client.logout()
        for family in (4, 6):
            with self.subTest(family=family), stub_kea({}) as kea:
                response = self.client.get(reverse(f"plugins:netbox_kea:combined_leases{family}"))
                self.assertEqual(response.status_code, 302)
                self.assertIn("login", response.url)
                self.assertEqual(kea.commands(), [])

    def test_overview_never_reads_leases(self):
        for selection in ({}, {"server": [self.server.pk, _make_db_server(name="other-server").pk]}):
            with self.subTest(selection=selection), stub_kea({}) as kea:
                response = self.client.get(
                    reverse("plugins:netbox_kea:combined"), {**selection, "q": "198.18.0.1", "by": "ip", "state": "0"}
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(kea.commands(), [])


class TestCombinedServerSelection(_ViewTestBase):
    def test_server_selection_reads_only_ascii_decimal_text(self):
        responses = _catalogue_responses(4, 7, "198.18.0.0/24")
        responses["stat-lease4-get"] = {"result": 2, "text": "unsupported"}
        for selection in ("\u00b2", "\u0661"):
            with self.subTest(selection=selection), stub_kea(responses):
                response = self.client.get(reverse("plugins:netbox_kea:combined_subnets4"), {"server": selection})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["server_scope"].selected_pks, set())
                self.assertContains(response, "Invalid Server selection")
                self.assertNotContains(response, "198.18.0.0/24")


class TestServerScope(_ViewTestBase):
    sections = ("subnets", "shared_networks", "reservations", "leases")

    def setUp(self):
        super().setUp()
        self.second = _make_db_server(name="other")
        self.hidden = _make_db_server(name="hidden")
        self.viewer = get_user_model().objects.create_user(username="server-scope-viewer")
        permission = ObjectPermission.objects.create(
            name="view-selected-servers", actions=["view"], constraints={"name__in": [self.server.name, "other"]}
        )
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.viewer)
        self.client.force_login(self.viewer)

    def _url(self, section="subnets", family=4):
        name = "combined" if section == "overview" else f"combined_{section}{family}"
        return reverse(f"plugins:netbox_kea:{name}")

    def test_lease_chooser_lists_only_permitted_selected_servers_with_the_family(self):
        for family in (4, 6):
            unavailable = _make_db_server(name=f"unavailable-family-{family}", **{f"dhcp{family}": False})
            unselected = _make_db_server(name=f"unselected-{family}")
            permission = ObjectPermission.objects.get(name="view-selected-servers")
            permission.constraints = {
                "name__in": [self.server.name, self.second.name, unavailable.name, unselected.name]
            }
            permission.save()
            self.client.force_login(self.viewer)
            for selection, expected in (
                ({}, [self.second, self.server, unselected]),
                ({"server": [self.server.pk, self.second.pk]}, [self.second, self.server]),
                ({"server": [self.server.pk, unavailable.pk]}, [self.server]),
                ({"server": [self.second.pk, unavailable.pk]}, [self.second]),
                ({"server": [self.server.pk, self.hidden.pk]}, []),
                ({"server": "invalid"}, []),
            ):
                with self.subTest(family=family, selection=selection), stub_kea({}) as kea:
                    response = self.client.get(self._url("leases", family), {**selection, "state": "0"})
                    self.assertEqual(response.status_code, 200)
                    page = BeautifulSoup(response.content, "html.parser")
                    links = page.select(".list-group a")
                    self.assertEqual(
                        [link.get_text(strip=True) for link in links], [server.name for server in expected]
                    )
                    self.assertEqual(
                        [urlsplit(link["href"]).path for link in links],
                        [reverse(f"plugins:netbox_kea:server_leases{family}", args=[server.pk]) for server in expected],
                    )
                    if not expected:
                        self.assertContains(response, "Invalid Server selection")
                    self.assertEqual(kea.commands(), [])

    def test_server_selector_waits_for_apply(self):
        response = self.client.get(self._url("overview"), {"server": [self.server.pk, self.second.pk]})
        form = BeautifulSoup(response.content, "html.parser").select_one("#server-filter-form")
        self.assertIsNotNone(form)
        submit = form.select_one('button[type="submit"]')
        self.assertIsNotNone(submit)
        self.assertEqual(submit.get_text(strip=True), "Apply")
        self.assertFalse(form.select("[onchange]"))
        self.assertEqual(len(form.select('input[name="server"]')), 2)
        self.assertIn("Show all servers", form.get_text())

    def test_valid_selection_normalizes_the_tab_query_string(self):
        response = self.client.get(
            self._url("overview"), {"server": [f"0{self.second.pk}", f"0{self.server.pk}", str(self.server.pk)]}
        )
        page = BeautifulSoup(response.content, "html.parser")
        query = "&".join(f"server={pk}" for pk in sorted((self.server.pk, self.second.pk)))
        links = page.select(".nav-tabs a")
        self.assertEqual(len(links), 6)
        for link in links:
            self.assertEqual(urlsplit(link["href"]).query, query)

    def test_invalid_selection_preserves_raw_ids_in_the_tab_links(self):
        selection = [f"0{self.server.pk}", "abc", ""]
        response = self.client.get(self._url("overview"), {"server": selection})
        self.assertContains(response, "Invalid Server selection")
        page = BeautifulSoup(response.content, "html.parser")
        links = page.select(".nav-tabs a")
        self.assertEqual(len(links), 6)
        for link in links:
            self.assertEqual(parse_qs(urlsplit(link["href"]).query, keep_blank_values=True), {"server": selection})

    def test_context_exposes_server_scope_without_duplicate_facts(self):
        response = self.client.get(self._url("overview"))
        server_scope = response.context["server_scope"]
        self.assertIsInstance(server_scope.kind, Enum)
        self.assertTrue(server_scope.is_all)
        self.assertFalse(server_scope.is_one)
        self.assertFalse(server_scope.is_invalid)
        self.assertEqual(set(server_scope.all_servers), {self.server, self.second})
        for key in ("all_servers", "selected_server_pks", "server_qs", "scope_warnings"):
            self.assertNotIn(key, response.context)
        self.assertEqual(response.context["server_scope_warnings"], [])

    def test_invalid_selections_show_an_explicit_state_on_every_section(self):
        selections = (
            ["abc"],
            ["999999999"],
            [str(self.hidden.pk)],
            [""],
            [str(self.server.pk), "abc"],
            [str(self.server.pk), str(self.hidden.pk)],
            [str(self.server.pk), "999999999"],
            [str(self.server.pk), ""],
            ["9" * 100],
        )
        for section in (*self.sections, "overview"):
            families = (4,) if section == "overview" else (4, 6)
            for family in families:
                for selection in selections:
                    with self.subTest(section=section, family=family, selection=selection), stub_kea({}) as kea:
                        response = self.client.get(self._url(section, family), {"server": selection, "q": "needle"})
                        self.assertContains(response, "Invalid Server selection")
                        self.assertTrue(response.context["server_scope"].is_invalid)
                        self.assertContains(response, f'href="{self._url(section, family)}?q=needle"')
                        self.assertNotContains(response, '<div class="table-responsive')
                        self.assertEqual(kea.commands(), [])

    def _apply(self, response, checked):
        """Submit the Server selector as a browser does, with only the *checked* Server IDs ticked."""
        form = BeautifulSoup(response.content, "html.parser").select_one("#server-filter-form")
        data = [(field["name"], field["value"]) for field in form.select('input[type="hidden"]')]
        data += [
            ("server", box["value"]) for box in form.select('input[name="server"]') if int(box["value"]) in checked
        ]
        return self.client.get(f"{form['action']}?{urlencode(data)}")

    def test_apply_without_a_checked_server_shows_the_invalid_state(self):
        for section in (*self.sections, "overview"):
            for family in (4,) if section == "overview" else (4, 6):
                with self.subTest(section=section, family=family), stub_kea({}) as kea:
                    page = self.client.get(self._url(section, family), {"server": "abc", "q": "needle"})
                    response = self._apply(page, checked=())
                    self.assertContains(response, "Invalid Server selection")
                    if section not in ("shared_networks", "overview"):
                        self.assertContains(response, f'href="{self._url(section, family)}?q=needle"')
                    tab = BeautifulSoup(response.content, "html.parser").select_one(".nav-tabs a.active")
                    self.assertContains(self.client.get(tab["href"]), "Invalid Server selection")
                    self.assertEqual(kea.commands(), [])

    def test_apply_keeps_the_filters_of_the_section(self):
        filters = {
            "q": "needle",
            "subnet_id": "1",
            "scope": "global",
            "by": "hostname",
            "state": "0",
            "sort": "name",
            "per_page": "25",
            "page": "2",
            "cursor": "abc",
            f"reservation_cursor_{self.server.pk}": "abc",
            "export": "csv",
        }
        expected = {
            "overview": set(),
            "subnets": {"q", "subnet_id", "sort", "per_page"},
            "shared_networks": {"sort", "per_page"},
            "reservations": {"q", "subnet_id", "scope", "sort", "per_page"},
            "leases": {"q", "by", "state", "sort", "per_page"},
        }
        for section, fields in expected.items():
            with self.subTest(section=section):
                page = self.client.get(self._url(section), {"server": "abc", **filters})
                form = BeautifulSoup(page.content, "html.parser").select_one("#server-filter-form")
                hidden = {field["name"]: field["value"] for field in form.select('input[type="hidden"]')}
                hidden.pop("server_selection")
                self.assertEqual(hidden, {key: filters[key] for key in fields})

    def test_apply_of_one_server_keeps_the_lease_search(self):
        page = self.client.get(self._url("leases"), {"q": "needle", "by": "hostname", "state": "0"})
        response = self._apply(page, checked={self.server.pk})
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]))
        self.assertEqual(parse_qs(location.query), {"q": ["needle"], "by": ["hostname"], "state": ["0"]})

    def test_show_all_servers_in_the_selector_keeps_the_filters(self):
        page = self.client.get(self._url(), {"server": [self.server.pk, self.second.pk], "q": "needle"})
        form = BeautifulSoup(page.content, "html.parser").select_one("#server-filter-form")
        (link,) = (link for link in form.select("a") if "Show all servers" in link.get_text())
        self.assertEqual(link["href"], f"{self._url()}?q=needle")

    def test_no_selection_reads_all_permitted_servers(self):
        responses = _catalogue_responses(4, 1, "198.18.0.0/24")
        responses["stat-lease4-get"] = {"result": 2, "text": "unsupported"}
        with stub_kea(responses):
            response = self.client.get(self._url())
        rows = list(response.context["table"].data)
        self.assertEqual({row["server_pk"] for row in rows}, {self.server.pk, self.second.pk})

    def test_several_valid_servers_are_the_only_servers_read(self):
        self.client.force_login(self.user)
        responses = _catalogue_responses(4, 1, "198.18.0.0/24")
        responses["stat-lease4-get"] = {"result": 2, "text": "unsupported"}
        with stub_kea(responses):
            response = self.client.get(self._url(), {"server": [self.server.pk, self.second.pk]})
        rows = list(response.context["table"].data)
        self.assertEqual({row["server_pk"] for row in rows}, {self.server.pk, self.second.pk})
        server_scope = response.context["server_scope"]
        self.assertIsInstance(server_scope.kind, Enum)
        self.assertFalse(server_scope.is_all)
        self.assertFalse(server_scope.is_one)
        self.assertFalse(server_scope.is_invalid)

    def test_one_server_redirects_to_each_family_tab_with_only_compatible_filters(self):
        expected_filters = {
            "subnets": {"page", "per_page", "sort"},
            "shared_networks": {"page", "per_page", "sort"},
            "reservations": {"q", "subnet_id", "scope", "per_page", "sort"},
            "leases": {"q", "by", "state", "per_page", "sort"},
        }
        filters = {
            "q": "needle & spaces",
            "subnet_id": "1",
            "scope": "global",
            "by": "hostname",
            "state": "0",
            "page": "2",
            "per_page": "50",
            "sort": "-hostname",
            "unrelated": "drop",
            f"reservation_cursor_{self.server.pk}": "done",
        }
        for section in self.sections:
            for family in (4, 6):
                with self.subTest(section=section, family=family), stub_kea({}) as kea:
                    response = self.client.get(self._url(section, family), {"server": self.server.pk, **filters})
                    self.assertEqual(response.status_code, 302)
                    location = urlsplit(response["Location"])
                    self.assertEqual(
                        location.path, reverse(f"plugins:netbox_kea:server_{section}{family}", args=[self.server.pk])
                    )
                    self.assertEqual(
                        parse_qs(location.query), {key: [filters[key]] for key in expected_filters[section]}
                    )
                    self.assertEqual(kea.commands(), [])

    def test_duplicate_decimal_ids_still_select_one_server(self):
        response = self.client.get(self._url(), {"server": [str(self.server.pk), f"0{self.server.pk}"]})
        self.assertRedirects(
            response,
            reverse("plugins:netbox_kea:server_subnets4", args=[self.server.pk]),
            fetch_redirect_response=False,
        )

    def test_lease_redirect_preserves_state_in_the_canonical_search_form(self):
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            with self.subTest(family=family), stub_kea(_catalogue_responses(family, 1, cidr)):
                response = self.client.get(
                    self._url("leases", family), {"server": self.server.pk, "state": "1"}, follow=True
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["form"]["state"].value(), "1")

    def test_htmx_single_server_uses_a_navigation_response(self):
        for section in (*self.sections, "overview"):
            families = (4,) if section == "overview" else (4, 6)
            for family in families:
                with self.subTest(section=section, family=family), stub_kea({}) as kea:
                    response = self.client.get(
                        self._url(section, family), {"server": self.server.pk}, HTTP_HX_REQUEST="true"
                    )
                    target = "server" if section == "overview" else f"server_{section}{family}"
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(
                        response["HX-Redirect"],
                        reverse(f"plugins:netbox_kea:{target}", args=[self.server.pk])
                        + (f"?family={family}" if section == "overview" else ""),
                    )
                    self.assertEqual(response.content, b"")
                    self.assertEqual(kea.commands(), [])

    def test_an_export_with_a_selected_server_without_the_family_is_refused(self):
        Server.objects.filter(pk=self.second.pk).update(dhcp6=False)
        exports = {"subnets": "table", "shared_networks": "table", "reservations": "json"}
        for selection in ([self.second.pk], [self.server.pk, self.second.pk]):
            for section, export in exports.items():
                with self.subTest(selection=selection, section=section), stub_kea({}) as kea:
                    response = self.client.get(self._url(section, 6), {"server": selection, "export": export})
                    expected = f"{self._url(section, 6)}?" + "&".join(f"server={pk}" for pk in sorted(selection))
                    self.assertRedirects(response, expected, fetch_redirect_response=False)
                    self.assertEqual(kea.commands(), [])
        response = self.client.get(self._url("subnets", 6), {"server": self.second.pk, "export": "table"}, follow=True)
        self.assertContains(response, "Export refused: DHCPv6 is not enabled on other.")

    def test_export_refusal_keeps_hostile_query_values_inside_the_local_route(self):
        Server.objects.filter(pk=self.second.pk).update(dhcp6=False)
        for section in ("subnets", "shared_networks", "reservations"):
            for value in (
                "//outside.example/path",
                "https://outside.example/path",
                "/\\outside.example",
                "\r\nLocation: //outside.example",
            ):
                with self.subTest(section=section, value=value), stub_kea({}) as kea:
                    response = self.client.get(
                        self._url(section, 6),
                        {"server": self.second.pk, "export": "table", "q": value, "return_url": value},
                    )
                    self.assertEqual(response.status_code, 302)
                    location = urlsplit(response["Location"])
                    self.assertEqual(location.scheme, "")
                    self.assertEqual(location.netloc, "")
                    self.assertEqual(location.path, self._url(section, 6))
                    self.assertEqual(
                        parse_qs(location.query), {"server": [str(self.second.pk)], "q": [value], "return_url": [value]}
                    )
                    self.assertEqual(kea.commands(), [])

    def test_export_refusal_preserves_repeated_values_on_each_combined_route(self):
        exports = {"subnets": "table", "shared_networks": "table", "reservations": "json"}
        for family in (4, 6):
            Server.objects.filter(pk=self.second.pk).update(**{f"dhcp{family}": False})
            for section, export in exports.items():
                for selection in ([self.second.pk], [self.server.pk, self.second.pk, self.second.pk]):
                    query = {
                        "server": list(map(str, selection)),
                        "export": [export, export],
                        "q": ["//outside.example/path", "", "percent% & spaces + #fragment"],
                        "return_url": ["https://outside.example/path", "/\\outside.example"],
                        "sort": ["hostname", "-hostname"],
                        "page": ["2", "3"],
                    }
                    with self.subTest(family=family, section=section, selection=selection), stub_kea({}) as kea:
                        response = self.client.get(self._url(section, family), query)
                        self.assertEqual(response.status_code, 302)
                        location = urlsplit(response["Location"])
                        self.assertEqual(location.scheme, "")
                        self.assertEqual(location.netloc, "")
                        self.assertEqual(location.fragment, "")
                        self.assertEqual(location.path, self._url(section, family))
                        self.assertEqual(
                            parse_qs(location.query, keep_blank_values=True),
                            {key: values for key, values in query.items() if key != "export"},
                        )
                        self.assertEqual(kea.commands(), [])

    def test_export_refusal_keeps_the_deployment_prefix_on_each_combined_route(self):
        for family in (4, 6):
            Server.objects.filter(pk=self.second.pk).update(**{f"dhcp{family}": False})
            for section in ("subnets", "shared_networks", "reservations"):
                url = self._url(section, family)
                query = {"server": [str(self.server.pk), str(self.second.pk)], "q": ["needle & spaces", ""]}
                # The test client skips WSGIHandler, which sets this from SCRIPT_NAME.
                set_script_prefix("/netbox/")
                try:
                    with self.subTest(family=family, section=section), stub_kea({}) as kea:
                        response = self.client.get(url, {**query, "export": "table"}, SCRIPT_NAME="/netbox")
                        self.assertEqual(response.status_code, 302)
                        location = urlsplit(response["Location"])
                        self.assertEqual(location.path, self._url(section, family))
                        self.assertEqual(location.path, f"/netbox{url}")
                        self.assertEqual(parse_qs(location.query, keep_blank_values=True), query)
                        self.assertEqual(kea.commands(), [])
                finally:
                    clear_script_prefix()

    def test_export_refusal_renders_the_warning_and_reads_only_the_supported_selection(self):
        Server.objects.filter(pk=self.second.pk).update(dhcp4=False)
        responses = _catalogue_responses(4, 1, "198.18.0.0/24")
        responses["stat-lease4-get"] = {"result": 2, "text": "unsupported"}
        with stub_kea(responses):
            response = self.client.get(
                self._url(), {"server": [self.server.pk, self.second.pk], "export": "table"}, follow=True
            )
        self.assertContains(response, "Export refused: DHCPv4 is not enabled on other.")
        self.assertEqual({row["server_pk"] for row in response.context["table"].data}, {self.server.pk})

    def test_selected_server_without_the_family_has_a_notice_even_without_a_lease_query(self):
        for family in (4, 6):
            Server.objects.filter(pk=self.server.pk).update(**{f"dhcp{family}": False})
            for section in self.sections:
                with self.subTest(section=section, family=family), stub_kea({}) as kea:
                    response = self.client.get(self._url(section, family), {"server": self.server.pk}, follow=True)
                    self.assertContains(response, "Protocol not enabled")
                    self.assertEqual(
                        response.wsgi_request.path,
                        reverse(f"plugins:netbox_kea:server_{section}{family}", args=[self.server.pk]),
                    )
                    self.assertEqual(kea.commands(), [])

    def test_no_selection_skips_a_server_without_the_family_without_a_notice(self):
        Server.objects.filter(pk__in=[self.server.pk, self.second.pk]).update(dhcp6=False)
        for section in self.sections:
            with self.subTest(section=section), stub_kea({}) as kea:
                response = self.client.get(self._url(section, 6))
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, "is not enabled on this Server")
                self.assertEqual(response.context["server_scope_warnings"], [])
                self.assertEqual(kea.commands(), [])

    def test_overview_honors_a_selection_of_several_servers(self):
        self.client.force_login(self.user)
        response = self.client.get(self._url("overview"), {"server": [self.server.pk, self.second.pk]})
        self.assertEqual(set(response.context["server_scope"].servers), {self.server, self.second})

    def test_overview_without_selection_shows_only_permitted_servers(self):
        response = self.client.get(self._url("overview"))
        self.assertContains(response, self.server.get_absolute_url())
        self.assertContains(response, self.second.get_absolute_url())
        self.assertNotContains(response, self.hidden.get_absolute_url())

    def test_overview_with_one_server_redirects_to_its_detail_page(self):
        response = self.client.get(self._url("overview"), {"server": self.server.pk, "q": "drop"})
        self.assertRedirects(response, self.server.get_absolute_url() + "?family=4", fetch_redirect_response=False)


class TestCombinedSubnetDiagnostics(_ViewTestBase):
    def _subnet_actions_response(self, *, verified=True, writable=True):
        if not writable:
            from django.contrib.contenttypes.models import ContentType
            from users.models import ObjectPermission

            self.user.is_superuser = False
            self.user.save()
            permission = ObjectPermission.objects.create(name="view-subnet-server", actions=["view"])
            permission.object_types.add(ContentType.objects.get_for_model(type(self.server)))
            permission.users.add(self.user)
        responses = _catalogue_responses(4, 7, "198.18.0.0/24")
        responses["stat-lease4-get"] = {"result": 2, "text": "unsupported"}
        if not verified:
            responses["subnet4-list"] = {"result": 2, "text": "unsupported"}
        with stub_kea(responses):
            return self.client.get(reverse("plugins:netbox_kea:combined_subnets4"))

    def test_writable_verified_subnet_offers_options_and_identity_actions(self):
        response = self._subnet_actions_response()
        self.assertEqual(response.status_code, 200)
        page = BeautifulSoup(response.content, "html.parser")
        for action in ("options_edit", "wipe_leases"):
            url = reverse(f"plugins:netbox_kea:server_subnet4_{action}", args=[self.server.pk, 7])
            links = [link for link in page.select("td a") if urlsplit(link["href"]).path == url]
            self.assertEqual(len(links), 1, f"Missing {action} action")
            self.assertEqual(
                parse_qs(urlsplit(links[0]["href"]).query).get("return_url"),
                [reverse("plugins:netbox_kea:combined_subnets4")],
            )

    def test_writable_configured_subnet_offers_no_options_or_identity_actions(self):
        """A Subnet options change needs a Verified Subnet, so a Subnet that Kea did not confirm has no form."""
        response = self._subnet_actions_response(verified=False)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "198.18.0.0/24")
        paths = {urlsplit(link["href"]).path for link in BeautifulSoup(response.content, "html.parser").select("td a")}
        for action in ("options_edit", "wipe_leases"):
            url = reverse(f"plugins:netbox_kea:server_subnet4_{action}", args=[self.server.pk, 7])
            self.assertNotIn(url, paths)

    def test_readonly_subnet_has_no_mutation_actions(self):
        response = self._subnet_actions_response(writable=False)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "198.18.0.0/24")
        paths = {urlsplit(link["href"]).path for link in BeautifulSoup(response.content, "html.parser").select("td a")}
        for action in ("options_edit", "wipe_leases"):
            url = reverse(f"plugins:netbox_kea:server_subnet4_{action}", args=[self.server.pk, 7])
            self.assertNotIn(url, paths)

    def test_complete_catalogue_is_reused_for_unchanged_requests(self):
        url = reverse("plugins:netbox_kea:combined_subnets4")
        responses = _catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.1.0/24", "pools": []}])
        responses["stat-lease4-get"] = {"result": 2, "text": "unknown command"}

        with stub_kea(responses) as kea:
            first_response = self.client.get(url)
            second_response = self.client.get(url)

        self.assertContains(first_response, "198.18.1.0/24")
        self.assertContains(second_response, "198.18.1.0/24")
        self.assertEqual(kea.commands().count("subnet4-list"), 1)
        self.assertEqual(kea.commands().count("config-get"), 1)

    def test_unavailable_catalogue_preserves_specific_diagnostics(self):
        url = reverse("plugins:netbox_kea:combined_subnets4")

        with stub_kea(
            {
                "subnet4-list": requests.ConnectionError("identity unavailable"),
                "config-get": requests.ConnectionError("configuration unavailable"),
            }
        ):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Kea subnet identity facts are unavailable.")
        self.assertContains(response, "Kea configuration facts are unavailable.")
        self.assertNotContains(response, HEADLINES["lease"])
        self.assertTrue(response.context["errors"])
        self.assertContains(response, "alert-danger")

    def test_empty_config_response_preserves_confirmed_empty_identity(self):
        with stub_kea(
            {
                "subnet4-list": {"result": 3, "text": "no subnets"},
                "config-get": [],
                "stat-lease4-get": {"result": 2, "text": "unknown command"},
            }
        ):
            response = self.client.get(reverse("plugins:netbox_kea:combined_subnets4"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["table"].data), [])
        self.assertEqual(response.context["errors"], [])
        self.assertContains(response, "alert-warning")

    def test_incomplete_catalogue_explains_omitted_facts(self):
        responses = _catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.0.0/24", "pools": "not-a-list"}])
        responses["stat-lease4-get"] = {"result": 2, "text": "unknown command"}
        url = reverse("plugins:netbox_kea:combined_subnets4")

        with stub_kea(responses):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "198.18.0.0/24")
        self.assertContains(response, "Kea returned a non-list Pool collection.")
        self.assertEqual(response.context["errors"], [])
        self.assertContains(response, "alert-warning")

        self.assertContains(response, "Some server data is incomplete:")
        self.assertNotContains(response, "Some server data is unavailable or incomplete:")

    def test_repeated_catalogue_diagnostics_render_once(self):
        responses = _catalogue_responses_for_subnets(
            4,
            [{"id": 1, "subnet": "198.18.0.0/24", "pools": ["invalid-one", "invalid-two"]}],
        )
        responses["stat-lease4-get"] = {"result": 2, "text": "unknown command"}
        url = reverse("plugins:netbox_kea:combined_subnets4")

        with stub_kea(responses):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Kea returned an invalid Pool.", count=1)


class TestCombinedSharedNetworkDiagnostics(_ViewTestBase):
    def _url(self):
        return reverse("plugins:netbox_kea:combined_shared_networks4")

    def test_unreachable_server_is_reported_with_its_snapshot_diagnostic(self):
        with stub_kea({"config-get": requests.ConnectionError("unreachable")}):
            response = self.client.get(self._url())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["errors"],
            [
                (self.server.name, HEADLINES["configuration"]),
                (self.server.name, "Kea configuration facts are unavailable."),
            ],
        )
        self.assertNotContains(response, HEADLINES["lease"])
        self.assertContains(response, "alert-danger")
        self.assertNotContains(response, "alert-warning")

    def test_non_object_family_configuration_is_reported_without_a_server_error(self):
        with stub_kea({"config-get": {"result": 0, "arguments": {"Dhcp4": []}}}):
            response = self.client.get(self._url())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["errors"],
            [
                (self.server.name, HEADLINES["configuration"]),
                (self.server.name, "Kea did not return a Dhcp4 configuration object."),
            ],
        )
        self.assertNotContains(response, HEADLINES["lease"])

    def test_incomplete_snapshot_keeps_valid_shared_networks_visible(self):
        responses = _catalogue_responses_for_subnets(
            4,
            [],
            shared_networks=[{"name": "clients", "subnet4": []}, None],
        )

        with stub_kea(responses):
            response = self.client.get(self._url())

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "clients")
        self.assertEqual(response.context["errors"], [])
        self.assertEqual(
            response.context["warnings"],
            [(self.server.name, "Kea returned a non-object Shared Network.")],
        )
        self.assertContains(response, "alert-warning")
        self.assertNotContains(response, "alert-danger")

    def test_writable_server_offers_shared_network_actions(self):
        responses = _catalogue_responses_for_subnets(4, [], shared_networks=[{"name": "clients", "subnet4": []}])
        with stub_kea(responses):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'aria-label="Edit clients"')
        self.assertContains(response, 'aria-label="Delete clients"')

    def test_readonly_server_hides_shared_network_actions(self):
        from django.contrib.contenttypes.models import ContentType
        from users.models import ObjectPermission

        self.user.is_superuser = False
        self.user.save()
        permission = ObjectPermission.objects.create(name="view-shared-network-server", actions=["view"])
        permission.object_types.add(ContentType.objects.get_for_model(type(self.server)))
        permission.users.add(self.user)
        responses = _catalogue_responses_for_subnets(4, [], shared_networks=[{"name": "clients", "subnet4": []}])
        with stub_kea(responses):
            response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "clients")
        self.assertNotContains(response, 'aria-label="Edit clients"')


class TestCombinedReservationsWithoutAddress(_ViewTestBase):
    """The global reservations tab hits the same address-less crash as the per-server tab (#110)."""

    def _url(self, version=4):
        return reverse(f"plugins:netbox_kea:combined_reservations{version}")

    def test_v4_identifier_only_reservation_renders(self):
        page = _res_page([{"subnet-id": 3742, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "printer-1"}])
        with stub_kea(
            {
                **_catalogue_responses(4, 3742, "198.18.0.0/24"),
                "reservation-get-page": page,
                "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
            }
        ):
            response = self.client.get(self._url(4))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"printer-1", response.content)

    def test_v6_prefix_only_reservation_renders(self):
        page = _res_page([{"subnet-id": 12, "duid": "00:01:00:01:12:34", "prefixes": ["2001:db8:1::/64"]}])
        with stub_kea(
            {
                **_catalogue_responses(6, 12, "2001:db8::/48"),
                "reservation-get-page": page,
                "lease6-get-by-state": {"result": 0, "arguments": {"leases": []}},
            }
        ):
            response = self.client.get(self._url(6))
        self.assertEqual(response.status_code, 200)


class TestCombinedReservationsShowWhatIsReserved(_ViewTestBase):
    """The global tab shows the identifier and prefixes an address-less host reserves.

    Rendering 200 only proves the crash is gone; these assert the row actually says
    what the reservation is, which is the point of showing it at all.
    """

    def _url(self, version=4, query=""):
        base = reverse(f"plugins:netbox_kea:combined_reservations{version}")
        return base + (f"?{query.removeprefix('&')}" if query else "")

    def _stub(self, hosts, version=4):
        cidr = "198.18.0.0/24" if version == 4 else "2001:db8::/48"
        return {
            **_catalogue_responses(version, hosts[0]["subnet-id"], cidr),
            "reservation-get-page": _res_page(hosts),
            f"lease{version}-get-by-state": {"result": 0, "arguments": {"leases": []}},
        }

    def test_v4_flex_id_row_shows_the_identifier_and_its_type(self):
        hosts = [{"subnet-id": 1, "flex-id": "vendor-42", "hostname": "kiosk"}]
        with stub_kea(self._stub(hosts)):
            response = self.client.get(self._url(4))
        body = response.content.decode()
        self.assertIn("vendor-42", body)
        self.assertIn("flex-id", body)

    def test_v6_prefix_only_row_shows_its_prefixes_and_no_address(self):
        hosts = [{"subnet-id": 12, "duid": "00:01:00:01:12:34", "prefixes": ["2001:db8:1::/64"]}]
        with stub_kea(self._stub(hosts, version=6)):
            response = self.client.get(self._url(6))
        body = response.content.decode()
        self.assertIn("2001:db8:1::/64", body)
        self.assertIn("No address", body)


class TestCombinedReservationCapabilityConcurrency(_ViewTestBase):
    def test_writable_servers_discover_capabilities_concurrently(self):
        second_server = _make_db_server(name="test-kea-secondary", ca_url="https://kea-secondary.example.com")
        barrier = threading.Barrier(2)
        completed_probes = []

        configuration = _catalogue_responses(4, 1, "198.18.0.0/24")["config-get"]

        def simultaneous_configuration_response(_body):
            barrier.wait(timeout=30)
            completed_probes.append(True)
            return configuration

        hosts = [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "printer"}]
        responses = {
            **_catalogue_responses(4, 1, "198.18.0.0/24"),
            "reservation-get-page": _res_page(hosts),
            "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
            "config-get": simultaneous_configuration_response,
        }
        url = reverse("plugins:netbox_kea:combined_reservations4")
        url += f"?server={self.server.pk}&server={second_server.pk}"

        with stub_kea(responses):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        # Each Server reads its Catalogue, then its capabilities, in pairs across the two Servers.
        self.assertEqual(len(completed_probes), 4)
        self.assertEqual(response.context["mutation_unavailable_servers"], [])

    def test_a_failed_capability_read_does_not_hide_the_reservations(self):
        hosts = [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "printer"}]
        responses = {
            **_catalogue_responses(4, 1, "198.18.0.0/24"),
            "reservation-get-page": _res_page(hosts),
            "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
        }
        # The Catalogue read succeeds; the capability read of the Server Configuration fails.
        responses["config-get"] = queued(responses["config-get"], requests.ConnectionError)

        with stub_kea(responses):
            response = self.client.get(reverse("plugins:netbox_kea:combined_reservations4"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "printer")
        self.assertEqual(
            response.context["mutation_unavailable_servers"],
            [(self.server.name, "Reservation mutation capabilities could not be confirmed.")],
        )


class TestCombinedReservationFanOut(_ViewTestBase):
    def test_a_server_that_cannot_build_a_client_keeps_the_other_servers(self):
        # A client certificate without its key fails the client construction with a KeaClientSettingsError.
        broken = _make_db_server(name="broken-kea", ca_url="https://kea-broken.example.com", client_cert_path="/cert")
        hosts = [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "printer"}]
        responses = {
            **_catalogue_responses(4, 1, "198.18.0.0/24"),
            "reservation-get-page": _res_page(hosts),
            "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
        }
        url = reverse("plugins:netbox_kea:combined_reservations4") + f"?server={self.server.pk}&server={broken.pk}"

        with stub_kea(responses), self.assertLogs("netbox_kea.read_failure", level="WARNING"):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "printer")
        self.assertEqual(response.context["errors"], [("broken-kea", HEADLINES["reservation"])])
        self.assertEqual(response.context["mutation_unavailable_servers"], [])

    @with_kea_client_config(kea_timeout=7, lease_query_max_unpaged_leases=250)
    def test_a_worker_builds_its_client_from_the_request_read_of_the_settings_row(self):
        from django.db import connection

        from netbox_kea.views.fan_out import fan_out

        def fetch(server):
            client = server.get_client(4)
            return client.timeout, client.max_unpaged_leases, connection.connection is None

        read = fan_out([self.server], "catalogue", fetch)

        # A worker that read the row itself would open a connection and miss the uncommitted test value.
        self.assertEqual(read.results, [(self.server, (7, 250, True))])

    @with_display_cache_config(configuration_ttl=0)
    def test_a_worker_reads_the_display_cache_ttl_from_the_request_read_of_the_settings_row(self):
        from django.db import connection

        from netbox_kea import server_configuration
        from netbox_kea.views.fan_out import fan_out

        def fetch(server):
            for _ in range(2):
                server_configuration.display(server, 4)
            return connection.connection is None

        with stub_kea({"config-get": {"result": 0, "arguments": {"Dhcp4": {}}}}) as kea:
            read = fan_out([self.server], "configuration", fetch)

        # A worker that read the row itself would open a connection and cache with the committed TTL.
        self.assertEqual(read.results, [(self.server, True)])
        self.assertEqual(kea.commands(), ["config-get", "config-get"])

    def test_a_worker_that_reads_an_unpinned_settings_row_fails_loudly(self):
        from netbox_kea.models import SyncConfig
        from netbox_kea.views.fan_out import fan_out

        # A worker that read the row would open its own database connection.
        with self.assertRaisesMessage(RuntimeError, "SyncConfig"):
            fan_out([self.server], "configuration", lambda server: SyncConfig.get())

    @with_kea_client_config(kea_timeout=7)
    def test_the_request_thread_reads_the_live_row_after_a_fan_out(self):
        from netbox_kea.models import KeaClientConfig
        from netbox_kea.views.fan_out import fan_out

        read = fan_out([self.server], "configuration", lambda server: server.get_client(4).timeout)
        KeaClientConfig.objects.filter(pk=1).update(kea_timeout=9)

        self.assertEqual(read.results, [(self.server, 7)])
        self.assertEqual(KeaClientConfig.get().kea_timeout, 9)
        self.assertEqual(self.server.get_client(4).timeout, 9)

    def test_a_server_that_cannot_be_reached_gets_no_capability_read(self):
        # A second read of an unreachable Server only adds its timeout to the page.
        responses = {
            **_catalogue_responses(4, 1, "198.18.0.0/24"),
            "reservation-get-page": requests.ConnectionError,
        }
        url = reverse("plugins:netbox_kea:combined_reservations4")

        with stub_kea(responses) as kea:
            response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["errors"], [(self.server.name, HEADLINES["reservation"])])
        # Only the Catalogue read sends config-get.
        self.assertEqual(kea.commands().count("config-get"), 1)


class TestCombinedReservationSyncControl(_ViewTestBase):
    """The combined tab must offer the same Reservation synchronization as one server.

    The table cell renders the Sync all button only from ``sync_url``, which the
    enrichment sets only for a caller that passes the manual Sync rule. The combined
    view left it out, so the button never rendered there.
    """

    def _url(self, version=4):
        return reverse(f"plugins:netbox_kea:combined_reservations{version}")

    def test_unsynchronized_row_offers_the_sync_control(self):
        hosts = [{"subnet-id": 1, "hw-address": "aa:bb:cc:00:00:01", "ip-address": "198.18.0.10"}]
        stub = {
            **_catalogue_responses(4, 1, "198.18.0.0/24"),
            "reservation-get-page": _res_page(hosts),
            "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
        }

        with stub_kea(stub):
            response = self.client.get(self._url(4))

        body = response.content.decode()
        sync_url = reverse("plugins:netbox_kea:server_reservation4_sync", args=[self.server.pk, 1])
        self.assertIn("Not Synchronized", body)
        self.assertIn(sync_url, body)
        self.assertIn("Sync all", body)


class TestCombinedReservationCursorPagination(_ViewTestBase):
    """The Next page link must carry the encoded per-server cursor, not just exist."""

    def _url(self, version=4, query=""):
        return reverse(f"plugins:netbox_kea:combined_reservations{version}") + (
            f"?{query.removeprefix('&')}" if query else ""
        )

    #: Only a full page can carry a next cursor.
    PAGE_SIZE = _RESERVATION_PAGE_SIZE

    def _stub(self, *, next_from=0, next_source=0, hosts=None):
        if hosts is None:
            hosts = [
                {
                    "subnet-id": 1,
                    "hw-address": f"aa:bb:cc:00:{index // 256:02x}:{index % 256:02x}",
                    "ip-address": f"198.18.{index // 256}.{index % 256}",
                }
                for index in range(self.PAGE_SIZE)
            ]
        return {
            **_catalogue_responses(4, 1, "198.18.0.0/16"),
            "reservation-get-page": _res_page(hosts, next_from=next_from, next_source=next_source),
            "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
        }

    def test_next_page_url_carries_the_encoded_cursor(self):
        # Kea's two-part cursor (source-index 1, from 5) as one opaque base64url token.
        with stub_kea(self._stub(next_from=5, next_source=1)) as kea:
            response = self.client.get(self._url())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(kea.bodies("reservation-get-page")), 1)
        next_page_url = response.context["next_page_url"]
        self.assertIsNotNone(next_page_url)
        self.assertIn(f"reservation_cursor_{self.server.pk}=WzEsNV0", next_page_url)
        self.assertContains(response, "Next page")

    def test_the_cursor_round_trips_to_the_next_reservation_page_request(self):
        with stub_kea(self._stub(next_from=5, next_source=1)):
            first = self.client.get(self._url())
        next_page_url = first.context["next_page_url"]

        # A short terminal page ends the traversal on the second request.
        terminal = [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.9.9"}]
        with stub_kea(self._stub(hosts=terminal)) as kea:
            second = self.client.get(next_page_url)

        self.assertEqual(second.status_code, 200)
        body = kea.bodies("reservation-get-page")[0]
        # The decoded cursor must reach Kea as its native from/source-index pair.
        self.assertEqual(body["arguments"]["from"], 5)
        self.assertEqual(body["arguments"]["source-index"], 1)

    def test_an_exhausted_source_offers_no_next_page(self):
        terminal = [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "198.18.9.9"}]
        with stub_kea(self._stub(hosts=terminal)):
            response = self.client.get(self._url())

        self.assertIsNone(response.context["next_page_url"])
        self.assertNotContains(response, "Next page")

    def test_substring_search_finds_a_reservation_after_the_first_page(self):
        responses = self._stub(next_from=100, next_source=1)
        matching_host = {
            "subnet-id": 1,
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "198.18.9.9",
            "hostname": "printer-needle-office",
        }
        responses["reservation-get-page"] = queued(responses["reservation-get-page"], _res_page([matching_host]))
        with stub_kea(responses):
            response = self.client.get(self._url(query="&q=needle"))

        self.assertContains(response, "printer-needle-office")

    def test_search_limits_each_batch_and_can_continue_after_no_matches(self):
        responses = self._stub()
        pages = [self._stub(next_from=index * 100, next_source=index)["reservation-get-page"] for index in range(1, 6)]
        match = {"subnet-id": 1, "flex-id": "later-printer", "hostname": "printer-needle-office"}
        responses["reservation-get-page"] = queued(*pages, _res_page([match]))
        with stub_kea(responses) as kea:
            first = self.client.get(self._url(query="&q=needle"))
            self.assertEqual(len(kea.bodies("reservation-get-page")), 5)
            self.assertNotContains(first, "printer-needle-office")
            self.assertContains(first, "Additional Reservations may remain.")
            self.assertContains(first, "Search is incomplete.")
            self.assertContains(first, "At most 500 Reservations per server were inspected.")
            self.assertContains(first, "Narrow the filters or continue with Next page.")
            self.assertNotContains(first, "No reservations found.")
            continuation = first.context["next_page_url"]
            self.assertIsNotNone(continuation)
            second = self.client.get(continuation)
        self.assertContains(second, "printer-needle-office")
        self.assertEqual(kea.bodies("reservation-get-page")[-1]["arguments"]["from"], 500)
        self.assertEqual(kea.bodies("reservation-get-page")[-1]["arguments"]["source-index"], 5)

    def test_a_full_batch_cursor_does_not_claim_that_more_records_exist(self):
        responses = self._stub()
        pages = [self._stub(next_from=index * 100, next_source=1)["reservation-get-page"] for index in range(1, 6)]
        responses["reservation-get-page"] = queued(*pages, _res_page([]))
        with stub_kea(responses) as kea:
            first = self.client.get(self._url(query="&q=needle"))
            self.assertEqual(len(kea.bodies("reservation-get-page")), 5)
            self.assertContains(first, "Additional Reservations may remain.")
            self.assertNotContains(first, "More Reservations remain.")
            second = self.client.get(first.context["next_page_url"])
        self.assertContains(second, "No reservations found.")
        self.assertIsNone(second.context["next_page_url"])

    def test_a_subnet_confirmed_absent_is_an_empty_complete_server_result(self):
        responses = {
            **_catalogue_responses(4, 30, "198.18.30.0/24"),
            "reservation-get-page": {"result": 1, "text": "subnet 20 is not configured"},
        }
        with stub_kea(responses) as kea:
            snapshot = fetch(self.server, 4, ReservationQuery(subnet_id=20)).loaded
        self.assertEqual(snapshot.records, ())
        self.assertTrue(snapshot.complete)
        self.assertEqual(kea.bodies("reservation-get-page"), [])

    def test_an_uncertain_subnet_absence_uses_a_bounded_unscoped_read(self):
        def page(body):
            if "subnet-id" in body["arguments"]:
                return {"result": 1, "text": "subnet 20 is not configured"}
            return _res_page([])

        responses = {
            **_catalogue_responses(4, 30, "198.18.30.0/24"),
            "subnet4-list": requests.ConnectionError("identity unavailable"),
            "reservation-get-page": page,
        }
        with stub_kea(responses) as kea:
            snapshot = fetch(self.server, 4, ReservationQuery(subnet_id=20)).loaded
        self.assertEqual(snapshot.records, ())
        self.assertEqual(len(kea.bodies("reservation-get-page")), 1)
        self.assertNotIn("subnet-id", kea.bodies("reservation-get-page")[0]["arguments"])

    def test_a_quarantined_subnet_is_not_treated_as_confirmed_absent(self):
        responses = _catalogue_responses(4, 20, "198.18.20.0/24")
        responses["config-get"] = {
            "result": 0,
            "arguments": {"Dhcp4": {"subnet4": [{"id": 20, "subnet": "198.18.30.0/24"}], "shared-networks": []}},
        }
        responses["reservation-get-page"] = _res_page([{"subnet-id": 20, "flex-id": "quarantined-printer"}])
        with stub_kea(responses) as kea:
            snapshot = fetch(self.server, 4, ReservationQuery(subnet_id=20)).loaded
        self.assertEqual(len(kea.bodies("reservation-get-page")), 1)
        self.assertNotIn("subnet-id", kea.bodies("reservation-get-page")[0]["arguments"])
        self.assertFalse(snapshot.complete)
        self.assertIn("unverified-scope", [diagnostic.code for diagnostic in snapshot.diagnostics])

    def test_exhausted_search_can_report_no_matches_without_a_limit_warning(self):
        with stub_kea(self._stub(hosts=[])):
            response = self.client.get(self._url(query="&q=needle"))
        self.assertContains(response, "No reservations found.")
        self.assertNotContains(response, "Search is incomplete.")
        self.assertIsNone(response.context["next_page_url"])

    def test_a_match_on_the_fifth_page_still_warns_if_more_records_remain(self):
        responses = self._stub()
        pages = [self._stub(next_from=index * 100, next_source=1)["reservation-get-page"] for index in range(1, 6)]
        pages[-1]["arguments"]["hosts"][0]["hostname"] = "office-needle-printer"
        responses["reservation-get-page"] = queued(*pages)
        with stub_kea(responses):
            response = self.client.get(self._url(query="&q=needle"))
        self.assertContains(response, "office-needle-printer")
        self.assertContains(response, "Search is incomplete.")
        self.assertContains(response, "At most 500 Reservations per server were inspected.")
        self.assertIsNotNone(response.context["next_page_url"])

    def test_subnet_and_global_filters_reach_the_kea_page_request(self):
        for query, subnet_id in (("&subnet_id=1", 1), ("&scope=global", 0)):
            with self.subTest(query=query), stub_kea(self._stub(hosts=[])) as kea:
                response = self.client.get(self._url(query=query))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(kea.bodies("reservation-get-page")[0]["arguments"]["subnet-id"], subnet_id)

    def test_global_scope_with_an_in_subnet_filter_needs_no_reservation_pages(self):
        with stub_kea(self._stub(hosts=[])) as kea:
            response = self.client.get(self._url(query="&scope=global&subnet_id=1"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.bodies("reservation-get-page"), [])


class TestReservationIdentifierColumns(_ViewTestBase):
    """A typed identifier column must stay empty for every other identifier type.

    The reservation row carries one ``identifier`` plus its ``identifier_type``, so a
    column bound straight to ``identifier`` showed a client-id under "Hardware
    Address" and a hw-address under "DUID".
    """

    def _stub(self, hosts, version=4):
        cidr = "198.18.0.0/24" if version == 4 else "2001:db8::/48"
        return {
            **_catalogue_responses(version, 1, cidr),
            "reservation-get-page": _res_page(hosts),
            f"lease{version}-get-by-state": {"result": 0, "arguments": {"leases": []}},
        }

    def _table(self, version, hosts):
        url = reverse(f"plugins:netbox_kea:combined_reservations{version}")
        with stub_kea(self._stub(hosts, version=version)):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.context["table"]

    def _cell(self, table, column_name):
        row = next(iter(table.rows))
        return str(row.get_cell(column_name))

    def test_v4_hw_address_column_is_empty_for_a_client_id_reservation(self):
        table = self._table(4, [{"subnet-id": 1, "client-id": "01aabbccddeeff", "hostname": "kiosk"}])
        # The domain value normalizes a client-id to colon-separated octets.
        normalized = "01:aa:bb:cc:dd:ee:ff"

        self.assertNotIn(normalized, self._cell(table, "hw_address"))
        self.assertIn(normalized, self._cell(table, "identifier"))
        self.assertIn("client-id", self._cell(table, "identifier"))

    def test_v4_hw_address_column_shows_a_hw_address_reservation(self):
        table = self._table(4, [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "printer"}])

        self.assertIn("aa:bb:cc:dd:ee:ff", self._cell(table, "hw_address"))

    def test_v6_duid_column_is_empty_for_a_hw_address_reservation(self):
        table = self._table(6, [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:ff", "hostname": "sensor"}])

        self.assertNotIn("aa:bb:cc:dd:ee:ff", self._cell(table, "duid"))
        self.assertIn("aa:bb:cc:dd:ee:ff", self._cell(table, "identifier"))

    def test_v6_duid_column_shows_a_duid_reservation(self):
        table = self._table(6, [{"subnet-id": 1, "duid": "00:01:00:01:12:34", "hostname": "laptop"}])

        self.assertIn("00:01:00:01:12:34", self._cell(table, "duid"))
