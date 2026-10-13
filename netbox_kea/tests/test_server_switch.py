# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Switch Servers through the emitted scope-bar links and real request handling."""

import json
from urllib.parse import parse_qs, urlsplit

import requests
from bs4 import BeautifulSoup
from django.contrib.contenttypes.models import ContentType
from django.contrib.messages import get_messages
from django.urls import reverse
from users.models import ObjectPermission

from netbox_kea import subnet_catalogue
from netbox_kea.models import Server

from .kea_stub import _catalogue_responses_for_subnets, _res_page, stub_kea
from .utils import _make_db_server, _ViewTestBase


class TestServerSwitch(_ViewTestBase):
    def test_failed_automatic_lease_search_also_replaces_history(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with stub_kea(_catalogue_responses_for_subnets(4, [])):
            full_page = self.client.get(url, {"state": "0"})
        form = BeautifulSoup(full_page.content, "html.parser").select_one("#lease-search form")
        headers = json.loads(form["hx-headers"])
        with stub_kea(
            {
                **_catalogue_responses_for_subnets(4, []),
                "lease4-get-page": requests.ConnectionError("Unavailable"),
            }
        ):
            response = self.client.get(
                url,
                {"q": "", "state": "0", "by": ""},
                headers={
                    "HX-Request": "true",
                    "HX-Current-URL": "http://testserver" + url + "?state=0",
                    **headers,
                },
            )
        self.assertContains(response, "Failed to query server")
        self.assertIn("HX-Replace-Url", response.headers)
        self.assertNotIn("HX-Push-Url", response.headers)

    def test_state_only_lease_auto_load_replaces_history_after_a_subnet_filter_is_dropped(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        with stub_kea(_catalogue_responses_for_subnets(4, [])):
            full_page = self.client.get(url, {"state": "0"})
        form = BeautifulSoup(full_page.content, "html.parser").select_one("#lease-search form")
        self.assertEqual(form["hx-trigger"], "load")
        self.assertIsNotNone(form.get("hx-headers"))
        headers = json.loads(form["hx-headers"])
        responses = {
            **_catalogue_responses_for_subnets(4, []),
            "lease4-get-page": {"result": 0, "arguments": {"leases": [], "count": 0}},
        }
        with stub_kea(responses):
            response = self.client.get(
                url,
                {"q": "", "state": "0", "by": ""},
                headers={"HX-Request": "true", "HX-Current-URL": "http://testserver" + url + "?state=0", **headers},
            )
        self.assertIn("HX-Replace-Url", response.headers)
        self.assertNotIn("HX-Push-Url", response.headers)
        with stub_kea(responses):
            user_search = self.client.get(
                url,
                {"q": "", "state": "0", "by": ""},
                HTTP_HX_REQUEST="true",
                HTTP_HX_CURRENT_URL="http://testserver" + url + "?state=0",
            )
        self.assertIn("HX-Push-Url", user_search.headers)

    def test_switching_from_options_editor_opens_view_only_target_configuration(self):
        target = _make_db_server(name="view-only-server", dhcp6=False)
        self.user.is_superuser = False
        self.user.save()
        for action, pks in (("view", [self.server.pk, target.pk]), ("change", [self.server.pk])):
            permission = ObjectPermission.objects.create(
                name=f"options-switch-{action}", actions=[action], constraints={"pk__in": pks}
            )
            permission.object_types.add(ContentType.objects.get_for_model(Server))
            permission.users.add(self.user)
        self.client.force_login(self.user)
        with stub_kea(_catalogue_responses_for_subnets(4, [])):
            source = self.client.get(reverse("plugins:netbox_kea:server_dhcp4_options_edit", args=[self.server.pk]))
        self.assertEqual(source.status_code, 200)
        page = BeautifulSoup(source.content, "html.parser")
        link = next(
            node for node in page.select('nav[aria-label="Switch Server"] a') if node.text.strip() == target.name
        )
        with stub_kea(_catalogue_responses_for_subnets(4, [])):
            destination = self.client.get(link["href"], follow=True)
        self.assertEqual(destination.status_code, 200)
        self.assertEqual(
            destination.redirect_chain[0][0], reverse("plugins:netbox_kea:server_option_def4", args=[target.pk])
        )
        self.assertEqual(
            BeautifulSoup(destination.content, "html.parser")
            .select_one('[aria-label="Workspace sections"] [aria-current="page"]')
            .text,
            "Configuration",
        )
        with stub_kea(_catalogue_responses_for_subnets(6, [])):
            source6 = self.client.get(reverse("plugins:netbox_kea:server_dhcp6_options_edit", args=[self.server.pk]))
            page6 = BeautifulSoup(source6.content, "html.parser")
            link6 = next(
                node for node in page6.select('nav[aria-label="Switch Server"] a') if node.text.strip() == target.name
            )
        with stub_kea({}) as kea:
            disabled = self.client.get(link6["href"], follow=True)
        self.assertContains(disabled, "Protocol not enabled")
        self.assertEqual(kea.commands(), [])

    def test_automatic_lease_search_replaces_the_current_history_entry(self):
        url = reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk])
        responses = {
            **_catalogue_responses_for_subnets(4, []),
            "lease4-get-by-hostname": {"result": 0, "arguments": {"leases": []}},
        }
        query = {"q": "printer", "by": "hostname", "state": ""}
        current = "http://testserver" + url + "?by=hostname&q=printer"
        with stub_kea(responses):
            response = self.client.get(url, query, HTTP_HX_REQUEST="true", HTTP_HX_CURRENT_URL=current)
        # Same search: keep the address bar as it is, so the history entry does not change under the reader.
        self.assertEqual(response.get("HX-Replace-Url"), url + "?by=hostname&q=printer")
        self.assertNotIn("HX-Push-Url", response.headers)
        with stub_kea(responses):
            changed = self.client.get(url, query, HTTP_HX_REQUEST="true", HTTP_HX_CURRENT_URL="http://testserver" + url)
        self.assertEqual(changed.get("HX-Push-Url"), url + "?q=printer&by=hostname")
        self.assertNotIn("HX-Replace-Url", changed.headers)

    def test_all_servers_link_keeps_the_section_family_and_search(self):
        with stub_kea(_catalogue_responses_for_subnets(6, [])):
            response = self.client.get(
                reverse("plugins:netbox_kea:server_leases6", args=[self.server.pk]),
                {"q": "printer", "by": "hostname", "state": "0", "page": "2"},
            )
        page = BeautifulSoup(response.content, "html.parser")
        all_servers = next(
            link for link in page.select('nav[aria-label="Switch Server"] a') if link.text == "All Servers"
        )
        self.assertEqual(urlsplit(all_servers["href"]).path, reverse("plugins:netbox_kea:combined_leases6"))
        self.assertEqual(
            parse_qs(urlsplit(all_servers["href"]).query), {"q": ["printer"], "by": ["hostname"], "state": ["0"]}
        )

    def test_switching_from_a_record_form_opens_the_section_without_copying_the_record(self):
        target = _make_db_server(name="second-server")
        with stub_kea({}):
            source = self.client.get(
                reverse("plugins:netbox_kea:server_shared_network6_delete", args=[self.server.pk, "clients"])
            )
        page = BeautifulSoup(source.content, "html.parser")
        link = next(
            node for node in page.select('nav[aria-label="Switch Server"] a') if node.text.strip() == target.name
        )
        with stub_kea({}) as kea:
            switched = self.client.get(link["href"])
        self.assertEqual(
            urlsplit(switched.url).path, reverse("plugins:netbox_kea:server_shared_networks6", args=[target.pk])
        )
        self.assertEqual(parse_qs(urlsplit(switched.url).query), {})
        self.assertTrue(
            any("Record selection dropped" in str(message) for message in get_messages(switched.wsgi_request))
        )
        self.assertEqual(kea.commands(), [])

    def test_permitted_reservation_filters_and_previous_selection_survive_switching(self):
        target = _make_db_server(name="second-server", ca_url="http://target.example.invalid/")
        previous = (
            reverse("plugins:netbox_kea:combined_reservations6")
            + f"?server={self.server.pk}&server={target.pk}&q=printer"
        )
        url = reverse("plugins:netbox_kea:server_switch", args=[self.server.pk])
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            with (
                self.subTest(family=family),
                stub_kea(_catalogue_responses_for_subnets(family, [{"id": 7, "subnet": cidr}])) as kea,
            ):
                response = self.client.get(
                    url,
                    {
                        "target": target.pk,
                        "section": "reservations",
                        "family": family,
                        "q": "printer",
                        "subnet_id": "7",
                        "scope": "in-subnet",
                        "cursor": "old-server-cursor",
                        "page": "3",
                        "export": "yaml",
                        "return_url": previous,
                    },
                )
            self.assertEqual(
                urlsplit(response.url).path,
                reverse(f"plugins:netbox_kea:server_reservations{family}", args=[target.pk]),
            )
            self.assertEqual(
                parse_qs(urlsplit(response.url).query),
                {
                    "q": ["printer"],
                    "subnet_id": ["7"],
                    "scope": ["in-subnet"],
                    "return_url": [previous],
                },
            )
            self.assertEqual(kea.commands(), [f"subnet{family}-list"])
            self.assertEqual(kea.urls(), [target.ca_url])
            self.assertEqual(list(get_messages(response.wsgi_request)), [])
            with stub_kea(
                {
                    **_catalogue_responses_for_subnets(family, [{"id": 7, "subnet": cidr}]),
                    "reservation-get-page": _res_page([]),
                }
            ):
                destination = self.client.get(response.url)
            self.assertEqual(destination.status_code, 200)
            page = BeautifulSoup(destination.content, "html.parser")
            self.assertEqual(page.select_one("#id_q")["value"], "printer")
            self.assertEqual(page.select_one("#id_subnet_id option[selected]")["value"], "7")
            self.assertEqual(page.select_one("#id_scope option[selected]")["value"], "in-subnet")
            self.assertEqual(page.select_one('[aria-label="Server Scope"]').text, target.name)

    def test_lease_subnet_search_uses_fresh_target_identities(self):
        target = _make_db_server(name="second-server")
        url = reverse("plugins:netbox_kea:server_switch", args=[self.server.pk])
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            for by, q in (("subnet_id", "7"), ("subnet", cidr)):
                with self.subTest(family=family, by=by):
                    # A cached display still contains the Subnet after the target removes it.
                    with stub_kea(_catalogue_responses_for_subnets(family, [{"id": 7, "subnet": cidr}])):
                        subnet_catalogue.display(target, family)
                    with stub_kea(_catalogue_responses_for_subnets(family, [])) as kea:
                        response = self.client.get(
                            url, {"target": target.pk, "section": "leases", "family": family, "by": by, "q": q}
                        )
                    self.assertEqual(parse_qs(urlsplit(response.url).query), {})
                    self.assertEqual(kea.commands(), [f"subnet{family}-list"])
                    self.assertTrue(any("Subnet filter dropped" in str(m) for m in get_messages(response.wsgi_request)))

    def test_unavailable_target_drops_only_subnet_filter_and_reports_failed_read(self):
        target = _make_db_server(name="second-server")
        with stub_kea({"subnet4-list": requests.ConnectionError("private transport details")}) as kea:
            response = self.client.get(
                reverse("plugins:netbox_kea:server_switch", args=[self.server.pk]),
                {
                    "target": target.pk,
                    "section": "reservations",
                    "family": "4",
                    "subnet_id": "7",
                    "q": "printer",
                },
            )
        self.assertEqual(parse_qs(urlsplit(response.url).query), {"q": ["printer"]})
        notices = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertIn("Failed to load subnet configuration from Kea.", notices)
        self.assertTrue(any("Subnet filter dropped" in message for message in notices))
        self.assertNotIn("private transport details", " ".join(notices))
        self.assertEqual(kea.commands(), ["subnet4-list"])

    def test_disabled_target_keeps_requested_family_without_kea_reads(self):
        target = _make_db_server(name="only-four", dhcp6=False)
        with stub_kea({}) as kea:
            response = self.client.get(
                reverse("plugins:netbox_kea:server_switch", args=[self.server.pk]),
                {
                    "target": target.pk,
                    "section": "leases",
                    "family": "6",
                    "q": "printer",
                    "by": "hostname",
                },
                follow=True,
            )
        self.assertContains(response, "Protocol not enabled")
        self.assertEqual(
            BeautifulSoup(response.content, "html.parser").select_one('[aria-label="Server Scope"]').text, target.name
        )
        self.assertTrue(response.redirect_chain[0][0].split("?")[0].endswith("/leases6/"))
        self.assertEqual(kea.commands(), [])

    def test_selector_and_endpoint_enforce_view_permissions_for_both_servers(self):
        target = _make_db_server(name="visible-server")
        hidden = _make_db_server(name="hidden-server")
        self.user.is_superuser = False
        self.user.save()
        permission = ObjectPermission.objects.create(
            name="visible-switch-servers", actions=["view"], constraints={"pk__in": [self.server.pk, target.pk]}
        )
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(self.user)
        self.client.force_login(self.user)
        with stub_kea({}) as kea:
            page = BeautifulSoup(self.client.get(self.server.get_absolute_url()).content, "html.parser")
            offered = page.select_one('nav[aria-label="Switch Server"]').text
            self.assertIn(target.name, offered)
            self.assertNotIn(hidden.name, offered)
            for source, destination in ((self.server, hidden), (hidden, target)):
                response = self.client.get(
                    reverse("plugins:netbox_kea:server_switch", args=[source.pk]), {"target": destination.pk}
                )
                self.assertEqual(response.status_code, 404)
        self.assertEqual(kea.commands(), [])

    def test_invalid_target_values_are_refused_without_kea_reads(self):
        url = reverse("plugins:netbox_kea:server_switch", args=[self.server.pk])
        for target in ("", "bad", "-1", "١", "9" * 500, "999999", None):
            with self.subTest(target=target), stub_kea({}) as kea:
                query = {"section": "leases", "family": "4"}
                if target is not None:
                    query["target"] = target
                response = self.client.get(url, query)
            self.assertIn(response.status_code, (400, 404))
            self.assertEqual(kea.commands(), [])

    def test_missing_subnet_filter_is_dropped_with_an_explanation(self):
        target = _make_db_server(name="second-server")
        url = reverse("plugins:netbox_kea:server_switch", args=[self.server.pk])
        for section, search in (
            ("reservations", {"subnet_id": "7", "q": "printer", "scope": "in-subnet"}),
            ("leases", {"by": "subnet_id", "q": "7", "state": "0"}),
        ):
            with self.subTest(section=section), stub_kea(_catalogue_responses_for_subnets(4, [])):
                response = self.client.get(url, {"target": target.pk, "section": section, "family": "4", **search})
            self.assertEqual(response.status_code, 302)
            query = parse_qs(urlsplit(response.url).query)
            self.assertNotIn("subnet_id", query)
            if section == "leases":
                self.assertNotIn("q", query)
                self.assertNotIn("by", query)
                self.assertEqual(query["state"], ["0"])
            else:
                self.assertEqual(query, {"q": ["printer"], "scope": ["in-subnet"]})
            self.assertTrue(
                any("Subnet filter dropped" in str(message) for message in get_messages(response.wsgi_request))
            )

    def test_lease_search_switch_keeps_filters_and_resets_pagination(self):
        target = _make_db_server(name="second-server")
        responses = _catalogue_responses_for_subnets(4, [])
        with stub_kea(responses):
            source = self.client.get(
                reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]),
                {"q": "printer", "by": "hostname", "state": "0", "page": "2", "per_page": "50"},
            )
        page = BeautifulSoup(source.content, "html.parser")
        selector = page.select_one('nav[aria-label="Switch Server"]')
        self.assertIsNotNone(selector)
        link = next(node for node in selector.select("a") if node.text.strip() == target.name)
        with stub_kea({}) as kea:
            switched = self.client.get(link["href"])
        self.assertEqual(switched.status_code, 302)
        self.assertEqual(urlsplit(switched.url).path, reverse("plugins:netbox_kea:server_leases4", args=[target.pk]))
        self.assertEqual(
            parse_qs(urlsplit(switched.url).query),
            {"q": ["printer"], "by": ["hostname"], "state": ["0"], "per_page": ["50"]},
        )
        self.assertEqual(kea.commands(), [])
        with stub_kea(responses):
            destination = self.client.get(switched.url)
        result = BeautifulSoup(destination.content, "html.parser")
        self.assertEqual(result.select_one('[aria-label="Server Scope"]').text, target.name)
        self.assertEqual(result.select_one("#id_q")["value"], "printer")
