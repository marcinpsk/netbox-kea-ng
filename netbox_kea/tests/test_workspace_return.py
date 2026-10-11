# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Follow workspace links through real Server requests and Kea transport stubs."""

from urllib.parse import parse_qs, urlencode, urlsplit

from bs4 import BeautifulSoup
from django.test import override_settings
from django.urls import reverse

from .kea_stub import SubnetDaemon, _catalogue_responses_for_subnets, _network_present, _res_page, stub_kea
from .utils import _make_db_server, _page_data, _ViewTestBase


class TestWorkspaceReturn(_ViewTestBase):
    def test_return_validation_uses_the_same_path_as_real_application_navigation(self):
        invalid = reverse("plugins:netbox_kea:combined") + ";junk"
        quoted = reverse("plugins:netbox_kea:combined_reservations4").replace("reservations4", "%72eservations4")
        quoted += "?q=printer%20room#selected"
        form_url = reverse("plugins:netbox_kea:server_shared_network4_add", args=[self.server.pk])
        fallback = reverse("plugins:netbox_kea:server_shared_networks4", args=[self.server.pk])
        responses = {
            **_catalogue_responses_for_subnets(4, []),
            "reservation-get-page": {"result": 3},
        }
        for origin, status, destination in ((invalid, 404, fallback), (quoted, 200, quoted)):
            with self.subTest(origin=origin), stub_kea(responses):
                self.assertEqual(self.client.get(origin).status_code, status)
                form = BeautifulSoup(self.client.get(form_url, {"return_url": origin}).content, "html.parser")
                cancel = next(link for link in form.select("a") if link.text.strip() == "Cancel")
                self.assertEqual(cancel["href"], destination)

    def test_server_filter_forms_and_subsections_keep_the_workspace_destination(self):
        origin = reverse("plugins:netbox_kea:combined_reservations4") + "?q=printer&scope=subnet#selected"
        responses = {
            **_catalogue_responses_for_subnets(4, []),
            "reservation-get-page": {"result": 3},
            "stat-lease4-get": {"result": 3},
        }
        for section in ("reservations4", "leases4", "subnets4", "shared_networks4", "option_def4"):
            with self.subTest(section=section), stub_kea(responses):
                response = self.client.get(
                    reverse(f"plugins:netbox_kea:server_{section}", args=[self.server.pk]), {"return_url": origin}
                )
                page = BeautifulSoup(response.content, "html.parser")
                if section in ("reservations4", "leases4"):
                    form = (
                        page.select_one("#lease-search form")
                        if section == "leases4"
                        else page.select_one('form:has([name="scope"])')
                    )
                    self.assertIsNotNone(form)
                    hidden = form.select_one('input[name="return_url"]')
                    self.assertIsNotNone(hidden)
                    self.assertEqual(hidden["value"], origin)
                else:
                    links = page.select(".nav-tabs.mb-3 a")
                    self.assertEqual(len(links), 2)
                    for link in links:
                        self.assertEqual(parse_qs(urlsplit(link["href"]).query).get("return_url"), [origin])

    def test_successful_subnet_edits_from_emitted_links_return_to_the_combined_origin(self):
        other = _make_db_server(name="other-server")
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            origin = (
                reverse(f"plugins:netbox_kea:combined_subnets{family}")
                + "?"
                + urlencode([("server", self.server.pk), ("server", other.pk), ("q", cidr)])
            )
            daemon = SubnetDaemon(family, [{"id": 7, "subnet": cidr}])
            with (
                self.subTest(family=family),
                stub_kea({**daemon.responses(), f"stat-lease{family}-get": {"result": 3}}),
            ):
                combined = BeautifulSoup(self.client.get(origin).content, "html.parser")
                edit = next(link["href"] for link in combined.select("td a") if link.text.strip() == "Edit subnet")
                form = self.client.get(edit)
                result = self.client.post(edit, {**_page_data(form), "valid_lft": "3600"})
                self.assertEqual(daemon.subnet(7)["valid-lifetime"], 3600)
                shown = self.client.get(edit)
                self.assertEqual(shown.context["form"]["valid_lft"].value(), 3600)
                self.assertRedirects(result, origin, fetch_redirect_response=False)

    @override_settings(FORCE_SCRIPT_NAME="/netbox/")
    def test_valid_return_paths_keep_script_prefix_quoted_queries_and_fragments(self):
        origin = reverse("plugins:netbox_kea:combined_reservations6") + "?q=printer%20room&scope=subnet#selected"
        url = reverse("plugins:netbox_kea:server_shared_network6_add", args=[self.server.pk])
        response = self.client.get(url, {"return_url": origin})
        self.assertEqual(response.status_code, 200)
        page = BeautifulSoup(response.content, "html.parser")
        self.assertEqual(next(link for link in page.select("a") if link.text.strip() == "Cancel")["href"], origin)
        self.assertEqual(
            next(link for link in page.select("a") if link.text.strip().startswith("Back to"))["href"], origin
        )

    def test_native_delete_modal_posts_its_original_workspace_destination(self):
        origin = reverse("plugins:netbox_kea:combined_overview6") + "?server_scope=1"
        page = BeautifulSoup(
            self.client.get(self.server.get_absolute_url(), {"family": 6, "return_url": origin}).content, "html.parser"
        )
        delete_path = reverse("plugins:netbox_kea:server_delete", args=[self.server.pk])
        control = next(link for link in page.select("a[hx-get]") if urlsplit(link["hx-get"]).path == delete_path)
        modal = BeautifulSoup(self.client.get(control["hx-get"], HTTP_HX_REQUEST="true").content, "html.parser")
        form = modal.select_one('form[method="post"]')
        hidden = form.select_one('input[name="return_url"]')
        self.assertIsNotNone(hidden)
        self.assertEqual(hidden["value"], origin)
        result = self.client.post(form["action"], {"confirm": "true", "return_url": hidden["value"]})
        self.assertRedirects(result, origin, fetch_redirect_response=False)

    def test_mutation_forms_reject_external_malformed_and_unknown_return_paths(self):
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            responses = {
                **_catalogue_responses_for_subnets(family, [{"id": 7, "subnet": cidr}]),
                f"network{family}-get": _network_present(family, "clients"),
                f"network{family}-del": {"result": 1, "text": "Refused"},
            }
            routes = (
                (f"server_subnet{family}_delete", [self.server.pk, 7], f"server_subnets{family}"),
                (
                    f"server_shared_network{family}_delete",
                    [self.server.pk, "clients"],
                    f"server_shared_networks{family}",
                ),
                (f"server_reservation{family}_add", [self.server.pk], f"server_reservations{family}"),
            )
            for name, args, destination in routes:
                fallback = reverse(f"plugins:netbox_kea:{destination}", args=[self.server.pk])
                for bad in (
                    "https://example.invalid/",
                    "//example.invalid/",
                    "/\\example.invalid/",
                    "relative",
                    "/plugins/kea/combined/\\",
                    "/not-an-application-page/",
                    "/plugins/kea/combined/\n",
                ):
                    with self.subTest(family=family, route=name, value=bad), stub_kea(responses):
                        response = self.client.get(
                            reverse(f"plugins:netbox_kea:{name}", args=args), {"return_url": bad}
                        )
                        self.assertEqual(response.status_code, 200)
                        page = BeautifulSoup(response.content, "html.parser")
                        self.assertEqual(
                            next(link for link in page.select("a") if link.text.strip() == "Cancel")["href"], fallback
                        )
                        self.assertFalse(any(link.text.strip().startswith("Back to") for link in page.select("a")))
                        if bad.startswith("https:") and "reservation" not in name:
                            result = self.client.post(
                                reverse(f"plugins:netbox_kea:{name}", args=args) + "?" + urlencode({"return_url": bad})
                            )
                            self.assertRedirects(result, fallback, fetch_redirect_response=False)

    def test_shared_network_actions_cancel_and_complete_at_the_original_workspace(self):
        other = _make_db_server(name="other-server")
        for family in (4, 6):
            origin = (
                reverse(f"plugins:netbox_kea:combined_shared_networks{family}")
                + "?"
                + urlencode([("server", self.server.pk), ("server", other.pk), ("per_page", 25)])
            )
            responses = {
                **_catalogue_responses_for_subnets(family, [], shared_networks=[{"name": "clients"}]),
                "config-test": {"result": 0},
                "config-set": {"result": 0},
                "config-write": {"result": 0},
                f"network{family}-del": {"result": 0},
                f"network{family}-get": _network_present(family, "clients"),
            }
            with stub_kea(responses) as kea:
                page = BeautifulSoup(self.client.get(origin).content, "html.parser")
                actions = page.select('td a[aria-label^="Edit"], td a[aria-label^="Delete"]')
                self.assertEqual(len(actions), 4)
                for link in actions:
                    with self.subTest(family=family, action=link["href"]):
                        self.assertEqual(parse_qs(urlsplit(link["href"]).query).get("return_url"), [origin])
                        response = self.client.get(link["href"])
                        form = BeautifulSoup(response.content, "html.parser")
                        self.assertEqual(
                            next(link for link in form.select("a") if link.text.strip() == "Cancel")["href"], origin
                        )
                        data = {**_page_data(response), "description": "Updated"} if "/edit/" in link["href"] else {}
                        result = self.client.post(link["href"], data)
                        self.assertRedirects(result, origin, fetch_redirect_response=False)
                self.assertIn("config-set", kea.commands())
                self.assertIn(f"network{family}-del", kea.commands())

    def test_combined_subnet_actions_keep_origin_through_cancel_and_refusal(self):
        other = _make_db_server(name="other-server")
        for family, cidr, pool in (
            (4, "198.18.0.0/24", "198.18.0.32-198.18.0.63"),
            (6, "2001:db8::/64", "2001:db8::20-2001:db8::3f"),
        ):
            origin = (
                reverse(f"plugins:netbox_kea:combined_subnets{family}")
                + "?"
                + urlencode([("server", self.server.pk), ("server", other.pk), ("q", cidr)])
            )
            responses = {
                **_catalogue_responses_for_subnets(family, [{"id": 7, "subnet": cidr, "pools": [{"pool": pool}]}]),
                f"stat-lease{family}-get": {"result": 3},
                f"lease{family}-wipe": {"result": 1, "text": "Refused"},
            }
            with stub_kea(responses):
                page = BeautifulSoup(self.client.get(origin).content, "html.parser")
                actions = [link for link in page.select("td a") if f"/subnets{family}/7/" in link["href"]]
                self.assertEqual(len({urlsplit(link["href"]).path for link in actions}), 12)
                for link in actions:
                    with self.subTest(family=family, action=link["href"]):
                        self.assertEqual(parse_qs(urlsplit(link["href"]).query).get("return_url"), [origin])
                        form_page = BeautifulSoup(self.client.get(link["href"]).content, "html.parser")
                        cancel = next(node for node in form_page.select("a") if node.text.strip() == "Cancel")
                        self.assertEqual(cancel["href"], origin)
                        refused = self.client.post(link["href"])
                        if refused.status_code == 302:
                            self.assertEqual(refused.url, origin)
                        else:
                            self.assertEqual(refused.status_code, 200)
                            redisplayed = BeautifulSoup(refused.content, "html.parser")
                            self.assertEqual(
                                next(node for node in redisplayed.select("a") if node.text.strip() == "Cancel")["href"],
                                origin,
                            )

    def test_server_navigation_and_reservation_edits_keep_the_combined_origin(self):
        other = _make_db_server(name="other-server")
        origin = (
            reverse("plugins:netbox_kea:combined_reservations4")
            + "?"
            + urlencode([("server", self.server.pk), ("server", other.pk), ("q", "printer"), ("scope", "subnet")])
        )
        record = {"subnet-id": 7, "hw-address": "02:00:00:00:00:01", "ip-address": "198.18.0.10", "hostname": "printer"}
        responses = {
            **_catalogue_responses_for_subnets(4, [{"id": 7, "subnet": "198.18.0.0/24"}]),
            "reservation-get-page": _res_page([record]),
            "lease4-get": {"result": 3},
            "lease4-get-by-state": {"result": 3},
        }
        with stub_kea(responses):
            combined = BeautifulSoup(self.client.get(origin).content, "html.parser")
            target = next(link["href"] for link in combined.select("td a") if link.text == self.server.name)
            page = BeautifulSoup(self.client.get(target).content, "html.parser")
            links = page.select(
                '[aria-label="Workspace sections"] a, [aria-label="DHCP family"] a, [aria-label="Server object tabs"] a'
            )
            self.assertGreater(len(links), 8)
            for link in links:
                self.assertEqual(parse_qs(urlsplit(link["href"]).query).get("return_url"), [origin], link["href"])
            edits = [
                link for link in page.select("td a") if "/reservations4/" in link["href"] and "/edit/" in link["href"]
            ]
            self.assertEqual(len(edits), 1)
            self.assertEqual(parse_qs(urlsplit(edits[0]["href"]).query).get("return_url"), [origin])

    def test_shared_network_and_reservation_links_keep_server_identity_and_origin(self):
        other = _make_db_server(name="other-server")
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            record = {"subnet-id": 7, "hw-address": "02:00:00:00:00:01"}
            if family == 4:
                record["ip-address"] = "198.18.0.10"
            else:
                record["ip-addresses"] = ["2001:db8::10"]
            responses = {
                **_catalogue_responses_for_subnets(
                    family, [{"id": 7, "subnet": cidr}], shared_networks=[{"name": "clients"}]
                ),
                "reservation-get-page": _res_page([record]),
                f"lease{family}-get": {"result": 3},
                f"lease{family}-get-by-state": {"result": 3},
            }
            for section, label in (("shared_networks", "clients"), ("reservations", record["hw-address"])):
                origin = (
                    reverse(f"plugins:netbox_kea:combined_{section}{family}")
                    + "?"
                    + urlencode(
                        [("server", self.server.pk), ("server", other.pk), ("sort", "server"), ("per_page", 25)]
                    )
                )
                with self.subTest(family=family, section=section), stub_kea(responses):
                    page = BeautifulSoup(self.client.get(origin).content, "html.parser")
                    links = [link for link in page.select("td a") if link.text.strip() == label]
                    self.assertEqual(len(links), 2)
                    for server in (self.server, other):
                        path = reverse(f"plugins:netbox_kea:server_{section}{family}", args=[server.pk])
                        link = next(link for link in links if urlsplit(link["href"]).path == path)
                        self.assertEqual(parse_qs(urlsplit(link["href"]).query).get("return_url"), [origin])
                        server_link = next(link for link in page.select("td a") if link.text == server.name)
                        self.assertEqual(server_link["href"], link["href"])

    def test_overview_cards_enter_server_sections_with_family_and_previous_workspace(self):
        other = _make_db_server(name="other-server")
        for family in (4, 6):
            origin = (
                reverse(f"plugins:netbox_kea:combined_overview{family}")
                + "?"
                + urlencode([("server", self.server.pk), ("server", other.pk)])
            )
            page = BeautifulSoup(self.client.get(origin).content, "html.parser")
            for card in page.select(".card.h-100"):
                server = next(
                    server for server in (self.server, other) if server.name in card.select_one(".card-header").text
                )
                for link in card.select("a"):
                    with self.subTest(family=family, target=link["href"]):
                        self.assertTrue(urlsplit(link["href"]).path.startswith(server.get_absolute_url()))
                        query = parse_qs(urlsplit(link["href"]).query)
                        self.assertEqual(query.get("return_url"), [origin])
                        if urlsplit(link["href"]).path == server.get_absolute_url():
                            self.assertEqual(query.get("family"), [str(family)])

    def test_identical_combined_subnets_open_their_owning_server_section(self):
        other = _make_db_server(name="other-server")
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            origin = (
                reverse(f"plugins:netbox_kea:combined_subnets{family}")
                + "?"
                + urlencode(
                    [
                        ("server", self.server.pk),
                        ("server", other.pk),
                        ("q", cidr),
                        ("subnet_id", 7),
                        ("sort", "subnet"),
                    ]
                )
            )
            with (
                self.subTest(family=family),
                stub_kea(
                    {
                        **_catalogue_responses_for_subnets(family, [{"id": 7, "subnet": cidr}]),
                        f"stat-lease{family}-get": {"result": 3},
                    }
                ),
            ):
                response = self.client.get(origin)
                page = BeautifulSoup(response.content, "html.parser")
                links = [link for link in page.select("td a") if link.text == cidr]
                self.assertEqual(len(links), 2)
                self.assertEqual(
                    {urlsplit(link["href"]).path for link in links},
                    {
                        reverse(f"plugins:netbox_kea:server_subnets{family}", args=[server.pk])
                        for server in (self.server, other)
                    },
                )
                for link in links:
                    self.assertEqual(parse_qs(urlsplit(link["href"]).query)["return_url"], [origin])
                    destination = BeautifulSoup(self.client.get(link["href"]).content, "html.parser")
                    back = next(link for link in destination.select("a") if link.text.strip().startswith("Back to"))
                    self.assertEqual(back["href"], origin)
