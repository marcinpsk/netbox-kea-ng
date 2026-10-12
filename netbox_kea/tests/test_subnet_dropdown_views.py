# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Reservation pages offer the configured Subnets as dropdowns labelled with CIDR and Kea Subnet ID."""

from unittest.mock import patch

import requests
from bs4 import BeautifulSoup
from django.urls import reverse

from netbox_kea import subnet_catalogue
from netbox_kea.views.notices import HEADLINES

from .kea_stub import (
    _catalogue_responses_for_subnets,
    _res_get,
    _res_page,
    _reservation_mutation_commands,
    stub_kea,
)
from .test_reservation_mutation_views import _identity_query, _mutation_responses
from .utils import _make_db_server, _ViewTestBase


def _options(response, selector: str) -> list[tuple[str, str, bool]]:
    page = BeautifulSoup(response.content, "html.parser")
    return [(str(o["value"]), o.get_text(), o.has_attr("selected")) for o in page.select(f"{selector} option")]


def _list_responses(family: int, subnets: list[dict]) -> dict:
    return {
        **_catalogue_responses_for_subnets(family, subnets),
        "reservation-get-page": _res_page([]),
        "list-commands": _reservation_mutation_commands(),
    }


class TestReservationSubnetIdFilter(_ViewTestBase):
    """The Subnet ID filter of a Server's Reservations lists that Server's Subnets."""

    _SUBNETS = [{"id": 7, "subnet": "198.18.7.0/24"}, {"id": 2, "subnet": "198.18.2.0/24"}]

    def _get(self, query: dict, responses: dict | None = None):
        url = reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk])
        with stub_kea(responses or _list_responses(4, self._SUBNETS)):
            response = self.client.get(url, query)
        self.assertEqual(response.status_code, 200)
        return response

    def test_the_filter_offers_all_subnets_and_each_subnet_by_cidr_and_id(self):
        response = self._get({"subnet_id": "7"})
        self.assertEqual(
            _options(response, "#id_subnet_id"),
            [
                ("", "All subnets", False),
                ("2", "198.18.2.0/24 (ID 2)", False),
                ("7", "198.18.7.0/24 (ID 7)", True),
            ],
        )

    def test_a_filter_value_that_the_catalogue_does_not_list_stays_selected(self):
        response = self._get({"subnet_id": "42"})
        self.assertIn(("42", "42 (not in the current configuration)", True), _options(response, "#id_subnet_id"))
        self.assertEqual(response.context["search_form"].cleaned_data["subnet_id"], 42)

    def test_without_catalogue_subnets_the_filter_stays_a_number_input(self):
        response = self._get({"subnet_id": "7"}, _list_responses(4, []))
        control = BeautifulSoup(response.content, "html.parser").select_one("#id_subnet_id")
        self.assertEqual((control.name, control["type"], control["value"]), ("input", "number", "7"))

    def test_an_unreachable_server_is_not_read_again_for_the_filter(self):
        responses = {
            **_catalogue_responses_for_subnets(4, self._SUBNETS),
            "reservation-get-page": requests.ConnectionError,
        }
        with stub_kea(responses) as kea:
            response = self.client.get(reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands().count("config-get"), 1)
        control = BeautifulSoup(response.content, "html.parser").select_one("#id_subnet_id")
        self.assertEqual(control.name, "input")


class TestCombinedReservationSubnetIdFilter(_ViewTestBase):
    """On All Servers each Subnet ID option names the CIDR that the ID has on each Server."""

    def test_one_option_per_subnet_id_names_the_cidr_on_each_server(self):
        second = _make_db_server(name="kea-b", ca_url="https://kea-b.example.com")
        self.server.name = "kea-a"
        self.server.save()
        # Each Server's Catalogue is cached, so the page reads it without another Kea request.
        for server, subnets in (
            (self.server, [{"id": 1, "subnet": "10.63.125.0/24"}, {"id": 3, "subnet": "10.63.3.0/24"}]),
            (second, [{"id": 1, "subnet": "10.1.0.0/24"}]),
        ):
            with stub_kea(_catalogue_responses_for_subnets(4, subnets)):
                subnet_catalogue.display(server, 4)
        url = reverse("plugins:netbox_kea:combined_reservations4")
        responses = {
            "reservation-get-page": _res_page([]),
            "list-commands": _reservation_mutation_commands(),
            # The mutation capability read takes the configuration; the Catalogue needs no new read.
            "config-get": _catalogue_responses_for_subnets(4, [])["config-get"],
        }
        with stub_kea(responses) as kea:
            response = self.client.get(url, {"server": [self.server.pk, second.pk], "subnet_id": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("subnet4-list", kea.commands())
        self.assertEqual(
            _options(response, "#id_subnet_id"),
            [
                ("", "All subnets", False),
                ("1", "1: 10.63.125.0/24 (kea-a), 10.1.0.0/24 (kea-b)", True),
                ("3", "3: 10.63.3.0/24 (kea-a)", False),
            ],
        )
        # The filter still means this Subnet ID on every selected Server.
        self.assertEqual({body["arguments"].get("subnet-id") for body in kea.bodies("reservation-get-page")}, {1})

    def test_a_server_whose_reservations_are_exhausted_keeps_its_subnets_on_later_pages(self):
        second = _make_db_server(name="kea-b", ca_url="https://kea-b.example.com")
        self.server.name = "kea-a"
        self.server.save()
        for server, subnets in (
            (self.server, [{"id": 1, "subnet": "10.63.125.0/24"}, {"id": 5, "subnet": "10.63.5.0/24"}]),
            (second, [{"id": 1, "subnet": "10.1.0.0/24"}]),
        ):
            with stub_kea(_catalogue_responses_for_subnets(4, subnets)):
                subnet_catalogue.display(server, 4)
        responses = {
            "reservation-get-page": _res_page([]),
            "list-commands": _reservation_mutation_commands(),
            "config-get": _catalogue_responses_for_subnets(4, [])["config-get"],
        }
        query = {
            "server": [self.server.pk, second.pk],
            f"reservation_cursor_{self.server.pk}": "done",
            f"reservation_cursor_{second.pk}": "WzEsNV0",
        }
        with stub_kea(responses) as kea:
            response = self.client.get(reverse("plugins:netbox_kea:combined_reservations4"), query)
        self.assertEqual(response.status_code, 200)
        # Page 2 reads the Reservations of kea-b only.
        self.assertEqual(len(kea.bodies("reservation-get-page")), 1)
        self.assertNotIn("subnet4-list", kea.commands())
        self.assertEqual(
            _options(response, "#id_subnet_id"),
            [
                ("", "All subnets", True),
                ("1", "1: 10.63.125.0/24 (kea-a), 10.1.0.0/24 (kea-b)", False),
                ("5", "5: 10.63.5.0/24 (kea-a)", False),
            ],
        )

    def test_an_exhausted_server_whose_catalogue_fails_is_reported_and_unlisted_ids_are_not_called_absent(self):
        second = _make_db_server(name="kea-b", ca_url="https://kea-b.example.com")
        self.server.name = "kea-a"
        self.server.save()
        # Only kea-b has a cached Catalogue; the Catalogue cache of kea-a has expired.
        with stub_kea(_catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "10.1.0.0/24"}])):
            subnet_catalogue.display(second, 4)
        responses = {
            "reservation-get-page": _res_page([]),
            "list-commands": _reservation_mutation_commands(),
            **_catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "10.1.0.0/24"}]),
        }
        query = {
            "server": [self.server.pk, second.pk],
            "subnet_id": "5",
            f"reservation_cursor_{self.server.pk}": "done",
            f"reservation_cursor_{second.pk}": "WzEsNV0",
        }
        with stub_kea(responses) as kea:
            answered = requests.Session.post
            unanswered = []

            def post(session, url, **kwargs):
                # kea-a does not answer.
                if url.startswith(self.server.ca_url):
                    unanswered.append(kwargs["json"]["command"])
                    raise requests.ConnectionError("kea-a is down")
                return answered(session, url, **kwargs)

            with patch("netbox_kea.kea.requests.Session.post", new=post):
                response = self.client.get(reverse("plugins:netbox_kea:combined_reservations4"), query)
        self.assertEqual(response.status_code, 200)
        # kea-a is read only for its expired Catalogue; kea-b answers from its cached Catalogue.
        self.assertIn("subnet4-list", unanswered)
        self.assertNotIn("reservation-get-page", unanswered)
        self.assertNotIn("subnet4-list", kea.commands())
        self.assertIn(("kea-a", HEADLINES["catalogue"]), response.context["errors"])
        self.assertContains(response, HEADLINES["catalogue"])
        self.assertEqual(
            _options(response, "#id_subnet_id"),
            [
                ("", "All subnets", False),
                ("1", "1: 10.1.0.0/24 (kea-b)", False),
                ("5", "5 (not listed)", True),
            ],
        )


class TestReservationFormSubnetDropdown(_ViewTestBase):
    """The Reservation form picks its Subnet from a dropdown labelled with CIDR and Kea Subnet ID."""

    def test_the_add_form_offers_the_subnets_and_submits_the_cidr(self):
        for family, cidr in ((4, "198.18.0.0/24"), (6, "2001:db8::/64")):
            with self.subTest(family=family):
                url = reverse(f"plugins:netbox_kea:server_reservation{family}_add", args=[self.server.pk])
                with stub_kea(_mutation_responses(family, 20, cidr, ["hw-address", "duid"])):
                    response = self.client.get(url, {"subnet_cidr": cidr})
                self.assertEqual(
                    _options(response, "#id_subnet_cidr"), [("", "---------", False), (cidr, f"{cidr} (ID 20)", True)]
                )
                self.assertNotContains(response, '<datalist id="kea-reservation-subnet-cidrs"')
                self.assertNotContains(response, 'list="kea-reservation')
                page = BeautifulSoup(response.content, "html.parser")
                self.assertEqual(
                    page.select_one("#id_subnet_cidr_helptext").get_text(), "Subnet the reservation belongs to."
                )
                preview = page.select_one("#published-name-preview")
                self.assertIn("change from:#id_subnet_cidr", preview["hx-trigger"])

    def test_without_catalogue_subnets_the_add_form_keeps_the_text_input(self):
        url = reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk])
        responses = {
            **_catalogue_responses_for_subnets(4, []),
            "list-commands": _reservation_mutation_commands(),
        }
        with stub_kea(responses):
            response = self.client.get(url)
        control = BeautifulSoup(response.content, "html.parser").select_one("#id_subnet_cidr")
        self.assertEqual((control.name, control["type"]), ("input", "text"))

    def test_the_edit_form_shows_the_subnet_disabled_with_its_label(self):
        url = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        responses = _mutation_responses(4, 20, "198.18.0.0/24", ["hw-address"])
        responses["reservation-get"] = _res_get({"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:ff"})
        with stub_kea(responses):
            response = self.client.get(f"{url}?{_identity_query()}")
        self.assertEqual(response.status_code, 200)
        control = BeautifulSoup(response.content, "html.parser").select_one("#id_subnet_cidr")
        self.assertEqual(control.name, "select")
        self.assertTrue(control.has_attr("disabled"))
        self.assertEqual(
            _options(response, "#id_subnet_cidr"),
            [("", "---------", False), ("198.18.0.0/24", "198.18.0.0/24 (ID 20)", True)],
        )
