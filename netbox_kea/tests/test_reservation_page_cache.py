# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Reservation pages serve each page from the display cache, show its read age and offer a Refresh (ADR 0009)."""

import json
from dataclasses import replace
from datetime import timedelta
from typing import Any

import requests
from bs4 import BeautifulSoup
from django.core.cache import cache
from django.urls import reverse

from netbox_kea import display_cache

from .kea_stub import _catalogue_responses, _res_get, _res_page, queued, stub_kea
from .utils import _make_db_server, _ViewTestBase, with_display_cache_config

_CIDR = "198.18.0.0/24"
_OLD = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.21", "hostname": "old"}
_NEW = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:02", "ip-address": "198.18.0.22", "hostname": "new"}
_PERSIST = {"config-test": {"result": 0}, "config-write": {"result": 0}}


def _responses(*pages: object) -> dict:
    """Return the Kea replies of a Reservations render whose page reads answer *pages* in order."""
    responses = _catalogue_responses(4, 20, _CIDR)
    responses.update(
        {
            "reservation-get-page": queued(*pages) if len(pages) > 1 else pages[0],
            "lease4-get-by-state": {"result": 0, "arguments": {"leases": []}},
        }
    )
    return responses


def _refresh_control(response):
    """Return the one Refresh control of a rendered page."""
    soup = BeautifulSoup(response.content, "html.parser")
    [control] = [button for button in soup.select("button[hx-get]") if "Refresh" in button.get_text()]
    return control


def _age_entries(seconds: int) -> None:
    """Move the read time of every cached Reservation page *seconds* into the past."""
    redis_cache: Any = cache  # django-redis adds keys(); the stubs know BaseCache only.
    keys = [key for key in redis_cache.keys(f"{display_cache.KEY_PREFIX}entry:*") if ":reservations:" in key]
    if not keys:
        raise AssertionError("no Reservation page is cached")
    for key in keys:
        snapshot = cache.get(key)
        cache.set(key, replace(snapshot, read_started=snapshot.read_started - timedelta(seconds=seconds)), 300)


class ServerReservationPageCacheTest(_ViewTestBase):
    """The Reservations tab of one Server."""

    def _url(self) -> str:
        return reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk])

    def _render(self, *pages: object, query: dict | None = None):
        with stub_kea(_responses(*pages)) as kea:
            response = self.client.get(self._url(), query or {})
        self.assertEqual(response.status_code, 200)
        return response, kea.commands().count("reservation-get-page")

    def _refresh(self, page, *pages: object):
        control = _refresh_control(page)
        headers = {"HX-Request": "true", **json.loads(control["hx-headers"])}
        with stub_kea(_responses(*pages)) as kea:
            response = self.client.get(control["hx-get"], headers=headers)
        self.assertEqual(response.status_code, 200)
        return response, kea.commands().count("reservation-get-page")

    def test_a_tab_switch_back_to_reservations_sends_no_page_read(self):
        _, reads = self._render(_res_page([_OLD]))
        self.assertEqual(reads, 1)
        with stub_kea(_responses(_res_page([]))):
            leases = self.client.get(reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]))
        self.assertEqual(leases.status_code, 200)

        response, reads = self._render(_res_page([_NEW]))

        self.assertEqual(reads, 0)
        self.assertContains(response, "198.18.0.21")
        self.assertNotContains(response, "198.18.0.22")

    def _assert_warm(self) -> None:
        self._render(_res_page([_OLD]))
        _, reads = self._render(_res_page([_OLD]))
        self.assertEqual(reads, 0, "the second render is cached")

    def test_a_reservation_added_through_the_plugin_shows_on_the_next_render(self):
        self._assert_warm()
        responses = {**_catalogue_responses(4, 20, _CIDR), **_PERSIST}
        responses.update({"reservation-add": {"result": 0}, "reservation-get": _res_get(_NEW)})
        with stub_kea(responses) as kea:
            added = self.client.post(
                reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]),
                {
                    "subnet_cidr": _CIDR,
                    "ip_address": "198.18.0.22",
                    "identifier_type": "hw-address",
                    "identifier": "aa:bb:cc:dd:ee:02",
                },
            )
        self.assertEqual(added.status_code, 302)
        self.assertIn("reservation-add", kea.commands())

        response, reads = self._render(_res_page([_OLD, _NEW]))

        self.assertEqual(reads, 1)
        self.assertContains(response, "198.18.0.22")

    def test_a_reservation_edited_through_the_plugin_shows_on_the_next_render(self):
        self._assert_warm()
        edit = reverse("plugins:netbox_kea:server_reservation4_edit", args=[self.server.pk, 20])
        edit += "?identifier_type=hw-address&identifier=aa:bb:cc:dd:ee:01"
        responses = {**_catalogue_responses(4, 20, _CIDR), **_PERSIST}
        changed = {**_OLD, "hostname": "renamed"}
        with stub_kea({**responses, "reservation-get": _res_get(_OLD)}):
            form_page = self.client.get(edit)
        fingerprint = form_page.context["form"].initial["managed_fingerprint"]
        responses.update(
            {
                "reservation-get": queued(_res_get(_OLD), _res_get(_OLD), _res_get(changed)),
                "reservation-update": {"result": 0},
            }
        )
        with stub_kea(responses):
            saved = self.client.post(
                edit, {"ip_address": "198.18.0.21", "hostname": "renamed", "managed_fingerprint": fingerprint}
            )
        self.assertEqual(saved.status_code, 302)

        response, reads = self._render(_res_page([changed]))

        self.assertEqual(reads, 1)
        self.assertContains(response, "renamed")

    def test_refresh_reads_live_once_and_the_next_render_serves_the_refilled_entry(self):
        page, _ = self._render(_res_page([_OLD]))

        refreshed, reads = self._refresh(page, _res_page([_NEW]))
        self.assertEqual(reads, 1)
        self.assertContains(refreshed, "198.18.0.22")

        response, reads = self._render(_res_page([_OLD]))
        self.assertEqual(reads, 0)
        self.assertContains(response, "198.18.0.22")
        self.assertNotContains(response, "198.18.0.21")

    def test_a_refresh_that_fails_leaves_no_entry(self):
        page, _ = self._render(_res_page([_OLD]))

        with self.assertLogs("netbox_kea.views.notices", "ERROR"):
            refreshed, reads = self._refresh(page, requests.ConnectionError("kea unreachable"))
        self.assertEqual(reads, 1)
        self.assertNotContains(refreshed, "198.18.0.21")

        response, reads = self._render(_res_page([_NEW]))
        self.assertEqual(reads, 1)
        self.assertContains(response, "198.18.0.22")

    def test_the_refresh_control_swaps_the_reservation_section_of_the_same_page(self):
        page, _ = self._render(_res_page([_OLD]), query={"q": "198.18"})
        control = _refresh_control(page)

        self.assertEqual(control["hx-get"], page.wsgi_request.get_full_path())
        self.assertEqual(control["hx-select"], control["hx-target"])
        self.assertEqual(control["hx-swap"], "outerHTML")
        refreshed, _ = self._refresh(page, _res_page([_OLD]))
        for response in (page, refreshed):
            section = BeautifulSoup(response.content, "html.parser").select_one(control["hx-target"])
            self.assertIsNotNone(section)
            self.assertIn("198.18.0.21", section.get_text())
            self.assertIn("Refresh", section.get_text())
        row = refreshed.context["table"].data.data[0]
        self.assertNotIn("refresh", row["edit_url"].lower())

    def test_the_page_shows_the_read_age_of_the_cached_entry(self):
        self._render(_res_page([_OLD]))
        _age_entries(42)

        response, reads = self._render(_res_page([_OLD]))

        self.assertEqual(reads, 0)
        self.assertContains(response, "Read 42 s ago")

    def test_a_failed_page_read_is_read_again_on_the_next_render(self):
        with self.assertLogs("netbox_kea.views.notices", "ERROR"):
            self._render(requests.ConnectionError("kea unreachable"))

        response, reads = self._render(_res_page([_OLD]))

        self.assertEqual(reads, 1)
        self.assertContains(response, "198.18.0.21")

    def test_a_page_with_records_that_did_not_parse_is_cached(self):
        broken = {"subnet-id": 20, "remote-id": "not-native"}
        self._render(_res_page([_OLD, broken]))

        response, reads = self._render(_res_page([_NEW]))

        self.assertEqual(reads, 0)
        self.assertContains(response, "198.18.0.21")
        self.assertContains(response, "Snapshot is incomplete")

    def test_a_search_whose_later_page_fails_is_read_again(self):
        unrelated = [{"subnet-id": 20, "flex-id": f"unrelated-{index}"} for index in range(100)]
        with self.assertLogs("netbox_kea.views.reservations", "ERROR"):
            first, reads = self._render(
                _res_page(unrelated, next_from=100, next_source=1),
                requests.ConnectionError("kea unreachable"),
                query={"q": "needle"},
            )
        self.assertEqual(reads, 2)
        self.assertContains(first, "page-fetch-failed")

        _, reads = self._render(_res_page([]), query={"q": "needle"})
        self.assertEqual(reads, 1)

    def test_a_search_that_stops_at_the_batch_limit_is_cached(self):
        empty = [_res_page([], next_from=index, next_source=1) for index in range(1, 6)]
        first, reads = self._render(*empty, query={"q": "needle"})
        self.assertEqual(reads, 5)
        self.assertContains(first, "The search batch limit was reached.")

        response, reads = self._render(_res_page([]), query={"q": "needle"})

        self.assertEqual(reads, 0)
        self.assertContains(response, "The search batch limit was reached.")

    def test_each_query_has_its_own_entry(self):
        self._render(_res_page([_OLD]))
        for query in ({"q": "old"}, {"scope": "in-subnet"}, {"subnet_id": "20"}, {"cursor": "WzEsMF0"}):
            with self.subTest(query=query):
                _, reads = self._render(_res_page([_OLD]), query=query)
                self.assertGreaterEqual(reads, 1)
                _, reads = self._render(_res_page([_OLD]), query=query)
                self.assertEqual(reads, 0)

    @with_display_cache_config(reservations_ttl=0)
    def test_a_ttl_of_0_reads_every_render(self):
        self._render(_res_page([_OLD]))

        _, reads = self._render(_res_page([_OLD]))

        self.assertEqual(reads, 1)

    def test_an_export_reads_live_with_a_warm_page(self):
        self._render(_res_page([_OLD]))

        with stub_kea(_responses(_res_page([_NEW]))) as kea:
            response = self.client.get(self._url(), {"export": "json"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands().count("reservation-get-page"), 1)
        self.assertEqual([record["hostname"] for record in response.json()["reservations"]], ["new"])


class CombinedReservationPageCacheTest(_ViewTestBase):
    """The combined Reservations page across Servers."""

    def setUp(self):
        super().setUp()
        self.other = _make_db_server(name="test-kea-other", ca_url="https://kea-other.example.com")
        self.query = {"server": [self.server.pk, self.other.pk]}

    def _render(self, *pages: object, headers: dict | None = None, url: str | None = None):
        with stub_kea(_responses(*pages)) as kea:
            if url is None:
                response = self.client.get(reverse("plugins:netbox_kea:combined_reservations4"), self.query)
            else:
                response = self.client.get(url, headers=headers)
        self.assertEqual(response.status_code, 200)
        return response, kea.commands().count("reservation-get-page")

    def test_a_second_render_sends_no_page_read(self):
        _, reads = self._render(_res_page([_OLD]))
        self.assertEqual(reads, 2)

        response, reads = self._render(_res_page([_NEW]))

        self.assertEqual(reads, 0)
        self.assertContains(response, "198.18.0.21")

    def test_the_page_shows_the_oldest_read_age_of_the_servers_in_scope(self):
        self._render(_res_page([_OLD]))
        _age_entries(7)
        # Only the other Server is read again, so its entry is younger than the entry of this Server.
        display_cache.rotate_after_write(self.other, 4, configuration=False)
        self._render(_res_page([_OLD]))
        _age_entries(35)

        response, reads = self._render(_res_page([_OLD]))

        self.assertEqual(reads, 0)
        self.assertContains(response, "Read 42 s ago")
        self.assertEqual(response.content.decode().count("Read "), 1)

    def test_one_refresh_rereads_every_server_in_scope(self):
        page, _ = self._render(_res_page([_OLD]))
        control = _refresh_control(page)
        self.assertEqual(control["hx-get"], page.wsgi_request.get_full_path())

        refreshed, reads = self._render(
            _res_page([_NEW]),
            url=control["hx-get"],
            headers={"HX-Request": "true", **json.loads(control["hx-headers"])},
        )
        self.assertEqual(reads, 2)
        self.assertIsNotNone(BeautifulSoup(refreshed.content, "html.parser").select_one(control["hx-target"]))

        response, reads = self._render(_res_page([_OLD]))
        self.assertEqual(reads, 0)
        self.assertContains(response, "198.18.0.22")
        self.assertNotContains(response, "198.18.0.21")

    def test_a_combined_export_reads_live_with_a_warm_page(self):
        self._render(_res_page([_OLD]))

        with stub_kea(_responses(_res_page([_NEW]))) as kea:
            response = self.client.get(
                reverse("plugins:netbox_kea:combined_reservations4"), {**self.query, "export": "json"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(kea.commands().count("reservation-get-page"), 2)
