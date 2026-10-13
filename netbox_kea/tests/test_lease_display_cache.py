# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The display cache of Lease Snapshots, Lease and Reservation badges, utilization and daemon status (ADR 0009)."""

import json
import time
from typing import Any

import requests
from bs4 import BeautifulSoup
from django.core.cache import cache
from django.urls import reverse

from netbox_kea import display_cache
from netbox_kea.views.notices import HEADLINES

from .kea_stub import (
    LeaseDaemon,
    _catalogue_responses,
    _res_page,
    lease_pages,
    lease_record,
    lease_reply,
    shown_token,
    stub_kea,
)
from .utils import _make_db_server, _ViewTestBase, save_key_without_certificate, with_display_cache_config

_CIDR = "198.18.0.0/24"
_RESERVED = {"subnet-id": 20, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.21", "hostname": "old"}
#: The Leases tab reads every Lease when the search names no Attribute.
_BROWSE = {"q": "", "by": "", "state": ""}


def _lease(address: str, hostname: str = "host") -> dict[str, Any]:
    return lease_record(address, subnet_id=20, hw_address="aa:bb:cc:dd:ee:01", hostname=hostname)


def _lease_commands(commands: list[str]) -> list[str]:
    return [command for command in commands if command.startswith("lease4-")]


def _wait_past_ttl(seconds: int) -> None:
    """Wait until an entry stored with a TTL of *seconds* has expired in the cache backend."""
    time.sleep(seconds + 0.2)


def _entries(kind: str) -> list[str]:
    redis_cache: Any = cache  # django-redis adds keys() and ttl(); the stubs know BaseCache only.
    return [key for key in redis_cache.keys(f"{display_cache.KEY_PREFIX}entry:*") if f":{kind}:" in key]


def _refresh_control(response):
    """Return the one Refresh control of a rendered page or partial."""
    soup = BeautifulSoup(response.content, "html.parser")
    [control] = [button for button in soup.select("button[hx-get]") if "Refresh" in button.get_text()]
    return control


def _section(response, selector: str) -> Any:
    section = BeautifulSoup(response.content, "html.parser").select_one(selector)
    if section is None:
        raise AssertionError(f"the response has no {selector}")
    return section


class _LeaseCacheBase(_ViewTestBase):
    def _leases(self, responses: dict, query: dict | None = None, headers: dict | None = None):
        """Render the Leases table partial as the search form requests it; return it and the Kea commands."""
        with stub_kea({**_catalogue_responses(4, 20, _CIDR), "reservation-get": {"result": 3}, **responses}) as kea:
            response = self.client.get(
                reverse("plugins:netbox_kea:server_leases4", args=[self.server.pk]),
                _BROWSE if query is None else query,
                headers={"HX-Request": "true", **(headers or {})},
            )
        self.assertEqual(response.status_code, 200)
        return response, kea.commands()

    def _refresh_leases(self, page, responses: dict):
        control = _refresh_control(page)
        with stub_kea({**_catalogue_responses(4, 20, _CIDR), "reservation-get": {"result": 3}, **responses}) as kea:
            response = self.client.get(
                control["hx-get"], headers={"HX-Request": "true", **json.loads(control["hx-headers"])}
            )
        self.assertEqual(response.status_code, 200)
        return response, kea.commands()

    def _reservations(self, leases: list[dict], url: str | None = None, headers: dict | None = None):
        """Render the Reservations tab, whose rows read Lease badges; return it and the Kea commands."""
        responses = {
            **_catalogue_responses(4, 20, _CIDR),
            "reservation-get-page": _res_page([_RESERVED]),
            "lease4-get-by-state": lease_reply(*leases),
        }
        with stub_kea(responses) as kea:
            response = self.client.get(
                url or reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk]), headers=headers
            )
        self.assertEqual(response.status_code, 200)
        return response, kea.commands()


class LeaseTableCacheTest(_LeaseCacheBase):
    """The Leases table of one Server and its Reservation badges."""

    def test_a_second_render_within_the_ttl_sends_no_kea_command(self):
        _, commands = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})
        self.assertEqual(_lease_commands(commands), ["lease4-get-page"])
        self.assertIn("reservation-get", commands)

        response, commands = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.22")])})

        self.assertEqual(commands, [], "the Lease page, its Catalogue and its Reservation badges are cached")
        self.assertContains(response, "198.18.0.21")
        self.assertNotContains(response, "198.18.0.22")

    @with_display_cache_config(leases_ttl=1)
    def test_a_render_after_the_leases_ttl_reads_the_leases_and_their_badges_again(self):
        self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})
        _wait_past_ttl(1)

        response, commands = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.22")])})

        self.assertEqual(_lease_commands(commands), ["lease4-get-page"])
        self.assertIn("reservation-get", commands)
        self.assertContains(response, "198.18.0.22")

    @with_display_cache_config(leases_ttl=17, reservations_ttl=300)
    def test_the_leases_ttl_reaches_the_lease_and_reservation_lookup_entries(self) -> None:
        self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})

        redis_cache: Any = cache
        for kind in ("leases", "reservation_lookups"):
            keys = _entries(kind)
            self.assertTrue(keys, f"no {kind} entry is cached")
            for key in keys:
                with self.subTest(key=key):
                    self.assertTrue(0 < redis_cache.ttl(key) <= 17, redis_cache.ttl(key))

    def test_each_search_has_its_own_entry_and_a_search_ignores_the_table_page(self):
        first = {"lease4-get-by-hostname": lease_reply(_lease("198.18.0.21", "alpha"))}
        self._leases(first, {"q": "alpha", "by": "hostname", "state": ""})

        _, commands = self._leases(first, {"q": "alpha", "by": "hostname", "state": "", "page": "2"})
        self.assertEqual(_lease_commands(commands), [], "a search reads its whole scope once")

        other = {"lease4-get-by-hostname": lease_reply(_lease("198.18.0.22", "beta"))}
        response, commands = self._leases(other, {"q": "beta", "by": "hostname", "state": ""})
        self.assertEqual(_lease_commands(commands), ["lease4-get-by-hostname"])
        self.assertContains(response, "198.18.0.22")

    def test_a_failed_lease_read_is_read_again_on_the_next_render(self):
        with self.assertLogs("netbox_kea.views.notices", "ERROR"):
            failed, _ = self._leases({"lease4-get-page": requests.ConnectionError("kea unreachable")})
        self.assertContains(failed, HEADLINES["lease"])

        response, commands = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})

        self.assertEqual(_lease_commands(commands), ["lease4-get-page"])
        self.assertContains(response, "198.18.0.21")

    def test_a_page_with_a_record_that_did_not_parse_is_cached(self):
        broken = lease_record("198.18.0.30", drop=("subnet-id",))
        self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21"), broken])})

        response, commands = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.22")])})

        self.assertEqual(_lease_commands(commands), [])
        self.assertContains(response, "198.18.0.21")
        self.assertContains(response, "could not be read")

    def test_a_subnet_search_of_an_unsettled_catalogue_is_read_again(self):
        unsettled = {
            **_catalogue_responses(4, 20, _CIDR),
            "config-get": {"result": 1, "text": "configuration unavailable"},
            "lease4-get-all": lease_reply(_lease("198.18.0.21")),
        }
        query = {"q": _CIDR, "by": "subnet", "state": ""}
        _, commands = self._leases(unsettled, query)
        self.assertEqual(_lease_commands(commands), ["lease4-get-all"])

        response, commands = self._leases(unsettled, query)

        self.assertEqual(_lease_commands(commands), ["lease4-get-all"])
        self.assertContains(response, "198.18.0.21")

    def test_a_subnet_search_of_a_settled_catalogue_is_cached(self):
        query = {"q": _CIDR, "by": "subnet", "state": ""}
        self._leases({"lease4-get-all": lease_reply(_lease("198.18.0.21"))}, query)

        response, commands = self._leases({"lease4-get-all": lease_reply(_lease("198.18.0.22"))}, query)

        self.assertEqual(commands, [])
        self.assertContains(response, "198.18.0.21")

    def test_a_lease_delete_through_the_plugin_makes_the_next_renders_read_live(self):
        held = _lease("198.18.0.21")
        daemon = LeaseDaemon(4, held, subnet_id=20)

        def page(body):
            return lease_pages(list(daemon.leases.values()))(body)

        def warm() -> None:
            self._leases({"lease4-get-page": page})
            self._reservations([held])
            _, leases = self._leases({"lease4-get-page": page})
            _, reservations = self._reservations([held])
            self.assertEqual(_lease_commands(leases + reservations), [], "both tabs are cached")

        warm()
        with stub_kea({**_catalogue_responses(4, 20, _CIDR), **daemon.responses()}) as kea:
            deleted = self.client.post(
                reverse("plugins:netbox_kea:server_leases4_delete", args=[self.server.pk]),
                {"pk": shown_token(held), "_confirm": "1"},
            )
        self.assertEqual(deleted.status_code, 302)
        self.assertIn("lease4-del", kea.commands())

        response, commands = self._leases({"lease4-get-page": page})
        self.assertEqual(_lease_commands(commands), ["lease4-get-page"])
        self.assertNotContains(response, "198.18.0.21")
        reservations, commands = self._reservations([])
        self.assertEqual(_lease_commands(commands), ["lease4-get-by-state"])
        self.assertNotContains(reservations, ">Active Lease<")

    def test_refresh_reads_the_leases_and_their_reservation_badges_live_and_refills_the_entries(self):
        page, _ = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})

        refreshed, commands = self._refresh_leases(page, {"lease4-get-page": lease_pages([_lease("198.18.0.22")])})
        self.assertEqual(_lease_commands(commands), ["lease4-get-page"])
        self.assertIn("reservation-get", commands, "Refresh rereads the Reservation badges of the shown rows")
        self.assertIn("subnet4-list", commands, "Refresh reads the Subnet Catalogue live")
        self.assertContains(refreshed, "198.18.0.22")

        response, commands = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})
        self.assertEqual(commands, [])
        self.assertContains(response, "198.18.0.22")

    def test_the_refresh_control_swaps_the_lease_search_section_of_the_same_search(self):
        page, _ = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})
        control = _refresh_control(page)

        self.assertEqual(control["hx-get"], page.wsgi_request.get_full_path())
        self.assertEqual((control["hx-select"], control["hx-target"]), ("#lease-search", "#lease-search"))
        self.assertEqual(control["hx-swap"], "outerHTML")
        refreshed, _ = self._refresh_leases(page, {"lease4-get-page": lease_pages([_lease("198.18.0.21")])})
        for response in (page, refreshed):
            section = _section(response, "#lease-search")
            self.assertIn("198.18.0.21", section.get_text())
            self.assertIn("Refresh", section.get_text())
            self.assertRegex(section.get_text(), r"Read \d+ s ago")

    def test_a_refresh_that_fails_shows_its_error_in_the_section_and_leaves_no_entry(self):
        page, _ = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})

        with self.assertLogs("netbox_kea.views.notices", "ERROR"):
            refreshed, _ = self._refresh_leases(page, {"lease4-get-page": requests.ConnectionError("kea unreachable")})
        self.assertIn(HEADLINES["lease"], _section(refreshed, "#lease-search").get_text())
        self.assertNotContains(refreshed, "198.18.0.21")

        response, commands = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.22")])})
        self.assertEqual(_lease_commands(commands), ["lease4-get-page"])
        self.assertContains(response, "198.18.0.22")

    def test_a_refresh_with_invalid_client_settings_shows_the_error_in_the_section(self):
        page, _ = self._leases({"lease4-get-page": lease_pages([_lease("198.18.0.21")])})
        save_key_without_certificate(self.server)

        with self.assertLogs("netbox_kea.views.leases", "ERROR"):
            refreshed, _ = self._refresh_leases(page, {"lease4-get-page": lease_pages([_lease("198.18.0.21")])})

        self.assertIn("An internal error occurred", _section(refreshed, "#lease-search").get_text())


class LeaseBadgeCacheTest(_LeaseCacheBase):
    """The Lease badges of Reservation rows."""

    def test_a_second_reservations_render_sends_no_lease_read(self):
        _, commands = self._reservations([_lease("198.18.0.21")])
        self.assertEqual(_lease_commands(commands), ["lease4-get-by-state"])

        response, commands = self._reservations([])

        self.assertEqual(commands, [])
        self.assertContains(response, ">Active Lease<")

    @with_display_cache_config(leases_ttl=1, reservations_ttl=300)
    def test_the_lease_badges_expire_with_the_leases_ttl_not_the_reservations_ttl(self):
        self._reservations([_lease("198.18.0.21")])
        _wait_past_ttl(1)

        response, commands = self._reservations([])

        self.assertNotIn("reservation-get-page", commands, "the Reservation page is still cached")
        self.assertEqual(_lease_commands(commands), ["lease4-get-by-state"])
        self.assertNotContains(response, ">Active Lease<")

    def test_a_badge_and_the_same_leases_tab_search_share_one_entry(self):
        # The badge of a DHCPv4 In-Subnet Reservation reads the assigned Leases of its Subnet: state code 0.
        self._leases(
            {"lease4-get-by-state": lease_reply(_lease("198.18.0.21"))}, {"q": "20", "by": "subnet_id", "state": "0"}
        )

        response, commands = self._reservations([])

        self.assertEqual(_lease_commands(commands), [])
        self.assertContains(response, ">Active Lease<")

    def test_a_reservations_refresh_rereads_the_lease_badges_of_its_rows(self):
        page, _ = self._reservations([_lease("198.18.0.21")])
        control = _refresh_control(page)

        refreshed, commands = self._reservations(
            [], url=control["hx-get"], headers={"HX-Request": "true", **json.loads(control["hx-headers"])}
        )

        self.assertEqual(_lease_commands(commands), ["lease4-get-by-state"])
        self.assertNotIn(">Active Lease<", str(_section(refreshed, control["hx-target"])))
        response, commands = self._reservations([_lease("198.18.0.21")])
        self.assertEqual(commands, [])
        self.assertNotContains(response, ">Active Lease<")

    def test_a_combined_reservations_refresh_rereads_the_lease_badges_of_its_rows(self):
        other = _make_db_server(name="test-kea-other", ca_url="https://kea-other.example.com")
        url = reverse("plugins:netbox_kea:combined_reservations4") + f"?server={self.server.pk}&server={other.pk}"
        page, _ = self._reservations([_lease("198.18.0.21")], url=url)
        control = _refresh_control(page)

        _, commands = self._reservations(
            [], url=control["hx-get"], headers={"HX-Request": "true", **json.loads(control["hx-headers"])}
        )

        self.assertEqual(_lease_commands(commands), ["lease4-get-by-state"] * 2)
