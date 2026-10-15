# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Reservation Synchronization State comes from the IPAM Ownership links of the Server (issue #74)."""

from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from ipam.models import IPAddress
from users.models import ObjectPermission

from netbox_kea.ipam_reconciliation import address_ownership
from netbox_kea.models import IPAMOwnershipLink, Server, next_confirmation_number

from .kea_stub import _catalogue_responses, _res_get, _res_page, stub_kea
from .utils import User, _make_db_server, _ViewTestBase

_NO_LEASES = {"result": 0, "arguments": {"leases": []}}
_ADDS_OWNER = "Sync adds this Server as an owner of the IP address."
_TAKES_OVER = "The IP address has no Kea sync marker. Sync takes it over."


def _host(n: int) -> dict:
    return {"subnet-id": 1, "hw-address": f"aa:bb:cc:00:00:{n:02x}", "ip-address": f"10.0.0.{n}", "hostname": f"h{n}"}


def _responses(*hosts: dict) -> dict:
    return {
        **_catalogue_responses(4, 1, "10.0.0.0/24"),
        "reservation-get-page": _res_page(list(hosts)),
        "lease4-get-by-state": _NO_LEASES,
    }


def _link(ip: IPAddress, server: Server, source: str = "reservation", **extra) -> IPAMOwnershipLink:
    return IPAMOwnershipLink.objects.create(
        server=server,
        family=4,
        source=source,
        ip_address=ip,
        facts={"hostname": "", "prefix_length": 24},
        confirmation=next_confirmation_number(),
        **extra,
    )


class TestReservationOwnershipBadge(_ViewTestBase):
    def setUp(self):
        super().setUp()
        self.v6_only = _make_db_server(name="v6-only", dhcp4=False)

    def _urls(self) -> dict[str, str]:
        return {
            "per-server": reverse("plugins:netbox_kea:server_reservations4", args=[self.server.pk]),
            # A second selected Server keeps the combined page from redirecting to the Server tab.
            "combined": reverse("plugins:netbox_kea:combined_reservations4")
            + f"?server={self.server.pk}&server={self.v6_only.pk}",
        }

    def _get(self, url: str, *hosts: dict):
        with stub_kea(_responses(*(hosts or (_host(5),)))):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response

    def _row(self, response) -> dict:
        return next(iter(response.context["table"].rows)).record

    def test_an_address_that_only_another_server_owns_is_not_synchronized(self):
        other = _make_db_server(name="other-kea")
        _link(IPAddress.objects.create(address="10.0.0.5/24", description="[kea-sync: reservation]"), other)
        for page, url in self._urls().items():
            with self.subTest(page=page):
                response = self._get(url)
                self.assertContains(response, "Not Synchronized 0/1")
                self.assertNotContains(response, "Synchronized 1/1")
                row = self._row(response)
                self.assertIsNone(row["netbox_ip_url"])
                self.assertTrue(row["sync_url"])
                self.assertEqual(row["sync_title"], _ADDS_OWNER)
                self.assertContains(response, f'title="{_ADDS_OWNER}"')

    def test_a_lease_link_is_not_synchronized_and_row_sync_synchronizes_it(self):
        ip = IPAddress.objects.create(address="10.0.0.5/24", status="dhcp", description="[kea-sync: lease]")
        _link(ip, self.server, source="lease", allocation_kind="address")
        url = self._urls()["per-server"]
        self.assertContains(self._get(url), "Not Synchronized 0/1")

        sync = reverse("plugins:netbox_kea:server_reservation4_sync", args=[self.server.pk, 1])
        with stub_kea({**_catalogue_responses(4, 1, "10.0.0.0/24"), "reservation-get": _res_get(_host(5))}):
            response = self.client.post(f"{sync}?identifier_type=hw-address&identifier=aa%3Abb%3Acc%3A00%3A00%3A05")
        self.assertContains(response, "Synchronized 1/1")

        self.assertEqual(
            set(IPAMOwnershipLink.objects.filter(ip_address=ip).values_list("source", flat=True)),
            {"lease", "reservation"},
        )
        response = self._get(url)
        self.assertContains(response, "Synchronized 1/1")
        self.assertContains(response, f'href="{ip.get_absolute_url()}"')

    def test_an_adopted_or_stale_marked_link_counts_as_owned(self):
        for name, extra in (
            ("adopted", {"adopted": True}),
            ("stale-marked", {"stale_mark": next_confirmation_number()}),
        ):
            with self.subTest(link=name):
                IPAddress.objects.all().delete()
                ip = IPAddress.objects.create(address="10.0.0.5/24", description="[kea-sync: reservation]")
                _link(ip, self.server, **extra)
                response = self._get(self._urls()["per-server"])
                self.assertContains(response, "Synchronized 1/1")
                self.assertContains(response, f'href="{ip.get_absolute_url()}"')
                self.assertIsNone(self._row(response)["sync_url"])

    def test_an_unmarked_address_keeps_its_sync_and_the_title_says_it_takes_the_address_over(self):
        IPAddress.objects.create(address="10.0.0.5/24", description="Router loopback")
        response = self._get(self._urls()["per-server"])
        self.assertContains(response, "Not Synchronized 0/1")
        row = self._row(response)
        self.assertTrue(row["sync_url"])
        self.assertEqual(row["sync_title"], _TAKES_OVER)
        self.assertContains(response, f'title="{_TAKES_OVER}"')

    def test_an_address_not_in_netbox_offers_sync_without_a_title(self):
        row = self._row(self._get(self._urls()["per-server"]))
        self.assertEqual(row["sync_state"].code, "not-synchronized")
        self.assertTrue(row["sync_url"])
        self.assertEqual(row["sync_title"], "")

    def test_an_address_the_user_may_not_view_is_unknown_and_shows_none_of_its_fields(self):
        ip = IPAddress.objects.create(
            address="10.0.0.5/24", dns_name="hidden.example.invalid", description="[kea-sync: reservation] rack 4"
        )
        _link(ip, self.server)
        limited = User.objects.create_user(username="ownership_limited", password="pass")
        permission = ObjectPermission.objects.create(name="ownership-view-server", actions=["view"])
        permission.object_types.add(ContentType.objects.get_for_model(Server))
        permission.users.add(limited)
        self.client.force_login(limited)

        response = self._get(self._urls()["per-server"])

        row = self._row(response)
        self.assertEqual(row["sync_state"].code, "unknown")
        self.assertEqual(row["sync_state"].reason, "You may not view an IP address of this Reservation in NetBox.")
        self.assertIsNone(row["netbox_ip_url"])
        self.assertIsNone(row["sync_url"])
        self.assertNotContains(response, ip.get_absolute_url())
        self.assertNotContains(response, "hidden.example.invalid")
        self.assertNotContains(response, "rack 4")

    def test_the_query_count_does_not_grow_with_the_rows(self):
        def render(server: Server, count: int) -> int:
            hosts = [_host(n) for n in range(10, 10 + count)]
            for host in hosts:
                ip = IPAddress.objects.create(
                    address=f"{host['ip-address']}/24", vrf=server.sync_vrf, description="[kea-sync: reservation]"
                )
                _link(ip, server)
            url = reverse("plugins:netbox_kea:server_reservations4", args=[server.pk])
            with stub_kea(_responses(*hosts)), CaptureQueriesContext(connection) as queries:
                response = self.client.get(url)
            self.assertContains(response, "Synchronized 1/1", count=count)
            return len(queries)

        from ipam.models import VRF

        render(_make_db_server(name="warm-up", sync_vrf=VRF.objects.create(name="warm-up")), 1)  # one-time reads
        one = render(_make_db_server(name="one-row", sync_vrf=VRF.objects.create(name="one-row")), 1)
        many = render(_make_db_server(name="many-rows", sync_vrf=VRF.objects.create(name="many-rows")), 6)
        self.assertEqual(one, many)


class TestAddressOwnershipRead(_ViewTestBase):
    def _state(self, description: str, *, linked: bool = True) -> str:
        IPAddress.objects.all().delete()
        ip = IPAddress.objects.create(address="10.0.0.5/24", description=description)
        if linked:
            _link(ip, self.server)
        return address_ownership(self.server, 4, "reservation", ["10.0.0.5"], self.user)["10.0.0.5"].state

    def test_only_a_well_formed_marker_at_the_start_of_the_description_is_a_marker(self):
        for description in ("[kea-sync: reservation]", "[kea-sync: lease] note", "Synced from Kea DHCP reservation"):
            with self.subTest(description=description):
                self.assertEqual(self._state(description), "owned")
        for description in ("", "Router loopback", "rack 4 [kea-sync: lease]", "[kea-sync: lease ]"):
            with self.subTest(description=description):
                self.assertEqual(self._state(description), "unmarked")
        self.assertEqual(self._state("[kea-sync: reservation]", linked=False), "not-synchronized")

    def test_an_address_without_an_ip_address_in_the_sync_vrf_is_not_in_netbox(self):
        from ipam.models import VRF

        IPAddress.objects.create(address="10.0.0.5/24", vrf=VRF.objects.create(name="elsewhere"))
        found = address_ownership(self.server, 4, "reservation", ["10.0.0.5"], self.user)
        self.assertEqual(found["10.0.0.5"].state, "not-in-netbox")
        self.assertIsNone(found["10.0.0.5"].ip)
