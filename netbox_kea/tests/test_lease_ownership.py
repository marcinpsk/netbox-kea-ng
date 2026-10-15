# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Lease Synchronization State comes from the IPAM Ownership links of the Server (issue #75)."""

import csv
import io

from bs4 import BeautifulSoup
from django.contrib.contenttypes.models import ContentType
from django.db import DatabaseError, connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from ipam.models import VRF, IPAddress, Prefix
from users.models import ObjectPermission

from netbox_kea.models import IPAMOwnershipLink, Server

from .kea_stub import _catalogue_responses, _catalogue_responses_for_subnets, lease_record, lease_reply, stub_kea
from .utils import User, _make_db_server, _ViewTestBase, ownership_link, prefix_ownership_link

_ADDS_OWNER = "Sync adds this Server as an owner of the {}."
_TAKES_OVER = "The {} has no Kea sync marker. Sync takes it over."
_UNREADABLE = "NetBox IPAM state could not be read."
_HIDDEN = "You may not view the {} of this lease in NetBox."
_PREFIX = "2001:db8:100:100::/56"
_RELEASED = 3


def _restricted_user(name):
    """Return a user who may view the Servers, but only the IPAM objects whose description ends with "visible"."""
    user = User.objects.create_user(username=name, password="pass")
    server = ObjectPermission.objects.create(name=f"{name}-server", actions=["view"])
    server.object_types.add(ContentType.objects.get_for_model(Server))
    server.users.add(user)
    ipam = ObjectPermission.objects.create(
        name=f"{name}-ipam", actions=["view"], constraints={"description__endswith": "visible"}
    )
    ipam.object_types.add(ContentType.objects.get_for_model(IPAddress), ContentType.objects.get_for_model(Prefix))
    ipam.users.add(user)
    return user


def _fail_ipam_reads(execute, sql, params, many, context):
    if "ipam_ipaddress" in sql or "ipam_prefix" in sql:
        raise DatabaseError("read failed")
    return execute(sql, params, many, context)


class _LeasePage(_ViewTestBase):
    family = 4

    def _responses(self, *records: dict) -> dict:
        if self.family == 4:
            responses = {**_catalogue_responses(4, 1, "10.0.0.0/24"), "lease4-get-all": lease_reply(*records)}
        else:
            subnets = [{"id": 1, "subnet": "2001:db8:1::/64"}]
            responses = {**_catalogue_responses_for_subnets(6, subnets), "lease6-get-all": lease_reply(*records)}
        return {**responses, "reservation-get": {"result": 3}}

    def _url(self) -> str:
        return reverse(f"plugins:netbox_kea:server_leases{self.family}", args=[self.server.pk])

    def _get(self, *records: dict, **params: str):
        with stub_kea(self._responses(*records)):
            response = self.client.get(self._url(), {"by": "subnet_id", "q": "1", **params}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        return response

    def _rows(self, response) -> dict[str, dict]:
        return {row.record["label"]: row.record for row in response.context["table"].rows}

    def _cell(self, response, label: str) -> BeautifulSoup:
        row = next(row for row in response.context["table"].rows if row.record["label"] == label)
        return BeautifulSoup(str(row.get_cell("netbox_ip")), "html.parser")

    def _export(self, *records: dict) -> dict[str, str]:
        with stub_kea(self._responses(*records)):
            response = self.client.get(self._url(), {"by": "subnet_id", "q": "1", "export": "table"})
        self.assertEqual(response.status_code, 200)
        rows = csv.DictReader(io.StringIO(response.content.decode()))
        return {row["IP Address"]: row["NetBox IP"] for row in rows}

    def _assert_badge(self, response, label: str, text: str, href: str | None, *, title: str | None = None):
        cell = self._cell(response, label)
        (badge,) = cell.select(".badge:not(button)")
        self.assertEqual(badge.get_text(strip=True), text)
        self.assertEqual(badge.get("href"), href)
        if title is not None:
            self.assertEqual(badge["title"], title)

    def _sync_button(self, response, label: str):
        return self._cell(response, label).select_one("button[hx-post]")


class TestAddressLeaseSynchronizationState(_LeasePage):
    def test_a_manual_ip_address_in_the_sync_vrf_is_unmarked_and_offers_sync(self):
        ip = IPAddress.objects.create(address="10.0.0.5/24", description="Router loopback")

        response = self._get(lease_record("10.0.0.5", subnet_id=1))

        row = self._rows(response)["10.0.0.5"]
        self.assertTrue(row.get("sync_url"))
        self.assertEqual(row["sync_state"].code, "unmarked")
        self._assert_badge(response, "10.0.0.5", "Unmarked", ip.get_absolute_url())
        self.assertEqual(self._sync_button(response, "10.0.0.5")["title"], _TAKES_OVER.format("IP address"))

    def test_an_ip_address_only_another_server_owns_is_not_synchronized_and_row_sync_adds_this_server(self):
        other = _make_db_server(name="other-kea")
        ip = IPAddress.objects.create(address="10.0.0.5/24", status="dhcp", description="[kea-sync: lease]")
        ownership_link(ip, other, source="lease", allocation_kind="address")
        record = lease_record("10.0.0.5", subnet_id=1)

        response = self._get(record)

        row = self._rows(response)["10.0.0.5"]
        self.assertEqual(row["sync_state"].code, "not-synchronized")
        self._assert_badge(response, "10.0.0.5", "Not Synchronized", ip.get_absolute_url())
        button = self._sync_button(response, "10.0.0.5")
        self.assertEqual(button["title"], _ADDS_OWNER.format("IP address"))

        with stub_kea({**self._responses(record), "lease4-get": {"result": 0, "arguments": record}}):
            synced = self.client.post(row["sync_url"], {"ip_address": "10.0.0.5"}, HTTP_HX_REQUEST="true")
        self.assertEqual(synced.status_code, 200)
        self.assertEqual(
            set(IPAMOwnershipLink.objects.filter(ip_address=ip).values_list("server__name", "source")),
            {("other-kea", "lease"), (self.server.name, "lease")},
        )

        response = self._get(record)
        self._assert_badge(response, "10.0.0.5", "Synced", ip.get_absolute_url())
        self.assertIsNone(self._sync_button(response, "10.0.0.5"))

    def test_a_link_of_another_source_of_this_server_is_not_synchronized(self):
        ip = IPAddress.objects.create(address="10.0.0.5/24", status="reserved", description="[kea-sync: reservation]")
        ownership_link(ip, self.server, source="reservation")

        row = self._rows(self._get(lease_record("10.0.0.5", subnet_id=1)))["10.0.0.5"]

        self.assertEqual(row["sync_state"].code, "not-synchronized")
        self.assertTrue(row.get("sync_url"))

    def test_an_ip_address_this_server_owns_from_a_lease_is_synced_without_sync(self):
        ip = IPAddress.objects.create(address="10.0.0.5/24", status="dhcp", description="[kea-sync: lease]")
        ownership_link(ip, self.server, source="lease", allocation_kind="address")

        response = self._get(lease_record("10.0.0.5", subnet_id=1))

        self.assertEqual(self._rows(response)["10.0.0.5"]["sync_state"].code, "synchronized")
        self._assert_badge(response, "10.0.0.5", "Synced", ip.get_absolute_url())
        self.assertIsNone(self._sync_button(response, "10.0.0.5"))

    def test_an_address_not_in_netbox_offers_sync_only(self):
        # An IP address in another VRF is not the object of the Lease.
        IPAddress.objects.create(address="10.0.0.5/24", vrf=VRF.objects.create(name="elsewhere"))

        response = self._get(lease_record("10.0.0.5", subnet_id=1))

        self.assertEqual(self._rows(response)["10.0.0.5"]["sync_state"].code, "not-in-netbox")
        cell = self._cell(response, "10.0.0.5")
        self.assertEqual(cell.select(".badge:not(button)"), [])
        self.assertFalse(self._sync_button(response, "10.0.0.5").has_attr("title"))

    def test_a_failed_netbox_read_is_unknown_without_a_link_or_sync_and_the_rows_stay(self):
        IPAddress.objects.create(address="10.0.0.5/24", description="Router loopback")

        with connection.execute_wrapper(_fail_ipam_reads), self.assertLogs("netbox_kea.views.leases", "ERROR"):
            response = self._get(lease_record("10.0.0.5", subnet_id=1), lease_record("10.0.0.6", subnet_id=1))

        rows = self._rows(response)
        self.assertEqual(set(rows), {"10.0.0.5", "10.0.0.6"})
        for label, row in rows.items():
            with self.subTest(label):
                self.assertEqual(row["sync_state"].code, "unknown")
                self.assertIsNone(row.get("sync_url"))
                self._assert_badge(response, label, "Unknown", None, title=_UNREADABLE)
                self.assertIsNone(self._sync_button(response, label))

    def test_an_ip_address_the_user_may_not_view_is_unknown_and_shows_none_of_its_fields(self):
        ip = IPAddress.objects.create(address="10.0.0.5/24", description="Router loopback", dns_name="hidden.invalid")
        self.client.force_login(_restricted_user("lease_ownership_limited"))

        response = self._get(lease_record("10.0.0.5", subnet_id=1))

        row = self._rows(response)["10.0.0.5"]
        self.assertEqual(row["sync_state"].code, "unknown")
        self.assertIsNone(row.get("sync_url"))
        self.assertEqual(row.get("sync_refusal", ""), "")
        self._assert_badge(response, "10.0.0.5", "Unknown", None, title=_HIDDEN.format("IP address"))
        self.assertNotContains(response, ip.get_absolute_url())
        self.assertNotContains(response, "hidden.invalid")

    def test_a_lease_that_is_not_current_shows_the_link_only(self):
        owned = IPAddress.objects.create(address="10.0.0.5/24", status="dhcp", description="[kea-sync: lease] visible")
        ownership_link(owned, self.server, source="lease", allocation_kind="address")
        manual = IPAddress.objects.create(address="10.0.0.6/24", description="Router loopback visible")
        IPAddress.objects.create(address="10.0.0.7/24", description="Router loopback")
        self.client.force_login(_restricted_user("lease_not_current"))
        records = [lease_record(f"10.0.0.{n}", subnet_id=1, state=_RELEASED) for n in (5, 6, 7, 8)]

        response = self._get(*records)

        rows = self._rows(response)
        for label, row in rows.items():
            with self.subTest(label):
                self.assertIsNone(row["sync_state"])
                self.assertIsNone(row.get("sync_url"))
                self.assertIsNone(self._sync_button(response, label))
        self._assert_badge(response, "10.0.0.5", "NetBox", owned.get_absolute_url())
        self._assert_badge(response, "10.0.0.6", "NetBox", manual.get_absolute_url())
        # The user may not view the IP address of the third Lease, and the fourth has none.
        for label in ("10.0.0.7", "10.0.0.8"):
            self.assertEqual(self._cell(response, label).select(".badge"), [])

    def test_the_table_export_writes_the_state_of_each_row(self):
        other = _make_db_server(name="other-kea")
        owned = IPAddress.objects.create(address="10.0.0.5/24", status="dhcp", description="[kea-sync: lease]")
        ownership_link(owned, self.server, source="lease", allocation_kind="address")
        foreign = IPAddress.objects.create(address="10.0.0.6/24", status="dhcp", description="[kea-sync: lease]")
        ownership_link(foreign, other, source="lease", allocation_kind="address")
        IPAddress.objects.create(address="10.0.0.7/24", description="Router loopback")
        IPAddress.objects.create(address="10.0.0.9/24", description="Router loopback")
        records = [
            *(lease_record(f"10.0.0.{n}", subnet_id=1) for n in (5, 6, 7, 8)),
            lease_record("10.0.0.9", subnet_id=1, state=_RELEASED),
        ]

        self.assertEqual(
            self._export(*records),
            {
                "10.0.0.5": "Synchronized",
                "10.0.0.6": "Not Synchronized",
                "10.0.0.7": "Unmarked",
                "10.0.0.8": "Not in NetBox",
                "10.0.0.9": "",
            },
        )
        with connection.execute_wrapper(_fail_ipam_reads), self.assertLogs("netbox_kea.views.leases", "ERROR"):
            self.assertEqual(self._export(records[0]), {"10.0.0.5": "Unknown"})

    def test_the_query_count_does_not_grow_with_the_rows(self):
        def render(server: Server, count: int) -> int:
            self.server = server
            records = [lease_record(f"10.0.0.{n}", subnet_id=1) for n in range(10, 10 + count)]
            for n in range(10, 10 + count):
                ip = IPAddress.objects.create(
                    address=f"10.0.0.{n}/24", vrf=server.sync_vrf, status="dhcp", description="[kea-sync: lease]"
                )
                ownership_link(ip, server, source="lease", allocation_kind="address")
            with CaptureQueriesContext(connection) as queries:
                response = self._get(*records)
            self.assertContains(response, " Synced</a>", count=count)
            return len(queries)

        render(_make_db_server(name="warm-up", sync_vrf=VRF.objects.create(name="warm-up")), 1)  # one-time reads
        one = render(_make_db_server(name="one-row", sync_vrf=VRF.objects.create(name="one-row")), 1)
        many = render(_make_db_server(name="many-rows", sync_vrf=VRF.objects.create(name="many-rows")), 6)
        self.assertEqual(one, many)


class TestDelegatedPrefixLeaseSynchronizationState(_LeasePage):
    family = 6

    @staticmethod
    def _prefix_lease(**changes) -> dict:
        return lease_record("2001:db8:100:100::", type="IA_PD", prefix_len=56, subnet_id=1, **changes)

    def test_a_manual_prefix_is_unmarked_and_offers_sync(self):
        prefix = Prefix.objects.create(prefix=_PREFIX, description="Customer block")

        response = self._get(self._prefix_lease())

        self.assertEqual(self._rows(response)[_PREFIX]["sync_state"].code, "unmarked")
        self._assert_badge(response, _PREFIX, "Unmarked", prefix.get_absolute_url())
        self.assertEqual(self._sync_button(response, _PREFIX)["title"], _TAKES_OVER.format("Prefix"))

    def test_a_prefix_only_another_server_owns_is_not_synchronized_and_row_sync_adds_this_server(self):
        other = _make_db_server(name="other-kea")
        prefix = Prefix.objects.create(prefix=_PREFIX, description="[kea-sync: delegated prefix]")
        prefix_ownership_link(prefix, other)
        record = self._prefix_lease()

        response = self._get(record)

        row = self._rows(response)[_PREFIX]
        self.assertEqual(row["sync_state"].code, "not-synchronized")
        self._assert_badge(response, _PREFIX, "Not Synchronized", prefix.get_absolute_url())
        self.assertEqual(self._sync_button(response, _PREFIX)["title"], _ADDS_OWNER.format("Prefix"))

        with stub_kea({**self._responses(record), "lease6-get": {"result": 0, "arguments": record}}):
            synced = self.client.post(row["sync_url"], {"ip_address": _PREFIX}, HTTP_HX_REQUEST="true")
        self.assertEqual(synced.status_code, 200)
        self.assertEqual(
            set(IPAMOwnershipLink.objects.filter(prefix=prefix).values_list("server__name", "source")),
            {("other-kea", "lease-prefix"), (self.server.name, "lease-prefix")},
        )

        response = self._get(record)
        self._assert_badge(response, _PREFIX, "Synced", prefix.get_absolute_url())
        self.assertIsNone(self._sync_button(response, _PREFIX))

    def test_a_prefix_outside_the_sync_vrf_or_of_another_length_is_not_in_netbox(self):
        Prefix.objects.create(prefix=_PREFIX, vrf=VRF.objects.create(name="other-vrf"))
        Prefix.objects.create(prefix="2001:db8:100:100::/60")
        Prefix.objects.create(prefix="2001:db8:100::/48")
        # An IP address at the network address of the delegated prefix is not its object.
        IPAddress.objects.create(address="2001:db8:100:100::/128", description="Router loopback")

        response = self._get(self._prefix_lease())

        self.assertEqual(self._rows(response)[_PREFIX]["sync_state"].code, "not-in-netbox")
        self.assertTrue(self._sync_button(response, _PREFIX))

    def test_a_failed_read_and_a_prefix_the_user_may_not_view_are_unknown(self):
        Prefix.objects.create(prefix=_PREFIX, description="Customer block")
        address = lease_record("2001:db8:1::10", subnet_id=1)

        with connection.execute_wrapper(_fail_ipam_reads), self.assertLogs("netbox_kea.views.leases", "ERROR"):
            response = self._get(address, self._prefix_lease())
        self.assertEqual(set(self._rows(response)), {"2001:db8:1::10", _PREFIX})
        self._assert_badge(response, _PREFIX, "Unknown", None, title=_UNREADABLE)
        self.assertIsNone(self._sync_button(response, _PREFIX))

        self.client.force_login(_restricted_user("prefix_ownership_limited"))
        response = self._get(address, self._prefix_lease())
        self._assert_badge(response, _PREFIX, "Unknown", None, title=_HIDDEN.format("Prefix"))
        self.assertIsNone(self._sync_button(response, _PREFIX))

    def test_the_table_export_writes_the_state_of_the_prefix(self):
        prefix = Prefix.objects.create(prefix=_PREFIX, description="[kea-sync: delegated prefix]")
        prefix_ownership_link(prefix, self.server)

        self.assertEqual(self._export(self._prefix_lease()), {_PREFIX: "Synchronized"})
        self.assertEqual(self._export(self._prefix_lease(state=_RELEASED)), {_PREFIX: ""})
