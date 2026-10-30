# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Reservation forms take the published name and store the hostname that makes Kea publish it (#304).

The Kea replies come from the configuration recorded from Kea 3.2.0: a global suffix ``dhcp.example.com``,
Subnet 10 with an empty suffix, Subnet 20 in the Shared Network ``office`` with ``office.example.net``,
and Subnet 21 with its own ``office.example.org.`` and one Pool with ``pool.example.org``.
"""

import copy
from typing import Any
from urllib.parse import urlencode

import requests
from django.urls import reverse

from netbox_kea import display_cache

from .kea_stub import _res_get, queued, stub_kea
from .test_kea_recordings import _recording
from .utils import _ViewTestBase

_HW = "aa:bb:cc:dd:ee:21"
_SUBNETS: dict[int, dict[int, str]] = {
    4: {10: "192.0.2.0/24", 20: "198.51.100.0/25", 21: "198.51.100.128/25"},
    6: {10: "2001:db8:1::/64", 20: "2001:db8:2::/64", 21: "2001:db8:3::/64"},
}
# An address of each Subnet outside every Pool, and one in the Pool of Subnet 21.
_ADDRESSES: dict[int, dict[int, str]] = {
    4: {10: "192.0.2.30", 20: "198.51.100.60", 21: "198.51.100.130"},
    6: {10: "2001:db8:1::5", 20: "2001:db8:2::5", 21: "2001:db8:3::5"},
}
_IN_POOL = {4: "198.51.100.210", 6: "2001:db8:3::150"}


def _address_field(family: int) -> str:
    return "ip_address" if family == 4 else "ip_addresses"


def _recorded(family: int) -> dict[str, Any]:
    recording = _recording(family)
    return {
        f"subnet{family}-list": recording[f"subnet{family}-list"],
        "config-get": recording["config-get"],
        "config-test": {"result": 0},
        "config-write": {"result": 0},
    }


def _stored(family: int, subnet_id: int, hostname: str, address: str | None = None) -> dict[str, Any]:
    raw: dict[str, Any] = {"subnet-id": subnet_id, "hw-address": _HW}
    address = _ADDRESSES[family][subnet_id] if address is None else address
    if address:
        raw.update({"ip-address": address} if family == 4 else {"ip-addresses": [address]})
    if hostname:
        raw["hostname"] = hostname
    return raw


def _with_subnet_21(family: int, fields: dict[str, Any]) -> dict[str, Any]:
    """Return the recorded config-get reply with *fields* set on Subnet 21."""
    reply = copy.deepcopy(_recording(family)["config-get"])
    daemon = reply["arguments"][f"Dhcp{family}"]
    for subnet in [
        *daemon.get(f"subnet{family}", []),
        *(member for network in daemon.get("shared-networks", []) for member in network.get(f"subnet{family}", [])),
    ]:
        if subnet["id"] == 21:
            subnet.update(fields)
    return reply


class _PublishedNameViewTest(_ViewTestBase):
    def setUp(self):
        super().setUp()
        for family in (4, 6):
            display_cache.rotate_configuration(self.server, family)

    def _url(self, family: int, subnet_id: int) -> str:
        url = reverse(f"plugins:netbox_kea:server_reservation{family}_edit", args=[self.server.pk, subnet_id])
        return f"{url}?{urlencode({'identifier_type': 'hw-address', 'identifier': _HW})}"

    def _open(self, family: int, subnet_id: int, stored: str):
        with stub_kea({**_recorded(family), "reservation-get": _res_get(_stored(family, subnet_id, stored))}):
            return self.client.get(self._url(family, subnet_id))

    def _form_data(
        self, family: int, subnet_id: int, hostname: str, address: str | None = None, **extra: str
    ) -> dict[str, str]:
        return {
            "subnet_cidr": _SUBNETS[family][subnet_id],
            _address_field(family): _ADDRESSES[family][subnet_id] if address is None else address,
            "identifier_type": "hw-address",
            "identifier": _HW,
            "hostname": hostname,
            **extra,
        }


class TestReservationAddPublishedName(_PublishedNameViewTest):
    def _post_add(self, family: int, subnet_id: int, hostname: str, address: str | None = None):
        intended = _stored(family, subnet_id, "", address)
        with stub_kea(
            {
                **_recorded(family),
                "reservation-add": {"result": 0},
                "reservation-get": _res_get(intended),
            }
        ) as kea:
            response = self.client.post(
                reverse(f"plugins:netbox_kea:server_reservation{family}_add", args=[self.server.pk]),
                self._form_data(family, subnet_id, hostname, address),
            )
        return response, kea

    def _add(self, family: int, subnet_id: int, hostname: str, address: str | None = None) -> dict[str, Any]:
        response, kea = self._post_add(family, subnet_id, hostname, address)
        self.assertEqual(response.status_code, 302)
        return kea.bodies("reservation-add")[0]["arguments"]["reservation"]

    def test_add_passes_the_entered_published_name_through_the_edit_module(self):
        for family in (4, 6):
            with self.subTest(family=family):
                self.assertEqual(self._add(family, 21, "host.office.example.org")["hostname"], "host")


class TestReservationEditPublishedName(_PublishedNameViewTest):
    def _save(
        self,
        family: int,
        subnet_id: int,
        stored: str,
        entered: str,
        *,
        form_page=None,
        config_get=None,
        address: str | None = None,
    ):
        form_page = form_page or self._open(family, subnet_id, stored)
        current = _stored(family, subnet_id, stored)
        responses = {
            **_recorded(family),
            "reservation-get": queued(_res_get(current), _res_get(current), _res_get(current)),
            "reservation-update": {"result": 0},
        }
        if config_get is not None:
            responses["config-get"] = config_get
        with stub_kea(responses) as kea:
            response = self.client.post(
                self._url(family, subnet_id),
                self._form_data(
                    family,
                    subnet_id,
                    entered,
                    address,
                    managed_fingerprint=form_page.context["form"].initial["managed_fingerprint"],
                ),
            )
        return response, kea

    def test_the_edit_form_uses_the_modules_published_name_initial_values(self):
        for family in (4, 6):
            with self.subTest(family=family):
                response = self._open(family, 21, "host")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["form"].initial["hostname"], "host.office.example.org")
                self.assertContains(response, 'value="host.office.example.org"')

    def test_a_changed_suffix_refuses_the_save(self):
        # The form showed the name under one suffix; Kea now has another, so the shown name is stale.
        form_page = self._open(4, 21, "host")
        changed = _recording(4)["config-get"]
        changed = {
            **changed,
            "arguments": {
                **changed["arguments"],
                "Dhcp4": {
                    **changed["arguments"]["Dhcp4"],
                    "shared-networks": [
                        {
                            **network,
                            "subnet4": [
                                {**subnet, "ddns-qualifying-suffix": "moved.example.org"}
                                for subnet in network["subnet4"]
                            ],
                        }
                        for network in changed["arguments"]["Dhcp4"]["shared-networks"]
                    ],
                },
            },
        }
        response, kea = self._save(4, 21, "host", "host.office.example.org", form_page=form_page, config_get=changed)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("reservation-update", kea.commands())
        self.assertIn(
            "The qualifying suffix differs from the one shown (office.example.org. → moved.example.org). "
            "Check the name and save again.",
            " ".join(response.context["form"].non_field_errors()),
        )
        self.assertContains(response, "The qualifying suffix differs from the one shown")
        preview_url = reverse("plugins:netbox_kea:server_reservation4_published_name", args=[self.server.pk])
        with stub_kea({**_recorded(4), "config-get": changed}):
            preview = self.client.get(
                preview_url, {"subnet_cidr": _SUBNETS[4][21], "ip_address": _ADDRESSES[4][21], "hostname": "host"}
            )
        self.assertEqual(preview.context["suffix"], "moved.example.org")
        self.assertEqual(preview.context["published"], "host.moved.example.org")
        refreshed = response.context["form"]["managed_fingerprint"].value()
        with stub_kea(
            {
                **_recorded(4),
                "config-get": changed,
                "reservation-get": _res_get(_stored(4, 21, "host")),
                "reservation-update": {"result": 0},
            }
        ) as retry_kea:
            retry = self.client.post(
                self._url(4, 21), self._form_data(4, 21, "host.moved.example.org", managed_fingerprint=refreshed)
            )
        self.assertEqual(retry.status_code, 302)
        self.assertEqual(retry_kea.bodies("reservation-update")[0]["arguments"]["reservation"]["hostname"], "host")

    def _save_with_unknown_suffix(self, family: int, entered: str, address: str):
        # An invalid suffix makes the configuration of Subnet 21 unknown; its identity stays verified.
        unknown = {**_recorded(family), "config-get": _with_subnet_21(family, {"ddns-qualifying-suffix": 5})}
        current = _stored(family, 21, "host")
        with stub_kea({**unknown, "reservation-get": _res_get(current)}):
            form_page = self.client.get(self._url(family, 21))
        self.assertEqual(form_page.status_code, 200)
        self.assertEqual(form_page.context["form"].initial["hostname"], "host")
        with stub_kea(
            {
                **unknown,
                "reservation-get": queued(_res_get(current), _res_get(current), _res_get(current)),
                "reservation-update": {"result": 0},
            }
        ) as kea:
            response = self.client.post(
                self._url(family, 21),
                self._form_data(
                    family,
                    21,
                    entered,
                    address,
                    managed_fingerprint=form_page.context["form"].initial["managed_fingerprint"],
                ),
            )
        return response, kea

    def test_an_unknown_suffix_refuses_a_changed_name_on_its_field(self):
        response, kea = self._save_with_unknown_suffix(4, "db", _ADDRESSES[4][21])
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("reservation-update", kea.commands())
        self.assertIn(
            "The DDNS qualifying suffix of Subnet 198.51.100.128/25 is unknown.",
            " ".join(response.context["form"].errors["hostname"]),
        )

    def _open_with_unknown_suffix(self, stored: str):
        unknown = {**_recorded(4), "config-get": _with_subnet_21(4, {"ddns-qualifying-suffix": 5})}
        with stub_kea({**unknown, "reservation-get": _res_get(_stored(4, 21, stored))}):
            form_page = self.client.get(self._url(4, 21))
        self.assertEqual(form_page.context["form"].initial["hostname"], stored)
        return form_page

    def test_a_stored_hostname_shown_without_a_suffix_stays_unchanged_once_the_suffix_is_known(self):
        # Kea publishes host.example.net.office.example.org; the form showed only the stored hostname.
        form_page = self._open_with_unknown_suffix("host.example.net")
        response, kea = self._save(
            4, 21, "host.example.net", "host.example.net", form_page=form_page, address="198.51.100.131"
        )
        self.assertEqual(response.status_code, 302)
        update = kea.bodies("reservation-update")[0]["arguments"]["reservation"]
        self.assertEqual(update["ip-address"], "198.51.100.131")
        self.assertEqual(update["hostname"], "host.example.net")

    def test_a_changed_name_shown_without_a_suffix_refuses_the_save_once_the_suffix_is_known(self):
        form_page = self._open_with_unknown_suffix("host.example.net")
        response, kea = self._save(4, 21, "host.example.net", "db.example.net", form_page=form_page)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("reservation-update", kea.commands())
        self.assertIn(
            "The form showed the stored hostname, but the qualifying suffix is now known. "
            "Check the name and save again.",
            " ".join(response.context["form"].non_field_errors()),
        )
        refreshed = response.context["form"]["managed_fingerprint"].value()
        self.assertNotEqual(refreshed, form_page.context["form"].initial["managed_fingerprint"])
        self.assertEqual(response.context["form"].initial["hostname"], "host.example.net.office.example.org")


class TestPublishedNamePreview(_PublishedNameViewTest):
    """The preview endpoint renders the name that Kea publishes, from the cached Subnet Catalogue."""

    def _preview(self, family: int, **params: str):
        url = reverse(f"plugins:netbox_kea:server_reservation{family}_published_name", args=[self.server.pk])
        return self.client.get(url, params, headers={"HX-Request": "true"})

    def _subnet(self, family: int, subnet_id: int, address: str | None = None) -> dict[str, str]:
        address = _ADDRESSES[family][subnet_id] if address is None else address
        return {"subnet_cidr": _SUBNETS[family][subnet_id], _address_field(family): address}

    def test_the_preview_shows_the_published_name(self):
        for family in (4, 6):
            for subnet_id, entered, published, address in (
                (21, "printer", "printer.office.example.org", None),
                (21, "web.example.com", "web.example.com", None),
                (21, "DB.Office.Example.org.", "db.office.example.org", None),
                (21, "printer", "printer.pool.example.org", _IN_POOL[family]),
                (20, "printer", "printer.office.example.net", None),
                (20, "printer", "printer.office.example.net", ""),
                (10, "printer", "printer", None),
            ):
                with (
                    self.subTest(family=family, subnet_id=subnet_id, entered=entered, address=address),
                    stub_kea(_recorded(family)),
                ):
                    response = self._preview(family, **self._subnet(family, subnet_id, address), hostname=entered)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.context["published"], published)
                    self.assertContains(response, f"<code>{published}</code>", html=False)

    def test_the_preview_shows_the_suffix_without_its_trailing_dot(self):
        with stub_kea(_recorded(4)):
            response = self._preview(4, **self._subnet(4, 21), hostname="printer")
        self.assertContains(response, "with the DDNS qualifying suffix <code>office.example.org</code>.")
        self.assertNotContains(response, "office.example.org.</code>")

    def test_the_preview_reads_the_cached_catalogue(self):
        with stub_kea(_recorded(4)) as kea:
            self._preview(4, **self._subnet(4, 21), hostname="printer")
            commands = kea.commands()
            response = self._preview(4, **self._subnet(4, 20), hostname="printer")
            self.assertEqual(kea.commands(), commands)
        self.assertEqual(response.context["published"], "printer.office.example.net")

    def test_the_preview_without_a_name_or_a_known_subnet(self):
        with stub_kea(_recorded(4)):
            self.assertEqual(self._preview(4, subnet_cidr=_SUBNETS[4][21], hostname="").content.strip(), b"")
            for cidr in ("203.0.113.0/24", "not-a-subnet", ""):
                with self.subTest(cidr=cidr):
                    response = self._preview(4, subnet_cidr=cidr, hostname="printer")
                    self.assertEqual(response.status_code, 200)
                    self.assertNotIn("published", response.context)
                    self.assertContains(response, "Enter a Subnet of this server")

    def test_an_unknown_suffix_says_so(self):
        with stub_kea({**_recorded(4), "config-get": requests.ConnectionError("config-get failed")}):
            response = self._preview(4, **self._subnet(4, 21), hostname="printer")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("published", response.context)
        self.assertContains(response, "The DDNS qualifying suffix for this Subnet and address is unknown")

    def test_a_pool_suffix_without_an_address_says_the_name_is_unknown(self):
        for family in (4, 6):
            with self.subTest(family=family), stub_kea(_recorded(family)):
                for address in ("", "not-an-address"):
                    response = self._preview(family, **self._subnet(family, 21, address), hostname="printer")
                    self.assertNotIn("published", response.context)
                    self.assertContains(response, "The DDNS qualifying suffix for this Subnet and address is unknown")

    def test_the_preview_needs_the_change_permission(self):
        from django.contrib.contenttypes.models import ContentType
        from users.models import ObjectPermission

        self.user.is_superuser = False
        self.user.save()
        permission = ObjectPermission.objects.create(name="view-published-name-server", actions=["view"])
        permission.object_types.add(ContentType.objects.get_for_model(type(self.server)))
        permission.users.add(self.user)
        with stub_kea(_recorded(4)) as kea:
            response = self._preview(4, subnet_cidr=_SUBNETS[4][21], hostname="printer")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(kea.commands(), [])

    def test_the_forms_request_the_preview(self):
        preview = reverse("plugins:netbox_kea:server_reservation4_published_name", args=[self.server.pk])
        with stub_kea(_recorded(4)):
            add = self.client.get(reverse("plugins:netbox_kea:server_reservation4_add", args=[self.server.pk]))
        self.assertContains(add, f'hx-get="{preview}"')
        self.assertContains(add, 'hx-include="#id_hostname, #id_subnet_cidr, #id_ip_address"')
        edit = self._open(4, 21, "host")
        self.assertContains(edit, f'hx-get="{preview}?{urlencode({"subnet_cidr": _SUBNETS[4][21]})}"')
