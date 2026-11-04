# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import re
from collections import defaultdict

from django.test import SimpleTestCase
from django.urls import (
    NoReverseMatch,
    Resolver404,
    URLResolver,
    include,
    path,
    resolve,
    reverse,
)

from netbox_kea.urls import urlpatterns
from netbox_kea.views.leases import ServerLeaseAddView


def _registered_paths(patterns, prefix=""):
    for entry in patterns:
        route = prefix + str(entry.pattern)
        if isinstance(entry, URLResolver):
            yield from _registered_paths(entry.url_patterns, route)
        else:
            yield route, entry.name


class TestPluginURLRegistration(SimpleTestCase):
    def _assert_unique_paths(self, patterns):
        names_by_path = defaultdict(list)
        for route, name in _registered_paths(patterns):
            names_by_path[route].append(name)
        duplicates = {route: names for route, names in names_by_path.items() if len(names) > 1}
        self.assertEqual(duplicates, {}, f"Duplicate plugin URL paths: {duplicates}")

    def test_plugin_paths_have_one_registration(self):
        self._assert_unique_paths(urlpatterns)

    def test_plugin_names_have_one_registration(self):
        # reverse() returns only one of two paths with the same name, so the other path is served but never linked.
        paths_by_name = defaultdict(list)
        for route, name in _registered_paths(urlpatterns):
            if name is not None:
                paths_by_name[name].append(route)
        duplicates = {name: routes for name, routes in paths_by_name.items() if len(routes) > 1}
        self.assertEqual(duplicates, {}, f"Duplicate plugin URL names: {duplicates}")

    def test_duplicate_guard_detects_an_explicit_path_repeated_in_an_include(self):
        view = ServerLeaseAddView.as_view()
        patterns = [
            path("servers/<int:pk>/leases4/add/", view, name="explicit_add"),
            path("servers/<int:pk>/", include([path("leases4/add/", view, name="registered_add")])),
        ]
        with self.assertRaisesRegex(AssertionError, "Duplicate plugin URL paths"):
            self._assert_unique_paths(patterns)

    def test_duplicate_guard_accepts_the_same_leaf_under_distinct_parent_paths(self):
        view = ServerLeaseAddView.as_view()
        patterns = [
            path("servers/<int:pk>/", include([path("add/", view, name="server_add")])),
            path("combined/", include([path("add/", view, name="combined_add")])),
        ]
        self._assert_unique_paths(patterns)

    def test_lease_add_names_reverse_and_resolve_to_the_registered_views(self):
        for family in (4, 6):
            with self.subTest(family=family):
                url = reverse("plugins:netbox_kea:server_lease_add", kwargs={"pk": 1, "family": family})
                self.assertTrue(url.endswith(f"/servers/1/leases{family}/add/"), url)
                match = resolve(url)
                self.assertIs(match.func.view_class, ServerLeaseAddView)
                self.assertEqual(match.view_name, "plugins:netbox_kea:server_lease_add")
                self.assertEqual(match.kwargs, {"pk": 1, "family": family})


# Each per-family UI route of the tree before the family became a route parameter: name, family, kwargs, path.
_RECORDED_PATHS: tuple[tuple[str, int, dict[str, object], str], ...] = (
    ("combined_configuration4", 4, {}, "/plugins/kea/combined/configuration4/"),
    ("combined_configuration6", 6, {}, "/plugins/kea/combined/configuration6/"),
    ("combined_leases4", 4, {}, "/plugins/kea/combined/leases4/"),
    ("combined_leases6", 6, {}, "/plugins/kea/combined/leases6/"),
    ("combined_overview4", 4, {}, "/plugins/kea/combined/overview4/"),
    ("combined_overview6", 6, {}, "/plugins/kea/combined/overview6/"),
    ("combined_reservations4", 4, {}, "/plugins/kea/combined/reservations4/"),
    ("combined_reservations6", 6, {}, "/plugins/kea/combined/reservations6/"),
    ("combined_shared_networks4", 4, {}, "/plugins/kea/combined/shared-networks4/"),
    ("combined_shared_networks6", 6, {}, "/plugins/kea/combined/shared-networks6/"),
    ("combined_subnets4", 4, {}, "/plugins/kea/combined/subnets4/"),
    ("combined_subnets6", 6, {}, "/plugins/kea/combined/subnets6/"),
    ("combined_sync4", 4, {}, "/plugins/kea/combined/sync4/"),
    ("combined_sync6", 6, {}, "/plugins/kea/combined/sync6/"),
    ("server_dhcp4_disable", 4, {"pk": 1}, "/plugins/kea/servers/1/dhcp4/disable/"),
    ("server_dhcp4_enable", 4, {"pk": 1}, "/plugins/kea/servers/1/dhcp4/enable/"),
    ("server_dhcp4_options_edit", 4, {"pk": 1}, "/plugins/kea/servers/1/dhcp4/options/"),
    ("server_dhcp6_disable", 6, {"pk": 1}, "/plugins/kea/servers/1/dhcp6/disable/"),
    ("server_dhcp6_enable", 6, {"pk": 1}, "/plugins/kea/servers/1/dhcp6/enable/"),
    ("server_dhcp6_options_edit", 6, {"pk": 1}, "/plugins/kea/servers/1/dhcp6/options/"),
    ("server_lease4_add", 4, {"pk": 1}, "/plugins/kea/servers/1/leases4/add/"),
    ("server_lease4_bulk_import", 4, {"pk": 1}, "/plugins/kea/servers/1/leases4/import/"),
    ("server_lease4_edit", 4, {"pk": 1, "ip_address": "192.0.2.15"}, "/plugins/kea/servers/1/leases4/192.0.2.15/edit/"),
    ("server_lease4_sync", 4, {"pk": 1}, "/plugins/kea/servers/1/leases4/sync/"),
    ("server_lease6_add", 6, {"pk": 1}, "/plugins/kea/servers/1/leases6/add/"),
    ("server_lease6_bulk_import", 6, {"pk": 1}, "/plugins/kea/servers/1/leases6/import/"),
    (
        "server_lease6_edit",
        6,
        {"pk": 1, "ip_address": "2001:db8::15"},
        "/plugins/kea/servers/1/leases6/2001:db8::15/edit/",
    ),
    ("server_lease6_sync", 6, {"pk": 1}, "/plugins/kea/servers/1/leases6/sync/"),
    ("server_leases4", 4, {"pk": 1}, "/plugins/kea/servers/1/leases4/"),
    ("server_leases4_delete", 4, {"pk": 1}, "/plugins/kea/servers/1/leases4/delete/"),
    ("server_leases6", 6, {"pk": 1}, "/plugins/kea/servers/1/leases6/"),
    ("server_leases6_delete", 6, {"pk": 1}, "/plugins/kea/servers/1/leases6/delete/"),
    ("server_option_def4", 4, {"pk": 1}, "/plugins/kea/servers/1/dhcp4/option-def/"),
    ("server_option_def4_add", 4, {"pk": 1}, "/plugins/kea/servers/1/dhcp4/option-def/add/"),
    (
        "server_option_def4_delete",
        4,
        {"pk": 1, "code": 224, "space": "dhcp4"},
        "/plugins/kea/servers/1/dhcp4/option-def/224/dhcp4/delete/",
    ),
    ("server_option_def6", 6, {"pk": 1}, "/plugins/kea/servers/1/dhcp6/option-def/"),
    ("server_option_def6_add", 6, {"pk": 1}, "/plugins/kea/servers/1/dhcp6/option-def/add/"),
    (
        "server_option_def6_delete",
        6,
        {"pk": 1, "code": 224, "space": "dhcp6"},
        "/plugins/kea/servers/1/dhcp6/option-def/224/dhcp6/delete/",
    ),
    ("server_reservation4_add", 4, {"pk": 1}, "/plugins/kea/servers/1/reservations4/add/"),
    ("server_reservation4_bulk_import", 4, {"pk": 1}, "/plugins/kea/servers/1/reservations4/import/"),
    ("server_reservation4_bulk_sync", 4, {"pk": 1}, "/plugins/kea/servers/1/reservations4/bulk-sync/"),
    ("server_reservation4_delete", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/reservations4/7/delete/"),
    ("server_reservation4_edit", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/reservations4/7/edit/"),
    ("server_reservation4_published_name", 4, {"pk": 1}, "/plugins/kea/servers/1/reservations4/published-name/"),
    ("server_reservation4_sync", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/reservations4/7/sync/"),
    ("server_reservation6_add", 6, {"pk": 1}, "/plugins/kea/servers/1/reservations6/add/"),
    ("server_reservation6_bulk_import", 6, {"pk": 1}, "/plugins/kea/servers/1/reservations6/import/"),
    ("server_reservation6_bulk_sync", 6, {"pk": 1}, "/plugins/kea/servers/1/reservations6/bulk-sync/"),
    ("server_reservation6_delete", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/reservations6/7/delete/"),
    ("server_reservation6_edit", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/reservations6/7/edit/"),
    ("server_reservation6_published_name", 6, {"pk": 1}, "/plugins/kea/servers/1/reservations6/published-name/"),
    ("server_reservation6_sync", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/reservations6/7/sync/"),
    ("server_reservations4", 4, {"pk": 1}, "/plugins/kea/servers/1/reservations4/"),
    ("server_reservations6", 6, {"pk": 1}, "/plugins/kea/servers/1/reservations6/"),
    ("server_shared_network4_add", 4, {"pk": 1}, "/plugins/kea/servers/1/shared-networks4/add/"),
    (
        "server_shared_network4_delete",
        4,
        {"pk": 1, "network_name": "office"},
        "/plugins/kea/servers/1/shared-networks4/office/delete/",
    ),
    (
        "server_shared_network4_edit",
        4,
        {"pk": 1, "network_name": "office"},
        "/plugins/kea/servers/1/shared-networks4/office/edit/",
    ),
    ("server_shared_network6_add", 6, {"pk": 1}, "/plugins/kea/servers/1/shared-networks6/add/"),
    (
        "server_shared_network6_delete",
        6,
        {"pk": 1, "network_name": "office"},
        "/plugins/kea/servers/1/shared-networks6/office/delete/",
    ),
    (
        "server_shared_network6_edit",
        6,
        {"pk": 1, "network_name": "office"},
        "/plugins/kea/servers/1/shared-networks6/office/edit/",
    ),
    ("server_shared_networks4", 4, {"pk": 1}, "/plugins/kea/servers/1/shared_networks4/"),
    ("server_shared_networks6", 6, {"pk": 1}, "/plugins/kea/servers/1/shared_networks6/"),
    ("server_subnet4_add", 4, {"pk": 1}, "/plugins/kea/servers/1/subnets4/add/"),
    ("server_subnet4_delete", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets4/7/delete/"),
    ("server_subnet4_edit", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets4/7/edit/"),
    ("server_subnet4_options_edit", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets4/7/options/"),
    ("server_subnet4_pool_add", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets4/7/pools/add/"),
    (
        "server_subnet4_pool_delete",
        4,
        {"pk": 1, "subnet_id": 7, "pool": "192.0.2.10-192.0.2.20"},
        "/plugins/kea/servers/1/subnets4/7/pools/192.0.2.10-192.0.2.20/delete/",
    ),
    ("server_subnet4_wipe_leases", 4, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets4/7/wipe/"),
    ("server_subnet6_add", 6, {"pk": 1}, "/plugins/kea/servers/1/subnets6/add/"),
    ("server_subnet6_delete", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets6/7/delete/"),
    ("server_subnet6_edit", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets6/7/edit/"),
    ("server_subnet6_options_edit", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets6/7/options/"),
    ("server_subnet6_pool_add", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets6/7/pools/add/"),
    (
        "server_subnet6_pool_delete",
        6,
        {"pk": 1, "subnet_id": 7, "pool": "2001:db8::10-2001:db8::20"},
        "/plugins/kea/servers/1/subnets6/7/pools/2001:db8::10-2001:db8::20/delete/",
    ),
    ("server_subnet6_wipe_leases", 6, {"pk": 1, "subnet_id": 7}, "/plugins/kea/servers/1/subnets6/7/wipe/"),
    ("server_subnets4", 4, {"pk": 1}, "/plugins/kea/servers/1/subnets4/"),
    ("server_subnets6", 6, {"pk": 1}, "/plugins/kea/servers/1/subnets6/"),
)
# A family digit at the end of a word of a route name or path, such as leases4 or dhcp6.
_FAMILY_DIGIT = re.compile(r"(?<=[a-z])[46](?=[_/\\.]|$)")


def _new_name(old: str) -> str:
    return _FAMILY_DIGIT.sub("", old)


class TestFamilyRouteParameter(SimpleTestCase):
    def test_each_recorded_path_reverses_from_the_name_without_the_family_digit(self):
        self.assertEqual(len(_RECORDED_PATHS), 78)
        for old, family, kwargs, recorded in _RECORDED_PATHS:
            with self.subTest(old):
                self.assertEqual(
                    reverse(f"plugins:netbox_kea:{_new_name(old)}", kwargs={**kwargs, "family": family}), recorded
                )

    def test_each_recorded_path_resolves_to_one_class_per_page_with_the_family(self):
        classes = defaultdict(set)
        for old, family, kwargs, recorded in _RECORDED_PATHS:
            with self.subTest(old):
                match = resolve(recorded)
                self.assertEqual(match.view_name, f"plugins:netbox_kea:{_new_name(old)}")
                self.assertEqual(match.kwargs, {**kwargs, "family": family})
                classes[match.view_name].add(match.func.view_class)
        self.assertEqual({name: len(found) for name, found in classes.items() if len(found) != 1}, {})
        for name, (view,) in classes.items():
            for owner in view.__mro__:
                with self.subTest(name, owner=owner.__name__):
                    self.assertNotIsInstance(vars(owner).get("dhcp_version"), int)

    def test_a_family_outside_4_and_6_neither_reverses_nor_resolves(self):
        with self.assertRaises(NoReverseMatch):
            reverse("plugins:netbox_kea:server_leases", kwargs={"pk": 1, "family": 5})
        with self.assertRaises(Resolver404):
            resolve("/plugins/kea/servers/1/leases5/")
