# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The display cache module: TTLs from the settings row, and the settings generation."""

from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from netbox_kea import display_cache, server_configuration, subnet_catalogue
from netbox_kea.models import DisplayCacheConfig

from .kea_stub import _catalogue_responses_for_subnets, stub_kea
from .utils import _make_db_server, _ViewTestBase, with_display_cache_config, with_kea_client_config


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class DisplayCacheSettingsTest(TestCase):
    """The TTL of each display read comes from the DisplayCacheConfig row, and a save of the row empties the cache."""

    def setUp(self):
        self.server = _make_db_server()
        self.responses = _catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.1.0/24"}])

    def _read_display(self) -> list[str]:
        with stub_kea(self.responses) as kea:
            server_configuration.display(self.server, 4)
            subnet_catalogue.display(self.server, 4)
        return kea.commands()

    def _entries(self):
        return cache.keys(f"{display_cache.KEY_PREFIX}entry:*")

    def _assert_warm(self) -> list[str]:
        live = self._read_display()
        self.assertIn("config-get", live)
        self.assertEqual(self._read_display(), [], "the second read is cached")
        return live

    @with_display_cache_config(configuration_ttl=0)
    def test_a_ttl_of_0_sends_every_display_read_to_kea(self):
        live = self._read_display()

        self.assertEqual(self._read_display(), live)
        self.assertEqual(self._entries(), [])

    @with_display_cache_config(configuration_ttl=123)
    def test_the_configuration_ttl_of_the_settings_row_reaches_the_cache(self):
        self._read_display()

        entries = self._entries()
        self.assertEqual(len(entries), 2, "one Server Configuration and one Catalogue entry")
        for key in entries:
            with self.subTest(key=key):
                self.assertTrue(100 < cache.ttl(key) <= 123, cache.ttl(key))

    def test_a_save_of_the_settings_row_with_the_same_values_makes_a_warm_entry_miss(self):
        live = self._assert_warm()

        DisplayCacheConfig.get().save()

        self.assertEqual(self._read_display(), live)

    def test_a_save_of_one_field_of_the_settings_row_makes_a_warm_entry_miss(self):
        live = self._assert_warm()

        row = DisplayCacheConfig.get()
        row.leases_ttl = 60
        row.save(update_fields=["leases_ttl"])

        self.assertEqual(self._read_display(), live)

    def test_a_rotation_of_the_configuration_generation_makes_a_warm_entry_miss(self):
        live = self._assert_warm()

        display_cache.rotate_configuration(self.server, 4)

        self.assertEqual(self._read_display(), live)

    def test_a_rotation_of_the_records_generation_keeps_the_configuration_entries(self):
        self._assert_warm()

        display_cache.rotate_records(self.server, 4)

        self.assertEqual(self._read_display(), [])


class DisplayCacheSettingsPageTest(_ViewTestBase):
    """A save of the Display Cache section on the Settings page empties the display cache."""

    def test_a_save_of_the_section_makes_a_warm_entry_miss(self):
        responses = _catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "198.18.1.0/24"}])
        with stub_kea(responses):
            subnet_catalogue.display(self.server, 4)
        with stub_kea({}) as kea:
            subnet_catalogue.display(self.server, 4)
        self.assertEqual(kea.commands(), [], "the second read is cached")

        response = self.client.post(
            reverse("plugins:netbox_kea:settings"),
            {
                "section": "display-cache",
                "display-cache-configuration_ttl": 300,
                "display-cache-reservations_ttl": 300,
                "display-cache-leases_ttl": 30,
                "display-cache-status_ttl": 15,
            },
            follow=True,
        )

        self.assertContains(response, "Display Cache saved.")
        with stub_kea(responses) as kea:
            subnet_catalogue.display(self.server, 4)
        self.assertIn("subnet4-list", kea.commands())
