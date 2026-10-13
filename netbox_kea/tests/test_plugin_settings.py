# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The settings rows are the only runtime source; a removed PLUGINS_CONFIG key only logs a warning (ADR 0010)."""

import importlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from django.test import SimpleTestCase, TestCase, override_settings

from netbox_kea import REMOVED_SETTINGS, warn_removed_settings
from netbox_kea.ipam_reconciliation import _get_stale_cleanup_mode
from netbox_kea.models import KeaClientConfig, Server
from netbox_kea.tests.utils import with_kea_client_config, with_sync_config

_SEED = importlib.import_module("netbox_kea.migrations.0018_seed_syncconfig")
_COPY = importlib.import_module("netbox_kea.migrations.0025_keaclientconfig_and_sync_settings")

_STARTUP_SETTINGS = """\
from netbox_kea.tests.isolated_settings import *  # noqa: F403

PLUGINS_CONFIG["netbox_kea"] = {"kea_timeout": 10, "not_a_setting": 1}  # noqa: F405
LOGGING = {
    "version": 1,
    "handlers": {"stderr": {"class": "logging.StreamHandler"}},
    "loggers": {"netbox_kea": {"handlers": ["stderr"], "level": "WARNING"}},
}
"""


class RemovedSettingWarningTest(SimpleTestCase):
    def test_each_removed_key_logs_one_warning_that_names_it_and_the_settings_page(self):
        config = {"netbox_kea": {"kea_timeout": 10, "stale_ip_cleanup": "deprecate"}}
        with override_settings(PLUGINS_CONFIG=config), self.assertLogs("netbox_kea", "WARNING") as logs:
            warn_removed_settings()

        self.assertEqual(len(logs.records), 2, logs.output)
        for record, key in zip(logs.records, ("kea_timeout", "stale_ip_cleanup"), strict=True):
            message = record.getMessage()
            self.assertIn(f"['{key}'] is ignored", message)
            self.assertIn("Settings page (DHCP Kea > Settings)", message)

    def test_a_key_that_was_never_a_setting_logs_nothing(self):
        for config in ({}, {"netbox_kea": {}}, {"netbox_kea": {"not_a_setting": 1}}):
            with self.subTest(config=config), override_settings(PLUGINS_CONFIG=config):
                with self.assertNoLogs("netbox_kea", "WARNING"):
                    warn_removed_settings()

    def test_every_key_that_a_migration_copies_is_a_removed_setting(self):
        copied = {
            "sync_interval_minutes",
            "sync_enabled",
            *_SEED.TYPE_TOGGLES,
            *_COPY.SYNC_KEYS,
            *_COPY.KEA_CLIENT_KEYS,
        }

        self.assertEqual(set(REMOVED_SETTINGS), copied)


class StartupWithRemovedSettingTest(SimpleTestCase):
    def test_startup_logs_the_warning_and_succeeds(self):
        environment = os.environ.copy()
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "removed_setting_settings.py").write_text(_STARTUP_SETTINGS)
            environment["PYTHONPATH"] = os.pathsep.join(
                [directory, *(str(Path(entry or Path.cwd()).resolve()) for entry in sys.path)]
            )
            environment["DJANGO_SETTINGS_MODULE"] = "removed_setting_settings"
            result = subprocess.run(
                [sys.executable, "-c", "import django; django.setup(); print('started')"],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=300,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("started", result.stdout)
        warnings = [line for line in result.stderr.splitlines() if "is ignored" in line]
        self.assertEqual(len(warnings), 1, result.stderr)
        self.assertIn("PLUGINS_CONFIG['netbox_kea']['kea_timeout'] is ignored", warnings[0])
        self.assertIn("DHCP Kea > Settings", warnings[0])


class SettingsRowReaderTest(TestCase):
    @with_kea_client_config(kea_timeout=7, lease_query_max_unpaged_leases=250)
    @with_sync_config(stale_ip_cleanup="deprecate")
    def test_each_reader_returns_the_row_value(self):
        client = Server(name="reader", ca_url="https://kea.example.invalid/").get_client(version=4)

        self.assertEqual((client.timeout, client.max_unpaged_leases), (7, 250))
        self.assertEqual(_get_stale_cleanup_mode(), "deprecate")

    @with_kea_client_config(lease_query_max_unpaged_leases=0)
    def test_zero_disables_the_lease_query_guard(self):
        client = Server(name="reader", ca_url="https://kea.example.invalid/").get_client(version=4)

        self.assertIsNone(client.max_unpaged_leases)

    def test_get_client_has_no_fallback_for_a_missing_row(self):
        KeaClientConfig.objects.all().delete()

        with self.assertRaises(KeaClientConfig.DoesNotExist):
            Server(name="reader", ca_url="https://kea.example.invalid/").get_client(version=4)
