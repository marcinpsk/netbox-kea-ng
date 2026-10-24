# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The managed-field list of the DHCP Import: the capability filter, and the table of the configuration guide."""

import re
from pathlib import Path

from django.test import SimpleTestCase

from netbox_kea.integrations.dhcp_import_fields import MANAGED_FIELDS, ManagedField, managed_fields
from netbox_kea.integrations.dhcp_import_report import Capability
from netbox_kea.integrations.dhcp_plugin_capabilities import PluginCapabilities

_GUIDE = Path(__file__).resolve().parents[2] / "docs/guide/configuration.md"


def _guide_table() -> dict[str, tuple[set[str], dict[str, str]]]:
    """Return each model row of the managed-field table: its fields, and its gated fields with their capability."""
    rows = {}
    for line in _GUIDE.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        model = re.fullmatch(r"`(\w+)`", cells[0])
        if len(cells) != 3 or model is None or model.group(1) not in MANAGED_FIELDS:
            continue
        rows[model.group(1)] = (
            set(re.findall(r"`(\w+)`", cells[1])),
            dict(re.findall(r"`(\w+)` \(`(\w+)`\)", cells[2])),
        )
    return rows


class ManagedFieldsTest(SimpleTestCase):
    def test_a_gated_field_counts_only_with_its_capability(self):
        without = managed_fields("ClientClass", PluginCapabilities(frozenset()))
        with_it = managed_fields("ClientClass", PluginCapabilities(frozenset({Capability.USER_CONTEXT})))

        gated = ManagedField("user_context", Capability.USER_CONTEXT)
        self.assertNotIn(gated, without)
        self.assertIn(gated, with_it)
        self.assertEqual(set(with_it) - set(without), {gated})
        self.assertIn(ManagedField("test"), without)

    def test_every_capability_of_a_model_filters_only_its_own_fields(self):
        everything = PluginCapabilities(frozenset(Capability))
        for model, fields in MANAGED_FIELDS.items():
            for field in fields:
                if field.capability is None:
                    continue
                with self.subTest(model=model, field=field.name):
                    lacking = PluginCapabilities(frozenset(Capability) - {field.capability})
                    left_out = set(managed_fields(model, everything)) - set(managed_fields(model, lacking))
                    self.assertEqual(left_out, {f for f in fields if f.capability == field.capability})

    def test_the_configuration_guide_lists_the_managed_fields_of_each_model(self):
        expected = {
            model: (
                {field.name for field in fields if field.capability is None},
                {field.name: field.capability.value for field in fields if field.capability is not None},
            )
            for model, fields in MANAGED_FIELDS.items()
        }

        self.assertEqual(_guide_table(), expected)
