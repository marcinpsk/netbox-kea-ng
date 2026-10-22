# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The managed-field list of the DHCP Import, its capability filter, and the tables of the DHCP Import guide."""

import re
from pathlib import Path

from django.test import SimpleTestCase

from netbox_kea.integrations.dhcp_import_fields import MANAGED_FIELDS, ManagedField, managed_fields
from netbox_kea.integrations.dhcp_import_report import (
    CAPABILITY_LABELS,
    OUTCOME_LABELS,
    REASON_LABELS,
    REASON_OUTCOME,
    Capability,
    Reason,
)
from netbox_kea.integrations.dhcp_plugin_capabilities import PluginCapabilities

_GUIDE = Path(__file__).resolve().parents[2] / "docs/guide/dhcp-import.md"


def _guide_rows(codes) -> dict[str, list[str]]:
    """Return the other cells of each guide table row whose first cell is one of *codes* in backticks."""
    rows = {}
    for line in _GUIDE.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        code = re.fullmatch(r"`(\w+)`", cells[0])
        if code is not None and code.group(1) in codes:
            rows[code.group(1)] = cells[1:]
    return rows


def _guide_table() -> dict[str, tuple[set[str], dict[str, str]]]:
    """Return each model row of the managed-field table: its fields, and its gated fields with their capability."""
    rows = {}
    for model, cells in _guide_rows(MANAGED_FIELDS).items():
        rows[model] = (
            set(re.findall(r"`(\w+)`", cells[0])),
            dict(re.findall(r"`(\w+)` \(`(\w+)`\)", cells[1])),
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

    def test_the_dhcp_import_guide_lists_the_managed_fields_of_each_model(self):
        expected = {
            model: (
                {field.name for field in fields if field.capability is None},
                {field.name: field.capability.value for field in fields if field.capability is not None},
            )
            for model, fields in MANAGED_FIELDS.items()
        }

        self.assertEqual(_guide_table(), expected)

    def test_the_dhcp_import_guide_lists_each_capability_with_its_name_and_gap(self):
        rows = _guide_rows({capability.value for capability in Capability})

        listed = {code: f"{cells[0]} (#88 gap {cells[1]})" for code, cells in rows.items()}
        self.assertEqual(listed, {capability.value: label for capability, label in CAPABILITY_LABELS.items()})

    def test_the_dhcp_import_guide_lists_each_reason_code_with_its_outcome_and_label(self):
        rows = _guide_rows({reason.value for reason in Reason})

        self.assertEqual(
            {code: tuple(cells) for code, cells in rows.items()},
            {reason.value: (OUTCOME_LABELS[REASON_OUTCOME[reason]], REASON_LABELS[reason]) for reason in Reason},
        )
