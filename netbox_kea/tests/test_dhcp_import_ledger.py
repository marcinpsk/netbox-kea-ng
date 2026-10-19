# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The parity ledger lists each Kea key that the DHCP Import can meet once, and agrees with a real Kea 3.2.

The key lists, the deprecated keys and the merged keys come from scripts/record_kea_config_get.py (see
test_kea_recordings.py). The agreement with the import's field maps needs netbox_dhcp.
"""

import json
import unittest
from pathlib import Path

from django.apps import apps
from django.core.exceptions import FieldDoesNotExist
from django.test import SimpleTestCase, tag

from netbox_kea.integrations import dhcp_import_ledger as ledger
from netbox_kea.integrations.dhcp_import_ledger import (
    LEDGER,
    MERGED_KEYS,
    Capability,
    Deprecated,
    Mapped,
    NotImported,
    Pending,
)
from netbox_kea.integrations.dhcp_import_report import Reason

_RECORDINGS = Path(__file__).with_name("kea_recordings")
# The open tickets of #89 that map a key.
_PARITY_TICKETS = frozenset({93, 94, 95, 96, 97, 98, 99, 100, 101, 104, 106, 107})
# Collections of child objects: an empty one in config-get is a Kea default, never a merge.
_CHILD_COLLECTIONS = frozenset({"option-data", "option-def", "pools", "pd-pools", "reservations", "subnet4", "subnet6"})


def _accepted_keys() -> dict[int, dict[str, set[str]]]:
    recorded = json.loads((_RECORDINGS / "accepted-keys.json").read_text())
    return {family: {table: set(keys) for table, keys in recorded[f"dhcp{family}"].items()} for family in (4, 6)}


def _declared(family: int) -> dict:
    return json.loads((_RECORDINGS / f"kea-dhcp{family}.conf").read_text())[f"Dhcp{family}"]


def _returned(family: int) -> dict:
    recording = json.loads((_RECORDINGS / f"dhcp{family}.json").read_text())
    return recording["config-get"]["arguments"][f"Dhcp{family}"]


def _subnets(daemon: dict, family: int) -> list[tuple[dict, dict | None]]:
    """Return each Subnet of *daemon* with its Shared Network, or ``None`` for a standalone Subnet."""
    standalone = [(subnet, None) for subnet in daemon.get(f"subnet{family}", [])]
    members = [
        (subnet, network)
        for network in daemon.get("shared-networks", [])
        for subnet in network.get(f"subnet{family}", [])
    ]
    return standalone + members


def _objects(daemon: dict, family: int) -> dict[str, list[dict]]:
    """Return every object of *daemon* by the ledger table that lists its keys."""
    subnets = [subnet for subnet, _network in _subnets(daemon, family)]
    classes = daemon.get("client-classes", [])
    pools = [pool for subnet in subnets for pool in subnet.get("pools", [])]
    pd_pools = [pool for subnet in subnets for pool in subnet.get("pd-pools", [])]
    reservations = [*daemon.get("reservations", []), *(r for subnet in subnets for r in subnet.get("reservations", []))]
    networks = daemon.get("shared-networks", [])
    with_options = [daemon, *networks, *subnets, *pools, *pd_pools, *reservations, *classes]
    return {
        f"Dhcp{family}": [daemon],
        "shared-networks": networks,
        f"subnet{family}": subnets,
        "pools": pools,
        "pd-pools": pd_pools,
        "reservations": reservations,
        "client-classes": classes,
        "option-def": [*daemon.get("option-def", []), *(d for c in classes for d in c.get("option-def", []))],
        "option-data": [option for parent in with_options for option in parent.get("option-data", [])],
    }


def _merged(declared: dict, returned: dict, parent: dict, table: str, family: int) -> set[str]:
    """Return the keys that config-get returned on an object that did not declare them, with its parent's value."""
    rewritten = {
        entry.replacement
        for key, entry in LEDGER[family][table].items()
        if isinstance(entry, Deprecated) and key in declared
    }
    return {
        key
        for key, value in returned.items()
        if key not in declared.keys() | rewritten | _CHILD_COLLECTIONS and key in parent and parent[key] == value
    }


def _observed_merges(family: int) -> dict[str, set[str]]:
    """Return the merged keys of each Shared Network, Subnet, Pool and PD Pool that the recording shows."""
    declared, returned = _declared(family), _returned(family)
    networks = {network["name"]: network for network in returned["shared-networks"]}
    merges: dict[str, set[str]] = {"shared-networks": set(), f"subnet{family}": set(), "pools": set()}
    if family == 6:
        merges["pd-pools"] = set()
    for network in declared["shared-networks"]:
        merges["shared-networks"] |= _merged(network, networks[network["name"]], returned, "shared-networks", family)
    subnets = {subnet["id"]: subnet for subnet, _network in _subnets(returned, family)}
    for subnet, network in _subnets(declared, family):
        got = subnets[subnet["id"]]
        parent = returned if network is None else networks[network["name"]]
        merges[f"subnet{family}"] |= _merged(subnet, got, parent, f"subnet{family}", family)
        for table in merges.keys() & {"pools", "pd-pools"}:
            # config-get keeps the order of the pools it read.
            for pool, got_pool in zip(subnet.get(table, []), got.get(table, []), strict=True):
                merges[table] |= _merged(pool, got_pool, got, table, family)
    return merges


class LedgerKeysTest(SimpleTestCase):
    def test_the_ledger_lists_every_key_kea_accepts_and_no_other(self):
        self.assertEqual(ledger.differences(_accepted_keys()), [])

    def test_a_key_missing_from_the_ledger_fails(self):
        recorded = _accepted_keys()
        recorded[4]["subnet4"].add("new-kea-key")

        self.assertEqual(ledger.differences(recorded), ["subnet4 (DHCPv4): new-kea-key is not in the ledger"])

    def test_a_ledger_key_that_kea_no_longer_has_fails(self):
        recorded = _accepted_keys()
        recorded[6]["pd-pools"].discard("excluded-prefix")

        self.assertEqual(
            ledger.differences(recorded),
            ["pd-pools (DHCPv6): excluded-prefix is in the ledger, but Kea has no such key"],
        )

    def test_a_ledger_table_that_kea_no_longer_has_fails(self):
        recorded = _accepted_keys()
        del recorded[4]["option-def"]

        self.assertEqual(ledger.differences(recorded), ["option-def (DHCPv4): Kea has no such object"])


class LedgerEntriesTest(SimpleTestCase):
    def _entries(self):
        return [
            (family, table, key, entry)
            for family, tables in LEDGER.items()
            for table, keys in tables.items()
            for key, entry in keys.items()
        ]

    def test_a_pending_entry_names_an_open_parity_ticket(self):
        for family, table, key, entry in self._entries():
            ticket = entry.ticket if isinstance(entry, Pending) else getattr(entry, "pending", None)
            if ticket is not None:
                with self.subTest(family=family, table=table, key=key):
                    self.assertIn(ticket, _PARITY_TICKETS)

    def test_a_not_imported_entry_has_a_not_imported_reason(self):
        for family, table, key, entry in self._entries():
            if isinstance(entry, NotImported):
                with self.subTest(family=family, table=table, key=key):
                    self.assertIn(entry.reason, {Reason.NO_PLUGIN_HOME, Reason.INVALID_KEA_DATA})
        with self.assertRaises(ValueError):
            NotImported(Reason.WRITE_FAILED)

    def test_a_deprecated_key_names_its_replacement_in_the_same_object(self):
        for family, table, key, entry in self._entries():
            if isinstance(entry, Deprecated):
                with self.subTest(family=family, table=table, key=key):
                    self.assertIn(entry.replacement, LEDGER[family][table])
                    self.assertNotIsInstance(LEDGER[family][table][entry.replacement], Deprecated)

    def test_every_capability_gates_a_key_and_names_its_gap(self):
        named = {
            capability
            for _family, _table, _key, entry in self._entries()
            for capability in getattr(entry, "capabilities", ())
        }
        self.assertEqual(named, set(Capability))
        self.assertEqual(set(ledger.GAPS), set(Capability))

    def test_user_context_is_gated_on_every_object_that_has_it(self):
        for family, tables in LEDGER.items():
            for table, keys in tables.items():
                if "user-context" in keys:
                    with self.subTest(family=family, table=table):
                        self.assertIn(Capability.USER_CONTEXT, keys["user-context"].capabilities)


class RecordedKeaBehaviourTest(SimpleTestCase):
    """The recorded Kea 3.2 shows the deprecated keys and the merged keys that the ledger states."""

    def test_kea_returns_the_replacement_of_each_deprecated_key(self):
        for family in (4, 6):
            declared, returned = _objects(_declared(family), family), _objects(_returned(family), family)
            for table, keys in LEDGER[family].items():
                for key, entry in keys.items():
                    if not isinstance(entry, Deprecated):
                        continue
                    with self.subTest(family=family, table=table, key=key):
                        self.assertTrue(any(key in obj for obj in declared[table]), "the coverage configuration")
                        self.assertFalse(any(key in obj for obj in returned[table]))
                        self.assertTrue(any(entry.replacement in obj for obj in returned[table]))

    def test_the_merged_keys_are_the_ones_kea_merged_into_config_get(self):
        for family in (4, 6):
            with self.subTest(family=family):
                self.assertEqual(
                    _observed_merges(family), {table: set(keys) for table, keys in MERGED_KEYS[family].items()}
                )

    def test_kea_merges_nothing_into_pools_and_delegated_prefix_pools(self):
        self.assertEqual(MERGED_KEYS[4]["pools"], frozenset())
        self.assertEqual((MERGED_KEYS[6]["pools"], MERGED_KEYS[6]["pd-pools"]), (frozenset(), frozenset()))


@tag("dhcp_plugin")
class LedgerAgreesWithTheImportTest(SimpleTestCase):
    """The mapped keys are the ones the import's field maps write, to fields the installed plugin has."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed("netbox_dhcp"):
            raise unittest.SkipTest("netbox_dhcp not installed")
        super().setUpClass()

    def _field_names(self, model: str) -> set[str]:
        return {field.name for field in apps.get_model("netbox_dhcp", model)._meta.get_fields()}

    def test_every_mapped_target_is_a_plugin_model_or_field(self):
        for family, tables in LEDGER.items():
            for table, keys in tables.items():
                for key, entry in keys.items():
                    if isinstance(entry, Mapped):
                        with self.subTest(family=family, table=table, key=key):
                            model, _, field = entry.target.partition(".")
                            if field:
                                apps.get_model("netbox_dhcp", model)._meta.get_field(field)
                            else:
                                apps.get_model("netbox_dhcp", model)

    def test_the_mapped_settings_are_the_field_maps_of_the_import(self):
        from netbox_kea.integrations import dhcp_plugin
        from netbox_kea.mappers.kea_to_dhcp import KEA_SETTINGS_KEYS

        field_maps = {
            "Dhcp": ("DHCPServer", dhcp_plugin._SERVER_FIELDS),
            "subnet": ("Subnet", dhcp_plugin._SUBNET_FIELDS),
            "client-classes": ("ClientClass", dhcp_plugin._COMMON_FIELDS),
        }
        for family in (4, 6):
            for prefix, (model, field_map) in field_maps.items():
                table = prefix if prefix == "client-classes" else f"{prefix}{family}"
                keys = LEDGER[family][table]
                with self.subTest(family=family, table=table):
                    written = {
                        kea_key: f"{model}.{attr}"
                        for kea_key, attr, _transform in field_map
                        if kea_key in keys and attr in self._field_names(model)
                    }
                    mapped = {
                        key: entry.target
                        for key, entry in keys.items()
                        if isinstance(entry, Mapped) and key in KEA_SETTINGS_KEYS
                    }
                    self.assertEqual(mapped, written)

    def test_a_key_without_a_plugin_home_has_no_plugin_field_of_its_name(self):
        models = {"Dhcp": "DHCPServer", "subnet": "Subnet", "shared-networks": "SharedNetwork", "pools": "Pool"}
        models |= {"pd-pools": "PDPool", "reservations": "HostReservation", "client-classes": "ClientClass"}
        models |= {"option-def": "OptionDefinition", "option-data": "Option"}
        for family, tables in LEDGER.items():
            for table, keys in tables.items():
                model = models[table.rstrip("46")]
                for key, entry in keys.items():
                    if isinstance(entry, NotImported):
                        with self.subTest(family=family, table=table, key=key):
                            with self.assertRaises(FieldDoesNotExist):
                                apps.get_model("netbox_dhcp", model)._meta.get_field(key.replace("-", "_"))
