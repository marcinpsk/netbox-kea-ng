# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The parity ledger lists each Kea key that the DHCP Import can meet once, and agrees with a real Kea 3.2.

The key lists, the deprecated keys and the merged keys come from scripts/record_kea_config_get.py (see
test_kea_recordings.py). The check of the plugin model fields needs netbox_dhcp.
"""

import ipaddress
import json
import unittest
from collections import defaultdict
from pathlib import Path

from django.apps import apps
from django.core.exceptions import FieldDoesNotExist
from django.test import SimpleTestCase, tag

from netbox_kea.constants import Family
from netbox_kea.integrations import dhcp_import_fields as fields
from netbox_kea.integrations import dhcp_import_ledger as ledger
from netbox_kea.integrations.dhcp_import_ledger import (
    KEA_DEFAULTS,
    LEDGER,
    MERGED_KEYS,
    Deprecated,
    Mapped,
    NotImported,
    Pending,
)
from netbox_kea.integrations.dhcp_import_report import Capability, Reason
from netbox_kea.kea_paths import OPTION_DEF
from netbox_kea.mappers.kea_to_dhcp import KEA_SETTINGS_KEYS

_RECORDINGS = Path(__file__).with_name("kea_recordings")
# The open tickets of #89 that map a key.
_PARITY_TICKETS = frozenset({97, 98, 99, 104, 107})
# Collections of child objects: an empty one in config-get is a Kea default, never a merge.
_CHILD_COLLECTIONS = frozenset({"option-data", OPTION_DEF, "pools", "pd-pools", "reservations", "subnet4", "subnet6"})


def _accepted_keys() -> dict[Family, dict[str, set[str]]]:
    recorded = json.loads((_RECORDINGS / "accepted-keys.json").read_text(encoding="utf-8"))
    return {4: _key_sets(recorded["dhcp4"]), 6: _key_sets(recorded["dhcp6"])}


def _key_sets(tables: dict[str, list[str]]) -> dict[str, set[str]]:
    return {table: set(keys) for table, keys in tables.items()}


def _declared(family: Family) -> dict:
    return json.loads((_RECORDINGS / f"kea-dhcp{family}.conf").read_text(encoding="utf-8"))[f"Dhcp{family}"]


def _returned(family: Family) -> dict:
    recording = json.loads((_RECORDINGS / f"dhcp{family}.json").read_text(encoding="utf-8"))
    return recording["config-get"]["arguments"][f"Dhcp{family}"]


def _subnets(daemon: dict, family: Family) -> list[tuple[dict, dict | None]]:
    """Return each Subnet of *daemon* with its Shared Network, or ``None`` for a standalone Subnet."""
    standalone = [(subnet, None) for subnet in daemon.get(f"subnet{family}", [])]
    members = [
        (subnet, network)
        for network in daemon.get("shared-networks", [])
        for subnet in network.get(f"subnet{family}", [])
    ]
    return standalone + members


_IDENTIFIERS = ("hw-address", "duid", "circuit-id", "client-id", "flex-id")


def _pool_identity(pool: dict) -> tuple:
    """Return a Pool by its address range, or a PD Pool by its prefix and lengths, whatever the spelling."""
    if "prefix" in pool:
        return (ipaddress.ip_address(pool["prefix"]), pool["prefix-len"], pool["delegated-len"])
    if "/" in pool["pool"]:
        network = ipaddress.ip_network(pool["pool"])
        return (network[0], network[-1])
    first, last = (ipaddress.ip_address(part.strip()) for part in pool["pool"].split("-"))
    return (first, last)


def _identity(table: str, family: Family, obj: dict):
    """Return the identity, within its parent, that pairs a configured object with the one config-get returned."""
    if table in ("pools", "pd-pools"):
        return _pool_identity(obj)
    if table == "reservations":
        # Kea returns a client-id without colons and in upper case.
        kind = next(key for key in _IDENTIFIERS if key in obj)
        return (kind, obj[kind].replace(":", "").lower())
    if table == OPTION_DEF:
        return (obj.get("space", f"dhcp{family}"), obj["code"])
    return obj["id"] if table == f"subnet{family}" else obj.get("name", table)


def _matches(table: str, family: Family, declared: dict, returned: dict) -> bool:
    """Return whether config-get returned *returned* for the configured *declared* object.

    Kea returns an option with its space, name and code, so the configured spelling decides.
    """
    if table != "option-data":
        return _identity(table, family, declared) == _identity(table, family, returned)
    key = "code" if "code" in declared else "name"
    return (
        declared[key] == returned.get(key)
        and declared.get("space", f"dhcp{family}") == returned["space"]
        and sorted(declared.get("client-classes", [])) == sorted(returned.get("client-classes", []))
    )


def _objects(daemon: dict, family: Family) -> dict[str, list[tuple[tuple, dict]]]:
    """Return every object of *daemon* by the ledger table that lists its keys, each with the path of its parent."""
    found: dict[str, list[tuple[tuple, dict]]] = defaultdict(list)

    def visit(table: str, obj: dict, scope: tuple) -> tuple:
        found[table].append((scope, obj))
        here = (*scope, (table, _identity(table, family, obj)))
        for child in ("option-data", OPTION_DEF):
            for entry in obj.get(child, []):
                found[child].append((here, entry))
        return here

    def visit_subnet(subnet: dict, scope: tuple) -> None:
        here = visit(f"subnet{family}", subnet, scope)
        for table in ("pools", "pd-pools", "reservations"):
            for child in subnet.get(table, []):
                visit(table, child, here)

    root = visit(f"Dhcp{family}", daemon, ())
    for table in ("client-classes", "reservations"):
        for obj in daemon.get(table, []):
            visit(table, obj, root)
    for subnet in daemon.get(f"subnet{family}", []):
        visit_subnet(subnet, root)
    for network in daemon.get("shared-networks", []):
        here = visit("shared-networks", network, root)
        for subnet in network.get(f"subnet{family}", []):
            visit_subnet(subnet, here)
    return found


def _paired(table: str, family: Family, declared: list[dict], returned: list[dict]) -> list[tuple[dict, dict]]:
    """Pair each configured object with the one config-get returned; both sides must hold the same objects."""
    by_identity = {_identity(table, family, obj): obj for obj in returned}
    identities = [_identity(table, family, obj) for obj in declared]
    if sorted(map(repr, identities)) != sorted(map(repr, by_identity)) or len(by_identity) != len(returned):
        raise AssertionError(f"{table}: config-get returned {sorted(by_identity)}, the configuration has {identities}")
    return [(obj, by_identity[identity]) for obj, identity in zip(declared, identities, strict=True)]


def _undeclared(declared: dict, returned: dict, parent: dict, table: str, family: Family) -> tuple[set[str], set[str]]:
    """Split the keys that config-get returned and the configuration did not declare: merged, or Kea defaults.

    A merged key has its parent's value. A declared deprecated key declares its replacement. An empty collection of
    child objects is a Kea default.
    """
    rewritten = {
        entry.replacement
        for key, entry in LEDGER[family][table].items()
        if isinstance(entry, Deprecated) and key in declared
    }
    undeclared = {
        key
        for key in returned.keys() - declared.keys() - rewritten
        if not (key in _CHILD_COLLECTIONS and returned[key] == [])
    }
    merged = {key for key in undeclared if key in parent and parent[key] == returned[key]}
    return merged, undeclared - merged


def _observed(family: Family) -> tuple[dict[str, set[str]], dict[str, set[tuple[str, str]]]]:
    """Return the merged keys and the Kea defaults, as (key, JSON value), of each object that the ledger states."""
    declared, returned = _declared(family), _returned(family)
    pool_tables = ["pools", *(["pd-pools"] if family == 6 else [])]
    tables = ["client-classes", "shared-networks", f"subnet{family}", *pool_tables]
    merges: dict[str, set[str]] = {table: set() for table in tables}
    defaults: dict[str, set[tuple[str, str]]] = {table: set() for table in tables}

    def observe(table: str, obj: dict, got: dict, parent: dict) -> None:
        merged, default = _undeclared(obj, got, parent, table, family)
        merges[table] |= merged
        defaults[table] |= {(key, json.dumps(got[key])) for key in default}

    for obj, got in _paired("client-classes", family, declared["client-classes"], returned["client-classes"]):
        observe("client-classes", obj, got, returned)
    networks = _paired("shared-networks", family, declared["shared-networks"], returned["shared-networks"])
    for obj, got in networks:
        observe("shared-networks", obj, got, returned)
    returned_networks = {obj["name"]: got for obj, got in networks}
    subnets = _paired(
        f"subnet{family}",
        family,
        [subnet for subnet, _network in _subnets(declared, family)],
        [subnet for subnet, _network in _subnets(returned, family)],
    )
    parents = {subnet["id"]: network for subnet, network in _subnets(declared, family)}
    for subnet, got in subnets:
        network = parents[subnet["id"]]
        observe(f"subnet{family}", subnet, got, returned if network is None else returned_networks[network["name"]])
        for table in pool_tables:
            for pool, got_pool in _paired(table, family, subnet.get(table, []), got.get(table, [])):
                observe(table, pool, got_pool, got)
    return merges, defaults


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
        del recorded[4][OPTION_DEF]

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

    def test_the_dhcpv6_pd_pool_keys_are_mapped_to_the_plugin_pd_pool(self):
        pd_pool = LEDGER[6]["pd-pools"]

        self.assertEqual(LEDGER[6]["subnet6"]["pd-pools"], Mapped("PDPool"))
        self.assertEqual([key for key, entry in pd_pool.items() if isinstance(entry, Pending)], [])
        self.assertEqual(
            {key: entry.target for key, entry in pd_pool.items() if isinstance(entry, Mapped)},
            {
                "prefix": "PDPool.prefix",
                "prefix-len": "PDPool.prefix",
                "delegated-len": "PDPool.delegated_length",
                "excluded-prefix": "PDPool.excluded_prefix",
                "excluded-prefix-len": "PDPool.excluded_prefix",
                "pool-id": "PDPool.pool_id",
                "client-classes": "PDPool.client_classes",
                "evaluate-additional-classes": "PDPool.evaluate_additional_classes",
                "option-data": "Option",
                "user-context": "PDPool.user_context",
            },
        )
        self.assertEqual(pd_pool["user-context"].capabilities, (Capability.USER_CONTEXT,))

    def test_a_not_imported_entry_refuses_a_reason_that_is_not_for_a_key(self):
        with self.assertRaises(ValueError):
            NotImported(Reason.WRITE_FAILED)

    def test_a_deprecated_key_names_its_replacement_in_the_same_object(self):
        for family, table, key, entry in self._entries():
            if isinstance(entry, Deprecated):
                with self.subTest(family=family, table=table, key=key):
                    self.assertIn(entry.replacement, LEDGER[family][table])
                    self.assertNotIsInstance(LEDGER[family][table][entry.replacement], Deprecated)

    def test_every_capability_but_the_family_gates_a_key(self):
        named = {
            capability
            for _family, _table, _key, entry in self._entries()
            for capability in getattr(entry, "capabilities", ())
        }
        # The family of a DHCPServer is the Kea daemon itself, not a key.
        self.assertEqual(named, set(Capability) - {Capability.SERVER_FAMILY})

    def test_user_context_is_gated_on_every_object_that_has_it(self):
        for family, tables in LEDGER.items():
            for table, keys in tables.items():
                # Kea's interface and socket settings have no plugin object.
                if "user-context" in keys and table != "interfaces-config":
                    with self.subTest(family=family, table=table):
                        self.assertIn(Capability.USER_CONTEXT, keys["user-context"].capabilities)

    def test_the_mapped_settings_are_the_field_maps_of_the_import(self):
        gated_subnet = tuple((key, attr, transform) for key, attr, transform, _cap in fields.GATED_SUBNET_FIELDS)
        # The Subnet interface is a relation to a DHCP server interface, written apart from the field maps.
        interface = (("interface", "server_interfaces", None),)
        field_maps = {
            "Dhcp": ("DHCPServer", fields.SERVER_FIELDS),
            "subnet": ("Subnet", (*fields.SUBNET_FIELDS, *gated_subnet, *interface)),
            "pools": ("Pool", fields.POOL_FIELDS),
            "client-classes": ("ClientClass", fields.CLIENT_CLASS_FIELDS),
        }

        def table_of(prefix: str, family: Family) -> str:
            return prefix if prefix in ("pools", "client-classes") else f"{prefix}{family}"

        for prefix, (model, field_map) in field_maps.items():
            # One field map serves both families, so each key must be a key of at least one of them.
            listed = set().union(*(LEDGER[family][table_of(prefix, family)] for family in LEDGER))
            with self.subTest(model=model):
                unlisted = {kea_key for kea_key, _attr, _transform in field_map} - listed
                self.assertEqual(unlisted, set(), f"{model} writes Kea keys that the ledger does not list")
        for family in LEDGER:
            for prefix, (model, field_map) in field_maps.items():
                table = table_of(prefix, family)
                keys = LEDGER[family][table]
                with self.subTest(family=family, table=table):
                    written = {kea_key: f"{model}.{attr}" for kea_key, attr, _transform in field_map if kea_key in keys}
                    mapped = {
                        key: entry.target
                        for key, entry in keys.items()
                        if isinstance(entry, Mapped) and key in KEA_SETTINGS_KEYS
                    }
                    self.assertEqual(mapped, written)

    def test_every_mapped_field_of_a_model_with_managed_fields_is_managed(self):
        # The fields that find an Option, and the name that a custom Option Definition takes when it is created.
        identity = {"Option.definition", "OptionDefinition.name"}
        for family, table, key, entry in self._entries():
            if not isinstance(entry, Mapped) or "." not in entry.target or entry.target in identity:
                continue
            model, field = entry.target.split(".")
            if model not in fields.MANAGED_FIELDS:
                continue
            with self.subTest(family=family, table=table, key=key):
                written = {"device_interfaces", "virtual_machine_interfaces"} if field == "interfaces" else {field}
                self.assertLessEqual(written, {managed.name for managed in fields.MANAGED_FIELDS[model]})


class RecordedKeaBehaviourTest(SimpleTestCase):
    """The recorded Kea 3.2 shows the deprecated keys and the merged keys that the ledger states."""

    def test_kea_returns_each_deprecated_key_as_its_replacement_on_the_same_object(self):
        for family in LEDGER:
            declared, returned = _objects(_declared(family), family), _objects(_returned(family), family)
            for table, keys in LEDGER[family].items():
                for key, entry in keys.items():
                    if not isinstance(entry, Deprecated):
                        continue
                    with self.subTest(family=family, table=table, key=key):
                        carriers = [(scope, obj) for scope, obj in declared[table] if key in obj]
                        self.assertTrue(carriers, "the coverage configuration declares the key")
                        self.assertFalse(any(key in obj for _scope, obj in returned[table]))
                        for scope, obj in carriers:
                            (got,) = [
                                other[entry.replacement]
                                for other_scope, other in returned[table]
                                if other_scope == scope and _matches(table, family, obj, other)
                            ]
                            if key == "comment":
                                got = got["comment"]
                            self.assertEqual(got, [obj[key]] if key == "client-class" else obj[key])

    def test_the_merged_keys_are_the_ones_kea_merged_into_config_get(self):
        for family in LEDGER:
            with self.subTest(family=family):
                merges, _defaults = _observed(family)
                self.assertEqual(merges, {table: set(keys) for table, keys in MERGED_KEYS[family].items()})

    def test_a_non_empty_collection_with_the_parent_value_counts_as_merged(self):
        option = {"code": 6, "data": "192.0.2.53"}
        merged, default = _undeclared(
            {"pool": "192.0.2.10-192.0.2.20"},
            {"pool": "192.0.2.10-192.0.2.20", "option-data": [option], "pool-id": 3},
            {"option-data": [option]},
            "pools",
            4,
        )
        self.assertEqual((merged, default), ({"option-data"}, {"pool-id"}))

    def test_an_option_matches_by_its_configured_code_or_name_in_its_space(self):
        returned = {"name": "tftp-list", "code": 224, "space": "dhcp4", "data": "192.0.2.69"}
        self.assertTrue(_matches("option-data", 4, {"code": 224}, returned))
        self.assertTrue(_matches("option-data", 4, {"name": "tftp-list"}, returned))
        self.assertFalse(_matches("option-data", 4, {"name": "tftp-list", "space": "vendor-sub"}, returned))
        self.assertFalse(_matches("option-data", 4, {"code": 224, "client-classes": ["voip"]}, returned))

    def test_a_pool_that_only_config_get_returns_fails_the_pairing(self):
        declared = [{"pool": "192.0.2.10 - 192.0.2.20"}]
        returned = [{"pool": "192.0.2.10-192.0.2.20"}, {"pool": "192.0.2.64/26"}]
        with self.assertRaises(AssertionError):
            _paired("pools", 4, declared, returned)
        self.assertEqual(_paired("pools", 4, declared, returned[:1]), [(declared[0], returned[0])])

    def test_every_other_undeclared_key_has_the_kea_default_of_the_ledger(self):
        for family in LEDGER:
            with self.subTest(family=family):
                _merges, defaults = _observed(family)
                expected = {
                    table: {(key, json.dumps(value)) for key, value in keys.items()}
                    for table, keys in KEA_DEFAULTS[family].items()
                }
                self.assertEqual(defaults, expected)


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
        """A field that the installed plugin lacks is the shape that #88 proposes, behind a missing capability."""
        from netbox_kea.integrations.dhcp_plugin_capabilities import probe

        capabilities = probe()
        for family, tables in LEDGER.items():
            for table, keys in tables.items():
                for key, entry in keys.items():
                    if isinstance(entry, Mapped):
                        with self.subTest(family=family, table=table, key=key):
                            model, _, field = entry.target.partition(".")
                            plugin_model = apps.get_model("netbox_dhcp", model)
                            if field and field not in self._field_names(model):
                                missing = [c for c in entry.capabilities if not capabilities.has(c)]
                                self.assertTrue(missing, f"{plugin_model.__name__} has no field {field}")

    def test_a_key_without_a_plugin_home_has_no_plugin_field_of_its_name(self):
        models = {"Dhcp": "DHCPServer", "subnet": "Subnet", "shared-networks": "SharedNetwork", "pools": "Pool"}
        models |= {"pd-pools": "PDPool", "reservations": "HostReservation", "client-classes": "ClientClass"}
        models |= {OPTION_DEF: "OptionDefinition", "option-data": "Option", "interfaces-config": "DHCPServer"}
        for family, tables in LEDGER.items():
            for table, keys in tables.items():
                model = models[table.rstrip("46")]
                for key, entry in keys.items():
                    if isinstance(entry, NotImported):
                        with self.subTest(family=family, table=table, key=key):
                            with self.assertRaises(FieldDoesNotExist):
                                apps.get_model("netbox_dhcp", model)._meta.get_field(key.replace("-", "_"))
