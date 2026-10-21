# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCP Import runs as three steps: read Kea, plan each family, apply each plan to the DHCP plugin."""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import unittest
from dataclasses import fields
from datetime import datetime, timezone
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.messages import ERROR, get_messages
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator
from django.db import models
from django.db.models.functions import Lower
from django.test import SimpleTestCase, TestCase
from django.test.utils import isolate_apps
from django.urls import reverse

from netbox_kea import kea_paths
from netbox_kea.integrations import dhcp_plugin
from netbox_kea.integrations.dhcp_import_ledger import KEA_DEFAULTS
from netbox_kea.integrations.dhcp_import_plan import (
    MAX_KEA_NAME_LENGTH,
    MAX_MAPPING_IDENTITY_LENGTH,
    REMOVAL_ORDER,
    FamilyPlan,
    GlobalReservationKey,
    InSubnetReservationKey,
    MappingSource,
    OptionDefinitionKey,
    PoolKey,
    keyed_reservations,
    kind_path,
    observations,
    plan_family,
)
from netbox_kea.integrations.dhcp_import_report import GAPS, Capability, Kind, Outcome, Reason
from netbox_kea.integrations.dhcp_plugin_capabilities import CHECKS, probe
from netbox_kea.ipam_reconciliation import ReservationObservation
from netbox_kea.mappers.kea_to_dhcp import KEA_SETTINGS_KEYS, parse_dhcp_config
from netbox_kea.models import KeaDhcpLink
from netbox_kea.pools import Pool
from netbox_kea.reservations import (
    GlobalReservationScope,
    InSubnetReservationScope,
    IPv4Reservation,
    ReservationDiagnostic,
    ReservationIdentity,
    ReservationSnapshot,
)
from netbox_kea.subnet_catalogue import CompleteCatalogueSnapshot, IncompleteCatalogueSnapshot, SubnetIdentity

from .kea_stub import stub_kea
from .test_integration_dhcp_plugin import _reservation_snapshot
from .test_kea_recordings import _RECORDINGS, _recording
from .utils import _make_db_server, imported_dhcp_server, imported_dhcp_servers, without_dhcp_plugin

DHCP_PLUGIN = "netbox_dhcp"
_IN_SUBNET_MAC = "02:00:00:00:00:0a"
_GLOBAL_DUID = "01:02:03:04:05:06"


def _recorded_config(family: int) -> dict:
    return _recording(family)["config-get"]["arguments"][f"Dhcp{family}"]


def _recording_configuration(family: int) -> dict:
    """Return the coverage configuration that Kea read for the recording: what each object declares."""
    return json.loads((_RECORDINGS / f"kea-dhcp{family}.conf").read_text(encoding="utf-8"))[f"Dhcp{family}"]


def _recorded_intent(family: int):
    """Parse the recorded config-get reply as the read step does; the recording has no subnet diagnostics."""
    intent = parse_dhcp_config(_recorded_config(family), family)
    intent.configuration_complete = True
    return intent


def _observation() -> ReservationObservation:
    """Return one In-Subnet and one Global DHCPv4 Reservation, built without a database or Kea."""
    subnet = SubnetIdentity(subnet_id=10, network=ipaddress.ip_network("192.0.2.0/24"))
    records = (
        IPv4Reservation(
            scope=InSubnetReservationScope(subnet),
            identity=ReservationIdentity("hw-address", _IN_SUBNET_MAC),
            addresses=(ipaddress.IPv4Address("192.0.2.30"),),
        ),
        IPv4Reservation(
            scope=GlobalReservationScope(),
            identity=ReservationIdentity("duid", _GLOBAL_DUID),
            addresses=(),
        ),
    )
    observed = datetime(2026, 10, 19, tzinfo=timezone.utc)
    catalogue = IncompleteCatalogueSnapshot(
        server_id=1,
        family=4,
        observed_at=observed,
        subnets=(),
        configured_subnets=(),
        diagnostics=(),
        identity_available=False,
        configuration_available=False,
        identity_complete=False,
        configuration_complete=False,
        consistent=True,
        configuration_hash=None,
        global_qualifying_suffix=None,
    )
    snapshot = ReservationSnapshot(
        family=4, records=records, diagnostics=(), complete=True, next_cursor=None, read_started=observed
    )
    return ReservationObservation(snapshot, 1, catalogue)


class PlanFromRecordedRepliesTest(SimpleTestCase):
    """The plan step is pure: it reads no database, no DHCP plugin and no Kea, and keys every planned object."""

    def test_the_dhcpv4_plan_keys_every_object_by_its_import_identity(self):
        observation = _observation()

        plan = plan_family(_recorded_intent(4), observation)

        self.assertIsInstance(plan, FamilyPlan)
        self.assertEqual((plan.family, plan.configuration_complete), (4, True))
        self.assertEqual([planned.key for planned in plan.client_classes], ["voip", "printers", "boot", "per-client"])
        self.assertEqual(
            [planned.key for planned in plan.option_definitions],
            [
                OptionDefinitionKey("dhcp4", 224),
                OptionDefinitionKey("dhcp4", 225),
                OptionDefinitionKey("dhcp4", 226),
                OptionDefinitionKey("dhcp4", 227),
                OptionDefinitionKey("vendor-sub", 1),
            ],
        )
        self.assertEqual([subnet.key for subnet in plan.subnets], [10, 20, 21])
        address = ipaddress.IPv4Address
        self.assertEqual(
            [[pool.key for pool in subnet.pools] for subnet in plan.subnets],
            [
                [
                    PoolKey(10, Pool(address("192.0.2.10"), address("192.0.2.20"))),
                    PoolKey(10, Pool(address("192.0.2.64"), address("192.0.2.127"))),
                ],
                [PoolKey(20, Pool(address("198.51.100.10"), address("198.51.100.50")))],
                [PoolKey(21, Pool(address("198.51.100.200"), address("198.51.100.220")))],
            ],
        )
        self.assertEqual(
            [planned.key for planned in keyed_reservations(plan.reservations)],
            [
                InSubnetReservationKey(10, "hw-address", _IN_SUBNET_MAC),
                GlobalReservationKey(4, "duid", _GLOBAL_DUID),
            ],
        )
        self.assertIs(plan.reservations, observation)
        self.assertEqual(plan.server.global_settings["valid-lifetime"], 4000)
        self.assertEqual(len(plan.server.global_options), len(_recorded_config(4)["option-data"]))

    def test_a_class_level_option_definition_is_planned_with_its_class(self):
        plan = plan_family(_recorded_intent(4), None)

        classes = {planned.key: planned for planned in plan.client_classes}
        (definition,) = classes["boot"].option_definitions
        self.assertEqual(definition.key, OptionDefinitionKey("dhcp4", 231, "boot"))
        self.assertEqual(definition.intent.user_context, {"comment": "Class definition"})
        self.assertEqual(definition.key.source, MappingSource(Kind.OPTION_DEFINITION, None, "boot:dhcp4:231"))
        self.assertEqual(definition.key.source.path(4), "Dhcp4/client-classes[name=boot]/option-def[code=231]")
        self.assertEqual(classes["voip"].option_definitions, ())
        self.assertNotIn(definition.key, [planned.key for planned in plan.option_definitions])

    def test_the_mapping_identity_holds_the_longest_class_level_option_definition(self):
        source = OptionDefinitionKey("s" * MAX_KEA_NAME_LENGTH, 65535, "c" * MAX_KEA_NAME_LENGTH).source

        self.assertEqual(len(source.kea_identity), MAX_MAPPING_IDENTITY_LENGTH)
        self.assertEqual(KeaDhcpLink._meta.get_field("kea_identity").max_length, MAX_MAPPING_IDENTITY_LENGTH)

    def test_a_class_level_option_definition_that_is_not_valid_is_dropped_with_its_class_path(self):
        config = {"client-classes": [{"name": "boot", "option-def": [{"name": "no-code", "type": "uint8"}]}]}

        plan = plan_family(parse_dhcp_config(config, 4), None)

        self.assertEqual(plan.client_classes[0].option_definitions, ())
        self.assertEqual(
            [(entry.kind, entry.path) for entry in plan.dropped],
            [(Kind.OPTION_DEFINITION, "Dhcp4/client-classes[name=boot]/option-def[0]")],
        )

    def test_the_dhcpv6_plan_keys_subnets_and_pools_and_plans_no_reservation_without_a_read(self):
        plan = plan_family(_recorded_intent(6), None)

        self.assertEqual([subnet.key for subnet in plan.subnets], [10, 20, 21])
        address = ipaddress.IPv6Address
        self.assertEqual(
            [pool.key for pool in plan.subnets[2].pools],
            [PoolKey(21, Pool(address("2001:db8:3::100"), address("2001:db8:3::1ff")))],
        )
        self.assertIsNone(plan.reservations)
        self.assertEqual(keyed_reservations(plan.reservations), ())

    def test_each_subnet_plans_the_values_that_the_configuration_declares(self):
        for family in (4, 6):
            configured = _recording_configuration(family)
            declared = {
                subnet["id"]: {key: subnet[key] for key in KEA_SETTINGS_KEYS if key in subnet}
                for subnet in [
                    *configured[f"subnet{family}"],
                    *(
                        member
                        for network in configured["shared-networks"]
                        for member in network.get(f"subnet{family}", [])
                    ),
                ]
            }
            plan = plan_family(_recorded_intent(family), None)
            with self.subTest(family=family):
                self.assertEqual({subnet.key: subnet.settings for subnet in plan.subnets}, declared)
                self.assertEqual(declared[20], {})
                self.assertEqual((declared[10]["valid-lifetime"], declared[10]["allocator"]), (3600, "random"))

    def test_a_member_subnet_reports_the_values_it_inherits_from_its_shared_network(self):
        for family, relay in ((4, ["198.51.100.2", "198.51.100.3"]), (6, ["2001:db8:ffff::2"])):
            plan = plan_family(_recorded_intent(family), None)
            office = {"reservations-global": True, "relay": {"ip-addresses": relay}, "interface": "eth0"}
            with self.subTest(family=family):
                self.assertEqual(
                    {subnet.key: subnet.inherited for subnet in plan.subnets},
                    {10: {}, 20: {**office, "ddns-qualifying-suffix": "office.example.net"}, 21: office},
                )

    def test_each_client_class_plans_the_values_that_the_configuration_declares(self):
        settings = {}
        for family in (4, 6):
            declared = {
                obj["name"]: {key: obj[key] for key in KEA_SETTINGS_KEYS if key in obj}
                for obj in _recording_configuration(family)["client-classes"]
            }
            plan = plan_family(_recorded_intent(family), None)
            settings[family] = {planned.key: planned.settings for planned in plan.client_classes}
            with self.subTest(family=family):
                self.assertEqual(settings[family], declared)
        # Kea returns its own default boot fields on a class that declares none, not the global values.
        returned = {obj["name"]: obj for obj in _recorded_config(4)["client-classes"]}
        unset = KEA_DEFAULTS[4]["client-classes"]["next-server"]
        self.assertEqual((returned["voip"]["next-server"], _recorded_config(4)["next-server"]), (unset, "192.0.2.1"))
        self.assertEqual(settings[4]["voip"], {})
        self.assertEqual(settings[4]["printers"], {"valid-lifetime": 4000, "boot-file-name": "global.efi"})

    def test_kea_default_counts_as_inherited_only_where_the_parent_has_no_value(self):
        # As config-get returns it: Kea gives rapid-commit to a standalone Subnet and to each Shared Network.
        config = {
            "subnet6": [
                {"id": 1, "subnet": "2001:db8:1::/64", "rapid-commit": False},
                {"id": 2, "subnet": "2001:db8:2::/64", "rapid-commit": True},
            ],
            "shared-networks": [
                {
                    "name": "fast",
                    "rapid-commit": True,
                    "subnet6": [
                        {"id": 3, "subnet": "2001:db8:3::/64", "rapid-commit": False},
                        {"id": 4, "subnet": "2001:db8:4::/64", "rapid-commit": True},
                        {"id": 5, "subnet": "2001:db8:5::/64"},
                    ],
                },
                {
                    "name": "default",
                    "rapid-commit": False,
                    "subnet6": [{"id": 6, "subnet": "2001:db8:6::/64", "rapid-commit": False}],
                },
            ],
        }

        plan = plan_family(parse_dhcp_config(config, 6), None)

        self.assertEqual(
            {subnet.key: subnet.settings for subnet in plan.subnets},
            {
                1: {},
                2: {"rapid-commit": True},
                3: {"rapid-commit": False},
                4: {"rapid-commit": True},
                5: {},
                6: {"rapid-commit": False},
            },
        )
        self.assertEqual(
            {subnet.key: subnet.inherited for subnet in plan.subnets},
            {1: {}, 2: {}, 3: {}, 4: {}, 5: {"rapid-commit": True}, 6: {}},
        )

    def test_a_merged_value_that_the_shared_network_declares_is_reported_on_its_members(self):
        # As config-get returns it: Kea merges valid-lifetime into the Shared Network and into each member.
        config = {
            "valid-lifetime": 4000,
            "shared-networks": [
                {
                    "name": "long",
                    "valid-lifetime": 9000,
                    "subnet4": [
                        {"id": 1, "subnet": "192.0.2.0/25", "valid-lifetime": 9000},
                        {"id": 2, "subnet": "192.0.2.128/25", "valid-lifetime": 4000},
                    ],
                }
            ],
        }

        plan = plan_family(parse_dhcp_config(config, 4), None)

        self.assertEqual({subnet.key: subnet.settings for subnet in plan.subnets}, {1: {}, 2: {"valid-lifetime": 4000}})
        self.assertEqual(
            {subnet.key: subnet.inherited for subnet in plan.subnets}, {1: {"valid-lifetime": 9000}, 2: {}}
        )

    def test_a_subnet_that_only_inherited_a_changed_global_value_declares_nothing(self):
        returned = {"valid-lifetime": 5000, "subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "valid-lifetime": 5000}]}

        plan = plan_family(parse_dhcp_config(returned, 4), None)

        self.assertEqual(plan.subnets[0].settings, {})

    def test_a_pool_outside_its_subnet_has_no_key(self):
        config = {"subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "pools": [{"pool": "198.51.100.1-198.51.100.9"}]}]}

        plan = plan_family(parse_dhcp_config(config, 4), None)

        (pool,) = plan.subnets[0].pools
        self.assertIsNone(pool.key)
        self.assertEqual(pool.intent.pool, "198.51.100.1-198.51.100.9")


def _complete_observation(*diagnostics: ReservationDiagnostic, complete: bool = True) -> ReservationObservation:
    """Return the Reservations of :func:`_observation` read against a Complete Catalogue Snapshot."""
    observation = _observation()
    catalogue = observation.catalogue
    complete_catalogue = CompleteCatalogueSnapshot(**{f.name: getattr(catalogue, f.name) for f in fields(catalogue)})
    snapshot = dataclasses.replace(observation.snapshot, diagnostics=diagnostics, complete=complete)
    return ReservationObservation(snapshot, observation.cutoff, complete_catalogue)


@without_dhcp_plugin()
class KindObservationTest(SimpleTestCase):
    """One pure rule says which Kea sources a read observed for each mapped kind, and whether it saw them all."""

    def test_a_complete_read_observes_every_mapped_kind_in_full(self):
        observed = observations(plan_family(_recorded_intent(4), _complete_observation()))

        self.assertEqual(list(observed), list(REMOVAL_ORDER))
        self.assertEqual({kind: o.incomplete for kind, o in observed.items()}, dict.fromkeys(REMOVAL_ORDER, ""))
        self.assertEqual(
            observed[Kind.SUBNET].sources,
            {MappingSource.subnet(10), MappingSource.subnet(20), MappingSource.subnet(21)},
        )
        self.assertIn(MappingSource(Kind.POOL, 10, "192.0.2.10-192.0.2.20"), observed[Kind.POOL].sources)
        self.assertEqual(len(observed[Kind.POOL].sources), 4)
        self.assertEqual(
            observed[Kind.CLIENT_CLASS].sources,
            {MappingSource.named(Kind.CLIENT_CLASS, name) for name in ("voip", "printers", "boot", "per-client")},
        )
        self.assertIn(
            MappingSource(Kind.OPTION_DEFINITION, None, "vendor-sub:1"), observed[Kind.OPTION_DEFINITION].sources
        )
        self.assertEqual(
            observed[Kind.RESERVATION].sources,
            {
                MappingSource(Kind.RESERVATION, 10, f"hw-address:{_IN_SUBNET_MAC}"),
                MappingSource(Kind.RESERVATION, None, f"duid:{_GLOBAL_DUID}"),
            },
        )

    def test_the_option_definition_observation_holds_the_class_level_definitions(self):
        observed = observations(plan_family(_recorded_intent(4), _complete_observation()))

        self.assertIn(
            MappingSource(Kind.OPTION_DEFINITION, None, "boot:dhcp4:231"), observed[Kind.OPTION_DEFINITION].sources
        )
        self.assertEqual(len(observed[Kind.OPTION_DEFINITION].sources), 6)

    def test_a_client_class_entry_that_is_not_valid_hides_its_option_definitions(self):
        config = {"client-classes": [{"name": "boot"}, {"test": "member('KNOWN')"}]}
        intent = parse_dhcp_config(config, 4)
        intent.configuration_complete = True

        observed = observations(plan_family(intent, _complete_observation()))

        self.assertEqual(
            {kind for kind, o in observed.items() if not o.complete}, {Kind.CLIENT_CLASS, Kind.OPTION_DEFINITION}
        )
        self.assertIn("hides its Option Definitions", observed[Kind.OPTION_DEFINITION].incomplete)

    def test_subnet_diagnostics_make_every_configuration_kind_incomplete_and_leave_reservations_complete(self):
        intent = _recorded_intent(4)
        intent.configuration_complete = False

        observed = observations(plan_family(intent, _complete_observation()))

        for kind in (Kind.OPTION_DEFINITION, Kind.CLIENT_CLASS, Kind.SHARED_NETWORK, Kind.SUBNET, Kind.POOL):
            with self.subTest(kind=kind):
                self.assertFalse(observed[kind].complete)
                self.assertIn("not read in full", observed[kind].incomplete)
        self.assertTrue(observed[Kind.RESERVATION].complete)

    def test_an_invalid_subnet_entry_makes_subnets_and_pools_incomplete_only(self):
        config = {"subnet4": [{"id": 1, "subnet": "192.0.2.0/24"}, {"id": 2}]}
        intent = parse_dhcp_config(config, 4)
        intent.configuration_complete = True

        observed = observations(plan_family(intent, _complete_observation()))

        self.assertEqual({kind for kind, o in observed.items() if not o.complete}, {Kind.SUBNET, Kind.POOL})
        self.assertIn("1 Subnet entry", observed[Kind.SUBNET].incomplete)

    def test_a_pool_without_a_valid_range_makes_pools_incomplete(self):
        config = {"subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "pools": [{"pool": "198.51.100.1-198.51.100.9"}]}]}
        intent = parse_dhcp_config(config, 4)
        intent.configuration_complete = True

        observed = observations(plan_family(intent, _complete_observation()))

        self.assertEqual({kind for kind, o in observed.items() if not o.complete}, {Kind.POOL})

    def test_each_reservation_gap_makes_the_reservation_observation_incomplete(self):
        quarantined = ReservationDiagnostic("invalid-identifier", "bad", "hosts[3]")
        truncated = ReservationDiagnostic("page-fetch-failed", "stopped", "pages[1]")
        cases = {
            "read failed": (None, "could not be read"),
            "catalogue incomplete": (_observation(), "Subnet Catalogue"),
            "quarantined record": (_complete_observation(quarantined, complete=False), "1 Reservation record"),
            "truncated walk": (_complete_observation(truncated), "every page"),
        }
        for name, (observation, reason) in cases.items():
            with self.subTest(name):
                observed = observations(plan_family(_recorded_intent(4), observation))[Kind.RESERVATION]
                self.assertFalse(observed.complete)
                self.assertIn(reason, observed.incomplete)

    def test_a_kind_without_a_path_refuses_instead_of_naming_the_daemon(self):
        with self.assertRaises(ValueError):
            MappingSource(Kind.OPTION).path(4)
        with self.assertRaises(ValueError):
            kind_path(4, Kind.SERVER)
        self.assertEqual(MappingSource.server().path(4), "Dhcp4")

    def test_a_mapping_source_names_its_kea_path(self):
        sources = {
            MappingSource.subnet(20): "Dhcp4/subnet4[id=20]",
            MappingSource(
                Kind.POOL, 20, "192.0.2.10-192.0.2.20"
            ): "Dhcp4/subnet4[id=20]/pools[pool=192.0.2.10-192.0.2.20]",
            MappingSource(Kind.RESERVATION, 20, "hw-address:02:00:00:00:00:01"): (
                "Dhcp4/subnet4[id=20]/reservations[hw-address=02:00:00:00:00:01]"
            ),
            MappingSource(Kind.RESERVATION, None, "duid:01:02"): "Dhcp4/reservations[duid=01:02]",
            MappingSource.named(Kind.CLIENT_CLASS, "voip"): "Dhcp4/client-classes[name=voip]",
            MappingSource(Kind.OPTION_DEFINITION, None, "dhcp4:222"): "Dhcp4/option-def[code=222]",
            MappingSource(Kind.OPTION_DEFINITION, None, "vendor-x:1"): "Dhcp4/option-def[space=vendor-x,code=1]",
            MappingSource(Kind.OPTION_DEFINITION, None, "a:b:vendor-x:1"): (
                "Dhcp4/client-classes[name=a:b]/option-def[space=vendor-x,code=1]"
            ),
            MappingSource.named(Kind.SHARED_NETWORK, "office"): "Dhcp4/shared-networks[name=office]",
        }
        for source, path in sources.items():
            with self.subTest(source=source):
                self.assertEqual(source.path(4), path)


class CapabilityProbeTest(SimpleTestCase):
    """The probe reads the plugin models and reports each #88 capability present or missing."""

    def test_every_capability_has_a_check_and_a_gap(self):
        self.assertEqual(set(CHECKS), set(Capability))
        self.assertEqual(set(GAPS), set(Capability))

    def test_netbox_dhcp_0_2_0_has_none_of_the_capabilities(self):
        if not apps.is_installed(DHCP_PLUGIN):
            self.skipTest(f"{DHCP_PLUGIN} not installed")
        self.assertEqual(apps.get_app_config(DHCP_PLUGIN).version, "0.2.0")
        # #88 checked each gap against 0.2.0: the plugin has none of the capabilities yet.
        expected = {
            Capability.SHARED_NETWORK_OPTIONAL_PREFIX: False,
            Capability.SUBNET_ID_PER_SERVER: False,
            Capability.NAME_PER_SERVER: False,
            Capability.SERVER_FAMILY: False,
            Capability.FLEX_ID_IDENTIFIER: False,
            Capability.USER_CONTEXT: False,
            Capability.OPTION_SPACES: False,
            Capability.OPTION_CODE_16_BIT: False,
            Capability.OPTION_WITHOUT_DEFINITION: False,
            Capability.SERVER_ID_FIELDS: False,
            Capability.RELAY_ADDRESS_LIST: False,
            Capability.DHCP4O6_SUBNET_SELECTION: False,
            Capability.ADDRESS_REGISTRATION: False,
            Capability.STASH_AGENT_OPTIONS: False,
        }
        capabilities = probe()
        self.assertEqual({capability: capabilities.has(capability) for capability in Capability}, expected)

    def test_netbox_dhcp_0_2_0_holds_the_option_spaces_of_its_choices_only(self):
        if not apps.is_installed(DHCP_PLUGIN):
            self.skipTest(f"{DHCP_PLUGIN} not installed")
        capabilities = probe()

        self.assertEqual(capabilities.option_spaces, {"dhcp4", "dhcp6", "vendor-specific-options-space"})
        self.assertTrue(capabilities.holds_space("vendor-specific-options-space"))
        for space in ("vendor-sub", "vendor-encapsulated-options-space", "vendor-4491"):
            with self.subTest(space=space):
                self.assertFalse(capabilities.holds_space(space))

    @isolate_apps("netbox_kea")
    def test_a_plugin_without_a_closed_space_choice_set_holds_every_space(self):
        capabilities = probe(_proposed_plugin_models().__getitem__)

        self.assertEqual(capabilities.option_spaces, frozenset())
        self.assertTrue(capabilities.holds_space("vendor-4491"))

    @isolate_apps("netbox_kea")
    def test_an_option_definition_without_a_user_context_lacks_the_capability(self):
        plugin = _proposed_plugin_models()
        plugin["OptionDefinition"] = _probe_model("ContextlessOptionDefinition", space=models.CharField(max_length=255))
        self.assertFalse(probe(plugin.__getitem__).has(Capability.USER_CONTEXT))

    @isolate_apps("netbox_kea")
    def test_an_option_without_a_user_context_lacks_the_capability(self):
        plugin = _proposed_plugin_models()
        plugin["Option"] = _probe_model("ContextlessOption")
        self.assertFalse(probe(plugin.__getitem__).has(Capability.USER_CONTEXT))

    @isolate_apps("netbox_kea")
    def test_a_plugin_with_the_proposed_shapes_has_every_capability(self):
        self.assertEqual(probe(_proposed_plugin_models().__getitem__).present, frozenset(Capability))

    @isolate_apps("netbox_kea")
    def test_a_name_unique_alone_lacks_the_name_per_server_capability(self):
        plugin = _proposed_plugin_models()

        plugin["ClientClass"] = _probe_model(
            "GloballyNamedClientClass",
            dhcp_server=models.ForeignKey(plugin["DHCPServer"], on_delete=models.CASCADE),
            name=models.CharField(max_length=255, unique=True),
            user_context=models.JSONField(null=True),
        )
        capabilities = probe(plugin.__getitem__)
        self.assertFalse(capabilities.has(Capability.NAME_PER_SERVER))
        self.assertTrue(capabilities.has(Capability.SUBNET_ID_PER_SERVER))

    @isolate_apps("netbox_kea")
    def test_a_unique_expression_on_the_name_lacks_the_name_per_server_capability(self):
        plugin = _proposed_plugin_models()
        global_name = models.UniqueConstraint(Lower("name"), name="expressionclientclass_global_name")
        plugin["ClientClass"] = _probe_model(
            "ExpressionClientClass",
            "name",
            dhcp_server=models.ForeignKey(plugin["DHCPServer"], on_delete=models.CASCADE),
            name=models.CharField(max_length=255),
            user_context=models.JSONField(null=True),
            extra_constraints=[global_name],
        )
        self.assertFalse(probe(plugin.__getitem__).has(Capability.NAME_PER_SERVER))

    @isolate_apps("netbox_kea")
    def test_a_relay_list_that_cannot_be_cleared_lacks_the_capability(self):
        plugin = _proposed_plugin_models()
        plugin["Subnet"] = _probe_model("RequiredRelaySubnet", relay=ArrayField(models.GenericIPAddressField()))
        self.assertFalse(probe(plugin.__getitem__).has(Capability.RELAY_ADDRESS_LIST))

    @isolate_apps("netbox_kea")
    def test_a_user_context_that_cannot_be_cleared_lacks_the_capability(self):
        plugin = _proposed_plugin_models()
        plugin["Pool"] = _probe_model("RequiredContextPool", user_context=models.JSONField())
        self.assertFalse(probe(plugin.__getitem__).has(Capability.USER_CONTEXT))


@without_dhcp_plugin()
class GatedValuesTest(SimpleTestCase):
    """With its capability a gated Kea value is planned on the plugin field that #88 proposes; without it, reported."""

    def _plan(self, obj, field_map, settings: dict, capabilities: frozenset):
        from netbox_kea.integrations.dhcp_plugin_capabilities import PluginCapabilities

        summary = dhcp_plugin.ImportSummary()
        source = dhcp_plugin._Source(4, Kind.SUBNET, "Dhcp4/subnet4[id=10]")
        values = dhcp_plugin.gated_values(obj, settings, field_map, PluginCapabilities(capabilities), summary, source)
        return values, {(entry.path, entry.capability) for entry in summary.entries}

    @isolate_apps("netbox_kea")
    def test_with_the_capabilities_the_subnet_relay_list_and_4o6_keys_are_planned(self):
        from netbox_kea.integrations.dhcp_import_fields import GATED_SUBNET_FIELDS

        settings = {"relay": {"ip-addresses": ["198.51.100.1", "2001:db8::1"]}, "4o6-subnet": "2001:db8::/64"}

        values, entries = self._plan(
            _proposed_plugin_models()["Subnet"](), GATED_SUBNET_FIELDS, settings, frozenset(Capability)
        )

        self.assertEqual(
            values,
            {
                "relay": ["198.51.100.1", "2001:db8::1"],
                "dhcp4o6_subnet": "2001:db8::/64",
                # Kea does not declare them, so they are cleared.
                "dhcp4o6_interface": "",
                "dhcp4o6_interface_id": "",
            },
        )
        self.assertEqual(entries, set())

    @isolate_apps("netbox_kea")
    def test_with_the_capability_a_relay_list_that_the_field_refuses_keeps_the_field(self):
        from netbox_kea.integrations.dhcp_import_fields import GATED_SUBNET_FIELDS

        subnet = _proposed_plugin_models()["Subnet"](relay=["198.51.100.9"])
        values, entries = self._plan(
            subnet, GATED_SUBNET_FIELDS, {"relay": {"ip-addresses": ["relay.example"]}}, frozenset(Capability)
        )

        self.assertEqual(values["relay"], ["198.51.100.9"])
        self.assertEqual(entries, {("Dhcp4/subnet4[id=10]/relay", None)})

    @isolate_apps("netbox_kea")
    def test_without_the_capabilities_a_declared_value_is_unsupported_and_an_empty_relay_is_not(self):
        from netbox_kea.integrations.dhcp_import_fields import GATED_SUBNET_FIELDS

        settings = {"relay": {"ip-addresses": []}, "4o6-interface": "eth1"}
        values, entries = self._plan(_proposed_plugin_models()["Subnet"](), GATED_SUBNET_FIELDS, settings, frozenset())

        self.assertEqual(
            (values, entries),
            ({}, {("Dhcp4/subnet4[id=10]/4o6-interface", Capability.DHCP4O6_SUBNET_SELECTION)}),
        )

    @isolate_apps("netbox_kea")
    def test_with_the_capabilities_a_gated_global_is_planned_and_an_undeclared_one_is_cleared(self):
        from netbox_kea.integrations.dhcp_import_fields import GATED_SERVER_FIELDS

        server = _proposed_plugin_models()["DHCPServer"](stash_agent_options=True)
        values, _entries = self._plan(
            server, GATED_SERVER_FIELDS, {"allow-address-registration": True}, frozenset(Capability)
        )

        self.assertEqual(values, {"allow_address_registration": True, "stash_agent_options": None})


class _ProbeModel(models.Model):
    """A model that the probe reads; no table is created."""

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return type(self).__name__


def _probe_model(
    model_name: str,
    /,
    *unique_per_server: str,
    extra_constraints: list[models.UniqueConstraint] | None = None,
    **fields: models.Field,
) -> type[models.Model]:
    """Return a model with *fields*, and a uniqueness constraint on each of *unique_per_server* with dhcp_server."""
    constraints = [
        models.UniqueConstraint(fields=[field, "dhcp_server"], name=f"{model_name.lower()}_{field}_per_server")
        for field in unique_per_server
    ]
    constraints.extend(extra_constraints or [])
    meta = type("Meta", (), {"constraints": constraints})
    return type(model_name, (_ProbeModel,), {"__module__": __name__, "Meta": meta, **fields})


def _proposed_plugin_models() -> dict[str, type[models.Model]]:
    """Return plugin models in the shapes that #88 proposes. Call it inside ``isolate_apps``."""
    server = _probe_model(
        "DHCPServer",
        family=models.PositiveSmallIntegerField(choices=[(4, "DHCPv4"), (6, "DHCPv6")]),
        host_reservation_identifiers=ArrayField(
            models.CharField(choices=[("hw-address", "hw-address"), ("flex-id", "flex-id")])
        ),
        user_context=models.JSONField(null=True),
        server_id_identifier=models.CharField(max_length=255),
        server_id_enterprise_id=models.PositiveIntegerField(),
        server_id_htype=models.PositiveIntegerField(),
        server_id_time=models.PositiveIntegerField(),
        allow_address_registration=models.BooleanField(null=True),
        stash_agent_options=models.BooleanField(null=True),
    )
    definition = _probe_model(
        "OptionDefinition",
        space=models.CharField(max_length=255),
        code=models.PositiveIntegerField(validators=[MaxValueValidator(65535)]),
        user_context=models.JSONField(null=True),
    )

    def parent() -> models.ForeignKey:
        return models.ForeignKey(server, on_delete=models.CASCADE)

    def user_context() -> models.JSONField:
        return models.JSONField(null=True)

    return {
        "DHCPServer": server,
        "SharedNetwork": _probe_model(
            "SharedNetwork",
            "name",
            dhcp_server=parent(),
            name=models.CharField(max_length=255),
            prefix=models.ForeignKey(_probe_model("Prefix"), on_delete=models.PROTECT, null=True),
            relay=ArrayField(models.GenericIPAddressField(), null=True),
            user_context=user_context(),
        ),
        "Subnet": _probe_model(
            "Subnet",
            "subnet_id",
            dhcp_server=parent(),
            subnet_id=models.PositiveIntegerField(),
            relay=ArrayField(models.GenericIPAddressField(), null=True),
            dhcp4o6_subnet=models.CharField(max_length=64),
            dhcp4o6_interface=models.CharField(max_length=64),
            dhcp4o6_interface_id=models.CharField(max_length=64),
            user_context=user_context(),
        ),
        "Pool": _probe_model("Pool", user_context=user_context()),
        "PDPool": _probe_model("PDPool", user_context=user_context()),
        "HostReservation": _probe_model("HostReservation", user_context=user_context()),
        "ClientClass": _probe_model(
            "ClientClass",
            "name",
            dhcp_server=parent(),
            name=models.CharField(max_length=255),
            user_context=user_context(),
        ),
        "OptionDefinition": definition,
        "Option": _probe_model(
            "Option",
            definition=models.ForeignKey(definition, on_delete=models.PROTECT, null=True),
            space=models.CharField(max_length=255),
            code=models.PositiveIntegerField(),
            user_context=user_context(),
        ),
    }


@without_dhcp_plugin()
class OptionValuesTest(SimpleTestCase):
    """With its capability an option without a definition keeps its space and code, and a user-context is planned."""

    def _values(self, candidate, opt, capabilities: frozenset):
        from netbox_kea.integrations.dhcp_plugin_capabilities import PluginCapabilities

        summary = dhcp_plugin.ImportSummary()
        source = dhcp_plugin._Source(6, Kind.OPTION, "Dhcp6/option-data[code=1003]")
        values = dhcp_plugin.option_values(candidate, opt, 6, PluginCapabilities(capabilities), summary, source)
        return values, {(entry.path, entry.capability) for entry in summary.entries}

    @isolate_apps("netbox_kea")
    def test_with_the_capabilities_an_option_without_a_definition_keeps_its_space_code_and_user_context(self):
        from netbox_kea.dhcp_options import parse_dhcp_option

        opt = parse_dhcp_option({"code": 1003, "data": "C0000245", "csv-format": False, "user-context": {"a": 1}})

        values, entries = self._values(_proposed_plugin_models()["Option"](definition=None), opt, frozenset(Capability))

        self.assertEqual(
            values,
            {
                "definition_id": None,
                "data": "C0000245",
                "csv_format": False,
                "send_option": None,
                "space": "dhcp6",
                "code": 1003,
                "user_context": {"a": 1},
            },
        )
        self.assertEqual(entries, set())

    @isolate_apps("netbox_kea")
    def test_with_a_definition_the_option_takes_the_code_of_its_definition(self):
        from netbox_kea.dhcp_options import parse_dhcp_option

        plugin = _proposed_plugin_models()
        definition = plugin["OptionDefinition"](space="dhcp6", code=1000)
        opt = parse_dhcp_option({"name": "tftp-list", "data": "2001:db8::69"})

        values, _entries = self._values(plugin["Option"](definition=definition), opt, frozenset(Capability))

        self.assertEqual((values["space"], values["code"], values["user_context"]), ("dhcp6", 1000, None))

    @isolate_apps("netbox_kea")
    def test_without_the_capabilities_a_declared_user_context_is_unsupported(self):
        from netbox_kea.dhcp_options import parse_dhcp_option

        opt = parse_dhcp_option({"code": 1003, "data": "x", "user-context": {"comment": "Kea comment"}})

        values, entries = self._values(_proposed_plugin_models()["Option"](definition=None), opt, frozenset())

        self.assertEqual(set(values), {"definition_id", "data", "csv_format", "send_option"})
        self.assertEqual(entries, {("Dhcp6/option-data[code=1003]/user-context", Capability.USER_CONTEXT)})


class ApplyPlanWithoutKeaTest(TestCase):
    """The apply step writes the DHCP plugin rows of a plan and sends no Kea command (no Kea stub is active)."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def test_apply_writes_the_planned_rows(self):
        server = _make_db_server(name="apply-plan", ca_url="https://kea.example.invalid", dhcp6=False)
        hosts = [
            {"subnet-id": 10, "hw-address": _IN_SUBNET_MAC, "ip-address": "192.0.2.30"},
            {"subnet-id": 0, "duid": _GLOBAL_DUID},
        ]
        # The read step: the only Kea access, before the apply.
        observation = _reservation_snapshot(_recorded_config(4), 4, hosts)
        plan = plan_family(_recorded_intent(4), observation)

        summary = dhcp_plugin.apply_plan(server, plan, probe())

        self.assertEqual(summary.errors, 0, summary.warnings)
        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        OptionDefinition = apps.get_model(DHCP_PLUGIN, "OptionDefinition")
        links = KeaDhcpLink.objects.filter(server=server, family=4, kind="subnet")
        self.assertEqual(
            {link.kea_subnet_id: str(link.sys4_object.prefix.prefix) for link in links},
            {10: "192.0.2.0/24", 20: "198.51.100.0/25", 21: "198.51.100.128/25"},
        )
        self.assertEqual(
            sorted(
                (str(pool.ip_range.start_address.ip), str(pool.ip_range.end_address.ip))
                for pool in Pool.objects.filter(subnet__dhcp_server__in=imported_dhcp_servers(server))
            ),
            [
                ("192.0.2.10", "192.0.2.20"),
                ("192.0.2.64", "192.0.2.127"),
                ("198.51.100.10", "198.51.100.50"),
                ("198.51.100.200", "198.51.100.220"),
            ],
        )
        self.assertEqual(
            set(
                ClientClass.objects.filter(dhcp_server__in=imported_dhcp_servers(server)).values_list("name", flat=True)
            ),
            {"voip", "printers", "boot", "per-client"},
        )
        self.assertEqual(
            set(
                OptionDefinition.objects.filter(
                    standard=False, dhcp_server__in=imported_dhcp_servers(server)
                ).values_list("space", "code")
            ),
            {("dhcp4", 224), ("dhcp4", 225), ("dhcp4", 226), ("dhcp4", 227)},
        )
        record = OptionDefinition.objects.get(dhcp_server__in=imported_dhcp_servers(server), code=225)
        self.assertEqual(record.record_types, ["uint8", "string"])
        in_subnet = HostReservation.objects.get(subnet=links.get(kea_subnet_id=10).sys4_object)
        self.assertEqual(str(in_subnet.ipv4_address.address.ip), "192.0.2.30")
        global_link = KeaDhcpLink.objects.get(
            server=server, family=4, kind="reservation", kea_subnet_id=None, kea_identity=f"duid:{_GLOBAL_DUID}"
        )
        self.assertEqual(global_link.sys4_object.duid, _GLOBAL_DUID)
        self.assertEqual((summary.subnets_created, summary.pools_created, summary.reservations_created), (3, 4, 2))
        # Each imported row has exactly one DHCP Import Mapping, and a second apply finds each row through it.
        rows = [
            *Pool.objects.filter(subnet__dhcp_server__in=imported_dhcp_servers(server)),
            *HostReservation.objects.filter(subnet__dhcp_server__in=imported_dhcp_servers(server)),
            *HostReservation.objects.filter(dhcp_server__in=imported_dhcp_servers(server), subnet__isnull=True),
            *ClientClass.objects.filter(dhcp_server__in=imported_dhcp_servers(server)),
            *OptionDefinition.objects.filter(standard=False, dhcp_server__in=imported_dhcp_servers(server)),
            *OptionDefinition.objects.filter(client_class__dhcp_server__in=imported_dhcp_servers(server)),
        ]
        mapped = KeaDhcpLink.objects.filter(server=server, family=4).exclude(kind__in=["subnet", "server"])
        self.assertCountEqual(
            mapped.values_list("object_type__model", "object_id"),
            [(row._meta.model_name, row.pk) for row in rows],
        )
        # Four Pools, two Reservations, four client classes and five custom Option Definitions, one of them in a class.
        self.assertEqual(mapped.count(), 15)
        before = set(KeaDhcpLink.objects.filter(server=server).values_list("pk", "object_id"))

        again = dhcp_plugin.apply_plan(server, plan, probe())

        self.assertEqual(again.errors, 0, again.warnings)
        self.assertEqual([entry.path for entry in again.entries if entry.outcome.value == "created"], [])
        self.assertEqual(set(KeaDhcpLink.objects.filter(server=server).values_list("pk", "object_id")), before)

    def _subnets(self, server) -> dict:
        links = KeaDhcpLink.objects.filter(server=server, family=4, kind="subnet")
        return {link.kea_subnet_id: link.sys4_object for link in links}

    def test_apply_writes_only_the_declared_values_of_each_subnet(self):
        server = _make_db_server(name="declared-values", ca_url="https://kea.example.invalid", dhcp6=False)

        summary = dhcp_plugin.apply_plan(server, plan_family(_recorded_intent(4), None), probe())

        self.assertEqual(summary.errors, 0, summary.warnings)
        subnets = self._subnets(server)
        member = {attr: getattr(subnets[20], attr) for attr in _INHERITABLE}
        self.assertEqual(member, dict.fromkeys(_INHERITABLE))
        standalone = {attr: getattr(subnets[10], attr) for attr in _INHERITABLE}
        self.assertEqual(
            standalone,
            {
                **dict.fromkeys(_INHERITABLE),
                "valid_lifetime": 3600,
                "min_valid_lifetime": 1800,
                "max_valid_lifetime": 7200,
                "offer_lifetime": 60,
                "renew_timer": 900,
                "rebind_timer": 1800,
                "allocator": "random",
                "ddns_qualifying_suffix": "",
                "reservations_in_subnet": False,
            },
        )
        self.assertEqual(
            (subnets[21].ddns_qualifying_suffix, subnets[21].ddns_ttl, subnets[21].reservations_out_of_pool),
            ("office.example.org.", 600, True),
        )
        detail = "Kea applies the value of Shared Network office, which is not imported."
        self.assertEqual(
            sorted(
                (entry.path, entry.detail)
                for entry in summary.entries
                if entry.reason == Reason.INHERITED_FROM_SHARED_NETWORK
            ),
            [
                ("Dhcp4/subnet4[id=20]/ddns-qualifying-suffix", detail),
                ("Dhcp4/subnet4[id=20]/interface", detail),
                ("Dhcp4/subnet4[id=20]/relay", detail),
                ("Dhcp4/subnet4[id=20]/reservations-global", detail),
                ("Dhcp4/subnet4[id=21]/interface", detail),
                ("Dhcp4/subnet4[id=21]/relay", detail),
                ("Dhcp4/subnet4[id=21]/reservations-global", detail),
            ],
        )

    def test_a_changed_global_value_leaves_a_subnet_that_only_inherited_it_without_a_value(self):
        server = _make_db_server(name="changed-global", ca_url="https://kea.example.invalid", dhcp6=False)
        dhcp_plugin.apply_plan(server, plan_family(_recorded_intent(4), None), probe())

        # Kea merges the new global value into each Shared Network and Subnet that does not declare one.
        changed = _with_value(_recorded_config(4), "renew-timer", 1000, 1200)
        intent = parse_dhcp_config(changed, 4)
        intent.configuration_complete = True
        summary = dhcp_plugin.apply_plan(server, plan_family(intent, None), probe())

        self.assertEqual(summary.errors, 0, summary.warnings)
        subnets = self._subnets(server)
        self.assertEqual((subnets[20].renew_timer, subnets[21].renew_timer, subnets[10].renew_timer), (None, None, 900))
        self.assertEqual(imported_dhcp_server(server, 4).renew_timer, 1200)

    def _client_classes(self, server) -> dict:
        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        rows = ClientClass.objects.filter(dhcp_server=imported_dhcp_server(server, 4))
        return {row.name: {attr: getattr(row, attr) for attr in _CLASS_FIELDS} for row in rows}

    def test_apply_writes_only_the_declared_values_of_each_client_class(self):
        server = _make_db_server(name="class-declared-values", ca_url="https://kea.example.invalid", dhcp6=False)

        summary = dhcp_plugin.apply_plan(server, plan_family(_recorded_intent(4), None), probe())

        self.assertEqual(summary.errors, 0, summary.warnings)
        dhcp_server = imported_dhcp_server(server, 4)
        self.assertEqual(
            (dhcp_server.next_server, dhcp_server.boot_file_name, dhcp_server.valid_lifetime),
            ("192.0.2.1", "global.efi", 4000),
        )
        nothing = dict.fromkeys(_CLASS_FIELDS)
        self.assertEqual(
            self._client_classes(server),
            {
                "voip": nothing,
                "per-client": nothing,
                "printers": {**nothing, "valid_lifetime": 4000, "boot_file_name": "global.efi"},
                "boot": {
                    **nothing,
                    "valid_lifetime": 600,
                    "min_valid_lifetime": 300,
                    "max_valid_lifetime": 900,
                    "next_server": "192.0.2.5",
                    "server_hostname": "boot.example.org",
                    "boot_file_name": "pxelinux.0",
                },
            },
        )

    def test_a_class_value_that_kea_no_longer_returns_is_cleared(self):
        server = _make_db_server(name="class-value-removed", ca_url="https://kea.example.invalid", dhcp6=False)
        dhcp_plugin.apply_plan(server, plan_family(_recorded_intent(4), None), probe())
        before = self._client_classes(server)
        self.assertEqual((before["boot"]["valid_lifetime"], before["printers"]["boot_file_name"]), (600, "global.efi"))

        config = _recorded_config(4)
        for obj in config["client-classes"]:
            if obj["name"] in ("boot", "printers"):
                del obj["valid-lifetime"]
                obj["boot-file-name"] = ""
        intent = parse_dhcp_config(config, 4)
        intent.configuration_complete = True
        summary = dhcp_plugin.apply_plan(server, plan_family(intent, None), probe())

        self.assertEqual(summary.errors, 0, summary.warnings)
        classes = self._client_classes(server)
        self.assertEqual(
            {name: (classes[name]["valid_lifetime"], classes[name]["boot_file_name"]) for name in ("boot", "printers")},
            {"boot": (None, None), "printers": (None, None)},
        )
        self.assertEqual(classes["boot"]["next_server"], "192.0.2.5")


_SUBNET_10 = "Dhcp4/subnet4[id=10]"


class SubnetCoverageTest(TestCase):
    """The coverage configuration gives Subnet 10 its classes, interface and values, and plugin 0.2.0 gaps are reported."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name="subnet-coverage", ca_url="https://kea.example.invalid", dhcp6=False)

    def _apply(self, config: dict | None = None, family: int = 4):
        intent = parse_dhcp_config(_recorded_config(family) if config is None else config, family)
        intent.configuration_complete = True
        summary = dhcp_plugin.apply_plan(self.server, plan_family(intent, None), probe())
        self.assertEqual(summary.errors, 0, summary.warnings)
        return summary

    def _subnet(self, subnet_id: int = 10, family: int = 4):
        return KeaDhcpLink.objects.get(
            server=self.server, family=family, kind="subnet", kea_subnet_id=subnet_id
        ).sys4_object

    @staticmethod
    def _names(relation) -> list[str]:
        return sorted(relation.values_list("name", flat=True))

    @staticmethod
    def _entries(summary, prefix: str) -> dict:
        return {
            entry.path: (entry.reason, entry.capability)
            for entry in summary.entries
            if entry.path.startswith(prefix) and entry.reason is not None
        }

    def test_subnet_10_gets_its_client_classes_and_declared_values(self):
        self._apply()

        subnet = self._subnet()
        self.assertEqual(
            (self._names(subnet.client_classes), self._names(subnet.evaluate_additional_classes)),
            (["voip"], ["printers"]),
        )
        self.assertEqual((subnet.valid_lifetime, subnet.allocator), (3600, "random"))
        self.assertEqual(
            (self._names(self._subnet(20).client_classes), self._names(self._subnet(21).client_classes)),
            ([], ["voip"]),
        )

    def test_adaptive_lease_time_threshold_is_imported_where_kea_declares_it(self):
        from decimal import Decimal

        config = _recorded_config(4)
        config["subnet4"][0]["adaptive-lease-time-threshold"] = 0.65

        self._apply(config)

        self.assertEqual(imported_dhcp_server(self.server, 4).adaptive_lease_time_threshold, Decimal("0.80"))
        self.assertEqual(self._subnet().adaptive_lease_time_threshold, Decimal("0.65"))
        # Subnet 20 inherits the global value, which Kea merges into config-get.
        self.assertIsNone(self._subnet(20).adaptive_lease_time_threshold)

    def test_with_plugin_0_2_0_the_relay_list_and_user_context_are_unsupported_and_the_rest_imports(self):
        relay = "manually set relay"
        self._apply()
        apps.get_model(DHCP_PLUGIN, "Subnet").objects.filter(pk=self._subnet().pk).update(relay=relay)

        summary = self._apply()

        unsupported = {
            path: capability
            for path, (reason, capability) in self._entries(summary, _SUBNET_10).items()
            if capability is not None
        }
        self.assertEqual(
            unsupported,
            {
                f"{_SUBNET_10}/relay": Capability.RELAY_ADDRESS_LIST,
                f"{_SUBNET_10}/user-context": Capability.USER_CONTEXT,
                f"{_SUBNET_10}/pools[pool=192.0.2.10-192.0.2.20]/user-context": Capability.USER_CONTEXT,
            },
        )
        subnet = self._subnet()
        # Without the capability the free-text field is not managed, so it keeps its value.
        self.assertEqual((subnet.relay, subnet.valid_lifetime), (relay, 3600))

    def test_a_declared_4o6_subnet_selection_is_unsupported_with_plugin_0_2_0(self):
        config = _recorded_config(4)
        config["subnet4"][0] |= {"4o6-subnet": "2001:db8::/64", "4o6-interface": "eth1"}

        summary = self._apply(config)

        self.assertEqual(
            self._entries(summary, f"{_SUBNET_10}/4o6"),
            {
                f"{_SUBNET_10}/4o6-subnet": (Reason.PLUGIN_GAP, Capability.DHCP4O6_SUBNET_SELECTION),
                f"{_SUBNET_10}/4o6-interface": (Reason.PLUGIN_GAP, Capability.DHCP4O6_SUBNET_SELECTION),
            },
        )

    def test_the_subnet_interface_links_the_dhcp_server_interface_of_that_name(self):
        from .test_integration_dhcp_plugin import _device

        self._apply()
        dhcp_server = imported_dhcp_server(self.server, 4)
        dhcp_server.device = _device("subnet-coverage-dev", "eth0", "eth1")
        dhcp_server.save()
        config = _recorded_config(4)
        config["interfaces-config"]["interfaces"] = ["eth0", "eth1"]

        summary = self._apply(config)

        self.assertEqual(self._names(self._subnet().server_interfaces), ["eth0"])
        self.assertEqual(self._entries(summary, f"{_SUBNET_10}/interface"), {})
        self.assertIn(f"{_SUBNET_10}", [entry.path for entry in summary.entries if entry.reason is None])

        config["subnet4"][0]["interface"] = "eth1"
        self._apply(config)

        self.assertEqual(self._names(self._subnet().server_interfaces), ["eth1"])

    def test_a_subnet_interface_that_the_dhcp_server_does_not_have_is_reported(self):
        from .test_integration_dhcp_plugin import _device

        no_device = self._apply()
        dhcp_server = imported_dhcp_server(self.server, 4)
        dhcp_server.device = _device("subnet-coverage-unlisted", "eth0")
        dhcp_server.save()
        # Kea's interface list does not name eth0, so the DHCP server does not list it.
        unlisted = self._apply()
        config = _recorded_config(4)
        config["interfaces-config"]["interfaces"] = ["eth0"]
        config["subnet4"][0]["interface"] = "eth7"
        missing = self._apply(config)

        path = f"{_SUBNET_10}/interface"
        for summary, detail in (
            (no_device, "The DHCP server is linked to no device or virtual machine."),
            (unlisted, "The DHCP server does not list interface eth0 of its device or virtual machine."),
            (missing, "The DHCP server's device or virtual machine has no interface eth7."),
        ):
            with self.subTest(detail=detail):
                (entry,) = [entry for entry in summary.entries if entry.path == path]
                self.assertEqual((entry.reason, entry.detail), (Reason.NO_MATCHING_INTERFACE, detail))
        self.assertEqual(self._names(self._subnet().server_interfaces), [])

    def test_a_member_subnet_reports_the_interface_of_its_shared_network(self):
        summary = self._apply()

        detail = "Kea applies the value of Shared Network office, which is not imported."
        for subnet_id in (20, 21):
            with self.subTest(subnet_id=subnet_id):
                (entry,) = [e for e in summary.entries if e.path == f"Dhcp4/subnet4[id={subnet_id}]/interface"]
                self.assertEqual((entry.reason, entry.detail), (Reason.INHERITED_FROM_SHARED_NETWORK, detail))

    def test_a_subnet_class_that_kea_does_not_define_is_reported_and_not_created(self):
        config = _recorded_config(4)
        config["subnet4"][0]["client-classes"] = ["voip", "KNOWN"]

        summary = self._apply(config)

        self.assertEqual(self._names(self._subnet().client_classes), ["voip"])
        self.assertEqual(
            self._entries(summary, f"{_SUBNET_10}/client-classes"),
            {f"{_SUBNET_10}/client-classes[KNOWN]": (Reason.NO_PLUGIN_HOME, None)},
        )
        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        self.assertFalse(ClientClass.objects.filter(name="KNOWN").exists())

    def test_a_subnet_class_that_kea_stops_naming_is_unlinked(self):
        self._apply()
        config = _recorded_config(4)
        del config["subnet4"][0]["evaluate-additional-classes"]

        summary = self._apply(config)

        self.assertEqual(self._names(self._subnet().evaluate_additional_classes), [])
        self.assertIn((_SUBNET_10, Outcome.UPDATED), [(entry.path, entry.outcome) for entry in summary.entries])
        self.assertEqual([entry.path for entry in self._apply(config).entries if entry.path == _SUBNET_10], [])

    def test_a_class_list_that_is_not_valid_keeps_the_class_links(self):
        self._apply()
        config = _recorded_config(4)
        config["subnet4"][0]["client-classes"] = ["voip", 7]
        config["subnet4"][0]["pools"][0]["evaluate-additional-classes"] = ["printers", None]

        summary = self._apply(config)

        pool = apps.get_model(DHCP_PLUGIN, "Pool").objects.get(subnet=self._subnet(), pool_id=7)
        self.assertEqual(
            (self._names(self._subnet().client_classes), self._names(pool.evaluate_additional_classes)),
            (["voip"], ["printers"]),
        )
        pool_path = f"{_SUBNET_10}/pools[pool=192.0.2.10-192.0.2.20]"
        self.assertEqual(
            self._entries(summary, f"{_SUBNET_10}/client-classes")
            | self._entries(summary, f"{pool_path}/evaluate-additional-classes"),
            {
                f"{_SUBNET_10}/client-classes": (Reason.INVALID_KEA_DATA, None),
                f"{pool_path}/evaluate-additional-classes": (Reason.INVALID_KEA_DATA, None),
            },
        )

    def test_dhcpv6_imports_the_global_adaptive_threshold_and_subnet_classes(self):
        from decimal import Decimal

        self.server.dhcp6 = True
        self.server.save()

        self._apply(family=6)

        self.assertEqual(imported_dhcp_server(self.server, 6).adaptive_lease_time_threshold, Decimal("0.80"))
        subnet = self._subnet(family=6)
        self.assertEqual(
            (self._names(subnet.client_classes), self._names(subnet.evaluate_additional_classes)),
            (["voip"], ["printers"]),
        )


def _class_chain(prefix: str, length: int) -> list[dict]:
    """Return *length* client classes, each with an Option that names the class before it."""
    names = [f"{prefix}{index}" for index in range(length)]
    return [
        {
            "name": name,
            "test": f"option[60].hex == '{name}'",
            "option-data": [{"code": 15, "data": f"{name}.example.org", "client-classes": [names[index - 1]]}]
            if index
            else [],
        }
        for index, name in enumerate(names)
    ]


_BOOT = "Dhcp4/client-classes[name=boot]"


class OptionCoverageTest(TestCase):
    """The coverage configuration imports option client classes and every declared Option Definition."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name="option-coverage", ca_url="https://kea.example.invalid")

    def _apply(self, config: dict | None = None, family: int = 4):
        intent = parse_dhcp_config(_recorded_config(family) if config is None else config, family)
        intent.configuration_complete = True
        summary = dhcp_plugin.apply_plan(self.server, plan_family(intent, None), probe())
        self.assertEqual(summary.errors, 0, summary.warnings)
        return summary

    def _options(self, parent, code: int) -> list[tuple]:
        from django.contrib.contenttypes.models import ContentType

        rows = apps.get_model(DHCP_PLUGIN, "Option").objects.filter(
            assigned_object_type=ContentType.objects.get_for_model(parent),
            assigned_object_id=parent.pk,
            definition__code=code,
        )
        return sorted((row.data, tuple(row.client_classes.values_list("name", flat=True))) for row in rows)

    @staticmethod
    def _entries(summary, kind: Kind) -> dict:
        return {entry.path: (entry.outcome, entry.capability) for entry in summary.entries if entry.kind == kind}

    def _mapped_definition(self, identity: str, family: int = 4):
        return KeaDhcpLink.objects.get(
            server=self.server, family=family, kind="option_definition", kea_identity=identity
        ).sys4_object

    def test_the_classed_and_the_unclassed_routers_are_two_options_of_the_dhcp_server(self):
        summary = self._apply()

        dhcp_server = imported_dhcp_server(self.server, 4)
        self.assertEqual(self._options(dhcp_server, 3), [("192.0.2.1", ("voip",)), ("192.0.2.254", ())])
        options = self._entries(summary, Kind.OPTION)
        self.assertEqual(options["Dhcp4/option-data[code=3,client-classes=voip]"], (Outcome.CREATED, None))
        self.assertEqual(options["Dhcp4/option-data[code=3]"], (Outcome.CREATED, None))

    def test_an_unused_custom_option_definition_is_imported_for_the_dhcp_server(self):
        summary = self._apply()

        definition = self._mapped_definition("dhcp4:227")
        self.assertEqual(
            (definition.name, definition.dhcp_server, definition.client_class, definition.options.count()),
            ("unused-flag", imported_dhcp_server(self.server, 4), None, 0),
        )
        entries = self._entries(summary, Kind.OPTION_DEFINITION)
        self.assertEqual(entries["Dhcp4/option-def[code=227]"], (Outcome.CREATED, None))
        # Kea's comment is a user-context, which plugin 0.2.0 cannot hold.
        self.assertEqual(
            entries["Dhcp4/option-def[code=227]/user-context"], (Outcome.UNSUPPORTED, Capability.USER_CONTEXT)
        )

    def test_the_class_level_definition_is_scoped_to_its_class_and_the_class_option_uses_it(self):
        summary = self._apply()

        boot = KeaDhcpLink.objects.get(server=self.server, family=4, kind="client_class", kea_identity="boot")
        definition = self._mapped_definition("boot:dhcp4:231")
        self.assertEqual(
            (definition.name, definition.client_class, definition.dhcp_server), ("boot-flag", boot.sys4_object, None)
        )
        self.assertEqual(list(definition.options.values_list("data", "assigned_object_id")), [("1", boot.object_id)])
        self.assertEqual(
            {path: value for path, value in self._entries(summary, Kind.OPTION_DEFINITION).items() if _BOOT in path},
            {
                f"{_BOOT}/option-def[code=231]": (Outcome.CREATED, None),
                f"{_BOOT}/option-def[code=231]/user-context": (Outcome.UNSUPPORTED, Capability.USER_CONTEXT),
            },
        )
        self.assertEqual(
            {path: value for path, value in self._entries(summary, Kind.OPTION).items() if _BOOT in path},
            {
                f"{_BOOT}/option-data[code=231]": (Outcome.CREATED, None),
                f"{_BOOT}/option-data[code=231]/user-context": (Outcome.UNSUPPORTED, Capability.USER_CONTEXT),
            },
        )

    def test_with_plugin_0_2_0_each_fact_without_its_capability_is_unsupported_with_its_options(self):
        self.server.dhcp6 = True
        self.server.save()
        spaces, code, no_definition = (
            Capability.OPTION_SPACES,
            Capability.OPTION_CODE_16_BIT,
            Capability.OPTION_WITHOUT_DEFINITION,
        )
        expected = {
            4: {
                "Dhcp4/option-def[space=vendor-sub,code=1]": spaces,
                "Dhcp4/option-data[space=vendor-sub,code=1]": spaces,
                "Dhcp4/option-data[code=150]": no_definition,
            },
            6: {
                "Dhcp6/option-def[code=1000]": code,
                "Dhcp6/option-def[code=1001]": code,
                "Dhcp6/option-def[code=1002]": code,
                "Dhcp6/option-def[space=vendor-sub,code=1]": spaces,
                "Dhcp6/option-data[code=1000]": code,
                "Dhcp6/option-data[code=1001]": code,
                "Dhcp6/option-data[code=1002]": code,
                "Dhcp6/option-data[space=vendor-sub,code=1]": spaces,
                # The first missing capability in the order of the parity ledger: an option code needs a definition.
                "Dhcp6/option-data[code=1003]": no_definition,
            },
        }
        for family, paths in expected.items():
            with self.subTest(family=family):
                summary = self._apply(family=family)
                unsupported = {
                    entry.path: entry.capability
                    for entry in summary.entries
                    if entry.kind in (Kind.OPTION, Kind.OPTION_DEFINITION)
                    and entry.outcome == Outcome.UNSUPPORTED
                    and entry.capability != Capability.USER_CONTEXT
                }
                self.assertEqual(unsupported, paths)
        self.assertEqual(self._mapped_definition("dhcp6:250", 6).name, "unused-flag")

    def test_a_second_run_keeps_every_option_and_definition_and_changes_nothing(self):
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        OptionDefinition = apps.get_model(DHCP_PLUGIN, "OptionDefinition")
        self._apply()
        options = set(Option.objects.values_list("pk", flat=True))
        definitions = set(OptionDefinition.objects.filter(standard=False).values_list("pk", flat=True))

        again = self._apply()

        written = (Outcome.CREATED, Outcome.UPDATED)
        self.assertEqual(
            [entry.path for entry in again.entries if entry.outcome in written and entry.kind != Kind.SERVER], []
        )
        self.assertEqual(set(Option.objects.values_list("pk", flat=True)), options)
        self.assertEqual(set(OptionDefinition.objects.filter(standard=False).values_list("pk", flat=True)), definitions)

    def test_an_option_that_an_older_import_wrote_without_classes_is_adopted(self):
        config = _recorded_config(4)
        options = config["option-data"]
        unclassed = next(o for o in options if o.get("code") == 3 and "client-classes" not in o)
        options.remove(unclassed)
        classed = next(o for o in options if o.get("code") == 3)
        older = json.loads(json.dumps(config))
        del next(o for o in older["option-data"] if o.get("code") == 3)["client-classes"]
        self._apply(older)
        dhcp_server = imported_dhcp_server(self.server, 4)
        self.assertEqual(self._options(dhcp_server, 3), [(classed["data"], ())])
        before = set(apps.get_model(DHCP_PLUGIN, "Option").objects.values_list("pk", flat=True))

        summary = self._apply(config)

        self.assertEqual(self._options(dhcp_server, 3), [(classed["data"], ("voip",))])
        self.assertEqual(set(apps.get_model(DHCP_PLUGIN, "Option").objects.values_list("pk", flat=True)), before)
        self.assertEqual(
            self._entries(summary, Kind.OPTION)["Dhcp4/option-data[code=3,client-classes=voip]"],
            (Outcome.UPDATED, None),
        )

    def test_a_stale_class_level_definition_is_removed_through_its_own_mapping(self):
        config = _recorded_config(4)
        boot = next(c for c in config["client-classes"] if c["name"] == "boot")
        boot["option-def"].append({"name": "spare", "code": 232, "space": "dhcp4", "type": "uint8"})
        self._apply(config)
        spare = self._mapped_definition("boot:dhcp4:232")
        intent = _recorded_intent(4)
        intent.read_started = datetime.now(timezone.utc)

        summary = dhcp_plugin.apply_plan(self.server, plan_family(intent, None), probe())

        OptionDefinition = apps.get_model(DHCP_PLUGIN, "OptionDefinition")
        self.assertFalse(OptionDefinition.objects.filter(pk=spare.pk).exists())
        self.assertEqual(
            self._entries(summary, Kind.OPTION_DEFINITION)[f"{_BOOT}/option-def[code=232]"], (Outcome.REMOVED, None)
        )
        self.assertTrue(OptionDefinition.objects.filter(pk=self._mapped_definition("boot:dhcp4:231").pk).exists())

    def _apply_read(self, config: dict, errors: int = 0):
        """Apply a Complete read of *config* that started now, so a mapping that it does not report is stale."""
        intent = parse_dhcp_config(config, 4)
        intent.configuration_complete = True
        intent.read_started = datetime.now(timezone.utc)
        summary = dhcp_plugin.apply_plan(self.server, plan_family(intent, None), probe())
        self.assertEqual(summary.errors, errors, summary.warnings)
        return summary

    def test_a_stale_client_class_goes_with_its_own_definition_and_options(self):
        self._apply()
        boot = KeaDhcpLink.objects.get(server=self.server, family=4, kind="client_class", kea_identity="boot")
        definition = self._mapped_definition("boot:dhcp4:231")
        options = list(definition.options.values_list("pk", flat=True))
        self.assertEqual(len(options), 1)
        config = _recorded_config(4)
        config["client-classes"] = [c for c in config["client-classes"] if c["name"] != "boot"]

        summary = self._apply_read(config)

        self.assertFalse(apps.get_model(DHCP_PLUGIN, "ClientClass").objects.filter(pk=boot.object_id).exists())
        self.assertFalse(apps.get_model(DHCP_PLUGIN, "OptionDefinition").objects.filter(pk=definition.pk).exists())
        self.assertFalse(apps.get_model(DHCP_PLUGIN, "Option").objects.filter(pk__in=options).exists())
        self.assertFalse(
            KeaDhcpLink.objects.filter(server=self.server, kea_identity__in=["boot", "boot:dhcp4:231"]).exists()
        )
        removed = {entry.path for entry in summary.entries if entry.outcome == Outcome.REMOVED}
        self.assertEqual(removed, {_BOOT, f"{_BOOT}/option-def[code=231]"})

    def test_a_stale_client_class_that_an_option_still_names_is_kept(self):
        self._apply()
        voip = KeaDhcpLink.objects.get(server=self.server, family=4, kind="client_class", kea_identity="voip")
        config = _without_class(_recorded_config(4), "voip")
        config["option-data"] = [o for o in config["option-data"] if o.get("client-classes") != []]

        summary = self._apply_read(config)

        dhcp_server = imported_dhcp_server(self.server, 4)
        # Kea no longer declares the classed routers, so its Option stays unpaired and keeps its class.
        self.assertEqual(self._options(dhcp_server, 3), [("192.0.2.1", ("voip",)), ("192.0.2.254", ())])
        self.assertTrue(apps.get_model(DHCP_PLUGIN, "ClientClass").objects.filter(pk=voip.object_id).exists())
        (entry,) = [e for e in summary.entries if e.path == "Dhcp4/client-classes[name=voip]"]
        self.assertEqual(entry.reason, Reason.REMOVAL_BLOCKED)
        self.assertIn("1 Option", entry.detail)

    def test_a_class_local_definition_wins_over_the_standard_definition_of_its_code(self):
        config = _recorded_config(4)
        config["client-classes"].append(
            {
                "name": "vendor-x",
                "test": "option[60].hex == 'x'",
                "option-def": [{"name": "vendor-text", "code": 43, "space": "dhcp4", "type": "string"}],
                "option-data": [{"code": 43, "name": "vendor-text", "space": "dhcp4", "data": "hello"}],
            }
        )

        summary = self._apply(config)

        definition = self._mapped_definition("vendor-x:dhcp4:43")
        self.assertEqual(definition.type, "string")
        self.assertEqual(list(definition.options.values_list("data", flat=True)), ["hello"])
        path = "Dhcp4/client-classes[name=vendor-x]/option-data[code=43]"
        self.assertEqual(self._entries(summary, Kind.OPTION)[path], (Outcome.CREATED, None))

    def test_an_option_does_not_bind_to_a_custom_definition_that_kea_does_not_declare(self):
        OptionDefinition = apps.get_model(DHCP_PLUGIN, "OptionDefinition")
        self._apply()
        operator = OptionDefinition.objects.create(
            name="operator-flag",
            space="dhcp4",
            code=228,
            type="uint8",
            family=4,
            dhcp_server=imported_dhcp_server(self.server, 4),
        )
        config = _recorded_config(4)
        config["option-data"].append({"code": 228, "space": "dhcp4", "data": "1"})

        summary = self._apply(config)

        self.assertEqual(
            self._entries(summary, Kind.OPTION)["Dhcp4/option-data[code=228]"],
            (Outcome.UNSUPPORTED, Capability.OPTION_WITHOUT_DEFINITION),
        )
        self.assertFalse(operator.options.exists())

    def test_an_option_whose_class_was_not_imported_in_this_run_is_skipped(self):
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        other = DHCPServer.objects.create(name="option-coverage other server")
        # Plugin 0.2.0 keeps class names unique across all DHCP servers, so this run cannot write voip.
        apps.get_model(DHCP_PLUGIN, "ClientClass").objects.create(name="voip", dhcp_server=other)

        summary = self._apply()

        (entry,) = [e for e in summary.entries if e.path == "Dhcp4/option-data[code=3,client-classes=voip]"]
        self.assertEqual(entry.reason, Reason.PARENT_NOT_IMPORTED)
        self.assertTrue(entry.detail.startswith("Client class voip was not imported."), entry.detail)
        self.assertEqual(self._options(imported_dhcp_server(self.server, 4), 3), [("192.0.2.254", ())])

    def test_an_option_keeps_its_row_when_its_class_declares_the_definition_of_its_code(self):
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        config = _recorded_config(4)
        boot = next(c for c in config["client-classes"] if c["name"] == "boot")
        # First the daemon declares the definition that the class option uses.
        config["option-def"].extend(boot.pop("option-def"))
        self._apply(config)
        (before,) = Option.objects.filter(definition__code=231)

        summary = self._apply()

        (after,) = Option.objects.filter(definition__code=231)
        self.assertEqual(after.pk, before.pk)
        self.assertEqual(after.definition, self._mapped_definition("boot:dhcp4:231"))
        self.assertEqual(self._entries(summary, Kind.OPTION)[f"{_BOOT}/option-data[code=231]"], (Outcome.UPDATED, None))

    def test_a_stale_client_class_that_a_kept_row_evaluates_is_kept(self):
        from ipam.models import Prefix
        from netaddr import IPNetwork

        self._apply()
        printers = KeaDhcpLink.objects.get(server=self.server, family=4, kind="client_class", kea_identity="printers")
        operator = apps.get_model(DHCP_PLUGIN, "Subnet").objects.create(
            name="operator subnet",
            prefix=Prefix.objects.create(prefix=IPNetwork("203.0.113.0/24")),
            dhcp_server=imported_dhcp_server(self.server, 4),
        )
        operator.evaluate_additional_classes.set([printers.object_id])

        summary = self._apply_read(_without_class(_recorded_config(4), "printers"))

        self.assertEqual(list(operator.evaluate_additional_classes.values_list("pk", flat=True)), [printers.object_id])
        (entry,) = [e for e in summary.entries if e.path == "Dhcp4/client-classes[name=printers]"]
        self.assertEqual(
            (entry.reason, entry.detail),
            (Reason.REMOVAL_BLOCKED, "It is kept while a class list of 1 Subnet names it."),
        )

    def test_a_stale_class_stays_when_the_stale_owner_of_an_option_that_names_it_stays(self):
        from ipam.models import Prefix
        from netaddr import IPNetwork

        config = _recorded_config(4)
        config["client-classes"] += [
            {"name": "a", "test": "option[60].hex == 'a'"},
            {
                "name": "b",
                "test": "option[60].hex == 'b'",
                "option-data": [{"code": 15, "data": "b.example.org", "client-classes": ["a"]}],
            },
        ]
        self._apply(config)
        b = KeaDhcpLink.objects.get(server=self.server, family=4, kind="client_class", kea_identity="b")
        operator = apps.get_model(DHCP_PLUGIN, "Subnet").objects.create(
            name="operator subnet",
            prefix=Prefix.objects.create(prefix=IPNetwork("203.0.113.0/24")),
            dhcp_server=imported_dhcp_server(self.server, 4),
        )
        operator.evaluate_additional_classes.set([b.object_id])

        summary = self._apply_read(_recorded_config(4))

        # The kept Subnet keeps b, so b's Option stays, and removing a would take its class away.
        blocked = {entry.path for entry in summary.entries if entry.reason == Reason.REMOVAL_BLOCKED}
        self.assertEqual(blocked, {"Dhcp4/client-classes[name=a]", "Dhcp4/client-classes[name=b]"})
        option = apps.get_model(DHCP_PLUGIN, "Option").objects.get(data="b.example.org")
        self.assertEqual(list(option.client_classes.values_list("name", flat=True)), ["a"])

    def test_a_stale_row_that_depends_on_a_failed_removal_stays(self):
        from django.db.models.signals import pre_delete

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        self._apply()
        printers = KeaDhcpLink.objects.get(server=self.server, family=4, kind="client_class", kea_identity="printers")
        subnet = KeaDhcpLink.objects.get(server=self.server, family=4, kind="subnet", kea_subnet_id=10).sys4_object
        config = _without_class(_recorded_config(4), "printers")
        config["subnet4"] = []

        def refuse(sender, instance, **kwargs):
            if instance.pk == subnet.pk:
                raise RuntimeError("the Subnet delete fails")

        pre_delete.connect(refuse, sender=Subnet, weak=False)
        try:
            summary = self._apply_read(config, errors=1)
        finally:
            pre_delete.disconnect(refuse, sender=Subnet)

        entries = {entry.path: entry.reason for entry in summary.entries if entry.reason is not None}
        self.assertEqual(entries[_SUBNET_10], Reason.WRITE_FAILED)
        self.assertEqual(entries["Dhcp4/client-classes[name=printers]"], Reason.REMOVAL_BLOCKED)
        # The kept Subnet still evaluates printers: the class removal would have taken it away.
        self.assertEqual(
            list(Subnet.objects.get(pk=subnet.pk).evaluate_additional_classes.values_list("pk", flat=True)),
            [printers.object_id],
        )

    def test_a_failed_removal_keeps_every_stale_row_that_relies_on_it(self):
        from django.db.models.signals import pre_delete

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        config = _recorded_config(4)
        config["client-classes"] += [
            {"name": "a", "test": "option[60].hex == 'a'"},
            {
                "name": "b",
                "test": "option[60].hex == 'b'",
                "option-data": [{"code": 15, "data": "b.example.org", "client-classes": ["a"]}],
            },
        ]
        config["subnet4"].append({"id": 30, "subnet": "203.0.113.0/24", "evaluate-additional-classes": ["b"]})
        self._apply(config)
        subnet = KeaDhcpLink.objects.get(server=self.server, family=4, kind="subnet", kea_subnet_id=30).sys4_object

        def refuse(sender, instance, **kwargs):
            if instance.pk == subnet.pk:
                raise RuntimeError("the Subnet delete fails")

        pre_delete.connect(refuse, sender=Subnet, weak=False)
        try:
            summary = self._apply_read(_recorded_config(4), errors=1)
        finally:
            pre_delete.disconnect(refuse, sender=Subnet)

        entries = {entry.path: entry.reason for entry in summary.entries if entry.reason is not None}
        self.assertEqual(entries["Dhcp4/subnet4[id=30]"], Reason.WRITE_FAILED)
        # b relies on the Subnet, and a relies on b: the removal of a would take the class from b's Option.
        self.assertEqual(entries["Dhcp4/client-classes[name=b]"], Reason.REMOVAL_BLOCKED)
        self.assertEqual(entries["Dhcp4/client-classes[name=a]"], Reason.REMOVAL_BLOCKED)
        option = apps.get_model(DHCP_PLUGIN, "Option").objects.get(data="b.example.org")
        self.assertEqual(list(option.client_classes.values_list("name", flat=True)), ["a"])

    def test_two_stale_client_classes_whose_options_name_each_other_are_both_removed(self):
        config = _recorded_config(4)
        config["client-classes"] += [
            {
                "name": "a",
                "test": "option[60].hex == 'a'",
                "option-data": [{"code": 15, "data": "a.example.org", "client-classes": ["b"]}],
            },
            {
                "name": "b",
                "test": "option[60].hex == 'b'",
                "option-data": [{"code": 15, "data": "b.example.org", "client-classes": ["a"]}],
            },
        ]
        self._apply(config)

        summary = self._apply_read(_recorded_config(4))

        removed = {entry.path for entry in summary.entries if entry.outcome == Outcome.REMOVED}
        self.assertEqual(removed, {"Dhcp4/client-classes[name=a]", "Dhcp4/client-classes[name=b]"})
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        self.assertFalse(Option.objects.filter(data__in=["a.example.org", "b.example.org"]).exists())

    def test_an_option_that_names_a_class_without_a_plugin_row_is_skipped(self):
        config = _recorded_config(4)
        config["option-data"].append(
            {"code": 15, "name": "domain-name", "data": "known.example.org", "client-classes": ["KNOWN"]}
        )

        summary = self._apply(config)

        (entry,) = [e for e in summary.entries if e.path == "Dhcp4/option-data[code=15,client-classes=KNOWN]"]
        self.assertEqual(entry.reason, Reason.PARENT_NOT_IMPORTED)
        self.assertIn("KNOWN", entry.detail)
        self.assertFalse(apps.get_model(DHCP_PLUGIN, "Option").objects.filter(data="known.example.org").exists())


def _without_class(config: dict, name: str) -> dict:
    """Return a copy of *config* without the client class *name*, and with *name* left out of every class list."""

    def strip(value):
        if isinstance(value, list):
            return [strip(item) for item in value]
        if not isinstance(value, dict):
            return value
        lists = (kea_paths.CLIENT_CLASSES, kea_paths.EVALUATE_ADDITIONAL_CLASSES)
        return {
            key: [each for each in item if each != name] if key in lists and isinstance(item, list) else strip(item)
            for key, item in value.items()
        }

    classes = [entry for entry in config[kea_paths.CLIENT_CLASSES] if entry["name"] != name]
    return strip({**config, kea_paths.CLIENT_CLASSES: []}) | {kea_paths.CLIENT_CLASSES: classes}


# The Subnet fields that Kea's config-get fills from the parent or that the coverage configuration declares.
_INHERITABLE = (
    "valid_lifetime",
    "min_valid_lifetime",
    "max_valid_lifetime",
    "offer_lifetime",
    "renew_timer",
    "rebind_timer",
    "t1_percent",
    "t2_percent",
    "cache_threshold",
    "cache_max_age",
    "calculate_tee_times",
    "store_extended_info",
    "allocator",
    "relay",
    "ddns_qualifying_suffix",
    "reservations_global",
    "reservations_in_subnet",
)


# The ClientClass fields that the coverage configuration declares on some class.
_CLASS_FIELDS = (
    "valid_lifetime",
    "min_valid_lifetime",
    "max_valid_lifetime",
    "next_server",
    "server_hostname",
    "boot_file_name",
)


def _with_value(config, key: str, old, new):
    """Return a copy of *config* in which every *key* that has the value *old* has the value *new*."""
    if isinstance(config, list):
        return [_with_value(item, key, old, new) for item in config]
    if not isinstance(config, dict):
        return config
    return {
        name: new if name == key and value == old else _with_value(value, key, old, new)
        for name, value in config.items()
    }


class StaleRemovalQueryCountTest(TestCase):
    """The removal decision reads each stale row once, so its queries grow linearly with the stale rows."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def _stale_chain_queries(self, prefix: str, length: int, network: str) -> int:
        """Import a chain of classes, keep its last class through an operator Subnet, and count a Complete read."""
        from django.db import connection
        from ipam.models import Prefix
        from netaddr import IPNetwork

        server = _make_db_server(name=f"chain-{prefix}", ca_url="https://kea.example.invalid", dhcp6=False)
        intent = parse_dhcp_config({"client-classes": _class_chain(prefix, length)}, 4)
        intent.configuration_complete = True
        self.assertEqual(dhcp_plugin.apply_plan(server, plan_family(intent, None), probe()).errors, 0)
        last = KeaDhcpLink.objects.get(server=server, kind="client_class", kea_identity=f"{prefix}{length - 1}")
        operator = apps.get_model(DHCP_PLUGIN, "Subnet").objects.create(
            name=f"chain-{prefix} operator",
            prefix=Prefix.objects.create(prefix=IPNetwork(network)),
            dhcp_server=imported_dhcp_server(server, 4),
        )
        operator.evaluate_additional_classes.set([last.object_id])
        empty = parse_dhcp_config({}, 4)
        empty.configuration_complete, empty.read_started = True, datetime.now(timezone.utc)
        executed = []

        def count(execute, sql, params, many, context):
            executed.append(sql)
            return execute(sql, params, many, context)

        # An execute wrapper counts every query: CaptureQueriesContext keeps only the last 9000.
        with connection.execute_wrapper(count):
            summary = dhcp_plugin.apply_plan(server, plan_family(empty, None), probe())

        blocked = [entry for entry in summary.entries if entry.reason == Reason.REMOVAL_BLOCKED]
        self.assertEqual(len(blocked), length)
        return len(executed)

    def test_a_chain_of_stale_classes_that_a_kept_row_holds_costs_queries_linear_in_its_length(self):
        short = self._stale_chain_queries("short", 50, "203.0.113.0/24")
        long = self._stale_chain_queries("long", 300, "198.51.100.0/24")

        # One plan reads one class in a bounded number of queries; a plan for every row on every pass is quadratic.
        self.assertLess((long - short) / 250, 60, (short, long))


class PluginVersionRefusalTest(TestCase):
    """An installed netbox-plugin-dhcp older than 0.2.0 makes the import refuse before any Kea read or write."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def test_sync_now_refuses_an_older_plugin_and_names_the_required_version(self):
        self.client.force_login(get_user_model().objects.create_superuser("version-refusal"))
        server = _make_db_server(name="version-refusal", sync_dhcp_plugin_enabled=True)
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[server.pk])

        with patch.object(apps.get_app_config(DHCP_PLUGIN), "version", "0.1.9"), stub_kea({}) as kea:
            response = self.client.post(url)

        self.assertRedirects(
            response, reverse("plugins:netbox_kea:server_dhcp_plugin", args=[server.pk]), fetch_redirect_response=False
        )
        (message,) = get_messages(response.wsgi_request)
        self.assertEqual(message.level, ERROR)
        self.assertEqual(
            str(message),
            "The DHCP Import needs netbox-plugin-dhcp 0.2.0 or later. The installed version is 0.1.9.",
        )
        self.assertEqual(kea.commands(), [])
        self.assertFalse(
            apps.get_model(DHCP_PLUGIN, "DHCPServer").objects.filter(name__startswith=server.name).exists()
        )
        self.assertFalse(KeaDhcpLink.objects.filter(server=server).exists())

    def test_sync_now_refuses_a_plugin_version_it_cannot_read(self):
        self.client.force_login(get_user_model().objects.create_superuser("version-unreadable"))
        server = _make_db_server(name="version-unreadable", sync_dhcp_plugin_enabled=True)
        url = reverse("plugins:netbox_kea:server_dhcp_plugin_sync", args=[server.pk])

        with patch.object(apps.get_app_config(DHCP_PLUGIN), "version", "main"), stub_kea({}) as kea:
            response = self.client.post(url)

        (message,) = get_messages(response.wsgi_request)
        self.assertEqual(message.level, ERROR)
        self.assertEqual(
            str(message),
            "The DHCP Import needs netbox-plugin-dhcp 0.2.0 or later. The installed version is main.",
        )
        self.assertEqual(kea.commands(), [])
        self.assertFalse(
            apps.get_model(DHCP_PLUGIN, "DHCPServer").objects.filter(name__startswith=server.name).exists()
        )
