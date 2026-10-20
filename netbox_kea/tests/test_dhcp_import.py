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

from netbox_kea.integrations import dhcp_plugin
from netbox_kea.integrations.dhcp_import_ledger import KEA_DEFAULTS
from netbox_kea.integrations.dhcp_import_plan import (
    REMOVAL_ORDER,
    FamilyPlan,
    GlobalReservationKey,
    InSubnetReservationKey,
    MappingSource,
    OptionDefinitionKey,
    PoolKey,
    keyed_reservations,
    observations,
    plan_family,
)
from netbox_kea.integrations.dhcp_import_report import GAPS, Capability, Kind, Reason
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
from .utils import _make_db_server, imported_dhcp_server, imported_dhcp_servers

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
            office = {"reservations-global": True, "relay": {"ip-addresses": relay}}
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
    def test_a_user_context_that_cannot_be_cleared_lacks_the_capability(self):
        plugin = _proposed_plugin_models()
        plugin["Pool"] = _probe_model("RequiredContextPool", user_context=models.JSONField())
        self.assertFalse(probe(plugin.__getitem__).has(Capability.USER_CONTEXT))


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
            relay=ArrayField(models.GenericIPAddressField()),
            user_context=user_context(),
        ),
        "Subnet": _probe_model(
            "Subnet",
            "subnet_id",
            dhcp_server=parent(),
            subnet_id=models.PositiveIntegerField(),
            relay=ArrayField(models.GenericIPAddressField()),
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
        ),
    }


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
            {("dhcp4", 224), ("dhcp4", 225), ("dhcp4", 226)},
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
        ]
        mapped = KeaDhcpLink.objects.filter(server=server, family=4).exclude(kind__in=["subnet", "server"])
        self.assertCountEqual(
            mapped.values_list("object_type__model", "object_id"),
            [(row._meta.model_name, row.pk) for row in rows],
        )
        # Four Pools, two Reservations, four client classes and three custom Option Definitions.
        self.assertEqual(mapped.count(), 13)
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
                "relay": "198.51.100.1",
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
                ("Dhcp4/subnet4[id=20]/relay", detail),
                ("Dhcp4/subnet4[id=20]/reservations-global", detail),
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
