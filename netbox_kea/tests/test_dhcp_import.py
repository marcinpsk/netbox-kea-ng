# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCP Import runs as three steps: read Kea, plan each family, apply each plan to the DHCP plugin."""

from __future__ import annotations

import ipaddress
import unittest
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
from netbox_kea.integrations.dhcp_import_plan import (
    FamilyPlan,
    GlobalReservationKey,
    InSubnetReservationKey,
    OptionDefinitionKey,
    PoolKey,
    keyed_reservations,
    plan_family,
)
from netbox_kea.integrations.dhcp_import_report import GAPS, Capability
from netbox_kea.integrations.dhcp_plugin_capabilities import CHECKS, probe
from netbox_kea.ipam_reconciliation import ReservationObservation
from netbox_kea.mappers.kea_to_dhcp import parse_dhcp_config
from netbox_kea.models import KeaDhcpLink
from netbox_kea.pools import Pool
from netbox_kea.reservations import (
    GlobalReservationScope,
    InSubnetReservationScope,
    IPv4Reservation,
    ReservationIdentity,
    ReservationSnapshot,
)
from netbox_kea.subnet_catalogue import IncompleteCatalogueSnapshot, SubnetIdentity

from .kea_stub import stub_kea
from .test_integration_dhcp_plugin import _reservation_snapshot
from .test_kea_recordings import _recording
from .utils import _make_db_server

DHCP_PLUGIN = "netbox_dhcp"
_IN_SUBNET_MAC = "02:00:00:00:00:0a"
_GLOBAL_DUID = "01:02:03:04:05:06"


def _recorded_config(family: int) -> dict:
    return _recording(family)["config-get"]["arguments"][f"Dhcp{family}"]


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

    def test_a_pool_outside_its_subnet_has_no_key(self):
        config = {"subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "pools": [{"pool": "198.51.100.1-198.51.100.9"}]}]}

        plan = plan_family(parse_dhcp_config(config, 4), None)

        (pool,) = plan.subnets[0].pools
        self.assertIsNone(pool.key)
        self.assertEqual(pool.intent.pool, "198.51.100.1-198.51.100.9")


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
                for pool in Pool.objects.filter(subnet__dhcp_server__name=server.name)
            ),
            [
                ("192.0.2.10", "192.0.2.20"),
                ("192.0.2.64", "192.0.2.127"),
                ("198.51.100.10", "198.51.100.50"),
                ("198.51.100.200", "198.51.100.220"),
            ],
        )
        self.assertEqual(
            set(ClientClass.objects.filter(dhcp_server__name=server.name).values_list("name", flat=True)),
            {"voip", "printers", "boot", "per-client"},
        )
        self.assertEqual(
            set(
                OptionDefinition.objects.filter(standard=False, dhcp_server__name=server.name).values_list(
                    "space", "code"
                )
            ),
            {("dhcp4", 224), ("dhcp4", 225), ("dhcp4", 226)},
        )
        record = OptionDefinition.objects.get(dhcp_server__name=server.name, code=225)
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
            *Pool.objects.filter(subnet__dhcp_server__name=server.name),
            *HostReservation.objects.filter(subnet__dhcp_server__name=server.name),
            *HostReservation.objects.filter(dhcp_server__name=server.name, subnet__isnull=True),
            *ClientClass.objects.filter(dhcp_server__name=server.name),
            *OptionDefinition.objects.filter(standard=False, dhcp_server__name=server.name),
        ]
        mapped = KeaDhcpLink.objects.filter(server=server, family=4).exclude(kind="subnet")
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
        self.assertFalse(apps.get_model(DHCP_PLUGIN, "DHCPServer").objects.filter(name=server.name).exists())
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
        self.assertFalse(apps.get_model(DHCP_PLUGIN, "DHCPServer").objects.filter(name=server.name).exists())
