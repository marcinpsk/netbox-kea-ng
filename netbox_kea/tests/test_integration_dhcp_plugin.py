# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the optional netbox_dhcp adapter (real DB + real plugin).

Gated on the plugin being installed. A dedicated CI job installs the exact
supported ``netbox_dhcp`` release. Other environments can skip this module.
Only the Kea HTTP boundary is bypassed. The ORM, IPAM/DCIM models, and the
``netbox_dhcp`` models are real.
"""

from __future__ import annotations

import ipaddress
import unittest
from functools import partial

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase, tag
from django.urls import reverse
from django.utils import timezone

from netbox_kea import server_configuration
from netbox_kea.dhcp_options import option_identity, parse_dhcp_option
from netbox_kea.integrations.dhcp_import_report import Kind, Reason, not_written
from netbox_kea.ipam_reconciliation import ReservationObservation
from netbox_kea.mappers.kea_to_dhcp import ServerConfigIntent, parse_dhcp_config
from netbox_kea.models import next_confirmation_number
from netbox_kea.reservations import (
    RESERVATION_INVALID_IDENTIFIER,
    RESERVATION_PAGE_FETCH_FAILED,
    Family,
    ReservationDiagnostic,
    ReservationSnapshot,
)
from netbox_kea.subnet_catalogue import IncompleteCatalogueSnapshot, SubnetIdentity, VerifiedSubnet

from .kea_stub import _res_page, kea_client, observed_configuration, stub_kea
from .utils import _make_db_server, lease_phase, linked_dhcp_targets, with_sync_config

DHCP_PLUGIN = "netbox_dhcp"


def _conf_v4():
    return {
        "subnet4": [
            {
                "id": 1,
                "subnet": "10.99.0.0/24",
                "pools": [{"pool": "10.99.0.10-10.99.0.100"}],
                "reservations": [
                    {"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "10.99.0.50", "hostname": "res-host"}
                ],
            }
        ]
    }


def _conf_v6():
    return {
        "subnet6": [
            {
                "id": 1,
                "subnet": "2001:db8:99::/64",
                "pools": [{"pool": "2001:db8:99::10-2001:db8:99::100"}],
                "reservations": [{"duid": "01:02:03:04:05", "ip-addresses": ["2001:db8:99::50"], "hostname": "res6"}],
            }
        ]
    }


def _subnet_entries(conf: dict, version: Family) -> list:
    subnet_key = f"subnet{version}"
    entries = list(conf.get(subnet_key, []))
    for shared_network in conf.get("shared-networks", []):
        entries.extend(shared_network.get(subnet_key, []))
    return entries


def _catalogue(conf: dict, version: Family) -> IncompleteCatalogueSnapshot:
    """Return the Subnet identities of *conf* with the effective DDNS qualifying suffixes."""
    entries = _subnet_entries(conf, version)
    # The real parser reads the effective DDNS qualifying suffixes from *conf*.
    configuration = observed_configuration(version, conf)
    declared = {subnet.declared_subnet_id: subnet for subnet in configuration.subnets}
    suffixes = {
        subnet_id: server_configuration.effective_qualifying_suffix(configuration, subnet)
        for subnet_id, subnet in declared.items()
    }
    verified = tuple(
        VerifiedSubnet(
            identity=SubnetIdentity(
                subnet_id=int(entry["id"]),
                network=ipaddress.ip_network(entry["subnet"]),
            ),
            declared_cidr=entry["subnet"],
            configuration=declared[int(entry["id"])].configuration if int(entry["id"]) in declared else None,
            shared_network=None,
            membership_known=False,
            qualifying_suffix=suffixes.get(int(entry["id"])),
            reservation_flags=None,
        )
        for entry in entries
        if isinstance(entry, dict) and entry.get("id") is not None and entry.get("subnet")
    )
    # The real parser's configuration facts; Shared Network membership is not shown.
    return IncompleteCatalogueSnapshot(
        server_id=1,
        family=version,
        observed_at=timezone.now(),
        subnets=verified,
        configured_subnets=(),
        diagnostics=(),
        identity_available=True,
        configuration_available=True,
        identity_complete=True,
        configuration_complete=not configuration.subnet_diagnostics,
        consistent=True,
        configuration_hash=None,
        global_qualifying_suffix=configuration.ddns_qualifying_suffix,
    )


def _reservation_snapshot(conf: dict, version: Family, hosts: list[dict] | None = None) -> ReservationObservation:
    """Build the real typed Snapshot used by the optional adapter."""
    entries = _subnet_entries(conf, version)
    catalogue = _catalogue(conf, version)
    if hosts is None:
        hosts = []
        for entry in entries:
            for reservation in entry.get("reservations", []):
                hosts.append({"subnet-id": int(entry["id"]), **reservation})
    client = kea_client(url="http://kea.example.invalid", send_service=False)
    with stub_kea({"reservation-get-page": _res_page(hosts)}):
        # Bound the page to the fixture so a larger fixture cannot silently truncate.
        cutoff = next_confirmation_number()
        return ReservationObservation(
            client.reservation_page(version, catalogue, limit=max(len(hosts), 1)), cutoff, catalogue
        )


class TestOptionalMetadataCoordination(TransactionTestCase):
    def test_ordinary_tag_edit_and_contenttype_delete_do_not_acquire_the_mapping_lock(self):
        from extras.models import Tag

        from netbox_kea import branching
        from netbox_kea.dhcp_mapping_lifecycle import _METADATA_LOCK

        if branching.installed() and apps.is_installed("netbox_dhcp"):
            self.skipTest("This profile verifies ordinary behavior without both optional plugins")
        self.client.force_login(get_user_model().objects.create_superuser("unbranched-metadata-admin"))
        tag = Tag.objects.create(name="ordinary tag", slug="ordinary-tag")
        stale = ContentType.objects.create(app_label="netbox_kea", model="obsolete_unbranched_mapping")
        stale_pk = stale.pk
        holder = connection.Database.connect(**connection.get_connection_params())
        try:
            with holder.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(%s, %s)", _METADATA_LOCK)
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_try_advisory_xact_lock(%s, %s)", _METADATA_LOCK)
                    self.assertFalse(cursor.fetchone()[0], "The independent writer did not hold the mapping lock")
                response = self.client.post(
                    reverse("extras:tag_edit", args=[tag.pk]),
                    {
                        "name": tag.name,
                        "slug": tag.slug,
                        "color": "112233",
                        "weight": 0,
                        "description": "ordinary edit",
                    },
                    follow=True,
                )
                self.assertEqual(response.status_code, 200)
                tag.refresh_from_db()
                self.assertEqual(tag.description, "ordinary edit")
                stale.delete()
            self.assertFalse(ContentType.objects.filter(pk=stale_pk).exists())
        finally:
            holder.close()


@tag("dhcp_plugin")
class DhcpPluginAdapterTest(TestCase):
    """Importing a Kea config into netbox_dhcp via the guarded adapter."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name=f"kea-int-{timezone.now().timestamp()}")
        from netbox_kea.integrations import dhcp_plugin

        self.adapter = dhcp_plugin

    # ── basic import ────────────────────────────────────────────────────────

    def test_target_deletion_accepts_a_model_attribute(self):
        from netbox_kea.models import KeaDhcpLink

        for target, link in linked_dhcp_targets(self.server):
            with self.subTest(model=target._meta.label):
                target.model = "target metadata"

                target.delete()

                self.assertFalse(type(target).objects.filter(pk=link.object_id).exists())
                self.assertFalse(KeaDhcpLink.objects.filter(pk=link.pk).exists())

    def test_dhcp_target_deletion_removes_only_its_matching_link(self):
        from netbox_kea.models import KeaDhcpLink

        targets = linked_dhcp_targets(self.server)
        remaining = {link.pk for _, link in targets}
        for target, link in targets:
            with self.subTest(model=target._meta.label, object_id=target.pk):
                target.delete()
                remaining.remove(link.pk)
                self.assertSetEqual(set(KeaDhcpLink.objects.values_list("pk", flat=True)), remaining)

    def test_dhcp_target_queryset_deletion_removes_its_links(self):
        from netbox_kea.models import KeaDhcpLink

        targets = linked_dhcp_targets(self.server)
        for target, link in targets:
            with self.subTest(model=target._meta.label):
                type(target).objects.filter(pk=target.pk).delete()
                self.assertFalse(KeaDhcpLink.objects.filter(pk=link.pk).exists())

    def test_dhcp_target_and_link_cleanup_rollback_together(self):
        from netbox_kea.models import KeaDhcpLink

        for target, link in linked_dhcp_targets(self.server):
            with self.subTest(model=target._meta.label):
                target_pk = target.pk
                with self.assertRaisesRegex(RuntimeError, "roll back target deletion"), transaction.atomic():
                    target.delete()
                    self.assertFalse(KeaDhcpLink.objects.filter(pk=link.pk).exists())
                    raise RuntimeError("roll back target deletion")
                self.assertTrue(type(target).objects.filter(pk=target_pk).exists())
                self.assertTrue(KeaDhcpLink.objects.filter(pk=link.pk).exists())

    def test_import_links_each_shared_ipam_object_to_its_source(self):
        from netbox_kea.models import IPAMOwnershipLink

        conf = _conf_v4()
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertCountEqual(
            IPAMOwnershipLink.objects.filter(server=self.server, family=4).values_list("source", flat=True),
            ["subnet", "pool", "reservation"],
        )

    def test_v4_import_creates_subnet_pool_reservation_sharing_ipam(self):
        from dcim.models import MACAddress
        from ipam.models import IPAddress, IPRange, Prefix

        from netbox_kea.models import KeaDhcpLink

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = _conf_v4()
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.subnets_created, 1)
        self.assertEqual(summary.pools_created, 1)
        self.assertEqual(summary.reservations_created, 1)

        # Subnet linked by Kea identity, sharing the IPAM Prefix the sync owns.
        link = KeaDhcpLink.objects.get(server=self.server, family=4, kind="subnet", kea_subnet_id=1)
        self.assertIsNone(link.kea_identity)
        subnet = link.sys4_object
        self.assertIsInstance(subnet, Subnet)
        self.assertEqual(str(subnet.prefix.prefix), "10.99.0.0/24")
        self.assertEqual(subnet.prefix, Prefix.objects.get(prefix="10.99.0.0/24"))
        self.assertIsNone(subnet.shared_network)

        # Pool shares the IPAM IPRange.
        pool = Pool.objects.get(subnet=subnet)
        self.assertEqual(pool.ip_range, IPRange.objects.get(start_address="10.99.0.10/24"))

        # Reservation shares the same IPAddress (status reserved) + MACAddress the sync made.
        res = HostReservation.objects.get(subnet=subnet)
        shared_ip = IPAddress.objects.get(address="10.99.0.50/24")
        self.assertEqual(res.ipv4_address, shared_ip)
        self.assertEqual(res.hostname, "res-host")
        self.assertEqual(res.hw_address, MACAddress.objects.get(mac_address="aa:bb:cc:dd:ee:01"))

    def test_v6_import_uses_ipv6_addresses_m2m(self):
        from ipam.models import IPAddress

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = _conf_v6()
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 6), _reservation_snapshot(conf, 6)
        )
        self.assertEqual(summary.errors, 0, summary.warnings)

        subnet = Subnet.objects.get(prefix__prefix="2001:db8:99::/64")
        res = HostReservation.objects.get(subnet=subnet)
        self.assertEqual(res.duid, "01:02:03:04:05")
        self.assertIsNone(res.ipv4_address)
        self.assertIn(IPAddress.objects.get(address="2001:db8:99::50/64"), res.ipv6_addresses.all())

    # ── the subnet_id decoupling (decision 5) ────────────────────────────────

    def test_dualstack_v4_and_v6_subnet_id_1_both_import_without_collision(self):
        from netbox_kea.models import KeaDhcpLink

        conf4 = _conf_v4()
        conf6 = _conf_v6()
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf4, 4), _reservation_snapshot(conf4, 4))
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf6, 6), _reservation_snapshot(conf6, 6))

        link4 = KeaDhcpLink.objects.get(server=self.server, family=4, kind="subnet", kea_subnet_id=1)
        link6 = KeaDhcpLink.objects.get(server=self.server, family=6, kind="subnet", kea_subnet_id=1)
        # Same Kea subnet-id (1) for both families, but distinct plugin Subnets +
        # distinct globally-unique plugin subnet_ids — no UniqueConstraint collision.
        self.assertNotEqual(link4.object_id, link6.object_id)
        self.assertNotEqual(link4.sys4_object.subnet_id, link6.sys4_object.subnet_id)

    # ── idempotency ──────────────────────────────────────────────────────────

    def test_reimport_is_idempotent(self):
        from netbox_kea.models import KeaDhcpLink

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = _conf_v4()
        snapshot = _reservation_snapshot(conf, 4)
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4), snapshot)
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4), snapshot)

        self.assertEqual(second.subnets_created, 0)
        self.assertEqual(second.pools_created, 0)
        self.assertEqual(second.reservations_created, 0)
        self.assertEqual(
            KeaDhcpLink.objects.filter(server=self.server, family=4, kind="subnet", kea_subnet_id=1).count(), 1
        )
        self.assertEqual(Subnet.objects.filter(prefix__prefix="10.99.0.0/24").count(), 1)
        self.assertEqual(Pool.objects.count(), 1)
        self.assertEqual(HostReservation.objects.count(), 1)

    def test_subnet_with_host_bits_reimports_onto_one_canonical_prefix(self):
        from ipam.models import Prefix

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        conf = {"subnet4": [{"id": 1, "subnet": "198.18.1.5/24", "pools": [{"pool": "198.18.1.10-198.18.1.20"}]}]}

        first = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))

        self.assertEqual((first.errors, second.errors), (0, 0), first.warnings + second.warnings)
        prefix = Prefix.objects.get(prefix="198.18.1.0/24", vrf=None)
        self.assertEqual(Prefix.objects.filter(prefix__net_contains_or_equals="198.18.1.0/24").count(), 1)
        subnet = Subnet.objects.get()
        self.assertEqual(subnet.prefix_id, prefix.pk)
        pool = Pool.objects.get(subnet=subnet)
        self.assertEqual(str(pool.ip_range.start_address), "198.18.1.10/24")
        self.assertEqual(str(pool.ip_range.end_address), "198.18.1.20/24")
        self.assertEqual((first.pools_created, second.pools_created), (1, 0))

    # ── per-item savepoints ──────────────────────────────────────────────────

    def test_subnet_database_error_is_counted_and_later_subnets_import(self):
        from netbox_kea.models import KeaDhcpLink

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf = {
            "subnet4": [
                # PostgreSQL cannot store a NUL character, so this Subnet's INSERT fails in the driver.
                {"id": 1, "subnet": "10.97.1.0/24", "hostname-char-set": "[^a-z]\x00"},
                {"id": 2, "subnet": "10.97.2.0/24"},
            ]
        }

        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))

        self.assertEqual(summary.errors, 1, summary.warnings)
        self.assertEqual(summary.subnets_created, 1)
        self.assertIn("subnet 10.97.1.0/24 (id=1)", summary.warnings[0])
        link = KeaDhcpLink.objects.get(server=self.server, family=4, kind="subnet", kea_subnet_id=2)
        self.assertEqual(str(link.sys4_object.prefix.prefix), "10.97.2.0/24")
        self.assertFalse(
            KeaDhcpLink.objects.filter(server=self.server, family=4, kind="subnet", kea_subnet_id=1).exists()
        )
        self.assertEqual(Subnet.objects.count(), 1)

    def test_pool_range_sync_error_is_counted_and_later_pools_import(self):
        from ipam.models import IPRange
        from netaddr import IPNetwork

        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        for mask in (24, 25):
            IPRange.objects.create(
                start_address=IPNetwork(f"10.96.0.10/{mask}"), end_address=IPNetwork(f"10.96.0.20/{mask}")
            )
        conf = {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.96.0.0/24",
                    "pools": [{"pool": "10.96.0.10-10.96.0.20"}, {"pool": "10.96.0.110-10.96.0.120"}],
                }
            ]
        }

        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))

        self.assertEqual(summary.errors, 1, summary.warnings)
        self.assertEqual(summary.pools_created, 1)
        self.assertIn("pool 10.96.0.10-10.96.0.20 in 10.96.0.0/24", summary.warnings[0])
        pool = Pool.objects.get()
        self.assertEqual(str(pool.ip_range.start_address), "10.96.0.110/24")

    def test_unusable_pool_is_skipped_and_a_cidr_pool_imports(self):
        from ipam.models import IPRange

        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        conf = {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.95.0.0/24",
                    "pools": [{"pool": "10.95.1.10-10.95.1.20"}, {"pool": "bad"}, {"pool": "10.95.0.128/26"}],
                }
            ]
        }

        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.pools_created, 1)
        self.assertEqual(
            summary.warnings,
            [
                "pool 10.95.1.10-10.95.1.20 in 10.95.0.0/24: unusable range, skipped",
                "pool bad in 10.95.0.0/24: unusable range, skipped",
            ],
        )
        # One detail covers a range outside the Subnet and text that is not a range.
        self.assertEqual(
            {(entry.path, entry.detail) for entry in summary.entries if entry.reason == Reason.INVALID_KEA_DATA},
            {
                (f"Dhcp4/subnet4[id=1]/pools[pool={pool}]", "The range is not valid or not inside the Subnet.")
                for pool in ("10.95.1.10-10.95.1.20", "bad")
            },
        )
        self.assertFalse(IPRange.objects.filter(start_address__net_host="10.95.1.10").exists())
        pool = Pool.objects.get()
        self.assertEqual(str(pool.ip_range.start_address), "10.95.0.128/24")
        self.assertEqual(str(pool.ip_range.end_address), "10.95.0.191/24")

    # ── deferred reporting ────────────────────────────────────────────────────

    def test_shared_network_subnets_flattened_and_reported(self):
        conf = {
            "shared-networks": [
                {"name": "office", "subnet4": [{"id": 5, "subnet": "10.50.0.0/24"}]},
            ]
        }
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(summary.shared_networks_not_imported, 1)
        self.assertIn(
            not_written(
                4,
                Kind.SHARED_NETWORK,
                "Dhcp4/shared-networks[name=office]",
                Reason.NOT_IN_SCOPE,
                "Its values and DHCP Options are not imported. Its Subnets are imported without it.",
            ),
            summary.entries,
        )
        subnet = Subnet.objects.get(prefix__prefix="10.50.0.0/24")
        # Flattened onto the DHCPServer, not a (prefix-requiring) SharedNetwork.
        self.assertIsNotNone(subnet.dhcp_server)
        self.assertIsNone(subnet.shared_network)

    # ── per-object error isolation ───────────────────────────────────────────

    def test_bad_cidr_is_per_subnet_error_not_fatal(self):
        """One unparseable subnet CIDR is counted as an error; other subnets still import."""
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf = {
            "subnet4": [
                {"id": 1, "subnet": "not-a-cidr"},  # CIDR validation fails within this Subnet import
                {"id": 2, "subnet": "10.51.0.0/24"},
            ]
        }
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertGreaterEqual(summary.errors, 1)
        # The bad subnet did not abort the import: the good one is present.
        self.assertTrue(Subnet.objects.filter(prefix__prefix="10.51.0.0/24").exists())
        self.assertEqual(summary.subnets_created, 1)
        self.assertIn(
            not_written(4, Kind.SUBNET, "Dhcp4/subnet4[id=1]", Reason.WRITE_FAILED, "See server logs."),
            summary.entries,
        )

    def test_reservation_database_failure_does_not_stop_healthy_sibling(self):
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        common_duid = ":".join(["aa"] * 83)
        conf = {"subnet6": [{"id": 3, "subnet": "2001:db8:3::/64"}]}
        hosts = [
            {"subnet-id": 3, "duid": common_duid + ":01", "hostname": "first.example"},
            {"subnet-id": 3, "duid": common_duid + ":02", "hostname": "collision.example"},
            {"subnet-id": 3, "duid": "01:02:03", "hostname": "healthy.example"},
        ]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 6), _reservation_snapshot(conf, 6, hosts)
        )

        self.assertEqual(summary.errors, 1, summary.warnings)
        self.assertEqual(summary.reservations_created, 2)
        self.assertTrue(HostReservation.objects.filter(hostname="healthy.example").exists())

    # ── idempotency edge cases ────────────────────────────────────────────────

    def test_stale_link_is_relinked_not_collided(self):
        """A dangling KeaDhcpLink (its subnet deleted) is relinked on re-import."""
        from netbox_kea.models import KeaDhcpLink

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf = {"subnet4": [{"id": 1, "subnet": "10.52.0.0/24"}]}  # bare: deletable without children

        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        link = KeaDhcpLink.objects.get(server=self.server, family=4, kind="subnet", kea_subnet_id=1)
        old_pk = link.sys4_object.pk

        Subnet.objects.filter(pk=old_pk).delete()
        self.assertFalse(KeaDhcpLink.objects.filter(pk=link.pk).exists())
        # Recreate a dangling link from an installation without target cleanup.
        link = KeaDhcpLink.objects.create(
            server=self.server,
            family=4,
            kind="subnet",
            kea_subnet_id=1,
            object_type_id=link.object_type_id,
            object_id=old_pk,
        )
        self.assertIsNone(link.sys4_object)

        # Re-import must relink the stale identity row, not violate the
        # keadhcplink_unique_subnet_identity constraint by creating a duplicate.
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(summary.errors, 0, summary.warnings)
        links = KeaDhcpLink.objects.filter(server=self.server, family=4, kind="subnet", kea_subnet_id=1)
        self.assertEqual(links.count(), 1)
        new_subnet = links.first().sys4_object
        self.assertIsNotNone(new_subnet)
        self.assertNotEqual(new_subnet.pk, old_pk)

    def test_reimport_clears_dropped_ipv6_addresses(self):
        """Re-importing a v6 reservation that lost its addresses clears the stale M2M relations."""
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        with_addrs = {
            "subnet6": [
                {
                    "id": 4,
                    "subnet": "2001:db8:53::/64",
                    "reservations": [
                        {
                            "duid": "0a:0b:0c",
                            "ip-addresses": ["2001:db8:53::10", "2001:db8:53::11"],
                            "hostname": "v6r",
                        }
                    ],
                }
            ]
        }
        self.adapter.import_server_config(
            self.server, parse_dhcp_config(with_addrs, 6), _reservation_snapshot(with_addrs, 6)
        )
        res = HostReservation.objects.get(hostname="v6r")
        self.assertEqual(res.ipv6_addresses.count(), 2)

        without_addrs = {
            "subnet6": [
                {
                    "id": 4,
                    "subnet": "2001:db8:53::/64",
                    "reservations": [{"duid": "0a:0b:0c", "ip-addresses": [], "hostname": "v6r"}],
                }
            ]
        }
        self.adapter.import_server_config(
            self.server, parse_dhcp_config(without_addrs, 6), _reservation_snapshot(without_addrs, 6)
        )
        res.refresh_from_db()
        self.assertEqual(res.ipv6_addresses.count(), 0)


@tag("dhcp_plugin")
class DhcpPluginOptionImportTest(TestCase):
    """Importing Kea ``option-data`` into netbox_dhcp ``Option`` rows (real ORM + defs)."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name=f"kea-opt-{timezone.now().timestamp()}")
        from netbox_kea.integrations import dhcp_plugin

        self.adapter = dhcp_plugin

    def _ct(self, model):
        from django.contrib.contenttypes.models import ContentType

        return ContentType.objects.get_for_model(model)

    def test_standard_subnet_option_binds_to_shipped_definition(self):
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        conf = {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.21.0.0/24",
                    "option-data": [
                        {"code": 3, "name": "routers", "data": "10.21.0.1", "space": "dhcp4", "always-send": True}
                    ],
                }
            ]
        }
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.options_created, 1, summary.warnings)
        self.assertEqual(summary.options_skipped, 0, summary.warnings)

        subnet = Subnet.objects.get(prefix__prefix="10.21.0.0/24")
        opt = Option.objects.get(assigned_object_type=self._ct(Subnet), assigned_object_id=subnet.pk)
        self.assertEqual(opt.definition.code, 3)
        self.assertTrue(opt.definition.standard)  # bound to the sys4-shipped standard def
        self.assertEqual(opt.data, "10.21.0.1")
        self.assertEqual(opt.send_option, "always-send")

    def test_global_option_assigned_to_dhcp_server(self):
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        conf = {
            "option-data": [{"code": 6, "name": "domain-name-servers", "data": "1.1.1.1", "space": "dhcp4"}],
            "subnet4": [],
        }
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(summary.options_created, 1, summary.warnings)
        srv = DHCPServer.objects.get(name=self.server.name)
        opt = Option.objects.get(assigned_object_type=self._ct(DHCPServer), assigned_object_id=srv.pk)
        self.assertEqual(opt.definition.code, 6)

    def test_custom_option_def_is_created_and_bound(self):
        OptionDefinition = apps.get_model(DHCP_PLUGIN, "OptionDefinition")
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        conf = {
            "option-def": [{"code": 224, "name": "my-custom", "space": "dhcp4", "type": "string"}],
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.22.0.0/24",
                    "option-data": [{"code": 224, "name": "my-custom", "data": "hello", "space": "dhcp4"}],
                }
            ],
        }
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.option_defs_created, 1, summary.warnings)
        self.assertEqual(summary.options_created, 1, summary.warnings)

        definition = OptionDefinition.objects.get(code=224, standard=False)
        self.assertEqual(definition.name, "my-custom")
        self.assertEqual(definition.dhcp_server.name, self.server.name)
        self.assertTrue(Option.objects.filter(definition=definition).exists())

    def test_unresolvable_option_is_skipped_not_fatal(self):
        # Custom code with no option-def → no definition to bind → skipped, import still ok.
        conf = {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.23.0.0/24",
                    "option-data": [{"code": 231, "data": "x", "space": "dhcp4"}],
                }
            ]
        }
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(summary.errors, 0)
        self.assertEqual(summary.options_created, 0)
        self.assertEqual(summary.options_skipped, 1, summary.warnings)
        self.assertEqual(summary.subnets_created, 1)  # subnet still imported

    def test_invalid_option_data_is_named_and_does_not_stop_other_option_imports(self):
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        invalid = {
            "code": 3,
            "name": "routers",
            "data": "not-an-address",
            "csv-format": True,
            "client-classes": ["voip"],
        }
        conf = {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "198.18.9.0/24",
                    "option-data": [invalid, {"code": 6, "data": "198.18.9.53", "csv-format": True}],
                }
            ],
        }
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.options_skipped, 1, summary.warnings)
        self.assertEqual(summary.options_created, 1, summary.warnings)
        self.assertEqual(summary.subnets_created, 1, summary.warnings)
        self.assertEqual(list(Option.objects.values_list("data", flat=True)), ["198.18.9.53"])
        warning = "\n".join(summary.warnings)
        self.assertIn(str(option_identity(parse_dhcp_option(invalid), 4)), warning)
        self.assertIn("not a valid IPv4 address", warning)

    def test_reimport_updates_option_not_duplicated(self):
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        conf = {
            "subnet4": [
                {"id": 1, "subnet": "10.24.0.0/24", "option-data": [{"code": 3, "data": "10.24.0.1", "space": "dhcp4"}]}
            ]
        }
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        conf["subnet4"][0]["option-data"][0]["data"] = "10.24.0.254"
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))

        self.assertEqual(second.options_created, 0)
        self.assertEqual(second.options_updated, 1)
        subnet = Subnet.objects.get(prefix__prefix="10.24.0.0/24")
        opt = Option.objects.get(assigned_object_type=self._ct(Subnet), assigned_object_id=subnet.pk)
        self.assertEqual(opt.data, "10.24.0.254")


@tag("dhcp_plugin")
class DhcpPluginTuningImportTest(TestCase):
    """Tuning fields land on DHCPServer/Subnet with parent-diff suppression (real ORM)."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name=f"kea-tune-{timezone.now().timestamp()}")
        from netbox_kea.integrations import dhcp_plugin

        self.adapter = dhcp_plugin

    def _import(self, conf: dict) -> None:
        """Import *conf* through the live read of the DHCP plugin sync."""
        from netbox_kea.views.dhcp_plugin_sync import _fetch_config_intent

        with stub_kea({"config-get": {"result": 0, "arguments": {"Dhcp4": conf}}}):
            intent = _fetch_config_intent(self.server, 4)
        assert isinstance(intent, ServerConfigIntent)
        self.adapter.import_server_config(self.server, intent)

    def test_global_settings_applied_to_dhcp_server(self):
        from decimal import Decimal

        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        conf = {
            "valid-lifetime": 3600,
            "renew-timer": 900,
            "allocator": "iterative",
            "t1-percent": 0.5,
            "decline-probation-period": 86400,
            "ddns-replace-client-name": "when-not-present",
            "server-id": {"type": "LLT", "enterprise-id": 0},
            "host-reservation-identifiers": ["hw-address", "duid", "circuit-id", "client-id", "flex-id"],
            "subnet4": [],
        }
        self._import(conf)

        srv = DHCPServer.objects.get(name=self.server.name)
        self.assertEqual(srv.valid_lifetime, 3600)
        self.assertEqual(srv.renew_timer, 900)
        self.assertEqual(srv.allocator, "iterative")
        self.assertEqual(srv.t1_percent, Decimal("0.5"))
        self.assertEqual(srv.decline_probation_period, 86400)
        # hyphenated Kea value normalized to the plugin's underscored choice
        self.assertEqual(srv.ddns_replace_client_name, "when_not_present")
        # server-id dict reduced to its type
        self.assertEqual(srv.server_id, "LLT")
        # The plugin's choice set has no flex-id.
        self.assertEqual(srv.host_reservation_identifiers, ["hw-address", "duid", "circuit-id", "client-id"])

    def test_absent_host_reservation_identifiers_keep_the_stored_value(self):
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        self._import({"host-reservation-identifiers": ["duid"], "subnet4": []})
        self._import({"valid-lifetime": 3600, "subnet4": []})
        self.assertEqual(DHCPServer.objects.get(name=self.server.name).host_reservation_identifiers, ["duid"])

    def test_subnet_value_equal_to_global_is_suppressed(self):
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf = {
            "valid-lifetime": 3600,
            "subnet4": [
                # subnet repeats the (inherited) global value — must NOT be stored on the subnet
                {"id": 1, "subnet": "10.30.0.0/24", "valid-lifetime": 3600},
            ],
        }
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        subnet = Subnet.objects.get(prefix__prefix="10.30.0.0/24")
        self.assertIsNone(subnet.valid_lifetime)  # inherits from the DHCPServer parent

    def test_subnet_value_differing_from_global_is_stored(self):
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf = {
            "valid-lifetime": 3600,
            "subnet4": [
                {"id": 1, "subnet": "10.31.0.0/24", "valid-lifetime": 7200, "relay": {"ip-addresses": ["10.31.0.3"]}},
            ],
        }
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        subnet = Subnet.objects.get(prefix__prefix="10.31.0.0/24")
        self.assertEqual(subnet.valid_lifetime, 7200)  # genuine per-subnet override stored
        self.assertEqual(subnet.relay, "10.31.0.3")  # relay dict flattened to CSV

    def test_v6_style_decimal_does_not_raise(self):
        # 0.8 has no exact float repr; the str-based Decimal coercion must keep it clean.
        from decimal import Decimal

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf = {
            "t2-percent": 0.5,
            "subnet6": [{"id": 1, "subnet": "2001:db8:30::/64", "t2-percent": 0.8}],
        }
        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 6))
        self.assertEqual(summary.errors, 0, summary.warnings)
        subnet = Subnet.objects.get(prefix__prefix="2001:db8:30::/64")
        self.assertEqual(subnet.t2_percent, Decimal("0.8"))

    def test_dualstack_global_first_family_wins_shared_fields(self):
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        # v4 sets shared valid-lifetime; v6 supplies preferred-lifetime and a *different*
        # valid-lifetime that must NOT clobber v4's (single DHCPServer spans both).
        self.adapter.import_server_config(self.server, parse_dhcp_config({"valid-lifetime": 3600, "subnet4": []}, 4))
        self.adapter.import_server_config(
            self.server, parse_dhcp_config({"valid-lifetime": 4000, "preferred-lifetime": 3000, "subnet6": []}, 6)
        )
        srv = DHCPServer.objects.get(name=self.server.name)
        self.assertEqual(srv.valid_lifetime, 3600)  # v4 (first) wins the shared field
        self.assertEqual(srv.preferred_lifetime, 3000)  # v6 fills the gap

    def test_tuning_reimport_is_idempotent(self):
        conf = {
            "valid-lifetime": 3600,
            "subnet4": [{"id": 1, "subnet": "10.32.0.0/24", "valid-lifetime": 7200}],
        }
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(second.subnets_created, 0)
        self.assertEqual(second.subnets_updated, 0)  # nothing changed → not reported as updated

    def test_subnet_override_cleared_when_value_returns_to_inherited(self):
        # Finding 1: a removed Kea override must not linger as stale data on re-import.
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf1 = {"valid-lifetime": 3600, "subnet4": [{"id": 7, "subnet": "10.42.0.0/24", "valid-lifetime": 7200}]}
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf1, 4))
        subnet = Subnet.objects.get(prefix__prefix="10.42.0.0/24")
        self.assertEqual(subnet.valid_lifetime, 7200)

        # Override removed in Kea (subnet value now equals the global) → must be cleared.
        conf2 = {"valid-lifetime": 3600, "subnet4": [{"id": 7, "subnet": "10.42.0.0/24", "valid-lifetime": 3600}]}
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf2, 4))
        subnet.refresh_from_db()
        self.assertIsNone(subnet.valid_lifetime)  # inherits again, not stale 7200
        self.assertEqual(second.subnets_updated, 1)

    def test_global_setting_change_resyncs_on_reimport(self):
        # Finding 2: a changed global value must re-sync (was write-once before).
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        self.adapter.import_server_config(self.server, parse_dhcp_config({"valid-lifetime": 3600, "subnet4": []}, 4))
        self.adapter.import_server_config(self.server, parse_dhcp_config({"valid-lifetime": 7200, "subnet4": []}, 4))
        srv = DHCPServer.objects.get(name=self.server.name)
        self.assertEqual(srv.valid_lifetime, 7200)

    def test_failed_global_save_does_not_clear_a_subnet_override(self):
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")
        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        conf1 = {"valid-lifetime": 3600, "subnet4": [{"id": 8, "subnet": "10.43.0.0/24", "valid-lifetime": 7200}]}
        first = self.adapter.import_server_config(self.server, parse_dhcp_config(conf1, 4))
        self.assertEqual(first.errors, 0, first.warnings)

        # A uint32 Kea lifetime is above the PostgreSQL integer maximum, so both saves fail in the driver.
        uint32_max = 4294967295
        conf2 = {
            "valid-lifetime": uint32_max,
            "subnet4": [{"id": 8, "subnet": "10.43.0.0/24", "valid-lifetime": uint32_max}],
        }
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf2, 4))

        self.assertEqual(DHCPServer.objects.get(name=self.server.name).valid_lifetime, 3600)
        subnet = Subnet.objects.get(prefix__prefix="10.43.0.0/24")
        self.assertEqual(subnet.valid_lifetime, 7200, "subnet override was cleared to inherit the stale DB global")
        self.assertEqual(second.errors, 2, second.warnings)
        self.assertIn("DHCPServer settings", second.warnings[0])
        self.assertIn("subnet 10.43.0.0/24 (id=8)", second.warnings[1])

    def test_failed_global_save_on_a_new_dhcp_server_has_only_the_failure_entry(self):
        from netbox_kea.integrations.dhcp_import_report import Kind, Reason

        # A uint32 Kea lifetime is above the PostgreSQL integer maximum, so the settings save fails in the driver.
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config({"valid-lifetime": 4294967295, "subnet4": []}, 4)
        )

        self.assertEqual(
            [(entry.path, entry.reason) for entry in summary.entries if entry.kind == Kind.SERVER],
            [("Dhcp4", Reason.WRITE_FAILED)],
        )


@tag("dhcp_plugin")
class DhcpPluginClientClassImportTest(TestCase):
    """Importing Kea ``client-classes`` into netbox_dhcp ``ClientClass`` rows."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name=f"kea-cc-{timezone.now().timestamp()}")
        from netbox_kea.integrations import dhcp_plugin

        self.adapter = dhcp_plugin

    def _conf(self):
        return {
            "next-server": "0.0.0.0",  # noqa: S104 - Kea sentinel value, not a bind address
            "client-classes": [
                {
                    "name": "voip",
                    "test": "substring(option[60].hex,0,6) == 'Aastra'",
                    "next-server": "192.0.2.254",
                    "boot-file-name": "/dev/null",
                    "server-hostname": "hal9000",
                    "option-data": [{"code": 3, "name": "routers", "data": "10.0.0.1", "space": "dhcp4"}],
                }
            ],
            "subnet4": [],
        }

    def test_client_class_created_with_settings_and_options(self):
        from django.contrib.contenttypes.models import ContentType

        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")

        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(self._conf(), 4))
        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.client_classes_created, 1)
        self.assertEqual(summary.options_created, 1)  # the class's routers option

        cc = ClientClass.objects.get(name=f"{self.server.name}: voip")
        self.assertEqual(cc.dhcp_server, DHCPServer.objects.get(name=self.server.name))
        self.assertEqual(cc.test, "substring(option[60].hex,0,6) == 'Aastra'")
        # BOOTP settings differ from the server baseline → stored on the class.
        self.assertEqual(cc.next_server, "192.0.2.254")
        self.assertEqual(cc.boot_file_name, "/dev/null")
        self.assertEqual(cc.server_hostname, "hal9000")
        # The class's option was imported and assigned to the ClientClass.
        ct = ContentType.objects.get_for_model(ClientClass)
        self.assertTrue(Option.objects.filter(assigned_object_type=ct, assigned_object_id=cc.pk).exists())

    def test_client_class_name_is_namespaced_to_server(self):
        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        self.adapter.import_server_config(self.server, parse_dhcp_config(self._conf(), 4))
        # Namespaced so two servers' identically-named Kea classes don't collide.
        self.assertTrue(ClientClass.objects.filter(name=f"{self.server.name}: voip").exists())
        self.assertFalse(ClientClass.objects.filter(name="voip").exists())

    def test_reimport_is_idempotent(self):
        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        self.adapter.import_server_config(self.server, parse_dhcp_config(self._conf(), 4))
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(self._conf(), 4))
        self.assertEqual(second.client_classes_created, 0)
        self.assertEqual(second.client_classes_updated, 0)
        self.assertEqual(ClientClass.objects.filter(name=f"{self.server.name}: voip").count(), 1)

    def test_changed_test_expression_reported_as_updated(self):
        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        conf = self._conf()
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        conf["client-classes"][0]["test"] = "substring(option[60].hex,0,4) == 'Cisco'"
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))
        self.assertEqual(second.client_classes_updated, 1)
        cc = ClientClass.objects.get(name=f"{self.server.name}: voip")
        self.assertEqual(cc.test, "substring(option[60].hex,0,4) == 'Cisco'")


def _mapped_conf():
    """Return a DHCPv4 configuration with one row of each mapped kind that the import writes."""
    return {
        "option-def": [{"name": "site-code", "code": 222, "type": "uint8", "space": "dhcp4"}],
        "client-classes": [
            {"name": "voip", "test": "option[60].hex == 'voip'", "option-data": [{"code": 222, "data": "7"}]}
        ],
        "subnet4": [
            {
                "id": 1,
                "subnet": "10.98.0.0/24",
                "pools": [{"pool": "10.98.0.10-10.98.0.100", "option-data": [{"code": 222, "data": "5"}]}],
                "reservations": [
                    {"hw-address": "aa:bb:cc:dd:ee:98", "ip-address": "10.98.0.150", "hostname": "mapped"}
                ],
            }
        ],
    }


@tag("dhcp_plugin")
class DhcpPluginMappingImportTest(TestCase):
    """Each imported Pool, In-Subnet Reservation, client class and custom Option Definition has a mapping."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        from netbox_kea.integrations import dhcp_plugin

        self.server = _make_db_server(name=f"kea-mapped-{timezone.now().timestamp()}")
        self.adapter = dhcp_plugin
        self.conf = _mapped_conf()

    def _import(self):
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(self.conf, 4), _reservation_snapshot(self.conf, 4)
        )
        self.assertEqual(summary.errors, 0, summary.warnings)
        return summary

    def _rows(self) -> dict:
        """Return the imported row of each kind, by the source columns it must map to."""
        model = partial(apps.get_model, DHCP_PLUGIN)
        subnet = model("Subnet").objects.get(dhcp_server__name=self.server.name, prefix__prefix="10.98.0.0/24")
        return {
            ("subnet", 1, None): subnet,
            ("pool", 1, "10.98.0.10-10.98.0.100"): model("Pool").objects.get(subnet=subnet),
            ("reservation", 1, "hw-address:aa:bb:cc:dd:ee:98"): model("HostReservation").objects.get(subnet=subnet),
            ("client_class", None, "voip"): model("ClientClass").objects.get(dhcp_server__name=self.server.name),
            ("option_definition", None, "dhcp4:222"): model("OptionDefinition").objects.get(
                standard=False, dhcp_server__name=self.server.name
            ),
        }

    def _assert_one_mapping_each(self, rows: dict) -> dict:
        from netbox_kea.models import KeaDhcpLink

        links = {}
        for source, row in rows.items():
            with self.subTest(source=source):
                mapped = KeaDhcpLink.objects.filter(
                    object_type=ContentType.objects.get_for_model(row), object_id=row.pk
                )
                self.assertEqual(
                    list(mapped.values_list("server", "family", "kind", "kea_subnet_id", "kea_identity")),
                    [(self.server.pk, 4, *source)],
                )
                links[source] = mapped.get().pk
        self.assertEqual(KeaDhcpLink.objects.filter(server=self.server).count(), len(rows))
        return links

    def test_each_imported_row_has_one_mapping_to_its_kea_source(self):
        self._import()

        self._assert_one_mapping_each(self._rows())

    def test_a_second_import_finds_every_row_through_its_mapping(self):
        from netbox_kea.integrations.dhcp_import_report import Outcome

        self._import()
        rows = {source: row.pk for source, row in self._rows().items()}
        links = self._assert_one_mapping_each(self._rows())

        second = self._import()

        changed = (Outcome.CREATED, Outcome.UPDATED)
        self.assertEqual([entry for entry in second.entries if entry.outcome in changed], [])
        self.assertEqual({source: row.pk for source, row in self._rows().items()}, rows)
        self.assertEqual(self._assert_one_mapping_each(self._rows()), links)

    def test_a_renamed_and_changed_row_keeps_its_mapping_and_the_next_import_updates_it(self):
        """Each change takes the row out of its structural match, so only the mapping can find it again."""
        from ipam.models import IPRange, Prefix
        from netaddr import IPNetwork

        self._import()
        rows = self._rows()
        pool_range = rows[("pool", 1, "10.98.0.10-10.98.0.100")].ip_range_id
        reservation_subnet = rows[("reservation", 1, "hw-address:aa:bb:cc:dd:ee:98")].subnet_id
        other_subnet = apps.get_model(DHCP_PLUGIN, "Subnet").objects.create(
            name="operator subnet",
            prefix=Prefix.objects.create(prefix=IPNetwork("10.98.5.0/24")),
            dhcp_server=rows[("subnet", 1, None)].dhcp_server,
        )
        changed = {
            ("pool", 1, "10.98.0.10-10.98.0.100"): {
                "ip_range": IPRange.objects.create(
                    start_address=IPNetwork("10.98.0.200/24"), end_address=IPNetwork("10.98.0.210/24")
                )
            },
            ("reservation", 1, "hw-address:aa:bb:cc:dd:ee:98"): {"subnet": other_subnet},
            ("option_definition", None, "dhcp4:222"): {"code": 223},
        }
        for source, row in rows.items():
            row.snapshot()
            row.name = f"renamed {row.pk}"
            for name, value in changed.get(source, {}).items():
                setattr(row, name, value)
            row.save()
        self.conf["option-def"][0]["type"] = "uint16"
        self.conf["client-classes"][0]["test"] = "option[60].hex == 'phone'"
        self.conf["subnet4"][0]["reservations"][0]["hostname"] = "renamed-host"
        self.conf["subnet4"][0]["pools"][0]["option-data"][0]["data"] = "6"

        summary = self._import()

        current = self._rows()
        self.assertEqual({source: row.pk for source, row in current.items()}, {s: r.pk for s, r in rows.items()})
        for source, row in current.items():
            with self.subTest(source=source):
                self.assertEqual(row.name, f"renamed {row.pk}")
        definition = current[("option_definition", None, "dhcp4:222")]
        self.assertEqual((definition.space, definition.code, definition.type), ("dhcp4", 222, "uint16"))
        self.assertEqual(current[("client_class", None, "voip")].test, "option[60].hex == 'phone'")
        reservation = current[("reservation", 1, "hw-address:aa:bb:cc:dd:ee:98")]
        self.assertEqual((reservation.subnet_id, reservation.hostname), (reservation_subnet, "renamed-host"))
        pool = current[("pool", 1, "10.98.0.10-10.98.0.100")]
        self.assertEqual(pool.ip_range_id, pool_range)
        self.assertEqual(list(pool.options.values_list("data", flat=True)), ["6"])
        self.assertEqual(
            {(entry.kind, entry.outcome.value) for entry in summary.entries if entry.kind != Kind.OPTION},
            {
                (Kind.OPTION_DEFINITION, "updated"),
                (Kind.CLIENT_CLASS, "updated"),
                (Kind.POOL, "updated"),
                (Kind.RESERVATION, "updated"),
            },
        )
        self._assert_one_mapping_each(current)

    def test_a_changed_definition_code_is_restored_before_options_bind_to_it(self):
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        self._import()
        definition = self._rows()[("option_definition", None, "dhcp4:222")]
        definition.snapshot()
        definition.code = 223
        definition.save()

        self._import()

        definition.refresh_from_db()
        self.assertEqual((definition.space, definition.code), ("dhcp4", 222))
        self.assertEqual(
            sorted(Option.objects.filter(definition=definition).values_list("data", flat=True)), ["5", "7"]
        )
        self.assertEqual(self._rows()[("option_definition", None, "dhcp4:222")].pk, definition.pk)

    def test_a_definition_moved_to_a_client_class_returns_to_its_dhcp_server(self):
        self._import()
        rows = self._rows()
        definition = rows[("option_definition", None, "dhcp4:222")]
        dhcp_server_id = definition.dhcp_server_id
        definition.snapshot()
        definition.dhcp_server = None
        definition.client_class = rows[("client_class", None, "voip")]
        definition.save()

        summary = self._import()

        # summary.errors leaves out a failed definition, so read its entries.
        self.assertEqual(summary.count(Kind.OPTION_DEFINITION, Reason.WRITE_FAILED), 0, summary.warnings)
        self.assertEqual(summary.count(Kind.OPTION, Reason.PARENT_NOT_IMPORTED), 0, summary.warnings)
        definition.refresh_from_db()
        self.assertEqual((definition.dhcp_server_id, definition.client_class_id), (dhcp_server_id, None))

    def test_a_moved_in_subnet_reservation_returns_to_its_subnet(self):
        from netbox_kea.dhcp_mapping_lifecycle import mapped_target
        from netbox_kea.integrations.dhcp_import_plan import MappingSource
        from netbox_kea.models import KeaDhcpLink

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        conf = {
            "subnet4": [
                {"id": 1, "subnet": "10.96.0.0/24", "reservations": [{"duid": "01:02:03:96"}]},
                {"id": 2, "subnet": "10.96.1.0/24"},
            ]
        }
        first = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4)
        )
        self.assertEqual(first.errors, 0, first.warnings)
        home, other = (mapped_target(self.server, 4, MappingSource.subnet(subnet_id)) for subnet_id in (1, 2))
        moved = HostReservation.objects.get(duid="01:02:03:96")
        moved.snapshot()
        moved.subnet = other
        moved.name = "moved by the operator"
        moved.save()

        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        (restored,) = HostReservation.objects.filter(duid="01:02:03:96")
        self.assertEqual((restored.pk, restored.subnet_id, restored.dhcp_server_id), (moved.pk, home.pk, None))
        self.assertEqual(restored.name, "moved by the operator")
        self.assertEqual(summary.reservations_updated, 1)
        self.assertEqual(
            list(
                KeaDhcpLink.objects.filter(kind="reservation", server=self.server).values_list(
                    "object_id", "kea_subnet_id"
                )
            ),
            [(moved.pk, 1)],
        )

    def test_a_custom_definition_of_both_families_is_unsupported_for_the_second_family(self):
        """One DHCPServer holds both families, and the plugin holds one custom definition per space and code there."""
        from netbox_kea.integrations.dhcp_import_report import Outcome, Reason
        from netbox_kea.models import KeaDhcpLink

        OptionDefinition = apps.get_model(DHCP_PLUGIN, "OptionDefinition")
        Option = apps.get_model(DHCP_PLUGIN, "Option")
        space = "vendor-specific-options-space"

        def conf(family):
            return {
                "option-def": [{"name": f"vendor-v{family}", "code": 250, "type": "uint8", "space": space}],
                "option-data": [{"code": 250, "space": space, "data": str(family)}],
                f"subnet{family}": [],
            }

        v4 = self.adapter.import_server_config(self.server, parse_dhcp_config(conf(4), 4))
        self.assertEqual(v4.option_defs_created, 1, v4.warnings)
        for _ in range(2):  # the next run reports the same limit and writes nothing
            v6 = self.adapter.import_server_config(self.server, parse_dhcp_config(conf(6), 6))
            self.assertEqual(v6.errors, 0, v6.warnings)
            entries = {entry.kind: entry for entry in v6.entries if entry.kind in (Kind.OPTION_DEFINITION, Kind.OPTION)}
            self.assertEqual(
                {kind: (entry.outcome, entry.reason) for kind, entry in entries.items()},
                {
                    Kind.OPTION_DEFINITION: (Outcome.UNSUPPORTED, Reason.PLUGIN_GAP),
                    Kind.OPTION: (Outcome.UNSUPPORTED, Reason.PLUGIN_GAP),
                },
            )
            self.assertIn("#94", entries[Kind.OPTION_DEFINITION].detail)
            self.assertIn(f"{space}:250", entries[Kind.OPTION].detail)

        (definition,) = OptionDefinition.objects.filter(standard=False, dhcp_server__name=self.server.name)
        self.assertEqual((definition.family, definition.name), (4, "vendor-v4"))
        self.assertEqual(list(Option.objects.filter(definition=definition).values_list("data", flat=True)), ["4"])
        self.assertEqual(
            list(KeaDhcpLink.objects.filter(server=self.server).values_list("family", "kind", "kea_identity")),
            [(4, "option_definition", f"{space}:250")],
        )

    def _seed_released_import(self) -> dict:
        """Write the rows that the importer before #93 wrote, with the kinds that migration 0029 gives its mappings.

        Rows match by structure, so they carry the names of that importer. Only the Subnet and the Global
        Reservation have a mapping. Both families shared one client class row.
        """
        from netbox_kea.ipam_reconciliation import PoolClaim, SubnetClaim, claim
        from netbox_kea.models import KeaDhcpLink
        from netbox_kea.pools import parse_pool

        model = partial(apps.get_model, DHCP_PLUGIN)
        network = ipaddress.ip_network("10.95.0.0/24")
        pool = parse_pool("10.95.0.10-10.95.0.100", network)
        prefix = claim(self.server, 4, [SubnetClaim(network)], force=False).prefixes[str(network)].prefix
        ip_range = claim(self.server, 4, [PoolClaim(pool, network)], force=False).ranges[f"{pool.start} - {pool.end}"]
        dhcp_server = model("DHCPServer").objects.create(
            name=self.server.name, description="Imported from Kea by netbox-kea"
        )
        subnet = model("Subnet").objects.create(
            name=f"{self.server.name} DHCPv4 subnet 1", prefix=prefix, dhcp_server=dhcp_server
        )
        rows = {
            ("subnet", 1, None): subnet,
            ("pool", 1, "10.95.0.10-10.95.0.100"): model("Pool").objects.create(
                name=f"{subnet.name} pool 10.95.0.10-10.95.0.100", subnet=subnet, ip_range=ip_range.ip_range
            ),
            ("reservation", 1, "duid:01:02:03:95"): model("HostReservation").objects.create(
                name=f"{subnet.name} duid:01:02:03:95", subnet=subnet, duid="01:02:03:95"
            ),
            ("reservation", None, "duid:01:02:03:94"): model("HostReservation").objects.create(
                name=f"{self.server.name} DHCPv4 duid:01:02:03:94", dhcp_server=dhcp_server, duid="01:02:03:94"
            ),
            ("client_class", None, "voip"): model("ClientClass").objects.create(
                name=f"{self.server.name}: voip", dhcp_server=dhcp_server, test="family 6"
            ),
            ("option_definition", None, "dhcp4:222"): model("OptionDefinition").objects.create(
                name="site-code", family=4, space="dhcp4", code=222, type="uint8", dhcp_server=dhcp_server
            ),
        }
        KeaDhcpLink.objects.create(server=self.server, family=4, kind="subnet", kea_subnet_id=1, sys4_object=subnet)
        KeaDhcpLink.objects.create(
            server=self.server,
            family=4,
            kind="reservation",
            kea_identity="duid:01:02:03:94",
            sys4_object=rows[("reservation", None, "duid:01:02:03:94")],
        )
        return rows

    def test_an_upgrade_adopts_the_rows_that_the_released_importer_wrote(self):
        from netbox_kea.integrations.dhcp_import_report import Outcome
        from netbox_kea.models import KeaDhcpLink

        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        rows = self._seed_released_import()
        conf4 = {
            "option-def": [{"name": "site-code", "code": 222, "type": "uint8", "space": "dhcp4"}],
            "client-classes": [{"name": "voip", "test": "family 4"}],
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.95.0.0/24",
                    "pools": [{"pool": "10.95.0.10-10.95.0.100", "option-data": [{"code": 222, "data": "5"}]}],
                }
            ],
        }
        hosts = [{"subnet-id": 1, "duid": "01:02:03:95"}, {"subnet-id": 0, "duid": "01:02:03:94"}]
        conf6 = {"client-classes": [{"name": "voip", "test": "family 6"}], "subnet6": []}

        def created(summary):
            self.assertEqual(summary.errors, 0, summary.warnings)
            return sorted(entry.kind.value for entry in summary.entries if entry.outcome == Outcome.CREATED)

        # The first run creates only what the released importer had not written: the Option and the class of DHCPv6.
        for expected4, expected6 in ((["option"], ["client_class"]), ([], [])):
            v4 = self.adapter.import_server_config(
                self.server, parse_dhcp_config(conf4, 4), _reservation_snapshot(conf4, 4, hosts)
            )
            v6 = self.adapter.import_server_config(self.server, parse_dhcp_config(conf6, 6))
            self.assertEqual((created(v4), created(v6)), (expected4, expected6))
            seen = {
                (link.kind, link.kea_subnet_id, link.kea_identity): link.object_id
                for link in KeaDhcpLink.objects.filter(server=self.server, family=4)
            }
            self.assertEqual(seen, {source: row.pk for source, row in rows.items()})

        classes = dict(ClientClass.objects.filter(dhcp_server__name=self.server.name).values_list("name", "test"))
        self.assertEqual(
            classes, {f"{self.server.name}: voip": "family 4", f"{self.server.name} DHCPv6: voip": "family 6"}
        )
        (v6_link,) = KeaDhcpLink.objects.filter(server=self.server, family=6)
        self.assertEqual(
            (v6_link.kind, v6_link.kea_identity, v6_link.object_id),
            ("client_class", "voip", ClientClass.objects.get(name=f"{self.server.name} DHCPv6: voip").pk),
        )
        for source, row in rows.items():
            with self.subTest(source=source):
                self.assertEqual(type(row).objects.filter(name=row.name).get().pk, row.pk)
        self.assertEqual(
            apps.get_model(DHCP_PLUGIN, "HostReservation").objects.filter(duid__startswith="01:02:03:9").count(), 2
        )

    def test_a_pool_of_a_subnet_without_a_kea_id_imports_without_a_mapping(self):
        from netbox_kea.models import KeaDhcpLink

        Pool = apps.get_model(DHCP_PLUGIN, "Pool")
        conf = {"subnet4": [{"subnet": "10.97.0.0/24", "pools": [{"pool": "10.97.0.10-10.97.0.20"}]}]}

        summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4))

        self.assertEqual((summary.errors, summary.subnets_created, summary.pools_created), (0, 1, 1), summary.warnings)
        self.assertEqual(Pool.objects.filter(subnet__dhcp_server__name=self.server.name).count(), 1)
        self.assertFalse(KeaDhcpLink.objects.filter(server=self.server).exists())

    def test_one_class_name_in_both_families_imports_two_rows(self):
        """One DHCPServer holds both families, so the class of the other family takes a family-qualified name."""
        from netbox_kea.models import KeaDhcpLink

        ClientClass = apps.get_model(DHCP_PLUGIN, "ClientClass")
        for family in (4, 6, 4, 6):
            conf = {"client-classes": [{"name": "voip", "test": f"family {family}"}], f"subnet{family}": []}
            summary = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, family))
            self.assertEqual(summary.errors, 0, summary.warnings)

        rows = {row.name: row.test for row in ClientClass.objects.filter(dhcp_server__name=self.server.name)}
        self.assertEqual(
            rows, {f"{self.server.name}: voip": "family 4", f"{self.server.name} DHCPv6: voip": "family 6"}
        )
        self.assertEqual(
            sorted(KeaDhcpLink.objects.filter(server=self.server).values_list("family", "kind", "kea_identity")),
            [(4, "client_class", "voip"), (6, "client_class", "voip")],
        )


@tag("dhcp_plugin")
class DhcpPluginReservationSnapshotImportTest(TestCase):
    """Typed Reservation Snapshots import into the matching plugin scope."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name=f"kea-pageres-{timezone.now().timestamp()}")
        from netbox_kea.integrations import dhcp_plugin

        self.adapter = dhcp_plugin

    def test_db_reservation_imported_into_linked_subnet(self):
        from ipam.models import IPAddress

        Subnet = apps.get_model(DHCP_PLUGIN, "Subnet")
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        # Subnet is in config-get; the reservation is ONLY in the hosts DB (subnet-id 7).
        conf = {"subnet4": [{"id": 7, "subnet": "10.40.0.0/24"}]}
        hosts = [{"subnet-id": 7, "hw-address": "aa:bb:cc:dd:ee:40", "ip-address": "10.40.0.50", "hostname": "db-host"}]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.reservations_created, 1, summary.warnings)
        subnet = Subnet.objects.get(prefix__prefix="10.40.0.0/24")
        res = HostReservation.objects.get(subnet=subnet)
        self.assertEqual(res.hostname, "db-host")
        # Shares the same IPAM IPAddress the reservation sync maintains.
        self.assertEqual(res.ipv4_address, IPAddress.objects.get(address="10.40.0.50/24"))

    def test_global_reservation_attached_to_dhcp_server(self):
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        DHCPServer = apps.get_model(DHCP_PLUGIN, "DHCPServer")

        conf = {"subnet4": []}
        hosts = [
            {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:00", "ip-address": "10.0.0.9", "hostname": "global-host"}
        ]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        res = HostReservation.objects.get(hostname="global-host")
        self.assertIsNone(res.subnet)
        self.assertEqual(res.dhcp_server, DHCPServer.objects.get(name=self.server.name))
        self.assertIsNone(res.ipv4_address)

    def test_manually_curated_address_is_left_unchanged_but_still_linked(self):
        """The unattended import never claims a foreign IPAM row, and still points at it."""
        from ipam.models import IPAddress

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        curated = IPAddress.objects.create(
            address="10.42.0.50/24",
            status="active",
            description="Held for the core switch by NetOps",
        )
        conf = {"subnet4": [{"id": 7, "subnet": "10.42.0.0/24"}]}
        hosts = [{"subnet-id": 7, "hw-address": "aa:bb:cc:dd:ee:42", "ip-address": "10.42.0.50", "hostname": "curated"}]

        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        curated.refresh_from_db()
        self.assertEqual(curated.description, "Held for the core switch by NetOps")
        self.assertEqual(curated.status, "active")
        self.assertEqual(curated.dns_name, "")
        self.assertEqual(summary.foreign_addresses_skipped, 1)
        self.assertTrue(
            any("10.42.0.50" in warning and "left unchanged" in warning for warning in summary.warnings),
            summary.warnings,
        )
        self.assertEqual(HostReservation.objects.get(hostname="curated").ipv4_address, curated)

    def test_unverified_subnet_id_is_quarantined_before_adapter(self):
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        conf = {"subnet4": []}  # subnet-id 99 was never imported
        hosts = [{"subnet-id": 99, "hw-address": "aa:bb:cc:dd:ee:99", "ip-address": "10.99.0.5"}]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        self.assertEqual(summary.reservations_created, 0)
        self.assertEqual(summary.reservations_quarantined, 1)
        self.assertFalse(HostReservation.objects.exists())
        self.assertTrue(any("cannot verify" in warning for warning in summary.warnings), summary.warnings)

    def test_reimport_is_idempotent(self):
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        conf = {"subnet4": [{"id": 7, "subnet": "10.41.0.0/24"}]}
        hosts = [{"subnet-id": 7, "hw-address": "aa:bb:cc:dd:ee:41", "ip-address": "10.41.0.50"}]

        snapshot = _reservation_snapshot(conf, 4, hosts)
        self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4), snapshot)
        second = self.adapter.import_server_config(self.server, parse_dhcp_config(conf, 4), snapshot)
        self.assertEqual(second.reservations_created, 0)
        self.assertEqual(HostReservation.objects.count(), 1)

    def test_global_hardware_reservation_keeps_its_identity_across_reimports(self):
        """A Global Scope skips the IPAM sync, which must not cost the reservation its MAC."""
        from dcim.models import MACAddress

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = {"subnet4": []}
        hosts = [{"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:11", "ip-address": "10.11.0.9", "hostname": "g-hw"}]
        intent = parse_dhcp_config(conf, 4)
        snapshot = _reservation_snapshot(conf, 4, hosts)

        first = self.adapter.import_server_config(self.server, intent, snapshot)
        second = self.adapter.import_server_config(self.server, intent, snapshot)

        self.assertEqual(first.errors, 0, first.warnings)
        self.assertEqual(second.errors, 0, second.warnings)
        self.assertEqual(second.reservations_created, 0)
        self.assertEqual(HostReservation.objects.count(), 1)
        self.assertEqual(
            HostReservation.objects.get().hw_address,
            MACAddress.objects.get(mac_address="aa:bb:cc:dd:ee:11"),
        )

    def test_global_reservation_mac_takes_the_published_name_of_its_subnet(self):
        """The MAC description takes the published name; the plugin row mirrors the stored Kea hostname."""
        from dcim.models import MACAddress

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        conf = {
            "ddns-qualifying-suffix": "dhcp.example.com",
            "subnet4": [{"id": 7, "subnet": "10.12.0.0/24", "ddns-qualifying-suffix": "lab.example.com."}],
        }
        hosts = [
            {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:12", "ip-address": "10.12.0.9", "hostname": "in-subnet"},
            {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:13", "ip-address": "10.13.0.9", "hostname": "outside"},
            {"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:14", "hostname": "Host.example.org."},
        ]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        for hardware, published in (
            ("aa:bb:cc:dd:ee:12", "in-subnet.lab.example.com"),
            ("aa:bb:cc:dd:ee:13", "outside.dhcp.example.com"),
            ("aa:bb:cc:dd:ee:14", "host.example.org"),
        ):
            with self.subTest(hardware=hardware):
                self.assertEqual(
                    MACAddress.objects.get(mac_address=hardware).description, f"dhcp_hostname: {published}"
                )
        self.assertEqual(
            sorted(HostReservation.objects.values_list("hostname", flat=True)),
            ["Host.example.org.", "in-subnet", "outside"],
        )

    def test_dual_stack_global_reservations_keep_separate_rows(self):
        """One identifier reserved globally in both protocols is two Reservations, not one.

        ``netbox_dhcp`` derives a reservation's family from its Subnet, and a Global
        Reservation has none, so both families matched the same row: the second import
        overwrote the first one's hostname and options instead of creating its own row.
        ``KeaDhcpLink`` carries the family that the row cannot.
        """
        from netbox_kea.models import KeaDhcpLink

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        identifier = "aa:bb:cc:dd:ee:41"
        conf4, conf6 = {"subnet4": []}, {"subnet6": []}
        hosts4 = [{"subnet-id": 0, "hw-address": identifier, "hostname": "dual-v4"}]
        hosts6 = [{"subnet-id": 0, "hw-address": identifier, "hostname": "dual-v6"}]

        for _ in range(2):  # idempotent: the second pass must update, never duplicate
            v4 = self.adapter.import_server_config(
                self.server, parse_dhcp_config(conf4, 4), _reservation_snapshot(conf4, 4, hosts4)
            )
            v6 = self.adapter.import_server_config(
                self.server, parse_dhcp_config(conf6, 6), _reservation_snapshot(conf6, 6, hosts6)
            )

        self.assertEqual(v4.errors, 0, v4.warnings)
        self.assertEqual(v6.errors, 0, v6.warnings)
        self.assertEqual(v4.reservations_created, 0)
        self.assertEqual(v6.reservations_created, 0)

        rows = list(HostReservation.objects.order_by("name"))
        self.assertEqual(len(rows), 2, [row.name for row in rows])
        v4_row, v6_row = rows
        self.assertIn("DHCPv4", v4_row.name)
        self.assertIn("DHCPv6", v6_row.name)
        # Each row keeps its own facts; one shared row kept only the last import's.
        self.assertEqual(v4_row.hostname, "dual-v4")
        self.assertEqual(v6_row.hostname, "dual-v6")
        self.assertEqual(
            sorted(
                KeaDhcpLink.objects.filter(kind="reservation", kea_subnet_id__isnull=True).values_list(
                    "family", "kea_identity"
                )
            ),
            [(4, f"hw-address:{identifier}"), (6, f"hw-address:{identifier}")],
        )

    def test_global_reservation_imported_before_the_link_is_adopted(self):
        """Relink a Global row from an earlier release instead of duplicating it."""
        from netbox_kea.models import KeaDhcpLink

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = {"subnet4": []}
        hosts = [{"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:42", "ip-address": "10.42.0.9", "hostname": "legacy"}]
        intent = parse_dhcp_config(conf, 4)
        snapshot = _reservation_snapshot(conf, 4, hosts)

        self.adapter.import_server_config(self.server, intent, snapshot)
        legacy = HostReservation.objects.get()
        legacy.name = "legacy name from an earlier import"
        legacy.save()
        KeaDhcpLink.objects.filter(kind="reservation", kea_subnet_id__isnull=True).delete()

        summary = self.adapter.import_server_config(self.server, intent, snapshot)

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertEqual(summary.reservations_created, 0)
        self.assertEqual(HostReservation.objects.count(), 1)
        adopted = HostReservation.objects.get()
        self.assertEqual(adopted.pk, legacy.pk)
        self.assertIn("DHCPv4", adopted.name)
        self.assertEqual(
            KeaDhcpLink.objects.filter(
                server=self.server, family=4, kind="reservation", kea_identity="hw-address:aa:bb:cc:dd:ee:42"
            ).count(),
            1,
        )

    def test_addressless_hardware_reservation_keeps_its_identity_across_reimports(self):
        """An identifier-only host reserves no address, so the IPAM sync skips it too."""
        from dcim.models import MACAddress

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = {"subnet4": [{"id": 12, "subnet": "10.12.0.0/24"}]}
        hosts = [{"subnet-id": 12, "hw-address": "aa:bb:cc:dd:ee:12", "hostname": "id-only"}]
        intent = parse_dhcp_config(conf, 4)
        snapshot = _reservation_snapshot(conf, 4, hosts)

        first = self.adapter.import_server_config(self.server, intent, snapshot)
        second = self.adapter.import_server_config(self.server, intent, snapshot)

        self.assertEqual(first.errors, 0, first.warnings)
        self.assertEqual(second.errors, 0, second.warnings)
        self.assertEqual(second.reservations_created, 0)
        self.assertEqual(HostReservation.objects.count(), 1)
        self.assertEqual(
            HostReservation.objects.get().hw_address,
            MACAddress.objects.get(mac_address="aa:bb:cc:dd:ee:12"),
        )

    def test_addressless_reservation_without_a_known_published_name_imports_without_a_mac_name(self):
        """A Pool suffix makes the name depend on the lease, so the MAC description gets no name."""
        from dcim.models import MACAddress

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        conf = {
            "subnet4": [
                {
                    "id": 13,
                    "subnet": "10.13.0.0/24",
                    "pools": [{"pool": "10.13.0.10-10.13.0.100", "ddns-qualifying-suffix": "pool.example.com"}],
                }
            ]
        }
        hosts = [{"subnet-id": 13, "hw-address": "aa:bb:cc:dd:ee:13", "hostname": "id-only"}]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertIn("reservation", summary.ownership.completed_sources)
        reservation = HostReservation.objects.get()
        self.assertEqual(reservation.hostname, "id-only")
        mac = MACAddress.objects.get(mac_address="aa:bb:cc:dd:ee:13")
        self.assertEqual(reservation.hw_address, mac)
        self.assertEqual(mac.description, "")

    def test_global_v6_reservation_does_not_invent_ipam_scope(self):
        from ipam.models import IPAddress

        intent = parse_dhcp_config({"subnet6": []}, 6)
        hosts = [{"subnet-id": 0, "duid": "01:02:03:0a", "ip-addresses": ["2001:db8:aa::5"], "hostname": "g6"}]
        snapshot = _reservation_snapshot({"subnet6": []}, 6, hosts)
        summary = self.adapter.import_server_config(self.server, intent, snapshot)

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertFalse(IPAddress.objects.filter(address__net_host="2001:db8:aa::5").exists())

    def test_reservation_whose_mac_row_cannot_be_written_rolls_back_its_ip(self):
        """A MAC write failure must not commit the reservation's earlier IP write."""
        from dcim.models import MACAddress
        from ipam.models import IPAddress

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        conf = {"subnet4": [{"id": 7, "subnet": "10.43.0.0/24"}]}
        hosts = [{"subnet-id": 7, "hw-address": "aa:bb:cc:dd:ee:43", "ip-address": "10.43.0.50"}]
        intent = parse_dhcp_config(conf, 4)
        snapshot = _reservation_snapshot(conf, 4, hosts)

        MACAddress.objects.create(mac_address="aa:bb:cc:dd:ee:43")
        MACAddress.objects.create(mac_address="aa:bb:cc:dd:ee:43")
        first = self.adapter.import_server_config(self.server, intent, snapshot)
        second = self.adapter.import_server_config(self.server, intent, snapshot)

        self.assertEqual(HostReservation.objects.count(), 0)
        self.assertFalse(IPAddress.objects.filter(address__net_host="10.43.0.50").exists())
        self.assertEqual(first.reservations_created, 0)
        self.assertFalse(first.reservations_unread)
        self.assertEqual(first.errors, 1, first.warnings)
        self.assertEqual(first.reservations_skipped, 0)
        self.assertEqual(second.errors, 1, second.warnings)
        self.assertTrue(
            any("could not be imported" in warning for warning in second.warnings),
            second.warnings,
        )

    def test_delegated_prefixes_import_as_shared_ipam_prefixes(self):
        """A DHCPv6 Reservation delegates prefixes, and the plugin models them."""
        from ipam.models import Prefix

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = {"subnet6": [{"id": 3, "subnet": "2001:db8:3::/64"}]}
        hosts = [
            {
                "subnet-id": 3,
                "duid": "01:02:03:04:05:06",
                "ip-addresses": ["2001:db8:3::5"],
                "prefixes": ["2001:db8:beef::/56", "2001:db8:cafe::/56"],
                "hostname": "pd-host",
            }
        ]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 6), _reservation_snapshot(conf, 6, hosts)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        res = HostReservation.objects.get(hostname="pd-host")
        self.assertCountEqual(
            [str(prefix.prefix) for prefix in res.ipv6_prefixes.all()],
            ["2001:db8:beef::/56", "2001:db8:cafe::/56"],
        )
        # The same IPAM rows the rest of the plugin reads, not private copies.
        self.assertEqual(
            set(res.ipv6_prefixes.values_list("pk", flat=True)),
            set(
                Prefix.objects.filter(prefix__in=["2001:db8:beef::/56", "2001:db8:cafe::/56"]).values_list(
                    "pk", flat=True
                )
            ),
        )

    def test_failed_reservation_write_rolls_back_its_delegated_prefix(self):
        """A valid name collision after Prefix creation must leave no partial IPAM row."""
        from ipam.models import Prefix

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        conf = {"subnet6": [{"id": 6, "subnet": "2001:db8:6::/64"}]}
        common_duid = ["aa"] * 83
        first_duid = ":".join([*common_duid, "01"])
        colliding_duid = ":".join([*common_duid, "02"])
        intent = parse_dhcp_config(conf, 6)

        first = self.adapter.import_server_config(
            self.server,
            intent,
            _reservation_snapshot(conf, 6, [{"subnet-id": 6, "duid": first_duid}]),
        )
        collision = self.adapter.import_server_config(
            self.server,
            intent,
            _reservation_snapshot(
                conf,
                6,
                [
                    {
                        "subnet-id": 6,
                        "duid": colliding_duid,
                        "prefixes": ["2001:db8:face::/56"],
                    }
                ],
            ),
        )

        self.assertEqual(first.errors, 0, first.warnings)
        self.assertEqual(HostReservation.objects.count(), 1)
        self.assertEqual(collision.errors, 1, collision.warnings)
        self.assertFalse(Prefix.objects.filter(prefix="2001:db8:face::/56").exists())

    def test_global_reservation_keeps_its_delegated_prefixes(self):
        """A delegated prefix carries its own length, so no Subnet has to supply one."""
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = {"subnet6": []}
        hosts = [{"subnet-id": 0, "duid": "01:02:03:0b", "prefixes": ["2001:db8:d00d::/56"], "hostname": "g6-pd"}]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 6), _reservation_snapshot(conf, 6, hosts)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        res = HostReservation.objects.get(hostname="g6-pd")
        self.assertIsNone(res.subnet)
        self.assertEqual(
            [(str(prefix.prefix), prefix.description) for prefix in res.ipv6_prefixes.all()],
            [("2001:db8:d00d::/56", "[kea-sync: delegated prefix]")],
        )

    def test_reimport_clears_dropped_delegated_prefixes(self):
        """Kea no longer delegates the prefix, so the imported record must not keep it."""
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = {"subnet6": [{"id": 4, "subnet": "2001:db8:4::/64"}]}
        identity = {"subnet-id": 4, "duid": "01:02:03:04:05:07", "hostname": "pd-dropped"}
        intent = parse_dhcp_config(conf, 6)

        self.adapter.import_server_config(
            self.server, intent, _reservation_snapshot(conf, 6, [{**identity, "prefixes": ["2001:db8:f00d::/56"]}])
        )
        second = self.adapter.import_server_config(self.server, intent, _reservation_snapshot(conf, 6, [identity]))

        self.assertEqual(second.errors, 0, second.warnings)
        res = HostReservation.objects.get(hostname="pd-dropped")
        self.assertEqual(list(res.ipv6_prefixes.all()), [])

    def test_skipped_reservation_leaves_no_delegated_prefix_behind(self):
        """The record never imports, so its prefixes must not appear in IPAM either."""
        from dcim.models import MACAddress
        from ipam.models import Prefix

        conf = {"subnet6": [{"id": 5, "subnet": "2001:db8:5::/64"}]}
        hosts = [
            {
                "subnet-id": 5,
                "hw-address": "aa:bb:cc:dd:ee:50",
                "prefixes": ["2001:db8:dead::/56"],
                "hostname": "pd-skipped",
            }
        ]

        MACAddress.objects.create(mac_address="aa:bb:cc:dd:ee:50")
        MACAddress.objects.create(mac_address="aa:bb:cc:dd:ee:50")
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 6), _reservation_snapshot(conf, 6, hosts)
        )

        self.assertEqual(summary.reservations_created, 0)
        self.assertFalse(Prefix.objects.filter(prefix="2001:db8:dead::/56").exists())

    def test_global_reservation_reports_a_curated_address_it_attaches(self):
        """A Global Scope skips the sync's own guard, so the import must apply it here."""
        from ipam.models import IPAddress

        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")
        curated = IPAddress.objects.create(
            address="10.0.0.12/32",
            status="active",
            description="Held for the console server by NetOps",
        )
        conf = {"subnet4": []}
        hosts = [{"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:ab", "ip-address": "10.0.0.12", "hostname": "g4-cur"}]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        curated.refresh_from_db()
        self.assertEqual(curated.description, "Held for the console server by NetOps")
        self.assertEqual(curated.status, "active")
        self.assertEqual(HostReservation.objects.get(hostname="g4-cur").ipv4_address, curated)
        self.assertEqual(summary.foreign_addresses_skipped, 1)
        self.assertTrue(any("10.0.0.12" in warning for warning in summary.warnings), summary.warnings)

    def test_global_reservation_reports_the_address_it_cannot_attach(self):
        """A Global Reservation has no Subnet to size an address from, so the address is lost."""
        HostReservation = apps.get_model(DHCP_PLUGIN, "HostReservation")

        conf = {"subnet4": []}
        hosts = [{"subnet-id": 0, "hw-address": "aa:bb:cc:dd:ee:aa", "ip-address": "10.0.0.11", "hostname": "g4-addr"}]
        summary = self.adapter.import_server_config(
            self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4, hosts)
        )

        self.assertEqual(summary.errors, 0, summary.warnings)
        self.assertIsNone(HostReservation.objects.get(hostname="g4-addr").ipv4_address)
        self.assertEqual(summary.addresses_unattached, 1)
        self.assertTrue(
            any("10.0.0.11" in warning for warning in summary.warnings),
            summary.warnings,
        )


@tag("dhcp_plugin")
class DhcpPluginStaleCleanupGuardTest(TestCase):
    """Stale-IP cleanup must never remove an IP a netbox_dhcp reservation references."""

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def setUp(self):
        self.server = _make_db_server(name=f"kea-clean-{timezone.now().timestamp()}")

    def test_reconciliation_never_removes_or_deprecates_a_referenced_ip(self):
        from ipam.models import IPAddress

        from netbox_kea import subnet_catalogue
        from netbox_kea.integrations import dhcp_plugin
        from netbox_kea.ipam_reconciliation import ReservationPhase, reconcile
        from netbox_kea.models import IPAMOwnershipLink

        from .kea_stub import _catalogue_responses_for_subnets
        from .test_ipam_reconciliation import _run_job
        from .test_jobs import _lease_page

        _run_job(self.server, [])
        conf = {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.77.0.0/24",
                    "reservations": [{"hw-address": "aa:bb:cc:dd:ee:77", "ip-address": "10.77.0.50", "hostname": "pc"}],
                }
            ]
        }
        dhcp_plugin.import_server_config(self.server, parse_dhcp_config(conf, 4), _reservation_snapshot(conf, 4))
        referenced = IPAddress.objects.get(address="10.77.0.50/24")
        lease = {"ip-address": "10.77.0.50", "hostname": "pc", "subnet-id": 1}
        empty_kea = {
            **_catalogue_responses_for_subnets(4, [{"id": 1, "subnet": "10.77.0.0/24"}]),
            "lease4-get-page": _lease_page([]),
            "reservation-get-page": _res_page([]),
        }
        for mode in ("remove", "deprecate"):
            with self.subTest(mode), with_sync_config(stale_ip_cleanup=mode):
                with stub_kea({"lease4-get-page": _lease_page([lease])}):
                    reconcile(self.server, 4, [lease_phase(self.server, 4, {1: 24})])
                self.assertTrue(IPAMOwnershipLink.objects.filter(ip_address=referenced).exists())

                # Both phases run, so the cleanup decides the last link of the Server.
                with stub_kea(empty_kea):
                    reservation_phase = ReservationPhase(subnet_catalogue.for_synchronization(self.server, 4))
                    report = reconcile(self.server, 4, [lease_phase(self.server, 4, {1: 24}), reservation_phase])

                self.assertEqual((report.removed, report.deprecated), (0, 0))
                self.assertIn(IPAddress.objects.get(pk=referenced.pk).status, {"reserved", "dhcp"})
                self.assertFalse(IPAMOwnershipLink.objects.filter(ip_address=referenced).exists())


class ImportSummaryCompletenessTest(TestCase):
    """Reservation import counts must distinguish traversal and record failures.

    Needs no ``netbox_dhcp`` model: a Snapshot with no records never
    reaches the per-record upsert, so this runs in the ordinary unit-test job.
    """

    def _snapshot(self, *, diagnostic_code: str | None = None):
        diagnostics = (
            ()
            if diagnostic_code is None
            else (
                ReservationDiagnostic(
                    code=diagnostic_code,
                    message="Reservation Snapshot diagnostic.",
                    source_position="records[1]",
                ),
            )
        )
        return ReservationSnapshot(
            family=4,
            records=(),
            diagnostics=diagnostics,
            complete=not diagnostics,
            next_cursor=None,
            read_started=timezone.now(),
        )

    def _import(self, snapshot):
        from netbox_kea.integrations.dhcp_plugin import ImportSummary, import_reservation_snapshot

        summary = ImportSummary()
        observation = (
            ReservationObservation(snapshot, next_confirmation_number(), _catalogue({}, 4))
            if snapshot is not None
            else None
        )
        import_reservation_snapshot(_make_db_server(), None, observation, None, summary, family=4)
        return summary

    def test_absent_snapshot_reports_the_counts_as_unread(self):
        summary = self._import(None)

        self.assertTrue(summary.reservations_unread)

    def test_truncated_snapshot_reports_counts_as_unread_without_quarantine(self):
        # A truncated traversal imports only part of the record set, so the counts
        # are no more complete than for a Snapshot that could not be read at all.
        summary = self._import(self._snapshot(diagnostic_code=RESERVATION_PAGE_FETCH_FAILED))

        self.assertTrue(summary.reservations_unread)
        self.assertEqual(summary.reservations_quarantined, 0)

    def test_record_quarantine_keeps_counts_read_and_counts_the_malformed_record(self):
        summary = self._import(self._snapshot(diagnostic_code=RESERVATION_INVALID_IDENTIFIER))

        self.assertFalse(summary.reservations_unread)
        self.assertEqual(summary.reservations_quarantined, 1)

    def test_complete_snapshot_reports_the_counts_as_read(self):
        summary = self._import(self._snapshot())

        self.assertFalse(summary.reservations_unread)
        self.assertEqual(summary.reservations_quarantined, 0)


class SkippedReservationCompletenessTest(TestCase):
    """A record the importer drops must be counted as skipped.

    Needs the real ``KeaDhcpLink`` table to resolve the Subnet, but never reaches the
    per-record upsert, so it runs without ``netbox_dhcp`` installed.
    """

    def setUp(self):
        self.server = _make_db_server()

    def test_record_for_an_unlinked_subnet_id_reports_the_record_as_skipped(self):
        from netbox_kea.integrations.dhcp_plugin import ImportSummary, import_reservation_snapshot
        from netbox_kea.views.dhcp_plugin_sync import _summary_problems

        conf = {"subnet4": [{"id": 7, "subnet": "198.18.7.0/24"}]}
        hosts = [{"subnet-id": 7, "hw-address": "aa:bb:cc:00:00:07", "ip-address": "198.18.7.10"}]
        snapshot = _reservation_snapshot(conf, 4, hosts)
        summary = ImportSummary()

        # No KeaDhcpLink exists for subnet-id 7, so the record cannot be imported.
        import_reservation_snapshot(self.server, None, snapshot, None, summary, family=4)

        self.assertTrue(snapshot.snapshot.complete)
        self.assertEqual(summary.reservations_created, 0)
        self.assertFalse(summary.reservations_unread)
        self.assertEqual(summary.reservations_skipped, 1)
        self.assertEqual(
            summary.entries,
            [
                not_written(
                    4,
                    Kind.RESERVATION,
                    "Dhcp4/subnet4[id=7]/reservations[hw-address=aa:bb:cc:00:00:07]",
                    Reason.PARENT_NOT_IMPORTED,
                    "Subnet 7 was not imported.",
                )
            ],
        )
        self.assertIn("reservation for unknown subnet-id 7 skipped", summary.warnings)
        self.assertNotIn("host_cmds", " ".join(_summary_problems(summary)))
