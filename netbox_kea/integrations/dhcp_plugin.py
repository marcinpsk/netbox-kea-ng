# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Adapter to the optional NetBox DHCP plugin (``netbox_dhcp``, sys4).

This module applies the plans of :mod:`netbox_kea.integrations.dhcp_import_plan` to the DHCP plugin and
compares DHCP data. The mapping lifecycle module coordinates
its targets with native branching. Both modules resolve optional DHCP models lazily,
so netbox-kea imports cleanly when the DHCP plugin is absent. Call
:func:`is_available` before any other entry point. :func:`integration_refusal` is the
only rule that decides whether the integration runs for a Server.

v1 scope (import + diff, read-only against Kea):

* Imports the **data tier** of a Kea ``config-get`` into ``netbox_dhcp`` rows —
  ``DHCPServer``, ``Subnet``, ``Pool``, ``PDPool``, ``HostReservation`` — reusing netbox-kea's
  IPAM ownership claims so the DHCP-plugin rows **share** the same
  ``ipam.Prefix``/``IPRange``/``IPAddress`` and ``dcim.MACAddress`` objects the
  IPAM sync maintains.
* **Delegated-prefix Pools** (DHCPv6 ``pd-pools``) import as ``PDPool`` rows in their Subnet. Their prefix and
  excluded prefix are NetBox Prefixes that the import owns through the IPAM source ``pd-pool`` (ADR 0006). The
  ``pd-pool`` phase runs after the removal of Stale DHCP Import Objects, so it can deprecate a Prefix that only a
  removed PD Pool used. A PD Pool that the plugin refuses (``PDPool.clean``) is unsupported, and the run goes on.
* **Host reservations** come from the shared typed Reservation Snapshot. The
  adapter never parses raw ``reservation-get-page`` records. Valid records import
  even when the snapshot quarantines other records. A Global Reservation skips the
  IPAM sync, so the import creates no address rows for it and reports every reserved
  address it could not attach.  Delegated prefixes and the prefixes that they exclude carry their own length, so
  they import as shared ``ipam.Prefix`` rows for every Scope, under the IPAM source ``reservation-prefix``. The stale
  cleanup of ``reservation-prefix`` runs after the removal of Stale DHCP Import Objects, as the ``pd-pool`` phase does.
* A plugin Subnet holds Kea's subnet ID (:func:`settle_subnet_ids`). While the plugin keeps Subnet IDs
  unique across all servers, a Subnet whose ID another Server or family holds is reported as unsupported,
  with its Pools, delegated-prefix Pools and In-Subnet Reservations.
* **Writes.** Every row except the DHCPServer goes through :func:`.dhcp_import_write.write_row`, with one small
  adapter class for its kind here. The protocol finds the row through its mapping or adopts an unmapped one, writes
  it, observes the mapping, reports a failure, and skips the planned subtree of an object that it does not write.
* **Ownership.** Every writer sets exactly the managed fields of :mod:`.dhcp_import_fields` on a mapped row, and
  :mod:`.dhcp_import_write` refuses a write that names another set. Unmanaged fields and unmapped rows stay.
* A Shared Network, a Subnet, a Pool, a PD Pool and a Reservation link the client classes of their class lists that
  the same run imported. A Shared Network and a Subnet link the DHCP server interface that their Kea ``interface``
  names, and report a name that matches none.
* **Client classes** (``client-classes``) are imported as ``ClientClass`` rows
  (test/template-test, additional-list flag, BOOTP + lifetime settings, options) with
  their Kea name. While the plugin keeps class names unique across all servers, a class
  whose name another row holds is reported as unsupported (:mod:`.dhcp_plugin_capabilities`).
* **Shared Networks** (``shared-networks``) are imported as ``SharedNetwork`` rows with their Kea name, settings,
  class lists, interface and options, before the Subnets, and never with a Prefix: a Kea Shared Network has none.
  Each member Subnet belongs to its Shared Network instead of the DHCPServer. Without the capability for an
  optional prefix (netbox-plugin-dhcp 0.2.0 requires one) every Shared Network is unsupported, and its member Subnets
  import onto the DHCPServer. Names follow the same uniqueness rule as client classes.
* **Removal.** A mapped row whose Kea source a Complete observation of its kind no longer reports is a Stale DHCP Import
  Object (:func:`stale_judgment`, :func:`remove_stale_objects`). The run removes it, children first, and reports it. An
  Incomplete observation keeps every row of its kind. A row whose delete would also delete a DHCP plugin row that the
  run keeps, that an Option still uses, or that a kept row names in a client class relation, stays. IPAM objects stay:
  ADR 0006 ownership decides them.
  The Subnet writes run first, so a kept Subnet that left a stale Shared Network no longer belongs to it.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from functools import cached_property
from itertools import count
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..ipam_reconciliation import (
        ClaimResult,
        RangeClaim,
        ReservationObservation,
        ReservationPrefixPhase,
        SyncReport,
    )
    from ..models import DhcpIntegrationConfig, Server
    from ..subnet_catalogue import CatalogueSnapshot
    from .dhcp_import_plan import (
        FamilyPlan,
        KindObservation,
        NamedKey,
        PDPoolKey,
        Planned,
        PlannedClientClass,
        PlannedOptions,
        PlannedSharedNetwork,
        PlannedSubnet,
        ReservationKey,
    )

from django.apps import apps
from django.db.models import F, Q
from django.db.models.deletion import Collector, ProtectedError

from .. import event_scope, kea_paths
from ..constants import Family
from ..dhcp_mapping_lifecycle import coordinated_import
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import OptionDefIntent, PDPoolIntent, PoolIntent, ServerConfigIntent
from ..published_name import reservation_published_name
from ..reservations import TRAVERSAL_DIAGNOSTIC_CODES, Reservation, identity_text
from ..subnet_catalogue import CatalogueUnavailable
from .dhcp_import_fields import (
    CLIENT_CLASS_FIELDS,
    GATED_NETWORK_FIELDS,
    GATED_SUBNET_FIELDS,
    MANAGED_FIELDS,
    NETWORK_FIELDS,
    POOL_FIELDS,
)
from .dhcp_import_mappings import (
    mapped_links,
    mapped_option_keys,
    mapped_target,
    subnet_id_mappings,
    unlinked,
)
from .dhcp_import_options import (
    CustomDefinitions,
    OptionReferences,
    option_paths,
    upsert_options,
    write_option_definition,
)
from .dhcp_import_plan import (
    REMOVAL_ORDER,
    InSubnetReservationKey,
    InvalidPoolKey,
    MappingSource,
    OptionDefinitionKey,
    PoolKey,
    SubnetKey,
    keyed_reservations,
    kind_path,
    mapped_kinds,
    observations,
    plan_family,
    planned_options,
)
from .dhcp_import_report import (
    KIND_LABELS,
    Capability,
    ImportEntry,
    Kind,
    Outcome,
    Reason,
    counted,
    not_written,
    written,
)
from .dhcp_import_server import (
    adoption_servers,
    apply_global_settings,
    link_interfaces,
    no_interface_detail,
    server_values,
    synthesized_name,
    upsert_dhcp_server,
)
from .dhcp_import_summary import ImportSummary
from .dhcp_import_values import (
    Source,
    declared_value,
    gated_values,
    settings_fields,
    user_context_fields,
)
from .dhcp_import_write import (
    FAILED,
    LateOutcome,
    NotWritten,
    RowAdapter,
    RowState,
    WriteScope,
    row_state,
    write_row,
)
from .dhcp_plugin_capabilities import PLUGIN_APP_LABEL, PluginCapabilities, plugin_model, probe

logger = logging.getLogger(__name__)


def is_available() -> bool:
    """Return ``True`` when the optional NetBox DHCP plugin is installed."""
    return apps.is_installed(PLUGIN_APP_LABEL)


def integration_refusal(server: Server, switch: DhcpIntegrationConfig | None = None) -> str:
    """Return why the DHCP plugin integration does not run for *server*, or "" when it runs (ADR 0010).

    A caller that checks many Servers passes the *switch* row that it read once.
    """
    from ..models import DhcpIntegrationConfig

    if not is_available():
        return "The NetBox DHCP plugin (netbox_dhcp) is not installed."
    if not server.sync_dhcp_plugin_enabled:
        return "Enable 'Sync to DHCP plugin' on this server first."
    if not server.dhcp4 and not server.dhcp6:
        # Server.save() does not call clean(), so a row can have no family.
        return "Enable DHCPv4 or DHCPv6 on this server first."
    # Read last, so that a Server that opts out costs no query.
    if not (switch or DhcpIntegrationConfig.get()).enabled:
        return "The DHCP plugin integration is off for all Servers. Turn it on in DHCP Kea > Settings."
    return ""


def runs_for(server: Server, switch: DhcpIntegrationConfig | None = None) -> bool:
    """Return whether the DHCP plugin integration runs for *server*."""
    return not integration_refusal(server, switch)


def scheduled_import_runs_for(server: Server) -> bool:
    """Return whether the periodic sync job runs the DHCP Import of *server*, whatever the IPAM sync settings."""
    from ..models import DhcpIntegrationConfig
    from .dhcp_import import supported_plugin_installed

    switch = DhcpIntegrationConfig.get()
    return switch.scheduled_import_enabled and runs_for(server, switch) and supported_plugin_installed()


# ─────────────────────────────────────────────────────────────────────────────
# IPAM / DCIM resolution (reuse netbox-kea sync helpers — share the same rows)
# ─────────────────────────────────────────────────────────────────────────────


def _reservation_addresses(
    reservation: Reservation, claims: ClaimResult, catalogue: CatalogueSnapshot, summary: ImportSummary
):
    """Attach the address objects returned by the whole-snapshot ownership claim."""
    ipv4_ip = None
    ipv6_ips = []
    unattached = []
    for address in reservation.addresses:
        result = claims.addresses[str(address)]
        if result.outcome == "error":
            raise RuntimeError("The reserved address could not be claimed")
        if result.outcome == "conflict":
            summary.foreign_addresses_skipped += 1
            summary.warn(
                f"reservation {reservation.identity.value}: manually curated NetBox IP {address} left unchanged"
            )
        elif result.outcome == "disagreement":
            summary.warn(f"reservation {reservation.identity.value}: owner disagreement for {address}; IPAM unchanged")
        if result.ip is None:
            unattached.append(str(address))
        elif address.version == 4:
            ipv4_ip = result.ip
        else:
            ipv6_ips.append(result.ip)
    if unattached:
        summary.addresses_unattached += len(unattached)
        summary.warn(
            f"reservation {reservation.identity.value}: reserved address(es) "
            f"{', '.join(unattached)} have no NetBox IP and were not attached"
        )
    hardware = reservation.identity.hardware_address
    mac_obj = None
    if hardware:
        try:
            hostname = reservation_published_name(reservation, catalogue)
        except CatalogueUnavailable:
            # The MAC description gets no name that the plugin cannot know; the DHCP row needs only the MAC.
            hostname = ""
        for address in reservation.addresses:
            mac_obj = claims.addresses[str(address)].resolved_macs.get((hardware, hostname))
            if mac_obj is not None:
                break
        if mac_obj is None:
            mac_obj = _resolve_mac(hardware, hostname)
    return ipv4_ip, ipv6_ips, mac_obj


def _resolve_mac(hw_address: str | None, hostname: str = ""):
    """Return the ``dcim.MACAddress`` row for *hw_address*, creating it when absent.

    Address claims return their resolved MAC rows. Global, addressless and curated
    Reservations can have no such result, so they resolve the DHCP identifier here.
    """
    if not hw_address:
        return None
    from ..sync import sync_mac_address

    return sync_mac_address(hw_address, hostname)


def _class_not_imported(name: str) -> str:
    """Return the detail of a fact whose client class *name* Kea defines but this run did not import."""
    return f"Client class {name} was not imported."


# ─────────────────────────────────────────────────────────────────────────────
# Upserts
# ─────────────────────────────────────────────────────────────────────────────


def _released_client_class_name(server, kea_name: str) -> str:
    """Return the name that the released importer gave a Kea class, before a class had a mapping."""
    return f"{server.name}: {kea_name}"[:255]


def _client_class_fields(
    obj,
    dhcp_server,
    planned: PlannedClientClass,
    summary: ImportSummary,
    path: str,
    capabilities: PluginCapabilities,
    name: str,
) -> dict:
    """Plan the managed fields of one Client Class with the *name* that it keeps or takes."""
    intent = planned.intent
    fields = {
        "name": name,
        "dhcp_server_id": dhcp_server.pk,
        "test": intent.test or "",
        "template_test": intent.template_test or "",
        "only_in_additional_list": intent.only_in_additional_list,
    }
    source = Source(intent.family, Kind.CLIENT_CLASS, path)
    fields |= user_context_fields(obj, intent.user_context, capabilities, summary, source, "client class")
    fields.update(settings_fields(obj, planned.settings, CLIENT_CLASS_FIELDS, summary, source))
    return fields


def _name_taken(kind: Kind, name: str, obj, dhcp_server, capabilities: PluginCapabilities) -> bool:
    """Return whether another row of *kind* holds *name* in the scope where the DHCP plugin keeps the names unique."""
    from ..models import MAPPING_KINDS

    others = plugin_model(MAPPING_KINDS[kind][0]).objects.filter(name=name)
    if capabilities.has(Capability.NAME_PER_SERVER):
        others = others.filter(dhcp_server=dhcp_server)
    return (others.exclude(pk=obj.pk) if obj is not None else others).exists()


def _taken_name(kind: Kind, name: str, capabilities: PluginCapabilities) -> NotWritten:
    """Return why the run does not give an object of *kind* its Kea *name*: another row holds it."""
    label = KIND_LABELS[kind].lower()
    if capabilities.has(Capability.NAME_PER_SERVER):
        return NotWritten(Reason.NOT_IN_SCOPE, f"Another {label} of this DHCP server holds the name {name!r}.")
    detail = (
        f"Another {label} holds the name {name!r}. "
        f"The DHCP plugin needs each {label} name to be unique across all DHCP servers."
    )
    return NotWritten(Reason.PLUGIN_GAP, detail, Capability.NAME_PER_SERVER)


@dataclass(frozen=True)
class _NamedAdapter(RowAdapter):
    """A client class or a Shared Network by its Kea name.

    Another row that holds the name stops a new row. A mapped row keeps its name, takes every other field, and the
    run reports the name.
    """

    scope: WriteScope
    key: NamedKey
    dhcp_server: Any
    options: PlannedOptions

    def _holds_name(self, row) -> bool:
        """Return whether another row than *row* holds the Kea name."""
        return _name_taken(self.key.kind, self.key.name, row, self.dhcp_server, self.scope.capabilities)

    def name(self, row) -> str:
        """Return the name of *row*: its Kea name, or the name that it keeps while another row holds that one."""
        return row.name if self._holds_name(row) else self.key.name

    def refusal(self) -> NotWritten | None:
        """Return why a new row cannot take the Kea name."""
        return _taken_name(self.key.kind, self.key.name, self.scope.capabilities) if self._holds_name(None) else None

    def diagnostics(self, row) -> list[ImportEntry]:
        """Return the entry of the Kea name that the mapped *row* cannot take."""
        if not self._holds_name(row):
            return []
        family = self.scope.family
        path = kea_paths.setting(self.key.path(family), "name")
        return [_taken_name(self.key.kind, self.key.name, self.scope.capabilities).entry(family, self.key.kind, path)]

    def descendants(self) -> Iterator[tuple[Kind, str]]:
        """Yield the DHCP Options of the object."""
        yield from option_paths(self.options, self.scope.family)


@dataclass(frozen=True)
class _ClientClassAdapter(_NamedAdapter):
    """A client class with its Kea name. Its subtree holds its DHCP Options and its own Option Definitions."""

    planned: PlannedClientClass

    def adopt(self):
        """Return the row that the released importer created before client classes had a mapping."""
        released = _released_client_class_name(self.scope.server, self.key.name)
        return unlinked(plugin_model("ClientClass").objects.filter(name=released)).first()

    def new_row(self):
        """Return a new client class."""
        return plugin_model("ClientClass")()

    def fields(self, row) -> dict:
        """Return the managed fields of the class."""
        path = self.key.path(self.scope.family)
        scope = self.scope
        return _client_class_fields(
            row, self.dhcp_server, self.planned, scope.summary, path, scope.capabilities, self.name(row)
        )

    def descendants(self) -> Iterator[tuple[Kind, str]]:
        """Yield the DHCP Options of the class, then its Option Definitions."""
        yield from super().descendants()
        for planned_definition in self.planned.option_definitions:
            yield Kind.OPTION_DEFINITION, planned_definition.key.path(self.scope.family)


def upsert_client_class(scope: WriteScope, dhcp_server, planned: PlannedClientClass, definitions: CustomDefinitions):
    """Get/create the DHCP-plugin ``ClientClass`` for *planned* through its mapping, with its Option Definitions.

    The row takes the Kea name. Its DHCP Options are written after every class row exists (:func:`apply_plan`).
    Return the row, or ``None`` when it was not written.
    """
    options = planned_options(planned, scope.family, definitions.declared)
    row = write_row(_ClientClassAdapter(scope, planned.key, dhcp_server, options, planned))
    if isinstance(row, NotWritten):
        for planned_definition in planned.option_definitions:
            definitions.written[planned_definition.key] = row.descendant()
        return None
    for planned_definition in planned.option_definitions:
        write_option_definition(scope, definitions, planned_definition.key, row)
    return row


def _shared_network_fields(
    obj, dhcp_server, planned: PlannedSharedNetwork, summary: ImportSummary, path: str, capabilities, name: str
) -> dict:
    """Plan the managed fields of one Shared Network with the *name* that it keeps or takes."""
    source = Source(planned.intent.family, Kind.SHARED_NETWORK, path)
    return {
        "name": name,
        "dhcp_server_id": dhcp_server.pk,
        **settings_fields(obj, planned.settings, NETWORK_FIELDS, summary, source),
        **gated_values(obj, planned.settings, GATED_NETWORK_FIELDS, capabilities, summary, source),
        **user_context_fields(obj, planned.intent.user_context, capabilities, summary, source, "Shared Network"),
    }


@dataclass(frozen=True)
class _SharedNetworkAdapter(_NamedAdapter):
    """A Shared Network with its Kea name and no Prefix: a Kea Shared Network has none."""

    planned: PlannedSharedNetwork
    classes: ClassReferences

    def blocked(self) -> NotWritten | None:
        """Return why the plugin cannot hold a Shared Network without the capability for an optional prefix."""
        if self.scope.capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX):
            return None
        detail = "The DHCP plugin needs a Prefix for each Shared Network, and a Kea Shared Network has none."
        return NotWritten(Reason.PLUGIN_GAP, detail, Capability.SHARED_NETWORK_OPTIONAL_PREFIX)

    def new_row(self):
        """Return a new Shared Network. The import never links a Prefix; a Prefix that an operator sets stays."""
        return plugin_model("SharedNetwork")(prefix_id=None)

    def fields(self, row) -> dict:
        """Return the managed fields of the Shared Network."""
        path = self.key.path(self.scope.family)
        scope = self.scope
        return _shared_network_fields(
            row, self.dhcp_server, self.planned, scope.summary, path, scope.capabilities, self.name(row)
        )

    def relations(self, row) -> dict[str, set[int]]:
        """Return the client classes and the DHCP server interface of the Shared Network."""
        intent, family, summary = self.planned.intent, self.scope.family, self.scope.summary
        path = self.key.path(family)
        relations = self.classes.relations(intent, path, Kind.SHARED_NETWORK, summary)
        interface = self.planned.settings.get(kea_paths.INTERFACE)
        relations["server_interfaces"] = _network_interface(
            self.dhcp_server, interface, path, Kind.SHARED_NETWORK, family, summary
        )
        return relations


def upsert_shared_network(scope: WriteScope, dhcp_server, planned: PlannedSharedNetwork, references: OptionReferences):
    """Get or create the DHCP plugin ``SharedNetwork`` of *planned* through its mapping, with its DHCP Options.

    Without the capability for an optional prefix the Shared Network is unsupported. Return the row, or ``None`` when
    it was not written.
    """
    options = planned_options(planned, scope.family, references.definitions.declared)
    row = write_row(_SharedNetworkAdapter(scope, planned.key, dhcp_server, options, planned, references.classes))
    if isinstance(row, NotWritten):
        return None
    upsert_options(scope, row, options, references)
    return row


def _import_shared_networks(scope: WriteScope, dhcp_server, plan: FamilyPlan, references: OptionReferences):
    """Write every Shared Network of *plan* before its Subnets. Return the row of each imported one by Kea name."""
    rows = {}
    for planned in plan.shared_networks:
        row = upsert_shared_network(scope, dhcp_server, planned, references)
        if row is not None:
            rows[planned.key.name] = row
    return rows


def _subnet_name(server, planned: PlannedSubnet) -> str:
    """Build a globally-unique name (NetBoxDHCPModelMixin requires unique ``name``)."""
    return synthesized_name(server.name, f" DHCPv{planned.intent.family} subnet {planned.key.subnet_id}")


def _pool_name(subnet_obj, pool_intent) -> str:
    """Build a unique pool name scoped to its parent subnet's (unique) name."""
    return synthesized_name(subnet_obj.name, f" pool {pool_intent.pool}")


def _pd_pool_name(subnet_obj, key: PDPoolKey) -> str:
    """Build a unique PD Pool name scoped to its parent subnet's (unique) name."""
    return synthesized_name(subnet_obj.name, f" pd pool {key.prefix} delegated /{key.delegated_length}")


def _reservation_name(scope_name: str, reservation: Reservation) -> str:
    """Build a unique reservation name scoped to its parent's (unique) name."""
    identity = reservation.identity
    return synthesized_name(scope_name, f" {identity_text(identity.identifier_type, identity.value)}")


def _served_by(dhcp_server) -> Q:
    """Return the Subnets of *dhcp_server*: its own, and the members of its Shared Networks."""
    return Q(dhcp_server=dhcp_server) | Q(shared_network__dhcp_server=dhcp_server)


@dataclass(frozen=True)
class _SubnetAdapter(RowAdapter):
    """A Subnet by its Kea subnet ID, which :func:`settle_subnet_ids` gave its mapped row before the write.

    A member of the imported *shared_network* belongs to it. With *keep_membership*, a stored Subnet keeps its parent.
    Else the Subnet belongs to *dhcp_server*: the DHCP plugin holds one of the two. *stopped* is why the run does not
    write it at all: another row keeps its Kea subnet ID, or the ID move failed. Its subtree holds its DHCP Options,
    Pools and delegated-prefix Pools; its In-Subnet Reservations follow ``SubnetIdSettlement``.
    """

    scope: WriteScope
    key: SubnetKey
    planned: PlannedSubnet
    dhcp_server: Any
    claims: ClaimResult
    classes: ClassReferences
    shared_network: Any
    keep_membership: bool
    declared: Mapping[OptionDefinitionKey, OptionDefIntent]
    stopped: NotWritten | None
    changed_before: bool

    def blocked(self) -> NotWritten | None:
        """Return the taken Kea subnet ID or the failed ID move of the Subnet."""
        return self.stopped

    def new_row(self):
        """Return a new Subnet with a name that is unique across all DHCP servers."""
        return plugin_model("Subnet")(name=_subnet_name(self.scope.server, self.planned))

    def fields(self, row) -> dict:
        """Return the managed fields of the Subnet, with the Prefix that the IPAM claim gave it."""
        intent, family, summary = self.planned.intent, self.scope.family, self.scope.summary
        capabilities = self.scope.capabilities
        network = subnet_network(intent.cidr, family)
        result = self.claims.prefixes[str(network)]
        if result.prefix is None:
            raise RuntimeError("The Subnet Prefix could not be claimed")
        if result.outcome in {"conflict", "disagreement"}:
            summary.warn(f"subnet {network}: IPAM ownership {result.outcome}, Prefix left unchanged")
        source = Source(family, Kind.SUBNET, self.key.path(family))
        existing = row if row.pk is not None else None
        settings = self.planned.settings
        return {
            "prefix_id": result.prefix.pk,
            **_subnet_parent(existing, self.dhcp_server, self.shared_network, self.keep_membership),
            # settle_subnet_ids gave a mapped row its Kea subnet ID.
            "subnet_id": self.key.subnet_id,
            **settings_fields(row, settings, NETWORK_FIELDS, summary, source),
            **gated_values(row, settings, GATED_SUBNET_FIELDS, capabilities, summary, source),
            **user_context_fields(row, intent.user_context, capabilities, summary, source, "Subnet"),
        }

    def relations(self, row) -> dict[str, set[int]]:
        """Return the client classes and the DHCP server interface of the Subnet."""
        intent, family, summary = self.planned.intent, self.scope.family, self.scope.summary
        path = self.key.path(family)
        relations = self.classes.relations(intent, path, Kind.SUBNET, summary)
        interface = self.planned.settings.get(kea_paths.INTERFACE)
        relations["server_interfaces"] = _network_interface(
            self.dhcp_server, interface, path, Kind.SUBNET, family, summary
        )
        return relations

    def descendants(self) -> Iterator[tuple[Kind, str]]:
        """Yield the DHCP Options of the Subnet, then each Pool and delegated-prefix Pool with its Options."""
        family = self.scope.family
        yield from option_paths(planned_options(self.planned, family, self.declared), family)
        children: tuple[Planned, ...] = (*self.planned.pools, *self.planned.pd_pools)
        for pool in children:
            yield pool.key.kind, pool.key.path(family)
            yield from option_paths(planned_options(pool, family, self.declared), family)


def upsert_subnet(
    scope: WriteScope,
    dhcp_server,
    planned: PlannedSubnet,
    claims: ClaimResult,
    subnet_ids: SubnetIdSettlement,
    references: OptionReferences,
    shared_network,
    keep_membership: bool,
):
    """Get/create the DHCP-plugin ``Subnet`` for *planned*, tracked via ``KeaDhcpLink`` by its key.

    A Subnet whose Kea subnet ID another row keeps, or whose ID move failed, is not written. A Subnet that
    :func:`settle_subnet_ids` renumbered is updated. Return the ``netbox_dhcp.Subnet`` row, or ``None`` when it was
    not written: then its In-Subnet Reservations are not written either.
    """
    subnet_id = planned.key.subnet_id
    taken = subnet_ids.taken.get(subnet_id)
    stopped = taken if taken is not None else FAILED if subnet_id in subnet_ids.failed else None
    adapter = _SubnetAdapter(
        scope,
        planned.key,
        planned,
        dhcp_server,
        claims,
        references.classes,
        shared_network,
        keep_membership,
        references.definitions.declared,
        stopped,
        changed_before=subnet_id in subnet_ids.renumbered,
    )
    row = write_row(adapter)
    if isinstance(row, NotWritten):
        if taken is None:
            # Its Reservations must not attach to the stored row.
            subnet_ids.failed.add(subnet_id)
        return None
    return row


def _subnet_parent(existing, dhcp_server, shared_network, keep_membership: bool) -> dict:
    """Return the parent fields of a Subnet: its imported Shared Network, its stored parent, or *dhcp_server*."""
    if shared_network is not None:
        return {"dhcp_server_id": None, "shared_network_id": shared_network.pk}
    if keep_membership and existing is not None:
        return {"dhcp_server_id": existing.dhcp_server_id, "shared_network_id": existing.shared_network_id}
    return {"dhcp_server_id": dhcp_server.pk, "shared_network_id": None}


def _network_interface(dhcp_server, name, path: str, kind: Kind, family: int, summary: ImportSummary) -> set[int]:
    """Return the DHCP server interface that the Kea ``interface`` of the Subnet or Shared Network at *path* names.

    A name that matches no interface of *dhcp_server* has an entry. The import creates no interface.
    """
    if not name:
        return set()
    found = set(dhcp_server.interfaces.filter(name=name).values_list("pk", flat=True))
    if not found:
        entry = not_written(
            family,
            kind,
            kea_paths.setting(path, kea_paths.INTERFACE),
            Reason.NO_MATCHING_INTERFACE,
            no_interface_detail(dhcp_server, name),
        )
        summary.record(entry)
    return found


def _report_inherited(summary: ImportSummary, planned: PlannedSubnet, capabilities: PluginCapabilities) -> None:
    """Record each value that a Subnet inherits from its Shared Network, which this run did not import."""
    path = planned.key.path(planned.intent.family)
    name = planned.intent.shared_network
    if capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX):
        detail = f"Kea applies the value of Shared Network {name}, which was not imported."
    else:
        detail = f"Kea applies the value of Shared Network {name}, which the installed DHCP plugin cannot hold."
    for key in planned.inherited:
        entry = not_written(
            planned.intent.family,
            Kind.SUBNET,
            kea_paths.setting(path, key),
            Reason.INHERITED_FROM_SHARED_NETWORK,
            detail,
        )
        summary.record(entry)


@dataclass
class SubnetIdSettlement:
    """What :func:`settle_subnet_ids` found and did, by Kea subnet ID."""

    # Why each planned Subnet whose Kea subnet ID another row keeps is not written; its subtree has the same reason.
    taken: dict[int, NotWritten] = field(default_factory=dict)
    renumbered: set[int] = field(default_factory=set)
    # The Subnets that need a move that failed, and those whose write failed later in the run.
    failed: set[int] = field(default_factory=set)


def _freeing_moves(
    key: int, requester: int | None, holds: dict[int, int], wants: dict[int, int]
) -> dict[int, int] | None:
    """Return the moves (row to Subnet ID) that free *key* for the row *requester*, or ``None`` when a row keeps it.

    A mapped row wants the Kea subnet ID of its mapping, and frees its ID when it moves there. A chain that comes
    back to *requester* is a cycle. A chain that comes back to another row has two rows that want one ID.
    """
    moves: dict[int, int] = {}
    while (holder := holds.get(key)) is not None and holder != requester:
        wanted = wants.get(holder)
        if wanted is None or wanted == key or holder in moves:
            return None
        moves[holder] = wanted
        key = wanted
    return moves


def _subnet_id_taken(planned: PlannedSubnet, holder, capabilities: PluginCapabilities) -> NotWritten:
    """Return why the run does not write *planned*, whose Kea subnet ID *holder* keeps, nor any object in it."""
    subnet_id = planned.key.subnet_id
    claim = f"Subnet {planned.intent.cidr} needs Subnet ID {subnet_id}, which Subnet {holder.name!r} ({holder.prefix})"
    if capabilities.has(Capability.SUBNET_ID_PER_SERVER):
        return NotWritten(Reason.NOT_IN_SCOPE, f"{claim} of this DHCP server holds.", covers_subtree=True)
    detail = f"{claim} holds. The DHCP plugin needs each Subnet ID to be unique across all DHCP servers."
    return NotWritten(Reason.SUBNET_ID_CLASH, detail, Capability.SUBNET_ID_PER_SERVER, covers_subtree=True)


def _move_subnet_ids(rows: dict, moves: dict[int, int], holds: dict[int, int]) -> None:
    """Give each row in *moves* (row to Subnet ID) its ID once no row in *holds* (ID to row) holds it.

    When only a cycle is left, one row of it first takes an ID that no row holds or wants.
    """
    holds, pending, parked = dict(holds), dict(moves), set()
    while pending:
        pk = next((pk for pk, number in pending.items() if number not in holds), None)
        if pk is not None:
            number = pending.pop(pk)
        else:
            # Distinct targets, each held by a pending row, form cycles: parking one row of each breaks it.
            pk = next((pk for pk in pending if pk not in parked), None)
            if pk is None or any(holds[number] not in pending for number in pending.values()):
                raise RuntimeError("The Subnet ID moves do not resolve")
            parked.add(pk)
            number = next(free for free in count(1) if free not in holds and free not in moves.values())
        row = rows[pk]
        if holds.get(row.subnet_id) == pk:
            del holds[row.subnet_id]
        row.snapshot()
        row.subnet_id = number
        row.save()
        holds[number] = pk


def settle_subnet_ids(
    server, dhcp_server, plan: FamilyPlan, capabilities: PluginCapabilities, summary: ImportSummary
) -> SubnetIdSettlement:
    """Give each mapped Subnet of *plan* its Kea subnet ID, and find each planned Subnet whose ID another row keeps.

    A row that an earlier importer let the plugin number moves to its Kea subnet ID. So can a mapped row of another
    family or Server that holds the ID. The capability probe decides the scope of the plugin's uniqueness rule:
    all DHCP servers, or *dhcp_server* only.
    """
    Subnet = plugin_model("Subnet")
    planned = {subnet.key.subnet_id: subnet for subnet in plan.subnets}
    wants, ours = subnet_id_mappings(Subnet, server, plan.family, planned)
    current = dict(Subnet.objects.filter(pk__in=ours.values()).values_list("pk", "subnet_id"))
    scope = Subnet.objects.all()
    if capabilities.has(Capability.SUBNET_ID_PER_SERVER):
        scope = scope.filter(_served_by(dhcp_server))
    holds = dict(scope.values_list("subnet_id", "pk"))

    result = SubnetIdSettlement()
    moves: dict[int, int] = {}
    dependent: set[int] = set()
    # A planned Subnet keeps its ID from a mapped row of another family or Server. A new Subnet has no row yet.
    claimed = {key: ours.get(key, -key) for key in planned}
    for key, subnet in planned.items():
        requester = ours[key] if ours.get(key) in current else None
        chain = _freeing_moves(key, requester, holds, wants)
        if chain is not None and requester is not None and current[requester] != key:
            chain[requester] = key
        if chain is None or any(claimed.get(number, pk) != pk for pk, number in chain.items()):
            holder = Subnet.objects.select_related("prefix").get(pk=holds[key])
            result.taken[key] = _subnet_id_taken(subnet, holder, capabilities)
            continue
        claimed.update({number: pk for pk, number in chain.items()})
        moves.update(chain)
        if chain:
            dependent.add(key)
        if requester in chain:
            result.renumbered.add(key)
    if not moves:
        return result
    try:
        with event_scope.atomic():
            _move_subnet_ids(Subnet.objects.in_bulk(moves), moves, holds)
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:
        # The Subnets that need a move fail. The others still import.
        logger.exception("DHCP-plugin import: the Subnets of %s could not take their Kea subnet IDs", server.name)
        summary.warn(f"Kea Subnets {sorted(dependent)} could not take their Kea subnet IDs: {exc}")
        result.failed, result.renumbered = dependent, set()
    return result


@dataclass(frozen=True)
class ClassReferences:
    """The client classes that this run imported for one family, for the class lists of its other Kea objects."""

    family: int
    # The names that Kea's client-classes of this family defines.
    defined: frozenset[str]
    # The row of each class that this run wrote, by Kea name.
    imported: dict[str, int]

    def resolve(
        self, names: tuple[str, ...], parent_path: str, key: str, kind: Kind, summary: ImportSummary
    ) -> set[int]:
        """Return the imported client class of each name in the class list *key* of the *kind* at *parent_path*.

        A name without an imported class has an entry and is left out. The import never creates a class for it.
        """
        found = set()
        for name in names:
            if name in self.imported:
                found.add(self.imported[name])
                continue
            path = kea_paths.class_reference(parent_path, key, name)
            if name in self.defined:
                detail = _class_not_imported(name)
                summary.record(not_written(self.family, kind, path, Reason.PARENT_NOT_IMPORTED, detail))
            else:
                detail = f"The DHCP plugin has no row for {name}, a class that Kea's client-classes does not define."
                summary.record(not_written(self.family, kind, path, Reason.NO_PLUGIN_HOME, detail))
        return found

    def option_classes(self, names: tuple[str, ...], path: str, summary: ImportSummary) -> frozenset[int] | None:
        """Return the imported client class of each name of the DHCP Option at *path*, or ``None`` to skip it.

        An option whose class has no row is not imported: without the class it would reach more clients.
        """
        missing = next((name for name in names if name not in self.imported), None)
        if missing is None:
            return frozenset(self.imported[name] for name in names)
        if missing in self.defined:
            cause = _class_not_imported(missing)
        else:
            cause = f"The DHCP plugin has no row for {missing}, a class that Kea's client-classes does not define."
        detail = f"{cause} Without the class the option would reach more clients."
        summary.record(not_written(self.family, Kind.OPTION, path, Reason.PARENT_NOT_IMPORTED, detail))
        return None

    def has_pending_import(self, names: tuple[str, ...]) -> bool:
        """Return whether Kea defines a named class that this run did not import."""
        return any(name in self.defined and name not in self.imported for name in names)

    def relations(self, intent, parent_path: str, kind: Kind, summary: ImportSummary) -> dict[str, set[int]]:
        """Return the imported client classes of the class lists of the Shared Network, Subnet or Pool *intent*.

        A list that is not valid (``None``) is left out, so its relation stays as it is.
        """
        lists = (
            ("client_classes", kea_paths.CLIENT_CLASSES, intent.client_classes),
            ("evaluate_additional_classes", kea_paths.EVALUATE_ADDITIONAL_CLASSES, intent.evaluate_additional_classes),
        )
        return {
            relation: self.resolve(names, parent_path, key, kind, summary)
            for relation, key, names in lists
            if names is not None
        }


@dataclass(frozen=True)
class _PoolAdapter(RowAdapter):
    """A Pool of *subnet_obj* by its range, with the IP Range that the IPAM claim gave it.

    A Pool without an IP Range to attach is not written. It adopts a Pool that an import created before Pools had a
    mapping.
    """

    scope: WriteScope
    key: PoolKey | InvalidPoolKey
    intent: PoolIntent
    subnet_obj: Any
    claims: ClaimResult
    classes: ClassReferences
    options: PlannedOptions

    def _claim(self) -> RangeClaim | None:
        """Return the IPAM claim of the range, or ``None`` when the claim left the range out."""
        if not isinstance(self.key, PoolKey):
            return None
        pool = self.key.range
        return self.claims.ranges.get(f"{pool.start} - {pool.end}")

    def blocked(self) -> NotWritten | None:
        """Return why the Pool has no IP Range to attach. A failed claim raises: the write fails."""
        result = self._claim()
        if result is not None and result.outcome == "error":
            raise RuntimeError("The allocation Pool could not be claimed")
        if result is not None and result.outcome in {"conflict", "disagreement"}:
            self.scope.summary.warn(
                f"pool {self.intent.pool}: IPAM ownership {result.outcome}, IP Range left unchanged"
            )
        if result is None or result.ip_range is None:
            return _unusable_pool(self.key, result)
        return None

    def _range(self):
        result = self._claim()
        if result is None:
            raise RuntimeError("The Pool has no IP Range to attach.")
        return result.ip_range

    def adopt(self):
        """Return the unmapped Pool of the same Subnet and IP Range."""
        return unlinked(plugin_model("Pool").objects.filter(subnet=self.subnet_obj, ip_range=self._range())).first()

    def new_row(self):
        """Return a new Pool with a name that is unique in its Subnet."""
        return plugin_model("Pool")(name=_pool_name(self.subnet_obj, self.intent))

    def fields(self, row) -> dict:
        """Return the managed fields of the Pool."""
        family, summary, intent = self.scope.family, self.scope.summary, self.intent
        source = Source(family, Kind.POOL, self.key.path(family))
        return {
            "subnet_id": self.subnet_obj.pk,
            "ip_range_id": self._range().pk,
            "pool_id": declared_value(row, "pool_id", kea_paths.POOL_ID, intent.pool_id, None, summary, source),
            **settings_fields(row, intent.settings, POOL_FIELDS, summary, source),
            **user_context_fields(row, intent.user_context, self.scope.capabilities, summary, source, "Pool"),
        }

    def relations(self, row) -> dict[str, set[int]]:
        """Return the client classes of the Pool."""
        path = self.key.path(self.scope.family)
        return self.classes.relations(self.intent, path, Kind.POOL, self.scope.summary)

    def descendants(self) -> Iterator[tuple[Kind, str]]:
        """Yield the DHCP Options of the Pool."""
        yield from option_paths(self.options, self.scope.family)


def upsert_pools(scope: WriteScope, subnet_obj, planned: PlannedSubnet, references: OptionReferences, claims) -> None:
    """Get/create DHCP-plugin ``Pool`` rows (and their options) for each planned Pool of *planned*."""
    for planned_pool in planned.pools:
        options = planned_options(planned_pool, scope.family, references.definitions.declared)
        adapter = _PoolAdapter(
            scope, planned_pool.key, planned_pool.intent, subnet_obj, claims, references.classes, options
        )
        row = write_row(adapter)
        if not isinstance(row, NotWritten):
            upsert_options(scope, row, options, references)


def _pd_pool_prefixes(claims: ClaimResult, planned: Planned[PDPoolKey, PDPoolIntent], summary: ImportSummary) -> tuple:
    """Return the claimed NetBox Prefixes of a PD Pool: its prefix and its excluded prefix (``None`` without one).

    Raise when a claim gave no Prefix.
    """
    found: list = []
    for network in (planned.key.prefix, planned.intent.excluded_prefix):
        if network is None:
            found.append(None)
            continue
        result = claims.prefixes[str(network)]
        if result.prefix is None:
            raise RuntimeError(f"The Prefix {network} could not be claimed")
        if result.outcome in {"conflict", "disagreement"}:
            summary.warn(f"pd pool prefix {network}: IPAM ownership {result.outcome}, Prefix left unchanged")
        found.append(result.prefix)
    return tuple(found)


@dataclass(frozen=True)
class _PDPoolAdapter(RowAdapter):
    """A delegated-prefix Pool of *subnet_obj*, with the Prefixes that the IPAM claim gave it.

    It adopts no unmapped row: no release imported PD Pools before, so such a row is an operator's. The DHCP plugin
    checks the row when it saves it, and a PD Pool that the plugin refuses is unsupported.
    """

    scope: WriteScope
    key: PDPoolKey
    planned: Planned[PDPoolKey, PDPoolIntent]
    subnet_obj: Any
    claims: ClaimResult
    classes: ClassReferences
    options: PlannedOptions

    refused_reason = Reason.PLUGIN_GAP

    def new_row(self):
        """Return a new PD Pool with a name that is unique in its Subnet."""
        return plugin_model("PDPool")(name=_pd_pool_name(self.subnet_obj, self.key))

    def fields(self, row) -> dict:
        """Return the managed fields of the PD Pool."""
        family, summary, intent = self.scope.family, self.scope.summary, self.planned.intent
        prefix_obj, excluded_obj = _pd_pool_prefixes(self.claims, self.planned, summary)
        source = Source(family, Kind.PD_POOL, self.key.path(family))
        return {
            "subnet_id": self.subnet_obj.pk,
            "prefix_id": prefix_obj.pk,
            "delegated_length": self.key.delegated_length,
            "excluded_prefix_id": excluded_obj.pk if excluded_obj is not None else None,
            "pool_id": declared_value(row, "pool_id", kea_paths.POOL_ID, intent.pool_id, None, summary, source),
            **user_context_fields(
                row, intent.user_context, self.scope.capabilities, summary, source, "delegated-prefix Pool"
            ),
        }

    def relations(self, row) -> dict[str, set[int]]:
        """Return the client classes of the PD Pool."""
        path = self.key.path(self.scope.family)
        return self.classes.relations(self.planned.intent, path, Kind.PD_POOL, self.scope.summary)

    def descendants(self) -> Iterator[tuple[Kind, str]]:
        """Yield the DHCP Options of the PD Pool."""
        yield from option_paths(self.options, self.scope.family)


def upsert_pd_pools(
    scope: WriteScope, subnet_obj, planned: PlannedSubnet, references: OptionReferences, claims: ClaimResult
) -> None:
    """Get/create DHCP-plugin ``PDPool`` rows (and their options) for each planned delegated-prefix Pool of *planned*.

    A PD Pool that the DHCP plugin refuses is unsupported with the plugin's reason, and its options are skipped.
    """
    for planned_pd_pool in planned.pd_pools:
        options = planned_options(planned_pd_pool, scope.family, references.definitions.declared)
        adapter = _PDPoolAdapter(
            scope, planned_pd_pool.key, planned_pd_pool, subnet_obj, claims, references.classes, options
        )
        row = write_row(adapter)
        if not isinstance(row, NotWritten):
            upsert_options(scope, row, options, references)


def _unusable_pool(key: PoolKey | InvalidPoolKey, result: RangeClaim | None) -> NotWritten:
    """Return why a Pool has no IP Range to attach."""
    if isinstance(key, InvalidPoolKey):
        return NotWritten(Reason.INVALID_KEA_DATA, "The range is not valid or not inside the Subnet.")
    if result is None:
        # The claim leaves out a range that a NetBox IP Range cannot hold.
        return NotWritten(Reason.PLUGIN_GAP, "The range is larger than a NetBox IP Range can hold.")
    if result.outcome in {"conflict", "disagreement"}:
        return NotWritten(Reason.IPAM_OWNERSHIP, f"IPAM ownership {result.outcome}.")
    return NotWritten(Reason.WRITE_FAILED, "The IP Range could not be claimed.")


def _find_reservation(base, reservation: Reservation, mac_obj):
    """Find an existing reservation with the same typed identity in the parent scope."""
    id_type = reservation.identity.identifier_type
    identifier = reservation.identity.value
    if id_type == "hw-address":
        return base.filter(hw_address=mac_obj).first() if mac_obj is not None else None
    if id_type == "duid":
        return base.filter(duid=identifier).first()
    if id_type == "circuit-id":
        return base.filter(circuit_id=identifier).first()
    if id_type == "client-id":
        return base.filter(client_id=identifier).first()
    if id_type == "flex-id":
        return base.filter(flex_id=identifier).first()
    return None


@dataclass(frozen=True)
class _ReservationAdapter(RowAdapter):
    """One typed Reservation, in its Global or In-Subnet Scope (*subnet_obj*, ``None`` for a Global one).

    The mapping holds the Reservation Identity: the Kea subnet ID of an In-Subnet Reservation, or none for a
    Global one, and the identifier. A Global Reservation has no Subnet, and ``netbox_dhcp`` derives a
    reservation's family from one, so its family lives in the ``KeaDhcpLink`` identity
    instead.  Without it one identifier shares a single row between DHCPv4 and DHCPv6,
    merging ``ipv4_address`` and ``ipv6_addresses``.

    It consumes the IPAM claim results, so the plugin reservation shares the same ``ipam.IPAddress`` and
    ``dcim.MACAddress`` rows that the lease and Reservation sync owns. The client classes refer to the classes that the
    same run imported. The delegated and excluded Prefixes attach after their claim (:func:`_attach_delegated_prefixes`),
    so the caller records the outcome. *stopped* is why its Subnet was not written.
    """

    scope: WriteScope
    key: ReservationKey
    reservation: Reservation
    subnet_obj: Any
    dhcp_server: Any
    references: OptionReferences
    claims: ClaimResult
    catalogue: CatalogueSnapshot
    adoption_servers: tuple[int, ...]
    options: PlannedOptions
    stopped: NotWritten | None
    # The relations of the stored row that state() read: each related pk, with its Prefix if it has one.
    _stored: dict[str, dict[int, Any]] = field(default_factory=dict, init=False, repr=False, compare=False)

    late_outcome = True

    @cached_property
    def _addresses(self) -> tuple:
        """Return the claimed IPv4 address, the IPv6 addresses and the MAC address row of the Reservation."""
        ipv4_ip, ipv6_ips, mac_obj = _reservation_addresses(
            self.reservation, self.claims, self.catalogue, self.scope.summary
        )
        if self.reservation.identity.hardware_address is not None and mac_obj is None:
            raise RuntimeError("The reservation hardware address could not be resolved.")
        return ipv4_ip, ipv6_ips, mac_obj

    def _scope_name(self) -> str:
        if self.subnet_obj is not None:
            return self.subnet_obj.name
        return f"{self.scope.server.name} DHCPv{self.reservation.family}"

    def blocked(self) -> NotWritten | None:
        """Return why the Subnet of an In-Subnet Reservation was not written."""
        return self.stopped

    def adopt(self):
        """Return the row that an import made before its Reservation had a mapping (a Global one: before the family).

        So an upgrade maps that row instead of duplicating it.
        """
        HostReservation = plugin_model("HostReservation")
        if self.subnet_obj is not None:
            base = HostReservation.objects.filter(subnet=self.subnet_obj)
        else:
            base = HostReservation.objects.filter(dhcp_server__in=self.adoption_servers, subnet__isnull=True)
        return _find_reservation(unlinked(base), self.reservation, self._addresses[2])

    def new_row(self):
        """Return a new Reservation with a name that is unique in its Scope."""
        return plugin_model("HostReservation")(name=_reservation_name(self._scope_name(), self.reservation))

    def fields(self, row) -> dict:
        """Return the managed fields of the Reservation. Its Scope is managed: a row that an operator moved returns."""
        reservation, subnet_obj = self.reservation, self.subnet_obj
        ipv4_ip, _ipv6_ips, mac_obj = self._addresses
        source = Source(reservation.family, Kind.RESERVATION, self.key.path(reservation.family))
        return {
            "subnet_id": subnet_obj.pk if subnet_obj is not None else None,
            "dhcp_server_id": None if subnet_obj is not None else self.dhcp_server.pk,
            # The DHCP row mirrors the stored Kea hostname, not the published name.
            "hostname": reservation.hostname or None,
            **_reservation_identifier_values(reservation, mac_obj),
            # One row holds one family. _reservation_addresses returns the other
            # family empty, which also splits a row an earlier import merged.
            "ipv4_address_id": ipv4_ip.pk if ipv4_ip is not None else None,
            **_reservation_boot_values(reservation),
            **user_context_fields(
                row, reservation.user_context, self.scope.capabilities, self.scope.summary, source, "Reservation"
            ),
        }

    def relations(self, row) -> dict[str, set[int]]:
        """Return the IPv6 addresses, the client classes and the kept delegated and excluded Prefixes.

        A Prefix that Kea no longer reports goes before the delegated phase evaluates stale links. The reported
        Prefixes attach after their claim.
        """
        path = self.key.path(self.reservation.family)
        classes = self.references.classes.resolve(
            self.reservation.client_classes, path, kea_paths.CLIENT_CLASSES, Kind.RESERVATION, self.scope.summary
        )
        # An empty address list clears the previous IPv6 relations.
        relations = {"ipv6_addresses": {address.pk for address in self._addresses[1]}, "client_classes": classes}
        for relation, networks in _reported_prefixes(self.reservation).items():
            # state() read the relations of a stored row; a new row has none.
            current = self._stored[relation] if row.pk is not None else {}
            relations[relation] = {
                pk for pk, prefix in current.items() if ipaddress.ip_network(str(prefix)) in networks
            }
        return relations

    def state(self, row) -> RowState:
        """Return the state of the stored *row*. The one read of its relations also gives the Prefixes it keeps."""
        self._stored.update(_reservation_relations(row))
        relations = {name: frozenset(rows) for name, rows in self._stored.items()}
        return row_state(row, self.scope.capabilities, relations)

    def adoption_fields(self, row) -> dict:
        """Return the family-qualified name of an adopted Global row, so the other family can create its own row."""
        return {"name": _reservation_name(self._scope_name(), self.reservation)} if self.subnet_obj is None else {}

    def descendants(self) -> Iterator[tuple[Kind, str]]:
        """Yield the DHCP Options of the Reservation."""
        yield from option_paths(self.options, self.reservation.family)


def _reservation_boot_values(reservation: Reservation) -> dict:
    """Return the DHCPv4 boot fields of a DHCP plugin Reservation. Kea's unset value (and DHCPv6) is ``None``."""
    return {
        "next_server": str(reservation.next_server) if reservation.next_server is not None else None,
        "server_hostname": reservation.server_hostname or None,
        "boot_file_name": reservation.boot_file_name or None,
    }


def _reported_prefixes(reservation: Reservation) -> dict[str, tuple]:
    """Return the networks of each Prefix relation of a DHCP plugin Reservation: delegated and excluded prefixes."""
    return {
        "ipv6_prefixes": reservation.delegated_prefixes,
        "excluded_ipv6_prefixes": tuple(pair.excluded for pair in reservation.excluded_prefixes),
    }


# The managed many-to-many relations of a DHCP plugin Reservation.
_RESERVATION_RELATIONS = tuple(managed.name for managed in MANAGED_FIELDS["HostReservation"] if managed.relation)


def _reservation_relations(obj) -> dict[str, dict[int, Any]]:
    """Read each managed relation of the DHCP plugin Reservation *obj*: each related pk, with its Prefix if it has one.

    One query for each relation.
    """
    related: dict[str, dict[int, Any]] = {}
    for name in _RESERVATION_RELATIONS:
        rows = getattr(obj, name)
        if rows.model._meta.label == "ipam.Prefix":
            related[name] = dict(rows.values_list("pk", "prefix"))
        else:
            related[name] = dict.fromkeys(rows.values_list("pk", flat=True))
    return related


def _relation_states(objs) -> dict[int, dict[str, frozenset[int]]]:
    """Read the managed relations of every row in one query for each relation, keyed by row."""
    pks = [obj.pk for obj in objs]
    if not pks:
        # Without the DHCP plugin no row is imported, and its model does not exist.
        return {}
    states: dict[int, dict[str, set[int]]] = {pk: {name: set() for name in _RESERVATION_RELATIONS} for pk in pks}
    rows = plugin_model("HostReservation").objects.filter(pk__in=pks)
    for name in _RESERVATION_RELATIONS:
        for pk, related in rows.values_list("pk", name):
            if related is not None:
                states[pk][name].add(related)
    return {pk: {name: frozenset(related) for name, related in state.items()} for pk, state in states.items()}


def _record_address_claims(report: SyncReport, claims: ClaimResult) -> bool:
    """Keep ownership outcomes separate from the DHCP rows that consume them."""
    report.conflicts.update(claims.conflicts)
    complete = True
    for address, result in claims.addresses.items():
        if result.outcome == "error":
            complete = False
        elif result.outcome == "conflict":
            report.conflicts.add(address)
        elif result.outcome == "disagreement":
            report.disagreements.add(address)
    return complete


def _record_snapshot_diagnostics(observation: ReservationObservation, family: int, summary: ImportSummary) -> None:
    """Record each quarantined record, and one entry for a traversal that did not read every record."""
    snapshot = observation.snapshot
    traversal = []
    for diagnostic in snapshot.diagnostics:
        summary.warn(f"reservation {diagnostic.source_position}: {diagnostic.message}")
        if diagnostic.code in TRAVERSAL_DIAGNOSTIC_CODES:
            traversal.append(diagnostic.message)
            continue
        path = kea_paths.reservation_record(family, diagnostic.source_position)
        summary.record(not_written(family, Kind.RESERVATION, path, Reason.INVALID_KEA_DATA, diagnostic.message))
    if snapshot.traversal_truncated:
        detail = " ".join(traversal) or "The Reservation walk did not reach the last page."
        summary.record(
            not_written(family, Kind.RESERVATION, kea_paths.reservations(family), Reason.READ_FAILED, detail)
        )


def _reservation_subnet(
    scope: WriteScope, key: InSubnetReservationKey, subnet_ids: SubnetIdSettlement | None
) -> tuple[Any, NotWritten | None]:
    """Return the Subnet row of an In-Subnet Reservation, or why its Subnet was not written.

    A Subnet whose Kea subnet ID another row keeps gives its own reason. A Subnet whose write failed, or that has no
    mapped row, was not imported.
    """
    taken = subnet_ids.taken.get(key.subnet_id) if subnet_ids is not None else None
    if taken is not None:
        return None, taken
    subnet_obj = None
    if subnet_ids is None or key.subnet_id not in subnet_ids.failed:
        subnet_obj = mapped_target(scope.server, scope.family, SubnetKey(key.subnet_id).source)
    if subnet_obj is None:
        return None, NotWritten(Reason.PARENT_NOT_IMPORTED, f"Subnet {key.subnet_id} was not imported.")
    return subnet_obj, None


def import_reservation_snapshot(
    scope: WriteScope,
    dhcp_server,
    observation: ReservationObservation | None,
    references: OptionReferences,
    *,
    adoption_servers: tuple[int, ...],
    subnet_ids: SubnetIdSettlement | None = None,
) -> DelegatedPrefixStep | None:
    """Import valid typed records and report quarantined Snapshot records.

    A Global Reservation may adopt an unmapped row of a DHCP server in *adoption_servers*. An In-Subnet
    Reservation of a Subnet that *subnet_ids* reports as taken or failed is not imported.

    Return the delegated-prefix step of the imported Reservations for :func:`reconcile_delegated_prefixes`, or
    ``None`` when no Snapshot was read or their Prefixes could not be attached.
    """
    from ..ipam_reconciliation import ReservationPrefixClaim, ReservationPrefixPhase, claim
    from ..ipam_sources import RESERVATION, RESERVATION_PREFIX

    server, family, summary, capabilities = scope.server, scope.family, scope.summary, scope.capabilities
    if observation is None:
        summary.record(
            not_written(
                family,
                Kind.RESERVATION,
                kea_paths.reservations(family),
                Reason.READ_FAILED,
                "The Reservation Snapshot could not be read.",
            )
        )
        summary.ownership.incomplete.add(RESERVATION)
        return None
    snapshot = observation.snapshot
    _record_snapshot_diagnostics(observation, family, summary)
    claims = claim(server, snapshot.family, snapshot.records, force=False, catalogue=observation.catalogue)
    summary.owner_disagreements += sum(result.outcome == "disagreement" for result in claims.addresses.values())
    imported: list[tuple[Planned[ReservationKey, Reservation], LateOutcome]] = []
    complete = snapshot.complete and not snapshot.diagnostics
    complete = _record_address_claims(summary.ownership, claims) and complete
    for planned in keyed_reservations(observation):
        reservation, key = planned.intent, planned.key
        subnet_obj, stopped = None, None
        if isinstance(key, InSubnetReservationKey):
            subnet_obj, stopped = _reservation_subnet(scope, key, subnet_ids)
        options = planned_options(planned, family, references.definitions.declared)
        adapter = _ReservationAdapter(
            scope,
            key,
            reservation,
            subnet_obj,
            dhcp_server,
            references,
            claims,
            observation.catalogue,
            adoption_servers,
            options,
            stopped,
        )
        result = write_row(adapter)
        if isinstance(result, NotWritten):
            complete = False
            continue
        upsert_options(scope, result.row, options, references)
        imported.append((planned, result))
    records = [planned.intent for planned, _ in imported]
    networks = dict.fromkeys(
        network for record in records for each in _reported_prefixes(record).values() for network in each
    )
    step: DelegatedPrefixStep | None = None
    try:
        with event_scope.atomic():
            prefix_claims = claim(
                server, snapshot.family, [ReservationPrefixClaim(network) for network in networks], force=False
            )
            _attach_delegated_prefixes(
                [(planned.intent, late.row) for planned, late in imported], prefix_claims, summary
            )
        failed = frozenset(address for address, result in prefix_claims.prefixes.items() if result.outcome == "error")
        step = DelegatedPrefixStep(ReservationPrefixPhase(records, observation.cutoff, complete and not failed), failed)
        if complete:
            summary.ownership.completed_sources.add(RESERVATION)
        else:
            summary.ownership.incomplete.add(RESERVATION)
    except event_scope.EventDispatchError:
        raise
    except Exception:
        summary.record(
            not_written(
                family,
                Kind.RESERVATION,
                kea_paths.reservations(family),
                Reason.WRITE_FAILED,
                "Delegated Prefixes could not be attached. See server logs.",
            )
        )
        summary.ownership.incomplete.add(RESERVATION_PREFIX)
        logger.exception("Could not attach delegated Prefixes after DHCP import")
        summary.warn("Delegated Prefixes could not be attached. See server logs.")
    relations = _relation_states([late.row for _, late in imported])
    for planned, late in imported:
        if late.before is None or late.before != row_state(late.row, capabilities, relations[late.row.pk]):
            outcome = Outcome.CREATED if late.before is None else Outcome.UPDATED
            summary.record(written(family, Kind.RESERVATION, planned.key.path(family), outcome))
    return step


@dataclass(frozen=True)
class DelegatedPrefixStep:
    """The delegated-prefix phase of the imported Reservations, and the Prefixes whose claim failed before attachment."""

    phase: ReservationPrefixPhase
    failed: frozenset[str]


def reconcile_delegated_prefixes(
    server, family: Family, step: DelegatedPrefixStep, unobserved: set[Kind], summary: ImportSummary
) -> None:
    """Link the delegated and excluded Prefixes of the imported Reservations again, and drop the stale links (ADR 0006).

    It runs after :func:`remove_stale_objects`: a removed Reservation no longer uses its Prefixes, so the cleanup can
    deprecate them. A Reservation that Kea no longer reports and that is still in NetBox (*unobserved*, see
    :func:`unobserved_kinds`) still uses its Prefixes, so the phase is then not complete and drops no link. A Prefix
    whose claim failed before attachment counts as one error, also when this claim of it succeeds.
    """
    from ..ipam_reconciliation import reconcile

    complete = step.phase.complete and Kind.RESERVATION not in unobserved
    report = reconcile(server, family, [replace(step.phase, complete=complete)])
    _record_report(summary, report)
    summary.ownership_errors += sum(report.prefixes[address].outcome != "error" for address in step.failed)
    for address in sorted(report.conflicts):
        summary.warn(f"delegated prefix {address}: IPAM ownership conflict, Prefix left unchanged")


def _attach_delegated_prefixes(imported, claims: ClaimResult, summary: ImportSummary) -> None:
    """Attach each imported Reservation's delegated and excluded Prefixes, and keep the old ones when a claim failed."""
    for reservation, obj in imported:
        reported = _reported_prefixes(reservation)
        if any(claims.prefixes[str(prefix)].outcome == "error" for each in reported.values() for prefix in each):
            summary.warn(
                f"reservation {reservation.identity.value}: delegated or excluded Prefix claim failed; "
                "existing reported Prefix attachments were retained"
            )
            continue
        for relation, networks in reported.items():
            results = (claims.prefixes[str(prefix)] for prefix in networks)
            getattr(obj, relation).set([result.prefix for result in results if result.prefix is not None])


def _reservation_identifier_values(reservation: Reservation, mac_obj) -> dict:
    """Return the identifier fields of a DHCP-plugin reservation: its single Kea identifier, the others cleared."""
    identity = reservation.identity
    values: dict = {"hw_address_id": None, "duid": None, "circuit_id": None, "client_id": None, "flex_id": None}
    # Each Kea identifier type names its plugin field.
    field_name = identity.identifier_type.replace("-", "_")
    if field_name == "hw_address":
        values["hw_address_id"] = mac_obj.pk
    else:
        values[field_name] = identity.value
    return values


def _claim_config_networks(server, plan: FamilyPlan):
    """Group every planned Subnet, Pool and delegated-prefix Pool prefix before claiming any of the three sources."""
    from ..ipam_reconciliation import PDPoolClaim, PoolClaim, SubnetClaim, claim

    subnets: list[SubnetClaim] = []
    pools: list[PoolClaim] = []
    for planned in plan.subnets:
        try:
            network = subnet_network(planned.intent.cidr, planned.intent.family)
        except ValueError:
            continue
        subnets.append(SubnetClaim(network))
        pools.extend(PoolClaim(pool.key.range, network) for pool in planned.pools if isinstance(pool.key, PoolKey))
    prefixes = [PDPoolClaim(prefix) for prefix in pd_pool_prefixes(plan)]
    return (
        claim(server, plan.family, subnets, force=False),
        claim(server, plan.family, pools, force=False),
        claim(server, plan.family, prefixes, force=False),
    )


def pd_pool_prefixes(plan: FamilyPlan) -> list:
    """Return the prefix and the excluded prefix of each planned delegated-prefix Pool, each once, in plan order."""
    networks = (
        network
        for subnet in plan.subnets
        for pd_pool in subnet.pd_pools
        for network in (pd_pool.key.prefix, pd_pool.intent.excluded_prefix)
        if network is not None
    )
    return list(dict.fromkeys(networks))


def reconcile_pd_pool_prefixes(
    server, plan: FamilyPlan, observed: Mapping[Kind, KindObservation], unobserved: set[Kind], summary: ImportSummary
) -> None:
    """Link the Prefixes of every planned delegated-prefix Pool again, and drop the stale ``pd-pool`` links (ADR 0006).

    It runs after :func:`remove_stale_objects`: a removed PD Pool no longer uses its Prefix, so the cleanup can
    deprecate it. Only a Complete observation of delegated-prefix Pools (*observed*), with a cutoff, drops a link. A PD
    Pool that Kea no longer reports and that is still in NetBox (*unobserved*) still uses its Prefixes, so the phase is
    then not complete.
    """
    from ..ipam_reconciliation import PDPoolPhase, reconcile

    complete = observed[Kind.PD_POOL].complete and Kind.PD_POOL not in unobserved
    report = reconcile(server, plan.family, [PDPoolPhase(pd_pool_prefixes(plan), plan.cutoff, complete)])
    _record_report(summary, report)


def _record_report(summary: ImportSummary, report: SyncReport) -> None:
    """Add the ownership work, the errors and the owner disagreements of one ``reconcile`` call to *summary*."""
    summary.ownership.merge(report)
    summary.ownership_errors += report.errors + report.prefix_errors
    summary.owner_disagreements += len(report.disagreements)


def unobserved_kinds(judgment: StaleJudgment, removed: set[MappingSource]) -> set[Kind]:
    """Return the kinds that still have a mapped DHCP plugin row whose Kea source the read does not observe.

    *removed* holds the sources that :func:`remove_stale_objects` removed. Each other unobserved row stayed: its kind
    was not observed in full, its removal failed or was blocked, another writer confirmed its mapping after the cutoff,
    or the plan has no cutoff.
    """
    return {
        kind
        for kind, judged in judgment.kinds.items()
        if judged.not_judged or judged.kept or judged.newer or judged.removable.keys() - removed
    }


# ─────────────────────────────────────────────────────────────────────────────
# Stale DHCP Import Objects: removal after a Complete observation of their kind
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _StaleRow:
    """A mapped row whose Kea source the run did not observe."""

    source: MappingSource
    # A DHCP plugin model instance; the plugin is optional, so its models have no static type here.
    target: Any


def _row_key(obj) -> tuple:
    return obj._meta.concrete_model, obj.pk


def _goes_with_parent(model) -> bool:
    """Return whether rows of *model* go with a deleted parent: models outside the DHCP plugin, Options, through rows.

    A mapped Option goes only when it is stale itself (:func:`_removal_plan`).
    """
    return model._meta.app_label != PLUGIN_APP_LABEL or model._meta.auto_created or model is plugin_model("Option")


def _counted_rows(rows: list) -> str:
    """Return the number of *rows* of each model, for the detail of an entry."""
    models = Counter(row._meta.concrete_model for row in rows)
    return ", ".join(
        counted(count, model._meta.verbose_name, model._meta.verbose_name_plural) for model, count in models.items()
    )


class _FootprintCollector(Collector):
    """A delete collector that leaves out the Options that the removal deletes before its row."""

    def __init__(self, using: str, deleted_first: frozenset[int]) -> None:
        super().__init__(using=using)
        self.deleted_first = deleted_first

    def related_objects(self, related_model, related_fields, objs):
        """Return the related rows of *objs*, without the Options that go first."""
        rows = super().related_objects(related_model, related_fields, objs)
        return rows.exclude(pk__in=self.deleted_first) if related_model is plugin_model("Option") else rows


def _collected(collector: Collector) -> list:
    rows = [obj for objects in collector.data.values() for obj in objects]
    rows.extend(obj for queryset in collector.fast_deletes for obj in queryset)
    return rows


def _owner_key(option) -> tuple:
    """Return the row key of the object that *option* is assigned to."""
    return option.assigned_object_type.model_class()._meta.concrete_model, option.assigned_object_id


def _option_goes_with(option, stale: dict, mapped_options: frozenset[tuple]) -> tuple | None:
    """Return the row whose removal takes *option*: the Option when it is stale, its owner when it is unmapped.

    Return ``None`` for a mapped Option that the run keeps: no removal takes it.
    """
    own = _row_key(option)
    if own in stale:
        return own
    return None if own in mapped_options else _owner_key(option)


def _class_relation_rows(targets: Iterable[tuple]) -> dict[tuple, list]:
    """Return the DHCP plugin rows that name each row key of *targets* in a many-to-many relation, by row key.

    A relation such as ``client_classes`` takes one query for all *targets*, whatever their number.
    """
    pks: dict[Any, list] = {}
    for model, pk in targets:
        pks.setdefault(model, []).append(pk)
    rows: dict[tuple, dict[tuple, Any]] = {}
    for model in apps.get_app_config(PLUGIN_APP_LABEL).get_models():
        for relation in model._meta.many_to_many:
            if relation.related_model in pks:
                named: Any = model.objects.filter(**{f"{relation.name}__in": pks[relation.related_model]})
                for row in named.annotate(named_pk=F(relation.name)):
                    rows.setdefault((relation.related_model, row.named_pk), {})[_row_key(row)] = row
    return {key: list(each.values()) for key, each in rows.items()}


@dataclass(frozen=True)
class _RemovalPlan:
    """The read-only plan of the delete of one stale row, with its evidence as row keys."""

    # The Options to delete before the row: each uses a definition that the delete removes, and it or its owner goes.
    options_first: tuple = ()
    # The other stale rows that the delete removes.
    cascaded: frozenset = frozenset()
    # The other stale rows that must go too, or the delete would remove or change a kept row: the rows that it
    # removes, the rows that name it in a class relation, and the stale Options, or the owners, that go with it.
    relies_on: frozenset = frozenset()
    # Why the row stays whatever else the run removes, for its entry. Empty when only kept stale rows can block it.
    blocked: str = ""


def _removal_plan(target, stale: dict, mapped_options: frozenset[tuple], named_by: dict[tuple, list]) -> _RemovalPlan:
    """Plan the delete of the stale row *target* against every *stale* row of the run. It writes nothing.

    A row outside *stale* is kept: when the delete would remove it, when it uses a row that the delete removes, or when
    it names the row in a many-to-many relation (without it, that row would reach more clients), the row stays. Each
    stale row with such a part is evidence in ``relies_on``. A stale Option goes alone, and an unmapped Option goes with
    the object that it is assigned to. A mapped Option of *mapped_options* outside *stale* is kept. *named_by* gives the
    rows that name each stale row in a many-to-many relation.
    """
    Option = plugin_model("Option")
    own = _row_key(target)
    first: dict[int, Any] = {}
    while True:
        collector = _FootprintCollector(target._state.db, frozenset(first))
        try:
            collector.collect([target])
            break
        except ProtectedError as error:
            removed = {own, *(_row_key(obj) for obj in _collected(collector)), *stale}
            protected = list(error.protected_objects)
            going = [
                obj
                for obj in protected
                if isinstance(obj, Option) and _option_goes_with(obj, stale, mapped_options) in removed
            ]
            if len(going) < len(protected):
                users = [obj for obj in protected if obj not in going]
                return _RemovalPlan(blocked=f"It is kept while it is in use by {_counted_rows(users)}.")
            first.update((obj.pk, obj) for obj in going)
    rows = _collected(collector)
    footprint = {own, *(_row_key(obj) for obj in rows)}
    # Counts only: any viewer of the Server reads the run, without permission on the rows.
    kept = [
        obj
        for obj in rows
        if _row_key(obj) not in stale
        and _row_key(obj) != own
        and (_row_key(obj) in mapped_options or not _goes_with_parent(obj._meta.concrete_model))
    ]
    if kept:
        return _RemovalPlan(blocked=f"It is kept because its removal would also remove {_counted_rows(kept)}.")
    cascaded = frozenset(_row_key(obj) for obj in rows if _row_key(obj) != own and _row_key(obj) in stale)
    relies_on = {*cascaded, *(_option_goes_with(obj, stale, mapped_options) for obj in first.values())}
    users = []
    for obj in named_by.get(own, ()):
        goes_with = _option_goes_with(obj, stale, mapped_options) if isinstance(obj, Option) else _row_key(obj)
        if goes_with is not None and (goes_with in stale or goes_with in footprint):
            relies_on.add(goes_with)
        else:
            users.append(obj)
    if users:
        return _RemovalPlan(blocked=f"It is kept while a class list of {_counted_rows(users)} names it.")
    return _RemovalPlan(tuple(first.values()), cascaded, frozenset(relies_on & stale.keys() - {own}))


def _keep_dependents(start: tuple, dependents: dict, alive: set, kept: dict, detail: str) -> list[tuple]:
    """Keep every row of *alive* that relies on the row *start*, directly or through other rows, with *detail*.

    Return the rows that it kept, in the order that it found them.
    """
    found: list[tuple] = []
    work = [start]
    while work:
        for key in dependents.get(work.pop(), ()):
            if key in alive:
                alive.discard(key)
                kept[key] = detail
                found.append(key)
                work.append(key)
    return found


def _dependents(plans: dict[tuple, _RemovalPlan]) -> dict[tuple, set[tuple]]:
    """Return the rows whose plan relies on each row: the reverse index of ``relies_on``."""
    index: dict[tuple, set[tuple]] = {}
    for key, plan in plans.items():
        for each in plan.relies_on:
            index.setdefault(each, set()).add(key)
    return index


def _relied_on_detail(row: _StaleRow, what: str) -> str:
    return f"It is kept because its removal relies on the removal of {_counted_rows([row.target])}, which {what}."


def _removal_set(
    stale: dict[tuple, _StaleRow], mapped_options: frozenset[tuple]
) -> tuple[dict[tuple, _RemovalPlan], dict[tuple, str]]:
    """Return the largest subset of stale rows whose deletion removes or changes no kept row.

    Return the plan of each row of that subset, and why each other stale row stays. Each plan is read once; a row that
    stays keeps every row that relies on it, through the reverse index.
    """
    named_by = _class_relation_rows(stale)
    plans = {key: _removal_plan(row.target, stale, mapped_options, named_by) for key, row in stale.items()}
    kept = {key: plan.blocked for key, plan in plans.items() if plan.blocked}
    alive = set(plans) - kept.keys()
    dependents = _dependents(plans)
    for key in list(kept):
        _keep_dependents(key, dependents, alive, kept, _relied_on_detail(stale[key], "is kept"))
    return {key: plan for key, plan in plans.items() if key in alive}, kept


def _components(plans: dict[tuple, _RemovalPlan]) -> list[list[tuple]]:
    """Return the strongly connected components of the ``relies_on`` graph, each after every component it relies on.

    Rows that rely on each other form one component. Tarjan's algorithm, without recursion, gives the components in
    this order. The rows and edges follow the order of *plans*, so the result does not change between runs.
    """
    order = {key: position for position, key in enumerate(plans)}

    def edges(key: tuple):
        return iter(sorted(plans[key].relies_on & plans.keys(), key=order.__getitem__))

    index: dict[tuple, int] = {}
    low: dict[tuple, int] = {}
    stack: list[tuple] = []
    on_stack: set[tuple] = set()
    components: list[list[tuple]] = []

    def visit(key: tuple) -> None:
        index[key] = low[key] = len(index)
        stack.append(key)
        on_stack.add(key)

    for root in plans:
        if root in index:
            continue
        visit(root)
        work = [(root, edges(root))]
        while work:
            key, successors = work[-1]
            for successor in successors:
                if successor not in index:
                    visit(successor)
                    work.append((successor, edges(successor)))
                    break
                if successor in on_stack:
                    low[key] = min(low[key], index[successor])
            else:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[key])
                if low[key] == index[key]:
                    component = []
                    while (member := stack.pop()) != key:
                        on_stack.discard(member)
                        component.append(member)
                    on_stack.discard(key)
                    components.append(sorted([*component, key], key=order.__getitem__))
    return components


def _delete_component(
    keys: list[tuple], plans: dict, removable: dict, removed: set, family: int, summary: ImportSummary
) -> tuple[list[tuple], tuple | None]:
    """Delete the rows of one component in one transaction, all or nothing, through the ORM.

    The ORM delete runs the guards, the mapping cleanup and the change log. Return the rows that the component
    removed, and ``None``; or no rows and the row whose delete failed, which has a write-failed entry.
    """
    gone: list[tuple] = []
    current = keys[0]
    try:
        with event_scope.atomic():
            for current in keys:
                if current in removed or current in gone:
                    continue
                plan = plans[current]
                # An Option that the delete of its own owner already removed is gone.
                for option in plugin_model("Option").objects.filter(
                    pk__in=[option.pk for option in plan.options_first]
                ):
                    option.delete()
                removable[current].target.delete()
                gone += [current, *(each for each in plan.cascaded if each not in removed and each not in gone)]
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001 (one failed removal must not abort the import)
        source = removable[current].source
        summary.record(FAILED.entry(family, source.kind, source.path(family)))
        summary.warn(f"stale {source.kind.value} {source.path(family)}: {exc}")
        return [], current
    return gone, None


@dataclass(frozen=True)
class KeptRow:
    """A stale row that the run keeps, and why, in counts only: a viewer of the Server may not view the rows."""

    # A DHCP plugin model instance; the plugin is optional, so its models have no static type here.
    target: Any
    reason: str


@dataclass(frozen=True)
class KindJudgment:
    """How one read judges the mapped rows of one kind, each by its Kea source."""

    # The rows whose source the read reports.
    observed: dict[MappingSource, Any]
    # The stale rows that the run removes.
    removable: dict[MappingSource, Any]
    # The stale rows that the run keeps, because a row that it keeps uses them.
    kept: dict[MappingSource, KeptRow]
    # The unobserved rows that a gap of the observation covers, and the gaps.
    not_judged: dict[MappingSource, Any]
    gaps: tuple[str, ...]
    # The unobserved rows that the read cannot judge: confirmed at or after the cutoff, or every one without a cutoff.
    newer: dict[MappingSource, Any]


@dataclass(frozen=True)
class StaleJudgment:
    """The judgment of every mapped row of one family against one read, and the read-only plan of its removal."""

    kinds: dict[Kind, KindJudgment]
    # Each stale row by row key, children first: the order of the removal.
    stale: dict[tuple, _StaleRow]
    # The delete plan of each removable row, by row key.
    plans: dict[tuple, _RemovalPlan]
    # Why each kept row stays, by row key, in the order that the removal plan found it.
    staying: dict[tuple, str]


def stale_judgment(server, plan: FamilyPlan, observed: Mapping[Kind, KindObservation]) -> StaleJudgment:
    """Judge each mapped row of the family of *plan* against the read that *observed* gives. It writes nothing.

    A mapping confirmed with a number at or above the cutoff of the plan belongs to a newer read, so it is never stale
    here. The import lock keeps two runs of one Server apart; the cutoff covers the other writers, such as an ADR 0008
    merge or revert replay in main. A plan without a cutoff can judge no unobserved mapping. :func:`_removal_set` then
    finds the stale rows whose deletion removes or changes no kept row, and no mapped Option that the run keeps.
    """
    family = plan.family
    judged: dict[Kind, dict[MappingSource, Any]] = {kind: {} for kind in mapped_kinds(family)}
    newer: dict[Kind, dict[MappingSource, Any]] = {kind: {} for kind in mapped_kinds(family)}
    for source, link in mapped_links(server, family):
        unordered = plan.cutoff is None or link.confirmation >= plan.cutoff
        rows = newer if unordered and source not in observed[source.kind].sources else judged
        rows[source.kind][source] = link.sys4_object
    splits = {kind: observed[kind].judge(rows, family) for kind, rows in judged.items()}
    stale = {_row_key(row): _StaleRow(source, row) for split in splits.values() for source, row in split.stale.items()}
    plans, staying = _removal_set(stale, mapped_option_keys())
    kinds = {
        kind: KindJudgment(
            observed=split.observed,
            removable={source: row for source, row in split.stale.items() if _row_key(row) in plans},
            kept={
                source: KeptRow(row, staying[_row_key(row)])
                for source, row in split.stale.items()
                if _row_key(row) in staying
            },
            not_judged=split.not_judged,
            gaps=split.gaps,
            newer=newer[kind],
        )
        for kind, split in splits.items()
    }
    return StaleJudgment(kinds, stale, plans, staying)


def remove_stale_objects(judgment: StaleJudgment, family: int, summary: ImportSummary) -> set[MappingSource]:
    """Remove each removable Stale DHCP Import Object of *judgment*, children first, report it, and return its source.

    Each kind with rows that its Incomplete observation cannot judge has one entry that says why, and each kept stale
    row has its own. Rows that rely on each other form one component, which goes in one transaction, all or nothing,
    after every component that it relies on. When a component fails, every pending row that relies on it, directly or
    through other rows, is kept too. IPAM objects stay: the DHCP plugin rows only reference them.
    """
    for kind, judged in judgment.kinds.items():
        if judged.not_judged:
            label = KIND_LABELS[kind]
            kept = counted(len(judged.not_judged), f"mapped {label} row was", f"mapped {label} rows were")
            detail = f"{' '.join(judged.gaps)} {kept} kept."
            summary.record(not_written(family, kind, kind_path(family, kind), Reason.INCOMPLETE_OBSERVATION, detail))
    removable, plans = judgment.stale, judgment.plans
    for key, detail in judgment.staying.items():
        _record_kept(removable[key], detail, family, summary)
    # A deleted instance has no pk, so every key comes from before the deletes.
    dependents = _dependents(plans)
    pending = set(plans)
    removed: set[tuple] = set()
    for component in _components(plans):
        if not pending.issuperset(component):
            # A failed component that it relies on keeps it.
            continue
        pending.difference_update(component)
        gone, failed = _delete_component(component, plans, removable, removed, family, summary)
        if failed is None:
            removed.update(gone)
            for source in (removable[each].source for each in gone):
                summary.record(written(family, source.kind, source.path(family), Outcome.REMOVED))
            continue
        together = _together_detail(removable[failed])
        for key in component:
            if key != failed:
                _record_kept(removable[key], together, family, summary)
        relied_on: dict[tuple, str] = {}
        for key in component:
            detail = _relied_on_detail(removable[key], "failed" if key == failed else "is kept")
            for each in _keep_dependents(key, dependents, pending, relied_on, detail):
                _record_kept(removable[each], detail, family, summary)
    return {removable[key].source for key in removed}


def _together_detail(row: _StaleRow) -> str:
    return f"It is kept because it is removed together with {_counted_rows([row.target])}, whose removal failed."


def _record_kept(row: _StaleRow, detail: str, family: int, summary: ImportSummary) -> None:
    summary.record(not_written(family, row.source.kind, row.source.path(family), Reason.REMOVAL_BLOCKED, detail))


# The DHCP plugin rows that apply_plan adds and changes.
_PLUGIN_UPSERTS = tuple(
    f"{PLUGIN_APP_LABEL}.{action}_{model}"
    for model in (
        "dhcpserver",
        "optiondefinition",
        "option",
        "clientclass",
        "sharednetwork",
        "subnet",
        "pool",
        "pdpool",
        "hostreservation",
    )
    for action in ("add", "change")
)


def _removal_permissions() -> tuple[str, ...]:
    """Return the delete permission of each model that a stale removal deletes, Options included."""
    from ..models import MAPPING_KINDS

    return tuple(f"{PLUGIN_APP_LABEL}.delete_{MAPPING_KINDS[kind][0].lower()}" for kind in REMOVAL_ORDER)


def import_permissions(server) -> tuple[str, ...]:
    """Return the IPAM, DCIM and DHCP plugin permissions that :func:`apply_plan` can use.

    The import claims Subnets, Pools, delegated-prefix Pool Prefixes and Reservations, reconciles the delegated Prefixes
    and the delegated-prefix Pool Prefixes, writes the DHCP plugin rows, and removes Stale DHCP Import Objects.
    """
    from ..ipam_reconciliation import (
        PDPoolPhase,
        PoolPhase,
        ReservationPrefixPhase,
        SubnetPhase,
        claim_permissions,
        reconcile_permissions,
    )
    from ..ipam_sources import RESERVATION

    claims = claim_permissions(SubnetPhase.source, PoolPhase.source, PDPoolPhase.source, RESERVATION)
    reconciles = reconcile_permissions(server, ReservationPrefixPhase.source, PDPoolPhase.source)
    return tuple(dict.fromkeys((*claims, *reconciles, *_PLUGIN_UPSERTS, *_removal_permissions())))


def import_server_config(
    server,
    config: ServerConfigIntent,
    reservation_observation: ReservationObservation | None = None,
) -> ImportSummary:
    """Plan one parsed ``(server, family)`` Kea config, probe the installed DHCP plugin, and apply the plan to it."""
    return apply_plan(server, plan_family(config, reservation_observation), probe())


def _import_definitions_and_classes(
    scope: WriteScope, dhcp_server, plan: FamilyPlan, adoption_servers: tuple[int, ...]
) -> tuple[OptionReferences, dict]:
    """Write every custom Option Definition and client class of *plan*, before any DHCP Option references them.

    Return what the Options can reference, and the row of each imported client class by Kea name.
    """
    definitions = CustomDefinitions(plan.declared_definitions, adoption_servers)
    for planned in plan.option_definitions:
        write_option_definition(scope, definitions, planned.key, dhcp_server)
    rows = {}
    for planned_class in plan.client_classes:
        row = upsert_client_class(scope, dhcp_server, planned_class, definitions)
        if row is not None:
            rows[planned_class.key.name] = row
    defined = frozenset(planned.key.name for planned in plan.client_classes)
    classes = ClassReferences(plan.family, defined, {name: row.pk for name, row in rows.items()})
    return OptionReferences(definitions, classes), rows


@coordinated_import
def apply_plan(server, plan: FamilyPlan, capabilities: PluginCapabilities) -> ImportSummary:
    """Apply the plan of one ``(server, family)`` to the DHCP plugin, writing a gated fact only with its *capabilities*.

    Idempotent: re-running finds each row through its ``KeaDhcpLink`` mapping and updates it rather than
    duplicating it.
    """
    from ..ipam_sources import POOL, RESERVATION, SUBNET

    summary = ImportSummary()
    scope = WriteScope(server, plan.family, summary, capabilities)
    root = plan.server.key.path(plan.family)
    invalid = (
        not_written(plan.family, dropped.kind, dropped.path, Reason.INVALID_KEA_DATA, dropped.detail)
        for dropped in plan.dropped
    )
    for entry in (*invalid, *plan.not_imported):
        summary.record(entry)
    dhcp_server, created = upsert_dhcp_server(server, plan.family)
    adopting = adoption_servers(server, dhcp_server)

    values = server_values(dhcp_server, plan.server, plan.family, capabilities, summary)
    changed = apply_global_settings(dhcp_server, values, summary, plan.family, capabilities)
    linked = link_interfaces(dhcp_server, plan.server.interfaces, summary, plan.family)
    if changed is not None and (created or changed or linked):
        summary.record(written(plan.family, Kind.SERVER, root, Outcome.CREATED if created else Outcome.UPDATED))
    references, class_rows = _import_definitions_and_classes(scope, dhcp_server, plan, adopting)
    declared = references.definitions.declared
    planned_classes = {planned.key.name: planned for planned in plan.client_classes}
    upsert_options(scope, dhcp_server, planned_options(plan.server, plan.family, declared), references)
    for name, row in class_rows.items():
        upsert_options(scope, row, planned_options(planned_classes[name], plan.family, declared), references)
    networks = _import_shared_networks(scope, dhcp_server, plan, references)

    prefix_claims, pool_claims, pd_pool_claims = _claim_config_networks(server, plan)
    summary.owner_disagreements += sum(
        result.outcome == "disagreement" for result in (*prefix_claims.prefixes.values(), *pool_claims.ranges.values())
    )
    subnet_ids = settle_subnet_ids(server, dhcp_server, plan, capabilities, summary)
    for planned_subnet in plan.subnets:
        name = planned_subnet.intent.shared_network
        network = networks.get(name)
        # A member of a Shared Network that this run could hold but did not write keeps its stored parent.
        keep = name is not None and network is None and capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX)
        subnet_obj = upsert_subnet(
            scope, dhcp_server, planned_subnet, prefix_claims, subnet_ids, references, network, keep
        )
        if subnet_obj is None:
            continue
        if network is None:
            _report_inherited(summary, planned_subnet, capabilities)
        upsert_options(scope, subnet_obj, planned_options(planned_subnet, plan.family, declared), references)
        upsert_pools(scope, subnet_obj, planned_subnet, references, pool_claims)
        upsert_pd_pools(scope, subnet_obj, planned_subnet, references, pd_pool_claims)
    for source, outcomes in ((SUBNET, prefix_claims.prefixes), (POOL, pool_claims.ranges)):
        if any(result.outcome == "error" for result in outcomes.values()):
            summary.ownership.incomplete.add(source)
        else:
            summary.ownership.completed_sources.add(source)
        summary.ownership.conflicts.update(
            address for address, result in outcomes.items() if result.outcome == "conflict"
        )
        summary.ownership.disagreements.update(
            address for address, result in outcomes.items() if result.outcome == "disagreement"
        )
    delegated_step = import_reservation_snapshot(
        scope, dhcp_server, plan.reservations, references, adoption_servers=adopting, subnet_ids=subnet_ids
    )
    observed = observations(plan)
    judgment = stale_judgment(server, plan, observed)
    unobserved = unobserved_kinds(judgment, remove_stale_objects(judgment, plan.family, summary))
    if delegated_step is not None:
        reconcile_delegated_prefixes(server, plan.family, delegated_step, unobserved, summary)
    if plan.family == 6:
        reconcile_pd_pool_prefixes(server, plan, observed, unobserved, summary)
    if not plan.configuration_complete:
        summary.ownership.incomplete.update({SUBNET, POOL})
    if (
        summary.errors
        or summary.reservations_skipped
        or summary.reservations_quarantined
        or summary.reservations_unread
    ):
        summary.ownership.incomplete.add(RESERVATION)
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Stale-cleanup exclusion (so the IPAM sync never GCs rows the plugin references)
# ─────────────────────────────────────────────────────────────────────────────


def sys4_referenced_ip_ids() -> set[int]:
    """PKs of ``ipam.IPAddress`` rows referenced by any DHCP-plugin reservation."""
    if not is_available():
        return set()
    HostReservation = plugin_model("HostReservation")
    ids: set[int] = set()
    ids.update(HostReservation.objects.exclude(ipv4_address__isnull=True).values_list("ipv4_address_id", flat=True))
    ids.update(HostReservation.objects.values_list("ipv6_addresses__id", flat=True))
    ids.discard(None)
    return ids


def sys4_referenced_prefix_ids() -> set[int]:
    """PKs of ``ipam.Prefix`` rows referenced by DHCP-plugin subnets/shared-networks/PD pools/reservations."""
    if not is_available():
        return set()
    Subnet = plugin_model("Subnet")
    SharedNetwork = plugin_model("SharedNetwork")
    PDPool = plugin_model("PDPool")
    HostReservation = plugin_model("HostReservation")
    ids: set[int] = set()
    ids.update(Subnet.objects.values_list("prefix_id", flat=True))
    ids.update(SharedNetwork.objects.values_list("prefix_id", flat=True))
    ids.update(PDPool.objects.values_list("prefix_id", flat=True))
    ids.update(PDPool.objects.values_list("excluded_prefix_id", flat=True))
    ids.update(HostReservation.objects.values_list("ipv6_prefixes__id", flat=True))
    ids.update(HostReservation.objects.values_list("excluded_ipv6_prefixes__id", flat=True))
    ids.discard(None)
    return ids


def sys4_referenced_iprange_ids() -> set[int]:
    """PKs of ``ipam.IPRange`` rows referenced by any DHCP-plugin pool."""
    if not is_available():
        return set()
    Pool = plugin_model("Pool")
    ids = set(Pool.objects.values_list("ip_range_id", flat=True))
    ids.discard(None)
    return ids
