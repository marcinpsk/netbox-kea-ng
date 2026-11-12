# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The client classes, Shared Networks, Subnets, Pools and delegated-prefix Pools that the DHCP Import writes.

* **Client classes** (``client-classes``) are imported as ``ClientClass`` rows
  (test/template-test, additional-list flag, BOOTP + lifetime settings, options) with
  their Kea name. While the plugin keeps class names unique across all servers, a class
  whose name another row holds is reported as unsupported (:mod:`.dhcp_plugin_capabilities`).
* **Shared Networks** (``shared-networks``) are imported as ``SharedNetwork`` rows with their Kea name, settings,
  class lists, interface and options, before the Subnets, and never with a Prefix: a Kea Shared Network has none.
  Each member Subnet belongs to its Shared Network instead of the DHCPServer. Without the capability for an
  optional prefix (netbox-plugin-dhcp 0.2.0 requires one) every Shared Network is unsupported, and its member Subnets
  import onto the DHCPServer. Names follow the same uniqueness rule as client classes.
* A plugin Subnet holds Kea's subnet ID (:func:`settle_subnet_ids`). While the plugin keeps Subnet IDs
  unique across all servers, a Subnet whose ID another Server or family holds is reported as unsupported,
  with its Pools, delegated-prefix Pools and In-Subnet Reservations.
* **Delegated-prefix Pools** (DHCPv6 ``pd-pools``) import as ``PDPool`` rows in their Subnet. Their prefix and
  excluded prefix are NetBox Prefixes that the import owns through the IPAM source ``pd-pool`` (ADR 0006). The
  ``pd-pool`` phase runs after the removal of Stale DHCP Import Objects, so it can deprecate a Prefix that only a
  removed PD Pool used. A PD Pool that the plugin refuses (``PDPool.clean``) is unsupported, and the run goes on.
* A Shared Network, a Subnet, a Pool, a PD Pool and a Reservation link the client classes of their class lists that
  the same run imported. A Shared Network and a Subnet link the DHCP server interface that their Kea ``interface``
  names, and report a name that matches none.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import count
from typing import TYPE_CHECKING, Any

from django.db.models import Q

from .. import event_scope, kea_paths
from ..ipam_sources import range_key
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import PDPoolIntent, PoolIntent
from .dhcp_import_fields import (
    CLIENT_CLASS_FIELDS,
    GATED_NETWORK_FIELDS,
    GATED_SUBNET_FIELDS,
    NETWORK_FIELDS,
    POOL_FIELDS,
)
from .dhcp_import_mappings import subnet_id_mappings, unlinked
from .dhcp_import_options import CustomDefinitions, OptionReferences, upsert_options, write_option_definition
from .dhcp_import_plan import InvalidPoolKey, NamedKey, PoolKey, SubnetKey, planned_options
from .dhcp_import_report import KIND_LABELS, Capability, ImportEntry, Kind, Reason, not_written
from .dhcp_import_server import no_interface_detail, synthesized_name
from .dhcp_import_summary import ImportSummary
from .dhcp_import_values import Source, declared_value, gated_values, settings_fields, user_context_fields
from .dhcp_import_write import FAILED, NotWritten, RowAdapter, WriteScope, WrittenStore, write_row
from .dhcp_plugin_capabilities import PluginCapabilities, plugin_model

if TYPE_CHECKING:
    from ..ipam_reconciliation import ClaimResult, RangeClaim
    from .dhcp_import_plan import (
        FamilyPlan,
        KindObservation,
        PDPoolKey,
        Planned,
        PlannedClientClass,
        PlannedSharedNetwork,
        PlannedSubnet,
    )

logger = logging.getLogger(__name__)


def _class_not_imported(name: str) -> str:
    """Return the detail of a fact whose client class *name* Kea defines but this run did not import."""
    return f"Client class {name} was not imported."


def released_client_class_name(server, kea_name: str) -> str:
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


@dataclass(frozen=True)
class _ClientClassAdapter(_NamedAdapter):
    """A client class with its Kea name."""

    planned: PlannedClientClass

    def adopt(self):
        """Return the row that the released importer created before client classes had a mapping."""
        released = released_client_class_name(self.scope.server, self.key.name)
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


def upsert_client_class(
    scope: WriteScope, dhcp_server, planned: PlannedClientClass, definitions: CustomDefinitions
) -> None:
    """Get/create the DHCP-plugin ``ClientClass`` for *planned* through its mapping, with its Option Definitions.

    The row takes the Kea name. Its DHCP Options are written after every class row exists
    (:func:`.dhcp_plugin.apply_plan`). The written store of the run holds the row, or why it was not written.
    """
    row = write_row(_ClientClassAdapter(scope, planned.key, dhcp_server, planned))
    if isinstance(row, NotWritten):
        return
    for planned_definition in planned.option_definitions:
        write_option_definition(scope, definitions, planned_definition.key, row)


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


def upsert_shared_network(
    scope: WriteScope, dhcp_server, planned: PlannedSharedNetwork, references: OptionReferences
) -> None:
    """Get or create the DHCP plugin ``SharedNetwork`` of *planned* through its mapping, with its DHCP Options.

    Without the capability for an optional prefix the Shared Network is unsupported.
    """
    row = write_row(_SharedNetworkAdapter(scope, planned.key, dhcp_server, planned, references.classes))
    if isinstance(row, NotWritten):
        return
    upsert_options(scope, row, planned_options(planned, scope.family, references.definitions.declared), references)


def import_shared_networks(scope: WriteScope, dhcp_server, plan: FamilyPlan, references: OptionReferences) -> None:
    """Write every Shared Network of *plan* before its Subnets. The written store of the run holds each row."""
    for planned in plan.shared_networks:
        upsert_shared_network(scope, dhcp_server, planned, references)


def _subnet_name(server, planned: PlannedSubnet) -> str:
    """Build a globally-unique name (NetBoxDHCPModelMixin requires unique ``name``)."""
    return synthesized_name(server.name, f" DHCPv{planned.intent.family} subnet {planned.key.subnet_id}")


def _pool_name(subnet_obj, pool_intent) -> str:
    """Build a unique pool name scoped to its parent subnet's (unique) name."""
    return synthesized_name(subnet_obj.name, f" pool {pool_intent.pool}")


def _pd_pool_name(subnet_obj, key: PDPoolKey) -> str:
    """Build a unique PD Pool name scoped to its parent subnet's (unique) name."""
    return synthesized_name(subnet_obj.name, f" pd pool {key.prefix} delegated /{key.delegated_length}")


def _served_by(dhcp_server) -> Q:
    """Return the Subnets of *dhcp_server*: its own, and the members of its Shared Networks."""
    return Q(dhcp_server=dhcp_server) | Q(shared_network__dhcp_server=dhcp_server)


@dataclass(frozen=True)
class _SubnetAdapter(RowAdapter):
    """A Subnet by its Kea subnet ID, which :func:`settle_subnet_ids` gave its mapped row before the write.

    A member of the imported *shared_network* belongs to it. With *keep_membership*, a stored Subnet keeps its parent.
    Else the Subnet belongs to *dhcp_server*: the DHCP plugin holds one of the two. *stopped* is why the run does not
    write it at all: another row keeps its Kea subnet ID, or the ID move failed. Its In-Subnet Reservations read its
    result from the written store of the run.
    """

    scope: WriteScope
    key: SubnetKey
    planned: PlannedSubnet
    dhcp_server: Any
    claims: ClaimResult
    classes: ClassReferences
    shared_network: Any
    keep_membership: bool
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


def upsert_subnet(
    scope: WriteScope,
    dhcp_server,
    planned: PlannedSubnet,
    claims: ClaimResult,
    subnet_ids: SubnetIdSettlement,
    references: OptionReferences,
):
    """Get/create the DHCP-plugin ``Subnet`` for *planned*, tracked via ``KeaDhcpLink`` by its key.

    The Subnet reads the row of its Shared Network from the written store of the run. A Subnet whose Kea subnet ID
    another row keeps, or whose ID move failed, is not written. A Subnet that :func:`settle_subnet_ids` renumbered is
    updated. Return the ``netbox_dhcp.Subnet`` row, or ``None`` when it was not written: then its In-Subnet
    Reservations are not written either.
    """
    subnet_id = planned.key.subnet_id
    name = planned.intent.shared_network
    network = scope.written.row(NamedKey(Kind.SHARED_NETWORK, name)) if name is not None else None
    # A member of a Shared Network that this run could hold but did not write keeps its stored parent.
    keep = name is not None and network is None and scope.capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX)
    taken = subnet_ids.taken.get(subnet_id)
    stopped = taken if taken is not None else FAILED if subnet_id in subnet_ids.failed else None
    adapter = _SubnetAdapter(
        scope,
        planned.key,
        planned,
        dhcp_server,
        claims,
        references.classes,
        network,
        keep,
        stopped,
        changed_before=subnet_id in subnet_ids.renumbered,
    )
    row = write_row(adapter)
    if isinstance(row, NotWritten):
        return None
    if network is None:
        _report_inherited(scope.summary, planned, scope.capabilities)
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


@dataclass(frozen=True)
class SubnetIdSettlement:
    """What :func:`settle_subnet_ids` found and did, by Kea subnet ID. The written store holds a failed Subnet write."""

    # Why each planned Subnet whose Kea subnet ID another row keeps is not written; its subtree has the same reason.
    taken: Mapping[int, NotWritten]
    renumbered: frozenset[int]
    # The Subnets that need an ID move that failed.
    failed: frozenset[int]


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

    taken: dict[int, NotWritten] = {}
    renumbered: set[int] = set()
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
            taken[key] = _subnet_id_taken(subnet, holder, capabilities)
            continue
        claimed.update({number: pk for pk, number in chain.items()})
        moves.update(chain)
        if chain:
            dependent.add(key)
        if requester in chain:
            renumbered.add(key)
    if not moves:
        return SubnetIdSettlement(taken, frozenset(renumbered), frozenset())
    try:
        with event_scope.atomic():
            _move_subnet_ids(Subnet.objects.in_bulk(moves), moves, holds)
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:
        # The Subnets that need a move fail. The others still import.
        logger.exception("DHCP-plugin import: the Subnets of %s could not take their Kea subnet IDs", server.name)
        summary.warn(f"Kea Subnets {sorted(dependent)} could not take their Kea subnet IDs: {exc}")
        return SubnetIdSettlement(taken, frozenset(), frozenset(dependent))
    return SubnetIdSettlement(taken, frozenset(renumbered), frozenset())


@dataclass(frozen=True)
class ClassReferences:
    """The client classes of one family for the class lists of its other Kea objects, read from the written store.

    Each class that Kea's client-classes defines is a planned object of the run, so a read before the class step
    raises (:class:`.dhcp_import_write.WriteOrderError`).
    """

    written: WrittenStore

    def _row(self, name: str):
        """Return the row of the class *name* that this run wrote, or ``None``."""
        return self.written.row(NamedKey(Kind.CLIENT_CLASS, name))

    def _defined(self, name: str) -> bool:
        """Return whether Kea's client-classes of this family defines the class *name*."""
        return NamedKey(Kind.CLIENT_CLASS, name) in self.written

    def resolve(
        self, names: tuple[str, ...], parent_path: str, key: str, kind: Kind, summary: ImportSummary
    ) -> set[int]:
        """Return the imported client class of each name in the class list *key* of the *kind* at *parent_path*.

        A name without an imported class has an entry and is left out. The import never creates a class for it.
        """
        family = self.written.family
        found = set()
        for name in names:
            row = self._row(name)
            if row is not None:
                found.add(row.pk)
                continue
            path = kea_paths.class_reference(parent_path, key, name)
            if self._defined(name):
                detail = _class_not_imported(name)
                summary.record(not_written(family, kind, path, Reason.PARENT_NOT_IMPORTED, detail))
            else:
                detail = f"The DHCP plugin has no row for {name}, a class that Kea's client-classes does not define."
                summary.record(not_written(family, kind, path, Reason.NO_PLUGIN_HOME, detail))
        return found

    def option_classes(self, names: tuple[str, ...], path: str, summary: ImportSummary) -> frozenset[int] | None:
        """Return the imported client class of each name of the DHCP Option at *path*, or ``None`` to skip it.

        An option whose class has no row is not imported: without the class it would reach more clients.
        """
        rows = [self._row(name) for name in names]
        missing = next((name for name, row in zip(names, rows, strict=True) if row is None), None)
        if missing is None:
            return frozenset(row.pk for row in rows)
        if self._defined(missing):
            cause = _class_not_imported(missing)
        else:
            cause = f"The DHCP plugin has no row for {missing}, a class that Kea's client-classes does not define."
        detail = f"{cause} Without the class the option would reach more clients."
        summary.record(not_written(self.written.family, Kind.OPTION, path, Reason.PARENT_NOT_IMPORTED, detail))
        return None

    def has_pending_import(self, names: tuple[str, ...]) -> bool:
        """Return whether Kea defines a named class that this run did not import."""
        return any(self._defined(name) and self._row(name) is None for name in names)

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

    def _claim(self) -> RangeClaim | None:
        """Return the IPAM claim of the range, or ``None`` when the claim left the range out."""
        if not isinstance(self.key, PoolKey):
            return None
        pool = self.key.range
        return self.claims.ranges.get(range_key(pool.start, pool.end))

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


def upsert_pools(scope: WriteScope, subnet_obj, planned: PlannedSubnet, references: OptionReferences, claims) -> None:
    """Get/create DHCP-plugin ``Pool`` rows (and their options) for each planned Pool of *planned*."""
    for planned_pool in planned.pools:
        adapter = _PoolAdapter(scope, planned_pool.key, planned_pool.intent, subnet_obj, claims, references.classes)
        row = write_row(adapter)
        if not isinstance(row, NotWritten):
            options = planned_options(planned_pool, scope.family, references.definitions.declared)
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


def upsert_pd_pools(
    scope: WriteScope, subnet_obj, planned: PlannedSubnet, references: OptionReferences, claims: ClaimResult
) -> None:
    """Get/create DHCP-plugin ``PDPool`` rows (and their options) for each planned delegated-prefix Pool of *planned*.

    A PD Pool that the DHCP plugin refuses is unsupported with the plugin's reason, and its options are skipped.
    """
    for planned_pd_pool in planned.pd_pools:
        adapter = _PDPoolAdapter(scope, planned_pd_pool.key, planned_pd_pool, subnet_obj, claims, references.classes)
        row = write_row(adapter)
        if not isinstance(row, NotWritten):
            options = planned_options(planned_pd_pool, scope.family, references.definitions.declared)
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


def claim_config_networks(server, plan: FamilyPlan):
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

    It runs after :func:`.dhcp_import_stale.remove_stale_objects`: a removed PD Pool no longer uses its Prefix, so the
    cleanup can deprecate it. Only a Complete observation of delegated-prefix Pools (*observed*), with a cutoff, drops a
    link. A PD Pool that Kea no longer reports and that is still in NetBox (*unobserved*) still uses its Prefixes, so
    the phase is then not complete.
    """
    from ..ipam_reconciliation import PDPoolPhase, reconcile

    complete = observed[Kind.PD_POOL].complete and Kind.PD_POOL not in unobserved
    phase = PDPoolPhase(pd_pool_prefixes(plan), plan.cutoff, complete)
    summary.ownership.reconciled(phase.source, reconcile(server, plan.family, [phase]))
