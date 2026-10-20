# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The plan step of the DHCP Import: the keyed DHCP plugin objects that one family of a Kea read intends.

The plan is pure. It reads no database, no DHCP plugin and no Kea, so a test can build it from recorded Kea
replies. Each planned object carries its key, and :class:`MappingSource` gives the DHCP Import Mapping identity of
a key: the columns of ``KeaDhcpLink`` that the apply step reads and writes. The plan keeps the Reservation
observation, and :func:`keyed_reservations` keys its records. :func:`observations` gives the Kea sources that the
read reports for each mapped kind, and whether the read is Complete for that kind: the removal of Stale DHCP Import
Objects and the drift view both use it. The apply step in :mod:`netbox_kea.integrations.dhcp_plugin` turns the parsed
intents into plugin field values.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, TypeVar

from .. import kea_paths
from ..constants import Family, validate_family
from ..dhcp_options import MAX_OPTION_CODE
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import (
    ClientClassIntent,
    OptionDefIntent,
    PoolIntent,
    ServerConfigIntent,
    SharedNetworkIntent,
    SubnetIntent,
)
from ..pools import Pool, parse_pool
from ..reservations import MAX_IDENTITY_LENGTH, IdentifierType, InSubnetReservationScope, Reservation, identity_text
from .dhcp_import_ledger import KEA_DEFAULTS, MERGED_KEYS
from .dhcp_import_report import KIND_LABELS, Kind, counted

if TYPE_CHECKING:
    from ..dhcp_options import DHCPOption
    from ..ipam_reconciliation import ReservationObservation
    from .dhcp_import_report import DroppedEntry

K = TypeVar("K")
T = TypeVar("T")


@dataclass(frozen=True)
class Planned(Generic[K, T]):
    """One intended DHCP plugin object: its key and the parsed Kea intent."""

    key: K
    intent: T


# The longest text of one address: an IPv6 address with no zero group.
_MAX_ADDRESS_TEXT = len(str(ipaddress.IPv6Address(2**128 - 1)))
#: The longest Kea name that the import keys: a DHCP plugin row holds a name of 255 characters.
MAX_KEA_NAME_LENGTH = 255
#: The longest ``KeaDhcpLink.kea_identity`` that a :class:`MappingSource` gives, from the identity of each kind.
MAX_MAPPING_IDENTITY_LENGTH = max(
    MAX_IDENTITY_LENGTH,  # A Reservation: "identifier-type:value".
    2 * _MAX_ADDRESS_TEXT + len("-"),  # A Pool: "start-end".
    MAX_KEA_NAME_LENGTH + len(":") + len(str(MAX_OPTION_CODE)),  # An Option Definition: "space:code".
    MAX_KEA_NAME_LENGTH,  # A Shared Network or a client class: its name.
)


@dataclass(frozen=True)
class MappingSource:
    """The Kea source of a DHCP Import Mapping in one Server and family, in the ``KeaDhcpLink`` identity columns.

    ``kea_subnet_id`` is the Kea subnet ID of the object or of its Subnet. ``kea_identity`` identifies the object in
    that Subnet, or in the Server and family when ``kea_subnet_id`` is ``None``. A Subnet has no ``kea_identity``, and
    the global configuration of a family has neither.
    """

    kind: Kind
    kea_subnet_id: int | None = None
    kea_identity: str | None = None

    @classmethod
    def server(cls) -> MappingSource:
        """Return the source of the global configuration of one family: the Server and family identify it."""
        return cls(Kind.SERVER)

    @classmethod
    def subnet(cls, subnet_id: int) -> MappingSource:
        """Return the source of a Subnet by its Kea subnet ID."""
        return cls(Kind.SUBNET, kea_subnet_id=subnet_id)

    @classmethod
    def named(cls, kind: Kind, name: str) -> MappingSource:
        """Return the source of a Shared Network or a client class by its Kea name."""
        return cls(kind, kea_identity=name)

    def columns(self) -> dict[str, object]:
        """Return the ``KeaDhcpLink`` identity columns, for a lookup and for a write."""
        return {"kind": self.kind.value, "kea_subnet_id": self.kea_subnet_id, "kea_identity": self.kea_identity}

    def path(self, family: int) -> str:
        """Return the Kea path of the source in *family*."""
        identity = self.kea_identity or ""
        if self.kind == Kind.SUBNET:
            return kea_paths.subnet(family, self.kea_subnet_id)
        if self.kind == Kind.POOL:
            return kea_paths.pool(kea_paths.subnet(family, self.kea_subnet_id), identity)
        if self.kind == Kind.RESERVATION:
            # An identifier type has no colon, so the first colon ends it.
            identifier_type, _, value = identity.partition(":")
            return kea_paths.reservation(family, self.kea_subnet_id, identifier_type, value)
        if self.kind == Kind.OPTION_DEFINITION:
            space, _, code = identity.rpartition(":")
            return kea_paths.option_definition(family, space, int(code))
        if self.kind == Kind.CLIENT_CLASS:
            return kea_paths.client_class(family, identity)
        if self.kind == Kind.SHARED_NETWORK:
            return kea_paths.shared_network(family, identity)
        if self.kind == Kind.SERVER:
            return kea_paths.daemon(family)
        raise ValueError(f"A {self.kind.value} source has no Kea path.")


@dataclass(frozen=True)
class OptionDefinitionKey:
    """A custom Option Definition by option space and code."""

    space: str
    code: int

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the definition."""
        return MappingSource(Kind.OPTION_DEFINITION, kea_identity=f"{self.space}:{self.code}")


@dataclass(frozen=True)
class PoolKey:
    """A Pool by the Kea subnet ID of its Subnet and its range. A Subnet without an ID gives ``None``."""

    subnet_id: int | None
    range: Pool

    @property
    def source(self) -> MappingSource | None:
        """Return the DHCP Import Mapping source of the Pool, or ``None`` when its Subnet has no Kea subnet ID."""
        if self.subnet_id is None:
            return None
        return MappingSource(Kind.POOL, kea_subnet_id=self.subnet_id, kea_identity=self.range.range)


@dataclass(frozen=True)
class GlobalReservationKey:
    """A Global Reservation by family and Kea identifier."""

    family: Family
    identifier_type: IdentifierType
    value: str

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the Reservation. The family is a column of the mapping."""
        return MappingSource(Kind.RESERVATION, kea_identity=identity_text(self.identifier_type, self.value))


@dataclass(frozen=True)
class InSubnetReservationKey:
    """An In-Subnet Reservation by the Kea subnet ID of its Subnet and its Kea identifier."""

    subnet_id: int
    identifier_type: IdentifierType
    value: str

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the Reservation."""
        return MappingSource(
            Kind.RESERVATION, kea_subnet_id=self.subnet_id, kea_identity=identity_text(self.identifier_type, self.value)
        )


ReservationKey = GlobalReservationKey | InSubnetReservationKey


@dataclass(frozen=True)
class PlannedServer:
    """The global configuration of one family, for the DHCPServer of the Server."""

    global_settings: dict
    global_options: tuple[DHCPOption, ...]
    # None: the key is absent or invalid in the Server Configuration Snapshot.
    host_reservation_identifiers: tuple[str, ...] | None
    user_context: dict | None
    # None: the interface list is not valid.
    interfaces: tuple[str, ...] | None


@dataclass(frozen=True)
class PlannedClientClass:
    """A client class by its Kea name."""

    key: str
    intent: ClientClassIntent
    # The Declared Values of the class, by Kea key.
    settings: dict


@dataclass(frozen=True)
class PlannedSubnet:
    """A Subnet by Kea subnet ID, with its Pools. ``None``: Kea gave no ID, so the Subnet has no mapping identity."""

    key: int | None
    intent: SubnetIntent
    # The Declared Values of the Subnet, by Kea key.
    settings: dict
    # The Declared Values of its Shared Network that the Subnet does not declare: Kea applies them to the Subnet.
    inherited: dict
    # A Pool key is None when its text is not a range inside the Subnet; the apply skips that Pool.
    pools: tuple[Planned[PoolKey | None, PoolIntent], ...]


@dataclass(frozen=True)
class FamilyPlan:
    """Every DHCP plugin object that one family of a Kea read intends, in apply order."""

    family: Family
    configuration_complete: bool
    server: PlannedServer
    option_definitions: tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]
    client_classes: tuple[PlannedClientClass, ...]
    # Planned so that the result reports each one; the DHCP plugin model holds none yet.
    shared_networks: tuple[Planned[str, SharedNetworkIntent], ...]
    subnets: tuple[PlannedSubnet, ...]
    # None: the read failed. keyed_reservations() keys its records.
    reservations: ReservationObservation | None
    # The configuration entries that the parse dropped as invalid.
    dropped: tuple[DroppedEntry, ...]


def _option_definitions(config: ServerConfigIntent) -> tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]:
    """Key each custom Option Definition. A later definition of the same key replaces an earlier one."""
    index: dict[OptionDefinitionKey, OptionDefIntent] = {}
    for definition in config.option_defs:
        index[OptionDefinitionKey(definition.space, definition.code)] = definition
    return tuple(Planned(key, definition) for key, definition in index.items())


def _pool_key(subnet: SubnetIntent, pool: PoolIntent) -> PoolKey | None:
    try:
        return PoolKey(subnet.kea_subnet_id, parse_pool(pool.pool, subnet_network(subnet.cidr, subnet.family)))
    except ValueError:
        return None


def declared_values(family: Family, table: str, settings: dict, parent: dict) -> dict:
    """Return the Declared Values among the *settings* that ``config-get`` returned for one Kea object of *table*.

    A key of :data:`MERGED_KEYS` is inherited when its value equals the value of the *parent* settings. A key of
    :data:`KEA_DEFAULTS` is inherited when the parent has no value and the value is Kea's default.
    """
    merged, defaults = MERGED_KEYS[family][table], KEA_DEFAULTS[family][table]

    def inherited(key: str, value) -> bool:
        if key in merged and key in parent:
            return value == parent[key]
        return key not in parent and key in defaults and value == defaults[key]

    return {key: value for key, value in settings.items() if not inherited(key, value)}


def _planned_client_class(intent: ClientClassIntent, family: Family) -> PlannedClientClass:
    # Kea merges no value into a client class, so the class has no parent values.
    settings = declared_values(family, kea_paths.CLIENT_CLASSES, intent.settings, {})
    return PlannedClientClass(intent.name, intent, settings)


def _planned_subnets(config: ServerConfigIntent, family: Family) -> tuple[PlannedSubnet, ...]:
    """Plan each Subnet with its Declared Values. Its parent is its Shared Network, else the global configuration."""
    networks = {network.name: network.settings for network in config.shared_networks}
    planned = []
    for subnet in config.subnets:
        network_settings = networks[subnet.shared_network] if subnet.shared_network is not None else None
        parent = config.global_settings if network_settings is None else network_settings
        settings = declared_values(family, kea_paths.subnet_collection(family), subnet.settings, parent)
        inherited = {}
        if network_settings is not None:
            from_network = declared_values(family, kea_paths.SHARED_NETWORKS, network_settings, config.global_settings)
            inherited = {key: value for key, value in from_network.items() if key not in settings}
        pools = tuple(Planned(_pool_key(subnet, pool), pool) for pool in subnet.pools)
        planned.append(PlannedSubnet(subnet.kea_subnet_id, subnet, settings, inherited, pools))
    return tuple(planned)


def reservation_key(reservation: Reservation) -> ReservationKey:
    """Return the key of a Reservation: its Reservation Identity."""
    identity = reservation.identity
    if isinstance(reservation.scope, InSubnetReservationScope):
        return InSubnetReservationKey(reservation.scope.subnet.subnet_id, identity.identifier_type, identity.value)
    return GlobalReservationKey(reservation.family, identity.identifier_type, identity.value)


def keyed_reservations(observation: ReservationObservation | None) -> tuple[Planned[ReservationKey, Reservation], ...]:
    """Key each valid record of a Reservation observation. A failed read (``None``) gives no record."""
    if observation is None:
        return ()
    return tuple(Planned(reservation_key(record), record) for record in observation.snapshot.records)


def plan_family(config: ServerConfigIntent, observation: ReservationObservation | None) -> FamilyPlan:
    """Return the plan of one family from its parsed configuration and its Reservation observation."""
    family = validate_family(config.family)
    return FamilyPlan(
        family=family,
        configuration_complete=config.configuration_complete,
        server=PlannedServer(
            config.global_settings,
            config.global_options,
            config.host_reservation_identifiers,
            config.user_context,
            config.interfaces,
        ),
        option_definitions=_option_definitions(config),
        client_classes=tuple(_planned_client_class(intent, family) for intent in config.client_classes),
        shared_networks=tuple(Planned(intent.name, intent) for intent in config.shared_networks),
        subnets=_planned_subnets(config, family),
        reservations=observation,
        dropped=tuple(config.dropped),
    )


#: The mapped kinds whose Stale DHCP Import Objects a run removes, children before their parents.
REMOVAL_ORDER: tuple[Kind, ...] = (
    Kind.RESERVATION,
    Kind.POOL,
    Kind.SUBNET,
    Kind.SHARED_NETWORK,
    Kind.CLIENT_CLASS,
    Kind.OPTION_DEFINITION,
)
_CONFIGURATION_KINDS = frozenset(REMOVAL_ORDER) - {Kind.RESERVATION}


@dataclass(frozen=True)
class KindObservation:
    """The Kea sources of one mapped kind that a read reports, and why the observation is Incomplete.

    Only a Complete observation can make a mapped row stale.
    """

    sources: frozenset[MappingSource]
    # Empty when the observation is Complete.
    incomplete: str = ""

    @property
    def complete(self) -> bool:
        """Return whether the read reported every Kea source of the kind."""
        return not self.incomplete


def _configuration_gaps(plan: FamilyPlan) -> dict[Kind, list[str]]:
    """Return why the configuration read is Incomplete for each configuration kind."""
    gaps: dict[Kind, list[str]] = {kind: [] for kind in _CONFIGURATION_KINDS}
    if not plan.configuration_complete:
        for reasons in gaps.values():
            reasons.append("The Server Configuration was not read in full.")
    dropped = Counter(entry.kind for entry in plan.dropped)
    for kind, reasons in gaps.items():
        if dropped[kind]:
            label = KIND_LABELS[kind]
            entries = counted(dropped[kind], f"{label} entry that is", f"{label} entries that are")
            reasons.append(f"The configuration has {entries} not valid.")
    if dropped[Kind.SUBNET]:
        gaps[Kind.POOL].append("A Subnet entry that is not valid hides its Pools.")
    unkeyed_subnets = sum(subnet.key is None for subnet in plan.subnets)
    if unkeyed_subnets:
        gaps[Kind.SUBNET].append(f"{counted(unkeyed_subnets, 'Subnet has', 'Subnets have')} no Kea subnet ID.")
    unkeyed_pools = sum(pool.key is None or pool.key.source is None for subnet in plan.subnets for pool in subnet.pools)
    if unkeyed_pools:
        gaps[Kind.POOL].append(f"{counted(unkeyed_pools, 'Pool has', 'Pools have')} no mapping identity.")
    return gaps


def _reservation_gap(observation: ReservationObservation | None) -> str:
    """Return why the Reservation observation is Incomplete, or "" when it holds every Reservation."""
    # Imported here: models imports this module, and subnet_catalogue imports models.
    from ..subnet_catalogue import CompleteCatalogueSnapshot

    if observation is None:
        return "The Reservation Snapshot could not be read."
    if not isinstance(observation.catalogue, CompleteCatalogueSnapshot):
        return "The Subnet Catalogue of the Reservation Snapshot is incomplete."
    snapshot = observation.snapshot
    if snapshot.traversal_truncated:
        return "The Reservation walk did not read every page."
    if snapshot.diagnostics:
        records = counted(len(snapshot.diagnostics), "Reservation record", "Reservation records")
        return f"{records} could not be parsed, and one of them can be a mapped Reservation."
    if not snapshot.complete:
        return "The Reservation Snapshot is incomplete."
    return ""


def _observed_sources(plan: FamilyPlan) -> dict[Kind, frozenset[MappingSource]]:
    """Return the Kea source of each object that the plan reports, by mapped kind."""
    return {
        Kind.RESERVATION: frozenset(planned.key.source for planned in keyed_reservations(plan.reservations)),
        Kind.POOL: frozenset(
            pool.key.source
            for subnet in plan.subnets
            for pool in subnet.pools
            if pool.key is not None and pool.key.source is not None
        ),
        Kind.SUBNET: frozenset(MappingSource.subnet(subnet.key) for subnet in plan.subnets if subnet.key is not None),
        Kind.SHARED_NETWORK: frozenset(
            MappingSource.named(Kind.SHARED_NETWORK, planned.key) for planned in plan.shared_networks
        ),
        Kind.CLIENT_CLASS: frozenset(
            MappingSource.named(Kind.CLIENT_CLASS, planned.key) for planned in plan.client_classes
        ),
        Kind.OPTION_DEFINITION: frozenset(planned.key.source for planned in plan.option_definitions),
    }


def observations(plan: FamilyPlan) -> dict[Kind, KindObservation]:
    """Return the observation of each kind of :data:`REMOVAL_ORDER` that one family of a read gives.

    The global configuration of a family has no observation: a family that was not read gives no plan.
    """
    sources = _observed_sources(plan)
    gaps = {kind: " ".join(reasons) for kind, reasons in _configuration_gaps(plan).items()}
    gaps[Kind.RESERVATION] = _reservation_gap(plan.reservations)
    return {kind: KindObservation(sources[kind], gaps[kind]) for kind in REMOVAL_ORDER}


def kind_path(family: int, kind: Kind) -> str:
    """Return the Kea path that names every entry of one mapped kind in *family*."""
    daemon = kea_paths.daemon(family)
    subnets = kea_paths.every_entry(kea_paths.setting(daemon, kea_paths.subnet_collection(family)))
    collections = {
        Kind.RESERVATION: kea_paths.reservations(family),
        Kind.POOL: kea_paths.pool_collection(subnets),
        Kind.SHARED_NETWORK: kea_paths.setting(daemon, kea_paths.SHARED_NETWORKS),
        Kind.CLIENT_CLASS: kea_paths.setting(daemon, kea_paths.CLIENT_CLASSES),
        Kind.OPTION_DEFINITION: kea_paths.option_definition_collection(family),
    }
    if kind == Kind.SUBNET:
        return subnets
    if kind not in collections:
        raise ValueError(f"A {kind.value} has no collection that a run can remove from.")
    return kea_paths.every_entry(collections[kind])
