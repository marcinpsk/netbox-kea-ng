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
import json
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, TypeVar

from .. import kea_paths
from ..constants import Family, validate_family
from ..dhcp_options import MAX_OPTION_CODE, DHCPOption, DHCPOptionIdentity, OptionDefinition, option_identity
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import (
    ClientClassIntent,
    OptionDefIntent,
    PDPoolIntent,
    PoolIntent,
    ServerConfigIntent,
    SharedNetworkIntent,
    SubnetIntent,
)
from ..pools import Pool, parse_pool
from ..reservations import MAX_IDENTITY_LENGTH, IdentifierType, InSubnetReservationScope, Reservation, identity_text
from .dhcp_import_ledger import KEA_DEFAULTS, MERGED_KEYS
from .dhcp_import_report import KIND_LABELS, ImportEntry, Kind, counted

if TYPE_CHECKING:
    from datetime import datetime

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
#: A DHCP Option holds the identity of its parent and its client classes, so an Option can have no source.
MAX_MAPPING_IDENTITY_LENGTH = max(
    MAX_IDENTITY_LENGTH,  # A Reservation: "identifier-type:value".
    2 * _MAX_ADDRESS_TEXT + len("-"),  # A Pool: "start-end".
    _MAX_ADDRESS_TEXT + 2 * len("/128"),  # A delegated-prefix Pool: "prefix/length/delegated-length".
    # An Option Definition: "space:code", or "class:space:code" in a client class.
    2 * (MAX_KEA_NAME_LENGTH + len(":")) + len(str(MAX_OPTION_CODE)),
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
        if self.kind == Kind.PD_POOL:
            # The delegated length follows the last slash.
            prefix, _, delegated = identity.rpartition("/")
            return kea_paths.pd_pool(kea_paths.subnet(family, self.kea_subnet_id), prefix, int(delegated))
        if self.kind == Kind.RESERVATION:
            # An identifier type has no colon, so the first colon ends it.
            identifier_type, _, value = identity.partition(":")
            return kea_paths.reservation(family, self.kea_subnet_id, identifier_type, value)
        if self.kind == Kind.OPTION_DEFINITION:
            # A space name has no colon, so the last two colons end the class name and the space.
            rest, _, code = identity.rpartition(":")
            class_name, separator, space = rest.rpartition(":")
            return kea_paths.option_definition(family, space, int(code), class_name if separator else None)
        if self.kind == Kind.OPTION:
            return OptionKey.from_source(self).path(family)
        if self.kind == Kind.CLIENT_CLASS:
            return kea_paths.client_class(family, identity)
        if self.kind == Kind.SHARED_NETWORK:
            return kea_paths.shared_network(family, identity)
        if self.kind == Kind.SERVER:
            return kea_paths.daemon(family)
        raise ValueError(f"A {self.kind.value} source has no Kea path.")


@dataclass(frozen=True)
class OptionDefinitionKey:
    """A custom Option Definition by option space and code, in the daemon or in the client class *client_class*."""

    space: str
    code: int
    client_class: str | None = None

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the definition."""
        identity = f"{self.space}:{self.code}"
        if self.client_class is not None:
            identity = f"{self.client_class}:{identity}"
        return MappingSource(Kind.OPTION_DEFINITION, kea_identity=identity)


@dataclass(frozen=True)
class OptionKey:
    """A DHCP Option by the source of the object that assigns it, its identity (ADR 0014), and its occurrence.

    Kea can assign one identity more than once in one object: *occurrence* counts the earlier ones.
    """

    parent: MappingSource
    identity: DHCPOptionIdentity
    occurrence: int = 0

    @property
    def source(self) -> MappingSource | None:
        """Return the DHCP Import Mapping source of the Option, or ``None`` when a mapping cannot hold its identity.

        The Option takes the Kea subnet ID of its parent. Its ``kea_identity`` is a JSON list: the kind and the
        ``kea_identity`` of the parent, the space, the code (else the name), the sorted client classes and the
        occurrence.
        """
        identity = json.dumps(
            [
                self.parent.kind.value,
                self.parent.kea_identity,
                self.identity.space,
                self.identity.code_or_name,
                sorted(self.identity.client_classes),
                self.occurrence,
            ],
            separators=(",", ":"),
        )
        if len(identity) > MAX_MAPPING_IDENTITY_LENGTH:
            return None
        return MappingSource(Kind.OPTION, kea_subnet_id=self.parent.kea_subnet_id, kea_identity=identity)

    @classmethod
    def from_source(cls, source: MappingSource) -> OptionKey:
        """Return the key that the Option *source* holds."""
        if source.kea_identity is None:
            raise ValueError("A DHCP Option source needs its identity.")
        kind, parent_identity, space, code_or_name, classes, occurrence = json.loads(source.kea_identity)
        parent = MappingSource(Kind(kind), source.kea_subnet_id, parent_identity)
        return cls(parent, DHCPOptionIdentity(space, code_or_name, frozenset(classes)), occurrence)

    def path(self, family: int) -> str:
        """Return the Kea path of the Option in *family*."""
        value = self.identity.code_or_name
        code, name = (value, None) if isinstance(value, int) else (None, value)
        classes = tuple(sorted(self.identity.client_classes))
        option = DHCPOption(code, name, self.identity.space, "", None, None, None, classes)
        return kea_paths.option(self.parent.path(family), option, family)


def _known_definitions(
    declared: Mapping[OptionDefinitionKey, OptionDefIntent], class_name: str | None
) -> list[OptionDefinition]:
    """Return the custom Option Definitions that name an option of *class_name*: its own first, then the daemon's."""
    owners = (None,) if class_name is None else (class_name, None)
    return [
        OptionDefinition(
            code=intent.code,
            name=intent.name,
            space=intent.space,
            type=intent.type,
            array=intent.array,
            encapsulate=intent.encapsulate,
            record_types=intent.record_types,
        )
        for owner in owners
        for key, intent in declared.items()
        if key.client_class == owner
    ]


def option_keys(
    parent: MappingSource | None,
    options: Sequence[DHCPOption],
    family: int,
    declared: Mapping[OptionDefinitionKey, OptionDefIntent],
) -> tuple[OptionKey | None, ...]:
    """Key each option that the object of *parent* assigns, with the custom Option Definitions that Kea *declared*.

    The options of an object without a mapping source (``None``) have no key.
    """
    if parent is None:
        return (None,) * len(options)
    definitions = _known_definitions(declared, parent.kea_identity if parent.kind == Kind.CLIENT_CLASS else None)
    seen: Counter[DHCPOptionIdentity] = Counter()
    keys = []
    for option in options:
        identity = option_identity(option, family, definitions)
        keys.append(OptionKey(parent, identity, seen[identity]))
        seen[identity] += 1
    return tuple(keys)


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
class PDPoolKey:
    """A delegated-prefix Pool by the Kea subnet ID of its Subnet, its prefix and its delegated length.

    A Subnet without an ID gives ``None``. Another delegated length is another PD Pool.
    """

    subnet_id: int | None
    prefix: ipaddress.IPv6Network
    delegated_length: int

    @property
    def source(self) -> MappingSource | None:
        """Return the DHCP Import Mapping source of the PD Pool, or ``None`` when its Subnet has no Kea subnet ID."""
        if self.subnet_id is None:
            return None
        identity = f"{self.prefix}/{self.delegated_length}"
        return MappingSource(Kind.PD_POOL, kea_subnet_id=self.subnet_id, kea_identity=identity)


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
    # The custom Option Definitions of the class, written scoped to its row.
    option_definitions: tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...] = ()


@dataclass(frozen=True)
class PlannedSharedNetwork:
    """A Shared Network by its Kea name."""

    key: str
    intent: SharedNetworkIntent
    # The Declared Values of the Shared Network, by Kea key. Its parent is the global configuration.
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
    pd_pools: tuple[Planned[PDPoolKey, PDPoolIntent], ...] = ()


@dataclass(frozen=True)
class FamilyPlan:
    """Every DHCP plugin object that one family of a Kea read intends, in apply order."""

    family: Family
    configuration_complete: bool
    # When the read started. A mapping confirmed later belongs to a newer read, which this plan cannot judge.
    read_started: datetime | None
    # The IPAM confirmation number taken before the read; None: the delegated-prefix Pool phase removes no link.
    ipam_cutoff: int | None
    server: PlannedServer
    option_definitions: tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]
    client_classes: tuple[PlannedClientClass, ...]
    shared_networks: tuple[PlannedSharedNetwork, ...]
    subnets: tuple[PlannedSubnet, ...]
    # None: the read failed. keyed_reservations() keys its records.
    reservations: ReservationObservation | None
    # The configuration entries that the parse dropped as invalid.
    dropped: tuple[DroppedEntry, ...]
    # The global keys that the parity ledger lists as not imported, one entry each.
    not_imported: tuple[ImportEntry, ...]

    @property
    def every_option_definition(self) -> tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]:
        """Return the custom Option Definitions of the daemon, then those of each client class."""
        in_classes = (definition for planned in self.client_classes for definition in planned.option_definitions)
        return (*self.option_definitions, *in_classes)

    def option_keys(self) -> tuple[OptionKey | None, ...]:
        """Key each DHCP Option of each object that the plan holds, the Reservations included."""
        declared = {planned.key: planned.intent for planned in self.every_option_definition}
        return tuple(
            key
            for parent, options in self._option_parents()
            for key in option_keys(parent, options, self.family, declared)
        )

    def _option_parents(self) -> Iterator[tuple[MappingSource | None, tuple[DHCPOption, ...]]]:
        """Yield the mapping source and the options of each object that assigns DHCP Options."""
        yield MappingSource.server(), self.server.global_options
        for planned_class in self.client_classes:
            yield MappingSource.named(Kind.CLIENT_CLASS, planned_class.key), planned_class.intent.options
        for network in self.shared_networks:
            yield MappingSource.named(Kind.SHARED_NETWORK, network.key), network.intent.options
        for subnet in self.subnets:
            yield (MappingSource.subnet(subnet.key) if subnet.key is not None else None), subnet.intent.options
            for pool in subnet.pools:
                yield (pool.key.source if pool.key is not None else None), pool.intent.options
            for pd_pool in subnet.pd_pools:
                yield pd_pool.key.source, pd_pool.intent.options
        for reservation in keyed_reservations(self.reservations):
            yield reservation.key.source, reservation.intent.options


def _option_definitions(
    definitions: tuple[OptionDefIntent, ...], class_name: str | None = None
) -> tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]:
    """Key each custom Option Definition of the daemon or of a client class. A later one of the same key wins."""
    index: dict[OptionDefinitionKey, OptionDefIntent] = {}
    for definition in definitions:
        index[OptionDefinitionKey(definition.space, definition.code, class_name)] = definition
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
    return PlannedClientClass(intent.name, intent, settings, _option_definitions(intent.option_defs, intent.name))


def _planned_shared_networks(config: ServerConfigIntent, family: Family) -> tuple[PlannedSharedNetwork, ...]:
    """Plan each Shared Network with its Declared Values against the global configuration."""
    return tuple(
        PlannedSharedNetwork(
            intent.name,
            intent,
            declared_values(family, kea_paths.SHARED_NETWORKS, intent.settings, config.global_settings),
        )
        for intent in config.shared_networks
    )


def _planned_subnets(
    config: ServerConfigIntent, family: Family, networks: tuple[PlannedSharedNetwork, ...]
) -> tuple[PlannedSubnet, ...]:
    """Plan each Subnet with its Declared Values. Its parent is its Shared Network, else the global configuration."""
    by_name = {network.key: network for network in networks}
    planned = []
    for subnet in config.subnets:
        network = by_name[subnet.shared_network] if subnet.shared_network is not None else None
        parent = config.global_settings if network is None else network.intent.settings
        settings = declared_values(family, kea_paths.subnet_collection(family), subnet.settings, parent)
        inherited = {}
        if network is not None:
            inherited = {key: value for key, value in network.settings.items() if key not in settings}
        pools = tuple(Planned(_pool_key(subnet, pool), pool) for pool in subnet.pools)
        pd_pools = tuple(
            Planned(PDPoolKey(subnet.kea_subnet_id, pd_pool.prefix, pd_pool.delegated_length), pd_pool)
            for pd_pool in subnet.pd_pools
        )
        planned.append(PlannedSubnet(subnet.kea_subnet_id, subnet, settings, inherited, pools, pd_pools))
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
    networks = _planned_shared_networks(config, family)
    return FamilyPlan(
        family=family,
        configuration_complete=config.configuration_complete,
        read_started=config.read_started,
        ipam_cutoff=config.ipam_cutoff,
        server=PlannedServer(
            config.global_settings,
            config.global_options,
            config.host_reservation_identifiers,
            config.user_context,
            config.interfaces,
        ),
        option_definitions=_option_definitions(config.option_defs),
        client_classes=tuple(_planned_client_class(intent, family) for intent in config.client_classes),
        shared_networks=networks,
        subnets=_planned_subnets(config, family, networks),
        reservations=observation,
        dropped=tuple(config.dropped),
        not_imported=config.not_imported,
    )


#: The mapped kinds whose Stale DHCP Import Objects a run removes, children before their parents.
REMOVAL_ORDER: tuple[Kind, ...] = (
    Kind.OPTION,
    Kind.RESERVATION,
    Kind.POOL,
    Kind.PD_POOL,
    Kind.SUBNET,
    Kind.SHARED_NETWORK,
    Kind.CLIENT_CLASS,
    Kind.OPTION_DEFINITION,
)
_CONFIGURATION_KINDS = frozenset(REMOVAL_ORDER) - {Kind.RESERVATION}
#: The mapped kinds whose objects assign DHCP Options. The global configuration of a family has no observation.
_OPTION_PARENTS = (Kind.CLIENT_CLASS, Kind.SHARED_NETWORK, Kind.SUBNET, Kind.POOL, Kind.PD_POOL, Kind.RESERVATION)


def mapped_kinds(family: int) -> tuple[Kind, ...]:
    """Return the kinds of :data:`REMOVAL_ORDER` that *family* has: only DHCPv6 has delegated-prefix Pools."""
    return tuple(kind for kind in REMOVAL_ORDER if family == 6 or kind != Kind.PD_POOL)


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
        gaps[Kind.PD_POOL].append("A Subnet entry that is not valid hides its delegated-prefix Pools.")
    if dropped[Kind.CLIENT_CLASS]:
        gaps[Kind.OPTION_DEFINITION].append("A client class entry that is not valid hides its Option Definitions.")
    for entry in plan.dropped:
        for hidden in entry.hides:
            label = KIND_LABELS[entry.kind]
            gaps[hidden].append(f"A {label} entry that is not valid hides the {KIND_LABELS[hidden]} entries in it.")
    unkeyed_subnets = sum(subnet.key is None for subnet in plan.subnets)
    if unkeyed_subnets:
        gaps[Kind.SUBNET].append(f"{counted(unkeyed_subnets, 'Subnet has', 'Subnets have')} no Kea subnet ID.")
    unkeyed_pools = sum(pool.key is None or pool.key.source is None for subnet in plan.subnets for pool in subnet.pools)
    if unkeyed_pools:
        gaps[Kind.POOL].append(f"{counted(unkeyed_pools, 'Pool has', 'Pools have')} no mapping identity.")
    unkeyed_pd_pools = sum(pd_pool.key.source is None for subnet in plan.subnets for pd_pool in subnet.pd_pools)
    if unkeyed_pd_pools:
        pd_pools = counted(unkeyed_pd_pools, "delegated-prefix Pool has", "delegated-prefix Pools have")
        gaps[Kind.PD_POOL].append(f"{pd_pools} no mapping identity.")
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


def _observed_sources(plan: FamilyPlan, options: tuple[OptionKey | None, ...]) -> dict[Kind, frozenset[MappingSource]]:
    """Return the Kea source of each object that the plan reports, by mapped kind. *options* keys its Options."""
    return {
        Kind.OPTION: frozenset(key.source for key in options if key is not None and key.source is not None),
        Kind.RESERVATION: frozenset(planned.key.source for planned in keyed_reservations(plan.reservations)),
        Kind.POOL: frozenset(
            pool.key.source
            for subnet in plan.subnets
            for pool in subnet.pools
            if pool.key is not None and pool.key.source is not None
        ),
        Kind.PD_POOL: frozenset(
            pd_pool.key.source
            for subnet in plan.subnets
            for pd_pool in subnet.pd_pools
            if pd_pool.key.source is not None
        ),
        Kind.SUBNET: frozenset(MappingSource.subnet(subnet.key) for subnet in plan.subnets if subnet.key is not None),
        Kind.SHARED_NETWORK: frozenset(
            MappingSource.named(Kind.SHARED_NETWORK, planned.key) for planned in plan.shared_networks
        ),
        Kind.CLIENT_CLASS: frozenset(
            MappingSource.named(Kind.CLIENT_CLASS, planned.key) for planned in plan.client_classes
        ),
        Kind.OPTION_DEFINITION: frozenset(planned.key.source for planned in plan.every_option_definition),
    }


def _option_gaps(plan: FamilyPlan, gaps: dict[Kind, list[str]], options: tuple[OptionKey | None, ...]) -> list[str]:
    """Return why the read is Incomplete for the DHCP Options: their own gaps, and each gap of a kind that holds them.

    A read observes the Options of an object only where it observes that object.
    """
    reasons = list(gaps[Kind.OPTION])
    for kind in _OPTION_PARENTS:
        if kind in mapped_kinds(plan.family):
            reasons.extend(gaps[kind])
    unkeyed = sum(key is None or key.source is None for key in options)
    if unkeyed:
        reasons.append(f"{counted(unkeyed, 'DHCP Option has', 'DHCP Options have')} no mapping identity.")
    return list(dict.fromkeys(reasons))


def observations(plan: FamilyPlan) -> dict[Kind, KindObservation]:
    """Return the observation of each mapped kind of the family (:func:`mapped_kinds`) that one family of a read gives.

    The global configuration of a family has no observation: a family that was not read gives no plan.
    """
    options = plan.option_keys()
    sources = _observed_sources(plan, options)
    gaps = _configuration_gaps(plan)
    reservation_gap = _reservation_gap(plan.reservations)
    gaps[Kind.RESERVATION] = [reservation_gap] if reservation_gap else []
    gaps[Kind.OPTION] = _option_gaps(plan, gaps, options)
    return {kind: KindObservation(sources[kind], " ".join(gaps[kind])) for kind in mapped_kinds(plan.family)}


def kind_path(family: int, kind: Kind) -> str:
    """Return the Kea path that names every entry of one mapped kind in *family*."""
    daemon = kea_paths.daemon(family)
    subnets = kea_paths.every_entry(kea_paths.setting(daemon, kea_paths.subnet_collection(family)))
    collections = {
        Kind.RESERVATION: kea_paths.reservations(family),
        Kind.POOL: kea_paths.pool_collection(subnets),
        Kind.PD_POOL: kea_paths.pd_pool_collection(subnets),
        Kind.SHARED_NETWORK: kea_paths.setting(daemon, kea_paths.SHARED_NETWORKS),
        Kind.CLIENT_CLASS: kea_paths.setting(daemon, kea_paths.CLIENT_CLASSES),
        Kind.OPTION_DEFINITION: kea_paths.option_definition_collection(family),
        Kind.OPTION: kea_paths.option_collection(daemon),
    }
    if kind == Kind.SUBNET:
        return subnets
    if kind not in collections:
        raise ValueError(f"A {kind.value} has no collection that a run can remove from.")
    return kea_paths.every_entry(collections[kind])
