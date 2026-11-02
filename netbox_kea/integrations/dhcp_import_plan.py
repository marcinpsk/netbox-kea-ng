# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The plan step of the DHCP Import: the keyed DHCP plugin objects that one family of a Kea read intends.

The plan is pure. It reads no database, no DHCP plugin and no Kea, so a test can build it from recorded Kea
replies. Each planned object carries its key. A key gives its :class:`MappingSource`, the DHCP Import Mapping
identity in the columns of ``KeaDhcpLink`` that the apply step reads and writes, and its Kea path. :data:`KEY_KINDS`
gives the key class that decodes a source of each kind. The plan keeps the Reservation
observation, and :func:`keyed_reservations` keys its records. :func:`observations` gives the Kea sources that the
read reports for each mapped kind, and whether the read is Complete for that kind: the removal of Stale DHCP Import
Objects and the drift view both use it. The apply step in :mod:`netbox_kea.integrations.dhcp_plugin` turns the parsed
intents into plugin field values.
"""

from __future__ import annotations

import ipaddress
import json
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, ClassVar, Generic, Protocol, TypedDict, TypeVar, cast, get_args

from .. import kea_paths
from ..constants import Family, validate_family
from ..dhcp_options import DHCPOptionIdentity, OptionDefinition, option_identity
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
from ..reservations import IdentifierType, InSubnetReservationScope, Reservation, identity_text
from .dhcp_import_ledger import KEA_DEFAULTS, MERGED_KEYS
from .dhcp_import_report import KIND_LABELS, ImportEntry, Kind, counted

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


#: The longest Kea name that the import keys: a DHCP plugin row holds a name of 255 characters.
MAX_KEA_NAME_LENGTH = 255


class SourceColumns(TypedDict):
    """The ``KeaDhcpLink`` identity columns of a mapping source."""

    kind: str
    kea_subnet_id: int | None
    kea_identity: str | None


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

    def columns(self) -> SourceColumns:
        """Return the ``KeaDhcpLink`` identity columns, for a lookup and for a write."""
        return {"kind": self.kind.value, "kea_subnet_id": self.kea_subnet_id, "kea_identity": self.kea_identity}

    def path(self, family: int) -> str:
        """Return the Kea path of the source in *family*: the path of the key that the source holds."""
        return KEY_KINDS[self.kind].from_source(self, family).path(family)


def _subnet_id(source: MappingSource) -> int:
    """Return the Kea subnet ID of *source*, which its kind needs."""
    if source.kea_subnet_id is None:
        raise ValueError(f"A {source.kind.value} source needs its Kea subnet ID.")
    return source.kea_subnet_id


def _identity(source: MappingSource) -> str:
    """Return the identity of *source*, which its kind needs."""
    if source.kea_identity is None:
        raise ValueError(f"A {source.kind.value} source needs its identity.")
    return source.kea_identity


@dataclass(frozen=True)
class ServerKey:
    """The global configuration of one family: the Server and the family identify it."""

    kind: ClassVar[Kind] = Kind.SERVER

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the global configuration."""
        return MappingSource.server()

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> ServerKey:
        """Return the key that the global configuration *source* holds."""
        return cls()

    def path(self, family: int) -> str:
        """Return the Kea path of the daemon of *family*."""
        return kea_paths.daemon(family)


@dataclass(frozen=True)
class SubnetKey:
    """A Subnet by its Kea subnet ID."""

    subnet_id: int
    kind: ClassVar[Kind] = Kind.SUBNET

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the Subnet."""
        return MappingSource.subnet(self.subnet_id)

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> SubnetKey:
        """Return the key that the Subnet *source* holds."""
        return cls(_subnet_id(source))

    def path(self, family: int) -> str:
        """Return the Kea path of the Subnet in *family*."""
        return kea_paths.subnet(family, self.subnet_id)


@dataclass(frozen=True)
class NamedKey:
    """A client class or a Shared Network by its Kea name."""

    kind: Kind
    name: str

    def __post_init__(self) -> None:
        """Refuse a kind that Kea does not identify by name."""
        if self.kind not in _NAMED_PATHS:
            raise ValueError(f"A {self.kind.value} has no Kea name.")

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the named object."""
        return MappingSource.named(self.kind, self.name)

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> NamedKey:
        """Return the key that the client class or Shared Network *source* holds."""
        return cls(source.kind, _identity(source))

    def path(self, family: int) -> str:
        """Return the Kea path of the named object in *family*."""
        return _NAMED_PATHS[self.kind](family, self.name)


_NAMED_PATHS = {Kind.CLIENT_CLASS: kea_paths.client_class, Kind.SHARED_NETWORK: kea_paths.shared_network}


@dataclass(frozen=True)
class OptionDefinitionKey:
    """A custom Option Definition by option space and code, in the daemon or in the client class *client_class*."""

    space: str
    code: int
    client_class: str | None = None
    kind: ClassVar[Kind] = Kind.OPTION_DEFINITION

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the definition."""
        identity = f"{self.space}:{self.code}"
        if self.client_class is not None:
            identity = f"{self.client_class}:{identity}"
        return MappingSource(Kind.OPTION_DEFINITION, kea_identity=identity)

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> OptionDefinitionKey:
        """Return the key that the Option Definition *source* holds."""
        # A space name has no colon, so the last two colons end the class name and the space.
        rest, _, code = _identity(source).rpartition(":")
        class_name, separator, space = rest.rpartition(":")
        return cls(space, int(code), class_name if separator else None)

    def path(self, family: int) -> str:
        """Return the Kea path of the definition in *family*."""
        return kea_paths.option_definition(family, self.space, self.code, self.client_class)


@dataclass(frozen=True)
class OptionKey:
    """A DHCP Option by the source of the object that assigns it, its identity (ADR 0014), and its occurrence.

    Kea can assign one identity more than once in one object: *occurrence* counts the earlier ones.
    """

    parent: MappingSource
    identity: DHCPOptionIdentity
    occurrence: int = 0
    kind: ClassVar[Kind] = Kind.OPTION

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the Option.

        The Option takes the Kea subnet ID of its parent. Its ``kea_identity`` is a JSON list: the kind and the
        ``kea_identity`` of the parent, the space, the code (else the name), the sorted client classes and the
        occurrence. The list has no length limit (ADR 0013).
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
        return MappingSource(Kind.OPTION, kea_subnet_id=self.parent.kea_subnet_id, kea_identity=identity)

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> OptionKey:
        """Return the key that the Option *source* holds."""
        kind, parent_identity, space, code_or_name, classes, occurrence = json.loads(_identity(source))
        parent = MappingSource(Kind(kind), source.kea_subnet_id, parent_identity)
        return cls(parent, DHCPOptionIdentity(space, code_or_name, frozenset(classes)), occurrence)

    def path(self, family: int) -> str:
        """Return the Kea path of the Option in *family*."""
        return kea_paths.option_of_identity(self.parent.path(family), self.identity, family)


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


@dataclass(frozen=True)
class PlannedOptions:
    """The DHCP Options that one Kea object assigns, each with its key.

    *owner* is the key of the object. Only a Pool whose range is not valid has no mapping source, and then no option
    has a key.
    """

    owner: OptionOwnerKey
    options: tuple[DHCPOption, ...]
    keys: tuple[OptionKey | None, ...]

    @property
    def kind(self) -> Kind:
        """Return the kind of the object: :attr:`Kind.SERVER` for the global configuration."""
        return self.owner.kind

    @property
    def parent(self) -> MappingSource | None:
        """Return the mapping source of the object."""
        return self.owner.source

    @property
    def class_name(self) -> str | None:
        """Return the name of the client class that assigns the options, whose own definitions they use first."""
        return self.owner.name if isinstance(self.owner, NamedKey) and self.kind == Kind.CLIENT_CLASS else None

    def paths(self, family: int) -> tuple[str, ...]:
        """Return the Kea path of each option: the path of its key, else its literal path under the object.

        A run names a keyed Option by its key also when it removes it, so the key gives the one path of the Option.
        """
        owner_path = self.owner.path(family)
        return tuple(
            key.path(family) if key is not None else kea_paths.option(owner_path, option, family)
            for option, key in zip(self.options, self.keys, strict=True)
        )


def planned_options(planned, family: int, declared: Mapping[OptionDefinitionKey, OptionDefIntent]) -> PlannedOptions:
    """Key each option of the *planned* object, with the custom Option Definitions that Kea *declared*.

    The plan and the apply both take the options of an object from here, so their sources cannot drift.
    """
    key = planned.key
    options = planned.global_options if isinstance(planned, PlannedServer) else planned.intent.options
    parent = key.source
    unkeyed = PlannedOptions(key, options, (None,) * len(options))
    if parent is None:
        return unkeyed
    definitions = _known_definitions(declared, unkeyed.class_name)
    seen: Counter[DHCPOptionIdentity] = Counter()
    keys = []
    for option in options:
        identity = option_identity(option, family, definitions)
        keys.append(OptionKey(parent, identity, seen[identity]))
        seen[identity] += 1
    return replace(unkeyed, keys=tuple(keys))


@dataclass(frozen=True)
class PoolKey:
    """A Pool by the Kea subnet ID of its Subnet and its range."""

    subnet_id: int
    range: Pool
    kind: ClassVar[Kind] = Kind.POOL

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the Pool."""
        return MappingSource(Kind.POOL, kea_subnet_id=self.subnet_id, kea_identity=self.range.range)

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> PoolKey:
        """Return the key that the Pool *source* holds: its range is ``start-end``."""
        start, _, end = _identity(source).partition("-")
        return cls(_subnet_id(source), Pool(ipaddress.ip_address(start), ipaddress.ip_address(end)))

    def path(self, family: int) -> str:
        """Return the Kea path of the Pool in *family*, by the text that Kea's config-get gives its range."""
        start, end = self.range.start, self.range.end
        networks = list(ipaddress.summarize_address_range(start, end))
        text = str(networks[0]) if len(networks) == 1 else self.range.range
        return kea_paths.pool(kea_paths.subnet(family, self.subnet_id), text)


@dataclass(frozen=True)
class InvalidPoolKey:
    """A Pool whose Kea text is not a range inside its Subnet. It has a Kea path but no mapping source.

    The run never writes it, and its Pool and DHCP Option observations stay Incomplete.
    """

    subnet_id: int
    text: str
    kind: ClassVar[Kind] = Kind.POOL
    source: ClassVar[None] = None

    def path(self, family: int) -> str:
        """Return the Kea path of the Pool in *family*, by its Kea text."""
        return kea_paths.pool(kea_paths.subnet(family, self.subnet_id), self.text)


@dataclass(frozen=True)
class PDPoolKey:
    """A delegated-prefix Pool by the Kea subnet ID of its Subnet, its prefix and its delegated length.

    Another delegated length is another PD Pool.
    """

    subnet_id: int
    prefix: ipaddress.IPv6Network
    delegated_length: int
    kind: ClassVar[Kind] = Kind.PD_POOL

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the PD Pool."""
        identity = f"{self.prefix}/{self.delegated_length}"
        return MappingSource(Kind.PD_POOL, kea_subnet_id=self.subnet_id, kea_identity=identity)

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> PDPoolKey:
        """Return the key that the PD Pool *source* holds."""
        # The delegated length follows the last slash.
        prefix, _, delegated = _identity(source).rpartition("/")
        return cls(_subnet_id(source), ipaddress.IPv6Network(prefix), int(delegated))

    def path(self, family: int) -> str:
        """Return the Kea path of the PD Pool in *family*."""
        return kea_paths.pd_pool(kea_paths.subnet(family, self.subnet_id), str(self.prefix), self.delegated_length)


class ReservationKey(ABC):
    """A Reservation by its Reservation Identity, in its Scope: Global or In-Subnet."""

    kind: ClassVar[Kind] = Kind.RESERVATION
    identifier_type: IdentifierType
    value: str

    @property
    @abstractmethod
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the Reservation."""

    @abstractmethod
    def path(self, family: int) -> str:
        """Return the Kea path of the Reservation in *family*."""

    @classmethod
    def from_source(cls, source: MappingSource, family: int) -> ReservationKey:
        """Return the key that the Reservation *source* holds. A source without a Kea subnet ID is Global."""
        # An identifier type has no colon, so the first colon ends it.
        identifier_type, _, value = _identity(source).partition(":")
        if identifier_type not in get_args(IdentifierType):
            raise ValueError(f"A Reservation source has no Kea identifier type: {identifier_type!r}.")
        kea_type = cast("IdentifierType", identifier_type)
        if source.kea_subnet_id is None:
            return GlobalReservationKey(validate_family(family), kea_type, value)
        return InSubnetReservationKey(source.kea_subnet_id, kea_type, value)


@dataclass(frozen=True)
class GlobalReservationKey(ReservationKey):
    """A Global Reservation by family and Kea identifier."""

    family: Family
    identifier_type: IdentifierType
    value: str

    @property
    def source(self) -> MappingSource:
        """Return the DHCP Import Mapping source of the Reservation. The family is a column of the mapping."""
        return MappingSource(Kind.RESERVATION, kea_identity=identity_text(self.identifier_type, self.value))

    def path(self, family: int) -> str:
        """Return the Kea path of the Reservation in *family*."""
        return kea_paths.reservation(family, None, self.identifier_type, self.value)


@dataclass(frozen=True)
class InSubnetReservationKey(ReservationKey):
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

    def path(self, family: int) -> str:
        """Return the Kea path of the Reservation in *family*."""
        return kea_paths.reservation(family, self.subnet_id, self.identifier_type, self.value)


MappingKey = ServerKey | SubnetKey | NamedKey | PoolKey | PDPoolKey | ReservationKey | OptionDefinitionKey | OptionKey
#: The key of an object that assigns DHCP Options.
OptionOwnerKey = ServerKey | SubnetKey | NamedKey | PoolKey | InvalidPoolKey | PDPoolKey | ReservationKey


class _KeyDecoder(Protocol):
    def from_source(self, source: MappingSource, family: int) -> MappingKey: ...


#: The key class that decodes a mapping source of each kind: one entry for each kind of ``models.MAPPING_KINDS``.
KEY_KINDS: dict[Kind, _KeyDecoder] = {
    Kind.SERVER: ServerKey,
    Kind.SHARED_NETWORK: NamedKey,
    Kind.SUBNET: SubnetKey,
    Kind.POOL: PoolKey,
    Kind.PD_POOL: PDPoolKey,
    Kind.RESERVATION: ReservationKey,
    Kind.CLIENT_CLASS: NamedKey,
    Kind.OPTION_DEFINITION: OptionDefinitionKey,
    Kind.OPTION: OptionKey,
}


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
    key: ServerKey = ServerKey()


@dataclass(frozen=True)
class PlannedClientClass:
    """A client class by its Kea name."""

    key: NamedKey
    intent: ClientClassIntent
    # The Declared Values of the class, by Kea key.
    settings: dict
    # The custom Option Definitions of the class, written scoped to its row.
    option_definitions: tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...] = ()


@dataclass(frozen=True)
class PlannedSharedNetwork:
    """A Shared Network by its Kea name."""

    key: NamedKey
    intent: SharedNetworkIntent
    # The Declared Values of the Shared Network, by Kea key. Its parent is the global configuration.
    settings: dict


@dataclass(frozen=True)
class PlannedSubnet:
    """A Subnet by Kea subnet ID, with its Pools."""

    key: SubnetKey
    intent: SubnetIntent
    # The Declared Values of the Subnet, by Kea key.
    settings: dict
    # The Declared Values of its Shared Network that the Subnet does not declare: Kea applies them to the Subnet.
    inherited: dict
    # A Pool whose text is not a range inside the Subnet has an InvalidPoolKey; the apply skips that Pool.
    pools: tuple[Planned[PoolKey | InvalidPoolKey, PoolIntent], ...]
    pd_pools: tuple[Planned[PDPoolKey, PDPoolIntent], ...] = ()


@dataclass(frozen=True)
class FamilyPlan:
    """Every DHCP plugin object that one family of a Kea read intends, in apply order."""

    family: Family
    configuration_complete: bool
    # The confirmation number taken before the read. A mapping or IPAM link confirmed with a number at or above it
    # belongs to a newer read, which this plan cannot judge. None: the plan removes no mapped row and no link.
    cutoff: int | None
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

    @property
    def declared_definitions(self) -> dict[OptionDefinitionKey, OptionDefIntent]:
        """Return each custom Option Definition that Kea declares, by key."""
        return {planned.key: planned.intent for planned in self.every_option_definition}

    def option_sets(self) -> tuple[PlannedOptions, ...]:
        """Return the DHCP Options of each object that the plan holds, the Reservations included."""
        declared = self.declared_definitions
        return tuple(planned_options(planned, self.family, declared) for planned in self._option_parents())

    def _option_parents(self) -> Iterator:
        """Yield each planned object that assigns DHCP Options."""
        yield self.server
        yield from self.client_classes
        yield from self.shared_networks
        for subnet in self.subnets:
            yield subnet
            yield from subnet.pools
            yield from subnet.pd_pools
        yield from keyed_reservations(self.reservations)


def _option_definitions(
    definitions: tuple[OptionDefIntent, ...], class_name: str | None = None
) -> tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]:
    """Key each custom Option Definition of the daemon or of a client class. A later one of the same key wins."""
    index: dict[OptionDefinitionKey, OptionDefIntent] = {}
    for definition in definitions:
        index[OptionDefinitionKey(definition.space, definition.code, class_name)] = definition
    return tuple(Planned(key, definition) for key, definition in index.items())


def _pool_key(subnet: SubnetIntent, pool: PoolIntent) -> PoolKey | InvalidPoolKey:
    try:
        return PoolKey(subnet.kea_subnet_id, parse_pool(pool.pool, subnet_network(subnet.cidr, subnet.family)))
    except ValueError:
        return InvalidPoolKey(subnet.kea_subnet_id, pool.pool)


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
    key = NamedKey(Kind.CLIENT_CLASS, intent.name)
    return PlannedClientClass(key, intent, settings, _option_definitions(intent.option_defs, intent.name))


def _planned_shared_networks(config: ServerConfigIntent, family: Family) -> tuple[PlannedSharedNetwork, ...]:
    """Plan each Shared Network with its Declared Values against the global configuration."""
    return tuple(
        PlannedSharedNetwork(
            NamedKey(Kind.SHARED_NETWORK, intent.name),
            intent,
            declared_values(family, kea_paths.SHARED_NETWORKS, intent.settings, config.global_settings),
        )
        for intent in config.shared_networks
    )


def _planned_subnets(
    config: ServerConfigIntent, family: Family, networks: tuple[PlannedSharedNetwork, ...]
) -> tuple[PlannedSubnet, ...]:
    """Plan each Subnet with its Declared Values. Its parent is its Shared Network, else the global configuration."""
    by_name = {network.key.name: network for network in networks}
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
        planned.append(PlannedSubnet(SubnetKey(subnet.kea_subnet_id), subnet, settings, inherited, pools, pd_pools))
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
        cutoff=config.cutoff,
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
# The kinds whose objects the configuration read observes. DHCP Options take the gaps of their parent kind.
_CONFIGURATION_KINDS = frozenset(REMOVAL_ORDER) - {Kind.RESERVATION, Kind.OPTION}
_CONFIGURATION_GAP = "The Server Configuration was not read in full."
#: The mapped kinds whose objects assign DHCP Options. The global configuration of a family has no observation.
_OPTION_PARENTS = (Kind.CLIENT_CLASS, Kind.SHARED_NETWORK, Kind.SUBNET, Kind.POOL, Kind.PD_POOL, Kind.RESERVATION)


def mapped_kinds(family: int) -> tuple[Kind, ...]:
    """Return the kinds of :data:`REMOVAL_ORDER` that *family* has: only DHCPv6 has delegated-prefix Pools."""
    return tuple(kind for kind in REMOVAL_ORDER if family == 6 or kind != Kind.PD_POOL)


@dataclass(frozen=True)
class KindObservation:
    """The Kea sources of one mapped kind that a read reports, and why the observation is Incomplete.

    Only a mapped row that no gap covers (:meth:`gap`) can be stale.
    """

    sources: frozenset[MappingSource]
    # Empty when the observation is Complete.
    incomplete: str = ""
    # DHCP Options only: why the read cannot judge the Options of each kind of parent; () when it can.
    option_gaps: Mapping[Kind, tuple[str, ...]] | None = None

    @property
    def complete(self) -> bool:
        """Return whether the read reported every Kea source of the kind."""
        return not self.incomplete

    def gap(self, source: MappingSource, family: int) -> tuple[str, ...]:
        """Return why the read of *family* cannot judge the mapped row of *source*: () when a missing source makes it stale.

        A DHCP Option is judged by its own gaps and by the observation of the kind of its parent.
        """
        if self.option_gaps is None:
            return (self.incomplete,) if self.incomplete else ()
        return self.option_gaps[OptionKey.from_source(source, family).parent.kind]


def _configuration_gaps(plan: FamilyPlan) -> dict[Kind, list[str]]:
    """Return why the configuration read is Incomplete for each configuration kind."""
    gaps: dict[Kind, list[str]] = {kind: [] for kind in _CONFIGURATION_KINDS}
    if not plan.configuration_complete:
        for reasons in gaps.values():
            reasons.append(_CONFIGURATION_GAP)
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
    unkeyed_pools = sum(pool.key.source is None for subnet in plan.subnets for pool in subnet.pools)
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


def _observed_sources(plan: FamilyPlan, options: tuple[PlannedOptions, ...]) -> dict[Kind, frozenset[MappingSource]]:
    """Return the Kea source of each object that the plan reports, by mapped kind. *options* keys its Options."""
    pools = (pool.key.source for subnet in plan.subnets for pool in subnet.pools)
    return {
        Kind.OPTION: frozenset(key.source for each in options for key in each.keys if key is not None),
        Kind.RESERVATION: frozenset(planned.key.source for planned in keyed_reservations(plan.reservations)),
        Kind.POOL: frozenset(source for source in pools if source is not None),
        Kind.PD_POOL: frozenset(pd_pool.key.source for subnet in plan.subnets for pd_pool in subnet.pd_pools),
        Kind.SUBNET: frozenset(subnet.key.source for subnet in plan.subnets),
        Kind.SHARED_NETWORK: frozenset(planned.key.source for planned in plan.shared_networks),
        Kind.CLIENT_CLASS: frozenset(planned.key.source for planned in plan.client_classes),
        Kind.OPTION_DEFINITION: frozenset(planned.key.source for planned in plan.every_option_definition),
    }


def _option_gaps(
    plan: FamilyPlan, gaps: dict[Kind, list[str]], options: tuple[PlannedOptions, ...]
) -> dict[Kind, tuple[str, ...]]:
    """Return why the read cannot judge the DHCP Options of each kind of parent.

    A read observes the Options of an object only where it observes that object, so the gaps of the Options of one
    kind of parent are the gaps of that kind, the option-data entries of that kind that the parse dropped, and their
    Options without a mapping identity. The global configuration has no observation of its own: its Options take the
    gap of an unread Server Configuration.
    """
    dropped = Counter(entry.parent for entry in plan.dropped if entry.kind == Kind.OPTION)
    unkeyed = Counter(each.kind for each in options for key in each.keys if key is None)
    found = {}
    for kind in (Kind.SERVER, *(kind for kind in _OPTION_PARENTS if kind in mapped_kinds(plan.family))):
        if kind == Kind.SERVER:
            reasons = [] if plan.configuration_complete else [_CONFIGURATION_GAP]
        else:
            reasons = list(gaps[kind])
        if dropped[kind]:
            owner = "the global configuration" if kind == Kind.SERVER else f"a {KIND_LABELS[kind]}"
            entries = counted(
                dropped[kind], f"DHCP Option entry of {owner} that is", f"DHCP Option entries of {owner} that are"
            )
            reasons.append(f"The configuration has {entries} not valid.")
        if unkeyed[kind]:
            reasons.append(f"{counted(unkeyed[kind], 'DHCP Option has', 'DHCP Options have')} no mapping identity.")
        found[kind] = tuple(dict.fromkeys(reasons))
    return found


def observations(plan: FamilyPlan) -> dict[Kind, KindObservation]:
    """Return the observation of each mapped kind of the family (:func:`mapped_kinds`) that one family of a read gives.

    The global configuration of a family has no observation: a family that was not read gives no plan.
    """
    options = plan.option_sets()
    sources = _observed_sources(plan, options)
    gaps = _configuration_gaps(plan)
    reservation_gap = _reservation_gap(plan.reservations)
    gaps[Kind.RESERVATION] = [reservation_gap] if reservation_gap else []
    option_gaps = _option_gaps(plan, gaps, options)
    every_gap = " ".join(dict.fromkeys(reason for reasons in option_gaps.values() for reason in reasons))
    return {
        kind: KindObservation(sources[kind], every_gap, option_gaps)
        if kind == Kind.OPTION
        else KindObservation(sources[kind], " ".join(gaps[kind]))
        for kind in mapped_kinds(plan.family)
    }


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
