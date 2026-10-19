# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The plan step of the DHCP Import: the keyed DHCP plugin objects that one family of a Kea read intends.

The plan is pure. It reads no database, no DHCP plugin and no Kea, so a test can build it from recorded Kea
replies. Each planned object carries its DHCP Import Mapping identity where one exists (a Subnet by Kea subnet ID,
a Global Reservation by family and identifier), else its structural key. The plan keeps the Reservation
observation, and :func:`keyed_reservations` keys its records. The apply step in
:mod:`netbox_kea.integrations.dhcp_plugin` turns the parsed intents into plugin field values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, TypeVar

from ..constants import Family, validate_family
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import ClientClassIntent, OptionDefIntent, PoolIntent, ServerConfigIntent, SubnetIntent
from ..pools import Pool, parse_pool
from ..reservations import IdentifierType, InSubnetReservationScope, Reservation

if TYPE_CHECKING:
    from ..dhcp_options import DHCPOption
    from ..ipam_reconciliation import ReservationObservation

K = TypeVar("K")
T = TypeVar("T")


@dataclass(frozen=True)
class Planned(Generic[K, T]):
    """One intended DHCP plugin object: its key and the parsed Kea intent."""

    key: K
    intent: T


@dataclass(frozen=True)
class OptionDefinitionKey:
    """A custom Option Definition by option space and code."""

    space: str
    code: int


@dataclass(frozen=True)
class PoolKey:
    """A Pool by the Kea subnet ID of its Subnet and its range. A Subnet without an ID gives ``None``."""

    subnet_id: int | None
    range: Pool


@dataclass(frozen=True)
class GlobalReservationKey:
    """A Global Reservation by family and Kea identifier: its DHCP Import Mapping identity."""

    family: Family
    identifier_type: IdentifierType
    value: str


@dataclass(frozen=True)
class InSubnetReservationKey:
    """An In-Subnet Reservation by the Kea subnet ID of its Subnet and its Kea identifier."""

    subnet_id: int
    identifier_type: IdentifierType
    value: str


ReservationKey = GlobalReservationKey | InSubnetReservationKey


@dataclass(frozen=True)
class PlannedServer:
    """The global configuration of one family, for the DHCPServer of the Server."""

    global_settings: dict
    global_options: tuple[DHCPOption, ...]
    # None: the key is absent or invalid in the Server Configuration Snapshot.
    host_reservation_identifiers: tuple[str, ...] | None


@dataclass(frozen=True)
class PlannedSubnet:
    """A Subnet by Kea subnet ID, with its Pools. ``None``: Kea gave no ID, so the Subnet has no mapping identity."""

    key: int | None
    intent: SubnetIntent
    # A Pool key is None when its text is not a range inside the Subnet; the apply skips that Pool.
    pools: tuple[Planned[PoolKey | None, PoolIntent], ...]


@dataclass(frozen=True)
class FamilyPlan:
    """Every DHCP plugin object that one family of a Kea read intends, in apply order."""

    family: Family
    configuration_complete: bool
    server: PlannedServer
    option_definitions: tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]
    client_classes: tuple[Planned[str, ClientClassIntent], ...]
    subnets: tuple[PlannedSubnet, ...]
    # None: the read failed. keyed_reservations() keys its records.
    reservations: ReservationObservation | None


def default_space(family: int) -> str:
    """Return the Kea and DHCP plugin default option space of a family."""
    return "dhcp6" if family == 6 else "dhcp4"


def _option_definitions(config: ServerConfigIntent) -> tuple[Planned[OptionDefinitionKey, OptionDefIntent], ...]:
    """Key each custom Option Definition that has a code. A later definition of the same key replaces an earlier one."""
    index: dict[OptionDefinitionKey, OptionDefIntent] = {}
    for definition in config.option_defs:
        if definition.code is None:
            continue
        index[OptionDefinitionKey(definition.space or default_space(config.family), definition.code)] = definition
    return tuple(Planned(key, definition) for key, definition in index.items())


def _pool_key(subnet: SubnetIntent, pool: PoolIntent) -> PoolKey | None:
    try:
        return PoolKey(subnet.kea_subnet_id, parse_pool(pool.pool, subnet_network(subnet.cidr, subnet.family)))
    except ValueError:
        return None


def _planned_subnet(subnet: SubnetIntent) -> PlannedSubnet:
    pools = tuple(Planned(_pool_key(subnet, pool), pool) for pool in subnet.pools)
    return PlannedSubnet(subnet.kea_subnet_id, subnet, pools)


def _reservation_key(reservation: Reservation) -> ReservationKey:
    identity = reservation.identity
    if isinstance(reservation.scope, InSubnetReservationScope):
        return InSubnetReservationKey(reservation.scope.subnet.subnet_id, identity.identifier_type, identity.value)
    return GlobalReservationKey(reservation.family, identity.identifier_type, identity.value)


def keyed_reservations(observation: ReservationObservation | None) -> tuple[Planned[ReservationKey, Reservation], ...]:
    """Key each valid record of a Reservation observation. A failed read (``None``) gives no record."""
    if observation is None:
        return ()
    return tuple(Planned(_reservation_key(record), record) for record in observation.snapshot.records)


def plan_family(config: ServerConfigIntent, observation: ReservationObservation | None) -> FamilyPlan:
    """Return the plan of one family from its parsed configuration and its Reservation observation."""
    return FamilyPlan(
        family=validate_family(config.family),
        configuration_complete=config.configuration_complete,
        server=PlannedServer(config.global_settings, config.global_options, config.host_reservation_identifiers),
        option_definitions=_option_definitions(config),
        client_classes=tuple(Planned(intent.name, intent) for intent in config.client_classes),
        subnets=tuple(_planned_subnet(subnet) for subnet in config.subnets),
        reservations=observation,
    )
