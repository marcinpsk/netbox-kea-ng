# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, cast

from typing_extensions import assert_never

from .constants import Family, IPAddressValue
from .dhcp_options import (
    DHCPOption,
    DHCPOptionEdit,
    OptionDefinition,
    option_data,
    option_matches_intent,
    parse_dhcp_options,
)
from .identifiers import normalize_hex
from .leases import DHCPv4AddressLease, DHCPv6PrefixLease, Lease, LeaseSnapshot

if TYPE_CHECKING:
    from .subnet_catalogue import CatalogueSnapshot, SubnetIdentity, VerifiedSubnet

IdentifierType = Literal["hw-address", "duid", "circuit-id", "client-id", "flex-id"]
FLEX_ID: IdentifierType = "flex-id"
ReservationQueryMode = Literal["page", "identity", "address", "hostname"]

_IDENTIFIERS: dict[Family, tuple[IdentifierType, ...]] = {
    4: ("hw-address", "duid", "circuit-id", "client-id", "flex-id"),
    6: ("duid", "hw-address", "flex-id"),
}
# A Kea lease carries only these identifier types, so a circuit-id or flex-id
# Reservation can never be matched from a lease record.
_LEASE_IDENTIFIERS: dict[Family, tuple[IdentifierType, ...]] = {
    4: ("hw-address", "client-id"),
    6: ("duid", "hw-address"),
}
_IDENTIFIER_LABELS: dict[IdentifierType, str] = {
    "hw-address": "Hardware Address",
    "duid": "DUID",
    "client-id": "Client ID",
    "circuit-id": "Circuit ID",
    "flex-id": "Flex ID",
}
_HEX_IDENTIFIER_OCTETS: dict[IdentifierType, tuple[int, int]] = {
    "hw-address": (1, 20),
    "duid": (1, 128),
    "client-id": (2, 128),
}
_HEX_IDENTIFIERS = frozenset(_HEX_IDENTIFIER_OCTETS)
_MAX_OPAQUE_IDENTIFIER_LENGTH = 255
_QUERY_PARAMETERS_BY_MODE: dict[ReservationQueryMode, frozenset[str]] = {
    "page": frozenset({"page", "limit", "cursor"}),
    "identity": frozenset({"scope", "subnet_id", "identifier_type", "identifier"}),
    "address": frozenset({"subnet_id", "ip_address"}),
    "hostname": frozenset({"hostname"}),
}
_QUERY_SELECTORS_BY_MODE: dict[ReservationQueryMode, frozenset[str]] = {
    "page": frozenset({"page", "limit", "cursor"}),
    "identity": frozenset({"scope", "identifier_type", "identifier"}),
    "address": frozenset({"ip_address"}),
    "hostname": frozenset({"hostname"}),
}
_QUERY_PARAMETERS = frozenset().union(*_QUERY_PARAMETERS_BY_MODE.values())


def _max_identifier_length(identifier_type: IdentifierType) -> int:
    """Return the longest normalized value one identifier type can hold."""
    octets = _HEX_IDENTIFIER_OCTETS.get(identifier_type)
    # Normalized hex is colon-separated octet pairs: three characters per octet, less one.
    return octets[1] * 3 - 1 if octets else _MAX_OPAQUE_IDENTIFIER_LENGTH


def identity_text(identifier_type: IdentifierType, value: str) -> str:
    """Return the ``identifier-type:value`` text of one Reservation identifier."""
    return f"{identifier_type}:{value}"


#: Longest :func:`identity_text` any Reservation Identity can produce.
MAX_IDENTITY_LENGTH = max(len(identity_text(name, "x" * _max_identifier_length(name))) for name in _IDENTIFIER_LABELS)


def reservation_query_mode(parameter_names: Collection[str]) -> ReservationQueryMode:
    """Select one REST Reservation query mode from its supplied parameters."""
    provided = set(parameter_names) & _QUERY_PARAMETERS
    selected = tuple(mode for mode, selectors in _QUERY_SELECTORS_BY_MODE.items() if not provided.isdisjoint(selectors))
    if len(selected) != 1:
        raise ValueError("Select exactly one Reservation query.")
    mode = selected[0]
    if not provided <= _QUERY_PARAMETERS_BY_MODE[mode]:
        raise ValueError("Select exactly one Reservation query.")
    return mode


def reservation_identifier_types(family: int) -> tuple[IdentifierType, ...]:
    """Return the ordered native Reservation Identity types for one family."""
    # bool is an int subclass and 4.0 == 4, so membership alone accepts both.
    if not isinstance(family, int) or isinstance(family, bool) or family not in (4, 6):
        raise ValueError(f"family must be 4 or 6, got {family!r}")
    return _IDENTIFIERS[cast(Family, family)]


def lease_identifier_types(family: int) -> tuple[IdentifierType, ...]:
    """Return the ordered Identity types that a lease can carry for one family."""
    reservation_identifier_types(family)
    return _LEASE_IDENTIFIERS[cast(Family, family)]


def _lease_identifiers(lease: Lease) -> tuple[tuple[IdentifierType, str | None], ...]:
    """Return each identifier that *lease* carries, in the order of ``lease_identifier_types``."""
    if isinstance(lease, DHCPv4AddressLease):
        return (("hw-address", lease.hw_address), ("client-id", lease.client_id))
    return (("duid", lease.duid), ("hw-address", lease.hw_address))


@dataclass(frozen=True)
class LeaseIdentities:
    """The Reservation Identities that one Lease carries, in match order."""

    identities: tuple[ReservationIdentity, ...]
    #: The Lease also carries an identifier that no Reservation can hold, so no match proves "no Reservation".
    foreign: bool


def lease_identities(lease: Lease) -> LeaseIdentities:
    """Return the normalized Reservation Identities that one typed Lease carries, in match order."""
    identities: list[ReservationIdentity] = []
    foreign = False
    for identifier_type, value in _lease_identifiers(lease):
        if value is None:
            continue
        try:
            identities.append(ReservationIdentity(identifier_type, value))
        except ValueError:
            foreign = True
    return LeaseIdentities(tuple(identities), foreign)


class UnknownLeasePresence(Enum):
    """Why the Current Lease Presence of a Reservation is Unknown."""

    #: The Lease Snapshot excluded a record, so a missing Lease cannot be confirmed.
    INCOMPLETE_SNAPSHOT = auto()
    #: A Current Lease carries an identifier that no Reservation can hold.
    FOREIGN_IDENTIFIER = auto()
    #: The Lease query guard refused the query.
    QUERY_GUARD = auto()
    #: Kea returned a failure result, or the transport failed.
    KEA_ERROR = auto()
    #: Kea returned a reply that the reader cannot use.
    MALFORMED_REPLY = auto()
    #: The Server settings, the search or the Lease Snapshot of the read were not valid.
    INVALID_READ = auto()
    #: Kea has no Lease query for the identifier, and no reserved address can match.
    UNSEARCHABLE_IDENTIFIER = auto()
    #: Kea does not know a Lease command, so no Reservation of the Server has an observable Lease.
    LEASE_HOOK_UNAVAILABLE = auto()


@dataclass(frozen=True)
class LeasePresent:
    """The client of the Reservation holds a Current Lease."""

    #: The reserved address that holds the Lease; ``None`` when the identity matched.
    address: IPAddressValue | None


@dataclass(frozen=True)
class LeaseAbsent:
    """A complete Lease Snapshot shows no Current Lease for the client of the Reservation."""


@dataclass(frozen=True)
class LeasePresenceUnknown:
    """No Lease Snapshot can show whether the client of the Reservation holds a Current Lease."""

    reason: UnknownLeasePresence


CurrentLeasePresence = LeasePresent | LeaseAbsent | LeasePresenceUnknown


@dataclass(frozen=True)
class CurrentLeaseFacts:
    """The Current Leases of one Lease Snapshot, as a Reservation can match them."""

    addresses: frozenset[IPAddressValue]
    identities: frozenset[ReservationIdentity]
    #: Why the Snapshot cannot show that a Reservation holds no Lease; ``None`` when it can.
    gap: UnknownLeasePresence | None


def current_lease_facts(snapshot: LeaseSnapshot) -> CurrentLeaseFacts:
    """Return the Current Leases of *snapshot*; only they are live evidence of a relationship."""
    current = snapshot.current_records
    identities: set[ReservationIdentity] = set()
    foreign = False
    for lease in current:
        carried = lease_identities(lease)
        identities.update(carried.identities)
        foreign = foreign or carried.foreign
    gap = None
    if not snapshot.complete:
        gap = UnknownLeasePresence.INCOMPLETE_SNAPSHOT
    elif foreign:
        gap = UnknownLeasePresence.FOREIGN_IDENTIFIER
    return CurrentLeaseFacts(
        addresses=frozenset(lease.identity.address for lease in current if lease.kind == "address"),
        identities=frozenset(identities),
        gap=gap,
    )


def current_lease_presence(reservation: Reservation, facts: CurrentLeaseFacts) -> CurrentLeasePresence:
    """Return whether the client of *reservation* holds one of the Current Leases of *facts*.

    The facts of an In-Subnet Reservation are the Leases of its Subnet, so a reserved address matches too. The facts
    of a Global Reservation are the Leases of its identity in any Subnet, so only the identity matches.
    """
    if isinstance(reservation.scope, InSubnetReservationScope):
        matched = next((address for address in reservation.addresses if address in facts.addresses), None)
        if matched is not None:
            return LeasePresent(matched)
    if reservation.identity in facts.identities:
        return LeasePresent(None)
    if not reservation.addresses and reservation.identity.identifier_type not in lease_identifier_types(
        reservation.family
    ):
        return LeasePresenceUnknown(UnknownLeasePresence.UNSEARCHABLE_IDENTIFIER)
    if facts.gap is not None:
        return LeasePresenceUnknown(facts.gap)
    return LeaseAbsent()


class UnknownReservationMatch(Enum):
    """Why the Reservation Match of a Lease is Unknown."""

    #: The Subnet Catalogue does not verify the Subnet of the Lease, so no lookup has a scope.
    UNVERIFIED_SUBNET = auto()
    #: Kea returned a failure result, or the transport failed.
    KEA_ERROR = auto()
    #: Kea returned a reply that the reader cannot use.
    MALFORMED_REPLY = auto()
    #: The Server settings were not valid, or Kea returned a Reservation that does not parse or fit the lookup.
    INVALID_READ = auto()
    #: No Reservation matched, and the Lease carries an identifier that no Reservation can hold.
    FOREIGN_IDENTIFIER = auto()
    #: Kea does not know a Reservation command, so no Lease of the Server has a known match.
    RESERVATION_HOOK_UNAVAILABLE = auto()
    #: Kea can give an allocation of another Subnet of the Shared Network, which changes the match, or not.
    UNKNOWN_SHARED_NETWORK = auto()
    #: The configuration does not show the reservation flags that decide whether Kea applies the Reservation.
    RESERVATION_FLAGS_UNKNOWN = auto()
    #: reservations-out-of-pool applies, and the configuration does not show the Pools that decide the match.
    POOLS_UNKNOWN = auto()


class IgnoredReservationReason(Enum):
    """Why Kea does not apply the Reservation of a Lease's client in the Lease's Subnet."""

    #: The Reservation is Global, and the Subnet sets reservations-global to false.
    GLOBAL_RESERVATIONS_DISABLED = auto()
    #: The Reservation is In-Subnet, and the Subnet sets reservations-in-subnet to false.
    IN_SUBNET_RESERVATIONS_DISABLED = auto()
    #: The Subnet sets reservations-out-of-pool, each reserved allocation of the Lease kind is in a Pool of the Subnet,
    #: and the Lease does not hold one of them.
    OUT_OF_POOL = auto()


@dataclass(frozen=True)
class Reserved:
    """The Reservation of the client reserves the allocation of the Lease."""

    reservation: Reservation


@dataclass(frozen=True)
class StaleMac:
    """The Reservation reserves the allocation of the Lease for another hardware address."""

    reservation: Reservation
    #: The normalized hardware address of the Lease.
    lease_mac: str


@dataclass(frozen=True)
class PendingAddressChange:
    """The Reservation reserves other allocations of the Lease kind; the Lease keeps its own until renewal."""

    reservation: Reservation
    #: Every reserved allocation of the Lease kind that counts, because the domain names no primary one.
    reserved: tuple[IPAddressValue, ...] | tuple[ipaddress.IPv6Network, ...]


@dataclass(frozen=True)
class HostOnlyReservation:
    """The Reservation reserves no allocation that counts for the Lease's Subnet, so Kea assigns the Lease from a pool."""

    reservation: Reservation


@dataclass(frozen=True)
class OtherKindReservation:
    """The Reservation reserves only allocations of the other kind than the Lease that count for its Subnet."""

    reservation: Reservation


@dataclass(frozen=True)
class IgnoredReservation:
    """Kea does not apply the Reservation in the Lease's Subnet, so the Lease is a dynamic allocation."""

    reservation: Reservation
    reason: IgnoredReservationReason


@dataclass(frozen=True)
class Unreserved:
    """No Reservation of the client is in the Subnet of the Lease or in the Global Scope."""

    #: The Subnet of the Lease, where a new Reservation goes.
    subnet: VerifiedSubnet


@dataclass(frozen=True)
class ReservationMatchUnknown:
    """No lookup can show how the Lease relates to a Reservation."""

    reason: UnknownReservationMatch


ReservationMatch = (
    Reserved
    | StaleMac
    | PendingAddressChange
    | HostOnlyReservation
    | OtherKindReservation
    | IgnoredReservation
    | Unreserved
    | ReservationMatchUnknown
)


def reservation_match(
    lease: Lease,
    subnet: VerifiedSubnet,
    reservation: Reservation | None,
    shared_network: tuple[VerifiedSubnet, ...] | None,
    *,
    global_reservation: Reservation | None,
) -> ReservationMatch:
    """Return how *reservation*, which the lookups of *lease* found in *subnet* or globally, relates to *lease*.

    ``None`` is no Reservation found. *shared_network* holds *subnet* and the other Subnets of its Shared Network;
    ``None`` is a Shared Network that the Catalogue cannot show. A Reservation of a scope that the reservation flags
    of *subnet* disable is ignored: the lookups try the enabled scopes first. Global and In-Subnet Reservations
    follow one rule: a reserved address counts in *subnet*, and a reserved delegated prefix always counts. With
    reservations-out-of-pool, an In-Subnet reserved allocation in a Pool of *subnet* does not count, but a Lease of
    a reserved allocation stays Reserved. When the In-Subnet Reservation holds allocations but gives none of the
    Lease kind, Kea tries *global_reservation*, the Global Reservation of the client: the lookups read it only where
    ``tries_global_reservation()`` is true. An In-Subnet Reservation of no allocation stays Host-Only. When the
    Global Reservation gives an allocation, the match is Unknown with other Subnets in *shared_network* or with no
    *shared_network*, because Kea tries their In-Subnet Reservations first. Else DHCPv6 takes the Global match, and
    DHCPv4 gives the In-Subnet address. The match is Unknown when a fact that the configuration does not show
    changes it.

    Raises:
        ValueError: If *subnet* is not the Subnet of *lease*, *shared_network* does not hold *subnet*, or
            *global_reservation* is not a Global Reservation that Kea tries after *reservation*.

    """
    if lease.subnet_id != subnet.subnet_id:
        raise ValueError("The Reservation Match of a Lease needs the Subnet of the Lease.")
    if shared_network is not None and subnet not in shared_network:
        raise ValueError("The Shared Network of a Reservation Match must hold the Subnet of the Lease.")
    if global_reservation is not None and (
        reservation is None
        or not isinstance(global_reservation.scope, GlobalReservationScope)
        or not tries_global_reservation(lease, subnet, reservation)
    ):
        raise ValueError("A Reservation Match tries a Global Reservation only where Kea tries it.")
    if reservation is None:
        if lease_identities(lease).foreign:
            return ReservationMatchUnknown(UnknownReservationMatch.FOREIGN_IDENTIFIER)
        return Unreserved(subnet)
    flags = subnet.reservation_flags
    if flags is None:
        return ReservationMatchUnknown(UnknownReservationMatch.RESERVATION_FLAGS_UNKNOWN)
    in_subnet = isinstance(reservation.scope, InSubnetReservationScope)
    if in_subnet and not flags.in_subnet:
        return IgnoredReservation(reservation, IgnoredReservationReason.IN_SUBNET_RESERVATIONS_DISABLED)
    if not in_subnet and not flags.global_:
        return IgnoredReservation(reservation, IgnoredReservationReason.GLOBAL_RESERVATIONS_DISABLED)
    fallback = None
    if global_reservation is not None:
        fallback = reservation_match(lease, subnet, global_reservation, shared_network, global_reservation=None)
    return _applied_match(
        lease, subnet, reservation, shared_network, out_of_pool=in_subnet and flags.out_of_pool, fallback=fallback
    )


def _applied_match(
    lease: Lease,
    subnet: VerifiedSubnet,
    reservation: Reservation,
    shared_network: tuple[VerifiedSubnet, ...] | None,
    *,
    out_of_pool: bool,
    fallback: ReservationMatch | None,
) -> ReservationMatch:
    """Return the match of *reservation*, of a scope that *subnet* applies; *fallback* is the Global match Kea tries."""
    prefix_lease = isinstance(lease, DHCPv6PrefixLease)
    addresses = _reserved_addresses(reservation, subnet, shared_network, out_of_pool=out_of_pool)
    # Kea also checks a reserved prefix against the PD Pools, and the configuration facts do not hold them.
    prefixes_unknown = out_of_pool and prefix_lease
    prefixes = () if prefixes_unknown else reservation.delegated_prefixes
    prefix_unknown = reservation.delegated_prefixes if prefixes_unknown else ()
    holds = _holds_allocation(lease, reservation)

    def outcome(
        counted: tuple[IPAddressValue, ...], delegated: tuple[ipaddress.IPv6Network, ...], excluded: bool
    ) -> ReservationMatch:
        """Return the match when *counted* and *delegated* count, and *excluded* says a Pool excludes the Lease kind."""
        own = delegated if prefix_lease else counted
        # DHCPv4 goes on to the Global address only past an excluded one; DHCPv6 past any IA without an allocation.
        if fallback is not None and _gives_allocation(fallback) and not own and (excluded or lease.family == 6):
            return _fallback_match(lease, subnet, reservation, shared_network, fallback)
        if holds:
            return _allocation_match(lease, reservation, reservation.addresses, reservation.delegated_prefixes)
        if excluded and not own:
            return IgnoredReservation(reservation, IgnoredReservationReason.OUT_OF_POOL)
        return _allocation_match(lease, reservation, counted, delegated)

    known_excluded = False if prefix_lease else addresses.in_pool
    excluded = bool(prefix_unknown) if prefix_lease else addresses.in_pool or bool(addresses.pool_unknown)
    match = outcome(addresses.counted, prefixes, excluded)
    if isinstance(match, ReservationMatchUnknown):
        return match
    for reason, alternative in (
        (
            UnknownReservationMatch.POOLS_UNKNOWN,
            ((*addresses.counted, *addresses.pool_unknown), (*prefixes, *prefix_unknown), known_excluded)
            if addresses.pool_unknown or prefix_unknown
            else None,
        ),
        (
            UnknownReservationMatch.UNKNOWN_SHARED_NETWORK,
            ((*addresses.counted, *addresses.possible), prefixes, excluded) if addresses.possible else None,
        ),
    ):
        if alternative is not None and match != outcome(*alternative):
            return ReservationMatchUnknown(reason)
    return match


def _fallback_match(
    lease: Lease,
    subnet: VerifiedSubnet,
    reservation: Reservation,
    shared_network: tuple[VerifiedSubnet, ...] | None,
    fallback: ReservationMatch,
) -> ReservationMatch:
    """Return the match when Kea goes on past *reservation*, and *fallback*, the Global match, gives an allocation.

    Kea walks the In-Subnet Reservations of the other Subnets of the Shared Network first, and the lookups do not
    read them. In DHCPv4, the applied Global address only selects *subnet*: ``currentHost()`` is then *reservation*,
    so Kea gives its address, also in a Pool.
    """
    if shared_network is None or len(shared_network) > 1:
        return ReservationMatchUnknown(UnknownReservationMatch.UNKNOWN_SHARED_NETWORK)
    if isinstance(fallback, ReservationMatchUnknown) or lease.family == 6:
        return fallback
    local = tuple(address for address in reservation.addresses if address in subnet.network)
    return _allocation_match(lease, reservation, local, ())


def tries_global_reservation(lease: Lease, subnet: VerifiedSubnet, reservation: Reservation) -> bool:
    """Return whether Kea can try the Global Reservation of the client of *lease* after *reservation*.

    Only an In-Subnet Reservation that can give no allocation of the Lease kind qualifies, in a Subnet that applies
    both scopes. DHCPv4 goes on when reservations-out-of-pool can exclude the reserved address. DHCPv6 goes on when
    the Reservation holds an allocation, the Lease holds none of them, and no local allocation of the Lease kind
    counts or can count. A Reservation of no allocation stops Kea in both families.
    """
    flags = subnet.reservation_flags
    if flags is None or not (flags.in_subnet and flags.global_):
        return False
    if not isinstance(reservation.scope, InSubnetReservationScope):
        return False
    if lease.family == 4:
        return flags.out_of_pool and any(
            address in subnet.network and _pool_holds(address, subnet) is not False for address in reservation.addresses
        )
    if not (reservation.addresses or reservation.delegated_prefixes) or _holds_allocation(lease, reservation):
        return False
    # A reserved prefix counts, or the PD Pools that the configuration does not show can let it count.
    if isinstance(lease, DHCPv6PrefixLease):
        return not reservation.delegated_prefixes
    return all(
        flags.out_of_pool and address in subnet.network and _pool_holds(address, subnet) is True
        for address in reservation.addresses
    )


def _holds_allocation(lease: Lease, reservation: Reservation) -> bool:
    """Return whether *reservation* reserves the allocation of *lease*."""
    if isinstance(lease, DHCPv6PrefixLease):
        return lease.prefix in reservation.delegated_prefixes
    return lease.address in reservation.addresses


def _gives_allocation(match: ReservationMatch) -> bool:
    """Return whether *match*, of a Global Reservation, gives an allocation of the Lease kind, or can give one."""
    match match:
        case Reserved() | StaleMac() | PendingAddressChange() | ReservationMatchUnknown():
            return True
        case HostOnlyReservation() | OtherKindReservation() | IgnoredReservation() | Unreserved():
            return False
        case _:
            assert_never(match)


def _pool_holds(address: IPAddressValue, subnet: VerifiedSubnet) -> bool | None:
    """Return whether a Pool of *subnet* holds *address*; None when the configuration does not show the Pools."""
    if subnet.configuration is None:
        return None
    return any(pool.contains(address) for pool in subnet.configuration.pools)


@dataclass(frozen=True)
class _ReservedAddresses:
    """The reserved addresses of a Reservation, sorted by whether they count for the Lease's Subnet."""

    #: The addresses that Kea gives for the Subnet.
    counted: tuple[IPAddressValue, ...]
    #: An address in the Subnet is in a Pool, so reservations-out-of-pool leaves it out.
    in_pool: bool
    #: The addresses that count only when no Pool holds them, and the configuration does not show the Pools.
    pool_unknown: tuple[IPAddressValue, ...]
    #: The addresses outside the Subnet that Kea can give through the Shared Network, or not.
    possible: tuple[IPAddressValue, ...]


def _reserved_addresses(
    reservation: Reservation,
    subnet: VerifiedSubnet,
    shared_network: tuple[VerifiedSubnet, ...] | None,
    *,
    out_of_pool: bool,
) -> _ReservedAddresses:
    """Sort the reserved addresses of *reservation* for *subnet*, the Subnet of the Lease."""
    counted: list[IPAddressValue] = []
    in_pool = False
    pool_unknown: list[IPAddressValue] = []
    possible: list[IPAddressValue] = []
    for address in reservation.addresses:
        if address in subnet.network:
            pool_holds = _pool_holds(address, subnet) if out_of_pool else False
            if pool_holds is None:
                pool_unknown.append(address)
            elif pool_holds:
                in_pool = True
            else:
                counted.append(address)
        elif shared_network is None:
            possible.append(address)
        elif (sibling := next((member for member in shared_network if address in member.network), None)) is not None:
            (counted if _gives_sibling_address(sibling, reservation.family) else possible).append(address)
    return _ReservedAddresses(tuple(counted), in_pool, tuple(pool_unknown), tuple(possible))


def _gives_sibling_address(sibling: VerifiedSubnet, family: Family) -> bool:
    """Return whether Kea gives a Global reserved address in *sibling*, another Subnet of the Lease's Shared Network.

    DHCPv4 needs reservations-global on the sibling and a client that passes its class filter. DHCPv6 keeps the lease
    only when reservations-global of the sibling allows it. Without these facts, Kea can give the address or not.
    """
    flags = sibling.reservation_flags
    if flags is None or not flags.global_:
        return False
    if family == 6:
        return True
    return sibling.configuration is not None and not sibling.configuration.settings.client_classes


def _allocation_match(
    lease: Lease,
    reservation: Reservation,
    addresses: tuple[IPAddressValue, ...],
    prefixes: tuple[ipaddress.IPv6Network, ...],
) -> ReservationMatch:
    """Return the Reservation Match of *lease* when the reserved *addresses* and *prefixes* count."""
    reserved: tuple[IPAddressValue, ...] | tuple[ipaddress.IPv6Network, ...]
    target: IPAddressValue | ipaddress.IPv6Network
    if isinstance(lease, DHCPv6PrefixLease):
        reserved, holds_other, target = prefixes, bool(addresses), lease.prefix
    else:
        reserved, holds_other, target = addresses, bool(prefixes), lease.address
    if not reserved:
        return OtherKindReservation(reservation) if holds_other else HostOnlyReservation(reservation)
    if target not in reserved:
        return PendingAddressChange(reservation, reserved)
    reserved_mac = reservation.identity.hardware_address
    lease_mac = next(
        (mac for identity in lease_identities(lease).identities if (mac := identity.hardware_address)), None
    )
    if reserved_mac is not None and lease_mac is not None and lease_mac != reserved_mac:
        return StaleMac(reservation, lease_mac)
    return Reserved(reservation)


def reservation_identifier_choices(family: int) -> tuple[tuple[IdentifierType, str], ...]:
    """Return the native Reservation Identity types and their UI labels."""
    return tuple(
        (identifier_type, _IDENTIFIER_LABELS[identifier_type])
        for identifier_type in reservation_identifier_types(family)
    )


class MalformedReservation(ValueError):
    """A raw reservation cannot become one unambiguous domain record."""

    def __init__(self, code: str, message: str, field: str = "") -> None:
        self.code = code
        self.field = field
        super().__init__(message)


@dataclass(frozen=True)
class ReservationIdentity:
    """Exactly one normalized native Kea Reservation identifier."""

    identifier_type: IdentifierType
    value: str

    def __post_init__(self) -> None:
        if self.identifier_type not in _IDENTIFIER_LABELS:
            raise ValueError("Unsupported Reservation identifier type.")
        if self.identifier_type in _HEX_IDENTIFIERS:
            try:
                normalized = _normalize_hex(self.value, self.identifier_type)
            except MalformedReservation as exc:
                raise ValueError(str(exc)) from exc
        elif not isinstance(self.value, str) or not self.value:
            raise ValueError("Reservation identifier value must be a non-empty string.")
        elif len(self.value) > _MAX_OPAQUE_IDENTIFIER_LENGTH:
            raise ValueError(
                f"Reservation identifier value must not exceed {_MAX_OPAQUE_IDENTIFIER_LENGTH} characters."
            )
        else:
            normalized = self.value
        object.__setattr__(self, "value", normalized)

    @property
    def hardware_address(self) -> str | None:
        """Return the normalized hardware address when the identifier is one, else None."""
        return self.value if self.identifier_type == "hw-address" else None


@dataclass(frozen=True)
class GlobalReservationScope:
    """The Kea Global Reservation Scope."""

    kind: Literal["global"] = "global"


@dataclass(frozen=True)
class InSubnetReservationScope:
    """An In-Subnet Reservation Scope bound to one catalogued Subnet Identity; writes verify it through MutationScope."""

    subnet: SubnetIdentity
    kind: Literal["in-subnet"] = "in-subnet"


ReservationScope = GlobalReservationScope | InSubnetReservationScope


#: The longest server-hostname and boot-file-name that Kea 3.2 accepts on a host.
MAX_SERVER_HOSTNAME_LENGTH = 63
MAX_BOOT_FILE_NAME_LENGTH = 127
NEXT_SERVER_RULE = "The next server must be an IPv4 address other than 0.0.0.0 and 255.255.255.255."
_BROADCAST = ipaddress.IPv4Address("255.255.255.255")
# Kea returns this next-server for a host that sets none.
_UNSET_NEXT_SERVER = ipaddress.IPv4Address(0)
# Kea removes these characters from both ends of a client class name of a host.
_KEA_TRIMMED = " \t\n\r"


def parse_next_server(value: Any) -> ipaddress.IPv4Address:
    """Return the next server of a DHCPv4 Reservation from its text.

    Raises:
        ValueError: If *value* is not an IPv4 address that Kea accepts as the next server of a host.

    """
    try:
        address = ipaddress.IPv4Address(value) if isinstance(value, str) else None
    except ValueError:
        address = None
    if address is None or address in (_UNSET_NEXT_SERVER, _BROADCAST):
        raise ValueError(NEXT_SERVER_RULE)
    return address


def parse_client_classes(value: Any) -> tuple[str, ...]:
    """Return the client class names of a Reservation in the form that Kea stores them.

    Raises:
        ValueError: If *value* is not a list of unique, non-empty names without surrounding whitespace.

    """
    if (
        not isinstance(value, list | tuple)
        or not all(isinstance(name, str) and name and name == name.strip(_KEA_TRIMMED) for name in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError("Client classes must be unique, non-empty names without surrounding whitespace.")
    return tuple(value)


@dataclass(frozen=True)
class ExcludedPrefix:
    """The prefix that Kea excludes from one delegated prefix of a DHCPv6 Reservation (RFC 6603)."""

    delegated: ipaddress.IPv6Network
    excluded: ipaddress.IPv6Network

    def __post_init__(self) -> None:
        if not isinstance(self.delegated, ipaddress.IPv6Network) or not isinstance(
            self.excluded, ipaddress.IPv6Network
        ):
            raise ValueError("An excluded prefix and its delegated prefix must be IPv6 prefixes.")
        if self.excluded.prefixlen <= self.delegated.prefixlen or not self.excluded.subnet_of(self.delegated):
            raise ValueError(
                f"The excluded prefix {self.excluded} must be a longer prefix inside "
                f"the delegated prefix {self.delegated}."
            )


@dataclass(frozen=True)
class IPv4Reservation:
    """One immutable DHCPv4 Reservation."""

    scope: ReservationScope
    identity: ReservationIdentity
    addresses: tuple[ipaddress.IPv4Address, ...]
    delegated_prefixes: tuple[()] = ()
    hostname: str = ""
    options: tuple[DHCPOption, ...] = ()
    family: Literal[4] = 4
    client_classes: tuple[str, ...] = ()
    #: ``None`` is Kea's unset value, 0.0.0.0.
    next_server: ipaddress.IPv4Address | None = None
    server_hostname: str = ""
    boot_file_name: str = ""
    excluded_prefixes: tuple[()] = ()
    # Kea's user-context, read-only and opaque: no edit changes it, so it is not part of the compared value.
    user_context: Any = field(default=None, compare=False)

    def __post_init__(self) -> None:
        _validate_reservation_value(self)


@dataclass(frozen=True)
class IPv6Reservation:
    """One immutable DHCPv6 Reservation."""

    scope: ReservationScope
    identity: ReservationIdentity
    addresses: tuple[ipaddress.IPv6Address, ...]
    delegated_prefixes: tuple[ipaddress.IPv6Network, ...]
    hostname: str = ""
    options: tuple[DHCPOption, ...] = ()
    family: Literal[6] = 6
    client_classes: tuple[str, ...] = ()
    #: One entry for each delegated prefix that excludes a prefix, in the order of ``delegated_prefixes``.
    excluded_prefixes: tuple[ExcludedPrefix, ...] = ()
    next_server: None = None
    server_hostname: str = ""
    boot_file_name: str = ""
    # Kea's user-context, read-only and opaque: no edit changes it, so it is not part of the compared value.
    user_context: Any = field(default=None, compare=False)

    def __post_init__(self) -> None:
        _validate_reservation_value(self)


Reservation = IPv4Reservation | IPv6Reservation


def reservation_record_data(reservation: Reservation, *, include_subnet_id: bool = True) -> dict[str, Any]:
    """Return the normalized public data for one Reservation."""
    if isinstance(reservation.scope, InSubnetReservationScope):
        subnet: dict[str, Any] = {"cidr": reservation.scope.subnet.cidr}
        if include_subnet_id:
            subnet = {"id": reservation.scope.subnet.subnet_id, **subnet}
        scope: dict[str, Any] = {"type": "in-subnet", "subnet": subnet}
    else:
        scope = {"type": "global"}
    return {
        "family": reservation.family,
        "scope": scope,
        "identity": {
            "type": reservation.identity.identifier_type,
            "value": reservation.identity.value,
        },
        "addresses": [str(address) for address in reservation.addresses],
        "delegated_prefixes": [str(prefix) for prefix in reservation.delegated_prefixes],
        "hostname": reservation.hostname,
        "options": [
            {
                "code": option.code,
                "name": option.name,
                "space": option.space,
                "data": option.data,
                "csv_format": option.csv_format,
                "always_send": option.always_send,
                "never_send": option.never_send,
                "client_classes": list(option.client_classes),
            }
            for option in reservation.options
        ],
        "client_classes": list(reservation.client_classes),
        "next_server": None if reservation.next_server is None else str(reservation.next_server),
        "server_hostname": reservation.server_hostname,
        "boot_file_name": reservation.boot_file_name,
        "excluded_prefixes": [
            {"delegated_prefix": str(pair.delegated), "excluded_prefix": str(pair.excluded)}
            for pair in reservation.excluded_prefixes
        ],
        # Read-only and opaque: the value that Kea holds, or None.
        "user_context": reservation.user_context,
    }


T = TypeVar("T")


@dataclass(frozen=True)
class Unchanged:
    """Leave one managed Reservation fact unchanged."""


@dataclass(frozen=True)
class SetValue(Generic[T]):
    """Set one managed Reservation fact to an explicit value."""

    value: T


@dataclass(frozen=True)
class ClearValue:
    """Remove one optional managed Reservation fact."""


FieldChange = Unchanged | SetValue[T] | ClearValue
UNCHANGED = Unchanged()


@dataclass(frozen=True)
class ReservationChange:
    """Explicit changes to the mutable facts of one Reservation."""

    addresses: FieldChange[tuple[IPAddressValue, ...]] = UNCHANGED
    delegated_prefixes: FieldChange[tuple[ipaddress.IPv6Network, ...]] = UNCHANGED
    hostname: FieldChange[str] = UNCHANGED
    options: DHCPOptionEdit | None = None
    client_classes: FieldChange[tuple[str, ...]] = UNCHANGED
    next_server: FieldChange[ipaddress.IPv4Address | None] = UNCHANGED
    server_hostname: FieldChange[str] = UNCHANGED
    boot_file_name: FieldChange[str] = UNCHANGED
    excluded_prefixes: FieldChange[tuple[ExcludedPrefix, ...]] = UNCHANGED


@dataclass(frozen=True)
class ReservationCapabilities:
    """Live identifier and mutation capabilities for one DHCP family."""

    family: Family
    identifiers: tuple[IdentifierType, ...]
    mutation_available: bool
    explanation: str
    unavailable_identifiers: tuple[tuple[IdentifierType, str], ...] = ()


class ReservationConflict(RuntimeError):
    """The edit form no longer matches the Reservation or the Subnet that it showed, so it cannot save."""


@dataclass(frozen=True)
class ReservationDiagnostic:
    """One sanitized explanation for a quarantined Reservation."""

    code: str
    message: str
    source_position: str


RESERVATION_PAGE_FETCH_FAILED = "page-fetch-failed"
RESERVATION_PAGINATION_STALLED = "pagination-stalled"
RESERVATION_PAGE_LIMIT_REACHED = "page-limit-reached"
RESERVATION_INVALID_IDENTIFIER = "invalid-identifier"
TRAVERSAL_DIAGNOSTIC_CODES: frozenset[str] = frozenset(
    {RESERVATION_PAGE_FETCH_FAILED, RESERVATION_PAGINATION_STALLED, RESERVATION_PAGE_LIMIT_REACHED}
)
#: The traversal diagnostics of a walk that an error stopped. A walk stopped at its configured limit is not one.
_TRAVERSAL_ERROR_CODES: frozenset[str] = TRAVERSAL_DIAGNOSTIC_CODES - {RESERVATION_PAGE_LIMIT_REACHED}


@dataclass(frozen=True)
class ReservationSnapshot:
    """One bounded observation that preserves valid Reservations and diagnostics."""

    family: Family
    records: tuple[Reservation, ...]
    diagnostics: tuple[ReservationDiagnostic, ...]
    complete: bool
    next_cursor: str | None
    #: The aware time at which the read of the first page started.
    read_started: datetime

    def __post_init__(self) -> None:
        if self.read_started.tzinfo is None:
            raise ValueError("A Reservation Snapshot needs an aware read time.")

    @property
    def traversal_truncated(self) -> bool:
        """Report whether Reservation page traversal stopped early."""
        return any(diagnostic.code in TRAVERSAL_DIAGNOSTIC_CODES for diagnostic in self.diagnostics)

    @property
    def settled(self) -> bool:
        """Return false for a page walk that an error stopped; the display cache never stores it."""
        return not any(diagnostic.code in _TRAVERSAL_ERROR_CODES for diagnostic in self.diagnostics)


#: Display label to stable machine key. Templates and Python branch on the key, so
#: renaming a label can never silently change which branch a state matches.
SynchronizationLabel = Literal[
    "Not Applicable",
    "Not Synchronized",
    "Partially Synchronized",
    "Synchronized",
    "Unknown",
]

_SYNCHRONIZATION_STATE_CODES: dict[SynchronizationLabel, str] = {
    "Not Applicable": "not-applicable",
    "Not Synchronized": "not-synchronized",
    "Partially Synchronized": "partially-synchronized",
    "Synchronized": "synchronized",
    "Unknown": "unknown",
}


@dataclass(frozen=True)
class ReservationSynchronizationState:
    """One aggregate synchronization state for all allocation addresses."""

    label: SynchronizationLabel
    synchronized: int
    total: int
    reason: str = ""

    @property
    def code(self) -> str:
        """Return the stable machine key to compare against, never the display text."""
        return _SYNCHRONIZATION_STATE_CODES[self.label]

    @classmethod
    def from_counts(cls, synchronized: int, total: int) -> ReservationSynchronizationState:
        """Build the exact aggregate state for known address counts."""
        if total < 1 or not 0 <= synchronized <= total:
            raise ValueError("Synchronization counts are invalid.")
        label: SynchronizationLabel
        if synchronized == 0:
            label = "Not Synchronized"
        elif synchronized == total:
            label = "Synchronized"
        else:
            label = "Partially Synchronized"
        return cls(label=label, synchronized=synchronized, total=total)

    @classmethod
    def not_applicable(cls, reason: str) -> ReservationSynchronizationState:
        """Build a Not Applicable state with a concise reason."""
        return cls(label="Not Applicable", synchronized=0, total=0, reason=reason)

    @classmethod
    def unknown(cls, total: int, reason: str) -> ReservationSynchronizationState:
        """Build an Unknown state when the target could not be observed."""
        return cls(label="Unknown", synchronized=0, total=total, reason=reason)


def _validate_reservation_value(reservation: Reservation) -> None:
    if reservation.identity.identifier_type not in reservation_identifier_types(reservation.family):
        raise ValueError(f"{reservation.identity.identifier_type} is not valid for DHCPv{reservation.family}.")
    if (
        isinstance(reservation.scope, InSubnetReservationScope)
        and reservation.scope.subnet.network.version != reservation.family
    ):
        raise ValueError("The Reservation Scope must use the same address family as the Reservation.")
    if not isinstance(reservation.hostname, str):
        raise ValueError("Reservation hostname must be a string.")
    if len(set(reservation.addresses)) != len(reservation.addresses):
        raise ValueError("Reservation addresses must be unique.")
    if any(address.version != reservation.family for address in reservation.addresses):
        raise ValueError("Reservation addresses must use the Reservation family.")
    if isinstance(reservation.scope, InSubnetReservationScope) and any(
        address not in reservation.scope.subnet.network for address in reservation.addresses
    ):
        raise ValueError("Reservation addresses must belong to the In-Subnet Scope.")
    if reservation.family == 4:
        if len(reservation.addresses) > 1:
            raise ValueError("A DHCPv4 Reservation permits at most one address.")
        if reservation.delegated_prefixes:
            raise ValueError("A DHCPv4 Reservation does not support delegated prefixes.")
    else:
        if len(set(reservation.delegated_prefixes)) != len(reservation.delegated_prefixes):
            raise ValueError("Reservation delegated prefixes must be unique.")
        if any(prefix.version != 6 for prefix in reservation.delegated_prefixes):
            raise ValueError("A DHCPv6 Reservation requires IPv6 delegated prefixes.")
    if any(not isinstance(option, DHCPOption) for option in reservation.options):
        raise ValueError("Reservation options must be DHCPOption values.")
    parse_client_classes(reservation.client_classes)
    _validate_boot_fields(reservation)
    _validate_excluded_prefixes(reservation)


def _validate_boot_fields(reservation: Reservation) -> None:
    """Refuse a DHCPv4 boot field that Kea 3.2 refuses on a host, and every boot field of a DHCPv6 Reservation."""
    next_server, server_hostname, boot_file_name = (
        reservation.next_server,
        reservation.server_hostname,
        reservation.boot_file_name,
    )
    if not isinstance(server_hostname, str) or not isinstance(boot_file_name, str):
        raise ValueError("The server hostname and the boot file name must be strings.")
    if reservation.family == 6:
        if next_server is not None or server_hostname or boot_file_name:
            raise ValueError("A DHCPv6 Reservation has no next server, server hostname or boot file name.")
        return
    if next_server is not None:
        parse_next_server(str(next_server) if isinstance(next_server, ipaddress.IPv4Address) else None)
    if len(server_hostname) > MAX_SERVER_HOSTNAME_LENGTH:
        raise ValueError(f"The server hostname must not exceed {MAX_SERVER_HOSTNAME_LENGTH} characters.")
    if len(boot_file_name) > MAX_BOOT_FILE_NAME_LENGTH:
        raise ValueError(f"The boot file name must not exceed {MAX_BOOT_FILE_NAME_LENGTH} characters.")


def _validate_excluded_prefixes(reservation: Reservation) -> None:
    """Refuse an excluded prefix that is not paired with one delegated prefix, in the order of the delegated ones."""
    excluded = reservation.excluded_prefixes
    if any(not isinstance(pair, ExcludedPrefix) for pair in excluded):
        raise ValueError("Excluded prefixes must be ExcludedPrefix values.")
    delegated = [pair.delegated for pair in excluded]
    order = [prefix for prefix in reservation.delegated_prefixes if prefix in delegated]
    if delegated != order:
        raise ValueError(
            "Each excluded prefix must belong to one delegated prefix of the Reservation, "
            "at most one for each delegated prefix."
        )


def _reservation_to_raw(reservation: Reservation) -> dict[str, Any]:
    """Serialize managed Reservation facts for the private Kea adapter."""
    subnet_id = 0 if isinstance(reservation.scope, GlobalReservationScope) else reservation.scope.subnet.subnet_id
    raw: dict[str, Any] = {
        "subnet-id": subnet_id,
        reservation.identity.identifier_type: reservation.identity.value,
    }
    if reservation.family == 4 and reservation.addresses:
        raw["ip-address"] = str(reservation.addresses[0])
    if reservation.family == 6 and reservation.addresses:
        raw["ip-addresses"] = [str(address) for address in reservation.addresses]
    if reservation.delegated_prefixes:
        raw["prefixes"] = [str(prefix) for prefix in reservation.delegated_prefixes]
    if reservation.hostname:
        raw["hostname"] = reservation.hostname
    if reservation.options:
        raw["option-data"] = [option_data(option) for option in reservation.options]
    if reservation.client_classes:
        raw["client-classes"] = list(reservation.client_classes)
    if reservation.next_server is not None:
        raw["next-server"] = str(reservation.next_server)
    if reservation.server_hostname:
        raw["server-hostname"] = reservation.server_hostname
    if reservation.boot_file_name:
        raw["boot-file-name"] = reservation.boot_file_name
    if reservation.excluded_prefixes:
        excluded = {pair.delegated: str(pair.excluded) for pair in reservation.excluded_prefixes}
        # Kea pairs the lists by position, and an empty entry excludes nothing.
        raw["excluded-prefixes"] = [excluded.get(prefix, "") for prefix in reservation.delegated_prefixes]
    if reservation.user_context is not None:
        raw["user-context"] = reservation.user_context
    return raw


def reservation_matches_intent(
    observed: Reservation,
    intended: Reservation,
    definitions: Sequence[OptionDefinition] = (),
) -> bool:
    """Say whether one refetched Reservation carries every fact the caller submitted.

    Kea resolves an Option submitted by name alone against its own definitions and
    returns the code, space and CSV format with it, so an unspecified Option fact is
    Kea's to fill and is not compared.
    """
    if replace(observed, options=()) != replace(intended, options=()):
        return False
    if len(observed.options) != len(intended.options):
        return False
    return all(
        option_matches_intent(observed_option, intended_option, intended.family, definitions)
        for observed_option, intended_option in zip(observed.options, intended.options, strict=True)
    )


def reservation_fingerprint(reservation: Reservation) -> str:
    """Return a stable fingerprint of managed facts only."""
    encoded = json.dumps(
        _reservation_to_raw(replace(reservation, options=(), user_context=None)), sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _change_value(change: FieldChange[T], current: T, empty: T) -> T:
    if isinstance(change, Unchanged):
        return current
    if isinstance(change, ClearValue):
        return empty
    return change.value


def apply_reservation_change(reservation: Reservation, change: ReservationChange) -> Reservation:
    """Apply explicit mutable-field changes without changing Identity or Scope."""
    addresses = _change_value(change.addresses, reservation.addresses, ())
    prefixes = _change_value(change.delegated_prefixes, reservation.delegated_prefixes, ())
    excluded = _change_value(change.excluded_prefixes, reservation.excluded_prefixes, ())
    if change.options is not None:
        raise ValueError("Merge DHCP Option edits onto the raw record through FreshReservation.updated.")
    shared: dict[str, Any] = {
        "hostname": _change_value(change.hostname, reservation.hostname, ""),
        "client_classes": _change_value(change.client_classes, reservation.client_classes, ()),
        "next_server": _change_value(change.next_server, reservation.next_server, None),
        "server_hostname": _change_value(change.server_hostname, reservation.server_hostname, ""),
        "boot_file_name": _change_value(change.boot_file_name, reservation.boot_file_name, ""),
    }
    # One ReservationChange serves both families, so narrow before replace(). Each cast
    # reaches __post_init__, which rejects a value the other family cannot hold.
    if isinstance(reservation, IPv4Reservation):
        return replace(
            reservation,
            addresses=cast("tuple[ipaddress.IPv4Address, ...]", addresses),
            delegated_prefixes=cast("tuple[()]", prefixes),
            excluded_prefixes=cast("tuple[()]", excluded),
            **shared,
        )
    return replace(
        reservation,
        addresses=cast("tuple[ipaddress.IPv6Address, ...]", addresses),
        delegated_prefixes=prefixes,
        excluded_prefixes=excluded,
        **shared,
    )


def _family(value: int) -> Family:
    if value not in (4, 6):
        raise ValueError(f"family must be 4 or 6, got {value!r}")
    return cast(Family, value)


def _normalize_hex(value: Any, identifier_type: IdentifierType) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError("The identifier is not a string.")
        return normalize_hex(value, _HEX_IDENTIFIER_OCTETS[identifier_type])
    except ValueError as exc:
        raise MalformedReservation(
            RESERVATION_INVALID_IDENTIFIER,
            "The Reservation identifier is invalid.",
            identifier_type,
        ) from exc


def _identity(raw: dict[str, Any], family: Family) -> ReservationIdentity:
    if "remote-id" in raw:
        raise MalformedReservation(
            "unsupported-identifier",
            "Relay remote ID is not a native Reservation Identity. Configure the Kea Flex ID hook instead.",
            "remote-id",
        )
    invalid_family_identifier = next(
        (
            identifier_type
            for identifier_type in _IDENTIFIER_LABELS
            if identifier_type in raw and identifier_type not in reservation_identifier_types(family)
        ),
        None,
    )
    if invalid_family_identifier is not None:
        raise MalformedReservation(
            "invalid-family-identifier",
            f"The Reservation contains an identifier that is not valid for DHCPv{family}.",
            invalid_family_identifier,
        )
    identifiers = [
        (identifier_type, raw[identifier_type])
        for identifier_type in reservation_identifier_types(family)
        if identifier_type in raw
    ]
    if len(identifiers) != 1:
        code = "missing-identifier" if not identifiers else "ambiguous-identifier"
        raise MalformedReservation(code, "A Reservation must contain exactly one supported identifier.")
    identifier_type, value = identifiers[0]
    if identifier_type in _HEX_IDENTIFIERS:
        normalized = _normalize_hex(value, identifier_type)
    elif not isinstance(value, str) or not value:
        raise MalformedReservation(
            RESERVATION_INVALID_IDENTIFIER,
            "The Reservation identifier is invalid.",
            identifier_type,
        )
    else:
        normalized = value
    try:
        return ReservationIdentity(identifier_type=identifier_type, value=normalized)
    except ValueError as exc:
        raise MalformedReservation(
            RESERVATION_INVALID_IDENTIFIER,
            "The Reservation identifier is invalid.",
            identifier_type,
        ) from exc


def _scope(raw: dict[str, Any], catalogue: CatalogueSnapshot) -> ReservationScope:
    from .subnet_catalogue import VerifiedSubnet

    subnet_id = raw.get("subnet-id")
    if isinstance(subnet_id, bool) or not isinstance(subnet_id, int) or subnet_id < 0:
        raise MalformedReservation("invalid-scope", "The Reservation has an invalid scope.", "subnet-id")
    if subnet_id == 0:
        return GlobalReservationScope()
    subnet = catalogue.find_by_id(subnet_id)
    if not isinstance(subnet, VerifiedSubnet):
        raise MalformedReservation(
            "unverified-scope",
            "The Reservation refers to a Subnet that the Subnet Catalogue cannot verify.",
            "subnet-id",
        )
    return InSubnetReservationScope(subnet=subnet.identity)


def _addresses(raw: dict[str, Any], family: Family) -> tuple[IPAddressValue, ...]:
    if family == 4:
        if "ip-addresses" in raw:
            raise MalformedReservation(
                "invalid-addresses", "DHCPv4 does not support an ip-addresses collection.", "ip-addresses"
            )
        values = () if raw.get("ip-address") in (None, "") else (raw.get("ip-address"),)
    else:
        if "ip-address" in raw:
            raise MalformedReservation(
                "invalid-addresses", "DHCPv6 does not support a scalar ip-address.", "ip-address"
            )
        values = raw.get("ip-addresses", [])
        if not isinstance(values, list):
            raise MalformedReservation("invalid-addresses", "Reservation addresses must be a list.", "ip-addresses")
    parsed: list[IPAddressValue] = []
    for index, value in enumerate(values):
        field = "ip-address" if family == 4 else f"ip-addresses[{index}]"
        if not isinstance(value, str):
            raise MalformedReservation("invalid-address", "The Reservation contains an invalid address.", field)
        try:
            address = ipaddress.ip_address(value)
        except (TypeError, ValueError) as exc:
            raise MalformedReservation(
                "invalid-address", "The Reservation contains an invalid address.", field
            ) from exc
        # A scoped IPv6 address (fe80::1%eth0) is no allocation, and NetBox IPAM cannot hold one.
        if address.version != family or address in parsed or getattr(address, "scope_id", None):
            raise MalformedReservation(
                "invalid-address", "The Reservation contains an invalid or duplicate address.", field
            )
        parsed.append(address)
    return tuple(parsed)


def _prefixes(raw: dict[str, Any], family: Family) -> tuple[ipaddress.IPv6Network, ...]:
    values = raw.get("prefixes", [])
    if family == 4:
        if values not in (None, []):
            raise MalformedReservation("invalid-prefixes", "DHCPv4 does not support delegated prefixes.", "prefixes")
        return ()
    if not isinstance(values, list):
        raise MalformedReservation("invalid-prefixes", "Delegated prefixes must be a list.", "prefixes")
    parsed: list[ipaddress.IPv6Network] = []
    for index, value in enumerate(values):
        field = f"prefixes[{index}]"
        if not isinstance(value, str):
            raise MalformedReservation("invalid-prefix", "The Reservation contains an invalid delegated prefix.", field)
        try:
            prefix = ipaddress.IPv6Network(value, strict=True)
        except (TypeError, ValueError) as exc:
            raise MalformedReservation(
                "invalid-prefix", "The Reservation contains an invalid delegated prefix.", field
            ) from exc
        if prefix in parsed:
            raise MalformedReservation(
                "invalid-prefix", "The Reservation contains a duplicate delegated prefix.", field
            )
        parsed.append(prefix)
    return tuple(parsed)


def _parse_reservation(raw: Any, family: Family, catalogue: CatalogueSnapshot) -> Reservation:
    if not isinstance(raw, dict):
        raise MalformedReservation("invalid-record", "Kea returned a non-object Reservation.")
    identity = _identity(raw, family)
    scope = _scope(raw, catalogue)
    addresses = _addresses(raw, family)
    if isinstance(scope, InSubnetReservationScope):
        for index, address in enumerate(addresses):
            if address not in scope.subnet.network:
                field = "ip-address" if family == 4 else f"ip-addresses[{index}]"
                raise MalformedReservation(
                    "invalid-address",
                    "The Reservation contains an address outside its verified In-Subnet Scope.",
                    field,
                )
    prefixes = _prefixes(raw, family)
    hostname = raw.get("hostname", "")
    if not isinstance(hostname, str):
        raise MalformedReservation("invalid-hostname", "The Reservation hostname is invalid.", "hostname")
    try:
        options = parse_dhcp_options(raw.get("option-data", []))
    except ValueError as exc:
        raise MalformedReservation(
            "invalid-options", "The Reservation contains invalid DHCP Options.", "option-data"
        ) from exc
    try:
        client_classes = parse_client_classes(raw.get("client-classes", []))
    except ValueError as exc:
        raise MalformedReservation("invalid-client-classes", str(exc), "client-classes") from exc
    excluded = _excluded_prefixes(raw, family, prefixes)
    next_server, server_hostname, boot_file_name = _boot_fields(raw, family)
    if family == 4:
        return IPv4Reservation(
            scope=scope,
            identity=identity,
            addresses=cast(tuple[ipaddress.IPv4Address, ...], addresses),
            hostname=hostname,
            options=options,
            client_classes=client_classes,
            next_server=next_server,
            server_hostname=server_hostname,
            boot_file_name=boot_file_name,
            user_context=raw.get("user-context"),
        )
    return IPv6Reservation(
        scope=scope,
        identity=identity,
        addresses=cast(tuple[ipaddress.IPv6Address, ...], addresses),
        delegated_prefixes=prefixes,
        hostname=hostname,
        options=options,
        client_classes=client_classes,
        excluded_prefixes=excluded,
        user_context=raw.get("user-context"),
    )


def _excluded_prefixes(
    raw: dict[str, Any], family: Family, prefixes: tuple[ipaddress.IPv6Network, ...]
) -> tuple[ExcludedPrefix, ...]:
    """Pair each entry of Kea's excluded-prefixes with the delegated prefix at its position; empty excludes none."""
    values = raw.get("excluded-prefixes")
    if family == 4:
        if values not in (None, []):
            raise MalformedReservation(
                "invalid-excluded-prefixes", "DHCPv4 does not support excluded prefixes.", "excluded-prefixes"
            )
        return ()
    if values is None:
        return ()
    if not isinstance(values, list) or len(values) != len(prefixes):
        raise MalformedReservation(
            "invalid-excluded-prefixes",
            "Excluded prefixes must pair one to one with the delegated prefixes.",
            "excluded-prefixes",
        )
    pairs: list[ExcludedPrefix] = []
    for index, (prefix, value) in enumerate(zip(prefixes, values, strict=True)):
        if value == "":
            continue
        try:
            if not isinstance(value, str):
                raise TypeError("An excluded prefix must be a string.")
            pairs.append(ExcludedPrefix(prefix, ipaddress.IPv6Network(value, strict=True)))
        except (TypeError, ValueError) as exc:
            raise MalformedReservation(
                "invalid-excluded-prefix",
                "The Reservation contains an invalid excluded prefix.",
                f"excluded-prefixes[{index}]",
            ) from exc
    return tuple(pairs)


def _boot_fields(raw: dict[str, Any], family: Family) -> tuple[ipaddress.IPv4Address | None, str, str]:
    """Return the next server, server hostname and boot file name of a host; Kea returns 0.0.0.0 and "" for none."""
    next_server: ipaddress.IPv4Address | None = None
    value = raw.get("next-server")
    if value is not None and value != str(_UNSET_NEXT_SERVER):
        try:
            if family == 6:
                raise ValueError("A DHCPv6 host has no next server.")
            next_server = parse_next_server(value)
        except ValueError as exc:
            raise MalformedReservation(
                "invalid-boot-field", "The Reservation next server is invalid.", "next-server"
            ) from exc
    texts: list[str] = []
    for key, limit in (
        ("server-hostname", 0 if family == 6 else MAX_SERVER_HOSTNAME_LENGTH),
        ("boot-file-name", 0 if family == 6 else MAX_BOOT_FILE_NAME_LENGTH),
    ):
        text = raw.get(key, "")
        if not isinstance(text, str) or len(text) > limit:
            raise MalformedReservation("invalid-boot-field", f"The Reservation {key} is invalid.", key)
        texts.append(text)
    return next_server, texts[0], texts[1]


def _exact_reservation(raw: Any, family: int, catalogue: CatalogueSnapshot) -> Reservation:
    """Parse one exact Kea target or fail closed."""
    return _parse_reservation(raw, _family(family), catalogue)


def _parse_record_at(
    raw: Any,
    family: Family,
    catalogue: CatalogueSnapshot,
    index: int,
    expected_hostname: str | None = None,
) -> tuple[Reservation | None, ReservationDiagnostic | None]:
    try:
        reservation = _parse_reservation(raw, family, catalogue)
        # Kea matches a hostname lookup without case and returns the hostname as stored.
        if expected_hostname is not None and reservation.hostname.lower() != expected_hostname.lower():
            raise MalformedReservation(
                "target-mismatch",
                "Kea returned a Reservation that does not match the requested hostname.",
                "hostname",
            )
    except MalformedReservation as exc:
        suffix = f".{exc.field}" if exc.field else ""
        return None, ReservationDiagnostic(
            code=exc.code,
            message=str(exc),
            source_position=f"hosts[{index}]{suffix}",
        )
    else:
        return reservation, None


def _parse_reservation_page(
    hosts: Any,
    family: int,
    catalogue: CatalogueSnapshot,
    next_cursor: str | None,
    *,
    read_started: datetime,
    expected_hostname: str | None = None,
) -> ReservationSnapshot:
    """Build one typed Snapshot and quarantine malformed records individually."""
    parsed_family = _family(family)
    if not isinstance(hosts, list):
        raise RuntimeError("reservation-get-page returned a malformed hosts collection.")
    records: list[Reservation] = []
    diagnostics: list[ReservationDiagnostic] = []
    for index, raw in enumerate(hosts):
        record, diagnostic = _parse_record_at(raw, parsed_family, catalogue, index, expected_hostname)
        if record is not None:
            records.append(record)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
    return ReservationSnapshot(
        family=parsed_family,
        records=tuple(records),
        diagnostics=tuple(diagnostics),
        complete=not diagnostics,
        next_cursor=next_cursor,
        read_started=read_started,
    )
