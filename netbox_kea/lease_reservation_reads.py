# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The lookups that relate Leases and Reservations: display cache reads in a worker pool (ADR 0002, ADR 0009).

The Current Lease lookups give the Lease badges of Reservation rows, and the Reservation lookups give the
Reservation badges of Lease rows.
"""

from __future__ import annotations

import concurrent.futures
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from typing import Concatenate, ParamSpec, TypeVar

from . import constants, display_cache, subnet_catalogue
from .constants import Family, LeaseState
from .kea import KeaClient, LeaseQueryGuardError, close_quietly
from .lease_reads import LeaseSearch, cached_read
from .leases import DHCPv6PrefixLease, Lease, LeaseSnapshot
from .models import DisplayCacheConfig, KeaClientConfig, PinnedSettings, Server
from .read_failure import ReadFailure, ReadFailureKind, attempt
from .reservations import (
    CurrentLeaseFacts,
    CurrentLeasePresence,
    GlobalReservationScope,
    InSubnetReservationScope,
    LeasePresenceUnknown,
    Reservation,
    ReservationMatch,
    ReservationMatchUnknown,
    ReservationScope,
    UnknownLeasePresence,
    UnknownReservationMatch,
    current_lease_facts,
    current_lease_presence,
    lease_identities,
    reservation_match,
    tries_global_reservation,
)
from .subnet_catalogue import CatalogueSnapshot, VerifiedSubnet

_MAX_WORKERS = 10

T = TypeVar("T")
R = TypeVar("R")
P = ParamSpec("P")


class _FailedLookup(Exception):
    """A Reservation lookup failed, so the Reservation Match is *unknown*."""

    def __init__(self, unknown: ReservationMatchUnknown) -> None:
        super().__init__(unknown.reason)
        self.unknown = unknown


class WorkerClients:
    """One Kea client per worker thread, built on its first cache miss and closed when the pool ends."""

    def __init__(self, server: Server, family: Family) -> None:
        self._server = server
        self._family = family
        self._local = threading.local()
        self._registry = threading.Lock()
        self._clients: list[KeaClient] = []

    def __call__(self) -> KeaClient:
        """Return the client of the calling thread, built on the first call."""
        client: KeaClient | None = getattr(self._local, "client", None)
        if client is None:
            client = self._server.get_client(version=self._family)
            with self._registry:
                self._clients.append(client)
            self._local.client = client
        return client

    def close(self) -> None:
        """Close each client after the pool stops; a close failure is logged, and the rest still close."""
        with self._registry:
            clients = tuple(self._clients)
        for client in clients:
            close_quietly(client)


def _pooled(server: Server, family: Family, work: Callable[[WorkerClients, T], R], items: Sequence[T]) -> list[R]:
    """Return the result of *work* for each of *items*, in their order, from a pool of at most ``_MAX_WORKERS`` worker threads.

    The settings rows are read on the calling thread and pinned in each worker. Each worker builds its Kea client on
    its first cache miss, and the pool closes each client when it ends. A failure of *work* raises.
    """
    if not items:
        return []
    pinned = PinnedSettings.read(KeaClientConfig, DisplayCacheConfig)
    clients = WorkerClients(server, family)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(items), _MAX_WORKERS)) as executor:
            futures = [executor.submit(pinned.context().run, work, clients, item) for item in items]
            try:
                return [future.result() for future in futures]
            except BaseException:
                # The result is lost, so the items that wait for a worker do not run.
                executor.shutdown(wait=True, cancel_futures=True)
                raise
    finally:
        clients.close()


def _search(reservation: Reservation) -> LeaseSearch | None:
    """Return the Lease search that observes the client of *reservation*, or ``None`` when Kea has none."""
    family = reservation.family
    if isinstance(reservation.scope, InSubnetReservationScope):
        # DHCPv6 registered leases are current too, and only an unfiltered Subnet query returns them.
        state: LeaseState | None = "assigned" if family == 4 else None
        return LeaseSearch(constants.BY_SUBNET_ID, reservation.scope.subnet.subnet_id, state)
    # A Global Reservation has no Subnet, so only a Subnet-free identity query can answer it.
    selector = constants.LEASE_SELECTOR_BY_IDENTIFIER[family].get(reservation.identity.identifier_type)
    return None if selector is None else LeaseSearch(selector, reservation.identity.value)


def _observe(
    server: Server, family: Family, read_since: datetime, clients: WorkerClients, search: LeaseSearch
) -> CurrentLeaseFacts | UnknownLeasePresence:
    """Return the Current Leases of one Lease search, or why Kea could not show them."""
    try:
        read = attempt(
            f"The Lease lookup of Server {server.pk}",
            lambda: cached_read(server, family, search, clients, read_since=read_since),
        )
    except LeaseQueryGuardError:
        return UnknownLeasePresence.QUERY_GUARD
    if isinstance(read, ReadFailure):
        return _LEASE_PRESENCE_UNKNOWN[read.kind]
    loaded = read.loaded
    # Only a Subnet search by CIDR can resolve to a Catalogue, and no Reservation lookup sends one.
    if not isinstance(loaded, LeaseSnapshot):
        raise TypeError(f"The Lease lookup {search.parts!r} resolved to a Catalogue.")
    return current_lease_facts(loaded)


#: Why a failed Lease lookup leaves the Current Lease Presence unknown.
_LEASE_PRESENCE_UNKNOWN: dict[ReadFailureKind, UnknownLeasePresence] = {
    "unsupported": UnknownLeasePresence.LEASE_HOOK_UNAVAILABLE,
    "refused": UnknownLeasePresence.KEA_ERROR,
    "unreachable": UnknownLeasePresence.KEA_ERROR,
    "malformed": UnknownLeasePresence.MALFORMED_REPLY,
    "misconfigured": UnknownLeasePresence.INVALID_READ,
}

#: Why a failed Reservation lookup leaves the Reservation Match unknown.
_RESERVATION_MATCH_UNKNOWN: dict[ReadFailureKind, UnknownReservationMatch] = {
    "unsupported": UnknownReservationMatch.RESERVATION_HOOK_UNAVAILABLE,
    "refused": UnknownReservationMatch.KEA_ERROR,
    "unreachable": UnknownReservationMatch.KEA_ERROR,
    "malformed": UnknownReservationMatch.MALFORMED_REPLY,
    "misconfigured": UnknownReservationMatch.INVALID_READ,
}


def lease_presence(
    server: Server, family: Family, reservations: Sequence[Reservation], *, read_since: datetime
) -> tuple[CurrentLeasePresence, ...]:
    """Return the Current Lease Presence of each of *reservations*, in their order.

    Each distinct Lease search is one display cache entry. An entry read before *read_since*, the read time of the
    Reservation table, is read again, so a Refresh also reads each lookup live. When Kea does not know a Lease
    command, every Reservation is Unknown.

    Raises:
        ValueError: If a Reservation is not of *family*.
        TypeError: If a lookup resolves to a Catalogue, which only a Subnet search by CIDR can do.

    """
    if any(reservation.family != family for reservation in reservations):
        raise ValueError(f"Every Reservation of a DHCPv{family} lookup must be a DHCPv{family} Reservation.")
    searches = [_search(reservation) for reservation in reservations]
    lookups = list(dict.fromkeys(search for search in searches if search is not None))
    observed = dict(
        zip(lookups, _pooled(server, family, partial(_observe, server, family, read_since), lookups), strict=True)
    )
    if UnknownLeasePresence.LEASE_HOOK_UNAVAILABLE in observed.values():
        return tuple(LeasePresenceUnknown(UnknownLeasePresence.LEASE_HOOK_UNAVAILABLE) for _ in reservations)
    presences: list[CurrentLeasePresence] = []
    for reservation, search in zip(reservations, searches, strict=True):
        facts = UnknownLeasePresence.UNSEARCHABLE_IDENTIFIER if search is None else observed[search]
        if isinstance(facts, UnknownLeasePresence):
            presences.append(LeasePresenceUnknown(facts))
        else:
            presences.append(current_lease_presence(reservation, facts))
    return tuple(presences)


@dataclass(frozen=True)
class _ReservationLookup:
    """One display cache entry: the Reservation that one lookup of a Lease row found, or ``None`` for none."""

    reservation: Reservation | None
    #: False when the Reservation was parsed against a Subnet Catalogue that did not settle.
    catalogue_settled: bool
    read_started: datetime

    @property
    def settled(self) -> bool:
        """Return false for a result of an unsettled Catalogue; the cache never stores it. A failed lookup raises."""
        return self.catalogue_settled


class _ReservationLookups:
    """The Reservation lookups of one ``reservation_matches()`` call, each read once for all of its Leases."""

    def __init__(self, server: Server, family: Family, catalogue: CatalogueSnapshot, read_since: datetime) -> None:
        self._server = server
        self._family = family
        self._catalogue = catalogue
        self._read_since = read_since
        self._registry = threading.Lock()
        self._locks: dict[display_cache.QueryParts, threading.Lock] = {}
        self._found: dict[display_cache.QueryParts, Reservation | None] = {}
        self._failures: dict[display_cache.QueryParts, ReservationMatchUnknown] = {}

    def _find(
        self,
        clients: WorkerClients,
        parts: display_cache.QueryParts,
        lookup: Callable[Concatenate[KeaClient, P], Reservation | None],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> Reservation | None:
        """Return the Reservation that *lookup* finds, from the display cache entry of *parts* or from Kea.

        Leases of one client repeat a lookup, so each one runs once per call, also when workers need it at once. A
        failure that leaves the Reservation Match unknown is kept, and each Lease that needs the lookup gets a new
        ``_FailedLookup``. Any other failure raises.
        """
        with self._registry:
            lock = self._locks.setdefault(parts, threading.Lock())
        with lock:
            if parts in self._failures:
                raise _FailedLookup(self._failures[parts])
            if parts not in self._found:
                found = attempt(
                    f"A Reservation lookup of Server {self._server.pk}",
                    lambda: self._cached(clients, parts, lookup, *args, **kwargs),
                )
                if isinstance(found, ReadFailure):
                    self._failures[parts] = ReservationMatchUnknown(_RESERVATION_MATCH_UNKNOWN[found.kind])
                    raise _FailedLookup(self._failures[parts])
                self._found[parts] = found
            return self._found[parts]

    def _cached(
        self,
        clients: WorkerClients,
        parts: display_cache.QueryParts,
        lookup: Callable[Concatenate[KeaClient, P], Reservation | None],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> Reservation | None:
        """Read the display cache entry of *parts*; a miss builds the client of the calling thread and asks Kea."""

        def read() -> _ReservationLookup:
            started = datetime.now(tz=timezone.utc)
            return _ReservationLookup(lookup(clients(), *args, **kwargs), self._catalogue.settled, started)

        return display_cache.cached(
            self._server,
            self._family,
            "reservation_lookups",
            read,
            query=parts,
            fresh=lambda entry: entry.read_started >= self._read_since,
        ).reservation

    def _in_subnet(self, clients: WorkerClients, lease: Lease, subnet: VerifiedSubnet) -> Reservation | None:
        """Return the In-Subnet Reservation found by the allocation of *lease*, then by each of its identities."""
        family, catalogue, subnet_id = self._family, self._catalogue, subnet.subnet_id
        scope = InSubnetReservationScope(subnet.identity)
        if isinstance(lease, DHCPv6PrefixLease):
            parts: display_cache.QueryParts = ("prefix", subnet_id, str(lease.prefix))
            found = self._find(clients, parts, KeaClient.reservation_by_prefix, catalogue, scope, lease.prefix)
        else:
            address = str(lease.address)
            parts = ("address", subnet_id, address)
            found = self._find(clients, parts, KeaClient.reservation_by_address, family, catalogue, scope, address)
        return found if found is not None else self._by_identity(clients, lease, scope, subnet_id)

    def _global(self, clients: WorkerClients, lease: Lease, _subnet: VerifiedSubnet) -> Reservation | None:
        """Return the Global Reservation found by an identity of *lease*."""
        return self._by_identity(clients, lease, GlobalReservationScope(), 0)

    def _by_identity(
        self, clients: WorkerClients, lease: Lease, scope: ReservationScope, scope_id: int
    ) -> Reservation | None:
        """Return the Reservation of *scope* found by the first identity of *lease* that one is found by."""
        for identity in lease_identities(lease).identities:
            parts = ("identity", scope_id, identity.identifier_type, identity.value)
            found = self._find(
                clients, parts, KeaClient.reservation_by_identity, self._family, self._catalogue, scope, identity
            )
            if found is not None:
                return found
        return None

    def reservation_of(self, clients: WorkerClients, lease: Lease, subnet: VerifiedSubnet) -> Reservation | None:
        """Return the first Reservation found in the scopes that the flags of *subnet* enable, then in the others.

        The In-Subnet scope comes before the Global scope. Unknown flags keep that order for every scope.
        """
        flags = subnet.reservation_flags
        scopes = ((self._in_subnet, flags is None or flags.in_subnet), (self._global, flags is None or flags.global_))
        enabled = [lookup for lookup, applies in scopes if applies]
        disabled = [lookup for lookup, applies in scopes if not applies]
        for lookup in (*enabled, *disabled):
            found = lookup(clients, lease, subnet)
            if found is not None:
                return found
        return None

    def match(self, clients: WorkerClients, row: tuple[Lease, VerifiedSubnet]) -> ReservationMatch:
        """Return the Reservation Match of one Lease in its Verified Subnet, or why Kea could not show it."""
        lease, subnet = row
        try:
            found = self.reservation_of(clients, lease, subnet)
            tries_global = found is not None and tries_global_reservation(lease, subnet, found)
            global_found = self._global(clients, lease, subnet) if tries_global else None
        except _FailedLookup as failed:
            return failed.unknown
        shared_network = self._catalogue.shared_network_subnets(subnet)
        return reservation_match(lease, subnet, found, shared_network, global_reservation=global_found)


def reservation_matches(
    server: Server, family: Family, leases: Sequence[Lease], *, read_since: datetime
) -> tuple[ReservationMatch, ...]:
    """Return the Reservation Match of each of *leases*, in their order.

    The display Subnet Catalogue scopes the lookups; a Lease outside its Verified Subnets is Unknown without a lookup.
    Each distinct lookup is one display cache entry. An entry read before *read_since*, the read time of the Lease
    table, is read again. When Kea does not know a Reservation command, every Lease is Unknown.

    Raises:
        ValueError: If a Lease is not of *family*.

    """
    if any(lease.family != family for lease in leases):
        raise ValueError(f"Every Lease of a DHCPv{family} lookup must be a DHCPv{family} Lease.")
    if not leases:
        return ()
    catalogue = subnet_catalogue.display(server, family)
    rows = [(lease, catalogue.find_by_id(lease.subnet_id)) for lease in leases]
    verified = [(lease, subnet) for lease, subnet in rows if isinstance(subnet, VerifiedSubnet)]
    lookups = _ReservationLookups(server, family, catalogue, read_since)
    looked_up = iter(_pooled(server, family, lookups.match, verified))
    unverified = ReservationMatchUnknown(UnknownReservationMatch.UNVERIFIED_SUBNET)
    matches = tuple(next(looked_up) if isinstance(subnet, VerifiedSubnet) else unverified for _lease, subnet in rows)
    hook_unavailable = ReservationMatchUnknown(UnknownReservationMatch.RESERVATION_HOOK_UNAVAILABLE)
    if hook_unavailable in matches:
        return tuple(hook_unavailable for _ in leases)
    return matches
