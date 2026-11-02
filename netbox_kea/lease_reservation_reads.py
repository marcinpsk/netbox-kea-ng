# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The lookups that relate Leases and Reservations: display cache reads in a worker pool (ADR 0002, ADR 0009).

The Current Lease lookups give the Lease badges of Reservation rows, and the Reservation lookups give the
Reservation badges of Lease rows.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import threading
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Generic, TypeVar

from . import constants, display_cache, subnet_catalogue
from .constants import Family, LeaseState
from .kea import KeaClient, LeaseQueryGuardError, close_quietly
from .lease_reads import LeaseSearch, cached_read
from .leases import Lease, LeaseSnapshot
from .models import DisplayCacheConfig, KeaClientConfig, PinnedSettings, Server
from .read_failure import ReadFailure, ReadFailureKind, attempt
from .reservations import (
    CurrentLeaseFacts,
    CurrentLeasePresence,
    InSubnetReservationScope,
    LeasePresenceUnknown,
    Reservation,
    ReservationIdentity,
    ReservationKey,
    ReservationMatch,
    ReservationMatchUnknown,
    ReservationScope,
    UnknownLeasePresence,
    UnknownReservationMatch,
    current_lease_facts,
    current_lease_presence,
    reservation_match,
)
from .subnet_catalogue import CatalogueSnapshot, VerifiedSubnet

_MAX_WORKERS = 10

T = TypeVar("T")
R = TypeVar("R")
K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class _FailedReservationLookup(Exception):
    """A Reservation lookup failed, so the Reservation Match is Unknown for *reason*."""

    def __init__(self, reason: UnknownReservationMatch) -> None:
        super().__init__(reason)
        self.reason = reason


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


def _pooled(clients: WorkerClients, work: Callable[[T], R], items: Sequence[T]) -> list[R]:
    """Return the result of *work* for each of *items*, in their order, from a pool of at most ``_MAX_WORKERS`` worker threads.

    The settings rows are read on the calling thread and pinned in each worker. Each worker builds its Kea client of
    *clients* on its first cache miss, and the pool closes each client when it ends. A failure of *work* raises.
    """
    try:
        if not items:
            return []
        pinned = PinnedSettings.read(KeaClientConfig, DisplayCacheConfig)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(items), _MAX_WORKERS)) as executor:
            futures = [executor.submit(pinned.context().run, work, item) for item in items]
            try:
                return [future.result() for future in futures]
            except BaseException:
                # The result is lost, so the items that wait for a worker do not run.
                executor.shutdown(wait=True, cancel_futures=True)
                raise
    finally:
        clients.close()


class _OncePerCall(Generic[K, V]):
    """The lookups of one batch call: each distinct lookup runs once, also when worker threads need it at once.

    A Read Failure is kept, so each row that needs the lookup gets it without a new read. Any other failure raises,
    and the next row that needs the lookup reads it again.
    """

    def __init__(self, label: str) -> None:
        self._label = label
        self._registry = threading.Lock()
        self._locks: dict[K, threading.Lock] = {}
        self._results: dict[K, V | ReadFailure] = {}

    def get(self, key: K, read: Callable[[], V]) -> V | ReadFailure:
        """Return the result of the lookup *key*, read by *read* on its first call."""
        with self._registry:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._results:
                self._results[key] = attempt(self._label, read)
            return self._results[key]


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
    clients = WorkerClients(server, family)
    observed = dict(
        zip(lookups, _pooled(clients, partial(_observe, server, family, read_since, clients), lookups), strict=True)
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


class _KeaReservationLookup:
    """The ``ReservationLookup`` of one ``reservation_matches()`` call: Kea's ``reservation-get`` through the cache."""

    def __init__(
        self, server: Server, family: Family, catalogue: CatalogueSnapshot, read_since: datetime, clients: WorkerClients
    ) -> None:
        self._server = server
        self._family = family
        self._catalogue = catalogue
        self._read_since = read_since
        self._clients = clients
        self._lookups: _OncePerCall[display_cache.QueryParts, Reservation | None] = _OncePerCall(
            f"A Reservation lookup of Server {server.pk}"
        )

    def find(self, scope: ReservationScope, key: ReservationKey) -> Reservation | None:
        """Return the Reservation of *scope* that *key* finds, from the display cache entry of the lookup or from Kea.

        Raises:
            _FailedReservationLookup: If the lookup failed with a Read Failure, in this row or in an earlier one.
            ValueError: If *key* is an address or a delegated prefix and *scope* is not In-Subnet.

        """
        parts, lookup = self._lookup(scope, key)
        found = self._lookups.get(parts, partial(self._cached, parts, lookup))
        if isinstance(found, ReadFailure):
            raise _FailedReservationLookup(_RESERVATION_MATCH_UNKNOWN[found.kind])
        return found

    def _lookup(
        self, scope: ReservationScope, key: ReservationKey
    ) -> tuple[display_cache.QueryParts, Callable[[KeaClient], Reservation | None]]:
        """Return the query parts of the lookup of *key* in *scope*, and the ``KeaClient`` read that answers it."""
        family, catalogue = self._family, self._catalogue
        if isinstance(key, ReservationIdentity):
            scope_id = scope.subnet.subnet_id if isinstance(scope, InSubnetReservationScope) else 0
            parts: display_cache.QueryParts = ("identity", scope_id, key.identifier_type, key.value)
            return parts, lambda client: client.reservation_by_identity(family, catalogue, scope, key)
        if not isinstance(scope, InSubnetReservationScope):
            raise ValueError("A Reservation lookup by allocation needs an In-Subnet Scope.")
        in_subnet = scope
        if isinstance(key, ipaddress.IPv6Network):
            parts = ("prefix", in_subnet.subnet.subnet_id, str(key))
            return parts, lambda client: client.reservation_by_prefix(catalogue, in_subnet, key)
        address = str(key)
        parts = ("address", in_subnet.subnet.subnet_id, address)
        return parts, lambda client: client.reservation_by_address(family, catalogue, in_subnet, address)

    def _cached(
        self, parts: display_cache.QueryParts, lookup: Callable[[KeaClient], Reservation | None]
    ) -> Reservation | None:
        """Read the display cache entry of *parts*; a miss builds the client of the calling thread and asks Kea."""

        def read() -> _ReservationLookup:
            started = datetime.now(tz=UTC)
            return _ReservationLookup(lookup(self._clients()), self._catalogue.settled, started)

        return display_cache.cached(
            self._server,
            self._family,
            "reservation_lookups",
            read,
            query=parts,
            fresh=lambda entry: entry.read_started >= self._read_since,
        ).reservation

    def match(self, row: tuple[Lease, VerifiedSubnet]) -> ReservationMatch:
        """Return the Reservation Match of one Lease in its Verified Subnet, or why Kea could not show it."""
        lease, subnet = row
        try:
            return reservation_match(lease, subnet, self._catalogue.shared_network_subnets(subnet), self)
        except _FailedReservationLookup as failed:
            return ReservationMatchUnknown(failed.reason)


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
    clients = WorkerClients(server, family)
    lookup = _KeaReservationLookup(server, family, catalogue, read_since, clients)
    looked_up = iter(_pooled(clients, lookup.match, verified))
    unverified = ReservationMatchUnknown(UnknownReservationMatch.UNVERIFIED_SUBNET)
    matches = tuple(next(looked_up) if isinstance(subnet, VerifiedSubnet) else unverified for _lease, subnet in rows)
    hook_unavailable = ReservationMatchUnknown(UnknownReservationMatch.RESERVATION_HOOK_UNAVAILABLE)
    if hook_unavailable in matches:
        return tuple(hook_unavailable for _ in leases)
    return matches
