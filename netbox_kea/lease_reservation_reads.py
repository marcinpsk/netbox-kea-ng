# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Current Lease lookups of Reservation rows: display cache reads in a worker pool (ADR 0002, ADR 0009)."""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from collections.abc import Sequence
from datetime import datetime

import requests

from . import constants
from .constants import Family, LeaseState
from .kea import KeaClient, KeaException, LeaseQueryGuardError
from .leases import LeaseSnapshot
from .models import DisplayCacheConfig, KeaClientConfig, PinnedSettings, Server
from .reservations import (
    CurrentLeaseFacts,
    CurrentLeasePresence,
    InSubnetReservationScope,
    LeasePresenceUnknown,
    Reservation,
    UnknownLeasePresence,
    current_lease_facts,
    current_lease_presence,
)
from .views._base import close_quietly
from .views.lease_reads import LeaseSearch, cached_read

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10


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
    server: Server, family: Family, search: LeaseSearch, clients: WorkerClients, read_since: datetime
) -> CurrentLeaseFacts | UnknownLeasePresence:
    """Return the Current Leases of one Lease search, or why Kea could not show them."""
    try:
        loaded = cached_read(server, family, search, clients, read_since=read_since).loaded
    except LeaseQueryGuardError:
        return UnknownLeasePresence.QUERY_GUARD
    except KeaException as exc:
        logger.debug("Kea refused the Lease lookup of server %s: result %s", server.pk, exc.response.get("result"))
        if exc.unsupported_command:
            return UnknownLeasePresence.LEASE_HOOK_UNAVAILABLE
        return UnknownLeasePresence.KEA_ERROR
    except requests.RequestException as exc:
        logger.debug("The Lease lookup of server %s failed: %s", server.pk, type(exc).__name__)
        return UnknownLeasePresence.KEA_ERROR
    # MalformedReply and MalformedLeaseResponse are RuntimeErrors, as are malformed statistics.
    except RuntimeError as exc:
        logger.debug("The Lease lookup of server %s failed: %s", server.pk, type(exc).__name__)
        return UnknownLeasePresence.MALFORMED_REPLY
    # A ValidationError is a ValueError too: a Snapshot read across a backward clock step finishes before it starts.
    except ValueError as exc:
        logger.debug("The Lease lookup of server %s was not valid: %s", server.pk, type(exc).__name__)
        return UnknownLeasePresence.INVALID_READ
    # Only a Subnet search by CIDR can resolve to a Notice, and no Reservation lookup sends one.
    if not isinstance(loaded, LeaseSnapshot):
        raise TypeError(f"The Lease lookup {search.parts!r} resolved to a Notice.")
    return current_lease_facts(loaded)


def lease_presence(
    server: Server, family: Family, reservations: Sequence[Reservation], *, read_since: datetime
) -> tuple[CurrentLeasePresence, ...]:
    """Return the Current Lease Presence of each of *reservations*, in their order.

    Each distinct Lease search is one display cache entry. An entry read before *read_since*, the read time of the
    Reservation table, is read again, so a Refresh also reads each lookup live. When Kea does not know a Lease
    command, every Reservation is Unknown.

    Raises:
        ValueError: If a Reservation is not of *family*.
        TypeError: If a lookup resolves to a Notice, which only a Subnet search by CIDR can do.

    """
    if any(reservation.family != family for reservation in reservations):
        raise ValueError(f"Every Reservation of a DHCPv{family} lookup must be a DHCPv{family} Reservation.")
    searches = [_search(reservation) for reservation in reservations]
    lookups = {search for search in searches if search is not None}
    observed: dict[LeaseSearch, CurrentLeaseFacts | UnknownLeasePresence] = {}
    if lookups:
        pinned = PinnedSettings.read(KeaClientConfig, DisplayCacheConfig)
        clients = WorkerClients(server, family)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(lookups), _MAX_WORKERS)) as executor:
                futures = {
                    executor.submit(pinned.context().run, _observe, server, family, search, clients, read_since): search
                    for search in lookups
                }
                for future in concurrent.futures.as_completed(futures):
                    observed[futures[future]] = future.result()
        finally:
            clients.close()
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
