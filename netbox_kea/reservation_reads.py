# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Reservation reads of the Reservations tabs, the Reservation export, the REST API and the change and Sync targets.

Each read of one Reservation by its identity names the Catalogue that it reads (ADR 0009).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from django.utils import timezone

from . import display_cache, subnet_catalogue
from .constants import Family
from .kea import KeaClient
from .models import Server
from .read_failure import ReadFailure, attempt
from .reservations import (
    RESERVATION_PAGE_FETCH_FAILED,
    RESERVATION_PAGE_LIMIT_REACHED,
    GlobalReservationScope,
    InSubnetReservationScope,
    Reservation,
    ReservationDiagnostic,
    ReservationIdentity,
    ReservationScope,
    ReservationSnapshot,
    reservation_identifier_types,
)
from .subnet_catalogue import CatalogueSnapshot, SubnetLookup, VerifiedSubnet

#: The number of Reservations in one page that Kea reads for a tab or an export.
PAGE_SIZE = 100
#: The number of pages that one Reservation search reads before it stops.
SEARCH_PAGE_LIMIT = 5


@dataclass(frozen=True)
class ReservationQuery:
    """What one Reservation read asks of a Server.

    It reads the page after *cursor* that matches *q*, *subnet_id* and *scope* through the display cache, or with
    *full* the complete Snapshot for a transfer, always live. With *refresh* it reads the page live and replaces its
    cached entry. With *mutations* it also reads the mutation capabilities that the cached Server Configuration
    shows, for a user who can change the Server.
    """

    cursor: str | None = None
    q: str = ""
    subnet_id: int | None = None
    scope: str = ""
    full: bool = False
    mutations: bool = False
    refresh: bool = False

    @property
    def filtered(self) -> bool:
        """Return whether the query searches for matches instead of browsing every Reservation."""
        return bool(self.q or self.subnet_id is not None or self.scope)

    @property
    def page_parts(self) -> display_cache.QueryParts:
        """Return the parts that select the page, which key its display cache entry."""
        return (self.cursor, self.q, self.subnet_id, self.scope)


@dataclass(frozen=True)
class ReservationPage:
    """One display cache entry: a Reservation page and the Subnet Catalogue that its records were parsed against."""

    snapshot: ReservationSnapshot
    catalogue: CatalogueSnapshot

    @property
    def settled(self) -> bool:
        """Return false when the page walk or the Catalogue read did not settle; the cache never stores it."""
        return self.snapshot.settled and self.catalogue.settled


def empty_snapshot(family: Family, read_started: datetime) -> ReservationSnapshot:
    """Return an incomplete Snapshot with no records, read at *read_started*."""
    return ReservationSnapshot(
        family=family, records=(), diagnostics=(), complete=False, next_cursor=None, read_started=read_started
    )


def _matches(reservation: Reservation, q: str, subnet_id: int | None, scope: str) -> bool:
    """Apply the same substring, Subnet, and Scope predicates before presentation."""
    in_subnet = isinstance(reservation.scope, InSubnetReservationScope)
    record_subnet_id = (
        reservation.scope.subnet.subnet_id if isinstance(reservation.scope, InSubnetReservationScope) else 0
    )
    if subnet_id is not None and record_subnet_id != subnet_id:
        return False
    if scope and scope != ("in-subnet" if in_subnet else "global"):
        return False
    query = q.casefold()
    return (
        not query
        or any(query in str(address).casefold() for address in reservation.addresses)
        or query in reservation.hostname.casefold()
        or query in reservation.identity.value.casefold()
        or any(
            query in (option.name or "").casefold() or query in option.data.casefold() for option in reservation.options
        )
    )


def _read_later_search_page(
    client: KeaClient, family: Family, catalogue: CatalogueSnapshot, cursor: str | None, subnet_id: int | None
) -> ReservationSnapshot | None:
    """Read a later page of a Reservation search, or return None when the read fails: it ends the search batch."""
    page = attempt(
        f"A later DHCPv{family} Reservation search page",
        lambda: client.reservation_page(
            family, catalogue, cursor=cursor, limit=PAGE_SIZE, subnet_id=subnet_id, max_raw_pages=1
        ),
    )
    return None if isinstance(page, ReadFailure) else page


def _read_page(
    server: Server, family: Family, query: ReservationQuery, catalogue: CatalogueSnapshot
) -> ReservationSnapshot:
    """Read a browse page, or scan a bounded batch until a filtered page matches.

    The records are parsed against *catalogue*. A browse page has the time of its own read. A search, and a page
    that needs no read, have the time at which this call started.
    """
    subnet_id, scope, cursor = query.subnet_id, query.scope, query.cursor
    started = timezone.now()
    if subnet_id is not None and subnet_id > 0 and scope == "global":
        return replace(empty_snapshot(family, started), complete=True)
    read_subnet_id = 0 if scope == "global" else subnet_id
    if (
        read_subnet_id is not None
        and read_subnet_id > 0
        and not isinstance(catalogue.find_by_id(read_subnet_id), VerifiedSubnet)
    ):
        if catalogue.identity_complete and catalogue.consistent:
            return replace(empty_snapshot(family, started), complete=True)
        read_subnet_id = None
    with server.get_client(version=family) as client:
        if not query.filtered:
            return client.reservation_page(family, catalogue, cursor=cursor, limit=PAGE_SIZE)
        return _search_batch(client, family, catalogue, query, read_subnet_id, started)


def _search_batch(
    client: KeaClient,
    family: Family,
    catalogue: CatalogueSnapshot,
    query: ReservationQuery,
    read_subnet_id: int | None,
    started: datetime,
) -> ReservationSnapshot:
    """Scan a bounded batch of filtered pages from the cursor of *query* until a page matches."""
    q, subnet_id, scope, cursor = query.q, query.subnet_id, query.scope, query.cursor
    diagnostics = []
    complete = True
    for page_index in range(SEARCH_PAGE_LIMIT):
        read: ReservationSnapshot | None
        # The first page raises to the caller; a later page that fails ends the batch.
        if page_index == 0:
            read = client.reservation_page(
                family,
                catalogue,
                cursor=cursor,
                limit=PAGE_SIZE,
                subnet_id=read_subnet_id,
                max_raw_pages=1,
            )
        else:
            read = _read_later_search_page(client, family, catalogue, cursor, read_subnet_id)
        if read is None:
            diagnostics.append(
                ReservationDiagnostic(
                    code=RESERVATION_PAGE_FETCH_FAILED,
                    message="Search is incomplete because a Reservation page could not be read. Retry with Next page.",
                    source_position="search",
                )
            )
            return ReservationSnapshot(
                family=family,
                records=(),
                diagnostics=tuple(diagnostics),
                complete=False,
                next_cursor=cursor,
                read_started=started,
            )
        page = read
        matches = tuple(record for record in page.records if _matches(record, q, subnet_id, scope))
        diagnostics.extend(page.diagnostics)
        complete = complete and page.complete
        cursor = page.next_cursor
        if cursor is not None and page_index + 1 == SEARCH_PAGE_LIMIT:
            complete = False
            diagnostics.append(
                ReservationDiagnostic(
                    code=RESERVATION_PAGE_LIMIT_REACHED,
                    message=(
                        "Search is incomplete. The search batch limit was reached. Additional Reservations may remain. "
                        f"At most {SEARCH_PAGE_LIMIT * PAGE_SIZE} Reservations per server were inspected. "
                        "Narrow the filters or continue with Next page."
                    ),
                    source_position="search",
                )
            )
        if matches or cursor is None or page_index + 1 == SEARCH_PAGE_LIMIT:
            break
    return replace(page, records=matches, diagnostics=tuple(diagnostics), complete=complete, read_started=started)


def cached_page(server: Server, family: Family, query: ReservationQuery) -> ReservationPage:
    """Read the display cache entry of the page of *query*, or read it from Kea and store a settled result.

    On a miss it reads the display Subnet Catalogue, live on a Refresh, and the page parsed against it. A Kea,
    transport or reply failure raises. The view callers run it through ``load_snapshot()``.

    Raises:
        ValueError: If the Server configuration or the query is not valid.

    """

    def read() -> ReservationPage:
        catalogue = subnet_catalogue.display(server, family, refresh=query.refresh)
        return ReservationPage(_read_page(server, family, query, catalogue), catalogue)

    return display_cache.cached(server, family, "reservations", read, query=query.page_parts, refresh=query.refresh)


def read_snapshot(server: Server, family: Family) -> ReservationSnapshot:
    """Read the complete Reservation Snapshot of *family* from Kea, live, for a transfer.

    The records are parsed against the display Subnet Catalogue. A Kea, transport or reply failure raises.
    """
    catalogue = subnet_catalogue.display(server, family)
    with server.get_client(version=family) as client:
        return client.reservation_snapshot(family, catalogue, page_size=PAGE_SIZE)


def read_page(server: Server, family: Family, *, cursor: str | None, limit: int) -> ReservationSnapshot:
    """Read the page of at most *limit* Reservations after *cursor* from Kea, live, without a filter.

    The records are parsed against the display Subnet Catalogue. A Kea, transport or reply failure raises.
    """
    with server.get_client(version=family) as client:
        return client.reservation_page(family, subnet_catalogue.display(server, family), cursor=cursor, limit=limit)


def _scope(catalogue: CatalogueSnapshot, subnet_id: int | None) -> ReservationScope:
    """Return the Global Scope without *subnet_id*, else the In-Subnet Scope of its verified Subnet in *catalogue*.

    Raises:
        ValueError: If *catalogue* shows no verified Subnet with *subnet_id*.

    """
    if subnet_id is None:
        return GlobalReservationScope()
    subnet = catalogue.find_by_id(subnet_id)
    if not isinstance(subnet, VerifiedSubnet):
        raise ValueError("The Reservation Subnet is not verified.")
    return InSubnetReservationScope(subnet.identity)


def read_by_identity(
    server: Server, family: Family, subnet_id: int | None, identity: ReservationIdentity
) -> Reservation | None:
    """Read the Reservation of *identity* in the Subnet *subnet_id*, or in the Global Scope without one, live.

    A Kea, transport or reply failure raises.

    Raises:
        ValueError: If *subnet_id* is not a verified Subnet, or *identity* is not valid for *family*.

    """
    with server.get_client(version=family) as client:
        catalogue = subnet_catalogue.display(server, family)
        return client.reservation_by_identity(family, catalogue, _scope(catalogue, subnet_id), identity)


def read_change_target(
    server: Server, family: Family, subnet_id: int, identity: ReservationIdentity
) -> Reservation | None:
    """Read the Reservation to edit or delete: one live ``subnet{v}-list`` read, with no config-get and no cache.

    Return None when the read confirms that the Subnet is absent, or when Kea does not hold the Reservation. A Kea,
    transport or reply failure raises.

    Raises:
        SubnetUnconfirmed: If the read cannot confirm the Subnet or its absence.
        ValueError: If *identity* is not valid for *family*.

    """
    _require_family(family, identity)
    return _read_target(server, family, subnet_catalogue.read_identity(server, family), subnet_id, identity)


def read_sync_target(
    server: Server, family: Family, subnet_id: int, identity: ReservationIdentity
) -> tuple[Reservation, CatalogueSnapshot] | None:
    """Read the Reservation of a row Sync and the live Catalogue, with identity and configuration facts, that it uses.

    The read uses no cache and rotates no generation of it. Return None when the read confirms that the Subnet is
    absent, or when Kea does not hold the Reservation. A failed ``reservation-get`` raises. A failed ``config-get``
    does not raise: the returned Catalogue then has ``configuration_available`` False.

    Raises:
        SubnetUnconfirmed: If the ``subnet{v}-list`` read cannot confirm the Subnet or its absence.
        ValueError: If *identity* is not valid for *family*.

    """
    _require_family(family, identity)
    lookup = subnet_catalogue.read_verified(server, family)
    reservation = _read_target(server, family, lookup, subnet_id, identity)
    return None if reservation is None else (reservation, lookup.snapshot)


def _require_family(family: Family, identity: ReservationIdentity) -> None:
    """Raise ValueError before any Kea read when *identity* is not valid for *family*."""
    if identity.identifier_type not in reservation_identifier_types(family):
        raise ValueError(f"{identity.identifier_type} is not supported for DHCPv{family} Reservations.")


def _read_target(
    server: Server, family: Family, lookup: SubnetLookup, subnet_id: int, identity: ReservationIdentity
) -> Reservation | None:
    """Read the Reservation of *identity* in the Subnet *subnet_id* of *lookup*, or None when either is absent."""
    subnet = lookup.find_by_id(subnet_id)
    if subnet is None:
        return None
    with server.get_client(version=family) as client:
        return client.reservation_by_identity(
            family, lookup.snapshot, InSubnetReservationScope(subnet.identity), identity
        )


def read_by_address(server: Server, family: Family, subnet_id: int, address: str) -> Reservation | None:
    """Read the Reservation that holds *address* in the Subnet *subnet_id*, live.

    A Kea, transport or reply failure raises.

    Raises:
        ValueError: If *subnet_id* is not a verified Subnet, or *address* is not valid.

    """
    with server.get_client(version=family) as client:
        catalogue = subnet_catalogue.display(server, family)
        return client.reservation_by_address(family, catalogue, _scope(catalogue, subnet_id), address)


def read_by_hostname(server: Server, family: Family, hostname: str) -> ReservationSnapshot:
    """Read the Reservations whose hostname is *hostname*, live. A Kea, transport or reply failure raises.

    Raises:
        ValueError: If *hostname* is not valid.

    """
    with server.get_client(version=family) as client:
        return client.reservations_by_hostname(family, subnet_catalogue.display(server, family), hostname)
