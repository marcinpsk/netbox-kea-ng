# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Lease Snapshot reads of the Leases tab and of the Lease badges of Reservation rows (ADR 0009)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from . import constants, display_cache, subnet_catalogue
from .constants import Family
from .kea import KeaClient, LeaseQueryUnknownSubnet
from .leases import ALL_LEASES, LeaseQuery, LeaseSnapshot
from .models import Server
from .subnet_catalogue import CatalogueSnapshot, SubnetIdentity


@dataclass(frozen=True)
class LeaseSearch:
    """What one Lease read asks of a Server: its Lease Query and, for a read of every Lease, the page to read.

    A read of every Lease reads the page of *per_page* Leases after *cursor*. A search reads its whole scope.
    """

    query: LeaseQuery
    cursor: str | None = None
    per_page: int = 250

    @property
    def parts(self) -> display_cache.QueryParts:
        """Return the parts that select the read, which key its display cache entry.

        A search reads its whole scope, so only a read of every Lease holds the cursor and the page size.
        """
        query = self.query
        if query.selector != ALL_LEASES:
            return (query.selector, query.value, query.state)
        return (query.selector, query.value, query.state, self.cursor, self.per_page)


@dataclass(frozen=True)
class LeaseRead:
    """One display cache entry: a Lease Snapshot, or the Catalogue that could not resolve a Subnet search."""

    loaded: LeaseSnapshot | CatalogueSnapshot
    #: False when a Subnet search resolved through a Subnet Catalogue that did not settle.
    catalogue_settled: bool = True

    @property
    def settled(self) -> bool:
        """Return false for a Catalogue or for a result of an unsettled Catalogue; the cache never stores it."""
        return isinstance(self.loaded, LeaseSnapshot) and self.catalogue_settled


def _resolved_subnet(catalogue: CatalogueSnapshot, query: LeaseQuery) -> SubnetIdentity | CatalogueSnapshot:
    """Resolve the CIDR of a Subnet query to its Subnet Identity in *catalogue*.

    Return *catalogue* when it is unavailable, or when it shows no Subnet with the CIDR and it has diagnostics and
    incomplete configuration facts. A view shows its Notice.

    Raises:
        LeaseQueryUnknownSubnet: If the complete, consistent configuration facts show no Subnet with the CIDR.

    """
    if catalogue.unavailable:
        return catalogue
    subnet = catalogue.find_by_cidr(cast(str, query.value))
    if subnet is not None:
        return subnet.identity
    if catalogue.diagnostics and not catalogue.configuration_confirms_absence:
        return catalogue
    raise LeaseQueryUnknownSubnet


def read_leases(client: KeaClient, server: Server, family: Family, search: LeaseSearch) -> LeaseRead:
    """Read the Lease Snapshot of *search* from Kea. A Subnet search first resolves through a live Catalogue read.

    The Catalogue read is live, so a Subnet that Kea moved since the display Catalogue was cached never answers for
    the CIDR. A Kea, transport or reply failure raises. The view callers run it through ``load_snapshot()`` or refuse
    an export.

    Raises:
        LeaseQueryGuardError: If Kea cannot answer a Subnet query safely.
        ValueError: If the search is not valid.

    """
    query = search.query
    if query.selector == constants.BY_SUBNET:
        catalogue = subnet_catalogue.for_verification(server, family)
        found = _resolved_subnet(catalogue, query)
        if isinstance(found, CatalogueSnapshot):
            return LeaseRead(found, catalogue.settled)
        return LeaseRead(client.lease_search(query, server_id=server.pk, subnet=found), catalogue.settled)
    if query.selector == ALL_LEASES:
        snapshot = client.lease_get_page(
            family, limit=search.per_page, cursor=search.cursor, state=query.state, server_id=server.pk
        )
    else:
        snapshot = client.lease_search(query, server_id=server.pk)
    return LeaseRead(snapshot)


def cached_read(
    server: Server,
    family: Family,
    search: LeaseSearch,
    client: Callable[[], KeaClient],
    *,
    refresh: bool = False,
    read_since: datetime | None = None,
) -> LeaseRead:
    """Read the display cache entry of *search*, or read it from Kea through *client* and store a settled result.

    A hit calls *client* never, also for a Subnet search. With *refresh* it reads Kea live and replaces the entry. A
    badge passes the read time of its table as *read_since*: an entry read before it is read again. A Kea, transport or
    reply failure raises, as ``read_leases()`` does.
    """

    def fresh(entry: LeaseRead) -> bool:
        return read_since is None or (
            isinstance(entry.loaded, LeaseSnapshot) and entry.loaded.read_started >= read_since
        )

    return display_cache.cached(
        server,
        family,
        "leases",
        lambda: read_leases(client(), server, family, search),
        query=search.parts,
        refresh=refresh,
        fresh=fresh,
    )
