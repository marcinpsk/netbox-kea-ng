# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Lease Snapshot reads of the Leases tab and of the Lease badges of Reservation rows (ADR 0009)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .. import constants, display_cache, subnet_catalogue
from ..constants import Family, LeaseState
from ..kea import KeaClient, LeaseQueryUnknownSubnet
from ..leases import LeaseSnapshot
from ..models import Server
from ..subnet_catalogue import CatalogueSnapshot
from .notices import Notice, load_snapshot, notice


@dataclass(frozen=True)
class LeaseSearch:
    """What one Lease read asks of a Server.

    A selector *by* searches by the value *q*. Without one, the read covers every Lease: the page of *per_page*
    Leases after *cursor*.
    """

    by: str = ""
    q: Any = None
    state: LeaseState | None = None
    cursor: str | None = None
    per_page: int = 250

    @property
    def parts(self) -> display_cache.QueryParts:
        """Return the parts that select the read, which key its display cache entry.

        A search reads its whole scope, so only a read of every Lease holds the cursor and the page size.
        """
        q = self.q if self.q is None or isinstance(self.q, int) else str(self.q)
        if self.by:
            return (self.by, q, self.state)
        return (self.by, q, self.state, self.cursor, self.per_page)


@dataclass(frozen=True)
class LeaseRead:
    """One display cache entry: a Lease Snapshot, or the Notice of a Catalogue that could not resolve a Subnet search."""

    loaded: LeaseSnapshot | Notice
    #: False when a Subnet search resolved through a Subnet Catalogue that did not settle.
    catalogue_settled: bool = True

    @property
    def settled(self) -> bool:
        """Return false for a Notice or for a result of an unsettled Catalogue; the cache never stores it."""
        return isinstance(self.loaded, LeaseSnapshot) and self.catalogue_settled


def _resolved_search(catalogue: CatalogueSnapshot, search: LeaseSearch) -> LeaseSearch | Notice:
    """Resolve the CIDR of a Subnet search to its Subnet Identity in *catalogue*.

    Return the Notice of the Catalogue when it is unavailable, or when it shows no Subnet with the CIDR and its
    configuration facts are incomplete.

    Raises:
        LeaseQueryUnknownSubnet: If the complete, consistent configuration facts show no Subnet with the CIDR.

    """
    catalogue_notice = notice(catalogue)
    if catalogue_notice is not None and catalogue_notice.unavailable:
        return catalogue_notice
    subnet = catalogue.find_by_cidr(str(search.q.cidr))
    if subnet is not None:
        return replace(search, q=subnet.identity)
    if catalogue_notice is not None and not catalogue.configuration_confirms_absence:
        return catalogue_notice
    raise LeaseQueryUnknownSubnet


def _read_leases(client: KeaClient, server: Server, family: Family, search: LeaseSearch) -> LeaseRead:
    """Read the Lease Snapshot of *search* from Kea. A Subnet search first resolves through a live Catalogue read.

    The Catalogue read is live, so a Subnet that Kea moved since the display Catalogue was cached never answers for
    the CIDR. A Kea, transport or reply failure raises. The callers run it through ``load_snapshot()`` or refuse an
    export.

    Raises:
        LeaseQueryGuardError: If Kea cannot answer a Subnet query safely.
        ValueError: If the search is not valid.

    """
    resolved, catalogue_settled = search, True
    if search.by == constants.BY_SUBNET:
        catalogue = subnet_catalogue.for_verification(server, family)
        found = _resolved_search(catalogue, search)
        if isinstance(found, Notice):
            return LeaseRead(found, catalogue.settled)
        resolved, catalogue_settled = found, catalogue.settled
    if resolved.by:
        snapshot = client.lease_search(family, resolved.by, resolved.q, state=resolved.state, server_id=server.pk)
    else:
        snapshot = client.lease_get_page(
            family, limit=resolved.per_page, cursor=resolved.cursor, state=resolved.state, server_id=server.pk
        )
    return LeaseRead(snapshot, catalogue_settled)


def fetch(server: Server, family: Family, search: LeaseSearch, *, refresh: bool = False) -> LeaseSnapshot | Notice:
    """Read the Lease Snapshot of *search* through the display cache, or the Notice of a failed read.

    A hit sends no Kea command, also for a Subnet search. With *refresh* it reads Kea live and replaces the entry.
    It is safe in a worker thread that pins the Kea client and the display cache settings.

    Raises:
        LeaseQueryGuardError: If Kea cannot answer a Subnet query safely.
        ValueError: If the Server configuration or the search is not valid.

    """
    entry = load_snapshot(
        server,
        "lease",
        lambda: display_cache.cached(
            server,
            family,
            "leases",
            lambda: _read_leases(server.get_client(version=family), server, family, search),
            query=search.parts,
            refresh=refresh,
        ),
    )
    return entry if isinstance(entry, Notice) else entry.loaded
