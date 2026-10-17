# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2026 Andrew Backeby <andrew@backeby.eu>
# SPDX-License-Identifier: Apache-2.0
"""Typed Reservation list, filtering, export, and presentation helpers."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

import requests
from django.core.exceptions import BadRequest
from django.db import DatabaseError
from django.http import HttpRequest, HttpResponse
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from netbox.views import generic
from typing_extensions import assert_never
from utilities.views import register_model_view

from .. import constants, display_cache, forms, server_configuration, tables
from ..constants import Family
from ..ipam_reconciliation import (
    RESERVATION,
    Ownership,
    ReservationPhase,
    address_ownership,
    claim_permissions,
    reconcile_permissions,
)
from ..kea import KeaException
from ..lease_reservation_reads import lease_presence
from ..models import Server
from ..reservation_transfer import export_reservation_document
from ..reservations import (
    RESERVATION_PAGE_FETCH_FAILED,
    RESERVATION_PAGE_LIMIT_REACHED,
    InSubnetReservationScope,
    LeaseAbsent,
    LeasePresenceUnknown,
    LeasePresent,
    Reservation,
    ReservationCapabilities,
    ReservationDiagnostic,
    ReservationSnapshot,
    ReservationSynchronizationState,
    UnknownLeasePresence,
)
from ..subnet_catalogue import CatalogueSnapshot, VerifiedSubnet
from ..subnet_catalogue import display as subnet_catalogue
from ..sync_permissions import SyncGate, sync_gate
from ..utilities import OptionalViewTab
from ._base import IPAM_UNREADABLE, _client_settings_error, _safe_return_url, sync_title
from .notices import HEADLINES, Notice, load_snapshot, notice
from .read_age import read_age_context, refresh_requested
from .workspace import ServerFamilyMixin

logger = logging.getLogger(__name__)

_RESERVATION_PAGE_SIZE = 100
_RESERVATION_SEARCH_PAGE_LIMIT = 5
_MUTATION_UNCONFIRMED = "Reservation mutation capabilities could not be confirmed."


def _build_reservation_options_formset(post_data: Any) -> tuple[Any, bool]:
    """Build the Reservation options formset and reject a truncated management form."""
    if "options-TOTAL_FORMS" in post_data:
        formset = forms.ReservationOptionsFormSet(data=post_data, prefix="options")
        return formset, formset.is_valid()
    if any(key.startswith("options-") for key in post_data):
        formset = forms.ReservationOptionsFormSet(data=post_data, prefix="options")
        formset.is_valid()
        return formset, False
    return forms.ReservationOptionsFormSet(prefix="options"), True


#: The title of the Lease Unknown badge, for each reason that shows one.
_PARTIAL_LEASE_REASON = "Kea returned lease records that could not be read, so a missing Lease cannot be confirmed."
_FOREIGN_IDENTIFIER_REASON = (
    "A current lease carries a client identifier that no Reservation can hold, so a missing Lease cannot be confirmed."
)


def _unknown_badge_title(reason: UnknownLeasePresence) -> str:
    """Return the title of the Lease Unknown badge, or an empty string for a reason that shows no badge."""
    match reason:
        case UnknownLeasePresence.INCOMPLETE_SNAPSHOT:
            return _PARTIAL_LEASE_REASON
        case UnknownLeasePresence.FOREIGN_IDENTIFIER:
            return _FOREIGN_IDENTIFIER_REASON
        case (
            UnknownLeasePresence.QUERY_GUARD
            | UnknownLeasePresence.KEA_ERROR
            | UnknownLeasePresence.MALFORMED_REPLY
            | UnknownLeasePresence.INVALID_READ
            | UnknownLeasePresence.UNSEARCHABLE_IDENTIFIER
            | UnknownLeasePresence.LEASE_HOOK_UNAVAILABLE
        ):
            return ""
        case _:
            assert_never(reason)


def _enrich_reservations_with_lease_status(
    server: Server,
    reservations: list[dict[str, Any]],
    version: Family,
    *,
    read_since: datetime,
) -> None:
    """Show the Current Lease Presence of each Reservation row as its Lease badge.

    Rows arrive with ``has_active_lease`` at ``None``, which renders no badge. A Lease lookup read before *read_since*,
    the read time of the Reservation table, is read again. An unexpected failure is logged and leaves every badge out.
    """
    try:
        presences = lease_presence(server, version, [row["reservation"] for row in reservations], read_since=read_since)
    except Exception:
        logger.exception("Reservation lease enrichment failed")
        return
    for row, presence in zip(reservations, presences, strict=True):
        match presence:
            case LeasePresent(address=address):
                row["has_active_lease"] = True
                row["lease_url"] = _lease_search_url(row["reservation"], row["server_pk"], version, address)
            case LeaseAbsent():
                row["has_active_lease"] = False
            case LeasePresenceUnknown(reason=reason):
                row["lease_status_reason"] = _unknown_badge_title(reason)
            case _:
                assert_never(presence)


def _lease_search_url(
    reservation: Reservation,
    server_pk: int,
    version: Family,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
) -> str | None:
    """Return the lease search that finds the lease this Reservation matched.

    An addressless or multi-address Reservation has no single address to search by, so
    the identity that matched selects the route instead.
    """
    if address is not None:
        selector, value = constants.BY_IP, str(address)
    elif identity_selector := constants.LEASE_SELECTOR_BY_IDENTIFIER[version].get(reservation.identity.identifier_type):
        selector, value = identity_selector, reservation.identity.value
    elif isinstance(reservation.scope, InSubnetReservationScope):
        selector, value = constants.BY_SUBNET, reservation.scope.subnet.cidr
    else:
        return None
    base = reverse(f"plugins:netbox_kea:server_leases{version}", args=[server_pk])
    return f"{base}?{urlencode({'by': selector, 'q': value})}"


def _reservation_matches(reservation: Reservation, q: str, subnet_id: int | None, scope: str) -> bool:
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


def _reservation_table_record(reservation: Reservation, server: Server) -> dict[str, Any]:
    """Build one presentation row from a typed Reservation."""
    if isinstance(reservation.scope, InSubnetReservationScope):
        scope_kind = "in-subnet"
        subnet_id = reservation.scope.subnet.subnet_id
        subnet_cidr = reservation.scope.subnet.cidr
    else:
        scope_kind = "global"
        subnet_id = 0
        subnet_cidr = ""
    addresses = [str(address) for address in reservation.addresses]
    record = {
        "family": reservation.family,
        "scope_kind": scope_kind,
        # Set by lease enrichment. None means Kea was not read, so no badge renders.
        "has_active_lease": None,
        "lease_status_reason": "",
        "lease_url": None,
        "subnet_id": subnet_id,
        "subnet_cidr": subnet_cidr,
        "identifier_type": reservation.identity.identifier_type,
        "identifier": reservation.identity.value,
        "ip_address": addresses[0] if addresses else "",
        "ip_addresses": addresses,
        "extra_ips": addresses[1:],
        "prefixes": [str(prefix) for prefix in reservation.delegated_prefixes],
        "hostname": reservation.hostname,
        "options": reservation.options,
        "reservation": reservation,
        "server_name": server.name,
        "server_pk": server.pk,
    }
    if addresses:
        record["_ip_sort_key"] = int(reservation.addresses[0])
    return record


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
class ReservationRead:
    """The Reservation read of one Server: its Snapshot or the Notice of a failed read, and its capabilities."""

    query: ReservationQuery
    loaded: ReservationSnapshot | Notice
    #: ``None`` when the query did not ask for them or Kea could not confirm them.
    capabilities: ReservationCapabilities | None
    #: The Subnet Catalogue for the Subnet ID filter; ``None`` when the Server did not answer.
    catalogue: CatalogueSnapshot | None = None


def _empty_reservation_snapshot(version: Family, read_started: datetime) -> ReservationSnapshot:
    return ReservationSnapshot(
        family=version, records=(), diagnostics=(), complete=False, next_cursor=None, read_started=read_started
    )


@dataclass(frozen=True)
class _ReservationPage:
    """One display cache entry: a Reservation page and the Subnet Catalogue that its records were parsed against."""

    snapshot: ReservationSnapshot
    catalogue: CatalogueSnapshot

    @property
    def settled(self) -> bool:
        """Return false when the page walk or the Catalogue read did not settle; the cache never stores it."""
        return self.snapshot.settled and self.catalogue.settled


def _read_reservations(
    server: Server, version: Family, query: ReservationQuery, catalogue: CatalogueSnapshot
) -> ReservationSnapshot:
    """Read the complete Snapshot, a browse page, or scan a bounded batch until a filtered page matches.

    The records are parsed against *catalogue*. A browse page has the time of its own read. A search, and a page
    that needs no read, have the time at which this call started.
    """
    q, subnet_id, scope, cursor = query.q, query.subnet_id, query.scope, query.cursor
    if query.full:
        return server.get_client(version=version).reservation_snapshot(
            version, catalogue, page_size=_RESERVATION_PAGE_SIZE
        )
    started = timezone.now()
    if subnet_id is not None and subnet_id > 0 and scope == "global":
        return replace(_empty_reservation_snapshot(version, started), complete=True)
    read_subnet_id = 0 if scope == "global" else subnet_id
    if (
        read_subnet_id is not None
        and read_subnet_id > 0
        and not isinstance(catalogue.find_by_id(read_subnet_id), VerifiedSubnet)
    ):
        if catalogue.identity_complete and catalogue.consistent:
            return replace(_empty_reservation_snapshot(version, started), complete=True)
        read_subnet_id = None
    client = server.get_client(version=version)
    if not query.filtered:
        return client.reservation_page(version, catalogue, cursor=cursor, limit=_RESERVATION_PAGE_SIZE)
    diagnostics = []
    complete = True
    for page_index in range(_RESERVATION_SEARCH_PAGE_LIMIT):
        try:
            page = client.reservation_page(
                version,
                catalogue,
                cursor=cursor,
                limit=_RESERVATION_PAGE_SIZE,
                subnet_id=read_subnet_id,
                max_raw_pages=1,
            )
        except (KeaException, requests.RequestException, RuntimeError, ValueError):
            if page_index == 0:
                raise
            logger.exception("Failed to continue DHCPv%s Reservation search", version)
            diagnostics.append(
                ReservationDiagnostic(
                    code=RESERVATION_PAGE_FETCH_FAILED,
                    message="Search is incomplete because a Reservation page could not be read. Retry with Next page.",
                    source_position="search",
                )
            )
            return ReservationSnapshot(
                family=version,
                records=(),
                diagnostics=tuple(diagnostics),
                complete=False,
                next_cursor=cursor,
                read_started=started,
            )
        matches = tuple(record for record in page.records if _reservation_matches(record, q, subnet_id, scope))
        diagnostics.extend(page.diagnostics)
        complete = complete and page.complete
        cursor = page.next_cursor
        if cursor is not None and page_index + 1 == _RESERVATION_SEARCH_PAGE_LIMIT:
            complete = False
            diagnostics.append(
                ReservationDiagnostic(
                    code=RESERVATION_PAGE_LIMIT_REACHED,
                    message=(
                        "Search is incomplete. The search batch limit was reached. Additional Reservations may remain. "
                        f"At most {_RESERVATION_SEARCH_PAGE_LIMIT * _RESERVATION_PAGE_SIZE} Reservations per server were inspected. "
                        "Narrow the filters or continue with Next page."
                    ),
                    source_position="search",
                )
            )
        if matches or cursor is None or page_index + 1 == _RESERVATION_SEARCH_PAGE_LIMIT:
            break
    return replace(page, records=matches, diagnostics=tuple(diagnostics), complete=complete, read_started=started)


def _read_reservation_page(server: Server, version: Family, query: ReservationQuery) -> _ReservationPage:
    """Read the Subnet Catalogue, live on a Refresh, and the page of *query* parsed against it."""
    catalogue = subnet_catalogue(server, version, refresh=query.refresh)
    return _ReservationPage(_read_reservations(server, version, query, catalogue), catalogue)


def _display_capabilities(server: Server, version: Family) -> ReservationCapabilities | None:
    """Return the Reservation capabilities that the cached Server Configuration shows, for a page render."""
    return server_configuration.reservation_capabilities(server_configuration.display(server, version))


def _live_capabilities(server: Server, version: Family) -> ReservationCapabilities | None:
    """Return the Reservation capabilities of a live Server Configuration read, to authorize a write."""
    return server_configuration.reservation_capabilities(server_configuration.for_verification(server, version))


def fetch(server: Server, family: Family, query: ReservationQuery) -> ReservationRead:
    """Read the Reservations of *query* from Kea, and the mutation capabilities when it asks.

    It is safe in a worker thread. A Kea, transport or reply failure of the Reservation read is its Notice. Such a
    failure of the capability read leaves the capabilities unconfirmed and never hides the Reservations.

    Raises:
        ValueError: If the Server configuration or the query is not valid.

    """
    loaded: ReservationSnapshot | Notice
    catalogue: CatalogueSnapshot | None = None
    if query.full:
        loaded = load_snapshot(
            server, "reservation", lambda: _read_reservations(server, family, query, subnet_catalogue(server, family))
        )
    else:
        page = load_snapshot(
            server,
            "reservation",
            lambda: display_cache.cached(
                server,
                family,
                "reservations",
                lambda: _read_reservation_page(server, family, query),
                query=query.page_parts,
                refresh=query.refresh,
            ),
        )
        loaded, catalogue = (page, None) if isinstance(page, Notice) else (page.snapshot, page.catalogue)
    capabilities = None
    # A second read of a Server that did not answer would only add its timeout.
    unreachable = isinstance(loaded, Notice) and loaded.unreachable
    if query.mutations and not unreachable:
        capabilities = _display_capabilities(server, family)
    # A page comes with the Catalogue it was parsed against; only a failed read or an export reads it here.
    if catalogue is None and not unreachable:
        catalogue = subnet_catalogue(server, family)
    return ReservationRead(query, loaded, capabilities, catalogue)


@dataclass(frozen=True)
class PresentedReservations:
    """The Reservation rows of one Server for one user, and what the page shows about them."""

    rows: list[dict[str, Any]]
    #: The Notice of a failed read, else the Notice of the Snapshot.
    notice: Notice | None
    #: ``None`` when the read failed.
    snapshot: ReservationSnapshot | None
    can_mutate: bool
    #: Why a user who can change the Server cannot change its Reservations; empty otherwise.
    mutation_unavailable_reason: str

    @property
    def next_cursor(self) -> str | None:
        """Return the cursor of the next page, or ``None`` when no page remains or the read failed."""
        return None if self.snapshot is None else self.snapshot.next_cursor

    @property
    def partial(self) -> bool:
        """Return whether a match can be missing: the read failed, was incomplete, or more pages remain."""
        return self.snapshot is None or not self.snapshot.complete or self.snapshot.next_cursor is not None


def present(user: Any, server: Server, read: ReservationRead, *, return_url: str) -> PresentedReservations:
    """Present one Server's Reservation read to *user*. It reads the ORM, so it must run in the main thread.

    Each row gets its badges and, when the mutation capabilities allow, the edit and delete URLs that return to
    *return_url*.
    """
    snapshot: ReservationSnapshot | None
    read_notice: Notice | None
    if isinstance(read.loaded, Notice):
        snapshot, read_notice = None, read.loaded
    else:
        snapshot, read_notice = read.loaded, notice(read.loaded)
    rows = [] if snapshot is None else [_reservation_table_record(record, server) for record in snapshot.records]
    capabilities = read.capabilities
    can_mutate = capabilities is not None and capabilities.mutation_available
    reason = ""
    if read.query.mutations and not can_mutate:
        reason = (capabilities.explanation if capabilities is not None else "") or _MUTATION_UNCONFIRMED
    if snapshot is not None and rows:
        _enrich_reservations_with_badges(
            rows,
            server,
            snapshot.family,
            user=user,
            sync=sync_gate(user, claim_permissions(RESERVATION)),
            read_since=snapshot.read_started,
        )
        _attach_reservation_action_urls(rows, server.pk, snapshot.family, can_change=can_mutate, return_url=return_url)
    return PresentedReservations(
        rows=rows,
        notice=read_notice,
        snapshot=snapshot,
        can_mutate=can_mutate,
        mutation_unavailable_reason=reason,
    )


def empty_text(filtered: bool, partial: bool) -> str | None:
    """Return the empty table text of a filtered search that could miss a match, else ``None`` for the default."""
    return "No matches in this search batch." if filtered and partial else None


def _next_reservation_page_url(request: HttpRequest, cursor: str | None) -> str | None:
    if cursor is None:
        return None
    query = request.GET.copy()
    query["cursor"] = cursor
    query.pop("page", None)
    return f"{request.path}?{query.urlencode()}"


def _attach_reservation_action_urls(
    reservations: list[dict[str, Any]],
    server_pk: int,
    version: Family,
    *,
    can_change: bool,
    return_url: str,
) -> None:
    """Attach canonical Scope plus Identity mutation URLs that return to *return_url* to eligible rows."""
    for row in reservations:
        row["edit_url"] = None
        row["delete_url"] = None
        if not can_change or row["scope_kind"] != "in-subnet":
            continue
        query = urlencode(
            {"identifier_type": row["identifier_type"], "identifier": row["identifier"], "return_url": return_url}
        )
        try:
            args = [server_pk, row["subnet_id"]]
            edit = reverse(f"plugins:netbox_kea:server_reservation{version}_edit", args=args)
            delete = reverse(f"plugins:netbox_kea:server_reservation{version}_delete", args=args)
        except NoReverseMatch:
            logger.debug("No Reservation action URL for Subnet ID %r", row["subnet_id"])
            continue
        row["edit_url"] = f"{edit}?{query}"
        row["delete_url"] = f"{delete}?{query}"


_IPAM_HIDDEN = "You may not view an IP address of this Reservation in NetBox."


def _enrich_reservations_with_badges(
    reservations: list[dict[str, Any]],
    server: Server,
    version: Family,
    *,
    user: Any,
    sync: SyncGate,
    read_since: datetime,
) -> None:
    """Add active-lease and aggregate NetBox synchronization state to typed rows.

    A row that can take a Sync gets ``sync_url`` when *sync* allows it, else ``sync_refusal`` with the reason.
    A Lease badge read before *read_since*, the read time of the Reservation table, is read again.
    """
    _enrich_reservations_with_lease_status(server, reservations, version, read_since=read_since)

    addresses = [str(address) for row in reservations for address in row["reservation"].addresses]
    ownership: dict[str, Ownership] | None
    try:
        ownership = address_ownership(server, version, RESERVATION, addresses, user)
    except DatabaseError:
        logger.exception("Could not read NetBox IPAM state for Reservation badges")
        ownership = None

    for row in reservations:
        reservation: Reservation = row["reservation"]
        row.update(reservation_badge(reservation, ownership))
        state = row["sync_state"]
        row["sync_url"] = None
        row["sync_refusal"] = ""
        if (
            isinstance(reservation.scope, InSubnetReservationScope)
            and reservation.addresses
            and state.code in ("not-synchronized", "partially-synchronized")
        ):
            if sync.allowed:
                query = urlencode(
                    {
                        "identifier_type": reservation.identity.identifier_type,
                        "identifier": reservation.identity.value,
                    }
                )
                base = reverse(
                    f"plugins:netbox_kea:server_reservation{version}_sync",
                    args=[server.pk, reservation.scope.subnet.subnet_id],
                )
                row["sync_url"] = f"{base}?{query}"
            else:
                row["sync_refusal"] = sync.reason


def reservation_badge(reservation: Reservation, ownership: Mapping[str, Ownership] | None) -> dict[str, Any]:
    """Return the ``sync_state``, ``netbox_ip_url`` and ``sync_title`` of a Reservation row.

    *ownership* is the read of :func:`address_ownership` with the Reservation source; ``None`` means that it failed.
    """
    from ..sync import reservation_synchronization_state

    found = {str(address): ownership[str(address)] for address in reservation.addresses} if ownership else {}
    synchronized = {address: item.obj for address, item in found.items() if item.state == "synchronized"}
    if not isinstance(reservation.scope, InSubnetReservationScope) or not reservation.addresses:
        state = reservation_synchronization_state(reservation, frozenset())
    elif ownership is None:
        state = ReservationSynchronizationState.unknown(len(reservation.addresses), IPAM_UNREADABLE)
    elif any(item.state == "hidden" for item in found.values()):
        state = ReservationSynchronizationState.unknown(len(reservation.addresses), _IPAM_HIDDEN)
    else:
        state = reservation_synchronization_state(reservation, frozenset(synchronized))
    return {
        "sync_state": state,
        "netbox_ip_url": next((ip.get_absolute_url() for ip in synchronized.values() if ip is not None), None),
        "sync_title": _sync_title(found.values()),
    }


def _sync_title(ownership: Iterable[Ownership]) -> str:
    """Return what a Sync does to the IP addresses that exist but that this Server does not own."""
    states = {item.state for item in ownership}
    # A takeover changes more than an added owner, so its title wins.
    for state in ("unmarked", "not-synchronized"):
        if state in states:
            return sync_title(state, "IP address")
    return ""


def _reservation_list_context(
    request: HttpRequest,
    server: Server,
    version: Family,
) -> dict[str, Any]:
    """Fetch and present one bounded typed Reservation page."""
    search_form = forms.ReservationSearchForm(request.GET or None)
    filters = search_form.cleaned_data if search_form.is_valid() else {}
    can_change = Server.objects.restrict(request.user, "change").filter(pk=server.pk).exists()
    query = ReservationQuery(
        cursor=request.GET.get("cursor"), mutations=can_change, refresh=refresh_requested(request), **filters
    )
    read_started = None
    # Shown inside the section, because a Refresh swaps only the section and never shows a flash message.
    read_error = ""
    try:
        read = fetch(server, version, query)
    except ValueError:
        logger.exception("Unexpected error fetching DHCPv%s Reservations", version)
        read_error = HEADLINES["reservation"]
        read = ReservationRead(query, _empty_reservation_snapshot(version, timezone.now()), capabilities=None)
    else:
        read_started = None if isinstance(read.loaded, Notice) else read.loaded.read_started
    search_form.offer_subnets(forms.subnet_id_options(read.catalogue.subnet_choices if read.catalogue else ()))
    presented = present(request.user, server, read, return_url=_safe_return_url(request, request.get_full_path()))
    # A missing host_cmds hook has its own panel, so one cause shows one banner.
    hook_available = not (presented.notice is not None and presented.notice.unsupported_command)
    bulk_sync = sync_gate(request.user, reconcile_permissions(server, ReservationPhase.source))

    table_class = tables.ReservationTable4 if version == 4 else tables.ReservationTable6
    table = table_class(presented.rows, user=request.user, empty_text=empty_text(query.filtered, presented.partial))
    table.configure(request)
    return {
        **read_age_context(read_started),
        "read_error": read_error,
        "table": table,
        "dhcp_version": version,
        "hook_available": hook_available,
        "search_form": search_form,
        "snapshot_complete": presented.snapshot is not None and presented.snapshot.complete,
        "reservation_notice": presented.notice if hook_available else None,
        "next_page_url": _next_reservation_page_url(request, presented.next_cursor),
        "mutation_unavailable": bool(presented.mutation_unavailable_reason),
        "mutation_unavailable_reason": presented.mutation_unavailable_reason,
        "add_url": reverse(f"plugins:netbox_kea:server_reservation{version}_add", args=[server.pk])
        + f"?{urlencode({'return_url': _safe_return_url(request, request.get_full_path())})}"
        if presented.can_mutate
        else None,
        "bulk_sync_url": reverse(f"plugins:netbox_kea:server_reservation{version}_bulk_sync", args=[server.pk])
        if bulk_sync.allowed
        else None,
        "bulk_sync_refusal": bulk_sync.reason,
        "import_url": reverse(f"plugins:netbox_kea:server_reservation{version}_bulk_import", args=[server.pk])
        if presented.can_mutate
        else None,
    }


def _reservation_export_response(request: HttpRequest, server: Server, version: Family) -> HttpResponse:
    """Export a full typed Snapshot only when its traversal is complete."""
    format_name = request.GET.get("export")
    if format_name not in ("yaml", "json"):
        raise BadRequest("Reservation export format must be YAML or JSON.")
    try:
        server.get_client(version=version).close()
    except ValueError as exc:
        return HttpResponse(_client_settings_error(server, exc), status=500, content_type="text/plain")
    loaded = load_snapshot(
        server,
        "reservation",
        lambda: _read_reservations(server, version, ReservationQuery(full=True), subnet_catalogue(server, version)),
    )
    if isinstance(loaded, Notice):
        return HttpResponse(loaded.text, status=502, content_type="text/plain")
    snapshot = loaded
    if not snapshot.complete:
        return HttpResponse("The Reservation Snapshot is incomplete and cannot be exported.", status=409)
    content = export_reservation_document(snapshot.records, format_name)
    response = HttpResponse(
        content,
        content_type="application/json" if format_name == "json" else "application/yaml",
    )
    response["Content-Disposition"] = f'attachment; filename="kea-dhcpv{version}-reservations.{format_name}"'
    return response


_RESERVATIONS_TAB = OptionalViewTab(
    label="Reservations", weight=1040, is_enabled=lambda server: server.dhcp4 or server.dhcp6
)


@register_model_view(Server, "reservations4")
class ServerReservations4View(ServerFamilyMixin, generic.ObjectView):
    """Show bounded DHCPv4 Reservation Snapshots."""

    workspace_section = "reservations"
    dhcp_version = 4

    queryset = Server.objects.all()
    tab = _RESERVATIONS_TAB
    template_name = "netbox_kea/server_reservations.html"

    def get(self, request: HttpRequest, **kwargs) -> HttpResponse:
        """Redirect v6-only servers, export, or render the list."""
        instance = self.get_object(**kwargs)
        if "export" in request.GET:
            return _reservation_export_response(request, instance, 4)
        return super().get(request, **kwargs)

    def get_extra_context(self, request: HttpRequest, instance: Server) -> dict[str, Any]:
        """Return the DHCPv4 typed list context."""
        return _reservation_list_context(request, instance, 4)


@register_model_view(Server, "reservations6")
class ServerReservations6View(ServerFamilyMixin, generic.ObjectView):
    """Show bounded DHCPv6 Reservation Snapshots."""

    workspace_section = "reservations"
    dhcp_version = 6

    queryset = Server.objects.all()
    template_name = "netbox_kea/server_reservations.html"

    def get(self, request: HttpRequest, **kwargs) -> HttpResponse:
        """Export or render the DHCPv6 list."""
        instance = self.get_object(**kwargs)
        if "export" in request.GET:
            return _reservation_export_response(request, instance, 6)
        return super().get(request, **kwargs)

    def get_extra_context(self, request: HttpRequest, instance: Server) -> dict[str, Any]:
        """Return the DHCPv6 typed list context and shared tab."""
        return {**_reservation_list_context(request, instance, 6), "tab": _RESERVATIONS_TAB}
