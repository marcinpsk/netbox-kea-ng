# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import logging
import uuid
from abc import ABCMeta
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Generic, Literal, TypeVar
from urllib.parse import parse_qs, urlsplit, urlunsplit
from urllib.parse import urlencode as _urlencode

import requests
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from django.dispatch import Signal
from django.http import HttpResponse, HttpResponseForbidden
from django.http.request import HttpRequest, QueryDict
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from extras.models import JournalEntry
from netbox.tables import BaseTable
from netbox.views import generic
from typing_extensions import assert_never
from utilities.paginator import EnhancedPaginator, get_paginate_count
from utilities.views import GetReturnURLMixin, register_model_view

from .. import event_scope, forms, runtime_change, subnet_catalogue, tables
from ..constants import Family, LeaseState
from ..ipam_reconciliation import (
    LEASE,
    LEASE_PREFIX,
    Ownership,
    address_ownership,
    claim,
    claim_permissions,
    prefix_ownership,
)
from ..kea import (
    KeaException,
    LeaseQueryGuardError,
    LeaseQueryUnknownSubnet,
    lease_query_guard_message,
)
from ..lease_reads import LeaseSearch, cached_read, read_leases
from ..lease_reservation_reads import reservation_matches
from ..leases import (
    AllocationKind,
    DHCPv4AddressLease,
    DHCPv4Binding,
    DHCPv4LeaseRequest,
    DHCPv6Binding,
    DHCPv6LeaseRequest,
    DHCPv6PrefixLease,
    Lease,
    LeaseAbsent,
    LeaseEdit,
    LeaseFound,
    LeaseRequest,
    LeaseSnapshot,
    ShownLease,
    address_identity,
    creation_mismatches,
    fact_words,
    is_current,
    parse_selection,
    shown_lease,
)
from ..models import Server
from ..published_name import lease_published_name
from ..reservations import (
    GlobalReservationScope,
    HostOnlyReservation,
    IgnoredReservation,
    IgnoredReservationReason,
    OtherKindReservation,
    PendingAddressChange,
    Reservation,
    ReservationMatch,
    ReservationMatchUnknown,
    Reserved,
    StaleMac,
    UnknownReservationMatch,
    Unreserved,
    lease_identities,
)
from ..signals import lease_added, leases_deleted
from ..subnet_catalogue import CatalogueSnapshot, CatalogueUnavailable, VerifiedSubnet
from ..sync_permissions import SyncGate, sync_gate
from ..utilities import (
    OptionalViewTab,
    diagnostic_reasons,
    export_table,
    kea_error_hint,
    lease_csv_response,
    snapshot_rows,
)
from ._base import (
    IPAM_UNREADABLE,
    ConditionalLoginRequiredMixin,
    LazyClient,
    _client_settings_error,
    _KeaChangeMixin,
    _run_change,
    _run_change_loop,
    _safe_return_url,
    _strip_empty_params,
    sync_title,
)
from .notices import Notice, load_snapshot, notice, show_notices
from .read_age import read_age_context, refresh_requested
from .reservations import empty_text
from .workspace import ServerFamilyMixin

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseTable)
_LEASE_EXPORT_MAX_LEASES = 50_000


def _catalogue_notice(catalogue: CatalogueSnapshot) -> Notice:
    """Return the Notice of a Catalogue that could not resolve a Subnet search."""
    found = notice(catalogue)
    # The read returns a Catalogue only when it is unavailable or has diagnostics, so it always has a Notice.
    if found is None:
        raise TypeError("A Catalogue that could not resolve a Subnet search has no Notice.")
    return found


def fetch(server: Server, family: Family, search: LeaseSearch, *, refresh: bool = False) -> LeaseSnapshot | Notice:
    """Read the Lease Snapshot of *search* through the display cache, or the Notice of a failed read.

    A hit sends no Kea command. With *refresh* it reads Kea live and replaces the entry.

    Raises:
        LeaseQueryGuardError: If Kea cannot answer a Subnet query safely.
        ValueError: If the Server configuration or the search is not valid.

    """
    with LazyClient(server, family) as client:
        entry = load_snapshot(server, "lease", lambda: cached_read(server, family, search, client, refresh=refresh))
    if isinstance(entry, Notice):
        return entry
    if isinstance(entry.loaded, CatalogueSnapshot):
        return _catalogue_notice(entry.loaded)
    return entry.loaded


def _search_history(request: HttpRequest, response: HttpResponse, url: str) -> HttpResponse:
    """Replace automatic or unchanged searches; push user searches that change the URL."""
    current = urlsplit(_strip_empty_params(request.headers.get("HX-Current-URL", "")))
    target = urlsplit(url)
    unchanged = current.path == target.path and parse_qs(current.query, keep_blank_values=True) == parse_qs(
        target.query, keep_blank_values=True
    )
    if unchanged:
        # The same parameters in the reader's order: a reorder would change the URL of the current history entry.
        response["HX-Replace-Url"] = urlunsplit(("", "", current.path, current.query, ""))
        return response
    initial_search = request.headers.get("Kea-Initial-Search") == "true"
    response["HX-Replace-Url" if initial_search else "HX-Push-Url"] = url
    return response


def lease_sync_gates(user: Any) -> dict[AllocationKind, SyncGate]:
    """Apply the manual Sync rule to *user* for the claim of each Lease kind."""
    return {
        "address": sync_gate(user, claim_permissions(LEASE)),
        "delegated-prefix": sync_gate(user, claim_permissions(LEASE_PREFIX)),
    }


def _read_created_lease(request: HttpRequest, client: LazyClient, creation: LeaseRequest) -> Lease | None:
    """Read the Lease that Kea just created and check it against *creation*. It is a display read.

    Return ``None`` when the read fails, finds nothing, reads a malformed Lease or reads one that
    contradicts the request.
    """
    address = str(creation.address)
    try:
        result = client().lease_get(address_identity(creation.family, address))
    except (KeaException, requests.RequestException, RuntimeError, ValueError):
        logger.exception("Kea created lease %s, but the read back failed", address)
        return None
    if not isinstance(result, LeaseFound):
        logger.warning("Kea created lease %s, but the read back did not return it (%s)", address, result.outcome)
        return None
    mismatches = creation_mismatches(creation, result.lease)
    if mismatches:
        facts = fact_words(mismatches)
        logger.warning("Kea created lease %s, but the read back has another %s", address, facts)
        messages.warning(
            request, f"Lease {address} created, but the lease that Kea returned does not match the request ({facts})."
        )
        return None
    return result.lease


def _run_lease_sync_to_netbox(
    request: HttpRequest, server: Server, address: str, created: Lease | None, gate: SyncGate
) -> None:
    """Sync a just-created lease to NetBox IPAM from its fresh read back, when *gate* allows it.

    *gate* is the manual Sync rule of a lease claim; server-edit access alone is not enough. Only a Current Lease
    is claimed, also when the form supplied a Subnet. The sync uses ``force=False``, so a
    foreign (non-Kea-managed) NetBox IP is skipped rather than overwritten; that skip is
    reported as a warning instead of a misleading "synced" message. Queues a
    success/warning message; never raises.
    """
    if not gate.allowed:
        messages.warning(request, f"Lease created, but it was not synced to NetBox. {gate.reason}")
        return
    if created is None:
        messages.warning(request, "Lease created but NetBox IPAM sync failed; see server logs.")
        return
    if not is_current(created, datetime.now(tz=timezone.utc)):
        messages.warning(
            request, "Lease created, but it was not synced to NetBox: Kea did not report it as a current lease."
        )
        return
    try:
        result = claim(server, created.family, [created], force=False)
        outcome = next(iter(result.addresses.values())).outcome
        if outcome == "error":
            messages.error(request, "Lease created but NetBox IPAM sync failed; see server logs.")
        elif outcome == "disagreement":
            messages.warning(request, f"Lease created, but NetBox IPAM owners disagree about {address}.")
        elif outcome == "conflict":
            messages.warning(
                request,
                f"Lease created, but NetBox IPAM sync was skipped: {address} already exists and is not Kea-managed,"
                " or its note leaves no room for the new sync marker.",
            )
        else:
            nb_action = outcome if outcome in {"created", "updated"} else "already up to date"
            messages.success(request, f"IPAddress {address} {nb_action} in NetBox.")
    except event_scope.EventDispatchError:
        raise
    except (CatalogueUnavailable, RuntimeError, OSError, ValueError, DatabaseError, ValidationError):
        logger.exception("Failed to sync lease %s to NetBox", address)
        messages.error(request, "Lease created but NetBox IPAM sync failed; see server logs.")


def _add_lease_journal(
    server: "Server",
    user: Any,
    action: str,
    ip_addresses: "list[str] | str",
    hw_address: str = "",
    hostname: str = "",
    duid: str = "",
) -> None:
    """Create a JournalEntry on *server* recording a lease CRUD event.

    Args:
        server: The Server instance the journal entry is attached to.
        user: The request.user who performed the action.
        action: Human-readable action name: "added" or "deleted".
        ip_addresses: A single IP string or list of IPs affected.
        hw_address: Optional hardware address (for add events).
        hostname: Optional hostname (for add events).
        duid: Optional DUID (for DHCPv6 add events).

    Raises:
        DatabaseError: If the entry cannot be saved. The lease change in Kea is already done,
            so callers log the error and continue.

    """
    if isinstance(ip_addresses, str):
        ip_addresses = [ip_addresses]
    ip_list = ", ".join(ip_addresses)
    if len(ip_addresses) == 1:
        parts = [f"Lease {action}: {ip_list}"]
    else:
        parts = [f"{len(ip_addresses)} lease(s) {action}: {ip_list}"]
    if hw_address:
        parts.append(f"hw-address: {hw_address}")
    if duid:
        parts.append(f"duid: {duid}")
    if hostname:
        parts.append(f"hostname: {hostname}")
    JournalEntry.objects.create(
        assigned_object=server,
        created_by=user,
        kind="info",
        comments="; ".join(parts),
    )


def _journal_applied(request: HttpRequest, server: Server, action: str, ip_addresses: list[str], **facts: str) -> None:
    """Write the journal entry of an applied Lease change. A failure shows a separate error and keeps the change."""
    try:
        _add_lease_journal(server, request.user, action, ip_addresses, **facts)
    except DatabaseError:
        logger.exception("Failed to record the lease journal for server %s", server.pk)
        messages.error(
            request, "Kea applied the change, but NetBox could not write the journal entry; see server logs."
        )


def _signal_applied(request: HttpRequest, signal: Signal, name: str, **kwargs: Any) -> None:
    """Send *signal* after an applied Lease change. A receiver that fails shows a separate error."""
    responses = signal.send_robust(sender=None, request=request, **kwargs)
    errors = [response for _receiver, response in responses if isinstance(response, Exception)]
    for error in errors:
        logger.error("A receiver of the %s signal failed", name, exc_info=error)
    if errors:
        messages.error(request, f"Kea applied the change, but a receiver of the {name} signal failed; see server logs.")


def _incomplete_export_message(snapshot: LeaseSnapshot) -> str:
    """Return why a complete export of *snapshot* is refused."""
    reasons = diagnostic_reasons(snapshot.diagnostics)
    return (
        f"Export refused: Kea returned {len(snapshot.diagnostics)} lease record(s) that could not be read"
        f" ({reasons}). A complete export cannot leave them out."
    )


@dataclass(frozen=True)
class PresentedLeases:
    """The Lease table of one Snapshot for one user, with the actions that the user may take."""

    table: BaseTable
    can_delete: bool
    #: The Lease search page without empty parameters; the row actions return to it.
    return_url: str
    #: Kea does not know a Reservation command, so the page shows one notice and no row shows a Reservation badge.
    reservation_hook_unavailable: bool


def present(
    request: HttpRequest,
    server: Server,
    snapshot: LeaseSnapshot,
    table_class: type[T],
    *,
    visible_only: bool,
) -> PresentedLeases:
    """Build the Lease table of *snapshot* and fill its badge and action fields. It must run in the main thread.

    With *visible_only*, only the rows of the shown table page get badges, because each badge reads Kea. A badge read
    before *snapshot* is read again, so a badge is never older than the table, also after a Refresh.
    """
    rows = snapshot_rows(snapshot)
    # A state filter keeps the raw continuation, so a batch can hold no match while more Leases remain.
    batch_empty_text = empty_text(snapshot.query.state is not None, snapshot.next_cursor is not None)
    table = table_class(rows, user=request.user, empty_text=batch_empty_text)
    table.configure(request)
    if visible_only:
        rows = [row.record for row in table.paginated_rows]
    can_delete = request.user.has_perm("netbox_kea.bulk_delete_lease_from_server", obj=server)
    return_url = _strip_empty_params(request.get_full_path())
    reservation_hook_unavailable = _enrich_leases_with_badges(
        rows,
        server,
        snapshot.family,
        can_delete=can_delete,
        can_change=request.user.has_perm("netbox_kea.change_server", obj=server),
        user=request.user,
        sync=lease_sync_gates(request.user),
        return_url=return_url,
        read_since=snapshot.read_started,
    )
    if not can_delete:
        table.columns.hide("pk")
    return PresentedLeases(table, can_delete, return_url, reservation_hook_unavailable)


class BaseServerLeasesView(ServerFamilyMixin, generic.ObjectView, Generic[T]):
    """Generic base view for DHCP lease search tabs; specialised by IP version."""

    workspace_section = "leases"

    template_name = "netbox_kea/server_dhcp_leases.html"
    queryset = Server.objects.all()
    table: type[T]

    def get_table(self, data: list[dict[str, Any]], request: HttpRequest) -> T:
        """Build and configure the lease table for *request*."""
        table = self.table(data, user=request.user)
        table.configure(request)
        return table

    def _make_search_form(
        self, server: Server, data: Any | None = None, initial: dict[str, str] | None = None, *, refresh: bool = False
    ):
        """Build the lease-search form with the Subnet dropdown choices and their diagnostics.

        With *refresh* it reads the Subnet Catalogue live, so the Lease read and its badges that follow use it.
        """
        snapshot = subnet_catalogue.display(server, self.dhcp_version, refresh=refresh)
        return self.form(
            data,
            initial=initial,
            subnet_choices=snapshot.subnet_choices,
            subnet_cmds_available=snapshot.subnet_cmds_available,
            subnet_notice=notice(snapshot),
        )

    def get_extra_context(self, request: HttpRequest, instance: Server) -> dict[str, Any]:
        """Return an empty table, the search form, and the add-lease URL for the initial (non-HTMX) page load."""
        # For non-htmx requests.

        table = self.get_table([], request)
        bound = "q" in request.GET or "state" in request.GET
        # A link that names only the Attribute opens with its Search value control.
        form = self._make_search_form(
            instance, request.GET if bound else None, initial={"by": request.GET.get("by", "")}
        )
        can_change = Server.objects.restrict(request.user, "change").filter(pk=instance.pk).exists()
        ctx: dict[str, Any] = {
            "form": form,
            "table": table,
            "dhcp_version": self.dhcp_version,
        }
        if can_change:
            ctx["add_url"] = reverse(
                f"plugins:netbox_kea:server_lease{self.dhcp_version}_add",
                args=[instance.pk],
            )
            ctx["bulk_import_url"] = reverse(
                f"plugins:netbox_kea:server_lease{self.dhcp_version}_bulk_import",
                args=[instance.pk],
            )
        return ctx

    def get_export(self, request: HttpRequest, **kwargs) -> HttpResponse:
        """Stream all matching leases as a CSV download."""
        instance = self.get_object(**kwargs)
        form = self._make_search_form(instance, request.GET)
        if not form.is_valid():
            messages.warning(request, "Invalid form for export.")
            return redirect(request.path)

        by = form.cleaned_data["by"]
        if not by:
            messages.warning(request, "A search attribute is required to export.")
            return redirect(request.path)

        state_filter: LeaseState | None = form.cleaned_data.get("state")
        try:
            client = instance.get_client(version=self.dhcp_version)
        except ValueError as exc:
            messages.error(request, _client_settings_error(instance, exc))
            return redirect(request.path)
        try:
            # An export reads the Leases live.
            read = read_leases(
                client, instance, self.dhcp_version, LeaseSearch(by, form.cleaned_data["q"], state_filter)
            )
            if isinstance(read.loaded, CatalogueSnapshot):
                show_notices(request, _catalogue_notice(read.loaded))
                return redirect(request.path)
            snapshot = read.loaded
        except LeaseQueryGuardError as exc:
            messages.warning(request, lease_query_guard_message(exc, state_filter))
            return redirect(request.path)
        except KeaException as exc:
            logger.exception("Failed to fetch leases for export on server %s", instance.pk)
            messages.error(request, kea_error_hint(exc))
            return redirect(request.path)
        except (requests.RequestException, RuntimeError, ValueError):
            logger.exception("Transport/parse error fetching leases for export on server %s", instance.pk)
            messages.error(request, "Failed to fetch leases for export; see server logs.")
            return redirect(request.path)

        limited = request.GET["export"] == "table"
        if not limited and not snapshot.complete:
            messages.warning(request, _incomplete_export_message(snapshot))
            return redirect(request.path)
        if limited:
            table = present(request, instance, snapshot, self.table, visible_only=False).table
            return export_table(table, "leases_limited_coverage.csv", use_selected_columns=True)
        return lease_csv_response(
            snapshot.records,
            family=self.dhcp_version,
            evaluated_at=snapshot.evaluated_at,
            filename="leases.csv",
        )

    def get_export_all(self, request: HttpRequest, **kwargs) -> HttpResponse:
        """Export a bounded complete lease collection as a CSV download.

        Fetches leases through the Kea client up to the export safety limit.
        Refuses a partial export when the server has more leases than the limit.
        Requires the ``lease_cmds`` hook to be loaded on the Kea server.
        """
        instance = self.get_object(**kwargs)

        per_page = 1000

        try:
            client = instance.get_client(version=self.dhcp_version)
        except ValueError as exc:
            messages.error(request, _client_settings_error(instance, exc))
            return redirect(request.path)
        try:
            snapshot = client.lease_get_all(
                self.dhcp_version,
                per_page=per_page,
                max_leases=_LEASE_EXPORT_MAX_LEASES,
                server_id=instance.pk,
            )
        except KeaException as exc:
            logger.exception("Failed to fetch all leases for export on server %s", instance.pk)
            messages.error(request, kea_error_hint(exc))
            return redirect(request.path)
        except (requests.RequestException, ValueError, RuntimeError):
            logger.exception("Transport/parse error fetching all leases for export on server %s", instance.pk)
            messages.error(request, "Failed to fetch leases for export; see server logs.")
            return redirect(request.path)

        if snapshot.coverage != "exhaustive":
            logger.warning(
                "Refused a partial DHCPv%s lease export for server %s at the %s-lease limit",
                self.dhcp_version,
                instance.pk,
                _LEASE_EXPORT_MAX_LEASES,
            )
            messages.warning(
                request,
                f"Export is limited to {_LEASE_EXPORT_MAX_LEASES:,} leases. Narrow the lease set before exporting.",
            )
            return redirect(request.path)
        if not snapshot.complete:
            refusal = _incomplete_export_message(snapshot)
            logger.warning("Refused a DHCPv%s lease export for server %s: %s", self.dhcp_version, instance.pk, refusal)
            messages.warning(request, refusal)
            return redirect(request.path)

        return lease_csv_response(
            snapshot.records, family=self.dhcp_version, evaluated_at=snapshot.evaluated_at, filename="leases_all.csv"
        )

    def _search_without_table(
        self, request: HttpRequest, server: Server, form, lease_notice: Notice | None = None
    ) -> HttpResponse:
        """Render the search partial with the form and an empty table: a refused search or a failed read."""
        response = render(
            request,
            "netbox_kea/server_dhcp_leases_htmx.html",
            {
                "is_embedded": False,
                "object": server,
                "form": form,
                "table": self.get_table([], request),
                "paginate": False,
                "lease_notice": lease_notice,
            },
        )
        return _search_history(request, response, _strip_empty_params(request.get_full_path()))

    def _search_value_control(self, request: HttpRequest, server: Server) -> HttpResponse:
        """Render the Search value control of the Attribute that the user selected: a dropdown or a text input."""
        by = request.GET.get("by", "")
        q = request.GET.get("q", "")
        # An unbound form: a control that the user has not submitted shows no validation error.
        form = self._make_search_form(server, initial={"by": by, "q": q})
        if form.subnet_options and q not in dict(form.subnet_options):
            # The value belongs to the previous Attribute, so the dropdown starts empty.
            form = self.form(initial={"by": by}, subnet_choices=form.subnet_choices)
        return render(request, "netbox_kea/inc/lease_search_value.html", {"form": form})

    def get(self, request: HttpRequest, **kwargs) -> HttpResponse:
        """Dispatch to export, HTMX partial, or full page render as appropriate."""
        instance: Server = self.get_object(**kwargs)

        if "export" in request.GET:
            return self.get_export(request, **kwargs)

        if "export_all" in request.GET:
            return self.get_export_all(request, **kwargs)

        if not request.htmx:
            return super().get(request, **kwargs)

        if "value_control" in request.GET:
            return self._search_value_control(request, instance)

        refresh = refresh_requested(request)
        # Outside the try: the LeaseQueryGuardError handler below reads both `form` and
        # `form.cleaned_data`, so neither may depend on how far into the try we got.
        form = self._make_search_form(instance, request.GET, refresh=refresh)
        if not form.is_valid():
            return self._search_without_table(request, instance, form)

        try:
            by = form.cleaned_data["by"]
            # A search reads its whole scope and pages here; a read of every Lease reads one page from Kea.
            search = LeaseSearch(
                by,
                form.cleaned_data["q"],
                form.cleaned_data.get("state"),
                cursor=None if by else form.cleaned_data["page"] or None,
                per_page=get_paginate_count(request),
            )
            loaded = fetch(instance, self.dhcp_version, search, refresh=refresh)
            if isinstance(loaded, Notice):
                return self._search_without_table(request, instance, form, loaded)
            snapshot = loaded
            presented = present(request, instance, snapshot, self.table, visible_only=by != "")
            table = presented.table
            if by == "":
                next_page = None if snapshot.next_cursor is None else str(snapshot.next_cursor)
            else:
                next_page = table.page.next_page_number() if table.page.has_next() else None

            response = render(
                request,
                "netbox_kea/server_dhcp_leases_htmx.html",
                {
                    **read_age_context(snapshot.read_started),
                    "can_delete": presented.can_delete,
                    "is_embedded": False,
                    "object": instance,
                    "delete_action": (
                        reverse(
                            f"plugins:netbox_kea:server_leases{self.dhcp_version}_delete",
                            args=[instance.pk],
                        )
                        + "?"
                        + _urlencode({"return_url": presented.return_url})
                    ),
                    "return_url": presented.return_url,
                    "form": form,
                    "table": table,
                    "next_page": next_page,
                    "lease_notice": notice(snapshot),
                    "reservation_hook_unavailable": presented.reservation_hook_unavailable,
                    "paginate": True,
                    "page_lengths": EnhancedPaginator.default_page_lengths,
                },
            )
            _search_history(request, response, presented.return_url)
        except LeaseQueryGuardError as exc:
            logger.info("Rejected unsafe Subnet lease query on server %s: %s", instance.pk, exc)
            field = "q" if isinstance(exc, LeaseQueryUnknownSubnet) else "state"
            form.add_error(field, lease_query_guard_message(exc, form.cleaned_data.get("state")))
            return self._search_without_table(request, instance, form)
        # A Kea, transport or malformed-reply failure of the read is a Notice above; this is a request error.
        except ValueError:
            error_id = str(uuid.uuid4())
            logger.exception("HTMX leases handler error [%s]", error_id)
            return render(
                request,
                "netbox_kea/exception_htmx.html",
                {"error_id": error_id, "section_id": "lease-search"},
            )
        else:
            return response


# Single consolidated "Leases" tab shared by the v4 and v6 leases views. Only
# ServerLeases4View carries it as a class attribute (so exactly one tab entry is
# generated); ServerLeases6View injects it via get_extra_context so the same tab
# stays highlighted when viewing v6. An in-page v4/v6 toggle (template) switches
# between the two underlying URLs, which are unchanged.
_LEASES_TAB = OptionalViewTab(label="Leases", weight=1010, is_enabled=lambda s: s.dhcp4 or s.dhcp6)


@register_model_view(Server, "leases6")
class ServerLeases6View(BaseServerLeasesView[tables.LeaseTable6]):
    """DHCPv6 leases view (rendered under the shared Leases tab)."""

    form = forms.Leases6SearchForm
    table = tables.LeaseTable6
    dhcp_version = 6

    def get_extra_context(self, request: HttpRequest, instance: Server) -> dict[str, Any]:
        """Highlight the shared Leases tab (this view has no class-level tab of its own)."""
        ctx = super().get_extra_context(request, instance)
        ctx["tab"] = _LEASES_TAB
        return ctx


@register_model_view(Server, "leases4")
class ServerLeases4View(BaseServerLeasesView[tables.LeaseTable4]):
    """DHCPv4 leases view; owns the shared Leases tab."""

    tab = _LEASES_TAB
    form = forms.Leases4SearchForm
    table = tables.LeaseTable4
    dhcp_version = 4


class FakeLeaseModelMeta:
    """Minimal ``_meta`` shim so bulk_delete.html can introspect the lease pseudo-model."""

    app_label = "netbox_kea"
    model_name = "lease"
    verbose_name_plural = "leases"


# Fake model to allow us to use the bulk_delete.html template.
class FakeLeaseModel:
    """Pseudo-model used to satisfy the bulk_delete.html template contract without a real DB model."""

    _meta = FakeLeaseModelMeta


class BaseServerLeasesDeleteView(ServerFamilyMixin, GetReturnURLMixin, generic.ObjectView, metaclass=ABCMeta):
    """Base view for confirming and processing bulk deletion of DHCP leases."""

    workspace_section = "leases"

    queryset = Server.objects.all()
    default_return_url = "plugins:netbox_kea:server_list"

    def disabled_family_access(self, request: HttpRequest, server: Server) -> HttpResponse | None:
        """Preserve the Lease deletion permission on a disabled family."""
        if not request.user.has_perm("netbox_kea.bulk_delete_lease_from_server", obj=server):
            return HttpResponseForbidden("This user does not have permission to delete DHCP leases.")
        return None

    def get(self, request: HttpRequest, **kwargs):
        """Redirect back to the server on GET (this view is POST-only)."""
        return redirect(self.get_return_url(request, obj=self.get_object(**kwargs)))

    def post(self, request: HttpRequest, **kwargs) -> HttpResponse:
        """Show confirmation page or delete leases if confirmed."""
        instance: Server = self.get_object(**kwargs)

        if refusal := self.disabled_family_access(request, instance):
            return refusal

        form = self.form(request.POST)

        return_url = _strip_empty_params(self.get_return_url(request, obj=instance))
        if not form.is_valid():
            messages.warning(request, str(form.errors))
            return _after_lease_delete(request, return_url)

        selected: tuple[ShownLease, ...] = form.cleaned_data["pk"]
        if "_confirm" not in request.POST:
            return render(
                request,
                "netbox_kea/server_lease_bulk_delete.html",
                {
                    "object": instance,
                    "model": FakeLeaseModel,
                    "table": tables.LeaseDeleteTable([_shown_row(shown) for shown in selected], orderable=False),
                    "form": form,
                    "return_url": return_url,
                },
            )

        loop = _run_change_loop(selected, lambda shown: runtime_change.delete_lease(instance, self.dhcp_version, shown))
        for shown, message in loop.rejected:
            messages.error(request, f"Lease {shown.label}: {message}")
        deleted = [outcome.lease for _shown, outcome in loop.applied]
        if deleted:
            labels = [shown_lease(lease).label for lease in deleted]
            messages.success(request, f"Deleted {len(deleted)} DHCPv{self.dhcp_version} lease(s): {', '.join(labels)}.")
            _journal_applied(request, instance, "deleted", labels)
            _signal_applied(
                request,
                leases_deleted,
                "leases_deleted",
                server=instance,
                leases=tuple(deleted),
                dhcp_version=self.dhcp_version,
            )
        if loop.unknown is not None:
            shown, message = loop.unknown
            messages.warning(request, f"Lease {shown.label}: {message}")
        if loop.not_sent:
            not_sent = ", ".join(shown.label for shown in loop.not_sent)
            messages.warning(
                request,
                f"NetBox stopped at the unconfirmed lease and did not send the delete of {len(loop.not_sent)}"
                f" lease(s): {not_sent}.",
            )
        return _after_lease_delete(request, return_url)


def _after_lease_delete(request: HttpRequest, return_url: str) -> HttpResponse:
    """Show the queued messages: reload the page for the one-click row button, else redirect to *return_url*."""
    if request.headers.get("HX-Request"):
        response = HttpResponse()
        response["HX-Refresh"] = "true"
        return response
    return redirect(return_url)


class ServerLeases6DeleteView(BaseServerLeasesDeleteView):
    """Bulk-delete view for DHCPv6 leases."""

    form = forms.Lease6DeleteForm
    dhcp_version = 6
    tab = _LEASES_TAB


class ServerLeases4DeleteView(BaseServerLeasesDeleteView):
    """Bulk-delete view for DHCPv4 leases."""

    form = forms.Lease4DeleteForm
    dhcp_version = 4
    tab = _LEASES_TAB


_KIND_LABELS = {"address": "Address", "delegated-prefix": "Delegated prefix"}


def _binding_text(binding: DHCPv4Binding | DHCPv6Binding) -> str:
    if isinstance(binding, DHCPv6Binding):
        return f"DUID {binding.duid or '(empty)'}, IAID {binding.iaid}"
    parts = [
        f"{name} {value}" for name, value in (("MAC", binding.hw_address), ("client ID", binding.client_id)) if value
    ]
    return ", ".join(parts) or "(none)"


def _shown_row(shown: ShownLease) -> dict[str, Any]:
    """Return the confirmation row of one selected Lease: the facts that its delete compares."""
    return {
        "lease": shown.label,
        "kind": _KIND_LABELS[shown.identity.kind],
        "binding": _binding_text(shown.binding),
        "subnet_id": shown.subnet_id,
    }


class _BaseLeaseEditView(_KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Base view for editing a single Lease via ``lease{v}-update``.

    The route target is the address, or ``address/length`` for a delegated prefix. The page carries the
    shown Lease facts, and the save writes only the fields that differ from them.
    Subclasses must set ``dhcp_version`` and ``form_class``.
    """

    workspace_section = "leases"

    dhcp_version: Family
    form_class: type[forms._LeaseEditForm]

    def _get_server(self, pk: int) -> Server:
        return get_object_or_404(Server.objects.restrict(self.request.user, "view"), pk=pk)

    def _leases_url(self, server: Server) -> str:
        """Return the lease search that linked here, else the lease list."""
        return _safe_return_url(
            self.request, reverse(f"plugins:netbox_kea:server_leases{self.dhcp_version}", kwargs={"pk": server.pk})
        )

    def _render(self, request: HttpRequest, server: Server, form: forms._LeaseEditForm, shown: ShownLease):
        return render(
            request,
            "netbox_kea/server_lease_edit.html",
            {
                "object": server,
                "server": server,
                "lease_label": shown.label,
                "lease_kind": _KIND_LABELS[shown.identity.kind],
                "form": form,
                "dhcp_version": self.dhcp_version,
                "cancel_url": self._leases_url(server),
                "tab": self.tab,
            },
        )

    def get(self, request: HttpRequest, pk: int, ip_address: str) -> HttpResponse:
        """Render the edit form pre-filled with the current lease values and the shown facts."""
        server = self._get_server(pk)

        try:
            client = server.get_client(version=self.dhcp_version)
        except ValueError as exc:
            messages.error(request, _client_settings_error(server, exc))
            return redirect(self._leases_url(server))
        try:
            label, identity = parse_selection(self.dhcp_version, ip_address)
            result = client.lease_get(identity)
        except KeaException as exc:
            logger.exception("Failed to fetch lease %s on server %s", ip_address, pk)
            messages.error(request, kea_error_hint(exc))
            return redirect(self._leases_url(server))
        except (requests.RequestException, RuntimeError, ValueError):
            logger.exception("Failed to fetch lease %s on server %s", ip_address, pk)
            messages.error(request, "Failed to fetch lease: see server logs for details.")
            return redirect(self._leases_url(server))

        if isinstance(result, LeaseAbsent):
            messages.warning(request, f"Lease {label} not found.")
            return redirect(self._leases_url(server))
        if not isinstance(result, LeaseFound):
            logger.warning("Kea returned a malformed lease %s on server %s", label, pk)
            messages.error(request, "Kea returned a lease that could not be read; it cannot be edited.")
            return redirect(self._leases_url(server))
        lease = result.lease
        shown = shown_lease(lease)
        if shown.label != label:
            messages.warning(request, f"Kea now delegates {shown.label}, not {label}. Reload the lease list.")
            return redirect(self._leases_url(server))
        identifier = lease.hw_address if isinstance(lease, DHCPv4AddressLease) else lease.duid
        initial: dict[str, Any] = {
            "shown": shown.model_dump_json(),
            "hostname": lease.hostname,
            "valid_lft": lease.valid_lifetime,
            self.form_class.identifier_field: identifier or "",
        }
        return self._render(request, server, self.form_class(initial=initial), shown)

    def post(self, request: HttpRequest, pk: int, ip_address: str) -> HttpResponse:
        """Write the changed fields via ``lease{v}-update`` after a fresh read agrees with the shown facts."""
        server = self._get_server(pk)

        form = self.form_class(request.POST)
        valid = form.is_valid()
        shown: ShownLease | None = form.cleaned_data.get("shown")
        try:
            label, identity = parse_selection(self.dhcp_version, ip_address)
        except ValueError:
            label, identity = ip_address, None
        if shown is None or shown.identity != identity or shown.label != label:
            messages.error(request, "The form does not hold the shown facts of this lease. Reload the lease list.")
            return redirect(self._leases_url(server))
        if not valid:
            return self._render(request, server, form, shown)
        edit: LeaseEdit = form.cleaned_data["edit"]
        if not edit.written:
            messages.info(request, f"Lease {label} was not changed: the form holds the shown values.")
            return redirect(self._leases_url(server))
        _run_change(
            request,
            f"Lease {label} updated.",
            lambda: runtime_change.edit_lease(server, self.dhcp_version, shown, edit),
            subject=f"Lease {label}",
        )
        return redirect(self._leases_url(server))


@register_model_view(Server, "lease4_edit", path="leases4/<path:ip_address>/edit")
class ServerLease4EditView(_BaseLeaseEditView):
    """Edit a single DHCPv4 lease."""

    dhcp_version = 4
    form_class = forms.Lease4EditForm
    tab = _LEASES_TAB


@register_model_view(Server, "lease6_edit", path="leases6/<path:ip_address>/edit")
class ServerLease6EditView(_BaseLeaseEditView):
    """Edit a single DHCPv6 lease or delegated prefix."""

    dhcp_version = 6
    form_class = forms.Lease6EditForm
    tab = _LEASES_TAB


class _BaseLeaseAddView(_KeaChangeMixin, ServerFamilyMixin, generic.ObjectView):
    """Base view for creating a new lease via ``lease{v}-add``."""

    workspace_section = "leases"

    queryset = Server.objects.all()
    template_name = "netbox_kea/server_lease_add.html"
    dhcp_version: Family
    form_class: type[forms._LeaseAddForm]
    # Use _active_tab (not `tab`) so model_view_tabs does not register this as a
    # duplicate navigation entry — the add view URL resolves with pk-only, which
    # would cause the parent list tab to appear twice in the tab bar.
    _active_tab: OptionalViewTab

    def _leases_url(self, server: Server) -> str:
        return reverse(f"plugins:netbox_kea:server_leases{self.dhcp_version}", args=[server.pk])

    def _form(self, server: Server, gate: SyncGate, data: QueryDict | None = None) -> forms._LeaseAddForm:
        """Build the form with the user's manual Sync rule and the Server's automatic IPAM sync."""
        return self.form_class(
            data,
            sync_refusal=gate.reason,
            automatic_sync=server.sync_enabled and server.sync_leases_enabled,
        )

    def _render(self, request: HttpRequest, server: Server, form: forms._LeaseAddForm) -> HttpResponse:
        return render(
            request,
            self.template_name,
            {
                "object": server,
                "form": form,
                "dhcp_version": self.dhcp_version,
                "cancel_url": self._leases_url(server),
                "tab": self._active_tab,
            },
        )

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the empty add form."""
        server = self.get_object(pk=pk)

        return self._render(request, server, self._form(server, sync_gate(request.user, claim_permissions(LEASE))))

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Create the Lease of the typed request, read it back, and report both outcomes."""
        server = self.get_object(pk=pk)

        gate = sync_gate(request.user, claim_permissions(LEASE))
        form = self._form(server, gate, request.POST)
        if not form.is_valid():
            return self._render(request, server, form)
        creation: LeaseRequest = form.cleaned_data["request"]
        address = str(creation.address)
        outcome = _run_change(
            request,
            f"Lease for {address} created.",
            lambda: runtime_change.add_lease(server, self.dhcp_version, creation),
            subject=f"Lease {address}",
        )
        if outcome is None:
            return self._render(request, server, form)
        if outcome.application == "applied":
            self._after_creation(request, server, creation, gate, sync=form.cleaned_data["sync_to_netbox"])
        return redirect(self._leases_url(server))

    def _after_creation(
        self, request: HttpRequest, server: Server, creation: LeaseRequest, gate: SyncGate, *, sync: bool
    ) -> None:
        """Run the side effects of an applied creation: the display read, the journal, the signal and the sync."""
        address = str(creation.address)
        with LazyClient(server, self.dhcp_version) as client:
            created = _read_created_lease(request, client, creation)
        _journal_applied(
            request,
            server,
            "added",
            [address],
            hw_address=creation.hw_address if isinstance(creation, DHCPv4LeaseRequest) else "",
            hostname=creation.hostname or "",
            duid=creation.duid if isinstance(creation, DHCPv6LeaseRequest) else "",
        )
        _signal_applied(
            request,
            lease_added,
            "lease_added",
            server=server,
            creation=creation,
            lease=created,
            dhcp_version=self.dhcp_version,
        )
        if sync:
            _run_lease_sync_to_netbox(request, server, address, created, gate)


@register_model_view(Server, "lease4_add", path="leases4/add")
class ServerLease4AddView(_BaseLeaseAddView):
    """Create a new DHCPv4 lease."""

    dhcp_version = 4
    form_class = forms.Lease4AddForm
    _active_tab = _LEASES_TAB


@register_model_view(Server, "lease6_add", path="leases6/add")
class ServerLease6AddView(_BaseLeaseAddView):
    """Create a new DHCPv6 lease."""

    dhcp_version = 6
    form_class = forms.Lease6AddForm
    _active_tab = _LEASES_TAB


def _canonical_reservation_url(server_pk: int, reservation: Reservation, return_url: str) -> str | None:
    if isinstance(reservation.scope, GlobalReservationScope):
        return None
    params = {"identifier_type": reservation.identity.identifier_type, "identifier": reservation.identity.value}
    query = _urlencode({**params, "return_url": return_url} if return_url else params)
    base = reverse(
        f"plugins:netbox_kea:server_reservation{reservation.family}_edit",
        args=[server_pk, reservation.scope.subnet.subnet_id],
    )
    return f"{base}?{query}"


_NO_RESERVATION_FIELDS: dict[str, Any] = {
    "is_reserved": False,
    "host_reservation": False,
    "reservation_url": None,
    "create_reservation_url": None,
    "pending_ip_change": False,
    "pending_reservation_ip": "",
    "other_kind_reservation": False,
    "stale_mac": False,
    "stale_lease_mac": "",
    "reservation_mac": "",
    "delete_lease_url": "",
    "can_change_reservation": False,
    "reservation_unknown_reason": "",
    "reservation_ignored_reason": "",
}

#: The title of the Reservation Unknown badge when the lookups of the whole table failed.
_LOOKUPS_FAILED_REASON = "The Reservation lookups failed."


def _unknown_badge_title(reason: UnknownReservationMatch) -> str:
    """Return the title of the Reservation Unknown badge, or an empty string for the reason that the page shows."""
    match reason:
        case UnknownReservationMatch.UNVERIFIED_SUBNET:
            return "The Subnet Catalogue does not verify the Subnet of this lease, so no Reservation lookup can run."
        case UnknownReservationMatch.KEA_ERROR:
            return "Kea returned an error for a Reservation lookup, or did not answer it."
        case UnknownReservationMatch.MALFORMED_REPLY:
            return "Kea returned a Reservation lookup reply that cannot be read."
        case UnknownReservationMatch.INVALID_READ:
            return "The Server settings are not valid, or Kea returned a Reservation that does not parse or fit the lookup."
        case UnknownReservationMatch.FOREIGN_IDENTIFIER:
            return "No Reservation matched, and this lease carries a client identifier that no Reservation can hold."
        case UnknownReservationMatch.UNKNOWN_SHARED_NETWORK:
            return (
                "Kea can give this client an allocation of another Subnet in the Shared Network,"
                " and the configuration does not show whether it does."
            )
        case UnknownReservationMatch.RESERVATION_FLAGS_UNKNOWN:
            return (
                "The configuration does not show the reservation flags of this Subnet,"
                " so it is not known whether Kea applies this Reservation."
            )
        case UnknownReservationMatch.POOLS_UNKNOWN:
            return (
                "The configuration does not show the Pools of this Subnet,"
                " and reservations-out-of-pool decides whether Kea gives the reserved address or prefix."
            )
        # The page shows one notice for the whole table.
        case UnknownReservationMatch.RESERVATION_HOOK_UNAVAILABLE:
            return ""
        case _:
            assert_never(reason)


def _ignored_badge_title(reason: IgnoredReservationReason) -> str:
    """Return the title of the Reservation Ignored badge: the flag of the Subnet that makes Kea ignore it."""
    match reason:
        case IgnoredReservationReason.GLOBAL_RESERVATIONS_DISABLED:
            return (
                "This Subnet does not apply Global Reservations (reservations-global is false),"
                " so Kea ignores this Reservation."
            )
        case IgnoredReservationReason.IN_SUBNET_RESERVATIONS_DISABLED:
            return (
                "This Subnet does not apply its own Reservations (reservations-in-subnet is false),"
                " so Kea ignores this Reservation."
            )
        case IgnoredReservationReason.OUT_OF_POOL:
            return (
                "This Subnet sets reservations-out-of-pool, and the reserved address is inside a Pool,"
                " so Kea does not give it and assigns this lease from the pool."
            )
        case _:
            assert_never(reason)


def _create_reservation_url(
    row: dict[str, Any], subnet: VerifiedSubnet, server_pk: int, version: Family, return_url: str
) -> str:
    """Return the Reservation add form, prefilled from the Lease of *row* in its Subnet."""
    observed = row["lease"]
    is_prefix = isinstance(observed, DHCPv6PrefixLease)
    allocation_field = "prefixes" if is_prefix else "ip_addresses" if version == 6 else "ip_address"
    params = {
        "subnet_cidr": subnet.cidr,
        allocation_field: row["label"],
        "hostname": lease_published_name(observed.hostname),
        "return_url": return_url,
    }
    identities = lease_identities(observed).identities
    if identities:
        params["identifier_type"] = identities[0].identifier_type
        params["identifier"] = identities[0].value
    base = reverse(f"plugins:netbox_kea:server_reservation{version}_add", args=[server_pk])
    return f"{base}?{_urlencode({key: value for key, value in params.items() if value})}"


def _link_reservation(
    row: dict[str, Any], reservation: Reservation, server_pk: int, can_change: bool, return_url: str
) -> None:
    """Link the Reservation of one Lease row; a Global Reservation has no edit form, so it has no link."""
    row["reservation_url"] = _canonical_reservation_url(server_pk, reservation, return_url)
    row["can_change_reservation"] = can_change and row["reservation_url"] is not None


def _set_reservation_fields(
    row: dict[str, Any],
    match: ReservationMatch,
    server_pk: int,
    version: Family,
    can_change: bool,
    return_url: str,
) -> bool:
    """Set the Reservation fields of one Lease row from its Reservation Match, and return whether it may offer Sync.

    Unknown shows its reason and no action.
    """
    row.update(_NO_RESERVATION_FIELDS)
    match match:
        case ReservationMatchUnknown(reason=reason):
            row["reservation_unknown_reason"] = _unknown_badge_title(reason)
            return False
        case Unreserved(subnet=subnet):
            if can_change:
                row["create_reservation_url"] = _create_reservation_url(row, subnet, server_pk, version, return_url)
            return True
        case Reserved(reservation=reservation):
            _link_reservation(row, reservation, server_pk, can_change, return_url)
            row["is_reserved"] = True
            return True
        case StaleMac(reservation=reservation, lease_mac=lease_mac):
            _link_reservation(row, reservation, server_pk, can_change, return_url)
            row["is_reserved"] = True
            row["stale_mac"] = True
            row["stale_lease_mac"] = lease_mac
            row["reservation_mac"] = reservation.identity.value
            row["delete_lease_url"] = reverse(f"plugins:netbox_kea:server_leases{version}_delete", args=[server_pk])
            return False
        case PendingAddressChange(reservation=reservation, reserved=reserved):
            _link_reservation(row, reservation, server_pk, can_change, return_url)
            row["pending_ip_change"] = True
            row["pending_reservation_ip"] = ", ".join(str(item) for item in reserved)
            return False
        case HostOnlyReservation(reservation=reservation):
            _link_reservation(row, reservation, server_pk, can_change, return_url)
            row["host_reservation"] = True
            return True
        case OtherKindReservation(reservation=reservation):
            _link_reservation(row, reservation, server_pk, can_change, return_url)
            row["other_kind_reservation"] = True
            return True
        # Kea does not apply the Reservation, so the Lease is dynamic and a Sync cannot contradict it.
        case IgnoredReservation(reservation=reservation, reason=reason):
            _link_reservation(row, reservation, server_pk, can_change, return_url)
            row["reservation_ignored_reason"] = _ignored_badge_title(reason)
            return True
        case _:
            assert_never(match)


LeaseSyncCode = Literal["synchronized", "not-synchronized", "unmarked", "not-in-netbox", "unknown"]

#: The Lease Synchronization State terms of CONTEXT.md, which the table export writes.
_LEASE_SYNC_LABELS: dict[LeaseSyncCode, str] = {
    "synchronized": "Synchronized",
    "not-synchronized": "Not Synchronized",
    "unmarked": "Unmarked",
    "not-in-netbox": "Not in NetBox",
    "unknown": "Unknown",
}
_SYNC_STATES: frozenset[LeaseSyncCode] = frozenset({"not-synchronized", "unmarked", "not-in-netbox"})


@dataclass(frozen=True)
class LeaseSynchronizationState:
    """The Lease Synchronization State of one Current Lease, with the reason of an Unknown state."""

    code: LeaseSyncCode
    reason: str = ""

    @property
    def label(self) -> str:
        """Return the term of CONTEXT.md for the state."""
        return _LEASE_SYNC_LABELS[self.code]


def _ownership_key(observed: Lease) -> str:
    """Return the key of the ownership read of a Lease: its delegated prefix, or its address."""
    return str(observed.prefix) if isinstance(observed, DHCPv6PrefixLease) else str(observed.identity.address)


def _read_ownership(server: "Server", version: Family, leases: list[Lease], user: Any) -> dict[str, Ownership] | None:
    """Read the IPAM Ownership of the object of each Lease, by its lease source; ``None`` when the read fails."""
    addresses = [_ownership_key(lease) for lease in leases if not isinstance(lease, DHCPv6PrefixLease)]
    prefixes = [_ownership_key(lease) for lease in leases if isinstance(lease, DHCPv6PrefixLease)]
    try:
        return {
            **address_ownership(server, version, LEASE, addresses, user),
            **prefix_ownership(server, version, LEASE_PREFIX, prefixes, user),
        }
    except DatabaseError:
        logger.exception("Could not read NetBox IPAM state for Lease badges")
        return None


def _lease_badge(observed: Lease, current: bool, ownership: Mapping[str, Ownership] | None) -> dict[str, Any]:
    """Return the ``sync_state``, ``netbox_url`` and ``sync_title`` of a Lease row.

    A Lease that is not current has no state, only the link of an object that the user may view. *ownership* is the
    read of :func:`_read_ownership`; ``None`` means that it failed.
    """
    noun = "Prefix" if isinstance(observed, DHCPv6PrefixLease) else "IP address"
    found = ownership[_ownership_key(observed)] if ownership is not None else None
    url = found.obj.get_absolute_url() if found is not None and found.obj is not None else None
    state: LeaseSynchronizationState | None
    if not current:
        state = None
    elif found is None:
        state = LeaseSynchronizationState("unknown", IPAM_UNREADABLE)
    elif found.state == "hidden":
        state = LeaseSynchronizationState("unknown", f"You may not view the {noun} of this lease in NetBox.")
    else:
        state = LeaseSynchronizationState(found.state)
    title = sync_title(found.state, noun) if current and found is not None else ""
    return {"sync_state": state, "netbox_url": url, "sync_title": title}


def _enrich_leases_with_badges(
    leases: list[dict[str, Any]],
    server: "Server",
    version: Family,
    can_delete: bool = False,
    can_change: bool = False,
    *,
    user: Any,
    sync: Mapping[AllocationKind, SyncGate],
    return_url: str,
    read_since: datetime,
) -> bool:
    """In-place: add reservation and NetBox IPAM badge fields to lease dicts, and return whether Kea lacks host_cmds.

    Adds:
    - ``reservation_url``: reservation link if a reservation exists for this IP
    - ``can_change_reservation``: whether the user may edit the reservation (gates link vs plain badge)
    - ``host_reservation``: the matched Reservation holds no address and no delegated prefix for the Lease's Subnet
    - ``create_reservation_url``: pre-filled add link if host_cmds is loaded
    - ``sync_state``: the Lease Synchronization State of a Current Lease, ``None`` for another Lease
    - ``netbox_url``: the IP address or Prefix of the Lease in the sync VRF, when *user* may view it
    - ``sync_title``: what a Sync does to an object that the Server does not own
    - ``sync_url``: POST endpoint URL to claim a Current Lease whose state, Reservation Match and gate allow it
    - ``sync_refusal``: the reason when the gate of its kind refuses the user
    - ``can_delete``: whether the current user may delete this lease
    - ``can_change``: whether the current user may edit this lease (gates edit_url)
    - ``reservation_unknown_reason``: the title of the Reservation Unknown badge when the match is Unknown
    - ``reservation_ignored_reason``: the title of the Reservation Ignored badge when Kea ignores the Reservation

    *return_url* is the lease search page; the lease and Reservation edit forms return to it. Each Reservation lookup
    read before *read_since*, the read time of the Lease table, is read again.
    """
    try:
        matches = reservation_matches(server, version, [row["lease"] for row in leases], read_since=read_since)
    except Exception as exc:
        logger.warning("unexpected error during lease enrichment: %s", exc, exc_info=True)
        # An unexpected failure shows each row as Unknown, so "could not check" never looks like "not reserved".
        for row in leases:
            row.update(_NO_RESERVATION_FIELDS, reservation_unknown_reason=_LOOKUPS_FAILED_REASON)
        offers_sync = [False] * len(leases)
        hook_unavailable = False
    else:
        hook_unavailable = ReservationMatchUnknown(UnknownReservationMatch.RESERVATION_HOOK_UNAVAILABLE) in matches
        offers_sync = [
            _set_reservation_fields(row, match, server.pk, version, can_change, return_url)
            for row, match in zip(leases, matches, strict=True)
        ]

    sync_url = reverse(f"plugins:netbox_kea:server_lease{version}_sync", args=[server.pk])
    edit_url_name = f"plugins:netbox_kea:server_lease{version}_edit"
    edit_query = f"?{_urlencode({'return_url': return_url})}" if return_url else ""
    ownership = _read_ownership(server, version, [lease["lease"] for lease in leases], user)
    for lease, sync_allowed in zip(leases, offers_sync, strict=True):
        observed = lease["lease"]
        lease.update(_lease_badge(observed, lease["current"], ownership))
        state = lease["sync_state"]
        # Sync needs a Current Lease that the Server does not own and a Reservation Match that a Sync cannot contradict.
        if state is not None and state.code in _SYNC_STATES and sync_allowed:
            gate = sync[observed.kind]
            if gate.allowed:
                lease["sync_url"] = sync_url
            else:
                lease["sync_refusal"] = gate.reason
        if can_change:
            lease["edit_url"] = reverse(edit_url_name, args=[server.pk, lease["label"]]) + edit_query
        lease["can_delete"] = can_delete
        lease["can_change"] = can_change
    return hook_unavailable
