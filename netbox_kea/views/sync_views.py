# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import csv
import ipaddress
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, cast

import requests
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from django.http import Http404, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.http.request import HttpRequest
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import View

from .. import config_write, event_scope, forms, runtime_change, subnet_catalogue
from ..constants import Family
from ..ipam_reconciliation import (
    RESERVATION,
    ReservationPhase,
    address_ownership,
    claim_permissions,
    reconcile,
    reconcile_permissions,
)
from ..kea import KeaClient, KeaException, kea_error_message
from ..leases import (
    ExactLeaseResult,
    LeaseFound,
    LeaseIdentity,
    LeaseLookupFailed,
    LeaseRequest,
    is_current,
    parse_selection,
    shown_lease,
)
from ..models import Server
from ..reservation_transfer import (
    ReservationImportProposal,
    ReservationTransferDiagnostic,
    ReservationTransferError,
    parse_reservation_document,
    resolve_import_proposal,
)
from ..signals import lease_added
from ..subnet_catalogue import CatalogueUnavailable, for_synchronization
from ..sync_permissions import sync_gate
from ..utilities import (
    LeaseCSVError,
    parse_lease_csv,
)
from ._base import (
    ChangeLoop,
    ConditionalLoginRequiredMixin,
    OutcomeT,
    RowT,
    _client_settings_error,
    _journal_applied,
    _KeaChangeMixin,
    _persistence_failure,
    _run_change_loop,
    _signal_applied,
)
from .leases import _LEASES_TAB, _lease_journal_comments, lease_sync_gates
from .reservation_mutations import (
    _VERIFICATION_FAILED,
    _identity_from_request,
    _identity_label,
    _live_target,
    _record_applied,
)
from .reservations import _RESERVATIONS_TAB, _live_capabilities, reservation_badge
from .workspace import ServerFamilyMixin

logger = logging.getLogger(__name__)


def _row_error(request: HttpRequest, message: str) -> HttpResponse:
    """Return *message* as the error badge that replaces the row button which posted *request*."""
    # A 200 reply: htmx swaps no error reply, and NetBox's DEBUG htmx script replaces the page with a 4xx/5xx one.
    return render(request, "netbox_kea/inc/row_action_error.html", {"message": message})


class _BaseSyncView(ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Claim one fresh Current Lease: an address as an IP Address, a delegated prefix as a Prefix."""

    workspace_section = "leases"

    dhcp_version: Family

    def server_scope_access(self, request: HttpRequest) -> HttpResponse | None:
        """Preserve the manual claim permission of the selected Lease allocation kind."""
        try:
            _, identity = parse_selection(self.dhcp_version, request.POST.get("ip_address", "").strip())
        except ValueError:
            return None
        gate = lease_sync_gates(request.user)[identity.kind]
        return None if gate.allowed else _row_error(request, gate.reason)

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        selected = request.POST.get("ip_address", "").strip()
        if not selected:
            return _row_error(request, "ip_address is required")
        try:
            label, identity = parse_selection(self.dhcp_version, selected)
        except ValueError:
            return _row_error(request, "Invalid lease address or delegated prefix")

        gate = lease_sync_gates(request.user)[identity.kind]
        if not gate.allowed:
            return _row_error(request, gate.reason)

        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        try:
            client = server.get_client(version=self.dhcp_version)
        except ValueError as exc:
            return _row_error(request, _client_settings_error(server, exc))

        observed = self._fetch_live_data(client, identity)
        if isinstance(observed, LeaseLookupFailed):
            logger.warning("Kea returned a malformed lease%s for %s", self.dhcp_version, label)
            return _row_error(request, "Sync error: see server logs for details.")
        if not isinstance(observed, LeaseFound):
            return _row_error(request, "Could not fetch live data from Kea.")
        lease = observed.lease
        # The label holds the kind and the prefix length, so a changed allocation does not match.
        if shown_lease(lease).label != label:
            return _row_error(request, "The lease changed in Kea. Reload the lease list.")
        if not is_current(lease, datetime.now(tz=timezone.utc)):
            return _row_error(request, "The lease is not current in Kea, so it was not synchronized.")
        try:
            from ..ipam_reconciliation import claim

            result = claim(server, self.dhcp_version, [lease], force=True)
            outcome: str
            if identity.kind == "delegated-prefix":
                outcome = next(iter(result.prefixes.values())).outcome
            else:
                outcome = next(iter(result.addresses.values())).outcome
            if outcome == "error":
                return _row_error(request, "Sync error: see server logs for details.")
        except event_scope.EventDispatchError:
            raise
        except (RuntimeError, ValueError, ValidationError, DatabaseError):
            logger.exception("Sync error for lease %s", label)
            return _row_error(request, "Sync error: see server logs for details.")

        return render(
            request,
            "netbox_kea/inc/claim_results.html",
            {"claim_result": result},
        )

    def _fetch_live_data(self, client: KeaClient, identity: LeaseIdentity) -> ExactLeaseResult | None:
        """Read the live Lease with *identity* from Kea, or ``None`` when the read fails."""
        try:
            return client.lease_get(identity)
        except (KeaException, requests.RequestException, RuntimeError, ValueError):
            logger.exception("Failed to fetch live lease%s data for %s", self.dhcp_version, identity.address)
            return None


class ServerLease4SyncView(_BaseSyncView):
    """Claim a DHCPv4 lease in the Server's sync VRF."""

    dhcp_version: Family = 4


class ServerLease6SyncView(_BaseSyncView):
    """Claim a DHCPv6 lease in the Server's sync VRF."""

    dhcp_version: Family = 6


class _BaseReservationSyncView(ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Synchronize one exact typed Reservation and all its allocation addresses."""

    workspace_section = "reservations"

    dhcp_version: Family

    def server_scope_access(self, request: HttpRequest) -> HttpResponse | None:
        """Preserve manual Reservation claim permissions before the Server lookup."""
        gate = sync_gate(request.user, claim_permissions(RESERVATION))
        return None if gate.allowed else _row_error(request, gate.reason)

    def post(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        gate = sync_gate(request.user, claim_permissions(RESERVATION))
        if not gate.allowed:
            return _row_error(request, gate.reason)
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        identity = _identity_from_request(request, self.dhcp_version)
        try:
            reservation, catalogue = _live_target(server, self.dhcp_version, subnet_id, identity)
            from ..ipam_reconciliation import claim

            result = claim(server, self.dhcp_version, [reservation], force=True, catalogue=catalogue)
        except event_scope.EventDispatchError:
            raise
        except Http404:
            return _row_error(request, "The Reservation or its Subnet is no longer in Kea. Reload the list.")
        except KeaException as exc:
            logger.exception("Kea error synchronizing a DHCPv%s Reservation", self.dhcp_version)
            return _row_error(request, f"Reservation synchronization failed: {kea_error_message(exc)}")
        except (requests.RequestException, DatabaseError, RuntimeError, ValidationError, ValueError):
            logger.exception("Could not synchronize a DHCPv%s Reservation", self.dhcp_version)
            return _row_error(request, "Reservation synchronization failed. See server logs.")
        # The badge reads the links as the page does, so a reload shows the same state.
        addresses = [str(address) for address in reservation.addresses]
        try:
            ownership = address_ownership(server, self.dhcp_version, RESERVATION, addresses, request.user)
        except DatabaseError:
            logger.exception("Could not read NetBox IPAM state after a DHCPv%s Reservation Sync", self.dhcp_version)
            ownership = None
        return render(
            request,
            "netbox_kea/inc/claim_results.html",
            {
                "claim_result": result,
                "record": {**reservation_badge(reservation, ownership), "sync_url": None},
            },
        )


class ServerReservation4SyncView(_BaseReservationSyncView):
    """Synchronize one canonical DHCPv4 Reservation target."""

    dhcp_version = 4


class ServerReservation6SyncView(_BaseReservationSyncView):
    """Synchronize one canonical DHCPv6 Reservation target."""

    dhcp_version = 6


class _BaseBulkReservationSyncView(ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Fetch one full typed Snapshot and synchronize every valid Reservation."""

    workspace_section = "reservations"

    dhcp_version: Family = 4  # overridden in subclasses

    def disabled_family_access(self, request: HttpRequest, server: Server) -> HttpResponse | None:
        """Preserve all manual reconciliation permissions on a disabled family."""
        gate = sync_gate(request.user, reconcile_permissions(server, ReservationPhase.source))
        return None if gate.allowed else HttpResponseForbidden(gate.reason)

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        if refusal := self.disabled_family_access(request, server):
            return refusal

        catalogue = None
        try:
            catalogue = for_synchronization(server, self.dhcp_version)
        except CatalogueUnavailable:
            logger.exception("Could not read the Subnet Catalogue for server %s", server.pk)

        report = reconcile(server, self.dhcp_version, [ReservationPhase(catalogue)])
        summary = (
            f"Bulk sync: {report.created} created, {report.updated} updated, "
            f"{len(report.conflicts)} conflicts skipped, {report.cleaned} stale links cleaned, "
            f"{report.errors} errors."
        )
        if report.skipped_reservations:
            summary += f" {len(report.skipped_reservations)} not applicable."
        if report.quarantined_reservations:
            summary += f" {report.quarantined_reservations} quarantined."
        if report.reservation_traversal_truncated:
            summary += " Reservation list was read only in part."
        if report.disagreements:
            summary += f" {len(report.disagreements)} owner disagreements."
        if not report.complete:
            summary += " Reservation phase incomplete; cleanup skipped."
        if not report.complete or report.conflicts or report.disagreements:
            messages.warning(request, summary)
        else:
            messages.success(request, summary)
        redirect_url = reverse(
            f"plugins:netbox_kea:server_reservations{self.dhcp_version}",
            args=[pk],
        )
        return HttpResponseRedirect(redirect_url)


class ServerReservation4BulkSyncView(_BaseBulkReservationSyncView):
    """Bulk sync all DHCPv4 reservations to NetBox IPAM."""

    dhcp_version = 4


class ServerReservation6BulkSyncView(_BaseBulkReservationSyncView):
    """Bulk sync all DHCPv6 reservations to NetBox IPAM."""

    dhcp_version = 6


class ReservationCheckNetboxIPView(ConditionalLoginRequiredMixin, View):
    """Advisory GET endpoint: report what saving the Reservation does to the IP address *ip* in NetBox IPAM.

    Used by the Reservation form to warn, without blocking. Server-scoped via ``pk`` so the existing ``Server``
    view permission applies. Returns an empty body when the ``ip`` query param is missing or invalid, or when the
    sync VRF holds no IP address that the user may view, or when the IPAM read fails; otherwise renders an advisory
    HTML fragment.
    """

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Read the IPAM Ownership of *ip* and return an advisory fragment (or empty body)."""
        # Scope to a viewable server so anonymous/unauthorised probes can't
        # enumerate NetBox IPAM through this endpoint.
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)

        raw_ip = (request.GET.get("ip") or "").strip()
        if not raw_ip:
            return HttpResponse("")
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError:
            return HttpResponse("")
        if getattr(address, "scope_id", None):
            return HttpResponse("")
        family = cast("Family", address.version)
        # The read is limited to the IP addresses the user may view, so the advisory leaks no field of another one.
        try:
            (found,) = address_ownership(server, family, RESERVATION, [str(address)], request.user).values()
        except DatabaseError:
            logger.exception("Could not read NetBox IPAM state for the Reservation advisory")
            return HttpResponse("")
        if found.obj is None:
            return HttpResponse("")
        return render(request, "netbox_kea/inc/reservation_ip_check.html", {"nb_ip": found.obj, "state": found.state})


# ─────────────────────────────────────────────────────────────────────────────
# Import report, shared by the Reservation document import and the Lease CSV import
# ─────────────────────────────────────────────────────────────────────────────

ImportStatus = Literal["created", "unconfirmed", "not-applied", "not-sent"]

#: The count label, the heading and the Bootstrap color of each status of an import item, in report order.
_IMPORT_GROUPS: dict[ImportStatus, tuple[str, str, str]] = {
    "created": ("Created", "{Many} that Kea created", "success"),
    "unconfirmed": ("Not confirmed", "{One} that Kea did not confirm", "warning"),
    "not-applied": ("Not applied", "{Many} that Kea did not apply", "danger"),
    "not-sent": ("Not sent", "{Many} that NetBox did not send", "secondary"),
}


@dataclass(frozen=True)
class ImportNoun:
    """What an import calls one item and its columns: a Lease CSV row, or a Reservation document entry."""

    one: str
    many: str
    position: str
    subject: str


_LEASE_ROWS = ImportNoun("row", "rows", "Line", "Address")
_RESERVATION_ENTRIES = ImportNoun("entry", "entries", "Position", "Identity")


@dataclass(frozen=True)
class ImportGroup:
    """The items of one status of an import report, with the label, heading and color of the status."""

    status: ImportStatus
    label: str
    heading: str
    color: str
    rows: list[dict[str, Any]]

    @property
    def has_messages(self) -> bool:
        """Return whether the items carry a message: each item that Kea did not create, or a created item with a note."""
        return self.status != "created" or any(row["message"] for row in self.rows)


def _import_report(
    loop: ChangeLoop[RowT, OutcomeT],
    total: int,
    noun: ImportNoun,
    describe: Callable[[RowT], tuple[str, str]],
    note: Callable[[OutcomeT], str] = lambda _outcome: "",
) -> dict[str, Any]:
    """Return the report of an import loop: each item by status, with its position, its subject and its message.

    *describe* returns the position and the subject of an item, and *note* the message of a created item.
    """

    def entries(items: Iterable[tuple[RowT, str]]) -> list[dict[str, Any]]:
        return [
            {"position": position, "subject": subject, "message": text}
            for item, text in items
            for position, subject in (describe(item),)
        ]

    not_sent = f"NetBox stopped at an earlier {noun.one} and did not send this {noun.one}."
    rows_by_status: dict[ImportStatus, list[dict[str, Any]]] = {
        "created": entries((item, note(outcome)) for item, outcome in loop.applied),
        "unconfirmed": entries([(loop.unknown[0], loop.unknown[1].text)] if loop.unknown else []),
        "not-applied": entries((item, message.text) for item, message in loop.rejected),
        "not-sent": entries((item, not_sent) for item in loop.not_sent),
    }
    groups = []
    for status, rows in rows_by_status.items():
        label, heading, color = _IMPORT_GROUPS[status]
        heading = heading.format(One=noun.one.capitalize(), Many=noun.many.capitalize())
        groups.append(ImportGroup(status, label, heading, color, rows))
    return {"groups": groups, "unconfirmed": loop.unknown is not None, "total": total, "noun": noun}


# ─────────────────────────────────────────────────────────────────────────────
# Bulk Reservation Import (YAML or JSON to Kea)
# ─────────────────────────────────────────────────────────────────────────────


class _BaseBulkReservationImportView(_KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Validate one document, then create its Reservations, one Configuration Change for each entry (ADR 0012).

    An entry that Kea did not apply or did not confirm stops the import.
    """

    workspace_section = "reservations"

    dhcp_version: Family
    form_class: type

    template_name = "netbox_kea/server_reservation_bulk_import.html"

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the Reservation document import form."""
        instance = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        return self._render(request, instance, self.form_class(), None)

    def _render(self, request: HttpRequest, instance: Server, form: Any, result: dict[str, Any] | None) -> HttpResponse:
        return render(
            request,
            self.template_name,
            {
                "object": instance,
                "form": form,
                "dhcp_version": self.dhcp_version,
                "return_url": reverse(f"plugins:netbox_kea:server_reservations{self.dhcp_version}", args=[instance.pk]),
                "result": result,
                "tab": _RESERVATIONS_TAB,
            },
        )

    def _validate(
        self, instance: Server, proposals: Sequence[ReservationImportProposal]
    ) -> list[ReservationTransferDiagnostic]:
        """Return a diagnostic for each entry whose Subnet or Identity type the live Kea server does not have."""
        capabilities = _live_capabilities(instance, self.dhcp_version)
        if capabilities is None or not capabilities.mutation_available:
            raise RuntimeError("Reservation mutation commands are unavailable.")
        diagnostics: list[ReservationTransferDiagnostic] = []
        with subnet_catalogue.mutation(instance, self.dhcp_version) as scope:
            for index, proposal in enumerate(proposals):
                if proposal.identity.identifier_type not in capabilities.identifiers:
                    diagnostics.append(
                        ReservationTransferDiagnostic(
                            code="unavailable-identity",
                            message="The live Kea server does not support this Reservation Identity type.",
                            source_position=f"reservations[{index}].identity.type",
                        )
                    )
                elif scope.find_by_cidr(proposal.subnet_cidr) is None:
                    diagnostics.append(
                        ReservationTransferDiagnostic(
                            code="unknown-subnet",
                            message="The live Subnet Catalogue does not contain this CIDR.",
                            source_position=f"reservations[{index}].scope.subnet.cidr",
                        )
                    )
        return diagnostics

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Validate the complete document, then send one Configuration Change for each entry until one fails."""
        instance = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        form = self.form_class(request.POST, request.FILES)
        if not form.is_valid():
            return self._render(request, instance, form, None)

        try:
            parsed = parse_reservation_document(
                form.cleaned_data["document"],
                form.cleaned_data["format"],
                expected_family=self.dhcp_version,
            )
        except ReservationTransferError:
            logger.exception("Reservation transfer document parsing failed")
            form.add_error("document", "The document does not use valid syntax for the selected format.")
            return self._render(request, instance, form, None)
        if parsed.diagnostics:
            return self._render(request, instance, form, {"diagnostics": parsed.diagnostics})

        try:
            instance.get_client(version=self.dhcp_version).close()
        except ValueError as exc:
            form.add_error(None, _client_settings_error(instance, exc))
            return self._render(request, instance, form, None)
        try:
            diagnostics = self._validate(instance, parsed.proposals)
        except (KeaException, requests.RequestException, RuntimeError, ValueError):
            logger.exception("Could not prepare Reservation document import for server %s", instance.pk)
            form.add_error(None, "The live Kea server could not validate this import. See server logs.")
            return self._render(request, instance, form, None)
        if diagnostics:
            return self._render(request, instance, form, {"diagnostics": diagnostics})

        def create(entry: tuple[int, ReservationImportProposal]) -> config_write.ReservationChangeOutcome:
            _index, proposal = entry
            outcome = config_write.add_reservation(
                instance,
                self.dhcp_version,
                proposal.subnet_cidr,
                lambda subnet, _catalogue: resolve_import_proposal(proposal, subnet.identity),
            )
            # Record each applied entry before the next entry goes to Kea, so a later failure loses no record.
            if outcome.application == "applied":
                _record_applied(request, instance, "created", outcome)
            return outcome

        entries = list(enumerate(parsed.proposals))
        loop = _run_change_loop(entries, create, stop_on_rejection=True)
        if any(outcome.persistence == "not-requested" for _entry, outcome in loop.applied):
            messages.info(
                request, "Configuration persistence is disabled for this server, so Kea did not save the import."
            )
        result = _import_report(
            loop,
            len(entries),
            _RESERVATION_ENTRIES,
            lambda entry: (f"reservations[{entry[0]}]", _identity_label(entry[1].identity)),
            _created_note,
        )
        return self._render(request, instance, self.form_class(), result)


def _created_note(outcome: config_write.ReservationChangeOutcome) -> str:
    """Return the note of a created Reservation: a failed persist step or verification read, else nothing."""
    notes = (_persistence_failure(outcome), _VERIFICATION_FAILED if outcome.verification == "failed" else None)
    return " ".join(note for note in notes if note)


class ServerReservation4BulkImportView(_BaseBulkReservationImportView):
    """Bulk import DHCPv4 Reservations from a YAML or JSON document."""

    dhcp_version = 4
    form_class = forms.Reservation4ImportForm


class ServerReservation6BulkImportView(_BaseBulkReservationImportView):
    """Bulk import DHCPv6 Reservations from a YAML or JSON document."""

    dhcp_version = 6
    form_class = forms.Reservation6ImportForm


# ─────────────────────────────────────────────────────────────────────────────
# Bulk Lease CSV Import
# ─────────────────────────────────────────────────────────────────────────────


class _BaseBulkLeaseImportView(_KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Upload a CSV file and create one Lease for each row via ``lease_add``.

    **GET**: render the upload form.
    **POST**: parse each row into a typed creation request → one ``runtime_change.add_lease`` per row → show summary.
    A row that is not a valid request rejects the whole file before Kea sees any row. The import stops at the first
    row that Kea did not confirm.
    """

    workspace_section = "leases"

    dhcp_version: Family
    form_class: type

    template_name = "netbox_kea/server_lease_bulk_import.html"

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the CSV upload form."""
        instance = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        return self._render(request, instance, self.form_class(), None)

    def _render(self, request: HttpRequest, instance: Server, form: Any, result: dict[str, Any] | None) -> HttpResponse:
        return render(
            request,
            self.template_name,
            {
                "object": instance,
                "form": form,
                "dhcp_version": self.dhcp_version,
                "return_url": reverse(f"plugins:netbox_kea:server_leases{self.dhcp_version}", args=[instance.pk]),
                "result": result,
                "tab": _LEASES_TAB,
            },
        )

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Parse uploaded CSV and create leases in Kea."""
        instance = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        form = self.form_class(request.POST, request.FILES)

        if not form.is_valid():
            return self._render(request, instance, form, None)

        csv_file = form.cleaned_data["csv_file"]
        try:
            content = csv_file.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            form.add_error("csv_file", "File must be UTF-8 encoded.")
            return self._render(request, instance, form, None)

        try:
            rows = parse_lease_csv(self.dhcp_version, content)
        except LeaseCSVError as exc:
            # The message names the file line and the column, never a value of the file.
            logger.info("Refused a lease CSV import: %s", exc)
            form.add_error("csv_file", str(exc))
            return self._render(request, instance, form, None)
        except (ValueError, csv.Error):
            logger.exception("CSV parse error in lease bulk import")
            form.add_error("csv_file", "CSV parsing failed. Check the file format and column headers.")
            return self._render(request, instance, form, None)

        def signal_added(
            creation: LeaseRequest, outcome: runtime_change.RuntimeChangeOutcome
        ) -> runtime_change.RuntimeChangeOutcome:
            # Signal each applied row before the next row goes to Kea, so a later failure loses no signal.
            if outcome.application == "applied":
                # A bulk import reads nothing back, so no observed Lease goes with the confirmed request.
                _signal_applied(
                    request,
                    lease_added,
                    "lease_added",
                    server=instance,
                    creation=creation,
                    lease=None,
                    dhcp_version=self.dhcp_version,
                )
            return outcome

        loop = _run_change_loop(
            rows, lambda row: signal_added(row[1], runtime_change.add_lease(instance, self.dhcp_version, row[1]))
        )
        created = [str(creation.address) for (_line, creation), _outcome in loop.applied]
        if created:
            _journal_applied(request, instance, _lease_journal_comments("added", created))
        result = _import_report(loop, len(rows), _LEASE_ROWS, lambda row: (str(row[0]), str(row[1].address)))
        return self._render(request, instance, self.form_class(), result)


class ServerLease4BulkImportView(_BaseBulkLeaseImportView):
    """Bulk import DHCPv4 leases from a CSV file."""

    dhcp_version = 4
    form_class = forms.Lease4BulkImportForm


class ServerLease6BulkImportView(_BaseBulkLeaseImportView):
    """Bulk import DHCPv6 leases from a CSV file."""

    dhcp_version = 6
    form_class = forms.Lease6BulkImportForm
