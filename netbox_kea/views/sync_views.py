# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import csv
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from django.contrib import messages
from django.db import DatabaseError
from django.http import Http404, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.http.request import HttpRequest
from django.shortcuts import render
from django.urls import reverse
from django.views import View

from .. import (
    event_scope,
    forms,
    ip_parse,
    manual_sync,
    reservation_edit,
    runtime_change,
    server_configuration,
    subnet_catalogue,
)
from ..after_apply import LeaseImportAfterApply
from ..constants import Family
from ..ipam_ownership import address_ownership
from ..ipam_reconciliation import ReservationPhase, claim_permissions, reconcile, reconcile_permissions
from ..ipam_sources import RESERVATION
from ..leases import (
    LeaseAbsent,
    parse_selection,
    shown_lease,
)
from ..models import Server
from ..reservation_transfer import (
    ReservationImportProposal,
    ReservationTransferDiagnostic,
    ReservationTransferError,
    parse_reservation_document,
)
from ..reservations import ReservationCapabilities
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
    client_or_refusal,
    client_settings_refusal,
    persistence_failure,
    run_change_loop,
)
from .leases import LEASES_TAB, lease_sync_gates, show_lease_side_effects
from .manual_sync_presenter import manual_sync_lines
from .notices import Notice, failed_load, load_target
from .reservation_mutations import (
    RESERVATION_VERIFICATION_FAILED,
    live_reservation_target,
    reservation_identity_from_request,
    reservation_identity_label,
    show_reservation_side_effects,
)
from .reservations import MUTATION_UNCONFIRMED, RESERVATIONS_TAB, reservation_badge
from .server_scope import ServerAccessMixin
from .workspace import FamilyRouteMixin

logger = logging.getLogger(__name__)

_BULK_SYNC_EVENTS_FAILED = (
    "Bulk sync stopped: NetBox saved the changes made so far, but an event dispatch failed, and some events may"
    " already have been sent; see server logs. Check the addresses before you sync again."
)


def _row_error(request: HttpRequest, message: str) -> HttpResponse:
    """Return *message* as the error badge that replaces the row button which posted *request*."""
    # A 200 reply: htmx swaps no error reply, and NetBox's DEBUG htmx script replaces the page with a 4xx/5xx one.
    return render(request, "netbox_kea/inc/row_action_error.html", {"message": message})


def _manual_sync_reply(
    request: HttpRequest, outcome: manual_sync.ManualSyncOutcome, subject: str, record: dict[str, Any] | None = None
) -> HttpResponse:
    """Return the row reply of a Manual Sync: its error badge, or its allocation badges and each other line."""
    lines = manual_sync_lines(outcome, subject)
    if isinstance(outcome, manual_sync.NotRun):
        return _row_error(request, " ".join(line.text for line in lines))
    notes = [line.text for line in lines if not line.allocation]
    return render(
        request,
        "netbox_kea/inc/claim_results.html",
        {"claim_result": outcome.result, "record": record, "notes": notes},
    )


class ServerLeaseSyncView(FamilyRouteMixin, ServerAccessMixin, ConditionalLoginRequiredMixin, View):
    """Claim one fresh Current Lease: an address as an IP Address, a delegated prefix as a Prefix."""

    server_action = "view"
    workspace_section = "leases"

    def server_scope_access(self, request: HttpRequest) -> HttpResponse | None:
        """Preserve the manual claim permission of the selected Lease allocation kind."""
        try:
            _, identity = parse_selection(self.dhcp_version, request.POST.get("ip_address", "").strip())
        except ValueError:
            return None
        gate = lease_sync_gates(request.user)[identity.kind]
        return None if gate.allowed else _row_error(request, gate.reason)

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Claim the selected Lease."""
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

        server = self.server
        with client_or_refusal(server, self.dhcp_version) as client:
            if isinstance(client, str):
                return _row_error(request, client)
            observed = load_target(server, "lease_target", lambda: client.lease_get(identity))
        if isinstance(observed, Notice):
            return _row_error(request, observed.text)
        if isinstance(observed, LeaseAbsent):
            return _row_error(request, "The lease is no longer in Kea. Reload the lease list.")
        lease = observed.lease
        # The label holds the kind and the prefix length, so a changed allocation does not match.
        if shown_lease(lease).label != label:
            return _row_error(request, "The lease changed in Kea. Reload the lease list.")
        outcome = manual_sync.sync_lease(server, lease, gate, force=True)
        return _manual_sync_reply(request, outcome, f"Lease {label}")


class ServerReservationSyncView(FamilyRouteMixin, ServerAccessMixin, ConditionalLoginRequiredMixin, View):
    """Synchronize one exact typed Reservation and all its allocation addresses."""

    server_action = "view"
    workspace_section = "reservations"

    def server_scope_access(self, request: HttpRequest) -> HttpResponse | None:
        """Preserve manual Reservation claim permissions before the Server lookup."""
        gate = sync_gate(request.user, claim_permissions(RESERVATION))
        return None if gate.allowed else _row_error(request, gate.reason)

    def post(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        """Synchronize the selected Reservation."""
        gate = sync_gate(request.user, claim_permissions(RESERVATION))
        if not gate.allowed:
            return _row_error(request, gate.reason)
        server = self.server
        identity = reservation_identity_from_request(request, self.dhcp_version)
        if refusal := client_settings_refusal(server, self.dhcp_version):
            return _row_error(request, refusal)
        try:
            loaded = load_target(
                server,
                "reservation_target",
                lambda: live_reservation_target(server, self.dhcp_version, subnet_id, identity),
            )
        except Http404:
            return _row_error(request, "The Reservation or its Subnet is no longer in Kea. Reload the list.")
        if isinstance(loaded, Notice):
            return _row_error(request, loaded.text)
        reservation, catalogue = loaded
        outcome = manual_sync.sync_reservation(server, reservation, catalogue, gate)
        if isinstance(outcome, manual_sync.NotRun):
            return _manual_sync_reply(request, outcome, "Reservation")
        # The badge reads the links as the page does, so a reload shows the same state.
        addresses = [str(address) for address in reservation.addresses]
        try:
            ownership = address_ownership(server, self.dhcp_version, RESERVATION, addresses, request.user)
        except DatabaseError:
            logger.exception("Could not read NetBox IPAM state after a DHCPv%s Reservation Sync", self.dhcp_version)
            ownership = None
        record = {**reservation_badge(reservation, ownership), "sync_url": None}
        return _manual_sync_reply(request, outcome, "Reservation", record)


class ServerReservationBulkSyncView(FamilyRouteMixin, ServerAccessMixin, ConditionalLoginRequiredMixin, View):
    """Fetch one full typed Snapshot and synchronize every valid Reservation."""

    server_action = "view"
    workspace_section = "reservations"

    def disabled_family_access(self, request: HttpRequest, server: Server) -> HttpResponse | None:
        """Preserve all manual reconciliation permissions on a disabled family."""
        gate = sync_gate(request.user, reconcile_permissions(server, ReservationPhase.source))
        return None if gate.allowed else HttpResponseForbidden(gate.reason)

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Synchronize every valid Reservation of the family."""
        server = self.server
        if refusal := self.disabled_family_access(request, server):
            return refusal

        catalogue = None
        try:
            catalogue = for_synchronization(server, self.dhcp_version)
        except CatalogueUnavailable:
            logger.exception("Could not read the Subnet Catalogue for server %s", server.pk)

        redirect_url = reverse("plugins:netbox_kea:server_reservations", kwargs={"pk": pk, "family": self.dhcp_version})
        try:
            report = reconcile(server, self.dhcp_version, [ReservationPhase(catalogue)])
        except event_scope.EventDispatchError:
            logger.exception(
                "Server %s: the bulk Reservation Sync stopped; an event dispatch failed and some events may have been sent",
                pk,
            )
            messages.error(request, _BULK_SYNC_EVENTS_FAILED)
            return HttpResponseRedirect(redirect_url)
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
        return HttpResponseRedirect(redirect_url)


class ReservationCheckNetboxIPView(ServerAccessMixin, ConditionalLoginRequiredMixin, View):
    """Advisory GET endpoint: report what saving the Reservation does to the IP address *ip* in NetBox IPAM.

    Used by the Reservation form to warn, without blocking. Server-scoped via ``pk`` so the existing ``Server``
    view permission applies. Returns an empty body when the ``ip`` query param is missing or invalid, or when the
    sync VRF holds no IP address that the user may view, or when the IPAM read fails; otherwise renders an advisory
    HTML fragment.
    """

    server_action = "view"

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Read the IPAM Ownership of *ip* and return an advisory fragment (or empty body)."""
        # The gate scopes the read to a viewable Server, so a probe cannot enumerate NetBox IPAM through it.
        server = self.server

        raw_ip = (request.GET.get("ip") or "").strip()
        if not raw_ip:
            return HttpResponse("")
        try:
            address = ip_parse.ip_address(raw_ip)
        except ValueError:
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
    note: Callable[[RowT, OutcomeT], str] = lambda _item, _outcome: "",
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
        "created": entries((item, note(item, outcome)) for item, outcome in loop.applied),
        "unconfirmed": entries([(loop.unknown[0], loop.unknown[1].text)] if loop.unknown else []),
        "not-applied": entries((item, message.text) for item, message in loop.rejected),
        "not-sent": entries((item, not_sent) for item in loop.not_sent),
    }
    groups = []
    for status, rows in rows_by_status.items():
        label, heading, color = _IMPORT_GROUPS[status]
        heading = heading.format(One=noun.one.capitalize(), Many=noun.many.capitalize())
        groups.append(ImportGroup(status, label, heading, color, rows))
    unconfirmed = loop.unknown is not None
    stopped = loop.stopped_at is not None and not unconfirmed
    return {"groups": groups, "unconfirmed": unconfirmed, "stopped": stopped, "total": total, "noun": noun}


# ─────────────────────────────────────────────────────────────────────────────
# Bulk Reservation Import (YAML or JSON to Kea)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _ImportRefusal:
    """Why the live Server cannot validate a Reservation import: one form error per line."""

    lines: tuple[str, ...]


class ServerReservationBulkImportView(FamilyRouteMixin, ServerAccessMixin, ConditionalLoginRequiredMixin, View):
    """Validate one document, then create its Reservations, one Configuration Change for each entry (ADR 0012).

    An entry that Kea did not apply or did not confirm stops the import.
    """

    server_action = "change"
    workspace_section = "reservations"

    template_name = "netbox_kea/server_reservation_bulk_import.html"

    @property
    def form_class(self) -> type[forms._BaseBulkReservationImportForm]:
        """Return the import form of the route family."""
        return {4: forms.Reservation4ImportForm, 6: forms.Reservation6ImportForm}[self.dhcp_version]

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the Reservation document import form."""
        instance = self.server
        return self._render(request, instance, self.form_class(), None)

    def _render(self, request: HttpRequest, instance: Server, form: Any, result: dict[str, Any] | None) -> HttpResponse:
        return render(
            request,
            self.template_name,
            {
                "object": instance,
                "form": form,
                "dhcp_version": self.dhcp_version,
                "return_url": reverse(
                    "plugins:netbox_kea:server_reservations", kwargs={"pk": instance.pk, "family": self.dhcp_version}
                ),
                "result": result,
                "tab": RESERVATIONS_TAB,
            },
        )

    def _validate(
        self, instance: Server, proposals: Sequence[ReservationImportProposal]
    ) -> list[ReservationTransferDiagnostic] | _ImportRefusal:
        """Return a diagnostic for each entry whose Subnet or Identity type the live Kea server does not have.

        Return the refusal of the whole import when a live read cannot confirm the facts or the Server cannot take
        Reservation changes.
        """
        configuration = server_configuration.for_verification(instance, self.dhcp_version)
        if configuration.unavailable:
            return _ImportRefusal(failed_load(configuration).lines)
        capabilities = server_configuration.reservation_capabilities(configuration)
        if capabilities is None or not capabilities.mutation_available:
            return _ImportRefusal(
                ((capabilities.explanation if capabilities is not None else "") or MUTATION_UNCONFIRMED,)
            )
        with subnet_catalogue.mutation(instance, self.dhcp_version) as scope:
            catalogue = scope.snapshot
            if catalogue is None:
                raise TypeError("An entered mutation scope holds its Catalogue.")
            try:
                return self._entry_diagnostics(scope, capabilities, proposals)
            except CatalogueUnavailable:
                return _ImportRefusal(failed_load(catalogue).lines)

    @staticmethod
    def _entry_diagnostics(
        scope: subnet_catalogue.MutationScope,
        capabilities: ReservationCapabilities,
        proposals: Sequence[ReservationImportProposal],
    ) -> list[ReservationTransferDiagnostic]:
        """Return a diagnostic for each entry whose Identity type or Subnet the live Server does not have.

        Raises:
            CatalogueUnavailable: If the live Catalogue cannot confirm that a CIDR is absent.

        """
        diagnostics: list[ReservationTransferDiagnostic] = []
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
        instance = self.server
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
            import_context = reservation_edit.prepare_import(
                instance, request.user, sync_to_netbox=form.cleaned_data["sync_to_netbox"]
            )
        except reservation_edit.ImportSyncRefused as exc:
            form.add_error("sync_to_netbox", exc.message)
            return self._render(request, instance, form, None)

        if refusal := client_settings_refusal(instance, self.dhcp_version):
            form.add_error(None, refusal)
            return self._render(request, instance, form, None)
        diagnostics = self._validate(instance, parsed.proposals)
        if isinstance(diagnostics, _ImportRefusal):
            for line in diagnostics.lines:
                form.add_error(None, line)
            return self._render(request, instance, form, None)
        if diagnostics:
            return self._render(request, instance, form, {"diagnostics": diagnostics})

        after_facts: dict[int, reservation_edit.AfterApplyFacts] = {}

        def create(entry: tuple[int, ReservationImportProposal]) -> reservation_edit.AddOutcome:
            _index, proposal = entry
            return reservation_edit.save_import(instance, proposal)

        def after_applied(entry: tuple[int, ReservationImportProposal], outcome: reservation_edit.AddOutcome) -> None:
            facts = reservation_edit.after_apply(
                instance, outcome, request.user, request=request, import_context=import_context
            )
            after_facts[entry[0]] = facts
            show_reservation_side_effects(request, facts, show_claim=False)

        entries = list(enumerate(parsed.proposals))
        loop = run_change_loop(entries, create, stop_on_rejection=True, after_applied=after_applied)
        if any(outcome.persistence == "not-requested" for _entry, outcome in loop.applied):
            messages.info(
                request, "Configuration persistence is disabled for this server, so Kea did not save the import."
            )
        summary = reservation_edit.pool_overlap_summary(tuple(outcome for _entry, outcome in loop.applied))
        if summary.identities:
            identities = ", ".join(reservation_identity_label(identity) for identity in summary.identities)
            remainder = f", and {summary.remaining} more" if summary.remaining else ""
            messages.warning(request, f"Reservations with an address in an allocation Pool: {identities}{remainder}.")
        result = _import_report(
            loop,
            len(entries),
            _RESERVATION_ENTRIES,
            lambda entry: (f"reservations[{entry[0]}]", reservation_identity_label(entry[1].identity)),
            lambda entry, outcome: _created_note(outcome, after_facts[entry[0]]),
        )
        return self._render(request, instance, self.form_class(), result)


def _created_note(outcome: reservation_edit.AddOutcome, facts: reservation_edit.AfterApplyFacts) -> str:
    """Name persistence, verification, pool-check and Manual Sync problems for this created entry."""
    notes = [
        persistence_failure(outcome),
        RESERVATION_VERIFICATION_FAILED if outcome.verification == "failed" else None,
    ]
    notes.extend(
        f"NetBox could not check allocation Pools for Subnet {warning.subnet_cidr}."
        for warning in outcome.warnings
        if isinstance(warning, reservation_edit.PoolCheckUnavailable)
    )
    if not isinstance(facts.claim, str):
        notes.extend(line.text for line in manual_sync_lines(facts.claim, "Reservation") if line.level != "success")
    return " ".join(note for note in notes if note)


# ─────────────────────────────────────────────────────────────────────────────
# Bulk Lease CSV Import
# ─────────────────────────────────────────────────────────────────────────────


class ServerLeaseBulkImportView(FamilyRouteMixin, ServerAccessMixin, ConditionalLoginRequiredMixin, View):
    """Upload a CSV file and create one Lease for each row via ``lease_add``.

    **GET**: render the upload form.
    **POST**: parse each row into a typed creation request → one ``runtime_change.add_lease`` per row → show summary.
    A row that is not a valid request rejects the whole file before Kea sees any row. The import stops at the first
    row that Kea did not confirm.
    """

    server_action = "change"
    workspace_section = "leases"

    template_name = "netbox_kea/server_lease_bulk_import.html"

    @property
    def form_class(self) -> type[forms._BaseBulkLeaseImportForm]:
        """Return the import form of the route family."""
        return {4: forms.Lease4BulkImportForm, 6: forms.Lease6BulkImportForm}[self.dhcp_version]

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the CSV upload form."""
        instance = self.server
        return self._render(request, instance, self.form_class(), None)

    def _render(self, request: HttpRequest, instance: Server, form: Any, result: dict[str, Any] | None) -> HttpResponse:
        return render(
            request,
            self.template_name,
            {
                "object": instance,
                "form": form,
                "dhcp_version": self.dhcp_version,
                "return_url": reverse(
                    "plugins:netbox_kea:server_leases", kwargs={"pk": instance.pk, "family": self.dhcp_version}
                ),
                "result": result,
                "tab": LEASES_TAB,
            },
        )

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Parse uploaded CSV and create leases in Kea."""
        instance = self.server
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

        effects = LeaseImportAfterApply(instance, request.user, request)
        loop = run_change_loop(
            rows,
            lambda row: runtime_change.add_lease(instance, self.dhcp_version, row[1]),
            after_applied=lambda row, _outcome: effects.row_applied(row[1]),
        )
        if facts := effects.finish():
            show_lease_side_effects(request, facts)
        result = _import_report(loop, len(rows), _LEASE_ROWS, lambda row: (str(row[0]), str(row[1].address)))
        return self._render(request, instance, self.form_class(), result)
