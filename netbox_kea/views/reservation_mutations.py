# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import ipaddress
import json
import logging
from typing import Any
from urllib.parse import urlencode

from django.contrib import messages
from django.core.exceptions import BadRequest
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from netbox.views import generic

from .. import config_write, forms, reservation_edit, subnet_catalogue
from ..config_write import ReservationChangeOutcome
from ..constants import Family, IPAddressValue
from ..dhcp_options import parse_dhcp_option
from ..ipam_reconciliation import RESERVATION, ClaimResult, claim_permissions
from ..models import Server
from ..published_name import published_name, stored_hostname
from ..reservations import (
    InSubnetReservationScope,
    Reservation,
    ReservationCapabilities,
    ReservationConflict,
    ReservationIdentity,
    reservation_identifier_types,
)
from ..subnet_catalogue import CatalogueSnapshot, CatalogueUnavailable, VerifiedSubnet
from ..sync_permissions import sync_gate
from ._base import (
    _client_settings_refusal,
    _KeaChangeMixin,
    _run_change,
    _safe_return_url,
)
from .notices import Notice, failed_load, load_target, notice, show_notices
from .reservations import (
    RESERVATIONS_TAB,
    _build_reservation_options_formset,
    _display_capabilities,
    _live_capabilities,
)
from .workspace import ServerFamilyMixin

logger = logging.getLogger(__name__)

RESERVATION_VERIFICATION_FAILED = "Kea applied the change, but NetBox Kea could not verify the final Reservation."

RESERVATION_CLAIM_EVENTS_FAILED = (
    "NetBox IPAM sync saved changes, but could not dispatch their events. "
    "Synchronization may be incomplete; check the addresses before retrying."
)


def _warn_pool_facts(
    request: HttpRequest, facts: tuple[reservation_edit.PoolOverlap | reservation_edit.PoolCheckUnavailable, ...]
) -> None:
    """Present the non-blocking pool check facts of a Reservation add."""
    for fact in facts:
        if isinstance(fact, reservation_edit.PoolCheckUnavailable):
            messages.warning(
                request,
                f"The pool overlap check did not run. The configuration of Subnet {fact.subnet_cidr} is unavailable, "
                "so this Reservation was not checked against its pools.",
            )
        else:
            messages.warning(
                request,
                f"IP {fact.address} is within existing pool {fact.pool.range}. "
                "Kea allows this. Reservations take priority over pool allocation.",
            )


def _submitted_values(
    family: Family, cleaned_data: dict[str, Any], options_formset: Any
) -> reservation_edit.SubmittedValues:
    """Parse cleaned form strings and rows into the typed values of the edit module."""
    addresses: tuple[IPAddressValue, ...]
    if family == 4:
        addresses = (ipaddress.IPv4Address(cleaned_data["ip_address"]),) if cleaned_data.get("ip_address") else ()
    else:
        addresses = tuple(
            ipaddress.IPv6Address(value) for value in (cleaned_data.get("ip_addresses") or "").split(",") if value
        )
    prefixes = _networks(cleaned_data.get("prefixes"))
    rows = tuple(
        reservation_edit.OptionRow(
            name=row.get("name", ""),
            data=row.get("data", ""),
            always_send=bool(row.get("always_send")),
            delete=bool(row.get("DELETE")),
            original_option=parse_dhcp_option(row["original_option"])
            if row.get("original_option") is not None
            else None,
            client_classes=reservation_edit.class_names(row.get("client_classes", "")),
        )
        for row in (getattr(options_formset, "cleaned_data", []) or [])
        if row
    )
    next_server = cleaned_data.get("next_server")
    return reservation_edit.SubmittedValues(
        addresses,
        prefixes,
        cleaned_data.get("hostname", ""),
        rows,
        client_classes=reservation_edit.class_names(cleaned_data.get("client_classes", "")),
        next_server=ipaddress.IPv4Address(next_server) if next_server else None,
        server_hostname=cleaned_data.get("server_hostname", ""),
        boot_file_name=cleaned_data.get("boot_file_name", ""),
        excluded_prefixes=_networks(cleaned_data.get("excluded_prefixes")),
    )


def _networks(value: str | None) -> tuple[ipaddress.IPv6Network, ...]:
    """Parse a cleaned comma-separated prefix field."""
    return tuple(ipaddress.IPv6Network(item) for item in (value or "").split(",") if item)


def reservation_identity_from_request(request: HttpRequest, version: Family) -> ReservationIdentity:
    """Validate the single Reservation Identity that a view query selects."""
    types = request.GET.getlist("identifier_type")
    values = request.GET.getlist("identifier")
    if len(types) != 1 or len(values) != 1:
        raise BadRequest("Exactly one identifier_type and one identifier are required.")
    identifier_type = types[0]
    identifier = values[0]
    if identifier_type not in reservation_identifier_types(version) or not identifier:
        raise BadRequest(f"Invalid DHCPv{version} Reservation Identity.")
    try:
        return ReservationIdentity(identifier_type, identifier)
    except ValueError as exc:
        raise BadRequest(f"Invalid DHCPv{version} Reservation Identity.") from exc


def reservation_identity_label(identity: ReservationIdentity) -> str:
    """Return how a message names the Reservation with *identity*."""
    return f"{identity.identifier_type} {identity.value}"


def _exact_reservation(
    server: Server,
    version: Family,
    subnet: VerifiedSubnet | None,
    catalogue: CatalogueSnapshot,
    identity: ReservationIdentity,
) -> Reservation:
    """Read one exact Reservation within a verified Subnet."""
    if subnet is None:
        raise Http404("Reservation Subnet not found.")
    scope = InSubnetReservationScope(subnet.identity)
    with server.get_client(version=version) as client:
        reservation = client.reservation_by_identity(version, catalogue, scope, identity)
    if reservation is None:
        raise Http404("Reservation not found.")
    return reservation


def live_reservation_target(
    server: Server, version: Family, subnet_id: int, identity: ReservationIdentity
) -> tuple[Reservation, CatalogueSnapshot] | Notice:
    """Return one live Reservation and the Catalogue with configuration facts in which its Subnet is verified.

    Return the Catalogue Notice when the live Catalogue cannot confirm the Subnet.
    """
    with subnet_catalogue.mutation(server, version) as scope:
        catalogue = scope.snapshot
        if catalogue is None:
            raise TypeError("An entered mutation scope holds its Catalogue.")
        try:
            subnet = scope.find_by_id(subnet_id)
        except CatalogueUnavailable:
            return failed_load(catalogue)
    return _exact_reservation(server, version, subnet, catalogue, identity), catalogue


def _read_reservation_target(
    server: Server,
    version: Family,
    subnet_id: int,
    identity: ReservationIdentity,
) -> Reservation | Notice:
    """Return one live Reservation without invalidating the display snapshots.

    Return the Catalogue Notice when the ``subnet{v}-list`` read cannot confirm the Subnet.
    """
    observation = subnet_catalogue.read_identity(server, version)
    try:
        subnet = observation.find_by_id(subnet_id)
    except CatalogueUnavailable:
        return failed_load(observation.snapshot)
    return _exact_reservation(server, version, subnet, observation.snapshot, identity)


def _target_or_redirect(
    request: HttpRequest,
    server: Server,
    version: Family,
    subnet_id: int,
    identity: ReservationIdentity,
    return_url: str,
    *shown: Notice | None,
) -> Reservation | HttpResponse:
    """Load the Reservation to change, or show the Notice of the failed load with *shown* and redirect."""
    loaded = load_target(
        server, "reservation_target", lambda: _read_reservation_target(server, version, subnet_id, identity)
    )
    if isinstance(loaded, Notice):
        show_notices(request, loaded, *shown)
        return redirect(return_url)
    return loaded


def show_reservation_side_effects(
    request: HttpRequest, facts: reservation_edit.AfterApplyFacts, *, show_claim: bool = True
) -> None:
    """Present the independent journal, signal and IPAM claim facts of an applied Reservation change."""
    if facts.journal == "failed":
        messages.error(
            request, "Kea applied the change, but NetBox could not write the journal entry; see server logs."
        )
    if facts.journal == "events-failed":
        messages.error(
            request,
            "Kea applied the change, and the journal entry was saved, but NetBox could not dispatch its events; see server logs.",
        )
    if facts.signal == "events-failed":
        messages.error(
            request,
            "Kea applied the change, and the Reservation signal was sent, but NetBox could not dispatch its events; see server logs.",
        )
    if facts.signal == "failed":
        messages.error(
            request,
            f"Kea applied the change, but a receiver of the reservation_{facts.action} signal failed; see server logs.",
        )
    if not show_claim:
        return
    claim = facts.claim
    if isinstance(claim, reservation_edit.ClaimSkipped):
        if claim.reason == "nothing-to-sync":
            messages.info(
                request, f"Reservation {facts.action}. Nothing to sync to NetBox because it reserves no IP address."
            )
        elif claim.reason == "permission":
            messages.warning(
                request, f"Reservation {facts.action}, but it was not synced to NetBox. {claim.explanation}"
            )
    elif isinstance(claim, reservation_edit.ClaimFailure):
        if claim.reason == "events-failed":
            messages.error(
                request,
                f"Reservation {facts.action}. {RESERVATION_CLAIM_EVENTS_FAILED}",
            )
        else:
            messages.error(request, "The Reservation changed, but NetBox IPAM synchronization failed.")
    elif isinstance(claim, ClaimResult) and any(not address.synchronized for address in claim.addresses.values()):
        messages.warning(request, "The Reservation changed, but NetBox IPAM synchronization failed.")


def _show_applied_details(request: HttpRequest, outcome: ReservationChangeOutcome) -> None:
    """Show persistence-disabled and verification guidance for one applied Reservation change."""
    if outcome.persistence == "not-requested":
        messages.info(request, "Kea applied the change. Configuration persistence is disabled for this server.")
    if outcome.verification == "failed":
        messages.warning(request, RESERVATION_VERIFICATION_FAILED)


def _entered_address(value: str, family: Family) -> IPAddressValue | None:
    """Return the first address of an address field, or None when the field holds none or no valid one."""
    first = value.split(",", maxsplit=1)[0].strip()
    try:
        address = ipaddress.ip_address(first)
    except ValueError:
        return None
    return address if address.version == family else None


def _published_name_preview(
    server: Server, family: Family, cidr: str, address: IPAddressValue | None, hostname: str
) -> dict[str, Any]:
    """Return the preview facts of the name that Kea publishes for *hostname* at *address* in the Subnet *cidr*."""
    catalogue = subnet_catalogue.display(server, family)
    try:
        subnet = catalogue.find_by_cidr(cidr)
    except ValueError:
        subnet = None
    if subnet is None:
        return {"subnet_known": False}
    try:
        suffix = catalogue.subnet_qualifying_suffix(subnet.identity, address)
    except CatalogueUnavailable:
        return {"subnet_known": True}
    return {
        "subnet_known": True,
        # Display only: the configured value can end in a dot.
        "suffix": suffix.removesuffix("."),
        "published": published_name(stored_hostname(hostname, suffix), suffix),
    }


class _ReservationPublishedNameView(_KeaChangeMixin, ServerFamilyMixin, View):
    """Render the name that Kea publishes for the hostname in the Reservation form, from the cached catalogue."""

    workspace_section = "reservations"

    dhcp_version: Family

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        server = get_object_or_404(Server.objects.restrict(request.user, "change"), pk=pk)
        hostname = request.GET.get("hostname", "").strip()
        context: dict[str, Any] = {"hostname": hostname}
        if hostname:
            field = "ip_address" if self.dhcp_version == 4 else "ip_addresses"
            context.update(
                _published_name_preview(
                    server,
                    self.dhcp_version,
                    request.GET.get("subnet_cidr", "").strip(),
                    _entered_address(request.GET.get(field, ""), self.dhcp_version),
                    hostname,
                )
            )
        return render(request, "netbox_kea/inc/reservation_published_name.html", context)


class _ReservationMutationView(_KeaChangeMixin, ServerFamilyMixin, generic.ObjectView):
    workspace_section = "reservations"
    queryset = Server.objects.all()
    tab = RESERVATIONS_TAB
    template_name = "netbox_kea/server_reservation_form.html"
    dhcp_version: Family
    form_class: type[forms.Reservation4Form] | type[forms.Reservation6Form]
    form_action: str

    def _return_url(self, server: Server) -> str:
        """Return the Reservation search that linked here, else the Reservation list."""
        return _safe_return_url(
            self.request, reverse(f"plugins:netbox_kea:server_reservations{self.dhcp_version}", args=[server.pk])
        )

    def _form(self, server: Server, capabilities: ReservationCapabilities | None, **kwargs: Any):
        """Build the Reservation form with the user's manual Sync rule and the Server's automatic IPAM sync."""
        return self.form_class(
            capabilities=capabilities,
            sync_refusal=sync_gate(self.request.user, claim_permissions(RESERVATION)).reason,
            automatic_sync=server.sync_enabled and server.sync_reservations_enabled,
            **kwargs,
        )

    def _mutation_capabilities(self, request: HttpRequest, server: Server) -> ReservationCapabilities | HttpResponse:
        """Return the live confirmed mutation capabilities, or the response that refuses the mutation."""
        if refusal := _client_settings_refusal(server, self.dhcp_version):
            messages.error(request, refusal)
            return redirect(self._return_url(server))
        capabilities = _live_capabilities(server, self.dhcp_version)
        if capabilities is None or not capabilities.mutation_available:
            messages.error(request, "Reservation mutation capabilities are unavailable.")
            return redirect(self._return_url(server))
        return capabilities

    def _form_context(
        self,
        server: Server,
        form: Any,
        options_formset: Any,
        capabilities: ReservationCapabilities | None,
        *,
        subnet_cmds_available: bool = True,
        published_name_query: str = "",
        user_context: Any = None,
    ) -> dict[str, Any]:
        preview_url = reverse(
            f"plugins:netbox_kea:server_reservation{self.dhcp_version}_published_name", args=[server.pk]
        )
        return {
            "object": server,
            "form": form,
            "options_formset": options_formset,
            "return_url": self._return_url(server),
            "action": self.form_action,
            "dhcp_version": self.dhcp_version,
            "tab": self.tab,
            "subnet_cmds_available": subnet_cmds_available,
            "mutation_available": bool(capabilities and capabilities.mutation_available),
            "published_name_url": f"{preview_url}?{published_name_query}" if published_name_query else preview_url,
            # Read-only: no form field edits it, and an edit keeps the live value.
            "user_context": None if user_context is None else json.dumps(user_context, indent=2),
        }

    def _render(
        self,
        request: HttpRequest,
        server: Server,
        form: Any,
        options_formset: Any,
        capabilities: ReservationCapabilities | None,
        **context: Any,
    ) -> HttpResponse:
        return render(
            request,
            self.template_name,
            self._form_context(server, form, options_formset, capabilities, **context),
        )


class _ReservationAddView(_ReservationMutationView):
    form_action = "Add"

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        capabilities = None
        if refusal := _client_settings_refusal(server, self.dhcp_version):
            messages.error(request, refusal)
        else:
            capabilities = _display_capabilities(server, self.dhcp_version)
        snapshot = subnet_catalogue.display(server, self.dhcp_version)
        show_notices(request, notice(snapshot))
        initial_fields = (
            ("subnet_cidr", "ip_address", "identifier_type", "identifier", "hostname")
            if self.dhcp_version == 4
            else ("subnet_cidr", "ip_addresses", "prefixes", "identifier_type", "identifier", "hostname")
        )
        initial = {field: request.GET.get(field, "") for field in initial_fields if request.GET.get(field)}
        form = self._form(server, capabilities, initial=initial)
        form.offer_subnets(snapshot.subnet_choices)
        return self._render(
            request,
            server,
            form,
            forms.ReservationOptionsFormSet(prefix="options"),
            capabilities,
            subnet_cmds_available=snapshot.subnet_cmds_available,
        )

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        capabilities = self._mutation_capabilities(request, server)
        if isinstance(capabilities, HttpResponse):
            return capabilities
        form = self._form(server, capabilities, data=request.POST)
        options_formset, options_valid = _build_reservation_options_formset(request.POST)
        if form.is_valid() and options_valid:
            cleaned_data = form.cleaned_data
            try:
                identity = ReservationIdentity(cleaned_data["identifier_type"], cleaned_data["identifier"])
                values = _submitted_values(self.dhcp_version, cleaned_data, options_formset)
                outcome = _run_change(
                    request,
                    "Reservation created.",
                    lambda: reservation_edit.save_add(
                        server, self.dhcp_version, cleaned_data["subnet_cidr"], identity, values
                    ),
                    subject=f"Reservation {reservation_identity_label(identity)}",
                )
            except reservation_edit.EditConflict as exc:
                form.add_error(exc.field, exc.message)
            except ValueError:
                logger.exception("Could not build a DHCPv%s Reservation from the form", self.dhcp_version)
                messages.error(request, "The Reservation could not be created. See server logs.")
            else:
                if outcome is not None:
                    _warn_pool_facts(request, outcome.warnings)
                    if outcome.application == "applied":
                        facts = reservation_edit.after_apply(
                            server,
                            outcome,
                            request.user,
                            request=request,
                            sync_to_netbox=bool(cleaned_data.get("sync_to_netbox")),
                        )
                        show_reservation_side_effects(request, facts)
                        _show_applied_details(request, outcome)
                    return redirect(self._return_url(server))
        snapshot = subnet_catalogue.display(server, self.dhcp_version)
        show_notices(request, notice(snapshot))
        form.offer_subnets(snapshot.subnet_choices)
        return self._render(
            request,
            server,
            form,
            options_formset,
            capabilities,
            subnet_cmds_available=snapshot.subnet_cmds_available,
        )


class _ReservationEditView(_ReservationMutationView):
    form_action = "Edit"

    def _render(
        self,
        request: HttpRequest,
        server: Server,
        form: Any,
        options_formset: Any,
        capabilities: ReservationCapabilities | None,
        **context: Any,
    ) -> HttpResponse:
        # The Subnet field is disabled, so the preview request carries the Subnet in its URL.
        query = urlencode({"subnet_cidr": form.initial["subnet_cidr"]})
        return super()._render(
            request, server, form, options_formset, capabilities, published_name_query=query, **context
        )

    def get(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        if refusal := _client_settings_refusal(server, self.dhcp_version):
            messages.error(request, refusal)
            return redirect(self._return_url(server))
        identity = reservation_identity_from_request(request, self.dhcp_version)
        catalogue = subnet_catalogue.display(server, self.dhcp_version)
        reservation = _target_or_redirect(
            request, server, self.dhcp_version, subnet_id, identity, self._return_url(server), notice(catalogue)
        )
        if isinstance(reservation, HttpResponse):
            return reservation
        show_notices(request, notice(catalogue))
        state = reservation_edit.form_state(reservation, catalogue)
        capabilities = _display_capabilities(server, self.dhcp_version)
        form = self._form_for(server, state, capabilities)
        form.offer_subnets(catalogue.subnet_choices)
        return self._render(
            request,
            server,
            form,
            forms.ReservationOptionsFormSet(initial=state.options_initial, prefix="options"),
            capabilities,
            user_context=reservation.user_context,
        )

    def post(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        identity = reservation_identity_from_request(request, self.dhcp_version)
        return_url = self._return_url(server)
        try:
            reservation_edit.check_token(
                request.POST.get("managed_fingerprint", ""), self.dhcp_version, subnet_id, identity
            )
        except ReservationConflict as exc:
            form = self._form(
                server, None, data=request.POST, initial={"subnet_cidr": request.POST.get("subnet_cidr", "")}
            )
            form.add_error(None, f"{exc} Reload the form and try again.")
            options_formset, _valid = _build_reservation_options_formset(request.POST)
            return self._render(request, server, form, options_formset, None)
        capabilities = self._mutation_capabilities(request, server)
        if isinstance(capabilities, HttpResponse):
            return capabilities
        catalogue = subnet_catalogue.display(server, self.dhcp_version)
        # The disabled fields take their values from the initial data. The fingerprint check under the lock guards
        # the write.
        current = _target_or_redirect(request, server, self.dhcp_version, subnet_id, identity, return_url)
        if isinstance(current, HttpResponse):
            return current
        state = reservation_edit.form_state(current, catalogue)
        form = self._form(server, capabilities, data=request.POST, initial=state.initial)
        form.offer_subnets(catalogue.subnet_choices)
        for field in ("subnet_cidr", "identifier_type", "identifier"):
            form.fields[field].disabled = True
        options_formset, options_valid = _build_reservation_options_formset(request.POST)
        if form.is_valid() and options_valid:
            cleaned_data = form.cleaned_data
            try:
                values = _submitted_values(self.dhcp_version, cleaned_data, options_formset)
                outcome = _run_change(
                    request,
                    "Reservation updated.",
                    lambda: reservation_edit.save_edit(
                        server, self.dhcp_version, subnet_id, identity, cleaned_data["managed_fingerprint"], values
                    ),
                    subject=f"Reservation {reservation_identity_label(identity)}",
                )
            except reservation_edit.EditConflict as exc:
                if exc.live_state is not None:
                    data = form.data.copy()
                    data["managed_fingerprint"] = exc.live_state.initial["managed_fingerprint"]
                    form = self._form(server, capabilities, data=data, initial=exc.live_state.initial)
                    for field in ("subnet_cidr", "identifier_type", "identifier"):
                        form.fields[field].disabled = True
                    form.offer_subnets(catalogue.subnet_choices)
                form.add_error(exc.field, exc.message)
            except ReservationConflict as exc:
                form.add_error(None, f"{exc} Reload the form and try again.")
            except ValueError:
                logger.exception("Could not build the Reservation update from the form")
                messages.error(request, "The Reservation could not be updated. See server logs.")
            else:
                if outcome is not None:
                    if outcome.application == "applied":
                        facts = reservation_edit.after_apply(
                            server,
                            outcome,
                            request.user,
                            request=request,
                            sync_to_netbox=bool(cleaned_data.get("sync_to_netbox")),
                        )
                        show_reservation_side_effects(request, facts)
                        _show_applied_details(request, outcome)
                    return redirect(return_url)
        show_notices(request, notice(catalogue))
        return self._render(request, server, form, options_formset, capabilities, user_context=current.user_context)

    def _form_for(
        self,
        server: Server,
        state: reservation_edit.FormState,
        capabilities: ReservationCapabilities | None,
    ):
        form = self._form(server, capabilities, initial=state.initial)
        for field in ("subnet_cidr", "identifier_type", "identifier"):
            form.fields[field].disabled = True
        return form


class _ReservationDeleteView(_ReservationMutationView):
    template_name = "netbox_kea/server_reservation_delete.html"
    form_action = "Delete"

    def get(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        if refusal := _client_settings_refusal(server, self.dhcp_version):
            messages.error(request, refusal)
            return redirect(self._return_url(server))
        identity = reservation_identity_from_request(request, self.dhcp_version)
        reservation = _target_or_redirect(
            request, server, self.dhcp_version, subnet_id, identity, self._return_url(server)
        )
        if isinstance(reservation, HttpResponse):
            return reservation
        return render(
            request,
            self.template_name,
            {
                "object": server,
                "reservation_label": f"{reservation.identity.identifier_type} {reservation.identity.value}",
                "subnet_id": subnet_id,
                "dhcp_version": self.dhcp_version,
                "return_url": self._return_url(server),
                "tab": self.tab,
            },
        )

    def post(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        identity = reservation_identity_from_request(request, self.dhcp_version)
        return_url = self._return_url(server)
        capabilities = self._mutation_capabilities(request, server)
        if isinstance(capabilities, HttpResponse):
            return capabilities
        outcome = _run_change(
            request,
            "Reservation deleted.",
            lambda: config_write.delete_reservation(server, self.dhcp_version, subnet_id, identity),
            subject=f"Reservation {reservation_identity_label(identity)}",
        )
        if outcome is not None and outcome.application == "applied":
            facts = reservation_edit.after_apply(server, outcome, request.user, request=request)
            show_reservation_side_effects(request, facts)
            _show_applied_details(request, outcome)
        return redirect(return_url)


class ServerReservation4AddView(_ReservationAddView):
    """Create one typed DHCPv4 In-Subnet Reservation."""

    dhcp_version = 4
    form_class = forms.Reservation4Form


class ServerReservation6AddView(_ReservationAddView):
    """Create one typed DHCPv6 In-Subnet Reservation."""

    dhcp_version = 6
    form_class = forms.Reservation6Form


class ServerReservation4EditView(_ReservationEditView):
    """Edit one DHCPv4 Reservation by immutable Scope and Identity."""

    dhcp_version = 4
    form_class = forms.Reservation4Form


class ServerReservation6EditView(_ReservationEditView):
    """Edit one DHCPv6 Reservation by immutable Scope and Identity."""

    dhcp_version = 6
    form_class = forms.Reservation6Form


class ServerReservation4PublishedNameView(_ReservationPublishedNameView):
    """Preview the name that Kea publishes for a DHCPv4 Reservation hostname."""

    dhcp_version = 4


class ServerReservation6PublishedNameView(_ReservationPublishedNameView):
    """Preview the name that Kea publishes for a DHCPv6 Reservation hostname."""

    dhcp_version = 6


class ServerReservation4DeleteView(_ReservationDeleteView):
    """Delete one DHCPv4 Reservation by immutable Scope and Identity."""

    dhcp_version = 4
    form_class = forms.Reservation4Form


class ServerReservation6DeleteView(_ReservationDeleteView):
    """Delete one DHCPv6 Reservation by immutable Scope and Identity."""

    dhcp_version = 6
    form_class = forms.Reservation6Form
