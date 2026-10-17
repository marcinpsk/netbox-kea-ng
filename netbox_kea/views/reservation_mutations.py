# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import ipaddress
import logging
from dataclasses import replace
from typing import Any, Literal
from urllib.parse import urlencode

from django.contrib import messages
from django.core import signing
from django.core.exceptions import BadRequest, ValidationError
from django.db import DatabaseError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from netbox.views import generic

from .. import config_write, event_scope, forms, subnet_catalogue
from ..config_write import ReservationChangeOutcome
from ..constants import Family, IPAddressValue
from ..dhcp_options import DHCPOption
from ..ipam_reconciliation import RESERVATION, claim, claim_permissions
from ..models import Server
from ..pools import addresses_in_pools
from ..published_name import published_name, stored_hostname
from ..reservations import (
    ClearValue,
    FieldChange,
    InSubnetReservationScope,
    IPv4Reservation,
    IPv6Reservation,
    Reservation,
    ReservationCapabilities,
    ReservationChange,
    ReservationConflict,
    ReservationIdentity,
    SetValue,
    Unchanged,
    reservation_fingerprint,
    reservation_identifier_types,
)
from ..signals import reservation_created, reservation_deleted, reservation_updated
from ..subnet_catalogue import CatalogueSnapshot, CatalogueUnavailable, SubnetIdentity, VerifiedSubnet
from ..sync_permissions import sync_gate
from ._base import (
    _client_settings_error,
    _journal_applied,
    _KeaChangeMixin,
    _run_change,
    _safe_return_url,
    _signal_applied,
)
from .notices import Notice, load_target, notice, show_notices
from .reservations import (
    _RESERVATIONS_TAB,
    _build_reservation_options_formset,
    _display_capabilities,
    _live_capabilities,
)
from .workspace import ServerFamilyMixin

logger = logging.getLogger(__name__)

_FINGERPRINT_SALT = "netbox_kea.reservation-managed-facts"

_VERIFICATION_FAILED = "Kea applied the change, but NetBox Kea could not verify the final Reservation."

ReservationAction = Literal["created", "updated", "deleted"]

_SIGNALS = {
    "created": (reservation_created, "reservation_created"),
    "updated": (reservation_updated, "reservation_updated"),
    "deleted": (reservation_deleted, "reservation_deleted"),
}


def _warn_addresses_in_pools(
    request: HttpRequest,
    subnet: VerifiedSubnet,
    addresses: tuple[IPAddressValue, ...],
) -> None:
    """Add a non-blocking warning for each address in *addresses* that falls within a pool of *subnet*."""
    if not addresses:
        return
    if subnet.configuration is None:
        messages.warning(
            request,
            f"The pool overlap check did not run. The configuration of Subnet {subnet.cidr} is unavailable, "
            "so this Reservation was not checked against its pools.",
        )
        return
    for address, pool in addresses_in_pools(addresses, subnet.configuration.pools):
        messages.warning(
            request,
            f"IP {address} is within existing pool {pool.range}. "
            "Kea allows this. Reservations take priority over pool allocation.",
        )


def _in_subnet_scope(reservation: Reservation) -> InSubnetReservationScope:
    """Return the verified Subnet scope required by mutation routes."""
    if not isinstance(reservation.scope, InSubnetReservationScope):
        raise RuntimeError("Reservation mutation requires an In-Subnet Reservation.")
    return reservation.scope


def _options_from_formset(
    options_formset: Any,
    current: tuple[DHCPOption, ...] = (),
) -> tuple[DHCPOption, ...]:
    """Apply visible form changes while preserving unexposed option facts."""
    options: list[DHCPOption] = []
    remaining = list(enumerate(current))
    for row in getattr(options_formset, "cleaned_data", []) or []:
        if not row:
            continue
        original_index = row.get("original_index")
        existing: DHCPOption | None
        if original_index is not None:
            matching_position = next(
                (
                    position
                    for position, (current_index, _option) in enumerate(remaining)
                    if original_index == current_index
                ),
                None,
            )
            if matching_position is None:
                raise ValueError("The Reservation option source does not match the current Reservation.")
            _, existing = remaining.pop(matching_position)
            if row.get("DELETE"):
                continue
            if not row.get("name"):
                continue
            displayed_name = existing.name or (str(existing.code) if existing.code is not None else "")
            if row["name"] != displayed_name:
                existing = None
        else:
            if not row.get("name") or row.get("DELETE"):
                continue
            matching_positions = [
                position
                for position, (_current_index, option) in enumerate(remaining)
                if row["name"] == (option.name or (str(option.code) if option.code is not None else ""))
            ]
            if len(matching_positions) > 1:
                raise ValueError("The Reservation option name is ambiguous without its source position.")
            existing = remaining.pop(matching_positions[0])[1] if matching_positions else None
        submitted_always_send = bool(row.get("always_send"))
        if existing is not None:
            always_send = (
                existing.always_send if submitted_always_send == bool(existing.always_send) else submitted_always_send
            )
            options.append(
                replace(
                    existing,
                    data=row["data"],
                    always_send=always_send,
                )
            )
            continue
        options.append(
            DHCPOption(
                code=None,
                name=row["name"],
                space=None,
                data=row["data"],
                csv_format=None,
                always_send=True if submitted_always_send else None,
                never_send=None,
            )
        )
    return tuple(options)


def _options_initial(reservation: Reservation) -> list[dict[str, Any]]:
    return [
        {
            "original_index": index,
            "name": option.name or (str(option.code) if option.code is not None else ""),
            "data": option.data,
            "always_send": bool(option.always_send),
        }
        for index, option in enumerate(reservation.options)
    ]


def _signed_fingerprint(reservation: Reservation, suffix: str | None) -> str:
    scope = _in_subnet_scope(reservation)
    return signing.dumps(
        {
            "family": reservation.family,
            "subnet_id": scope.subnet.subnet_id,
            "identifier_type": reservation.identity.identifier_type,
            "identifier": reservation.identity.value,
            "fingerprint": reservation_fingerprint(reservation),
            # The form shows the published name under this suffix.
            "qualifying_suffix": suffix,
        },
        salt=_FINGERPRINT_SALT,
        compress=True,
    )


def _first_address(addresses: tuple[IPAddressValue, ...]) -> IPAddressValue | None:
    """Return the address that selects the Pool suffix: the first one, as for a synchronized Reservation."""
    return addresses[0] if addresses else None


def _shown_suffix(reservation: Reservation, catalogue: CatalogueSnapshot) -> str | None:
    """Return the suffix under which the edit form shows the hostname of *reservation*.

    None without a hostname, when the published name depends on the leased address, and when the suffix is unknown:
    the form then shows the stored hostname.
    """
    if not reservation.hostname:
        return None
    subnet = _in_subnet_scope(reservation).subnet
    if not reservation.addresses and catalogue.has_pool_qualifying_suffix(subnet):
        return None
    try:
        return catalogue.subnet_qualifying_suffix(subnet, _first_address(reservation.addresses))
    except CatalogueUnavailable:
        return None


class _UnknownSuffix(Exception):
    """The DDNS qualifying suffix at the submitted addresses is unknown, so no stored form of the entered name is."""


def _entered_suffix(catalogue: CatalogueSnapshot, subnet: SubnetIdentity, addresses: tuple[IPAddressValue, ...]) -> str:
    """Return the qualifying suffix of an entered hostname at the submitted *addresses*."""
    try:
        return catalogue.subnet_qualifying_suffix(subnet, _first_address(addresses))
    except CatalogueUnavailable as exc:
        raise _UnknownSuffix(str(exc)) from exc


def _hostname_change(
    current: Reservation,
    entered: str,
    addresses: tuple[IPAddressValue, ...],
    shown_suffix: str | None,
    catalogue: CatalogueSnapshot,
) -> FieldChange[str]:
    """Return the hostname change that makes Kea publish the *entered* name at the submitted *addresses*.

    A name that publishes the same name as the current hostname leaves the stored hostname unchanged.
    """
    if not current.hostname and not entered:
        return Unchanged()
    if current.hostname and shown_suffix is None and _shown_suffix(current, catalogue) is None:
        if entered == current.hostname:
            return Unchanged()
        # With an unknown suffix, _entered_suffix() below refuses the changed name on the hostname field.
        if not current.addresses and catalogue.has_pool_qualifying_suffix(_in_subnet_scope(current).subnet):
            raise ReservationConflict(
                "A Pool of the Subnet sets the DDNS qualifying suffix, so the published name depends on the address."
                " Save an address first, then change the hostname."
            )
    # The token holds no suffix when the form showed no hostname; edit_reservation() refuses a changed Reservation.
    if current.hostname and shown_suffix is not None and shown_suffix != _shown_suffix(current, catalogue):
        raise ReservationConflict("The DDNS qualifying suffix of the Subnet changed after the edit form was opened.")
    suffix = _entered_suffix(catalogue, _in_subnet_scope(current).subnet, addresses)
    stored = stored_hostname(entered, suffix)
    if published_name(stored, suffix) == published_name(current.hostname, suffix):
        return Unchanged()
    return _change(current.hostname, stored, "")


def _stored_for(
    catalogue: CatalogueSnapshot, subnet: VerifiedSubnet, name: str, addresses: tuple[IPAddressValue, ...]
) -> str:
    """Return the hostname to store so that Kea publishes *name* at *addresses* in *subnet*."""
    if not name:
        return ""
    return stored_hostname(name, _entered_suffix(catalogue, subnet.identity, addresses))


def _payload_from_post(token: str, reservation: Reservation) -> dict[str, Any]:
    try:
        payload = signing.loads(token, salt=_FINGERPRINT_SALT, max_age=86_400)
    except signing.BadSignature as exc:
        raise ReservationConflict("The edit fingerprint is invalid or expired.") from exc
    scope = _in_subnet_scope(reservation)
    target = {
        "family": reservation.family,
        "subnet_id": scope.subnet.subnet_id,
        "identifier_type": reservation.identity.identifier_type,
        "identifier": reservation.identity.value,
    }
    if not isinstance(payload, dict) or any(payload.get(key) != value for key, value in target.items()):
        raise ReservationConflict("The edit fingerprint does not match this Reservation.")
    fingerprint = payload.get("fingerprint")
    suffix = payload.get("qualifying_suffix")
    if not isinstance(fingerprint, str) or not fingerprint or not isinstance(suffix, str | None):
        raise ReservationConflict("The edit fingerprint is invalid.")
    return payload


def _identity_from_request(request: HttpRequest, version: Family) -> ReservationIdentity:
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


def _identity_label(identity: ReservationIdentity) -> str:
    """Return how a message names the Reservation with *identity*."""
    return f"{identity.identifier_type} {identity.value}"


def _read_reservation_target(
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


def _live_target(
    server: Server, version: Family, subnet_id: int, identity: ReservationIdentity
) -> tuple[Reservation, CatalogueSnapshot]:
    """Return one live Reservation and the Catalogue with configuration facts in which its Subnet is verified."""
    with subnet_catalogue.mutation(server, version) as scope:
        subnet = scope.find_by_id(subnet_id)
        catalogue = scope.snapshot
    if catalogue is None:
        raise RuntimeError("The Subnet Catalogue is unavailable.")
    return _read_reservation_target(server, version, subnet, catalogue, identity), catalogue


def _load_target(
    server: Server,
    version: Family,
    subnet_id: int,
    identity: ReservationIdentity,
) -> Reservation:
    """Return one live Reservation without invalidating the display snapshots."""
    observation = subnet_catalogue.read_identity(server, version)
    subnet = observation.find_by_id(subnet_id)
    return _read_reservation_target(server, version, subnet, observation.snapshot, identity)


def _record_applied(
    request: HttpRequest, server: Server, action: ReservationAction, outcome: ReservationChangeOutcome
) -> None:
    """Write the journal entry and send the signal of a Reservation change that Kea applied."""
    reservation = outcome.intended or outcome.previous
    if reservation is None:
        raise ValueError("An applied Reservation change needs the Reservation before or after it.")
    addresses = ", ".join(str(address) for address in reservation.addresses) or "no address"
    _journal_applied(request, server, f"Reservation {action}: {_identity_label(reservation.identity)}; {addresses}")
    signal, name = _SIGNALS[action]
    _signal_applied(
        request,
        signal,
        name,
        server=server,
        before=outcome.previous,
        after=outcome.intended,
        dhcp_version=reservation.family,
    )


def _after_applied(
    request: HttpRequest,
    server: Server,
    action: ReservationAction,
    outcome: ReservationChangeOutcome,
    *,
    sync_to_netbox: bool = False,
) -> None:
    """Run the side effects of a Reservation change that Kea applied. A failed side effect shows a separate error."""
    _record_applied(request, server, action, outcome)
    if outcome.persistence == "not-requested":
        messages.info(request, "Kea applied the change. Configuration persistence is disabled for this server.")
    if sync_to_netbox and outcome.intended is not None:
        _sync_to_netbox(request, server, action, outcome.intended, outcome.catalogue)
    if outcome.verification == "failed":
        messages.warning(request, _VERIFICATION_FAILED)


def _sync_to_netbox(
    request: HttpRequest,
    server: Server,
    action: ReservationAction,
    reservation: Reservation,
    catalogue: CatalogueSnapshot,
) -> None:
    """Claim the addresses of an applied Reservation in NetBox IPAM, when the manual Sync rule allows it."""
    if not reservation.addresses:
        messages.info(request, f"Reservation {action}. Nothing to sync to NetBox because it reserves no IP address.")
        return
    gate = sync_gate(request.user, claim_permissions(RESERVATION))
    if not gate.allowed:
        logger.warning("User %r requested a Reservation IPAM sync that the manual Sync rule refuses", request.user)
        messages.warning(request, f"Reservation {action}, but it was not synced to NetBox. {gate.reason}")
        return
    try:
        outcome = claim(server, reservation.family, [reservation], force=True, catalogue=catalogue)
    except event_scope.EventDispatchError:
        # The sync committed after Kea applied the Reservation, so the failed dispatch must not end the request.
        logger.exception("The events of the NetBox IPAM sync of a Reservation could not be dispatched")
        messages.error(
            request,
            f"Reservation {action}, and NetBox IPAM sync saved it, but NetBox could not dispatch the events of the"
            " sync; see server logs.",
        )
        return
    except (DatabaseError, ValidationError, ValueError, RuntimeError):
        logger.exception("Could not synchronize an applied Reservation change to NetBox IPAM")
        messages.error(request, "The Reservation changed, but NetBox IPAM synchronization failed.")
        return
    if any(not address.synchronized for address in outcome.addresses.values()):
        messages.warning(request, "The Reservation changed, but NetBox IPAM synchronization failed.")


def _change(current: Any, submitted: Any, empty: Any):
    if submitted == current:
        return Unchanged()
    if submitted == empty:
        return ClearValue()
    return SetValue(submitted)


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
    tab = _RESERVATIONS_TAB
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
        try:
            server.get_client(version=self.dhcp_version)
        except ValueError as exc:
            messages.error(request, _client_settings_error(server, exc))
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
        try:
            server.get_client(version=self.dhcp_version)
        except ValueError as exc:
            messages.error(request, _client_settings_error(server, exc))
            capabilities = None
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
                options = _options_from_formset(options_formset)
                outcome = _run_change(
                    request,
                    "Reservation created.",
                    lambda: config_write.add_reservation(
                        server,
                        self.dhcp_version,
                        cleaned_data["subnet_cidr"],
                        lambda subnet, catalogue: self._build(
                            request, cleaned_data, identity, options, subnet, catalogue
                        ),
                    ),
                    subject=f"Reservation {_identity_label(identity)}",
                )
            except _UnknownSuffix as exc:
                form.add_error("hostname", str(exc))
            except ValueError:
                logger.exception("Could not build a DHCPv%s Reservation from the form", self.dhcp_version)
                messages.error(request, "The Reservation could not be created. See server logs.")
            else:
                if outcome is not None:
                    if outcome.application == "applied":
                        _after_applied(
                            request,
                            server,
                            "created",
                            outcome,
                            sync_to_netbox=bool(cleaned_data.get("sync_to_netbox")),
                        )
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

    def _build(
        self,
        request: HttpRequest,
        cleaned_data: dict[str, Any],
        identity: ReservationIdentity,
        options: tuple[DHCPOption, ...],
        subnet: VerifiedSubnet,
        catalogue: CatalogueSnapshot,
    ) -> Reservation:
        """Return the Reservation of the form in the *subnet* that the scope read under the lock verified."""
        scope = InSubnetReservationScope(subnet.identity)
        hostname = cleaned_data.get("hostname", "")
        reservation: Reservation
        if self.dhcp_version == 4:
            ipv4_addresses = (
                (ipaddress.IPv4Address(cleaned_data["ip_address"]),) if cleaned_data.get("ip_address") else ()
            )
            reservation = IPv4Reservation(
                scope=scope,
                identity=identity,
                addresses=ipv4_addresses,
                hostname=_stored_for(catalogue, subnet, hostname, ipv4_addresses),
                options=options,
            )
        else:
            ipv6_addresses = tuple(
                ipaddress.IPv6Address(value) for value in (cleaned_data.get("ip_addresses") or "").split(",") if value
            )
            ipv6_prefixes = tuple(
                ipaddress.IPv6Network(value) for value in (cleaned_data.get("prefixes") or "").split(",") if value
            )
            reservation = IPv6Reservation(
                scope=scope,
                identity=identity,
                addresses=ipv6_addresses,
                delegated_prefixes=ipv6_prefixes,
                hostname=_stored_for(catalogue, subnet, hostname, ipv6_addresses),
                options=options,
            )
        _warn_addresses_in_pools(request, subnet, reservation.addresses)
        return reservation


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
        try:
            server.get_client(version=self.dhcp_version)
        except ValueError as exc:
            messages.error(request, _client_settings_error(server, exc))
            return redirect(self._return_url(server))
        identity = _identity_from_request(request, self.dhcp_version)
        catalogue = subnet_catalogue.display(server, self.dhcp_version)
        show_notices(request, notice(catalogue))
        reservation = load_target(
            server, "reservation_target", lambda: _load_target(server, self.dhcp_version, subnet_id, identity)
        )
        if isinstance(reservation, Notice):
            show_notices(request, reservation)
            return redirect(self._return_url(server))
        suffix = _shown_suffix(reservation, catalogue)
        capabilities = _display_capabilities(server, self.dhcp_version)
        form = self._form_for(server, reservation, suffix, capabilities)
        form.offer_subnets(catalogue.subnet_choices)
        return self._render(
            request,
            server,
            form,
            forms.ReservationOptionsFormSet(initial=_options_initial(reservation), prefix="options"),
            capabilities,
        )

    def post(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        identity = _identity_from_request(request, self.dhcp_version)
        return_url = self._return_url(server)
        capabilities = self._mutation_capabilities(request, server)
        if isinstance(capabilities, HttpResponse):
            return capabilities
        catalogue = subnet_catalogue.display(server, self.dhcp_version)
        # The disabled fields take their values from the initial data. The fingerprint check under the lock guards
        # the write.
        current = load_target(
            server, "reservation_target", lambda: _load_target(server, self.dhcp_version, subnet_id, identity)
        )
        if isinstance(current, Notice):
            show_notices(request, current)
            return redirect(return_url)
        suffix = _shown_suffix(current, catalogue)
        form = self._form(server, capabilities, data=request.POST, initial=self._initial(current, suffix))
        form.offer_subnets(catalogue.subnet_choices)
        for field in ("subnet_cidr", "identifier_type", "identifier"):
            form.fields[field].disabled = True
        options_formset, options_valid = _build_reservation_options_formset(request.POST)
        if form.is_valid() and options_valid:
            cleaned_data = form.cleaned_data
            try:
                payload = _payload_from_post(cleaned_data["managed_fingerprint"], current)

                def build(live: Reservation, live_catalogue: CatalogueSnapshot) -> ReservationChange:
                    options = _options_from_formset(options_formset, live.options)
                    return self._change(live, cleaned_data, options, payload["qualifying_suffix"], live_catalogue)

                outcome = _run_change(
                    request,
                    "Reservation updated.",
                    lambda: config_write.edit_reservation(
                        server, self.dhcp_version, subnet_id, identity, payload["fingerprint"], build
                    ),
                    subject=f"Reservation {_identity_label(identity)}",
                )
            except ReservationConflict as exc:
                form.add_error(None, f"{exc} Reload the form and try again.")
            except _UnknownSuffix as exc:
                form.add_error("hostname", str(exc))
            except ValueError:
                logger.exception("Could not build the Reservation update from the form")
                messages.error(request, "The Reservation could not be updated. See server logs.")
            else:
                if outcome is not None:
                    if outcome.application == "applied":
                        _after_applied(
                            request,
                            server,
                            "updated",
                            outcome,
                            sync_to_netbox=bool(cleaned_data.get("sync_to_netbox")),
                        )
                    return redirect(return_url)
        show_notices(request, notice(catalogue))
        return self._render(request, server, form, options_formset, capabilities)

    def _initial(self, reservation: Reservation, suffix: str | None) -> dict[str, Any]:
        scope = _in_subnet_scope(reservation)
        initial = {
            "subnet_cidr": scope.subnet.cidr,
            "identifier_type": reservation.identity.identifier_type,
            "identifier": reservation.identity.value,
            # Without a suffix the form shows the stored hostname.
            "hostname": reservation.hostname if suffix is None else published_name(reservation.hostname, suffix),
            "managed_fingerprint": _signed_fingerprint(reservation, suffix),
        }
        if reservation.family == 4:
            initial["ip_address"] = str(reservation.addresses[0]) if reservation.addresses else ""
        else:
            initial["ip_addresses"] = ",".join(str(address) for address in reservation.addresses)
            initial["prefixes"] = ",".join(str(prefix) for prefix in reservation.delegated_prefixes)
        return initial

    def _form_for(
        self,
        server: Server,
        reservation: Reservation,
        suffix: str | None,
        capabilities: ReservationCapabilities | None,
    ):
        form = self._form(server, capabilities, initial=self._initial(reservation, suffix))
        for field in ("subnet_cidr", "identifier_type", "identifier"):
            form.fields[field].disabled = True
        return form

    def _change(
        self,
        current: Reservation,
        cleaned_data: dict[str, Any],
        options: tuple[DHCPOption, ...],
        shown_suffix: str | None,
        catalogue: CatalogueSnapshot,
    ) -> ReservationChange:
        addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
        prefixes: tuple[ipaddress.IPv6Network, ...]
        if current.family == 4:
            addresses = (ipaddress.IPv4Address(cleaned_data["ip_address"]),) if cleaned_data.get("ip_address") else ()
            prefixes = current.delegated_prefixes
        else:
            addresses = tuple(
                ipaddress.IPv6Address(value) for value in (cleaned_data.get("ip_addresses") or "").split(",") if value
            )
            prefixes = tuple(
                ipaddress.IPv6Network(value) for value in (cleaned_data.get("prefixes") or "").split(",") if value
            )
        return ReservationChange(
            addresses=_change(current.addresses, addresses, ()),
            delegated_prefixes=_change(current.delegated_prefixes, prefixes, ()),
            hostname=_hostname_change(current, cleaned_data.get("hostname", ""), addresses, shown_suffix, catalogue),
            options=_change(current.options, options, ()),
        )


class _ReservationDeleteView(_ReservationMutationView):
    template_name = "netbox_kea/server_reservation_delete.html"
    form_action = "Delete"

    def get(self, request: HttpRequest, pk: int, subnet_id: int) -> HttpResponse:
        server = self.get_object(pk=pk)
        try:
            server.get_client(version=self.dhcp_version)
        except ValueError as exc:
            messages.error(request, _client_settings_error(server, exc))
            return redirect(self._return_url(server))
        identity = _identity_from_request(request, self.dhcp_version)
        reservation = load_target(
            server, "reservation_target", lambda: _load_target(server, self.dhcp_version, subnet_id, identity)
        )
        if isinstance(reservation, Notice):
            show_notices(request, reservation)
            return redirect(self._return_url(server))
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
        identity = _identity_from_request(request, self.dhcp_version)
        return_url = self._return_url(server)
        capabilities = self._mutation_capabilities(request, server)
        if isinstance(capabilities, HttpResponse):
            return capabilities
        outcome = _run_change(
            request,
            "Reservation deleted.",
            lambda: config_write.delete_reservation(server, self.dhcp_version, subnet_id, identity),
            subject=f"Reservation {_identity_label(identity)}",
        )
        if outcome is not None and outcome.application == "applied":
            _after_applied(request, server, "deleted", outcome)
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
