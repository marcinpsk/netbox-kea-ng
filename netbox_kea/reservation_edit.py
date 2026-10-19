# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The form state and meaning of one operator-requested Reservation add or edit."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from django.core import signing

from . import config_write
from .config_write import ReservationChangeOutcome
from .constants import Family, IPAddressValue
from .dhcp_options import DHCPOption
from .pools import Pool, addresses_in_pools
from .published_name import published_name, stored_hostname
from .reservations import (
    ClearValue,
    FieldChange,
    InSubnetReservationScope,
    IPv4Reservation,
    IPv6Reservation,
    Reservation,
    ReservationChange,
    ReservationConflict,
    ReservationIdentity,
    SetValue,
    Unchanged,
    reservation_fingerprint,
)
from .subnet_catalogue import CatalogueSnapshot, CatalogueUnavailable, SubnetIdentity, VerifiedSubnet

if TYPE_CHECKING:
    from .models import Server

_FINGERPRINT_SALT = "netbox_kea.reservation-managed-facts"


@dataclass(frozen=True)
class EditToken:
    """Authenticated shown facts for one Reservation edit."""

    fingerprint: str
    qualifying_suffix: str | None


def check_token(token: str, family: Family, subnet_id: int, identity: ReservationIdentity) -> EditToken:
    """Check the signature, one-day age and route identity before any Kea read or lock.

    Raises:
        ReservationConflict: If the token is invalid, expired or belongs to another Reservation.

    """
    try:
        payload = signing.loads(token, salt=_FINGERPRINT_SALT, max_age=86_400)
    except signing.BadSignature as exc:
        raise ReservationConflict("The edit fingerprint is invalid or expired.") from exc
    target = {
        "family": family,
        "subnet_id": subnet_id,
        "identifier_type": identity.identifier_type,
        "identifier": identity.value,
    }
    if not isinstance(payload, dict) or any(payload.get(key) != value for key, value in target.items()):
        raise ReservationConflict("The edit fingerprint does not match this Reservation.")
    fingerprint = payload.get("fingerprint")
    suffix = payload.get("qualifying_suffix")
    if not isinstance(fingerprint, str) or not fingerprint or not isinstance(suffix, str | None):
        raise ReservationConflict("The edit fingerprint is invalid.")
    return EditToken(fingerprint, suffix)


@dataclass(frozen=True)
class OptionRow:
    """The parsed visible values and source position of one Reservation option row."""

    name: str
    data: str
    always_send: bool = False
    delete: bool = False
    original_index: int | None = None


@dataclass(frozen=True)
class SubmittedValues:
    """Parsed allocation, Published Name and option rows submitted by the operator."""

    addresses: tuple[IPAddressValue, ...] = ()
    delegated_prefixes: tuple[ipaddress.IPv6Network, ...] = ()
    hostname: str = ""
    option_rows: tuple[OptionRow, ...] = ()


@dataclass(frozen=True)
class FormState:
    """The shown form values, signed token and option rows of one observed Reservation."""

    initial: dict[str, Any]
    options_initial: tuple[dict[str, Any], ...]


class EditConflict(ReservationConflict):
    """A public form conflict, with its field and replacement live form state when needed."""

    def __init__(self, message: str, *, field: str | None = None, live_state: FormState | None = None) -> None:
        """Keep the safe message and the facts needed to present and retry the edit."""
        super().__init__(message)
        self.message = message
        self.field = field
        self.live_state = live_state


@dataclass(frozen=True)
class PoolOverlap:
    """A submitted Reservation address lies inside one allocation Pool."""

    address: IPAddressValue
    pool: Pool


@dataclass(frozen=True)
class PoolCheckUnavailable:
    """The live Subnet has no configuration facts for the pool overlap check."""

    subnet_cidr: str


@dataclass(frozen=True)
class AddOutcome(ReservationChangeOutcome):
    """A Reservation add outcome with the non-blocking pool check facts of its build."""

    warnings: tuple[PoolOverlap | PoolCheckUnavailable, ...] = ()


def _in_subnet_scope(reservation: Reservation) -> InSubnetReservationScope:
    """Return the verified Subnet scope required by mutation routes."""
    if not isinstance(reservation.scope, InSubnetReservationScope):
        raise RuntimeError("Reservation mutation requires an In-Subnet Reservation.")
    return reservation.scope


def _options_from_rows(
    rows: tuple[OptionRow, ...],
    current: tuple[DHCPOption, ...] = (),
) -> tuple[DHCPOption, ...]:
    """Apply visible form changes while preserving unexposed option facts."""
    options: list[DHCPOption] = []
    remaining = list(enumerate(current))
    for row in rows:
        original_index = row.original_index
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
            if row.delete:
                continue
            if not row.name:
                continue
            displayed_name = existing.name or (str(existing.code) if existing.code is not None else "")
            if row.name != displayed_name:
                existing = None
        else:
            if not row.name or row.delete:
                continue
            matching_positions = [
                position
                for position, (_current_index, option) in enumerate(remaining)
                if row.name == (option.name or (str(option.code) if option.code is not None else ""))
            ]
            if len(matching_positions) > 1:
                raise ValueError("The Reservation option name is ambiguous without its source position.")
            existing = remaining.pop(matching_positions[0])[1] if matching_positions else None
        submitted_always_send = bool(row.always_send)
        if existing is not None:
            always_send = (
                existing.always_send if submitted_always_send == bool(existing.always_send) else submitted_always_send
            )
            options.append(
                replace(
                    existing,
                    data=row.data,
                    always_send=always_send,
                )
            )
            continue
        options.append(
            DHCPOption(
                code=None,
                name=row.name,
                space=None,
                data=row.data,
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


def _entered_suffix(catalogue: CatalogueSnapshot, subnet: SubnetIdentity, addresses: tuple[IPAddressValue, ...]) -> str:
    """Return the qualifying suffix of an entered hostname at the submitted *addresses*."""
    try:
        return catalogue.subnet_qualifying_suffix(subnet, _first_address(addresses))
    except CatalogueUnavailable as exc:
        raise EditConflict(str(exc), field="hostname") from exc


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
    live_suffix = _shown_suffix(current, catalogue)
    if current.hostname and shown_suffix is None and live_suffix is None and entered == current.hostname:
        return Unchanged()
    subnet = _in_subnet_scope(current).subnet
    if not current.addresses and catalogue.has_pool_qualifying_suffix(subnet):
        raise EditConflict(
            "A Pool of the Subnet sets the DDNS qualifying suffix, so the published name depends on the address."
            " Save an address first, then change the hostname."
        )
    if current.hostname and shown_suffix is not None:
        if live_suffix is None:
            _entered_suffix(catalogue, subnet, current.addresses)
        if shown_suffix != live_suffix:
            raise EditConflict(
                f"The qualifying suffix differs from the one shown ({shown_suffix} → {live_suffix}). "
                "Check the name and save again.",
                live_state=form_state(current, catalogue),
            )
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


def _change(current: Any, submitted: Any, empty: Any):
    if submitted == current:
        return Unchanged()
    if submitted == empty:
        return ClearValue()
    return SetValue(submitted)


def form_state(reservation: Reservation, catalogue: CatalogueSnapshot) -> FormState:
    """Return the edit form values and authenticated shown facts of the observed Reservation."""
    scope = _in_subnet_scope(reservation)
    suffix = _shown_suffix(reservation, catalogue)
    initial: dict[str, Any] = {
        "subnet_cidr": scope.subnet.cidr,
        "identifier_type": reservation.identity.identifier_type,
        "identifier": reservation.identity.value,
        "hostname": reservation.hostname if suffix is None else published_name(reservation.hostname, suffix),
        "managed_fingerprint": _signed_fingerprint(reservation, suffix),
    }
    if reservation.family == 4:
        initial["ip_address"] = str(reservation.addresses[0]) if reservation.addresses else ""
    else:
        initial["ip_addresses"] = ",".join(str(address) for address in reservation.addresses)
        initial["prefixes"] = ",".join(str(prefix) for prefix in reservation.delegated_prefixes)
    return FormState(initial, tuple(_options_initial(reservation)))


def build_add(
    family: Family,
    identity: ReservationIdentity,
    values: SubmittedValues,
    subnet: VerifiedSubnet,
    catalogue: CatalogueSnapshot,
) -> Reservation:
    """Build the typed Reservation in the Subnet and Catalogue verified under the change lock."""
    scope = InSubnetReservationScope(subnet.identity)
    options = _options_from_rows(values.option_rows)
    hostname = _stored_for(catalogue, subnet, values.hostname, values.addresses)
    if family == 4:
        return IPv4Reservation(
            scope=scope,
            identity=identity,
            addresses=tuple(ipaddress.IPv4Address(address) for address in values.addresses),
            hostname=hostname,
            options=options,
        )
    return IPv6Reservation(
        scope=scope,
        identity=identity,
        addresses=tuple(ipaddress.IPv6Address(address) for address in values.addresses),
        delegated_prefixes=values.delegated_prefixes,
        hostname=hostname,
        options=options,
    )


def build_edit(
    current: Reservation,
    catalogue: CatalogueSnapshot,
    values: SubmittedValues,
    shown: EditToken,
) -> ReservationChange:
    """Build explicit managed changes from the submitted values and live facts under the lock."""
    options = _options_from_rows(values.option_rows, current.options)
    prefixes = current.delegated_prefixes if current.family == 4 else values.delegated_prefixes
    return ReservationChange(
        addresses=_change(current.addresses, values.addresses, ()),
        delegated_prefixes=_change(current.delegated_prefixes, prefixes, ()),
        hostname=_hostname_change(current, values.hostname, values.addresses, shown.qualifying_suffix, catalogue),
        options=_change(current.options, options, ()),
    )


def save_edit(
    server: Server,
    family: Family,
    subnet_id: int,
    identity: ReservationIdentity,
    token: str,
    values: SubmittedValues,
) -> ReservationChangeOutcome:
    """Authenticate the submitted edit before any Kea read, then save with the locked fingerprint check."""
    shown = check_token(token, family, subnet_id, identity)
    return config_write.edit_reservation(
        server,
        family,
        subnet_id,
        identity,
        shown.fingerprint,
        lambda current, catalogue: build_edit(current, catalogue, values, shown),
    )


def save_add(
    server: Server,
    family: Family,
    subnet_cidr: str,
    identity: ReservationIdentity,
    values: SubmittedValues,
) -> AddOutcome:
    """Build and save one Reservation under the change lock, with typed pool overlap facts."""
    warnings: list[PoolOverlap | PoolCheckUnavailable] = []

    def build(subnet: VerifiedSubnet, catalogue: CatalogueSnapshot) -> Reservation:
        reservation = build_add(family, identity, values, subnet, catalogue)
        if reservation.addresses:
            if subnet.configuration is None:
                warnings.append(PoolCheckUnavailable(subnet.cidr))
            else:
                warnings.extend(
                    PoolOverlap(address, pool)
                    for address, pool in addresses_in_pools(reservation.addresses, subnet.configuration.pools)
                )
        return reservation

    outcome = config_write.add_reservation(server, family, subnet_cidr, build)
    return AddOutcome(
        outcome.application,
        outcome.persistence,
        outcome.diagnostics,
        previous=outcome.previous,
        intended=outcome.intended,
        verification=outcome.verification,
        catalogue=outcome.catalogue,
        warnings=tuple(warnings),
    )
