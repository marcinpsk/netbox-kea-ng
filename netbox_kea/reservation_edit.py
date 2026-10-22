# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The form state and meaning of one operator-requested Reservation add or edit."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Literal

from django.core import signing
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from extras.models import JournalEntry

from . import config_write, event_scope
from .config_write import ReservationChangeOutcome
from .constants import Family, IPAddressValue
from .dhcp_options import (
    DHCPOption,
    DHCPOptionChange,
    DHCPOptionConflict,
    DHCPOptionEdit,
    DHCPOptionNameChange,
    check_option_snapshot,
    merge_option_edit,
    option_data,
    parse_dhcp_options,
)
from .ipam_reconciliation import RESERVATION, ClaimResult, claim, claim_permissions
from .pools import Pool, addresses_in_pools
from .published_name import published_name, stored_hostname
from .reservation_transfer import ReservationImportProposal, resolve_import_proposal
from .reservations import (
    ClearValue,
    ExcludedPrefix,
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
from .signals import reservation_created, reservation_deleted, reservation_updated
from .subnet_catalogue import CatalogueSnapshot, CatalogueUnavailable, SubnetIdentity, VerifiedSubnet
from .sync_permissions import sync_gate

if TYPE_CHECKING:
    from .models import Server

logger = logging.getLogger(__name__)

_FINGERPRINT_SALT = "netbox_kea.reservation-managed-facts"


@dataclass(frozen=True)
class EditToken:
    """Authenticated shown facts for one Reservation edit."""

    fingerprint: str
    qualifying_suffix: str | None
    options: tuple[DHCPOption, ...]


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
    try:
        options = parse_dhcp_options(payload.get("options"))
    except ValueError as exc:
        raise ReservationConflict("The edit fingerprint has invalid DHCP Options.") from exc
    return EditToken(fingerprint, suffix, options)


@dataclass(frozen=True)
class OptionRow:
    """The parsed visible values and shown DHCP Option of one Reservation row."""

    name: str
    data: str
    always_send: bool = False
    delete: bool = False
    original_option: DHCPOption | None = None
    client_classes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SubmittedValues:
    """Parsed allocation, Published Name, DHCPv4 boot fields, client classes and option rows of the operator.

    *excluded_prefixes* are the submitted excluded prefixes; the build pairs each with the delegated prefix that holds it.
    """

    addresses: tuple[IPAddressValue, ...] = ()
    delegated_prefixes: tuple[ipaddress.IPv6Network, ...] = ()
    hostname: str = ""
    option_rows: tuple[OptionRow, ...] = ()
    client_classes: tuple[str, ...] = ()
    next_server: ipaddress.IPv4Address | None = None
    server_hostname: str = ""
    boot_file_name: str = ""
    excluded_prefixes: tuple[ipaddress.IPv6Network, ...] = ()


def class_text(classes: tuple[str, ...]) -> str:
    """Return the text of a client class field: the names, separated by commas."""
    return ", ".join(classes)


def class_names(text: str) -> tuple[str, ...]:
    """Return the names of a client class field, without the empty ones."""
    return tuple(name for name in (part.strip() for part in text.split(",")) if name)


def _class_change(live: tuple[str, ...], submitted: tuple[str, ...], field: str | None, owner: str) -> tuple[str, ...]:
    """Return the client classes that a class field sets: the live ones while it holds the text that showed them.

    Raises:
        EditConflict: If the field changes and the text cannot show a live name exactly, or names a class twice.

    """
    if submitted == class_names(class_text(live)):
        return live
    if any("," in name or name != name.strip() for name in live):
        raise EditConflict(
            f"A client class name of {owner} has a comma or surrounding spaces, so this field cannot change the "
            "classes without changing that name. Change them in Kea.",
            field=field,
        )
    if len(set(submitted)) != len(submitted):
        raise EditConflict(f"Enter each client class name of {owner} once.", field=field)
    return submitted


def excluded_prefix_pairs(
    delegated: tuple[ipaddress.IPv6Network, ...],
    excluded: tuple[ipaddress.IPv6Network, ...],
    live: tuple[ExcludedPrefix, ...] = (),
) -> tuple[ExcludedPrefix, ...]:
    """Pair each excluded prefix with the delegated prefix that holds it, in the order of *delegated*.

    An excluded prefix stays with its *live* delegated prefix while that one is still delegated. Any other one pairs
    with the one delegated prefix that holds it.

    Raises:
        EditConflict: If an excluded prefix is in no delegated prefix or in more than one, or a delegated prefix
            would exclude two prefixes.

    """
    paired: dict[ipaddress.IPv6Network, ipaddress.IPv6Network] = {}
    for prefix in excluded:
        # Kea keeps an exclusion for each delegation, so two delegations can exclude the same prefix.
        kept = next(
            (
                pair.delegated
                for pair in live
                if pair.excluded == prefix and pair.delegated in delegated and pair.delegated not in paired
            ),
            None,
        )
        holders = (
            [kept]
            if kept is not None
            else [held for held in delegated if prefix.prefixlen > held.prefixlen and prefix.subnet_of(held)]
        )
        if len(holders) != 1:
            where = "is not inside a delegated prefix" if not holders else "is inside more than one delegated prefix"
            raise EditConflict(
                f"The excluded prefix {prefix} {where} of this Reservation. "
                "Each excluded prefix must be a longer prefix inside exactly one delegated prefix.",
                field="excluded_prefixes",
            )
        if holders[0] in paired:
            raise EditConflict(
                f"The delegated prefix {holders[0]} can exclude one prefix only.", field="excluded_prefixes"
            )
        paired[holders[0]] = prefix
    return tuple(ExcludedPrefix(held, paired[held]) for held in delegated if held in paired)


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


def _option_edit(rows: tuple[OptionRow, ...], snapshot: tuple[DHCPOption, ...]) -> DHCPOptionEdit:
    """Translate parsed rows without using their position to identify an assignment."""
    changes: list[DHCPOptionChange] = []
    for row in rows:
        seen = row.original_option
        if row.delete:
            intended = None
        elif seen is None:
            if not row.name:
                continue
            classes = _class_change((), row.client_classes, None, f"DHCP Option '{row.name}'")
            intended = DHCPOption(
                None, row.name, None, row.data, None, True if row.always_send else None, None, classes
            )
        else:
            label = f"DHCP Option '{row.name or seen.name or seen.code}'"
            classes = _class_change(seen.client_classes, row.client_classes, None, label)
            intended = replace(seen, name=row.name or None, data=row.data, client_classes=classes)
            if bool(seen.always_send) != row.always_send:
                intended = replace(intended, always_send=row.always_send)
        if seen != intended:
            changes.append(DHCPOptionChange(seen, intended))
    return DHCPOptionEdit(snapshot, tuple(changes))


def _signed_fingerprint(reservation: Reservation, suffix: str | None) -> str:
    scope = _in_subnet_scope(reservation)
    return signing.dumps(
        {
            "family": reservation.family,
            "subnet_id": scope.subnet.subnet_id,
            "identifier_type": reservation.identity.identifier_type,
            "identifier": reservation.identity.value,
            "fingerprint": reservation_fingerprint(reservation),
            "options": [option_data(option) for option in reservation.options],
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
    # Without a shown suffix, the form showed the stored hostname, not a published name.
    if current.hostname and shown_suffix is None:
        if entered == current.hostname:
            return Unchanged()
        if live_suffix is not None:
            raise EditConflict(
                "The form showed the stored hostname, but the qualifying suffix is now known. "
                "Check the name and save again.",
                live_state=form_state(current, catalogue),
            )
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
    initial["client_classes"] = class_text(reservation.client_classes)
    if reservation.family == 4:
        initial["ip_address"] = str(reservation.addresses[0]) if reservation.addresses else ""
        initial["next_server"] = "" if reservation.next_server is None else str(reservation.next_server)
        initial["server_hostname"] = reservation.server_hostname
        initial["boot_file_name"] = reservation.boot_file_name
    else:
        initial["ip_addresses"] = ",".join(str(address) for address in reservation.addresses)
        initial["prefixes"] = ",".join(str(prefix) for prefix in reservation.delegated_prefixes)
        initial["excluded_prefixes"] = ",".join(str(pair.excluded) for pair in reservation.excluded_prefixes)
    options = tuple(
        {**option.form_initial(), "client_classes": class_text(option.client_classes)} for option in reservation.options
    )
    return FormState(initial, options)


def build_add(
    family: Family,
    identity: ReservationIdentity,
    values: SubmittedValues,
    subnet: VerifiedSubnet,
    catalogue: CatalogueSnapshot,
) -> Reservation:
    """Build the typed Reservation in the Subnet and Catalogue verified under the change lock."""
    scope = InSubnetReservationScope(subnet.identity)
    edit = _option_edit(values.option_rows, ())
    try:
        options = parse_dhcp_options(merge_option_edit(edit, [], family, catalogue.option_definitions))
    except (DHCPOptionConflict, DHCPOptionNameChange) as exc:
        raise EditConflict(exc.message) from exc
    hostname = _stored_for(catalogue, subnet, values.hostname, values.addresses)
    excluded = excluded_prefix_pairs(values.delegated_prefixes, values.excluded_prefixes)
    classes = _class_change((), values.client_classes, "client_classes", "this Reservation")
    if family == 4:
        return IPv4Reservation(
            scope=scope,
            identity=identity,
            addresses=tuple(ipaddress.IPv4Address(address) for address in values.addresses),
            hostname=hostname,
            options=options,
            client_classes=classes,
            next_server=values.next_server,
            server_hostname=values.server_hostname,
            boot_file_name=values.boot_file_name,
        )
    return IPv6Reservation(
        scope=scope,
        identity=identity,
        addresses=tuple(ipaddress.IPv6Address(address) for address in values.addresses),
        delegated_prefixes=values.delegated_prefixes,
        hostname=hostname,
        options=options,
        client_classes=classes,
        excluded_prefixes=excluded,
    )


def build_edit(
    current: Reservation,
    catalogue: CatalogueSnapshot,
    values: SubmittedValues,
    shown: EditToken,
) -> ReservationChange:
    """Build explicit managed changes from the submitted values and live facts under the lock."""
    try:
        check_option_snapshot(
            shown.options,
            tuple(row.original_option for row in values.option_rows if row.original_option is not None),
            current.family,
            catalogue.option_definitions,
        )
    except DHCPOptionConflict as exc:
        raise EditConflict(exc.message) from exc
    options = _option_edit(values.option_rows, shown.options)
    prefixes = current.delegated_prefixes if current.family == 4 else values.delegated_prefixes
    excluded = excluded_prefix_pairs(prefixes, values.excluded_prefixes, current.excluded_prefixes)
    return ReservationChange(
        addresses=_change(current.addresses, values.addresses, ()),
        delegated_prefixes=_change(current.delegated_prefixes, prefixes, ()),
        hostname=_hostname_change(current, values.hostname, values.addresses, shown.qualifying_suffix, catalogue),
        options=options,
        client_classes=_change(
            current.client_classes,
            _class_change(current.client_classes, values.client_classes, "client_classes", "this Reservation"),
            (),
        ),
        next_server=_change(current.next_server, values.next_server, None),
        server_hostname=_change(current.server_hostname, values.server_hostname, ""),
        boot_file_name=_change(current.boot_file_name, values.boot_file_name, ""),
        excluded_prefixes=_change(current.excluded_prefixes, excluded, ()),
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
        warnings.extend(_pool_warning_facts(reservation, subnet))
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


ReservationAction = Literal["created", "updated", "deleted"]
SideEffectStatus = Literal["succeeded", "failed", "events-failed", "not-applied"]


@dataclass(frozen=True)
class ClaimSkipped:
    """The reason an after-apply operation did not request an IPAM claim."""

    reason: Literal["not-applied", "not-requested", "nothing-to-sync", "permission"]
    explanation: str = ""


@dataclass(frozen=True)
class ClaimFailure:
    """A failed claim, or failed event dispatch after the claim committed."""

    reason: Literal["failed", "events-failed"]


@dataclass(frozen=True)
class AfterApplyFacts:
    """The independent journal, signal and IPAM claim facts after one Reservation change."""

    action: ReservationAction | None
    journal: SideEffectStatus
    signal: SideEffectStatus
    claim: ClaimResult | ClaimSkipped | ClaimFailure


def _pool_warning_facts(
    reservation: Reservation, subnet: VerifiedSubnet
) -> tuple[PoolOverlap | PoolCheckUnavailable, ...]:
    if not reservation.addresses:
        return ()
    if subnet.configuration is None:
        return (PoolCheckUnavailable(subnet.cidr),)
    return tuple(
        PoolOverlap(address, pool)
        for address, pool in addresses_in_pools(reservation.addresses, subnet.configuration.pools)
    )


def save_import(server: Server, proposal: ReservationImportProposal) -> AddOutcome:
    """Create one transfer proposal with its stored hostname and live pool overlap facts."""
    warnings: list[PoolOverlap | PoolCheckUnavailable] = []

    def build(subnet: VerifiedSubnet, _catalogue: CatalogueSnapshot) -> Reservation:
        reservation = resolve_import_proposal(proposal, subnet.identity)
        warnings.extend(_pool_warning_facts(reservation, subnet))
        return reservation

    outcome = config_write.add_reservation(server, proposal.family, proposal.subnet_cidr, build)
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


@dataclass(frozen=True)
class PoolOverlapSummary:
    """The bounded Reservation Identities with an address inside an allocation Pool."""

    identities: tuple[ReservationIdentity, ...]
    remaining: int


def pool_overlap_summary(outcomes: tuple[AddOutcome, ...], *, limit: int = 5) -> PoolOverlapSummary:
    """Count each applied scoped Reservation once, regardless of its addresses or Pools."""
    if limit < 1:
        raise ValueError("A pool overlap summary needs a positive limit.")
    identities = tuple(
        {
            (outcome.intended.family, outcome.intended.scope, outcome.intended.identity): outcome.intended.identity
            for outcome in outcomes
            if outcome.application == "applied"
            and outcome.intended is not None
            and any(isinstance(fact, PoolOverlap) for fact in outcome.warnings)
        }.values()
    )
    return PoolOverlapSummary(identities[:limit], max(0, len(identities) - limit))


def _journal_after_apply(
    server: Server, user: Any, action: ReservationAction, reservation: Reservation
) -> SideEffectStatus:
    addresses = ", ".join(str(address) for address in reservation.addresses) or "no address"
    identity = reservation.identity
    try:
        with event_scope.atomic():
            JournalEntry.objects.create(
                assigned_object=server,
                created_by=user,
                kind="info",
                comments=f"Reservation {action}: {identity.identifier_type} {identity.value}; {addresses}",
            )
    except event_scope.EventDispatchError:
        logger.exception("The journal entry committed but its events could not be dispatched")
        return "events-failed"
    except (DatabaseError, ValidationError, RuntimeError):
        logger.exception("Could not write the journal entry of an applied change to Server %s", server.pk)
        return "failed"
    return "succeeded"


def _signal_after_apply(
    server: Server, outcome: ReservationChangeOutcome, action: ReservationAction, reservation: Reservation, request: Any
) -> SideEffectStatus:
    signal = {"created": reservation_created, "updated": reservation_updated, "deleted": reservation_deleted}[action]
    try:
        responses = signal.send_robust(
            sender=None,
            server=server,
            before=outcome.previous,
            after=outcome.intended,
            dhcp_version=reservation.family,
            request=request,
        )
    except event_scope.EventDispatchError:
        logger.exception("The Reservation signal committed but its events could not be dispatched")
        return "events-failed"
    except (DatabaseError, ValidationError, ValueError, RuntimeError):
        logger.exception("Could not send the Reservation %s signal", action)
        return "failed"
    errors = [response for _receiver, response in responses if isinstance(response, Exception)]
    for error in errors:
        logger.error("A receiver of the reservation_%s signal failed", action, exc_info=error)
    if any(isinstance(error, event_scope.EventDispatchError) for error in errors):
        return "events-failed"
    return "failed" if errors else "succeeded"


class ImportSyncRefused(ValueError):
    """A requested import claim cannot pass the manual Sync permission rule."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class ImportContext:
    """One import's permission decision, bound to its Server and operator."""

    server: Server
    user: Any
    sync_to_netbox: bool = False
    _server_id: int = field(init=False, repr=False)
    _user_id: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.server.pk is None or self.user.pk is None:
            raise ValueError("An import needs a saved Server and user.")
        if self.sync_to_netbox:
            gate = sync_gate(self.user, claim_permissions(RESERVATION))
            if not gate.allowed:
                raise ImportSyncRefused(gate.reason)
        object.__setattr__(self, "_server_id", self.server.pk)
        object.__setattr__(self, "_user_id", self.user.pk)

    def check_target(self, server: Server, user: Any) -> None:
        """Refuse reuse of a permission decision for another Server or operator."""
        if server.pk != self._server_id or user.pk != self._user_id:
            raise ValueError("The import permission decision belongs to another Server or user.")


def prepare_import(server: Server, user: Any, *, sync_to_netbox: bool = False) -> ImportContext:
    """Check the optional claim permissions once, before the import sends any entry."""
    return ImportContext(server, user, sync_to_netbox)


def _claim_after_apply(
    server: Server, outcome: ReservationChangeOutcome, user: Any, requested: bool, context: ImportContext | None
) -> ClaimResult | ClaimSkipped | ClaimFailure:
    if not requested:
        return ClaimSkipped("not-requested")
    reservation = outcome.intended
    if reservation is None or not reservation.addresses:
        return ClaimSkipped("nothing-to-sync")
    try:
        if context is None:
            gate = sync_gate(user, claim_permissions(RESERVATION))
            if not gate.allowed:
                logger.warning("User %r requested a Reservation IPAM sync that the manual Sync rule refuses", user)
                return ClaimSkipped("permission", gate.reason)
        return claim(server, reservation.family, [reservation], force=True, catalogue=outcome.catalogue)
    except event_scope.EventDispatchError:
        logger.exception("The events of the NetBox IPAM sync of a Reservation could not be dispatched")
        return ClaimFailure("events-failed")
    except (DatabaseError, ValidationError, ValueError, RuntimeError):
        logger.exception("Could not synchronize an applied Reservation change to NetBox IPAM")
        return ClaimFailure("failed")


def after_apply(
    server: Server,
    outcome: ReservationChangeOutcome,
    user: Any,
    *,
    sync_to_netbox: bool = False,
    request: Any = None,
    import_context: ImportContext | None = None,
) -> AfterApplyFacts:
    """Run independent side effects only after Kea applied the change, outside its classification."""
    if outcome.application != "applied":
        return AfterApplyFacts(None, "not-applied", "not-applied", ClaimSkipped("not-applied"))
    if import_context is not None:
        import_context.check_target(server, user)
        sync_to_netbox = import_context.sync_to_netbox
    reservation = outcome.intended or outcome.previous
    if reservation is None:
        raise ValueError("An applied Reservation change needs the Reservation before or after it.")
    action: ReservationAction = (
        "deleted" if outcome.intended is None else "created" if outcome.previous is None else "updated"
    )
    journal = _journal_after_apply(server, user, action, reservation)
    signal = _signal_after_apply(server, outcome, action, reservation, request)
    return AfterApplyFacts(
        action, journal, signal, _claim_after_apply(server, outcome, user, sync_to_netbox, import_context)
    )
