# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Configuration Changes to a Server Configuration, and their typed outcome (ADR 0005, ADR 0012).

An operation returns a ``ConfigChangeOutcome`` when the change is live or can be live, and raises
``ChangeRejected`` when it is not live as far as NetBox can tell. Reservation writes are Configuration Changes too.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from django.db import DatabaseError, OperationalError, connection

from . import event_scope, server_configuration
from .change_outcome import Application, ChangeRejected, before_change, build_client, mutate, read_before
from .constants import Family, IPNetworkValue, Persistence
from .dhcp_options import DHCPOptionConflict, DHCPOptionEdit, DHCPOptionNameChange, OptionDefinition
from .kea import (
    CandidateConfiguration,
    CandidateTargetMissing,
    FreshReservation,
    KeaClient,
    KeaException,
    MalformedConfiguration,
    PoolAction,
    SharedNetworkEdit,
    SubnetEdit,
    SubnetFields,
    kea_error_message,
    subnet_network,
)
from .pools import Pool
from .read_failure import ReadFailure, attempt
from .reservations import (
    InSubnetReservationScope,
    MalformedReservation,
    Reservation,
    ReservationChange,
    ReservationConflict,
    ReservationIdentity,
    reservation_fingerprint,
    reservation_matches_intent,
)
from .subnet_catalogue import (
    CatalogueSnapshot,
    CatalogueUnavailable,
    MutationScope,
    NewSubnetIdentity,
    SharedNetworkMembership,
    VerifiedSubnet,
    mutation,
    read_identity,
)

if TYPE_CHECKING:
    from .models import Server

logger = logging.getLogger(__name__)

# How long an operation waits for another operation on the same Kea daemon.
LOCK_WAIT_SECONDS = 10.0

_LOCK_NOT_AVAILABLE = "55P03"


def _int4(text: str) -> int:
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:4], "big", signed=True)


# The first key of the two-key advisory lock form, which NetBox's one-key locks cannot reach.
_LOCK_CLASS = _int4("netbox_kea.config_write")


SUBNET_LIST_UNCONFIRMED = "NetBox could not confirm Kea's Subnet list, so it did not send the change. Try again later."
_CONFIG_TEST_UNUSABLE = "Kea did not return a usable reply to config-test."
_RESERVATION_UPDATE_UNUSABLE = "NetBox could not build the update from the Reservation that Kea returned."
# A live value that the edit form cannot show, so the operator cannot have seen it.
_UNSHOWABLE = "has a live value that the edit form cannot show."


def subnet_changed(subnet_id: int, cidr: str) -> str:
    """Return the message for a Subnet ID that no longer names the network *cidr* that the page showed."""
    return f"Subnet {subnet_id} ({cidr}) changed in Kea. Reload the page and try again."


@dataclass(frozen=True)
class ConfigChangeOutcome:
    """The result of a Configuration Change that is live or can be live."""

    application: Application
    persistence: Persistence
    diagnostics: tuple[str, ...] = ()


#: Whether a fresh read after an applied Reservation change shows what the change sent. "not-run": not applied.
Verification = Literal["verified", "failed", "not-run"]


@dataclass(frozen=True)
class ReservationChangeOutcome(ConfigChangeOutcome):
    """The outcome of a Reservation add, edit or delete (ADR 0012).

    *previous* is the Reservation that the read before the change observed, and *intended* the Reservation that the
    change sent; an add has no *previous* and a delete no *intended*. *catalogue* is the Subnet Catalogue in which the
    scope read verified the Subnet.
    """

    previous: Reservation | None = field(kw_only=True)
    intended: Reservation | None = field(kw_only=True)
    verification: Verification = field(kw_only=True)
    catalogue: CatalogueSnapshot = field(kw_only=True)


@dataclass(frozen=True)
class SubnetAddOutcome(ConfigChangeOutcome):
    """The outcome of a Subnet add, with the Subnet ID that the add sent."""

    subnet_id: int = field(kw_only=True)


def add_shared_network(server: Server, family: Family, name: str) -> ConfigChangeOutcome:
    """Add an empty Shared Network named *name*."""
    with build_client(server, family) as client, _serialized(client, family):
        if read_before(lambda: client.shared_network_exists(family, name)):
            raise ChangeRejected("not-sent", (f"Shared Network '{name}' already exists.",))
        application, diagnostics = mutate(
            client,
            family,
            lambda: client.network_add(family, name),
            on_failure=lambda: not client.shared_network_exists(family, name),
        )
        return _persisted(client, family, application, diagnostics)


def delete_shared_network(server: Server, family: Family, name: str) -> ConfigChangeOutcome:
    """Delete the Shared Network named *name*. Its member Subnets stay."""
    with build_client(server, family) as client, _serialized(client, family):
        if not read_before(lambda: client.shared_network_exists(family, name)):
            raise ChangeRejected("not-sent", (f"Shared Network '{name}' not found.",))
        application, diagnostics = mutate(
            client,
            family,
            lambda: client.network_del(family, name),
            on_failure=lambda: client.shared_network_exists(family, name),
        )
        return _persisted(client, family, application, diagnostics)


def add_subnet(
    server: Server,
    family: Family,
    cidr: str,
    subnet_id: int | None,
    fields: SubnetFields,
    shared_network: str | None,
) -> SubnetAddOutcome:
    """Add the Subnet *cidr*, and assign it to *shared_network* when one is named.

    *subnet_id* None lets the Subnet Catalogue allocate the ID. When the assignment does not apply, the operation
    deletes the new Subnet again.

    Raises:
        SubnetIdentityConflict: If a Subnet with the CIDR or with the operator's ID exists.
        SubnetIdExhausted: If no free Subnet ID remains.
        CatalogueUnavailable: If the Subnet list is incomplete, so NetBox cannot check the new identity.

    """
    with build_client(server, family) as client, _serialized(client, family):
        identity, application, diagnostics = _create_subnet(
            server, client, family, cidr, subnet_id, fields, shared_network
        )
        if application == "unknown":
            diagnostics = (*diagnostics, f"NetBox sent Subnet {identity.subnet_id} ({identity.cidr}).")
        elif shared_network is not None:
            application, diagnostics = _assign_new_subnet(server, client, family, identity, shared_network)
        persisted = client.persist(family)
        return SubnetAddOutcome(
            application, persisted.persistence, diagnostics + persisted.diagnostics, subnet_id=identity.subnet_id
        )


def _require_shared_network(client: KeaClient, family: Family, name: str, shown: bool | None) -> None:
    """Reject the change when Kea has no Shared Network *name*. *shown* is what the scope read shows, None: unknown."""
    if shown is None:
        shown = read_before(lambda: client.shared_network_exists(family, name))
    if not shown:
        raise ChangeRejected("not-sent", (f"Shared Network '{name}' not found.",))


def _create_subnet(
    server: Server,
    client: KeaClient,
    family: Family,
    cidr: str,
    requested_id: int | None,
    fields: SubnetFields,
    shared_network: str | None,
) -> tuple[NewSubnetIdentity, Application, tuple[str, ...]]:
    """Send the Subnet add under an identity from a live scope. Retry once when another Subnet took the allocated ID.

    Before that, reject a *shared_network* that Kea does not have.
    """
    with mutation(server, family) as scope:
        if shared_network is not None:
            _require_shared_network(client, family, shared_network, scope.has_shared_network(shared_network))
        identity = scope.prepare_creation(cidr, requested_id)
    taken = False

    def absent() -> bool:
        # Not live only while no Subnet has the ID and the CIDR that the add sent.
        nonlocal taken
        current = _subnet_now(server, family, identity.subnet_id)
        taken = current is not None and current.network != identity.network
        return current is None or taken

    def send() -> tuple[Application, tuple[str, ...]]:
        return mutate(
            client,
            family,
            lambda: client.subnet_add(family, identity.subnet_id, identity.cidr, fields),
            on_failure=absent,
        )

    try:
        application, diagnostics = send()
    except ChangeRejected:
        # The check read, not Kea's error text, shows that another writer took the allocated ID.
        if requested_id is not None or not taken:
            raise
        with mutation(server, family) as scope:
            identity = scope.prepare_creation(cidr)
        application, diagnostics = send()
    return identity, application, diagnostics


def _assign_new_subnet(
    server: Server, client: KeaClient, family: Family, identity: NewSubnetIdentity, name: str
) -> tuple[Application, tuple[str, ...]]:
    """Assign the new Subnet to the Shared Network *name*. Delete the Subnet again when the assignment did not apply."""
    subnet_id, network = identity.subnet_id, identity.network
    delete = _Undo(
        text=f"delete Subnet {subnet_id} again",
        send=lambda: client.subnet_del(family, subnet_id),
        not_live=lambda: _still_there(server, family, subnet_id, network),
        holds=lambda: _member_of(server, family, subnet_id, network, None),
    )
    assign = _Command(
        text=f"assign it to Shared Network '{name}'",
        send=lambda: client.network_subnet_add(family, name, subnet_id),
        not_live=lambda: _not_joined(server, family, subnet_id, name),
    )
    deleted = (
        f"NetBox added Subnet {subnet_id} ({identity.cidr}), but the assignment to Shared Network '{name}' did not "
        "apply, so NetBox deleted the Subnet again."
    )
    added = (f"add Subnet {subnet_id} ({identity.cidr})", delete)
    return _run_steps(client, family, (), assign, applied=(added,), rolled_back=deleted)


def edit_subnet(
    server: Server,
    family: Family,
    subnet_id: int,
    cidr: str,
    edit: SubnetEdit,
    *,
    shown: SubnetEdit,
    original_network: str | None,
    shared_network: str | None,
) -> ConfigChangeOutcome:
    """Set the fields of the Subnet with *subnet_id* that the edit form manages, and move it to *shared_network*.

    The operation acts only while that ID names the network *cidr* with the values *shown* in the Shared Network
    *original_network*: the Subnet that the operator saw. A Shared Network of None means none. The operation removes the
    Subnet from its Shared Network, adds it to the new one, and then updates the fields. When a step did not apply,
    it undoes the membership steps before it.
    """
    with build_client(server, family) as client, _serialized(client, family):
        with mutation(server, family) as scope:
            subnet = _subnet_as_seen(scope, subnet_id, cidr, membership=True)
            target_shown = None if shared_network is None else scope.has_shared_network(shared_network)
        current = subnet.shared_network.name if subnet.shared_network is not None else None
        if current != original_network:
            # Another writer moved the Subnet, so a move to *shared_network* would undo that change.
            raise ChangeRejected(
                "not-sent",
                (f"The Shared Network of Subnet {subnet_id} ({cidr}) changed in Kea. Reload the page and try again.",),
            )
        if shared_network is not None and shared_network != current:
            _require_shared_network(client, family, shared_network, target_shown)
        definition = read_before(lambda: client.subnet_definition(family, subnet_id))
        if definition.network != subnet.network:
            raise ChangeRejected("not-sent", (subnet_changed(subnet_id, cidr),))
        live = server_configuration.shown_subnet_definition(definition)
        if live is None:
            raise ChangeRejected("not-sent", (f"Subnet {subnet_id} ({cidr}) {_UNSHOWABLE}",))
        # A value that changed after the page showed it would go back to the old value with the update.
        if live.written_by(edit) != shown.written_by(edit):
            raise ChangeRejected("not-sent", (subnet_changed(subnet_id, cidr),))
        try:
            edited = definition.edited(edit)
        except MalformedConfiguration as exc:
            logger.warning("The Subnet that Kea returned cannot be edited", exc_info=True)
            raise ChangeRejected("not-sent", ("Kea returned a configuration that NetBox cannot edit safely.",)) from exc
        moves: list[_Step] = []
        if shared_network != current:
            if current is not None:
                moves.append(_leave(server, client, family, subnet, current))
            if shared_network is not None:
                moves.append(_join(server, client, family, subnet, shared_network, len(moves) + 1))
        update = _Command(
            text=f"update the fields of Subnet {subnet_id}",
            send=lambda: client.subnet_update(family, edited),
            # Not live while a fresh read returns the Subnet that the update started from.
            not_live=lambda: client.subnet_definition(family, subnet_id) == definition,
        )
        where = f"in Shared Network '{current}'" if current is not None else "outside all Shared Networks"
        moved_back = (
            f"A step of the change did not apply, so NetBox undid the steps before it. Subnet {subnet_id} ({cidr}) is "
            f"{where} again."
        )
        application, diagnostics = _run_steps(client, family, moves, update, rolled_back=moved_back)
        return _persisted(client, family, application, diagnostics)


def _leave(server: Server, client: KeaClient, family: Family, subnet: VerifiedSubnet, name: str) -> _Step:
    """Return step 1 of a move: remove *subnet* from the Shared Network *name*."""
    subnet_id, network = subnet.subnet_id, subnet.network
    return _Step(
        text=f"remove Subnet {subnet_id} from Shared Network '{name}'",
        send=lambda: client.network_subnet_del(family, name, subnet_id),
        not_live=lambda: _member_of(server, family, subnet_id, network, SharedNetworkMembership(name)),
        undo=_Undo(
            text=f"add Subnet {subnet_id} to Shared Network '{name}' to undo step 1",
            send=lambda: client.network_subnet_add(family, name, subnet_id),
            not_live=lambda: _not_joined(server, family, subnet_id, name),
            holds=lambda: _member_of(server, family, subnet_id, network, None),
        ),
    )


def _join(server: Server, client: KeaClient, family: Family, subnet: VerifiedSubnet, name: str, number: int) -> _Step:
    """Return step *number* of a move: add *subnet* to the Shared Network *name*."""
    subnet_id, network = subnet.subnet_id, subnet.network
    joined = SharedNetworkMembership(name)
    return _Step(
        text=f"add Subnet {subnet_id} to Shared Network '{name}'",
        send=lambda: client.network_subnet_add(family, name, subnet_id),
        not_live=lambda: _not_joined(server, family, subnet_id, name),
        undo=_Undo(
            text=f"remove Subnet {subnet_id} from Shared Network '{name}' to undo step {number}",
            send=lambda: client.network_subnet_del(family, name, subnet_id),
            not_live=lambda: _member_of(server, family, subnet_id, network, joined),
            holds=lambda: _member_of(server, family, subnet_id, network, joined),
        ),
    )


@dataclass(frozen=True)
class _Command:
    """One command of a multi-step change, and the fresh read that shows that the command is not live."""

    text: str
    send: Callable[[], None]
    not_live: Callable[[], bool]


@dataclass(frozen=True)
class _Undo(_Command):
    """A command that undoes an applied step. *holds* reads whether the target still holds what the step wrote."""

    holds: Callable[[], bool]


@dataclass(frozen=True)
class _Step(_Command):
    """A step that the operation undoes when a later step did not apply."""

    undo: _Undo


# The text of a step that applied, and the command that undoes it.
_Applied = tuple[str, _Undo]


def _run_steps(
    client: KeaClient,
    family: Family,
    steps: Sequence[_Step],
    last: _Command,
    *,
    applied: Sequence[_Applied] = (),
    rolled_back: str,
) -> tuple[Application, tuple[str, ...]]:
    """Send *steps* and then *last*, after the *applied* steps that already ran.

    After an unknown step, send nothing more. When a step did not apply, undo the applied steps, newest first.

    Raises:
        ChangeRejected: If a step did not apply and nothing that the change wrote is live. *rolled_back* comes
            first in the diagnostics when the operation undid a step.

    """
    done = list(applied)
    for step in steps:
        result = _send_step(client, family, done, step, rolled_back)
        if result is not None:
            return result
        done.append((step.text, step.undo))
    return _send_step(client, family, done, last, rolled_back) or ("applied", ())


def _send_step(
    client: KeaClient, family: Family, done: Sequence[_Applied], command: _Command, rolled_back: str
) -> tuple[Application, tuple[str, ...]] | None:
    """Send the step after *done*. Return None when it applied, and the result of the change when it did not."""
    text = f"Step {len(done) + 1}, {command.text}"
    try:
        application, diagnostics = mutate(client, family, command.send, on_failure=command.not_live)
    except ChangeRejected as rejection:
        return _roll_back(client, family, done, text, rejection, rolled_back)
    if application == "unknown":
        return "unknown", (*_applied_states(done), f"{text}: unknown.", *diagnostics)
    return None


def _roll_back(
    client: KeaClient,
    family: Family,
    done: Sequence[_Applied],
    failed: str,
    rejection: ChangeRejected,
    rolled_back: str,
) -> tuple[Application, tuple[str, ...]]:
    """Undo the *done* steps, newest first, after the step *failed* did not apply. Stop at the first undo that fails.

    Raises:
        ChangeRejected: If nothing that the change wrote is live: no step applied before, or every undo applied.

    """
    if not done:
        raise rejection
    states = [*_applied_states(done), f"{failed}: not applied.", *rejection.diagnostics]
    for number, (_text, undo) in enumerate(reversed(done), start=len(done) + 2):
        step = f"Step {number}, {undo.text}"
        problem = _undo(client, family, step, undo)
        if problem is not None:
            return "unknown", (*states, *problem)
        states.append(f"{step}: applied.")
    raise ChangeRejected(rejection.reason, (rolled_back, *rejection.diagnostics)) from rejection


def _applied_states(done: Sequence[_Applied]) -> tuple[str, ...]:
    return tuple(f"Step {number}, {text}: applied." for number, (text, _undo) in enumerate(done, start=1))


def _undo(client: KeaClient, family: Family, step: str, undo: _Undo) -> tuple[str, ...] | None:
    """Send *undo* only while its target holds what the step wrote. Return None when it applied, else its diagnostics."""
    try:
        holds = undo.holds()
    except CatalogueUnavailable:
        logger.warning("The read before a rollback did not confirm the Subnet", exc_info=True)
        return (f"{step}: not sent, because NetBox could not read the Subnet again.",)
    if not holds:
        return (f"{step}: not sent, because the Subnet changed in Kea.",)
    try:
        application, diagnostics = mutate(client, family, undo.send, on_failure=undo.not_live)
    except ChangeRejected as rejection:
        return (f"{step}: not applied.", *rejection.diagnostics)
    if application == "unknown":
        return (f"{step}: unknown.", *diagnostics)
    return None


def delete_subnet(server: Server, family: Family, subnet_id: int, cidr: str) -> ConfigChangeOutcome:
    """Delete the Subnet with *subnet_id*, only while that ID names the network *cidr*."""
    with build_client(server, family) as client, _serialized(client, family):
        with mutation(server, family) as scope:
            subnet = _subnet_as_seen(scope, subnet_id, cidr)
        application, diagnostics = mutate(
            client,
            family,
            lambda: client.subnet_del(family, subnet.subnet_id),
            on_failure=lambda: _still_there(server, family, subnet.subnet_id, subnet.network),
        )
        return _persisted(client, family, application, diagnostics)


def add_pool(server: Server, family: Family, subnet_id: int, cidr: str, pool: Pool) -> ConfigChangeOutcome:
    """Add *pool* to the Subnet with *subnet_id*, only while that ID names the network *cidr*."""
    return _change_pool(server, family, "add", subnet_id, cidr, pool)


def delete_pool(server: Server, family: Family, subnet_id: int, cidr: str, pool: Pool) -> ConfigChangeOutcome:
    """Delete *pool* from the Subnet with *subnet_id*, only while that ID names the network *cidr*."""
    return _change_pool(server, family, "del", subnet_id, cidr, pool)


def _change_pool(
    server: Server, family: Family, action: PoolAction, subnet_id: int, cidr: str, pool: Pool
) -> ConfigChangeOutcome:
    with build_client(server, family) as client, _serialized(client, family):
        with mutation(server, family) as scope:
            subnet = _subnet_as_seen(scope, subnet_id, cidr)
        _require_pool_state(subnet, action, pool)
        application, diagnostics = mutate(
            client,
            family,
            lambda: client.pool_change(family, action, subnet.subnet_id, subnet.declared_cidr, pool.range),
            # Not live: an added Pool is absent, or a deleted Pool is still there.
            on_failure=lambda: (pool in _pools_now(server, family, subnet)) == (action == "del"),
        )
        return _persisted(client, family, application, diagnostics)


def _persisted(
    client: KeaClient, family: Family, application: Application, diagnostics: tuple[str, ...]
) -> ConfigChangeOutcome:
    """Run the persist step and return the outcome of the change."""
    persisted = client.persist(family)
    return ConfigChangeOutcome(application, persisted.persistence, diagnostics + persisted.diagnostics)


def add_reservation(
    server: Server,
    family: Family,
    subnet_cidr: str,
    build: Callable[[VerifiedSubnet, CatalogueSnapshot], Reservation],
) -> ReservationChangeOutcome:
    """Create the Reservation that *build* returns for the Subnet *subnet_cidr*.

    *build* gets the Verified Subnet and the Catalogue of the scope read under the lock. An error that it raises
    propagates unchanged.
    """
    with build_client(server, family) as client, _serialized(client, family):
        subnet, catalogue = _reservation_subnet(
            server, family, lambda scope: scope.find_by_cidr(subnet_cidr), f"Subnet {subnet_cidr}"
        )
        reservation = build(subnet, catalogue)
        if reservation.family != family or reservation.scope != InSubnetReservationScope(subnet.identity):
            raise RuntimeError("The Reservation must belong to the Subnet that the scope read verified.")
        application, diagnostics = mutate(
            client, family, lambda: client.reservation_add(reservation), on_failure="unknown"
        )
        return _reservation_outcome(client, family, application, diagnostics, catalogue, None, reservation)


def edit_reservation(
    server: Server,
    family: Family,
    subnet_id: int,
    identity: ReservationIdentity,
    expected_fingerprint: str,
    build: Callable[[Reservation, CatalogueSnapshot], ReservationChange],
) -> ReservationChangeOutcome:
    """Apply the change that *build* returns to the Reservation with *identity* in the Subnet with *subnet_id*.

    The operation acts only while the managed facts of the Reservation have *expected_fingerprint*: the Reservation
    that the operator saw. *build* gets the Reservation and the Catalogue that the reads under the lock returned. An
    error that it raises propagates unchanged. The update keeps each Kea field that NetBox does not manage.
    """
    with build_client(server, family) as client, _serialized(client, family):
        subnet, catalogue = _reservation_subnet(
            server, family, lambda scope: scope.find_by_id(subnet_id), f"Subnet {subnet_id}"
        )
        fresh = _reservation_now(client, family, catalogue, subnet, identity, "The edit did not create it again.")
        if reservation_fingerprint(fresh.reservation) != expected_fingerprint:
            raise ChangeRejected(
                "target-changed", ("It changed after the edit form was opened. Reload the form and try again.",)
            )
        change = build(fresh.reservation, catalogue)
        if change.options is not None and change.options.changes and not catalogue.option_definitions_complete:
            target = change.options.changes[0]
            option = target.seen or target.intended
            label = option.name or str(option.code) if option is not None else "new option"
            raise ReservationConflict(f"DHCP Option '{label}' cannot be edited while its definitions are unavailable.")
        intended, record = _updated(fresh, change, catalogue.option_definitions)
        application, diagnostics = mutate(
            client, family, lambda: client.reservation_update(family, record), on_failure="unknown"
        )
        return _reservation_outcome(client, family, application, diagnostics, catalogue, fresh.reservation, intended)


def delete_reservation(
    server: Server, family: Family, subnet_id: int, identity: ReservationIdentity
) -> ReservationChangeOutcome:
    """Delete the Reservation with *identity* in the Subnet with *subnet_id*."""
    with build_client(server, family) as client, _serialized(client, family):
        subnet, catalogue = _reservation_subnet(
            server, family, lambda scope: scope.find_by_id(subnet_id), f"Subnet {subnet_id}"
        )
        current = _reservation_now(client, family, catalogue, subnet, identity).reservation
        scope = InSubnetReservationScope(subnet.identity)

        def send() -> None:
            if not client.reservation_del(family, scope, identity):
                raise ChangeRejected("target-changed", ("Kea reports that no host data source holds it.",))

        application, diagnostics = mutate(client, family, send, on_failure="unknown")
        return _reservation_outcome(client, family, application, diagnostics, catalogue, current, None)


def _reservation_subnet(
    server: Server, family: Family, find: Callable[[MutationScope], VerifiedSubnet | None], shown: str
) -> tuple[VerifiedSubnet, CatalogueSnapshot]:
    """Return the Verified Subnet that *find* returns from a live scope, and the Catalogue of that scope."""
    with mutation(server, family) as scope:
        try:
            subnet = find(scope)
        except CatalogueUnavailable as exc:
            raise ChangeRejected("not-sent", (SUBNET_LIST_UNCONFIRMED,)) from exc
        catalogue = scope.snapshot
    if subnet is None or catalogue is None:
        raise ChangeRejected(
            "target-changed", (f"{shown} is not in the Subnet list of Kea. Reload the page and try again.",)
        )
    return subnet, catalogue


def _reservation_now(
    client: KeaClient,
    family: Family,
    catalogue: CatalogueSnapshot,
    subnet: VerifiedSubnet,
    identity: ReservationIdentity,
    *not_changed: str,
) -> FreshReservation:
    """Read the Reservation with *identity* in *subnet* before the change. A Reservation that is gone rejects it."""
    scope = InSubnetReservationScope(subnet.identity)
    fresh = read_before(lambda: client.reservation_get_fresh(family, catalogue, scope, identity))
    if fresh is None:
        raise ChangeRejected("target-changed", ("Kea no longer holds it.", *not_changed))
    return fresh


def _updated(
    fresh: FreshReservation,
    change: ReservationChange,
    definitions: tuple[OptionDefinition, ...],
) -> tuple[Reservation, dict[str, Any]]:
    """Keep named option conflicts distinct from an unusable raw Reservation projection."""
    try:
        return fresh.updated(change, definitions)
    except (DHCPOptionConflict, DHCPOptionNameChange) as exc:
        raise ReservationConflict(exc.message) from exc
    except (MalformedReservation, ValueError, RuntimeError) as exc:
        logger.warning("Could not prepare a Reservation update", exc_info=True)
        raise ChangeRejected("not-sent", (_RESERVATION_UPDATE_UNUSABLE,)) from exc


def _reservation_outcome(
    client: KeaClient,
    family: Family,
    application: Application,
    diagnostics: tuple[str, ...],
    catalogue: CatalogueSnapshot,
    previous: Reservation | None,
    intended: Reservation | None,
) -> ReservationChangeOutcome:
    """Run the persist step, and the verification read after an applied change. The caller holds the lock."""
    persisted = client.persist(family)
    verification: Verification = "not-run"
    if application == "applied":
        verification = _verified(client, family, catalogue, previous, intended)
    return ReservationChangeOutcome(
        application,
        persisted.persistence,
        diagnostics + persisted.diagnostics,
        previous=previous,
        intended=intended,
        verification=verification,
        catalogue=catalogue,
    )


def _verified(
    client: KeaClient,
    family: Family,
    catalogue: CatalogueSnapshot,
    previous: Reservation | None,
    intended: Reservation | None,
) -> Verification:
    """Read the Reservation again and compare it with *intended*. A delete (*intended* None) expects no Reservation."""
    target = intended if intended is not None else previous
    if target is None:
        raise ValueError("A Reservation change needs the Reservation before or after it.")
    observed = attempt(
        "The verification read of a Reservation change",
        lambda: client.reservation_by_identity(family, catalogue, target.scope, target.identity),
    )
    if isinstance(observed, ReadFailure):
        return "failed"
    if observed is None or intended is None:
        return "verified" if observed is None and intended is None else "failed"
    return "verified" if reservation_matches_intent(observed, intended, catalogue.option_definitions) else "failed"


def set_subnet_options(
    server: Server, family: Family, subnet_id: int, cidr: str, edit: DHCPOptionEdit
) -> ConfigChangeOutcome:
    """Merge the typed option *edit* into the Subnet with *subnet_id*, only while that ID names the network *cidr*.

    Raises:
        DHCPOptionConflict: If the shown snapshot changed or an edited DHCP Option is missing or ambiguous.
        DHCPOptionNameChange: If the edit renames a coded DHCP Option.

    """
    with build_client(server, family) as client, _serialized(client, family):
        with mutation(server, family) as scope:
            subnet = _subnet_as_seen(scope, subnet_id, cidr)
        return _send_candidate(
            client,
            family,
            lambda candidate: candidate.set_subnet_options(subnet.subnet_id, subnet.network, edit),
            missing=subnet_changed(subnet_id, cidr),
        )


def set_server_options(server: Server, family: Family, edit: DHCPOptionEdit) -> ConfigChangeOutcome:
    """Merge the typed option *edit* into the server-global DHCP Options.

    Raises:
        DHCPOptionConflict: If the shown snapshot changed or an edited DHCP Option is missing or ambiguous.
        DHCPOptionNameChange: If the edit renames a coded DHCP Option.

    """
    return _read_modify_write(server, family, lambda candidate: candidate.set_global_options(edit), missing=None)


def add_option_definition(server: Server, family: Family, option_def: dict[str, Any]) -> ConfigChangeOutcome:
    """Add the Option Definition *option_def*. Kea's config-test refuses a duplicate."""
    return _read_modify_write(
        server, family, lambda candidate: candidate.add_option_definition(option_def), missing=None
    )


def delete_option_definition(server: Server, family: Family, code: int, space: str) -> ConfigChangeOutcome:
    """Delete the Option Definition with *code* in *space*."""
    return _read_modify_write(
        server,
        family,
        lambda candidate: candidate.delete_option_definition(code, space),
        missing=f"Option Definition {code} in space '{space}' not found.",
    )


def edit_shared_network(
    server: Server, family: Family, name: str, edit: SharedNetworkEdit, *, shown: SharedNetworkEdit
) -> ConfigChangeOutcome:
    """Set the fields of the Shared Network *name* that the edit form manages.

    The operation acts only while the live values of the Shared Network are *shown*: the values that the operator saw.
    """

    def change(candidate: CandidateConfiguration) -> None:
        live = server_configuration.shown_shared_network(
            server_configuration.candidate_snapshot(server, candidate), name
        )
        # The edit refuses a missing Shared Network first. The operation never sends a rejected candidate.
        candidate.edit_shared_network(name, edit)
        if live is None:
            raise ChangeRejected("not-sent", (f"Shared Network '{name}' {_UNSHOWABLE}",))
        if live != shown:
            raise ChangeRejected(
                "not-sent", (f"Shared Network '{name}' changed in Kea. Reload the page and try again.",)
            )

    return _read_modify_write(server, family, change, missing=f"Shared Network '{name}' not found.")


def _read_modify_write(
    server: Server, family: Family, edit: Callable[[CandidateConfiguration], None], *, missing: str | None
) -> ConfigChangeOutcome:
    """Edit the running configuration and send it back with config-set, all under the lock."""
    with build_client(server, family) as client, _serialized(client, family):
        return _send_candidate(client, family, edit, missing=missing)


def _send_candidate(
    client: KeaClient, family: Family, edit: Callable[[CandidateConfiguration], None], *, missing: str | None
) -> ConfigChangeOutcome:
    """Read the running configuration, edit it, test it and send it with config-set. The caller holds the lock.

    *missing* explains a target that *edit* does not find. None: *edit* names no target.
    """
    candidate = read_before(lambda: client.config_candidate(family))
    _edit(candidate, edit, missing)
    _test_before(client, family, candidate)
    # config-set commits and then runs the hook initialization, so no failure result proves it is not live.
    application, diagnostics = mutate(client, family, lambda: client.config_set(candidate), on_failure="unknown")
    return _persisted(client, family, application, diagnostics)


def _edit(
    candidate: CandidateConfiguration, edit: Callable[[CandidateConfiguration], None], missing: str | None
) -> None:
    """Run *edit* on the candidate. An error in the submitted rows propagates unchanged."""
    try:
        edit(candidate)
    except CandidateTargetMissing as exc:
        if missing is None:
            raise
        raise ChangeRejected("not-sent", (missing,)) from exc
    except MalformedConfiguration as exc:
        logger.warning("The configuration that Kea returned cannot be edited", exc_info=True)
        raise ChangeRejected("not-sent", ("Kea returned a configuration that NetBox cannot edit safely.",)) from exc


def _test_before(client: KeaClient, family: Family, candidate: CandidateConfiguration) -> None:
    """Send config-test of the candidate. A Kea without config-test skips it."""

    def test() -> None:
        try:
            client.config_test(candidate)
        except KeaException as exc:
            if exc.unsupported_command:
                logger.debug("config-test is not supported on DHCPv%s, so the candidate was not tested", family)
                return
            if client.forwarding_failed(exc, family) or exc.daemon_unreachable:
                raise
            logger.warning("config-test rejected a Configuration Change: %s", exc)
            raise ChangeRejected("config-test-rejected", (kea_error_message(exc),)) from exc

    before_change(test, _CONFIG_TEST_UNUSABLE)


@contextmanager
def _serialized(client: KeaClient, family: Family) -> Iterator[None]:
    """Hold the advisory lock of one Kea daemon and family until the transaction ends."""
    body_done = False
    try:
        with event_scope.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_setting('lock_timeout')")
                (previous,) = cursor.fetchone()
                # A lock_timeout without a unit is in milliseconds.
                cursor.execute("SELECT set_config('lock_timeout', %s::text, true)", [round(LOCK_WAIT_SECONDS * 1000)])
                try:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(%s, %s)", [_LOCK_CLASS, _int4(f"{family} {client.url}")]
                    )
                except OperationalError as exc:
                    if getattr(exc.__cause__, "sqlstate", None) != _LOCK_NOT_AVAILABLE:
                        raise
                    raise ChangeRejected(
                        "not-sent", ("Another change to this Kea server is still running. Try again later.",)
                    ) from exc
                cursor.execute("SELECT set_config('lock_timeout', %s, true)", [previous])
            acquired = time.monotonic()
            try:
                yield
            finally:
                held = time.monotonic() - acquired
                if held > LOCK_WAIT_SECONDS:
                    logger.warning(
                        "A Configuration Change held the DHCPv%s lock for %.1f s, longer than the %.1f s that "
                        "other changes to this Kea server wait before they are refused",
                        family,
                        held,
                        LOCK_WAIT_SECONDS,
                    )
            body_done = True
    except DatabaseError:
        if not body_done:
            raise
        # The transaction holds only the lock, and the change is already live in Kea.
        logger.warning("The lock transaction failed to end after the Configuration Change", exc_info=True)


def _subnet_as_seen(scope: MutationScope, subnet_id: int, cidr: str, *, membership: bool = False) -> VerifiedSubnet:
    """Return the Verified Subnet with *subnet_id* and the network *cidr*: the Subnet that the operator saw.

    *membership* True also requires a scope that confirms the Shared Network membership of the Subnet.
    """
    try:
        subnet = scope.find_with_membership(subnet_id) if membership else scope.find_by_id(subnet_id)
    except CatalogueUnavailable as exc:
        raise ChangeRejected("not-sent", (SUBNET_LIST_UNCONFIRMED,)) from exc
    if subnet is None or subnet.network != subnet_network(cidr, scope.family):
        raise ChangeRejected("not-sent", (subnet_changed(subnet_id, cidr),))
    return subnet


def _require_pool_state(subnet: VerifiedSubnet, action: PoolAction, pool: Pool) -> None:
    """Reject a Pool delete that the Subnet does not hold, or a Pool add that it holds. Without facts, Kea decides."""
    if subnet.configuration is None:
        return
    held = pool in subnet.configuration.pools
    if action == "del" and not held:
        problem = f"has no Pool {pool.range}"
    elif action == "add" and held:
        problem = f"already has Pool {pool.range}"
    else:
        return
    raise ChangeRejected(
        "not-sent", (f"Subnet {subnet.subnet_id} ({subnet.cidr}) {problem}. Reload the page and try again.",)
    )


def _subnet_now(server: Server, family: Family, subnet_id: int) -> VerifiedSubnet | None:
    """Read the Subnet with *subnet_id* in a fresh ``subnet{v}-list`` read. Return None when no Subnet has that ID."""
    return read_identity(server, family).find_by_id(subnet_id)


def _still_there(server: Server, family: Family, subnet_id: int, network: IPNetworkValue) -> bool:
    """Read in a fresh ``subnet{v}-list`` read whether *subnet_id* still names *network*."""
    current = _subnet_now(server, family, subnet_id)
    return current is not None and current.network == network


def _member_now(server: Server, family: Family, subnet_id: int) -> VerifiedSubnet | None:
    """Read the Subnet with *subnet_id* in a fresh ``subnet{v}-list`` read that confirms its Shared Network membership."""
    return read_identity(server, family).find_with_membership(subnet_id)


def _member_of(
    server: Server, family: Family, subnet_id: int, network: IPNetworkValue, membership: SharedNetworkMembership | None
) -> bool:
    """Read in a fresh ``subnet{v}-list`` read whether *subnet_id* names *network* and has the *membership*."""
    current = _member_now(server, family, subnet_id)
    return current is not None and current.network == network and current.shared_network == membership


def _not_joined(server: Server, family: Family, subnet_id: int, name: str) -> bool:
    """Read in a fresh ``subnet{v}-list`` read whether the Subnet with *subnet_id* is outside the Shared Network *name*."""
    current = _member_now(server, family, subnet_id)
    return current is None or current.shared_network != SharedNetworkMembership(name)


def _pools_now(server: Server, family: Family, subnet: VerifiedSubnet) -> tuple[Pool, ...]:
    """Return the Pools that *subnet* holds now in a fresh scope, and none when its ID is gone.

    Raises:
        CatalogueUnavailable: If the ID now names another network, or Kea did not return the configuration facts
            of the Subnet, so the Pools that the command reached are unknown.

    """
    with mutation(server, family) as scope:
        current = scope.find_by_id(subnet.subnet_id)
    if current is None:
        return ()
    # The ID now names another network, so this read cannot show the Pools of the Subnet that the command named.
    if current.network != subnet.network:
        raise CatalogueUnavailable(f"Subnet ID {subnet.subnet_id} now names {current.cidr}.")
    if current.configuration is None:
        raise CatalogueUnavailable("Kea did not return the configuration facts of the Subnet.")
    return current.configuration.pools
