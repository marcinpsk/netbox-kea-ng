# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Runtime Changes to the Leases and the DHCP service of a Server, and their typed outcome (ADR 0011).

An operation returns a ``RuntimeChangeOutcome`` when the change is live or can be live, and raises
``ChangeRejected`` when it is not live as far as NetBox can tell. No operation reads Kea after the send to classify
the change, and no operation runs a side effect: the caller runs them after ``applied``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from .change_outcome import (
    Application,
    ChangeRejected,
    FailurePolicy,
    before_change,
    build_client,
    mutate,
    read_before,
)
from .constants import Family
from .kea import KeaClient
from .leases import (
    FreshLease,
    Lease,
    LeaseAbsent,
    LeaseEdit,
    LeaseLookupFailed,
    LeaseRequest,
    ShownLease,
    fact_words,
    lease_edit_conflicts,
)

if TYPE_CHECKING:
    from .models import Server

_EDIT_UNUSABLE = "NetBox could not build the update from the Lease that Kea returned."


@dataclass(frozen=True)
class RuntimeChangeOutcome:
    """The result of a Runtime Change that is live or can be live."""

    application: Application
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class LeaseDeleteOutcome(RuntimeChangeOutcome):
    """The outcome of a Lease delete, with the Lease that the fresh read before the delete observed."""

    lease: Lease = field(kw_only=True)


def add_lease(server: Server, family: Family, request: LeaseRequest) -> RuntimeChangeOutcome:
    """Create the Lease of *request*. Kea supplies each fact that the request omits."""
    _require_family(family, request.family)
    with build_client(server, family) as client:
        return _outcome(client, family, lambda: client.lease_add(request))


def edit_lease(server: Server, family: Family, shown: ShownLease, edit: LeaseEdit) -> RuntimeChangeOutcome:
    """Write the fields of *edit* to the Lease *shown*, only while a fresh read agrees with the shown facts.

    The update sends the fresh Kea body with only the written fields changed. A Lease that is gone is never created
    again.

    Raises:
        ValueError: If *edit* writes no field, or *shown* is of another family.

    """
    _require_family(family, shown.identity.family)
    if not edit.written:
        raise ValueError("A Lease edit must write at least one field.")
    with build_client(server, family) as client:
        fresh = _as_shown(client, shown, edit, "the form")
        body = before_change(lambda: fresh.edited(edit), _EDIT_UNUSABLE)

        def send() -> None:
            if not client.lease_update(family, body):
                raise ChangeRejected(
                    "target-changed",
                    ("Kea reports that it was deleted or changed after the check. Reload the form and try again.",),
                )

        return _outcome(client, family, send)


def delete_lease(server: Server, family: Family, shown: ShownLease) -> LeaseDeleteOutcome:
    """Delete the Lease *shown*, only while a fresh read agrees with its kind, Subnet and client binding.

    Raises:
        ValueError: If *shown* is of another family.

    """
    _require_family(family, shown.identity.family)
    with build_client(server, family) as client:
        fresh = _as_shown(client, shown, LeaseEdit(), "the list")

        def send() -> None:
            if not client.lease_delete(fresh.lease.identity):
                raise ChangeRejected("target-changed", ("Kea reports that it no longer holds it.",))

        outcome = _outcome(client, family, send)
        return LeaseDeleteOutcome(outcome.application, outcome.diagnostics, lease=fresh.lease)


def wipe_leases(server: Server, family: Family, subnet_id: int) -> RuntimeChangeOutcome:
    """Delete every Lease of the Subnet with *subnet_id*. A Subnet without Leases is applied."""
    with build_client(server, family) as client:
        # The backend deletes the Leases one at a time, so a failure result can follow deleted Leases.
        return _outcome(client, family, lambda: client.lease_wipe(family, subnet_id))


def enable_dhcp(server: Server, family: Family) -> RuntimeChangeOutcome:
    """Start the DHCP service of *family* again after ``disable_dhcp``."""
    with build_client(server, family) as client:
        return _outcome(client, family, lambda: client.dhcp_enable(family), on_failure="reject")


def disable_dhcp(server: Server, family: Family, max_period: int | None) -> RuntimeChangeOutcome:
    """Stop the DHCP service of *family*, for *max_period* seconds, or until ``enable_dhcp`` when it is None."""
    with build_client(server, family) as client:
        return _outcome(client, family, lambda: client.dhcp_disable(family, max_period=max_period), on_failure="reject")


def _outcome(
    client: KeaClient,
    family: Family,
    send: Callable[[], None],
    *,
    on_failure: FailurePolicy = "unknown",
) -> RuntimeChangeOutcome:
    """Send the change and return its outcome. By default any failure result is unknown."""
    application, diagnostics = mutate(client, family, send, on_failure=on_failure)
    return RuntimeChangeOutcome(application, diagnostics)


def _as_shown(
    client: KeaClient, shown: ShownLease, edit: LeaseEdit, page: Literal["the form", "the list"]
) -> FreshLease:
    """Read the Lease *shown* again before the change. Reject the change when it does not agree with the shown facts."""
    fresh = read_before(lambda: client.lease_get_fresh(shown.identity))
    if isinstance(fresh, LeaseAbsent):
        not_created = ("The edit did not create it again.",) if edit.written else ()
        raise ChangeRejected("target-changed", ("Kea no longer holds it.", *not_created))
    if isinstance(fresh, LeaseLookupFailed):
        raise ChangeRejected("not-sent", ("Kea returned a lease that could not be read.",))
    conflicts = lease_edit_conflicts(shown, fresh.lease, edit)
    if conflicts:
        raise ChangeRejected(
            "target-changed",
            (f"Its {fact_words(conflicts)} changed in Kea after {page} was shown. Reload {page} and try again.",),
        )
    return fresh


def _require_family(family: Family, value: Family) -> None:
    if value != family:
        raise ValueError(f"A DHCPv{value} Lease cannot change on the DHCPv{family} service.")
