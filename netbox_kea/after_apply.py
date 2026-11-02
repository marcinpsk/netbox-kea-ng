# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The side effects after Kea applied a change: the journal entry, the robust signal and their typed facts.

Each step runs only after ``applied``, outside the call that classifies the change (ADR 0011, ADR 0012). A step
returns its status and never raises for a failure that the change must survive, so each step runs independently.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from django.core.exceptions import ValidationError
from django.db import DatabaseError
from extras.models import JournalEntry

from . import event_scope
from .leases import DHCPv4LeaseRequest, DHCPv6LeaseRequest, Lease, LeaseRequest, shown_lease
from .manual_sync import ManualSyncOutcome, refusal, sync_lease
from .signals import lease_added, leases_deleted

if TYPE_CHECKING:
    from django.dispatch import Signal

    from .constants import Family
    from .models import Server
    from .sync_permissions import SyncGate

logger = logging.getLogger(__name__)

SideEffectStatus = Literal["succeeded", "failed", "events-failed", "not-applied"]


def write_journal(server: Server, user: Any, comments: str) -> SideEffectStatus:
    """Write the journal entry of an applied change in its own savepoint."""
    try:
        with event_scope.atomic():
            JournalEntry.objects.create(assigned_object=server, created_by=user, kind="info", comments=comments)
    except event_scope.EventDispatchError:
        logger.exception("The journal entry committed but its events could not be dispatched")
        return "events-failed"
    except (DatabaseError, ValidationError, RuntimeError):
        logger.exception("Could not write the journal entry of an applied change to Server %s", server.pk)
        return "failed"
    return "succeeded"


def send_signal(signal: Signal, name: str, **values: Any) -> SideEffectStatus:
    """Send *signal*, called *name* in the logs, to every receiver, and classify the receiver errors."""
    try:
        responses = signal.send_robust(sender=None, **values)
    except event_scope.EventDispatchError:
        logger.exception("The %s signal committed but its events could not be dispatched", name)
        return "events-failed"
    except (DatabaseError, ValidationError, ValueError, RuntimeError):
        logger.exception("Could not send the %s signal", name)
        return "failed"
    # send_robust() returns the error of each receiver instead of raising it.
    errors = [response for _receiver, response in responses if isinstance(response, Exception)]
    for error in errors:
        logger.error("A receiver of the %s signal failed", name, exc_info=error)
    if any(isinstance(error, event_scope.EventDispatchError) for error in errors):
        return "events-failed"
    return "failed" if errors else "succeeded"


LeaseAction = Literal["added", "deleted"]

#: Why a Lease add ran no Manual Sync: the operator did not ask for one, or the display read observed no Lease.
LeaseSyncSkip = Literal["not-requested", "not-read-back"]

#: The signal that each Lease action sends.
LEASE_SIGNAL_NAMES: dict[LeaseAction, str] = {"added": "lease_added", "deleted": "leases_deleted"}


@dataclass(frozen=True)
class LeaseAfterApplyFacts:
    """The independent journal, signal and Manual Sync facts after Kea applied Lease changes."""

    action: LeaseAction
    journal: SideEffectStatus
    signal: SideEffectStatus
    sync: ManualSyncOutcome | LeaseSyncSkip = "not-requested"


@dataclass(frozen=True)
class LeaseAdded:
    """One Lease that Kea created: the confirmed request and the Lease that the display read observed, or None."""

    creation: LeaseRequest
    observed: Lease | None
    #: The manual Sync verdict when the operator asked for a Manual Sync, else None.
    sync: SyncGate | None = None


@dataclass(frozen=True)
class LeasesDeleted:
    """The Leases whose deletion Kea confirmed, as the fresh read before each deletion observed them."""

    family: Family
    leases: tuple[Lease, ...]


def _journal_comments(
    action: LeaseAction,
    ip_addresses: list[str],
    hw_address: str = "",
    hostname: str = "",
    duid: str = "",
) -> str:
    """Return the journal text of a Lease change: the action, the addresses and the facts."""
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
    return "; ".join(parts)


def _send_lease_added(server: Server, creation: LeaseRequest, observed: Lease | None, request: Any) -> SideEffectStatus:
    return send_signal(
        lease_added,
        LEASE_SIGNAL_NAMES["added"],
        server=server,
        creation=creation,
        lease=observed,
        dhcp_version=creation.family,
        request=request,
    )


def _sync_added(server: Server, change: LeaseAdded) -> ManualSyncOutcome | LeaseSyncSkip:
    if change.sync is None:
        return "not-requested"
    # A refusal comes first: it does not depend on the display read.
    if change.observed is None:
        return refusal(change.sync) or "not-read-back"
    # force=False: a NetBox IP address that is not Kea-managed is skipped, not overwritten.
    return sync_lease(server, change.observed, change.sync, force=False)


def lease_after_apply(
    server: Server, user: Any, change: LeaseAdded | LeasesDeleted, *, request: Any
) -> LeaseAfterApplyFacts:
    """Write the journal entry, send the Lease signal and run the requested Manual Sync of an applied change."""
    if isinstance(change, LeaseAdded):
        creation = change.creation
        comments = _journal_comments(
            "added",
            [str(creation.address)],
            hw_address=creation.hw_address if isinstance(creation, DHCPv4LeaseRequest) else "",
            hostname=creation.hostname or "",
            duid=creation.duid if isinstance(creation, DHCPv6LeaseRequest) else "",
        )
        journal = write_journal(server, user, comments)
        signal = _send_lease_added(server, creation, change.observed, request)
        return LeaseAfterApplyFacts("added", journal, signal, _sync_added(server, change))
    if not change.leases:
        raise ValueError("An applied Lease delete needs the deleted Leases.")
    labels = [shown_lease(lease).label for lease in change.leases]
    journal = write_journal(server, user, _journal_comments("deleted", labels))
    signal = send_signal(
        leases_deleted,
        LEASE_SIGNAL_NAMES["deleted"],
        server=server,
        leases=change.leases,
        dhcp_version=change.family,
        request=request,
    )
    return LeaseAfterApplyFacts("deleted", journal, signal)


@dataclass
class LeaseImportAfterApply:
    """The side effects of a bulk Lease import: one lease_added signal for each applied row, one journal entry."""

    server: Server
    user: Any
    request: Any
    _created: list[LeaseRequest] = field(default_factory=list, init=False)
    _signals: list[SideEffectStatus] = field(default_factory=list, init=False)

    def row_applied(self, creation: LeaseRequest) -> None:
        """Send lease_added for one applied row, before the next row goes to Kea. The import reads nothing back."""
        self._created.append(creation)
        self._signals.append(_send_lease_added(self.server, creation, None, self.request))

    def finish(self) -> LeaseAfterApplyFacts | None:
        """Write one journal entry for the applied rows, or return None when Kea applied no row."""
        if not self._created:
            return None
        journal = write_journal(
            self.server, self.user, _journal_comments("added", [str(item.address) for item in self._created])
        )
        # As for the receivers of one signal: a failed dispatch shows first.
        signal: SideEffectStatus = next(
            (status for status in ("events-failed", "failed") if status in self._signals), "succeeded"
        )
        return LeaseAfterApplyFacts("added", journal, signal)
