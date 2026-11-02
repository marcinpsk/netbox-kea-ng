# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Manual Sync: the claim of one Lease or one Reservation that an operator requests, with a typed outcome.

The caller reads the record from Kea and checks its own early gates. This module applies the verdict of the manual
Sync permission rule, checks that a Lease is a Current Lease, runs ``claim()`` and maps each of its failures to one
outcome. ``claim()`` stays the batch primitive of the DHCP Import and of the periodic job.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from django.core.exceptions import ValidationError
from django.db import DatabaseError

from . import event_scope
from .ipam_reconciliation import ClaimEventsFailed, ClaimResult, LeaseSubnetAbsent, claim
from .leases import Lease, is_current
from .subnet_catalogue import CatalogueSnapshot, CatalogueUnavailable

if TYPE_CHECKING:
    from .models import Server
    from .reservations import Reservation
    from .sync_permissions import SyncGate

logger = logging.getLogger(__name__)

NotRunReason = Literal["refused", "not-current", "stale", "unavailable", "failed"]


@dataclass(frozen=True)
class NotRun:
    """A Manual Sync that did not run, and why. *explanation* is the reason of the permission rule for ``refused``."""

    reason: NotRunReason
    explanation: str = ""


@dataclass(frozen=True)
class Ran:
    """A Manual Sync that ran: the outcome of each allocation, and whether NetBox dispatched the events of the claim."""

    result: ClaimResult
    events_dispatched: bool = True


ManualSyncOutcome = NotRun | Ran


def refusal(gate: SyncGate) -> NotRun | None:
    """Return the ``refused`` outcome when the manual Sync permission rule refuses, else None."""
    return None if gate.allowed else NotRun("refused", gate.reason)


def sync_lease(server: Server, lease: Lease, gate: SyncGate, *, force: bool) -> ManualSyncOutcome:
    """Claim one Lease that the caller read from Kea, when *gate* allows it and the Lease is a Current Lease."""
    if refused := refusal(gate):
        return refused
    if not is_current(lease, datetime.now(tz=timezone.utc)):
        return NotRun("not-current")
    return _run(server, f"Lease {lease.identity.address}", lambda: claim(server, lease.family, [lease], force))


def sync_reservation(
    server: Server, reservation: Reservation, catalogue: CatalogueSnapshot, gate: SyncGate
) -> ManualSyncOutcome:
    """Claim one Reservation in the Subnet Catalogue that verified it, when *gate* allows it."""
    if refused := refusal(gate):
        return refused
    return _run(
        server, "a Reservation", lambda: claim(server, reservation.family, [reservation], True, catalogue=catalogue)
    )


def _run(server: Server, what: str, run_claim: Callable[[], ClaimResult]) -> ManualSyncOutcome:
    """Run the claim of *what* and map each failure of the claim to its outcome."""
    try:
        result = run_claim()
    except ClaimEventsFailed as exc:
        logger.exception(
            "Server %s: the Manual Sync of %s committed, but NetBox did not dispatch its events", server.pk, what
        )
        return Ran(exc.result, events_dispatched=False)
    except event_scope.EventDispatchError:
        raise
    except LeaseSubnetAbsent:
        logger.warning("Server %s: %s names a Subnet ID that the Subnet Catalogue does not hold", server.pk, what)
        return NotRun("stale")
    except CatalogueUnavailable:
        logger.warning("Server %s: the Manual Sync of %s could not read a complete Subnet Catalogue", server.pk, what)
        return NotRun("unavailable")
    except (DatabaseError, ValidationError, RuntimeError):
        logger.exception("Server %s: the Manual Sync of %s failed", server.pk, what)
        return NotRun("failed")
    return Ran(result)
