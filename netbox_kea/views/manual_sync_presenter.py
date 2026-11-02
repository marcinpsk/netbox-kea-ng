# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one presentation of a Manual Sync outcome: the same words on every channel."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from django.contrib import messages
from django.http import HttpRequest
from typing_extensions import assert_never

from ..ipam_reconciliation import AddressClaim, PrefixClaim
from ..manual_sync import ManualSyncOutcome, NotRun, NotRunReason, Ran

Level = Literal["success", "info", "warning", "error"]

_SHOW: dict[Level, Callable[[HttpRequest, str], None]] = {
    "success": messages.success,
    "info": messages.info,
    "warning": messages.warning,
    "error": messages.error,
}

#: The level and the cause of each Manual Sync that did not run. ``refused`` names the reason of the permission rule.
_NOT_RUN: dict[NotRunReason, tuple[Level, str]] = {
    "not-current": ("warning", "Kea does not report it as a current lease."),
    "stale": ("warning", "it names a Subnet that the Kea configuration no longer holds."),
    "unavailable": ("warning", "NetBox could not read the Kea configuration."),
    "failed": ("error", "NetBox IPAM synchronization failed; see server logs."),
}

#: The words of each allocation outcome that synchronized the allocation.
_SYNCED_WORDS = {"created": "created", "updated": "updated", "unchanged": "already up to date"}

#: The level and the cause of each allocation outcome that did not synchronize the allocation.
_NOT_SYNCED: dict[str, tuple[Level, str]] = {
    "conflict": (
        "warning",
        "the object exists and is not Kea-managed, or its note leaves no room for the sync marker.",
    ),
    "disagreement": ("warning", "its NetBox IPAM owners disagree."),
    "not-applicable": ("info", "NetBox IPAM sync does not apply to it."),
    "error": ("error", "NetBox IPAM synchronization failed; see server logs."),
}


@dataclass(frozen=True)
class SyncLine:
    """One line of a Manual Sync outcome. A row reply shows the *allocation* lines as badges instead."""

    level: Level
    text: str
    allocation: bool = False


def manual_sync_lines(outcome: ManualSyncOutcome, subject: str) -> tuple[SyncLine, ...]:
    """Return the lines of *outcome* for *subject*, such as "Lease 192.0.2.10" or "Reservation"."""
    if isinstance(outcome, NotRun):
        if outcome.reason == "refused":
            return (SyncLine("warning", f"{subject} was not synced to NetBox. {outcome.explanation}"),)
        level, cause = _NOT_RUN[outcome.reason]
        return (SyncLine(level, f"{subject} was not synced to NetBox: {cause}"),)
    if isinstance(outcome, Ran):
        lines = _allocation_lines(outcome, subject)
        if not outcome.events_dispatched:
            lines.append(
                SyncLine(
                    "error",
                    f"{subject}: NetBox saved the sync but could not dispatch its events; see server logs."
                    " Check the addresses before you sync again.",
                )
            )
        return tuple(lines)
    assert_never(outcome)


def _allocation_lines(outcome: Ran, subject: str) -> list[SyncLine]:
    """Return one line for each allocation outcome, in the order of the first allocation that has it."""
    claims: dict[str, AddressClaim | PrefixClaim] = {**outcome.result.addresses, **outcome.result.prefixes}
    if not claims:
        return [SyncLine("info", f"{subject} reserves no IP address, so there is nothing to sync to NetBox.", True)]
    groups: dict[str, list[str]] = {}
    for name, result in claims.items():
        groups.setdefault("synced" if result.outcome in _SYNCED_WORDS else result.outcome, []).append(name)
    lines = []
    for kind, names in groups.items():
        if kind == "synced":
            done = ", ".join(f"{name} {_SYNCED_WORDS[claims[name].outcome]}" for name in names)
            lines.append(SyncLine("success", f"{subject} synced to NetBox: {done}.", True))
        else:
            level, cause = _NOT_SYNCED[kind]
            lines.append(SyncLine(level, f"{subject} was not synced to NetBox for {', '.join(names)}: {cause}", True))
    return lines


def show_manual_sync(request: HttpRequest, lines: Iterable[SyncLine]) -> None:
    """Queue each line as a message at its level."""
    for line in lines:
        _SHOW[line.level](request, line.text)
