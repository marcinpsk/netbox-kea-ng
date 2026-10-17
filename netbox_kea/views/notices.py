# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one rule that turns a Snapshot into a notice for the operator (ADR 0003, Presentation).

A view gets a :class:`Notice` from :func:`notice`, :func:`load_snapshot` or :func:`load_target` and hands it to a
channel: :func:`show_notices` on a full page, the Notice itself in a template, :class:`ServerNotices` on a combined
page, or :attr:`Notice.text` in a row badge or a plain-text reply.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, TypeVar, overload

import requests
from django.contrib import messages
from django.http import HttpRequest

from ..kea import KeaException, kea_error_message
from ..leases import LeaseAbsent, LeaseDiagnostic, LeaseFound, LeaseLookupFailed, LeaseSnapshot
from ..models import Server
from ..reservations import MalformedReservation, ReservationDiagnostic, ReservationSnapshot
from ..server_configuration import Diagnostic, ServerConfigurationSnapshot
from ..subnet_catalogue import CatalogueSnapshot
from ..utilities import diagnostic_reasons

logger = logging.getLogger(__name__)

SnapshotKind = Literal["catalogue", "configuration", "reservation", "lease"]
RecordKind = Literal["reservation", "lease"]
#: An exact load of one Lease or one Reservation, which is not a Snapshot.
TargetKind = Literal["lease_target", "reservation_target"]
NoticeKind = SnapshotKind | TargetKind
Snapshot = CatalogueSnapshot | ServerConfigurationSnapshot | ReservationSnapshot | LeaseSnapshot
#: What a read returns when it does not fail: a Snapshot, a display cache entry that holds one, or one record.
Read = TypeVar("Read")

#: The first line of an unavailable Notice, one per kind.
HEADLINES: dict[NoticeKind, str] = {
    "catalogue": "Failed to load subnet configuration from Kea.",
    "configuration": "Failed to load the Server Configuration from Kea.",
    "reservation": "Failed to load Reservations from Kea.",
    "lease": "Failed to load Leases from Kea.",
    "lease_target": "Failed to load the Lease from Kea.",
    "reservation_target": "Failed to load the Reservation from Kea.",
}
_RECORD_KINDS: frozenset[SnapshotKind] = frozenset({"reservation", "lease"})


@dataclass(frozen=True)
class Notice:
    """The level of one Snapshot or exact load and its typed diagnostics. A channel formats them."""

    kind: NoticeKind
    level: int
    diagnostics: tuple[Diagnostic | ReservationDiagnostic | LeaseDiagnostic, ...] = ()
    #: A raised read failed because Kea does not know the command, so its hook library is not loaded.
    unsupported_command: bool = False
    #: A raised read failed at the transport, so Kea did not answer.
    unreachable: bool = False
    #: Kea's answer to a refused read, from ``kea_error_message()``; empty for any other failure.
    reply: str = ""

    @property
    def unavailable(self) -> bool:
        """Return whether the Snapshot gave no usable facts."""
        return self.level == messages.ERROR

    @property
    def headline(self) -> str:
        """Return the headline of an unavailable Notice, else an empty string."""
        return HEADLINES[self.kind] if self.unavailable else ""

    @property
    def css(self) -> str:
        """Return the Bootstrap alert colour of the level."""
        return "danger" if self.unavailable else "warning"

    @property
    def lines(self) -> tuple[str, ...]:
        """Return the headline, Kea's answer, then each distinct message. A record list shows record diagnostics."""
        texts = () if self.kind in _RECORD_KINDS else tuple(diagnostic.message for diagnostic in self.diagnostics)
        return tuple(dict.fromkeys(text for text in (self.headline, self.reply, *texts) if text))

    @property
    def details(self) -> tuple[str, ...]:
        """Return the lines under the headline."""
        return tuple(line for line in self.lines if line != self.headline)

    @property
    def text(self) -> str:
        """Return every line in one string, for a row badge or a plain-text reply."""
        return " ".join(self.lines)


def _kind(snapshot: Snapshot) -> SnapshotKind:
    if isinstance(snapshot, CatalogueSnapshot):
        return "catalogue"
    if isinstance(snapshot, ServerConfigurationSnapshot):
        return "configuration"
    if isinstance(snapshot, ReservationSnapshot):
        return "reservation"
    if isinstance(snapshot, LeaseSnapshot):
        return "lease"
    raise TypeError(f"{type(snapshot).__name__} is not a Snapshot.")


def notice(snapshot: Snapshot) -> Notice | None:
    """Return an error for an unavailable Snapshot, a warning for a usable one with diagnostics, else None.

    A Snapshot that is incomplete only because more pages remain has no diagnostics, so it gives no Notice.
    """
    kind = _kind(snapshot)
    if isinstance(snapshot, (CatalogueSnapshot, ServerConfigurationSnapshot)) and snapshot.unavailable:
        return Notice(kind, messages.ERROR, snapshot.diagnostics)
    if snapshot.diagnostics:
        return Notice(kind, messages.WARNING, snapshot.diagnostics)
    return None


def failed_load(snapshot: CatalogueSnapshot | ServerConfigurationSnapshot) -> Notice:
    """Return the error Notice of a Snapshot that cannot give the facts that a load needs, with its diagnostics.

    An exact load cannot go on without them, so the Notice is an error also when the Snapshot is usable.
    """
    kind = _kind(snapshot)
    return Notice(kind, messages.ERROR, snapshot.diagnostics)


def _classified(server: Server, kind: RecordKind | TargetKind, read: Callable[[], Read]) -> Read | Notice:
    """Run *read*, and return an unavailable Notice when Kea refuses it, the transport fails or the reply is malformed.

    A Kea refusal carries Kea's answer. Every other exception still raises.
    """
    try:
        return read()
    except KeaException as exc:
        if exc.unsupported_command:
            logger.info("Server %s does not provide the %s read: its hook library is not loaded", server.pk, kind)
        else:
            logger.exception("Kea refused the %s read of server %s", kind, server.pk)
        return Notice(kind, messages.ERROR, unsupported_command=exc.unsupported_command, reply=kea_error_message(exc))
    # MalformedReply and MalformedLeaseResponse are RuntimeErrors; MalformedReservation is a ValueError.
    except (requests.RequestException, RuntimeError, MalformedReservation) as exc:
        logger.exception("Failed to read %s from server %s", kind, server.pk)
        return Notice(kind, messages.ERROR, unreachable=isinstance(exc, requests.RequestException))


def load_snapshot(server: Server, kind: RecordKind, read: Callable[[], Read]) -> Read | Notice:
    """Run a Reservation or Lease read, and return an unavailable Notice when Kea, the transport or the reply fails.

    A refused Lease query (``LeaseQueryGuardError``) still raises. A ``ValueError`` still raises, except
    ``MalformedReservation``, which is a malformed reply.
    """
    return _classified(server, kind, read)


@overload
def load_target(
    server: Server,
    kind: Literal["lease_target"],
    read: Callable[[], LeaseFound | LeaseAbsent | LeaseLookupFailed],
) -> LeaseFound | LeaseAbsent | Notice: ...


@overload
def load_target(server: Server, kind: Literal["reservation_target"], read: Callable[[], Read]) -> Read | Notice: ...


def load_target(server: Server, kind: TargetKind, read: Callable[[], object]) -> object:
    """Run an exact Lease or Reservation load, and return an unavailable Notice when Kea, the transport or the reply fails.

    A Lease that Kea returned but that cannot be read (``LeaseLookupFailed``) is a malformed reply. A ``ValueError``
    still raises, except ``MalformedReservation``, which is a malformed reply.
    """
    loaded = _classified(server, kind, read)
    if isinstance(loaded, LeaseLookupFailed):
        logger.warning(
            "Server %s returned a %s that could not be read: %s",
            server.pk,
            kind,
            diagnostic_reasons(loaded.diagnostics),
        )
        return Notice(kind, messages.ERROR, loaded.diagnostics)
    return loaded


def _worst_levels(notices: tuple[Notice | None, ...]) -> dict[str, int]:
    """Return each distinct line of *notices* once, in order, at the worst level that reported it."""
    levels: dict[str, int] = {}
    for item in notices:
        if item is None:
            continue
        for line in item.lines:
            levels[line] = max(levels.get(line, item.level), item.level)
    return levels


def inline_notices(*notices: Notice | None) -> list[tuple[str, tuple[str, ...]]]:
    """Group each distinct Snapshot message at its worst level for an inline partial."""
    levels = _worst_levels(notices)
    return [
        (css, lines)
        for level, css in ((messages.ERROR, "danger"), (messages.WARNING, "warning"))
        if (lines := tuple(line for line, found in levels.items() if found == level))
    ]


def show_notices(request: HttpRequest, *notices: Notice | None) -> None:
    """Show the Notices of one Server's Snapshots as Django messages."""
    for line, level in _worst_levels(notices).items():
        messages.add_message(request, level, line)


@dataclass
class ServerNotices:
    """The per-Server lists of a combined page. Each Server keeps its own lines, also when two Servers agree."""

    errors: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    #: The Notices with record diagnostics, for the page's record list.
    records: list[tuple[str, Notice]] = field(default_factory=list)

    def add(self, server: Server, *notices: Notice | None) -> None:
        """Add the Notices of the Snapshots of one Server."""
        for line, level in _worst_levels(notices).items():
            (self.errors if level == messages.ERROR else self.warnings).append((server.name, line))
        self.records.extend(
            (server.name, item)
            for item in notices
            if item is not None and item.kind in _RECORD_KINDS and item.diagnostics
        )

    @property
    def record_diagnostics(self) -> list[tuple[str, Diagnostic | ReservationDiagnostic | LeaseDiagnostic]]:
        """Return each record diagnostic with the name of its Server, for a record list."""
        return [(name, diagnostic) for name, item in self.records for diagnostic in item.diagnostics]
