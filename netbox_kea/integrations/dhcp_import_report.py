# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The vocabulary of a DHCP Import result: one entry for each Kea fact that a run wrote or did not write.

A written fact is created, updated or removed. A fact that was not written has a reason from the closed set
:class:`Reason`, and the reason alone gives its outcome (:data:`REASON_OUTCOME`), so the two cannot disagree.
It reads no database, so the mapper, the plan, the apply step and the stored result share it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class Kind(str, Enum):
    """The kind of Kea object that an entry describes."""

    SERVER = "server"
    OPTION_DEFINITION = "option_definition"
    CLIENT_CLASS = "client_class"
    SHARED_NETWORK = "shared_network"
    SUBNET = "subnet"
    POOL = "pool"
    RESERVATION = "reservation"
    OPTION = "option"


class Outcome(str, Enum):
    """What a run did with one Kea fact."""

    CREATED = "created"
    UPDATED = "updated"
    REMOVED = "removed"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    NOT_IMPORTED = "not_imported"


class Reason(str, Enum):
    """Why a run did not write one Kea fact."""

    PLUGIN_GAP = "plugin_gap"
    SUBNET_ID_CLASH = "subnet_id_clash"
    NOT_IN_SCOPE = "not_in_scope"
    INHERITED_FROM_SHARED_NETWORK = "inherited_from_shared_network"
    NO_MATCHING_INTERFACE = "no_matching_interface"
    INVALID_KEA_DATA = "invalid_kea_data"
    NO_PLUGIN_HOME = "no_plugin_home"
    PARENT_NOT_IMPORTED = "parent_not_imported"
    WRITE_FAILED = "write_failed"
    READ_FAILED = "read_failed"


KIND_LABELS: dict[Kind, str] = {
    Kind.SERVER: "Global configuration",
    Kind.OPTION_DEFINITION: "Option Definition",
    Kind.CLIENT_CLASS: "Client class",
    Kind.SHARED_NETWORK: "Shared Network",
    Kind.SUBNET: "Subnet",
    Kind.POOL: "Pool",
    Kind.RESERVATION: "Reservation",
    Kind.OPTION: "DHCP Option",
}
OUTCOME_LABELS: dict[Outcome, str] = {
    Outcome.CREATED: "Created",
    Outcome.UPDATED: "Updated",
    Outcome.REMOVED: "Removed",
    Outcome.UNSUPPORTED: "Unsupported",
    Outcome.SKIPPED: "Skipped",
    Outcome.NOT_IMPORTED: "Not imported",
}
REASON_LABELS: dict[Reason, str] = {
    Reason.PLUGIN_GAP: "The DHCP plugin cannot hold it",
    Reason.SUBNET_ID_CLASH: "Another Server or family holds this Subnet ID",
    Reason.NOT_IN_SCOPE: "Not in scope",
    Reason.INHERITED_FROM_SHARED_NETWORK: "Inherited from a Shared Network",
    Reason.NO_MATCHING_INTERFACE: "No matching interface",
    Reason.INVALID_KEA_DATA: "Invalid Kea data",
    Reason.NO_PLUGIN_HOME: "No DHCP plugin field by design",
    Reason.PARENT_NOT_IMPORTED: "Its parent object was not imported",
    Reason.WRITE_FAILED: "The write failed",
    Reason.READ_FAILED: "Kea could not be read in full",
}


def choices(labels: Mapping[Kind, str] | Mapping[Outcome, str] | Mapping[Reason, str]) -> list[tuple[str, str]]:
    """Return the model field choices of one vocabulary, in member order."""
    return [(member.value, label) for member, label in labels.items()]


REASON_OUTCOME: dict[Reason, Outcome] = {
    Reason.PLUGIN_GAP: Outcome.UNSUPPORTED,
    Reason.SUBNET_ID_CLASH: Outcome.UNSUPPORTED,
    Reason.NOT_IN_SCOPE: Outcome.NOT_IMPORTED,
    Reason.INHERITED_FROM_SHARED_NETWORK: Outcome.NOT_IMPORTED,
    Reason.NO_MATCHING_INTERFACE: Outcome.NOT_IMPORTED,
    Reason.INVALID_KEA_DATA: Outcome.NOT_IMPORTED,
    Reason.NO_PLUGIN_HOME: Outcome.NOT_IMPORTED,
    Reason.PARENT_NOT_IMPORTED: Outcome.SKIPPED,
    Reason.WRITE_FAILED: Outcome.SKIPPED,
    Reason.READ_FAILED: Outcome.SKIPPED,
}

WRITTEN: frozenset[Outcome] = frozenset({Outcome.CREATED, Outcome.UPDATED, Outcome.REMOVED})


@dataclass(frozen=True)
class ImportEntry:
    """One Kea fact of a run: its family, kind, Kea path and outcome, and the reason when it was not written."""

    family: int
    kind: Kind
    path: str
    outcome: Outcome
    reason: Reason | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        expected = None if self.outcome in WRITTEN else self.outcome
        if (REASON_OUTCOME[self.reason] if self.reason is not None else None) != expected:
            raise ValueError(f"Outcome {self.outcome} does not match reason {self.reason}")


def written(family: int, kind: Kind, path: str, outcome: Outcome) -> ImportEntry:
    """Return the entry of a fact that the run created, updated or removed."""
    return ImportEntry(family, kind, path, outcome)


def not_written(family: int, kind: Kind, path: str, reason: Reason, detail: str = "") -> ImportEntry:
    """Return the entry of a fact that the run did not write. The reason gives the outcome."""
    return ImportEntry(family, kind, path, REASON_OUTCOME[reason], reason, detail)


@dataclass(frozen=True)
class DroppedEntry:
    """A Kea configuration entry that the parse dropped as invalid, before any plan."""

    kind: Kind
    path: str
    detail: str
