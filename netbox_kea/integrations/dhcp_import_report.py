# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The vocabulary of a DHCP Import result: one entry for each Kea fact that a run wrote or did not write.

A written fact is created, updated or removed. A fact that was not written has a reason from the closed set
:class:`Reason`, and the reason alone gives its outcome (:data:`REASON_OUTCOME`), so the two cannot disagree.
An unsupported fact names the DHCP Plugin :class:`Capability` that it needs, when one decides it.
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
    PD_POOL = "pd_pool"
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
    IPAM_OWNERSHIP = "ipam_ownership"
    WRITE_FAILED = "write_failed"
    READ_FAILED = "read_failed"
    INCOMPLETE_OBSERVATION = "incomplete_observation"
    REMOVAL_BLOCKED = "removal_blocked"


KIND_LABELS: dict[Kind, str] = {
    Kind.SERVER: "Global configuration",
    Kind.OPTION_DEFINITION: "Option Definition",
    Kind.CLIENT_CLASS: "Client class",
    Kind.SHARED_NETWORK: "Shared Network",
    Kind.SUBNET: "Subnet",
    Kind.POOL: "Pool",
    Kind.PD_POOL: "Delegated-prefix Pool",
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
    Reason.IPAM_OWNERSHIP: "IPAM ownership kept the IPAM object unchanged",
    Reason.WRITE_FAILED: "The write failed",
    Reason.READ_FAILED: "Kea could not be read in full",
    Reason.INCOMPLETE_OBSERVATION: "Kea was not observed in full, so removal was suppressed",
    Reason.REMOVAL_BLOCKED: "Other rows still depend on it, so it was not removed",
}


class Capability(str, Enum):
    """A DHCP Plugin Capability that the write of a Kea fact needs, named after its #88 gap."""

    SHARED_NETWORK_OPTIONAL_PREFIX = "shared_network_optional_prefix"
    SUBNET_ID_PER_SERVER = "subnet_id_per_server"
    NAME_PER_SERVER = "name_per_server"
    SERVER_FAMILY = "server_family"
    FLEX_ID_IDENTIFIER = "flex_id_identifier"
    USER_CONTEXT = "user_context"
    OPTION_SPACES = "option_spaces"
    OPTION_CODE_16_BIT = "option_code_16_bit"
    OPTION_WITHOUT_DEFINITION = "option_without_definition"
    SERVER_ID_FIELDS = "server_id_fields"
    RELAY_ADDRESS_LIST = "relay_address_list"
    DHCP4O6_SUBNET_SELECTION = "dhcp4o6_subnet_selection"
    ADDRESS_REGISTRATION = "address_registration"
    STASH_AGENT_OPTIONS = "stash_agent_options"


#: The row of each capability in the #88 gap table.
GAPS: dict[Capability, int] = {
    Capability.SHARED_NETWORK_OPTIONAL_PREFIX: 1,
    Capability.SUBNET_ID_PER_SERVER: 2,
    Capability.NAME_PER_SERVER: 3,
    Capability.SERVER_FAMILY: 4,
    Capability.FLEX_ID_IDENTIFIER: 5,
    Capability.USER_CONTEXT: 6,
    Capability.OPTION_SPACES: 7,
    Capability.OPTION_CODE_16_BIT: 8,
    Capability.OPTION_WITHOUT_DEFINITION: 9,
    Capability.SERVER_ID_FIELDS: 10,
    Capability.RELAY_ADDRESS_LIST: 11,
    Capability.DHCP4O6_SUBNET_SELECTION: 12,
    Capability.ADDRESS_REGISTRATION: 13,
    Capability.STASH_AGENT_OPTIONS: 14,
}
_CAPABILITY_NAMES: dict[Capability, str] = {
    Capability.SHARED_NETWORK_OPTIONAL_PREFIX: "Shared Network without one enclosing Prefix",
    Capability.SUBNET_ID_PER_SERVER: "Subnet ID unique per DHCP server",
    Capability.NAME_PER_SERVER: "Name unique per DHCP server",
    Capability.SERVER_FAMILY: "DHCP server address family",
    Capability.FLEX_ID_IDENTIFIER: "flex-id Reservation identifier",
    Capability.USER_CONTEXT: "User context",
    Capability.OPTION_SPACES: "Kea option space names",
    Capability.OPTION_CODE_16_BIT: "DHCPv6 option codes above 255",
    Capability.OPTION_WITHOUT_DEFINITION: "DHCP Option without an Option Definition",
    Capability.SERVER_ID_FIELDS: "Full server-id",
    Capability.RELAY_ADDRESS_LIST: "Relay address list",
    Capability.DHCP4O6_SUBNET_SELECTION: "DHCPv4-over-DHCPv6 Subnet selection",
    Capability.ADDRESS_REGISTRATION: "Address registration",
    Capability.STASH_AGENT_OPTIONS: "Stashed relay agent options",
}
CAPABILITY_LABELS: dict[Capability, str] = {
    capability: f"{name} (#88 gap {GAPS[capability]})" for capability, name in _CAPABILITY_NAMES.items()
}


def choices(
    labels: Mapping[Kind, str] | Mapping[Outcome, str] | Mapping[Reason, str] | Mapping[Capability, str],
) -> list[tuple[str, str]]:
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
    Reason.IPAM_OWNERSHIP: Outcome.SKIPPED,
    Reason.WRITE_FAILED: Outcome.SKIPPED,
    Reason.READ_FAILED: Outcome.SKIPPED,
    Reason.INCOMPLETE_OBSERVATION: Outcome.SKIPPED,
    Reason.REMOVAL_BLOCKED: Outcome.SKIPPED,
}

WRITTEN: frozenset[Outcome] = frozenset({Outcome.CREATED, Outcome.UPDATED, Outcome.REMOVED})


@dataclass(frozen=True)
class ImportEntry:
    """One Kea fact of a run: its family, kind, Kea path and outcome, and the reason when it was not written.

    An unsupported fact names the missing :class:`Capability`, when one decides it.
    """

    family: int
    kind: Kind
    path: str
    outcome: Outcome
    reason: Reason | None = None
    detail: str = ""
    capability: Capability | None = None

    def __post_init__(self) -> None:
        expected = None if self.outcome in WRITTEN else self.outcome
        if (REASON_OUTCOME[self.reason] if self.reason is not None else None) != expected:
            raise ValueError(f"Outcome {self.outcome} does not match reason {self.reason}")
        if self.capability is not None and self.outcome != Outcome.UNSUPPORTED:
            raise ValueError(f"Only an unsupported entry names a capability, not {self.reason}")


def counted(count: int, singular: str, plural: str) -> str:
    """Return *count* with the singular or plural form of the phrase that follows it, for the detail of an entry."""
    return f"{count} {singular if count == 1 else plural}"


def written(family: int, kind: Kind, path: str, outcome: Outcome) -> ImportEntry:
    """Return the entry of a fact that the run created, updated or removed."""
    return ImportEntry(family, kind, path, outcome)


def not_written(family: int, kind: Kind, path: str, reason: Reason, detail: str = "") -> ImportEntry:
    """Return the entry of a fact that the run did not write. The reason gives the outcome."""
    return ImportEntry(family, kind, path, REASON_OUTCOME[reason], reason, detail)


def unsupported(family: int, kind: Kind, path: str, capability: Capability, detail: str) -> ImportEntry:
    """Return the entry of a fact that the run did not write because the installed DHCP plugin lacks *capability*."""
    return ImportEntry(family, kind, path, Outcome.UNSUPPORTED, Reason.PLUGIN_GAP, detail, capability)


def subnet_id_clash(family: int, kind: Kind, path: str, detail: str) -> ImportEntry:
    """Return the entry of a fact of a Subnet whose Kea subnet ID another Server or family holds in the DHCP plugin."""
    return ImportEntry(
        family, kind, path, Outcome.UNSUPPORTED, Reason.SUBNET_ID_CLASH, detail, Capability.SUBNET_ID_PER_SERVER
    )


@dataclass(frozen=True)
class DroppedEntry:
    """A Kea configuration entry that the parse dropped as invalid, before any plan."""

    kind: Kind
    path: str
    detail: str
