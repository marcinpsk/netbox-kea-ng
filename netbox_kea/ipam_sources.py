# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The IPAM Ownership sources (ADR 0006): the name of each source, and one row of facts for each.

Every other module takes a per-source fact from :data:`SOURCES`, and compares a source with the constants below.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .constants import Family
from .ipam_marker import MarkerKind
from .models import IPAMOwnershipSource

# The type check sees a TextChoices member as its (value, label) tuple; at runtime it is the str value.
LEASE = cast("str", IPAMOwnershipSource.LEASE)
RESERVATION = cast("str", IPAMOwnershipSource.RESERVATION)
SUBNET = cast("str", IPAMOwnershipSource.SUBNET)
POOL = cast("str", IPAMOwnershipSource.POOL)
RESERVATION_PREFIX = cast("str", IPAMOwnershipSource.RESERVATION_PREFIX)
LEASE_PREFIX = cast("str", IPAMOwnershipSource.LEASE_PREFIX)
PD_POOL = cast("str", IPAMOwnershipSource.PD_POOL)

#: The link field of an owned object: an IP address, a Prefix or an IP Range.
ObjectField = Literal["ip_address", "prefix", "ip_range"]
#: The workflows that observe sources: the sync job and the DHCP plugin import.
Workflow = Literal["job", "import"]

_BOTH: frozenset[Family] = frozenset({4, 6})
_DHCPV6: frozenset[Family] = frozenset({6})


@dataclass(frozen=True)
class OwnershipSource:
    """The facts of one IPAM Ownership source."""

    #: The link field of the objects that the source owns.
    object_field: ObjectField
    #: The address families that have the source.
    families: frozenset[Family]
    #: The workflows that observe the source.
    workflows: frozenset[Workflow]
    #: The marker kind of an object that only this source owns.
    marker_kind: MarkerKind
    #: The type flag of ``SyncConfig`` and ``Server`` that enables the source in the job, or ``None``.
    type_flag: str | None


#: One row for each source, in display order. On a Prefix with several live sources, the first source names the marker.
SOURCES: dict[str, OwnershipSource] = {
    LEASE: OwnershipSource("ip_address", _BOTH, frozenset({"job"}), "lease", "sync_leases_enabled"),
    RESERVATION: OwnershipSource(
        "ip_address", _BOTH, frozenset({"job", "import"}), "reservation", "sync_reservations_enabled"
    ),
    SUBNET: OwnershipSource("prefix", _BOTH, frozenset({"job", "import"}), "subnet", "sync_prefixes_enabled"),
    POOL: OwnershipSource("ip_range", _BOTH, frozenset({"job", "import"}), "pool", "sync_ip_ranges_enabled"),
    PD_POOL: OwnershipSource("prefix", _DHCPV6, frozenset({"import"}), "pd pool", None),
    RESERVATION_PREFIX: OwnershipSource("prefix", _DHCPV6, frozenset({"import"}), "delegated prefix", None),
    LEASE_PREFIX: OwnershipSource("prefix", _DHCPV6, frozenset({"job"}), "delegated prefix", None),
}
