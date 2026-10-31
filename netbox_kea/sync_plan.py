# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Sync Plan: which Kea sources of each address family one IPAM sync run of a Server reads.

The job, the completion receipts, the add forms and the Sync tab read the switches and type flags only through this
module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .constants import Family
from .models import IPAMOwnershipSource, Server, SyncConfig

# The type check sees a TextChoices member as its (value, label) tuple; at runtime it is the str value.
LEASE = cast("str", IPAMOwnershipSource.LEASE)
RESERVATION = cast("str", IPAMOwnershipSource.RESERVATION)
SUBNET = cast("str", IPAMOwnershipSource.SUBNET)
POOL = cast("str", IPAMOwnershipSource.POOL)
LEASE_PREFIX = cast("str", IPAMOwnershipSource.LEASE_PREFIX)

SourceScope = frozenset[tuple[Family, str]]

_SOURCE_FLAGS = {
    LEASE: "sync_leases_enabled",
    RESERVATION: "sync_reservations_enabled",
    SUBNET: "sync_prefixes_enabled",
    POOL: "sync_ip_ranges_enabled",
}

#: Every source that has its own type flags, in display order.
SYNC_SOURCES: tuple[str, ...] = tuple(_SOURCE_FLAGS)


def global_source_enabled(source: str, config: SyncConfig) -> bool:
    """Return whether the global type flag of *source* (one of ``SYNC_SOURCES``) is on."""
    return getattr(config, _SOURCE_FLAGS[source])


def any_source_enabled(config: SyncConfig) -> bool:
    """Return whether at least one global type flag is on."""
    return any(global_source_enabled(source, config) for source in SYNC_SOURCES)


def server_sync_enabled(server: Server, config: SyncConfig, *, run_now: bool = False) -> bool:
    """Return whether the sync job syncs *server*. A Run Now of the Server skips the Server switch."""
    return config.sync_enabled and (run_now or server.sync_enabled)


def source_sync_enabled(server: Server, source: str, config: SyncConfig) -> bool:
    """Return whether the global and the Server type flags of *source* (one of ``SYNC_SOURCES``) are both on."""
    return global_source_enabled(source, config) and getattr(server, _SOURCE_FLAGS[source])


def periodic_sync_enabled(server: Server, source: str, config: SyncConfig | None = None) -> bool:
    """Return whether the periodic sync job syncs *source* (one of ``SYNC_SOURCES``) for *server*."""
    config = SyncConfig.get() if config is None else config
    return server_sync_enabled(server, config) and source_sync_enabled(server, source, config)


@dataclass(frozen=True)
class SyncPlan:
    """The (family, source) pairs that one sync run of a Server reads."""

    sources: SourceScope

    @property
    def families(self) -> tuple[Family, ...]:
        """Return the families that have at least one source, in ascending order."""
        return tuple(sorted({family for family, _ in self.sources}))

    def reads(self, family: Family, source: str) -> bool:
        """Return whether the run reads *source* for *family*."""
        return (family, source) in self.sources


def sync_plan(server: Server, config: SyncConfig, *, run_now: bool = False) -> SyncPlan:
    """Return the Sync Plan of *server*. A Run Now of the Server skips the Server switch."""
    if not server_sync_enabled(server, config, run_now=run_now):
        return SyncPlan(frozenset())
    sources = [source for source in SYNC_SOURCES if source_sync_enabled(server, source, config)]
    families: tuple[Family, ...] = tuple(
        cast("Family", family) for family, enabled in ((4, server.dhcp4), (6, server.dhcp6)) if enabled
    )
    pairs = {(family, source) for family in families for source in sources}
    # Delegated-prefix leases own Prefixes on DHCPv6 with lease and Subnet sync; they have no type flag of their own.
    if 6 in families and LEASE in sources and SUBNET in sources:
        pairs.add((6, LEASE_PREFIX))
    return SyncPlan(frozenset(pairs))
