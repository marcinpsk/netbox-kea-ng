# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The result of one ``(server, family)`` DHCP Import: its entries, IPAM ownership outcomes and warnings.

Every DHCP fact count of :class:`ImportSummary` is a count of its entries, so nothing is counted without an entry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .. import kea_paths
from .dhcp_import_ownership import ImportOwnership
from .dhcp_import_report import ImportEntry, Kind, Outcome, Reason

if TYPE_CHECKING:
    from ..ipam_upgrade_barrier import ObservationCoverage

logger = logging.getLogger(__name__)


class Count:
    """A read-only count of the entries of one kind whose outcome or reason is one of the given values."""

    def __init__(self, kind: Kind, *matches: Outcome | Reason) -> None:
        self.kind = kind
        self.matches = matches

    def __get__(self, summary: ImportSummary | None, owner: type) -> int:
        return summary.count(self.kind, *self.matches, objects_only=True) if summary is not None else 0


@dataclass
class ImportSummary:
    """The entries, IPAM ownership outcomes and warnings of one ``(server, family)`` import.

    Every DHCP fact count is a count of :attr:`entries`, so nothing is counted without an entry.
    """

    ownership: ImportOwnership = field(default_factory=ImportOwnership)
    entries: list[ImportEntry] = field(default_factory=list)
    foreign_addresses_skipped: int = 0
    # Reserved addresses with no NetBox IP to attach. A Global Reservation has no
    # Subnet to size an address from, so the import never creates one for it.
    addresses_unattached: int = 0
    warnings: list[str] = field(default_factory=list)

    subnets_created = Count(Kind.SUBNET, Outcome.CREATED)
    subnets_updated = Count(Kind.SUBNET, Outcome.UPDATED)
    pools_created = Count(Kind.POOL, Outcome.CREATED)
    pd_pools_created = Count(Kind.PD_POOL, Outcome.CREATED)
    reservations_created = Count(Kind.RESERVATION, Outcome.CREATED)
    reservations_updated = Count(Kind.RESERVATION, Outcome.UPDATED)
    reservations_quarantined = Count(Kind.RESERVATION, Reason.INVALID_KEA_DATA)
    reservations_skipped = Count(Kind.RESERVATION, Reason.PARENT_NOT_IMPORTED)
    options_created = Count(Kind.OPTION, Outcome.CREATED)
    options_updated = Count(Kind.OPTION, Outcome.UPDATED)
    options_skipped = Count(Kind.OPTION, Outcome.UNSUPPORTED, Outcome.SKIPPED, Outcome.NOT_IMPORTED)
    option_defs_created = Count(Kind.OPTION_DEFINITION, Outcome.CREATED)
    client_classes_created = Count(Kind.CLIENT_CLASS, Outcome.CREATED)
    client_classes_updated = Count(Kind.CLIENT_CLASS, Outcome.UPDATED)
    shared_networks_created = Count(Kind.SHARED_NETWORK, Outcome.CREATED)
    shared_networks_updated = Count(Kind.SHARED_NETWORK, Outcome.UPDATED)

    shared_networks_unsupported = Count(Kind.SHARED_NETWORK, Outcome.UNSUPPORTED)

    @property
    def owner_disagreements(self) -> int:
        """Return the IPAM objects whose owners disagree, so the import left them unchanged."""
        return self.ownership.disagreements

    @property
    def removed(self) -> int:
        """Return the number of Stale DHCP Import Objects that the run removed."""
        return sum(entry.outcome == Outcome.REMOVED for entry in self.entries)

    def record(self, entry: ImportEntry) -> None:
        """Add the entry of one Kea fact."""
        self.entries.append(entry)

    def count(self, kind: Kind, *matches: Outcome | Reason, objects_only: bool = False) -> int:
        """Count matching facts of *kind*, or only object entries when *objects_only* is true."""
        return sum(
            entry.kind == kind
            and (entry.outcome in matches or entry.reason in matches)
            and (not objects_only or not kea_paths.is_setting(entry.path))
            for entry in self.entries
        )

    @property
    def reservations_unread(self) -> bool:
        """Return whether the Reservation Snapshot could not be read in full."""
        return self.count(Kind.RESERVATION, Reason.READ_FAILED) > 0

    @property
    def errors(self) -> int:
        """Return the failed object writes and IPAM reconciliation errors. A failed Option counts as skipped."""
        failed = (
            entry.reason == Reason.WRITE_FAILED and entry.kind not in (Kind.OPTION, Kind.OPTION_DEFINITION)
            for entry in self.entries
        )
        return sum(failed) + self.ownership.errors

    def coverage(self) -> ObservationCoverage:
        """Return what the run observed for the import receipt: complete only with every source complete and no error."""
        from ..ipam_upgrade_barrier import ObservationCoverage

        return ObservationCoverage(self.ownership.complete and not self.errors, self.ownership.completed_sources)

    def warn(self, message: str, error: BaseException | None = None) -> None:
        """Record a non-fatal warning and log it, with the traceback of *error* when one caused it."""
        self.warnings.append(message)
        logger.warning("DHCP-plugin import: %s", message, exc_info=error)
