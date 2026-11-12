# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The IPAM ownership outcome of each source of one ``(server, family)`` DHCP Import (ADR 0006).

The import claims the IPAM objects of its Subnets, Pools, delegated-prefix Pools, Reservation addresses and
Reservation delegated prefixes, and reconciles the two kinds of delegated Prefix again after the stale DHCP objects
go. This record is the one place that turns a claim result or a reconcile report into the outcome of its source.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..ipam_reconciliation import AddressClaim, PrefixClaim, RangeClaim, SyncReport


@dataclass
class _SourceOutcome:
    complete: bool = True
    disagreements: set[str] = field(default_factory=set)
    errors: int = 0


@dataclass
class ImportOwnership:
    """The IPAM ownership outcome of each source that one import claimed or reconciled."""

    _sources: dict[str, _SourceOutcome] = field(default_factory=dict)

    def _outcome(self, source: str) -> _SourceOutcome:
        return self._sources.setdefault(source, _SourceOutcome())

    def claimed(
        self, source: str, results: Mapping[str, AddressClaim | PrefixClaim | RangeClaim], *, complete: bool = True
    ) -> None:
        """Record the claim that speaks for *source*. A failed row, or an incomplete read (*complete*), leaves it open."""
        outcome = self._outcome(source)
        outcome.complete = outcome.complete and complete and all(each.outcome != "error" for each in results.values())
        outcome.disagreements.update(address for address, each in results.items() if each.outcome == "disagreement")

    def reconciled(self, source: str, report: SyncReport, *, attach_failures: Iterable[str] = ()) -> None:
        """Record the reconcile of *source*, which speaks for a Prefix that the import also claimed to attach it.

        A Prefix in *attach_failures* (its attach claim failed) counts as one error, also when the reconcile claim of
        it succeeds.
        """
        outcome = self._outcome(source)
        outcome.complete = outcome.complete and source in report.completed_sources and source not in report.incomplete
        outcome.disagreements.update(report.disagreements)
        outcome.errors += report.errors + report.prefix_errors
        outcome.errors += sum(report.prefixes[address].outcome != "error" for address in attach_failures)

    def mark_incomplete(self, *sources: str) -> None:
        """Record that the run did not observe each of *sources* in full."""
        for source in sources:
            self._outcome(source).complete = False

    @property
    def completed_sources(self) -> frozenset[str]:
        """Return the sources that the run observed in full."""
        return frozenset(source for source, outcome in self._sources.items() if outcome.complete)

    @property
    def incomplete(self) -> frozenset[str]:
        """Return the sources that the run did not observe in full."""
        return frozenset(source for source, outcome in self._sources.items() if not outcome.complete)

    @property
    def complete(self) -> bool:
        """Return whether the run observed every source that it recorded in full."""
        return not self.incomplete

    @property
    def disagreements(self) -> int:
        """Return the IPAM objects whose owners disagree, counted once in each source."""
        return sum(len(outcome.disagreements) for outcome in self._sources.values())

    @property
    def errors(self) -> int:
        """Return the IPAM reconciliation errors."""
        return sum(outcome.errors for outcome in self._sources.values())
