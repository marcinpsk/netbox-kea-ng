# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Sync Run Result: the recorded result of one Server in one IPAM synchronization run.

``KeaIpamSyncJob`` stores one entry per Server in ``job.data["summary"]``. This module owns the entry: the type, the
writer, the reader and the query that finds the jobs of a Server. No other code builds or parses an entry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from enum import StrEnum
from typing import TYPE_CHECKING, Any, TypeGuard

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q

from .models import Server

if TYPE_CHECKING:
    from core.models import Job
    from django.db.models import QuerySet

    from .ipam_reconciliation import SyncReport

#: How many conflicting IPs an entry names. A bare count does not tell an operator which IPs the sync left alone.
CONFLICT_SAMPLE_SIZE = 20

_SUMMARY = "summary"


class SyncRunState(StrEnum):
    """How the IPAM synchronization of one Server ended in one run."""

    # The sync finished and recorded its counts.
    SYNCED = "synced"
    # The job finished, but it did not run the IPAM sync of the Server.
    SKIPPED = "skipped"
    # The job stopped before the IPAM sync of the Server finished.
    INTERRUPTED = "interrupted"
    # The entry does not match the schema, for example an entry of an older version.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SyncCounts:
    """The counts of one Synced Server."""

    created: int
    updated: int
    errors: int
    prefix_errors: int
    conflicts: int
    conflict_sample: tuple[str, ...]
    conflicts_truncated: int
    disagreements: int
    skipped: int
    waiting: int
    unclassified: int

    @classmethod
    def from_report(cls, report: SyncReport) -> SyncCounts:
        """Return the counts of *report*, with the first conflicts by name."""
        return cls(
            created=report.created,
            updated=report.updated,
            errors=report.errors,
            prefix_errors=report.prefix_errors,
            conflicts=len(report.conflicts),
            conflict_sample=tuple(sorted(report.conflicts)[:CONFLICT_SAMPLE_SIZE]),
            conflicts_truncated=max(0, len(report.conflicts) - CONFLICT_SAMPLE_SIZE),
            disagreements=len(report.disagreements),
            skipped=len(report.skipped_reservations),
            waiting=report.waiting,
            unclassified=report.unclassified,
        )


_COUNT_FIELDS = tuple(field.name for field in fields(SyncCounts))
_KEYS = frozenset({"pk", "name", "state"})
_STATES = frozenset(state.value for state in SyncRunState)


@dataclass(frozen=True)
class SyncRunResult:
    """The result of one Server in one run; only a Synced result has counts."""

    server_pk: int
    server_name: str
    state: SyncRunState
    counts: SyncCounts | None = None

    def __post_init__(self) -> None:
        """Refuse counts on a state other than Synced, and a Synced result without counts."""
        if (self.state is SyncRunState.SYNCED) != (self.counts is not None):
            raise ValueError(f"A {self.state} Sync Run Result must {'' if self.counts is None else 'not '}have counts")

    @classmethod
    def synced(cls, server_pk: int, server_name: str, report: SyncReport) -> SyncRunResult:
        """Return the Synced result of one Server from its *report*."""
        return cls(server_pk, server_name, SyncRunState.SYNCED, SyncCounts.from_report(report))


def store(job: Job, results: list[SyncRunResult]) -> None:
    """Save *results* as the entries of *job*; the other keys of ``job.data`` stay."""
    if not isinstance(job.data, dict):
        job.data = {}
    job.data[_SUMMARY] = [_entry(result) for result in results]
    job.save(update_fields=["data"])


def _entry(result: SyncRunResult) -> dict[str, Any]:
    entry: dict[str, Any] = {"pk": result.server_pk, "name": result.server_name, "state": result.state.value}
    if result.counts is not None:
        entry.update(asdict(result.counts), conflict_sample=list(result.counts.conflict_sample))
    return entry


def read(job: Job) -> dict[int, SyncRunResult]:
    """Return the result of each Server that an entry of *job* names, in the order of the entries.

    An entry with an integer pk that does not match the schema reads as Unknown. An entry without one is left out.
    """
    entries = job.data.get(_SUMMARY) if isinstance(job.data, dict) else None
    if not isinstance(entries, list):
        return {}
    results: dict[int, SyncRunResult] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not _is_int(pk := entry.get("pk")):
            continue
        # Two entries of one Server do not match the schema either.
        results[pk] = _unknown(pk, entry) if pk in results else _parse(pk, entry)
    return results


def _parse(pk: int, entry: dict[str, Any]) -> SyncRunResult:
    name, state = entry.get("name"), entry.get("state")
    if not isinstance(name, str) or not isinstance(state, str) or state not in _STATES:
        return _unknown(pk, entry)
    state = SyncRunState(state)
    if state is not SyncRunState.SYNCED:
        return SyncRunResult(pk, name, state) if entry.keys() == _KEYS else _unknown(pk, entry)
    if entry.keys() != _KEYS | set(_COUNT_FIELDS):
        return _unknown(pk, entry)
    values = {key: entry[key] for key in _COUNT_FIELDS}
    sample = values.pop("conflict_sample")
    if not all(map(_is_int, values.values())) or not _is_str_list(sample):
        return _unknown(pk, entry)
    return SyncRunResult(pk, name, state, SyncCounts(conflict_sample=tuple(sample), **values))


def _unknown(pk: int, entry: dict[str, Any]) -> SyncRunResult:
    name = entry.get("name")
    return SyncRunResult(pk, name if isinstance(name, str) else "", SyncRunState.UNKNOWN)


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_str_list(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def jobs_of(server_pk: int) -> QuerySet[Job]:
    """Return the IPAM sync jobs of one Server, newest first.

    A Run Now job is bound to its Server. A periodic job is bound to no object, and its entries name its Servers.
    """
    from core.models import Job

    from .jobs import KeaIpamSyncJob

    bound = Q(object_type=ContentType.objects.get_for_model(Server), object_id=server_pk)
    # A containment test on a list matches each list that holds an element with these keys.
    unbound = Q(object_id__isnull=True, **{f"data__{_SUMMARY}__contains": [{"pk": server_pk}]})
    return Job.objects.filter(bound | unbound, name=KeaIpamSyncJob.name).order_by("-created")


def latest(server_pk: int) -> tuple[Job | None, SyncRunResult | None]:
    """Return the newest job of one Server and the result of the Server in it; a job can hold no result of it."""
    job = jobs_of(server_pk).first()
    return job, read(job).get(server_pk) if job is not None else None
