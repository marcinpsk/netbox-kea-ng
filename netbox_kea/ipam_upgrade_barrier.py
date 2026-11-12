# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The completion receipts and the upgrade barrier of IPAM Ownership (ADR 0006, design record #172).

A complete whole job or DHCP import stores a receipt of the sources that it observed on its Server. Until every
potential owner observed its sources, the stale cleanup keeps the last link of an adopted object.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from django.utils import timezone

from . import event_scope
from .constants import Family
from .integrations import dhcp_plugin
from .ipam_marker import marked_description_q, parse_marker
from .ipam_sources import OWNED_KINDS, SOURCES, ObjectField, Workflow
from .models import DhcpIntegrationConfig, IPAMOwnershipLink, IPAMOwnershipSource, Server, SyncConfig
from .sync_plan import SourceScope, served_families, sync_plan


def effective_sources(server: Server) -> dict[Workflow, SourceScope]:
    """Return current potential owners, shared by workflow completion and the upgrade barrier."""
    return _effective_sources(server, SyncConfig.get())


def _effective_sources(
    server: Server, config: SyncConfig, switch: DhcpIntegrationConfig | None = None
) -> dict[Workflow, SourceScope]:
    imported: SourceScope = frozenset()
    if dhcp_plugin.runs_for(server, switch):
        imported = frozenset(
            (family, source)
            for family in served_families(server)
            for source, row in SOURCES.items()
            if "import" in row.workflows and family in row.families
        )
    return {"job": sync_plan(server, config).sources, "import": imported}


@dataclass(frozen=True)
class _ObservationReceipt:
    """One successful whole workflow; the serializer owns its persisted shape."""

    sources: SourceScope
    completed_at: datetime

    def stored(self) -> dict[str, Any]:
        return {"sources": [list(pair) for pair in sorted(self.sources)], "completed_at": self.completed_at.isoformat()}

    @classmethod
    def read(cls, value: Any) -> _ObservationReceipt:
        if not isinstance(value, dict) or set(value) != {"sources", "completed_at"}:
            raise ValueError("Malformed IPAM observation receipt")
        sources = value["sources"]
        if not isinstance(sources, list) or any(
            not isinstance(pair, list)
            or len(pair) != 2
            or type(pair[0]) is not int
            or pair[0] not in (4, 6)
            or pair[1] not in IPAMOwnershipSource.values
            for pair in sources
        ):
            raise ValueError("Malformed IPAM observation source scope")
        completed_at = datetime.fromisoformat(value["completed_at"])
        if timezone.is_naive(completed_at):
            raise ValueError("An IPAM observation timestamp must be timezone aware")
        return cls(frozenset((cast("Family", pair[0]), pair[1]) for pair in sources), completed_at)


def _receipts(server: Server) -> dict[Workflow, _ObservationReceipt]:
    value = server.ipam_initial_observations
    if not isinstance(value, dict) or set(value) - {"job", "import"}:
        raise ValueError("Malformed IPAM initial observations")
    return {cast("Workflow", key): _ObservationReceipt.read(receipt) for key, receipt in value.items()}


@dataclass(frozen=True)
class ObservationCoverage:
    """What one workflow run observed in one family: whether the run was complete, and the sources it completed."""

    complete: bool
    sources: frozenset[str]


def complete_observation(server: Server, workflow: Workflow, coverage: Mapping[Family, ObservationCoverage]) -> None:
    """Publish only a whole run whose every family is complete and whose sources satisfy the current configuration."""
    if not coverage or any(not observed.complete for observed in coverage.values()):
        return
    scope = frozenset((family, source) for family, observed in coverage.items() for source in observed.sources)
    _complete_observation(server, workflow, scope)


def _complete_observation(server: Server, workflow: Workflow, observed: SourceScope) -> None:
    with event_scope.atomic():
        current = Server.objects.select_for_update(no_key=True).get(pk=server.pk)
        required = effective_sources(current)
        if not required[workflow] or not required[workflow] <= observed:
            return
        receipts = _receipts(current)
        receipts[workflow] = _ObservationReceipt(observed, timezone.now())
        current.snapshot()
        current.ipam_initial_observations = {key: receipt.stored() for key, receipt in receipts.items()}
        if current.ipam_first_complete_at is None and all(
            not scope or (key in receipts and scope <= receipts[key].sources) for key, scope in required.items()
        ):
            current.ipam_first_complete_at = timezone.now()
        current.save(update_fields=["ipam_initial_observations", "ipam_first_complete_at"])
        server.ipam_initial_observations = current.ipam_initial_observations
        server.ipam_first_complete_at = current.ipam_first_complete_at


def _pending_adoptions() -> set[tuple[Family, ObjectField]]:
    """Read potential owners for the current policy or one count snapshot."""
    pending: set[tuple[Family, ObjectField]] = set()
    config, switch = SyncConfig.get(), DhcpIntegrationConfig.get()
    for server in Server.objects.all():
        receipts = _receipts(server)
        for workflow, scope in _effective_sources(server, config, switch).items():
            observed = receipts[workflow].sources if workflow in receipts else frozenset()
            pending.update((family, SOURCES[source].object_field) for family, source in scope - observed)
    return pending


def adoption_waits(link: IPAMOwnershipLink, object_field: ObjectField) -> bool:
    """Return whether the barrier keeps *link*: it is adopted, and an owner of its family and kind has not observed.

    The stale cleanup freezes the policy before it asks.
    """
    return link.adopted and (link.family, object_field) in _pending_adoptions()


@dataclass(frozen=True)
class UpgradeCounts:
    """The objects that the job summary counts after an upgrade, each as a (link field, pk) pair."""

    #: Marked objects whose last link the upgrade barrier keeps.
    waiting_objects: frozenset[tuple[ObjectField, int]]
    #: Marker objects with no ownership link.
    unowned_objects: frozenset[tuple[ObjectField, int]]

    @property
    def waiting(self) -> int:
        """Count distinct objects protected by the upgrade barrier."""
        return len(self.waiting_objects)

    @property
    def unowned(self) -> int:
        """Count distinct marker objects with no ownership link."""
        return len(self.unowned_objects)


def upgrade_counts() -> UpgradeCounts:
    """Count distinct unowned marker objects and marked objects held by the current upgrade barrier."""
    waiting: set[tuple[ObjectField, int]] = set()
    unowned: set[tuple[ObjectField, int]] = set()
    pending = _pending_adoptions()
    for object_field, kind in OWNED_KINDS.items():
        for obj in kind.model.objects.filter(marked_description_q(), kea_ownership_links__isnull=True).only(
            "pk", "description"
        ):
            if parse_marker(obj.description) is not None:
                unowned.add((object_field, obj.pk))
        for link in IPAMOwnershipLink.objects.filter(adopted=True, **{f"{object_field}__isnull": False}).select_related(
            object_field
        ):
            obj = getattr(link, object_field)
            if parse_marker(obj.description) is not None and (link.family, object_field) in pending:
                waiting.add((object_field, obj.pk))
    return UpgradeCounts(frozenset(waiting), frozenset(unowned))
