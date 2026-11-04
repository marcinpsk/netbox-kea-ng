# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCP Import Mapping store: every read and write of ``KeaDhcpLink`` that the DHCP Import makes.

A mapping ties a Kea source (:class:`.dhcp_import_plan.MappingSource`) to the DHCP plugin row that the import wrote
for it. :func:`mapped_target` finds the row, and :func:`observe_mapping` records and confirms the mapping inside the
``metadata_scope()`` of :mod:`netbox_kea.dhcp_mapping_lifecycle`, which keeps the ADR 0008 coordination with native
branching. The OpenGrep rule ``kea-dhcp-mapping-query-outside-store`` refuses a ``KeaDhcpLink`` query in the other
modules of the import.

* Each imported Shared Network, Subnet, Pool, delegated-prefix Pool, Reservation, client class, custom Option
  Definition and DHCP Option has a DHCP Import Mapping (:class:`netbox_kea.models.KeaDhcpLink`) to its Kea source, and
  a re-import finds the row through it, also after an operator renames the row. The first import after an upgrade
  maps each unmapped row that matches by structure. No release imported delegated-prefix Pools before, so an unmapped
  PD Pool is an operator's row and stays. Kea refuses a Subnet without a subnet ID, so the parse drops one as Kea data
  that is not valid, with its Pools, PD Pools and DHCP Options. Each object that the import writes has a mapping.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from django.apps import apps
from django.db.models.signals import post_delete

from ..dhcp_mapping_lifecycle import metadata_scope, target_models
from ..models import KeaDhcpLink, exact_source, mapping_identity, next_confirmation_number
from .dhcp_import_plan import MappingSource, mapped_kinds
from .dhcp_import_report import Kind
from .dhcp_plugin_capabilities import PLUGIN_APP_LABEL

if TYPE_CHECKING:
    from django.db.models import QuerySet


def _source_columns(server, family: int, source: MappingSource) -> dict:
    """Return the source columns of the mapping of *source*, for a write."""
    return {"server": server, "family": family, **source.columns()}


def _source_mapping(server, family: int, source: MappingSource):
    """Return the mappings of *source*: at most one row, found through its unique index."""
    lookup = exact_source(server, family, **source.columns())
    return KeaDhcpLink.objects.filter(lookup)


def mapped_target(server, family: int, source: MappingSource):
    """Return the target that *source* maps to, or ``None`` when it has no mapping or its target is gone."""
    mapping = _source_mapping(server, family, source).first()
    return mapping.sys4_object if mapping is not None else None


def observe_mapping(server, family: int, target, source: MappingSource):
    """Record a source association, or refresh its observation without a semantic history change.

    Each call confirms the mapping with a new number of the confirmation sequence (ADR 0006).
    """
    from django.contrib.contenttypes.models import ContentType

    association = {
        **_source_columns(server, family, source),
        "object_type": ContentType.objects.get_for_model(target),
        "object_id": target.pk,
    }
    with metadata_scope():
        mapping = _source_mapping(server, family, source).first()
        desired = KeaDhcpLink(**association, confirmation=next_confirmation_number())
        if mapping is None:
            desired.save()
            return desired
        if mapping_identity(mapping) == mapping_identity(desired):
            mapping.confirmation = desired.confirmation
            KeaDhcpLink.objects.filter(pk=mapping.pk).update(confirmation=mapping.confirmation)
            return mapping
        mapping.snapshot()
        if (mapping.object_type_id, mapping.object_id) != (desired.object_type_id, desired.object_id):
            # The new target has not adopted its Options yet.
            mapping.options_mapped = False
        for name, value in association.items():
            setattr(mapping, name, value)
        mapping.confirmation = desired.confirmation
        mapping.save()
        return mapping


def options_mapped(server, family: int, source: MappingSource) -> bool:
    """Return whether the import has mapped the DHCP Options of the object of *source*. It must have a mapping."""
    return _source_mapping(server, family, source).values_list("options_mapped", flat=True).get()


def mark_options_mapped(server, family: int, source: MappingSource) -> None:
    """Record that the import has mapped the DHCP Options of the object of *source*, without a history change."""
    _source_mapping(server, family, source).filter(options_mapped=False).update(options_mapped=True)


def register_link_cleanup() -> None:
    """Remove mappings in the same database as a deleted supported DHCP target."""
    # Without the DHCP plugin there are no target models.
    for model in target_models():
        post_delete.connect(
            _delete_target_links,
            sender=model,
            dispatch_uid=f"netbox_kea.dhcp_target_links.{model._meta.label}",
        )


def _delete_target_links(sender, instance, using: str, **kwargs) -> None:
    from django.contrib.contenttypes.models import ContentType

    content_type = ContentType.objects.db_manager(using).get_for_model(sender)
    KeaDhcpLink.objects.using(using).filter(object_type_id=content_type.pk, object_id=instance.pk).delete()


def unlinked(base: QuerySet) -> QuerySet:
    """Restrict *base* to the rows no Kea link claims yet."""
    from django.contrib.contenttypes.models import ContentType

    claimed = KeaDhcpLink.objects.filter(
        object_type=ContentType.objects.get_for_model(base.model),
    ).values_list("object_id", flat=True)
    return base.exclude(pk__in=claimed)


def first_mapping(rows: QuerySet):
    """Return the mapping of one row of *rows*, or ``None`` when no mapping holds any of them."""
    from django.contrib.contenttypes.models import ContentType

    return KeaDhcpLink.objects.filter(
        object_type=ContentType.objects.get_for_model(rows.model), object_id__in=rows.values("pk")
    ).first()


def mapped_elsewhere(model, server) -> QuerySet:
    """Return the pks of the rows of *model* that a mapping of another Server holds, as a subquery."""
    from django.contrib.contenttypes.models import ContentType

    return (
        KeaDhcpLink.objects.filter(object_type=ContentType.objects.get_for_model(model))
        .exclude(server=server)
        .values("object_id")
    )


def subnet_id_mappings(subnet_model, server, family: int, kea_subnet_ids) -> tuple[dict[int, int], dict[int, int]]:
    """Return the Kea subnet ID that each mapped Subnet row wants, and the row of each ID of *kea_subnet_ids*.

    The first map holds the mappings of every Server and family, by row pk. The second holds the mappings of *server*
    and *family* only, by Kea subnet ID.
    """
    from django.contrib.contenttypes.models import ContentType

    links = KeaDhcpLink.objects.filter(
        kind=Kind.SUBNET.value, object_type=ContentType.objects.get_for_model(subnet_model)
    )
    wants = dict(links.values_list("object_id", "kea_subnet_id"))
    ours = dict(
        links.filter(server=server, family=family, kea_subnet_id__in=kea_subnet_ids).values_list(
            "kea_subnet_id", "object_id"
        )
    )
    return wants, ours


def mapped_option_keys() -> frozenset[tuple]:
    """Return the row key of each Option that a mapping holds, of any Server and family.

    An operator can assign the Option of another Server to an object of this one.
    """
    links = KeaDhcpLink.objects.filter(kind=Kind.OPTION.value)
    option = apps.get_model(PLUGIN_APP_LABEL, "Option")
    return frozenset((option, pk) for pk in links.values_list("object_id", flat=True))


def mapped_links(server, family: int) -> Iterator[tuple[MappingSource, Any]]:
    """Yield the Kea source and the mapping of each mapped row of *family* whose kind a run can remove, in pk order.

    A mapping whose row is gone has none, and is left out.
    """
    links = KeaDhcpLink.objects.filter(
        server=server, family=family, kind__in=[kind.value for kind in mapped_kinds(family)]
    )
    for link in links.prefetch_related("sys4_object").order_by("pk"):
        if link.sys4_object is not None:
            yield MappingSource(Kind(link.kind), link.kea_subnet_id, link.kea_identity), link


def mapped_rows(server, family: int) -> dict[Kind, dict[MappingSource, Any]]:
    """Return the DHCP plugin row of each mapping of *family* whose kind a run can remove, by kind and Kea source."""
    rows: dict[Kind, dict[MappingSource, Any]] = {kind: {} for kind in mapped_kinds(family)}
    for source, link in mapped_links(server, family):
        rows[source.kind][source] = link.sys4_object
    return rows
