# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from django.contrib.contenttypes.models import ContentType

from netbox_kea.integrations.dhcp_import_mappings import mapped_target, unlinked
from netbox_kea.models import KeaDhcpLink


def _unlinked(base):
    # ruleid: kea-dhcp-mapping-query-outside-store
    claimed = KeaDhcpLink.objects.filter(object_type=ContentType.objects.get_for_model(base.model))
    return base.exclude(pk__in=claimed.values("object_id"))


def _holders(using, pks):
    # ruleid: kea-dhcp-mapping-query-outside-store
    return KeaDhcpLink._base_manager.using(using).filter(object_id__in=pks)


def _new_mapping(server, family, target):
    # ruleid: kea-dhcp-mapping-query-outside-store
    return KeaDhcpLink(server=server, family=family, object_id=target.pk)


def _adoptable(server, family, source, base):
    # ok: kea-dhcp-mapping-query-outside-store
    row = mapped_target(server, family, source)
    # ok: kea-dhcp-mapping-query-outside-store
    return row or unlinked(base).first()


def _is_mapping(model):
    # ok: kea-dhcp-mapping-query-outside-store
    return model is KeaDhcpLink


def _serializer_model():
    # ok: kea-dhcp-mapping-query-outside-store
    return {"model": KeaDhcpLink, "fields": ("server", "family", "kind")}


def _links(server):
    # ok: kea-dhcp-mapping-query-outside-store
    return server.dhcp_plugin_links.all()
