# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from netbox_kea import event_scope
from netbox_kea.dhcp_mapping_lifecycle import mapped_target, observe_mapping
from netbox_kea.integrations.dhcp_import_write import ManagedFieldsMismatch, write_row


def upsert_pool(server, family, source, summary):
    pool = mapped_target(server, family, source)
    # ruleid: kea-dhcp-row-write-outside-protocol
    observe_mapping(server, family, pool, source)
    return pool


def upsert_subnet(server, family, source, summary):
    # ruleid: kea-dhcp-row-write-outside-protocol
    try:
        with event_scope.atomic():
            row = mapped_target(server, family, source)
            row.save()
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception:
        summary.record("write failed")
        return None
    return row


def upsert_option(server, family, source):
    # ruleid: kea-dhcp-row-write-outside-protocol
    try:
        mapped_target(server, family, source).save()
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise


def upsert_dhcp_server(server, family, source):
    with event_scope.atomic():
        dhcp_server = mapped_target(server, family, source)
        # ok: kea-dhcp-row-write-outside-protocol
        observe_mapping(server, family, dhcp_server, source)
    return dhcp_server


def _apply_global_settings(dhcp_server, summary):
    # ok: kea-dhcp-row-write-outside-protocol
    try:
        with event_scope.atomic():
            dhcp_server.save()
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception:
        summary.record("write failed")
        return None
    return True


def settle_subnet_ids(rows, summary):
    # ok: kea-dhcp-row-write-outside-protocol
    try:
        with event_scope.atomic():
            for row in rows:
                row.save()
    except event_scope.EventDispatchError:
        raise
    except Exception:
        summary.warn("the Subnet ID moves failed")


def upsert_pools(adapters):
    for adapter in adapters:
        # ok: kea-dhcp-row-write-outside-protocol
        write_row(adapter)
