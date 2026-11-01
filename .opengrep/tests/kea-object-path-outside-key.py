# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass

from netbox_kea import kea_paths


def subnet_path(planned):
    # ruleid: kea-object-path-outside-key
    return kea_paths.subnet(planned.intent.family, planned.key)


def pool_path(parent_path, planned):
    # ruleid: kea-object-path-outside-key
    return kea_paths.pool(parent_path, planned.intent.pool)


def pd_pool_path(parent_path, key):
    # ruleid: kea-object-path-outside-key
    return kea_paths.pd_pool(parent_path, str(key.prefix), key.delegated_length)


def reservation_path(key, family):
    # ruleid: kea-object-path-outside-key
    return kea_paths.reservation(family, None, key.identifier_type, key.value)


def upsert_client_class(intent, name):
    # ruleid: kea-object-path-outside-key
    return kea_paths.client_class(intent.family, name)


@dataclass(frozen=True)
class SubnetKey:
    subnet_id: int

    def path(self, family: int) -> str:
        # ok: kea-object-path-outside-key
        return kea_paths.subnet(family, self.subnet_id)


def collections(family, parent_path, index):
    # ok: kea-object-path-outside-key
    return kea_paths.reservations(family), kea_paths.pool_entry(parent_path, index), kea_paths.daemon(family)


def keyed(planned, family):
    # ok: kea-object-path-outside-key
    return planned.key.path(family)
