# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import django.core.cache

# ruleid: kea-cache-outside-display-cache
from django.core.cache import cache

# ruleid: kea-cache-outside-display-cache
from django.core.cache import caches as all_caches
from functools import cache as memoize

from netbox_kea import display_cache


def builds_its_own_entry(server):
    # ruleid: kea-cache-outside-display-cache
    snapshot = cache.get(f"netbox_kea:display:entry:{server.pk}:4")
    # ruleid: kea-cache-outside-display-cache
    all_caches["default"].set("netbox_kea:display:entry", snapshot, 300)
    # ruleid: kea-cache-outside-display-cache
    django.core.cache.cache.delete("netbox_kea:display:entry")
    return snapshot


def reads_a_generation(server):
    # ruleid: kea-cache-outside-display-cache
    return display_cache._generation(server, 4, "records")


def uses_the_module(server, read):
    # ok: kea-cache-outside-display-cache
    display_cache.rotate_records(server, 4)
    # ok: kea-cache-outside-display-cache
    display_cache.rotate_configuration(server, 4)
    # ok: kea-cache-outside-display-cache
    return display_cache.cached(server, 4, "catalogue", read, admit=bool)


# ok: kea-cache-outside-display-cache
@memoize
def memoized():
    return display_cache.KEY_PREFIX
