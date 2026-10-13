# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ruleid: kea-cache-outside-display-cache
import django.core.cache

# ruleid: kea-cache-outside-display-cache
from django.core import cache as cache_module

# ruleid: kea-cache-outside-display-cache
from django.core.cache import cache

# ruleid: kea-cache-outside-display-cache
from django.core.cache import caches as all_caches
from functools import cache as memoize

import netbox_kea.display_cache
from netbox_kea import display_cache
from netbox_kea import display_cache as absolute_cache

from . import display_cache as relative_cache

# ruleid: kea-cache-outside-display-cache
from .display_cache import _generation

# ruleid: kea-cache-outside-display-cache
from ..display_cache import _entry_key

# ruleid: kea-cache-outside-display-cache
from netbox_kea.display_cache import _generation_key, cached

# ok: kea-cache-outside-display-cache
from .display_cache import cached, rotate_configuration, rotate_records

# ok: kea-cache-outside-display-cache
from ..display_cache import KEY_PREFIX

# ruleid: kea-cache-outside-display-cache
from .display_cache import (
    cached as cached_again,
    _rotate,
)

# ok: kea-cache-outside-display-cache
from .display_cache import (
    rotate_configuration as rotate_configuration_again,
    rotate_records as rotate_records_again,
)


def builds_its_own_entry(server):
    # ruleid: kea-cache-outside-display-cache
    snapshot = cache.get(f"netbox_kea:display:entry:{server.pk}:4")
    # ruleid: kea-cache-outside-display-cache
    all_caches["default"].set("netbox_kea:display:entry", snapshot, 300)
    # ruleid: kea-cache-outside-display-cache
    django.core.cache.cache.delete("netbox_kea:display:entry")
    # ruleid: kea-cache-outside-display-cache
    cache_module.cache.delete("netbox_kea:display:entry")
    return snapshot


def reads_a_generation(server):
    # ruleid: kea-cache-outside-display-cache
    display_cache._generation(server, 4, "records")
    # ruleid: kea-cache-outside-display-cache
    relative_cache._generation(server, 4, "records")
    # ruleid: kea-cache-outside-display-cache
    absolute_cache._entry_key(server, 4, "catalogue", None)
    # ruleid: kea-cache-outside-display-cache
    return netbox_kea.display_cache._generation_key(server, 4, "records")


def uses_the_module(server, read):
    # ok: kea-cache-outside-display-cache
    display_cache.rotate_records(server, 4)
    # ok: kea-cache-outside-display-cache
    relative_cache.rotate_configuration(server, 4)
    # ok: kea-cache-outside-display-cache
    absolute_cache.rotate_records(server, None)
    # ok: kea-cache-outside-display-cache
    netbox_kea.display_cache.rotate_configuration(server, 6)
    # ok: kea-cache-outside-display-cache
    rotate_records(server, 6)
    # ok: kea-cache-outside-display-cache
    cached(server, 4, "catalogue", read)
    # ok: kea-cache-outside-display-cache
    return relative_cache.cached(server, 4, "catalogue", read)


# ok: kea-cache-outside-display-cache
@memoize
def memoized():
    return display_cache.KEY_PREFIX
