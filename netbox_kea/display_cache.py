# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The display cache: keys, generations, TTLs, admission and invalidation of each display read (ADR 0009).

Only this module touches the Django cache. Authority reads (verification, synchronization, import, mutation
scopes and checks after a write) never call it.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Literal, TypeVar

from django.core.cache import cache

from .constants import Family, validate_family
from .models import DisplayCacheConfig, Server, request_display_cache_config, require_persisted_server

#: The prefix of every key of the display cache. The test cache hygiene fixture clears it.
KEY_PREFIX = "netbox_kea:display:"

Kind = Literal["configuration", "catalogue"]
_Generation = Literal["configuration", "records"]

#: The DisplayCacheConfig field that holds the TTL of each kind. Both kinds read the Kea configuration only, so
#: their keys hold the configuration generation and not the records generation.
_TTL_FIELDS: dict[Kind, str] = {"configuration": "configuration_ttl", "catalogue": "configuration_ttl"}

T = TypeVar("T")


def cached(server: Server, family: int, kind: Kind, read: Callable[[], T], admit: Callable[[T], bool]) -> T:
    """Return the entry of *kind* for *server* and *family*, or call *read* and store its result when *admit* it.

    The key is built before *read* runs, so a rotation during the read leaves the result in an older generation.
    A TTL of 0 sends every call to *read* and stores nothing.
    """
    validated_family = validate_family(family)
    config = request_display_cache_config.get() or DisplayCacheConfig.get()
    ttl = getattr(config, _TTL_FIELDS[kind])
    if not ttl:
        return read()
    key = _entry_key(server, validated_family, kind, config)
    entry = cache.get(key)
    if entry is not None:
        return entry
    value = read()
    if admit(value):
        cache.set(key, value, ttl)
    return value


def rotate_configuration(server: Server, family: int) -> None:
    """Make every entry of *server* and *family* unreachable, after a change of the Kea configuration."""
    _rotate(server, validate_family(family), "configuration")


def rotate_records(server: Server, family: Family | None) -> None:
    """Make every entry that depends on Reservations or Leases unreachable. ``None`` rotates both families."""
    for validated_family in (4, 6) if family is None else (validate_family(family),):
        _rotate(server, validated_family, "records")


def _entry_key(server: Server, family: Family, kind: Kind, config: DisplayCacheConfig) -> str:
    # A Server instance with old connection settings fills only the entry of those settings.
    connection = server.kea_connection(family).fingerprint()
    # Every save of the settings row writes last_updated, so a save makes every older entry unreachable.
    settings = config.last_updated.isoformat() if config.last_updated else "-"
    return (
        f"{KEY_PREFIX}entry:{require_persisted_server(server)}:{family}:{kind}:"
        f"{_generation(server, family, 'configuration')}:{connection}:{settings}"
    )


def _generation_key(server: Server, family: Family, generation: _Generation) -> str:
    return f"{KEY_PREFIX}generation:{require_persisted_server(server)}:{family}:{generation}"


def _generation(server: Server, family: Family, generation: _Generation) -> str:
    key = _generation_key(server, family, generation)
    value = cache.get(key)
    if isinstance(value, str):
        return value
    candidate = secrets.token_hex(16)
    # add() keeps a generation that a concurrent read stored first.
    cache.add(key, candidate, timeout=None)
    value = cache.get(key)
    return value if isinstance(value, str) else candidate


def _rotate(server: Server, family: Family, generation: _Generation) -> None:
    cache.set(_generation_key(server, family, generation), secrets.token_hex(16), timeout=None)
