# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The display cache: keys, generations, TTLs, admission and invalidation of each display read (ADR 0009).

Only this module touches the Django cache. Authority reads (verification, synchronization, import, mutation
scopes and checks after a write) never call it. Callers pass a validated ``Family``.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Literal, Protocol, TypeVar

from django.core.cache import cache

from .constants import Family
from .models import DisplayCacheConfig, Server, require_persisted_server

#: The prefix of every key of the display cache. The test cache hygiene fixture clears it.
KEY_PREFIX = "netbox_kea:display:"

Kind = Literal["configuration", "catalogue"]
_Generation = Literal["configuration", "records"]

#: The DisplayCacheConfig field that holds the TTL of each kind. Both kinds read the Kea configuration only, so
#: their keys hold the configuration generation and not the records generation.
_TTL_FIELDS: dict[Kind, str] = {"configuration": "configuration_ttl", "catalogue": "configuration_ttl"}


class Cacheable(Protocol):
    """A display read that the cache can store."""

    @property
    def settled(self) -> bool:
        """Return false for a failed read or a page walk stopped by an error; the cache never stores it."""
        ...


T = TypeVar("T", bound=Cacheable)


def cached(server: Server, family: Family, kind: Kind, read: Callable[[], T]) -> T:
    """Return the entry of *kind* for *server* and *family*, or call *read* and store its result when it is settled.

    The key is built before *read* runs, so a rotation during the read leaves the result in an older generation.
    A TTL of 0 sends every call to *read* and stores nothing.
    """
    config = DisplayCacheConfig.get()
    ttl = getattr(config, _TTL_FIELDS[kind])
    if not ttl:
        return read()
    key = _entry_key(server, family, kind, config)
    entry = cache.get(key)
    if entry is not None:
        return entry
    value = read()
    if value.settled:
        cache.set(key, value, ttl)
    return value


def rotate_configuration(server: Server, family: Family) -> None:
    """Make every entry of *server* and *family* unreachable, after a change of the Kea configuration."""
    _rotate(server, family, "configuration")


def rotate_after_write(server: Server, family: Family | None, *, configuration: bool) -> None:
    """Rotate the records generation of *family*, and its configuration generation for a configuration change.

    ``None`` rotates both families. ``KeaClient`` calls this before and after each write command.
    """
    families: tuple[Family, ...] = (4, 6) if family is None else (family,)
    for each in families:
        _rotate(server, each, "records")
        if configuration:
            _rotate(server, each, "configuration")


def _entry_key(server: Server, family: Family, kind: Kind, config: DisplayCacheConfig) -> str:
    # A Server instance with old connection settings fills only the entry of those settings.
    connection = server.kea_connection(family).fingerprint()
    if config.last_updated is None:
        raise RuntimeError("The Display Cache settings row has no last_updated, so no key can show its last save.")
    # Every save of the settings row writes last_updated, so a save makes every older entry unreachable.
    settings = config.last_updated.isoformat()
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
    if isinstance(value, str):
        return value
    if value is None:
        # Evicted between add() and get(): an entry keyed on the candidate is never found again, which is a miss.
        return candidate
    raise RuntimeError(f"The display cache holds a {type(value).__name__} at {key}, not a generation.")


def _rotate(server: Server, family: Family, generation: _Generation) -> None:
    cache.set(_generation_key(server, family, generation), secrets.token_hex(16), timeout=None)
