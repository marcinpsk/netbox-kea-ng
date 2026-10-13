# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The display cache: keys, generations, TTLs, admission and invalidation of each display read (ADR 0009).

Only this module touches the Django cache. Authority reads (verification, synchronization, import, mutation
scopes and checks after a write) never call it. Callers pass a validated ``Family``.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable
from typing import Literal, NamedTuple, Protocol, TypeVar

from django.core.cache import cache

from . import __version__
from .constants import Family
from .models import DisplayCacheConfig, Server, require_persisted_server

#: The prefix of every key of the display cache. The test cache hygiene fixture clears it.
KEY_PREFIX = "netbox_kea:display:"

Kind = Literal["configuration", "catalogue", "reservations", "leases", "reservation_lookups", "utilization", "status"]
_Generation = Literal["configuration", "records"]
#: The parts of the query of one entry, such as a cursor and the search filters.
QueryParts = tuple[str | int | None, ...]


class _KindRule(NamedTuple):
    #: The DisplayCacheConfig field that holds the TTL of the kind.
    ttl_field: str
    #: The generations that the key holds; a write that rotates one of them makes the entry unreachable.
    generations: tuple[_Generation, ...]


_KINDS: dict[Kind, _KindRule] = {
    "configuration": _KindRule("configuration_ttl", ("configuration",)),
    "catalogue": _KindRule("configuration_ttl", ("configuration",)),
    # Records are parsed against the Subnet Catalogue, so their keys also hold the configuration generation.
    "reservations": _KindRule("reservations_ttl", ("configuration", "records")),
    # A Subnet search resolves its CIDR through the Subnet Catalogue, so Lease keys also hold the configuration one.
    "leases": _KindRule("leases_ttl", ("configuration", "records")),
    # The Reservation of a Lease row is parsed against the Subnet Catalogue, as a Reservation page is.
    "reservation_lookups": _KindRule("leases_ttl", ("configuration", "records")),
    # The Pools of a Subnet give its total, and its Leases give the assigned count.
    "utilization": _KindRule("status_ttl", ("configuration", "records")),
    # A daemon changes its status and version without a plugin write, so only the TTL ends the entry.
    "status": _KindRule("status_ttl", ()),
}


class Cacheable(Protocol):
    """A display read that the cache can store."""

    @property
    def settled(self) -> bool:
        """Return false for a failed read or a page walk stopped by an error; the cache never stores it."""
        ...


T = TypeVar("T", bound=Cacheable)


def cached(
    server: Server,
    family: Family | None,
    kind: Kind,
    read: Callable[[], T],
    *,
    query: QueryParts = (),
    refresh: bool = False,
    fresh: Callable[[T], bool] | None = None,
) -> T:
    """Return the entry of *kind* for *server*, *family* and *query*, or call *read* and store a settled result.

    A *family* of ``None`` is the Control Agent; only a kind without generations reads it.
    The key is built before *read* runs, so a rotation during the read leaves the result in an older generation.
    A TTL of 0 sends every call to *read* and stores nothing. With *refresh* the call removes the entry and reads
    again, so a refresh read that fails or is not settled leaves no entry. An entry that *fresh* rejects, such as a
    badge read before the table that shows it, is read again and replaced.
    """
    config = DisplayCacheConfig.get()
    ttl = getattr(config, _KINDS[kind].ttl_field)
    if not ttl:
        return read()
    key = _entry_key(server, family, kind, config, query)
    if refresh:
        cache.delete(key)
    else:
        entry = cache.get(key)
        if entry is not None and (fresh is None or fresh(entry)):
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


def _entry_key(server: Server, family: Family | None, kind: Kind, config: DisplayCacheConfig, query: QueryParts) -> str:
    rule = _KINDS[kind]
    if family is None and rule.generations:
        raise ValueError(f"The {kind} entries hold generations of a family, so the Control Agent has none.")
    # A Server instance with old connection settings fills only the entry of those settings.
    connection = server.kea_connection(family).fingerprint()
    if config.last_updated is None:
        raise RuntimeError("The Display Cache settings row has no last_updated, so no key can show its last save.")
    # Every save of the settings row writes last_updated, so a save makes every older entry unreachable.
    settings = config.last_updated.isoformat()
    generations = "" if family is None else ":".join(_generation(server, family, each) for each in rule.generations)
    digest = hashlib.sha256(json.dumps(query).encode()).hexdigest()
    # An entry pickled by another plugin version can hold another shape of its classes.
    return (
        f"{KEY_PREFIX}entry:{require_persisted_server(server)}:{family}:{kind}:{__version__}:"
        f"{generations}:{connection}:{settings}:{digest}"
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
