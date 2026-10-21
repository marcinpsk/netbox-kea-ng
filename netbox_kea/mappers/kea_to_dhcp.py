# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Pure transforms: a Kea ``DhcpN`` config block → normalized DHCP-plugin intent.

This module is deliberately free of Django, the ORM, and ``netbox_dhcp``: it
only reshapes the dicts that :meth:`KeaClient.command` returns for ``config-get``
into small dataclasses, plus the match keys used to upsert ``netbox_dhcp`` rows
idempotently.  Keeping it pure means it is fully unit-testable in CI, where the
optional DHCP plugin is not installed.

Input shape (the ``Dhcp4``/``Dhcp6`` object from ``config-get``)::

    {
        "subnet4": [{"id": 1, "subnet": "10.0.0.0/24",
                     "pools": [{"pool": "10.0.0.10-10.0.0.200"}],
                     "option-data": [...]}],
        "shared-networks": [{"name": "office", "subnet4": [ ...same shape... ]}],
    }

DHCPv6 uses ``subnet6``, and a DHCPv6 subnet can also hold ``pd-pools``.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .. import kea_paths
from ..dhcp_options import DHCPOption, parse_dhcp_option, parse_option_definition
from ..integrations.dhcp_import_fields import GATED_SUBNET_FIELDS
from ..integrations.dhcp_import_report import DroppedEntry, Kind

if TYPE_CHECKING:
    from datetime import datetime

logger = logging.getLogger(__name__)

# Scalar Kea config keys that map onto netbox_dhcp tuning fields (lifetimes, timers,
# lease/DDNS/BOOTP/network settings, and server-level globals), and the Subnet interface.  ``config-get``
# merges some of them from the parent; the plan keeps only the Declared Values.
# Captured verbatim here (the Kea→sys4 field mapping lives in the adapter).
KEA_SETTINGS_KEYS: tuple[str, ...] = (
    # lifetimes / timers
    "valid-lifetime",
    "min-valid-lifetime",
    "max-valid-lifetime",
    "preferred-lifetime",
    "min-preferred-lifetime",
    "max-preferred-lifetime",
    "offer-lifetime",
    "renew-timer",
    "rebind-timer",
    # lease behaviour
    "match-client-id",
    "authoritative",
    "reservations-global",
    "reservations-out-of-pool",
    "reservations-in-subnet",
    "calculate-tee-times",
    "t1-percent",
    "t2-percent",
    "cache-threshold",
    "cache-max-age",
    "store-extended-info",
    "allocator",
    "pd-allocator",
    kea_paths.ADAPTIVE_LEASE_TIME_THRESHOLD,
    # DDNS
    "ddns-send-updates",
    "ddns-override-no-update",
    "ddns-override-client-update",
    "ddns-replace-client-name",
    "ddns-generated-prefix",
    "ddns-qualifying-suffix",
    "ddns-update-on-renew",
    "ddns-conflict-resolution-mode",
    "ddns-ttl-percent",
    "ddns-ttl",
    "ddns-ttl-min",
    "ddns-ttl-max",
    "hostname-char-set",
    "hostname-char-replacement",
    # BOOTP
    "next-server",
    "server-hostname",
    "boot-file-name",
    # network (subnet)
    kea_paths.INTERFACE,
    "interface-id",
    "rapid-commit",
    # relay and the DHCPv4-over-DHCPv6 keys
    *(key for key, _attr, _transform, _capability in GATED_SUBNET_FIELDS),
    # server-level globals
    "decline-probation-period",
    "echo-client-id",
    "relay-supplied-options",
    "server-id",
)


def _settings(raw: dict) -> dict:
    """Extract the subset of :data:`KEA_SETTINGS_KEYS` present in a Kea config dict."""
    if not isinstance(raw, dict):
        return {}
    return {k: raw[k] for k in KEA_SETTINGS_KEYS if k in raw}


@dataclass(frozen=True)
class OptionDefIntent:
    """A Kea custom ``option-def`` entry (defines a non-standard option code)."""

    code: int
    name: str
    space: str
    type: str
    array: bool
    record_types: tuple[str, ...]
    encapsulate: str | None
    # None: the definition declares no user-context.
    user_context: dict | None = None


@dataclass(frozen=True)
class PoolIntent:
    """A Kea pool string (``start-end`` range or ``CIDR``) within a subnet, with its Declared Values."""

    pool: str
    options: tuple[DHCPOption, ...] = ()
    pool_id: int | None = None
    # A class list is None when it is not valid, so the import keeps the class links.
    client_classes: tuple[str, ...] | None = ()
    evaluate_additional_classes: tuple[str, ...] | None = ()
    # Kea merges no value into a Pool, so each setting is a Declared Value.
    settings: dict = field(default_factory=dict)
    # None: the Pool declares no user-context.
    user_context: dict | None = None

    @property
    def match_key(self) -> str:
        """Identity within a subnet: the normalized pool string."""
        return self.pool.strip()


@dataclass(frozen=True)
class PDPoolIntent:
    """A Kea ``pd-pools`` entry of a DHCPv6 subnet: its prefix, its delegated length and its Declared Values."""

    prefix: ipaddress.IPv6Network
    delegated_length: int
    # None: the PD Pool declares no excluded prefix, or the one it declares is not valid.
    excluded_prefix: ipaddress.IPv6Network | None = None
    options: tuple[DHCPOption, ...] = ()
    pool_id: int | None = None
    # A class list is None when it is not valid, so the import keeps the class links.
    client_classes: tuple[str, ...] | None = ()
    evaluate_additional_classes: tuple[str, ...] | None = ()
    # None: the PD Pool declares no user-context.
    user_context: dict | None = None


@dataclass(frozen=True)
class SubnetIntent:
    """A Kea subnet, with its parent shared-network (if any) and children."""

    kea_subnet_id: int | None
    cidr: str
    family: int
    shared_network: str | None
    pools: tuple[PoolIntent, ...]
    options: tuple[DHCPOption, ...]
    settings: dict = field(default_factory=dict)
    # A class list is None when it is not valid, so the import keeps the class links.
    client_classes: tuple[str, ...] | None = ()
    evaluate_additional_classes: tuple[str, ...] | None = ()
    # None: the Subnet declares no user-context.
    user_context: dict | None = None
    pd_pools: tuple[PDPoolIntent, ...] = ()


@dataclass(frozen=True)
class SharedNetworkIntent:
    """A Kea shared-network (groups subnets)."""

    name: str
    family: int
    options: tuple[DHCPOption, ...]
    settings: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ClientClassIntent:
    """A Kea client-class (classification rule + per-class settings/options)."""

    name: str
    family: int
    test: str
    template_test: str
    only_in_additional_list: bool | None
    options: tuple[DHCPOption, ...]
    settings: dict = field(default_factory=dict)
    # None: the class declares no user-context.
    user_context: dict | None = None
    # The custom Option Definitions that the class declares (DHCPv4 only).
    option_defs: tuple[OptionDefIntent, ...] = ()


@dataclass
class ServerConfigIntent:
    """Everything importable from one ``(server, family)`` Kea config block."""

    family: int
    configuration_complete: bool = False
    # When the read of this configuration started, before config-get. None: not known, so no mapped row is stale.
    read_started: datetime | None = None
    # From the Server Configuration Snapshot. None: the key is absent or invalid.
    host_reservation_identifiers: tuple[str, ...] | None = None
    shared_networks: list[SharedNetworkIntent] = field(default_factory=list)
    subnets: list[SubnetIntent] = field(default_factory=list)
    client_classes: list[ClientClassIntent] = field(default_factory=list)
    global_options: tuple[DHCPOption, ...] = ()
    option_defs: tuple[OptionDefIntent, ...] = ()
    global_settings: dict = field(default_factory=dict)
    # None: the configuration declares no user-context.
    user_context: dict | None = None
    # The entries of the interface list. None: the list is not valid, so the import leaves the links alone.
    interfaces: tuple[str, ...] | None = ()
    # Entries that the parse dropped as invalid, each with its Kea path.
    dropped: list[DroppedEntry] = field(default_factory=list)


def _optional_dhcp_option(raw, path: str, dropped: list[DroppedEntry]) -> DHCPOption | None:
    try:
        return parse_dhcp_option(raw)
    except ValueError as exc:
        logger.warning("Discarded an invalid option-data entry: %r", raw, exc_info=True)
        dropped.append(DroppedEntry(Kind.OPTION, path, str(exc)))
        return None


def _options(raw_list, parent: str, dropped: list[DroppedEntry]) -> tuple[DHCPOption, ...]:
    """Normalize the ``option-data`` list of the object at *parent*, dropping invalid entries."""
    if raw_list is None:
        return ()
    if not isinstance(raw_list, list):
        logger.warning("Discarded a non-list option-data collection: %r", raw_list)
        dropped.append(DroppedEntry(Kind.OPTION, kea_paths.option_collection(parent), "The collection is not a list."))
        return ()
    options = (
        _optional_dhcp_option(raw, kea_paths.option_entry(parent, index), dropped) for index, raw in enumerate(raw_list)
    )
    return tuple(option for option in options if option is not None)


def _option_def_intent(raw, family: int, path: str, dropped: list[DroppedEntry]) -> OptionDefIntent | None:
    """Normalize one Kea ``option-def`` entry; drop one that :func:`parse_option_definition` refuses."""
    try:
        definition = parse_option_definition(raw, family)
    except ValueError as exc:
        dropped.append(DroppedEntry(Kind.OPTION_DEFINITION, path, str(exc)))
        return None
    return OptionDefIntent(
        code=definition.code,
        name=definition.name,
        space=definition.space,
        type=definition.type,
        array=definition.array,
        record_types=definition.record_types,
        encapsulate=definition.encapsulate,
        user_context=raw.get(kea_paths.USER_CONTEXT),
    )


def _option_defs(
    raw_list, family: int, dropped: list[DroppedEntry], class_name: str | None = None
) -> tuple[OptionDefIntent, ...]:
    """Normalize the ``option-def`` list of the daemon or of the client class *class_name*, dropping invalid entries.

    An explicit null is not a list, so it is dropped.
    """
    if not isinstance(raw_list, list):
        path = kea_paths.option_definition_collection(family, class_name)
        dropped.append(DroppedEntry(Kind.OPTION_DEFINITION, path, "The collection is not a list."))
        return ()
    out = [
        _option_def_intent(raw, family, kea_paths.option_definition_entry(family, index, class_name), dropped)
        for index, raw in enumerate(raw_list)
    ]
    return tuple(o for o in out if o is not None)


def _pools(raw_list, subnet_path: str, dropped: list[DroppedEntry]) -> tuple[PoolIntent, ...]:
    """Normalize a subnet's ``pools`` list to non-empty pool strings (with options). A null list is dropped."""
    if not isinstance(raw_list, list):
        dropped.append(DroppedEntry(Kind.POOL, kea_paths.pool_collection(subnet_path), "The collection is not a list."))
        return ()
    out: list[PoolIntent] = []
    for index, entry in enumerate(raw_list):
        pool = entry.get("pool") if isinstance(entry, dict) else None
        if not isinstance(pool, str) or not pool:
            dropped.append(
                DroppedEntry(Kind.POOL, kea_paths.pool_entry(subnet_path, index), "The entry has no pool range.")
            )
            continue
        path = kea_paths.pool(subnet_path, pool)
        out.append(
            PoolIntent(
                pool=pool,
                options=_options(entry.get("option-data"), path, dropped),
                pool_id=_pool_id(entry.get(kea_paths.POOL_ID), Kind.POOL, path, dropped),
                client_classes=_class_list(entry, kea_paths.CLIENT_CLASSES, Kind.POOL, path, dropped),
                evaluate_additional_classes=_class_list(
                    entry, kea_paths.EVALUATE_ADDITIONAL_CLASSES, Kind.POOL, path, dropped
                ),
                settings=_settings(entry),
                user_context=entry.get(kea_paths.USER_CONTEXT),
            )
        )
    return tuple(out)


def _pool_id(raw, kind: Kind, path: str, dropped: list[DroppedEntry]) -> int | None:
    """Read the ``pool-id`` of the Pool or PD Pool (*kind*) at *path*; drop one that is not a non-negative integer."""
    if raw is None:
        return None
    if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
        return raw
    dropped.append(
        DroppedEntry(kind, kea_paths.setting(path, kea_paths.POOL_ID), "The ID is not a non-negative integer.")
    )
    return None


def _ipv6_prefix(address, length) -> ipaddress.IPv6Network | None:
    """Return the IPv6 prefix of a Kea address and prefix length, or ``None`` when they are not one prefix."""
    if not isinstance(address, str) or not isinstance(length, int) or isinstance(length, bool):
        return None
    try:
        # Kea refuses a prefix with bits set after its length, so a strict parse matches Kea.
        return ipaddress.IPv6Network(f"{address}/{length}")
    except ValueError:
        return None


def _excluded_prefix(raw: dict, path: str, dropped: list[DroppedEntry]) -> ipaddress.IPv6Network | None:
    """Read the excluded prefix of the PD Pool at *path*; drop one that is not a valid prefix."""
    if kea_paths.EXCLUDED_PREFIX not in raw and kea_paths.EXCLUDED_PREFIX_LEN not in raw:
        return None
    excluded = _ipv6_prefix(raw.get(kea_paths.EXCLUDED_PREFIX), raw.get(kea_paths.EXCLUDED_PREFIX_LEN))
    if excluded is None:
        path = kea_paths.setting(path, kea_paths.EXCLUDED_PREFIX)
        dropped.append(DroppedEntry(Kind.PD_POOL, path, "The excluded prefix is not a valid prefix."))
    return excluded


def _pd_pool_intent(raw, subnet_path: str, dropped: list[DroppedEntry]) -> PDPoolIntent | None:
    """Normalize one ``pd-pools`` entry; return ``None`` for one without a valid prefix and delegated length.

    The DHCP plugin decides whether it can hold the lengths, for example a delegated length shorter than the prefix.
    """
    entry = raw if isinstance(raw, dict) else {}
    prefix = _ipv6_prefix(entry.get(kea_paths.PREFIX), entry.get(kea_paths.PREFIX_LEN))
    delegated = entry.get(kea_paths.DELEGATED_LEN)
    valid_length = (
        isinstance(delegated, int) and not isinstance(delegated, bool) and 0 <= delegated <= ipaddress.IPV6LENGTH
    )
    if prefix is None or not valid_length:
        return None
    path = kea_paths.pd_pool(subnet_path, str(prefix), delegated)
    return PDPoolIntent(
        prefix=prefix,
        delegated_length=delegated,
        excluded_prefix=_excluded_prefix(entry, path, dropped),
        options=_options(entry.get(kea_paths.OPTION_DATA), path, dropped),
        pool_id=_pool_id(entry.get(kea_paths.POOL_ID), Kind.PD_POOL, path, dropped),
        client_classes=_class_list(entry, kea_paths.CLIENT_CLASSES, Kind.PD_POOL, path, dropped),
        evaluate_additional_classes=_class_list(
            entry, kea_paths.EVALUATE_ADDITIONAL_CLASSES, Kind.PD_POOL, path, dropped
        ),
        user_context=entry.get(kea_paths.USER_CONTEXT),
    )


def _pd_pools(raw_list, subnet_path: str, dropped: list[DroppedEntry]) -> tuple[PDPoolIntent, ...]:
    """Normalize the ``pd-pools`` list of a DHCPv6 subnet, dropping invalid entries. A null list is dropped."""
    if not isinstance(raw_list, list):
        path = kea_paths.pd_pool_collection(subnet_path)
        dropped.append(DroppedEntry(Kind.PD_POOL, path, "The collection is not a list."))
        return ()
    out: list[PDPoolIntent] = []
    for index, raw in enumerate(raw_list):
        intent = _pd_pool_intent(raw, subnet_path, dropped)
        if intent is None:
            path = kea_paths.pd_pool_entry(subnet_path, index)
            dropped.append(DroppedEntry(Kind.PD_POOL, path, "The entry has no valid prefix and delegated length."))
        else:
            out.append(intent)
    return tuple(out)


def _class_list(raw: dict, key: str, kind: Kind, path: str, dropped: list[DroppedEntry]) -> tuple[str, ...] | None:
    """Read the class names of the list *key* of the *kind* at *path*; drop a list that is not of names (``None``)."""
    names = raw.get(key, [])
    if isinstance(names, list) and all(isinstance(name, str) and name for name in names):
        return tuple(names)
    dropped.append(DroppedEntry(kind, kea_paths.setting(path, key), "The list is not a list of class names."))
    return None


def _subnet_id(raw: dict) -> int | None:
    if isinstance(raw.get("id"), bool):
        return None
    try:
        return int(raw["id"])
    except (KeyError, TypeError, ValueError):
        return None


def _subnet_intent(
    raw, family: int, shared_network: str | None, path: str, dropped: list[DroppedEntry]
) -> SubnetIntent | None:
    """Normalize the Kea subnet entry at *path*; drop one that is not a dict or has no CIDR."""
    if not isinstance(raw, dict):
        dropped.append(DroppedEntry(Kind.SUBNET, path, "The entry is not an object."))
        return None
    sid = _subnet_id(raw)
    cidr = raw.get("subnet")
    if not isinstance(cidr, str) or not cidr:
        if sid is not None:
            path = kea_paths.subnet(family, sid)
        dropped.append(DroppedEntry(Kind.SUBNET, path, "The Subnet has no CIDR."))
        return None
    subnet_path = kea_paths.subnet(family, sid, cidr)
    return SubnetIntent(
        kea_subnet_id=sid,
        cidr=cidr,
        family=family,
        shared_network=shared_network,
        pools=_pools(raw.get("pools", []), subnet_path, dropped),
        options=_options(raw.get("option-data"), subnet_path, dropped),
        settings=_settings(raw),
        client_classes=_class_list(raw, kea_paths.CLIENT_CLASSES, Kind.SUBNET, subnet_path, dropped),
        evaluate_additional_classes=_class_list(
            raw, kea_paths.EVALUATE_ADDITIONAL_CLASSES, Kind.SUBNET, subnet_path, dropped
        ),
        user_context=raw.get(kea_paths.USER_CONTEXT),
        pd_pools=_pd_pools(raw.get(kea_paths.PD_POOLS, []), subnet_path, dropped) if family == 6 else (),
    )


def _client_class_intent(raw, family: int, path: str, dropped: list[DroppedEntry]) -> ClientClassIntent | None:
    """Normalize the Kea ``client-classes`` entry at *path*; drop one that is not a dict or has no name."""
    name = raw.get("name") if isinstance(raw, dict) else None
    if not isinstance(name, str) or not name:
        dropped.append(DroppedEntry(Kind.CLIENT_CLASS, path, "The entry has no name."))
        return None
    # Kea renamed ``only-if-required`` → ``only-in-additional-list`` (2.7.4); accept either.
    only = raw.get("only-in-additional-list")
    if only is None:
        only = raw.get("only-if-required")
    return ClientClassIntent(
        name=name,
        family=family,
        test=raw.get("test", "") or "",
        template_test=raw.get("template-test", "") or "",
        only_in_additional_list=only,
        options=_options(raw.get("option-data"), kea_paths.client_class(family, name), dropped),
        settings=_settings(raw),
        user_context=raw.get(kea_paths.USER_CONTEXT),
        option_defs=_option_defs(raw.get(kea_paths.OPTION_DEF, []), family, dropped, name),
    )


def _interfaces(raw, family: int, dropped: list[DroppedEntry]) -> tuple[str, ...] | None:
    """Read the interface list of ``interfaces-config``. An absent list is empty; a malformed one is dropped."""
    if raw is None:
        return ()
    entries = raw.get("interfaces", []) if isinstance(raw, dict) else None
    if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
        path = f"{kea_paths.daemon(family)}/{kea_paths.INTERFACES_CONFIG}"
        dropped.append(DroppedEntry(Kind.SERVER, path, "The interface list is not a list of names."))
        return None
    return tuple(entries)


def _config_collection(conf: dict, key: str) -> list:
    """Read an optional config collection and reject a malformed container."""
    collection = conf.get(key, [])
    if not isinstance(collection, list):
        raise RuntimeError(f"Malformed Kea config: {key!r} must be a list")
    return collection


def parse_dhcp_config(conf: dict, version: int) -> ServerConfigIntent:
    """Parse a Kea ``Dhcp4``/``Dhcp6`` config block into a :class:`ServerConfigIntent`.

    Standalone subnets (under ``subnetN``) carry ``shared_network=None``; subnets
    nested in a ``shared-networks`` entry carry that network's name.  Malformed
    entries (non-dicts, subnets without a CIDR) are dropped into ``dropped`` rather than raising,
    so a partially-malformed live config still imports what it can.
    Malformed subnet, shared-network, and client-class containers raise RuntimeError.
    """
    if version not in (4, 6):
        raise ValueError(f"version must be 4 or 6, got {version!r}")
    family = version
    subnet_key = f"subnet{version}"
    result = ServerConfigIntent(family=family)

    if not isinstance(conf, dict):
        return result

    root = kea_paths.daemon(family)
    dropped = result.dropped
    result.global_options = _options(conf.get("option-data"), root, dropped)
    result.option_defs = _option_defs(conf.get(kea_paths.OPTION_DEF, []), family, dropped)
    result.global_settings = _settings(conf)
    # Global-only keys behind a DHCP Plugin Capability.
    for key in (kea_paths.ALLOW_ADDRESS_REGISTRATION, kea_paths.STASH_AGENT_OPTIONS):
        if key in conf:
            result.global_settings[key] = conf[key]
    result.user_context = conf.get(kea_paths.USER_CONTEXT)
    result.interfaces = _interfaces(conf.get(kea_paths.INTERFACES_CONFIG), family, dropped)

    for index, raw_cc in enumerate(_config_collection(conf, "client-classes")):
        cc = _client_class_intent(raw_cc, family, kea_paths.client_class_entry(family, index), dropped)
        if cc is not None:
            result.client_classes.append(cc)

    for index, raw in enumerate(_config_collection(conf, subnet_key)):
        subnet = _subnet_intent(raw, family, None, kea_paths.subnet_entry(root, family, index), dropped)
        if subnet is not None:
            result.subnets.append(subnet)

    for net_index, raw_net in enumerate(_config_collection(conf, "shared-networks")):
        name = raw_net.get("name") if isinstance(raw_net, dict) else None
        if not isinstance(name, str) or not name:
            path = kea_paths.shared_network_entry(family, net_index)
            dropped.append(
                DroppedEntry(Kind.SHARED_NETWORK, path, "The entry has no name, so its Subnets were not read.")
            )
            continue
        net_path = kea_paths.shared_network(family, name)
        result.shared_networks.append(
            SharedNetworkIntent(
                name=name,
                family=family,
                options=_options(raw_net.get("option-data"), net_path, dropped),
                settings=_settings(raw_net),
            )
        )
        for index, raw in enumerate(_config_collection(raw_net, subnet_key)):
            subnet = _subnet_intent(raw, family, name, kea_paths.subnet_entry(net_path, family, index), dropped)
            if subnet is not None:
                result.subnets.append(subnet)

    return result
