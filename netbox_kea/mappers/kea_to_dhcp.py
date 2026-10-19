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

DHCPv6 uses ``subnet6``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .. import kea_paths
from ..dhcp_options import DHCPOption, parse_dhcp_option
from ..integrations.dhcp_import_report import DroppedEntry, Kind

logger = logging.getLogger(__name__)

# Scalar Kea config keys that map onto netbox_dhcp tuning fields (lifetimes, timers,
# lease/DDNS/BOOTP/network settings, and server-level globals).  ``config-get``
# returns these fully defaulted+inherited at both the global and subnet scope; the
# adapter decides which apply to which model and suppresses values inherited from
# the parent.  Captured verbatim here (the Kea→sys4 field mapping lives in the adapter).
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
    "relay",
    "interface-id",
    "rapid-commit",
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
    name: str | None
    space: str | None
    type: str | None
    array: bool | None
    record_types: tuple[str, ...]
    encapsulate: str | None

    @property
    def match_key(self) -> tuple:
        """Identity: (space, code)."""
        return (self.space, self.code)


@dataclass(frozen=True)
class PoolIntent:
    """A Kea pool string (``start-end`` range or ``CIDR``) within a subnet."""

    pool: str
    options: tuple[DHCPOption, ...] = ()

    @property
    def match_key(self) -> str:
        """Identity within a subnet: the normalized pool string."""
        return self.pool.strip()


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


@dataclass(frozen=True)
class SharedNetworkIntent:
    """A Kea shared-network (groups subnets)."""

    name: str
    family: int
    options: tuple[DHCPOption, ...]


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


@dataclass
class ServerConfigIntent:
    """Everything importable from one ``(server, family)`` Kea config block."""

    family: int
    configuration_complete: bool = False
    # From the Server Configuration Snapshot. None: the key is absent or invalid.
    host_reservation_identifiers: tuple[str, ...] | None = None
    shared_networks: list[SharedNetworkIntent] = field(default_factory=list)
    subnets: list[SubnetIntent] = field(default_factory=list)
    client_classes: list[ClientClassIntent] = field(default_factory=list)
    global_options: tuple[DHCPOption, ...] = ()
    option_defs: tuple[OptionDefIntent, ...] = ()
    global_settings: dict = field(default_factory=dict)
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


def _option_def_intent(raw, path: str, dropped: list[DroppedEntry]) -> OptionDefIntent | None:
    """Normalize one Kea ``option-def`` entry; drop one that is not a dict or has no valid code."""
    if not isinstance(raw, dict):
        dropped.append(DroppedEntry(Kind.OPTION_DEFINITION, path, "The entry is not an object."))
        return None
    try:
        code = int(raw["code"])
    except (KeyError, TypeError, ValueError):
        dropped.append(DroppedEntry(Kind.OPTION_DEFINITION, path, "The entry has no valid code."))
        return None
    record_types = raw.get("record-types")
    record_types = tuple(str(r) for r in record_types) if isinstance(record_types, list) else ()
    return OptionDefIntent(
        code=code,
        name=raw.get("name"),
        space=raw.get("space"),
        type=raw.get("type"),
        array=raw.get("array"),
        record_types=record_types,
        encapsulate=raw.get("encapsulate") or None,
    )


def _option_defs(raw_list, family: int, dropped: list[DroppedEntry]) -> tuple[OptionDefIntent, ...]:
    """Normalize an ``option-def`` list, dropping invalid entries."""
    if not isinstance(raw_list, list):
        return ()
    out = [
        _option_def_intent(raw, kea_paths.option_definition_entry(family, index), dropped)
        for index, raw in enumerate(raw_list)
    ]
    return tuple(o for o in out if o is not None)


def _pools(raw_list, subnet_path: str, dropped: list[DroppedEntry]) -> tuple[PoolIntent, ...]:
    """Normalize a subnet's ``pools`` list to non-empty pool strings (with options)."""
    if not isinstance(raw_list, list):
        return ()
    out: list[PoolIntent] = []
    for index, entry in enumerate(raw_list):
        pool = entry.get("pool") if isinstance(entry, dict) else None
        if not pool:
            dropped.append(
                DroppedEntry(Kind.POOL, kea_paths.pool_entry(subnet_path, index), "The entry has no pool range.")
            )
            continue
        path = kea_paths.pool(subnet_path, pool)
        out.append(PoolIntent(pool=pool, options=_options(entry.get("option-data"), path, dropped)))
    return tuple(out)


def _subnet_id(raw: dict) -> int | None:
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
    if not cidr:
        if sid is not None:
            path = kea_paths.subnet(family, sid, "")
        dropped.append(DroppedEntry(Kind.SUBNET, path, "The Subnet has no CIDR."))
        return None
    subnet_path = kea_paths.subnet(family, sid, cidr)
    return SubnetIntent(
        kea_subnet_id=sid,
        cidr=cidr,
        family=family,
        shared_network=shared_network,
        pools=_pools(raw.get("pools"), subnet_path, dropped),
        options=_options(raw.get("option-data"), subnet_path, dropped),
        settings=_settings(raw),
    )


def _client_class_intent(raw, family: int, path: str, dropped: list[DroppedEntry]) -> ClientClassIntent | None:
    """Normalize the Kea ``client-classes`` entry at *path*; drop one that is not a dict or has no name."""
    name = raw.get("name") if isinstance(raw, dict) else None
    if not name:
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
    )


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
    result.option_defs = _option_defs(conf.get("option-def"), family, dropped)
    result.global_settings = _settings(conf)

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
        if not name:
            path = kea_paths.shared_network_entry(family, net_index)
            dropped.append(
                DroppedEntry(Kind.SHARED_NETWORK, path, "The entry has no name, so its Subnets were not read.")
            )
            continue
        net_path = kea_paths.shared_network(family, name)
        result.shared_networks.append(
            SharedNetworkIntent(
                name=name, family=family, options=_options(raw_net.get("option-data"), net_path, dropped)
            )
        )
        for index, raw in enumerate(_config_collection(raw_net, subnet_key)):
            subnet = _subnet_intent(raw, family, name, kea_paths.subnet_entry(net_path, family, index), dropped)
            if subnet is not None:
                result.subnets.append(subnet)

    return result
