# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The parity ledger: what the DHCP Import does with each Kea key that it can meet.

:data:`LEDGER` lists each key of each Kea object once, by family and by the Kea object (a table of
``tests/kea_recordings/accepted-keys.json``). An entry is one of:

* :class:`Mapped`: the import writes the key to a netbox_dhcp model or field.
* :class:`NotImported`: the key is not imported, for a reason from the closed set of the run result.
* :class:`Pending`: a later ticket of #89 maps the key.
* :class:`Deprecated`: Kea rewrites the key to its replacement, so ``config-get`` never returns it.

An entry names each DHCP Plugin Capability (#88) that its write needs, and :mod:`.dhcp_plugin_capabilities` checks
each one. :data:`MERGED_KEYS` lists the keys that Kea merges into ``config-get`` from the parent object, and
:data:`KEA_DEFAULTS` the values that Kea gives when no level declares a key, for the Declared Value inference.
It reads no database. ``test_dhcp_import_ledger.py`` compares it with the recordings of a real Kea.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..constants import Family
from ..kea_paths import OPTION_DEF
from .dhcp_import_report import Capability, Reason


@dataclass(frozen=True)
class Mapped:
    """The import writes the key to *target*, a netbox_dhcp ``Model`` or ``Model.field``."""

    target: str
    capabilities: tuple[Capability, ...] = ()
    # The #89 ticket that completes a partial mapping.
    pending: int | None = None


@dataclass(frozen=True)
class NotImported:
    """The import does not write the key, for a reason of the run result."""

    reason: Reason = Reason.NO_PLUGIN_HOME

    def __post_init__(self):
        if self.reason not in (Reason.NO_PLUGIN_HOME, Reason.INVALID_KEA_DATA):
            raise ValueError(f"{self.reason} is not a reason to leave a Kea key out of the import")


@dataclass(frozen=True)
class Pending:
    """The #89 ticket *ticket* maps the key."""

    ticket: int
    capabilities: tuple[Capability, ...] = ()


@dataclass(frozen=True)
class Deprecated:
    """Kea rewrites the key to *replacement* in ``config-get``."""

    replacement: str


Entry = Mapped | NotImported | Pending | Deprecated

_USER_CONTEXT = (Capability.USER_CONTEXT,)
# A Shared Network and its membership need it; its other keys need it only through their object.
_OPTIONAL_PREFIX = (Capability.SHARED_NETWORK_OPTIONAL_PREFIX,)
_LIFETIMES = ("valid-lifetime", "min-valid-lifetime", "max-valid-lifetime")
_PREFERRED_LIFETIMES = ("preferred-lifetime", "min-preferred-lifetime", "max-preferred-lifetime")
_BOOT_FIELDS = ("next-server", "server-hostname", "boot-file-name")
_DDNS = (
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
)
_LEASE = (
    "renew-timer",
    "rebind-timer",
    "calculate-tee-times",
    "t1-percent",
    "t2-percent",
    "cache-threshold",
    "cache-max-age",
    "store-extended-info",
    "allocator",
    "adaptive-lease-time-threshold",
    "reservations-global",
    "reservations-in-subnet",
    "reservations-out-of-pool",
)
_CLASS_REFERENCES = ("client-classes", "evaluate-additional-classes")
_DHCP4_LEASE = ("match-client-id", "authoritative", "offer-lifetime", *_BOOT_FIELDS)
# The keys that Kea 3.2 rewrites, in every object that accepts them.
_DEPRECATED = {
    "client-class": Deprecated("client-classes"),
    "require-client-classes": Deprecated("evaluate-additional-classes"),
    "comment": Deprecated("user-context"),
}


def _fields(model: str, *keys: str) -> dict[str, Entry]:
    """Map each key to the *model* field of the same name."""
    return {key: Mapped(f"{model}.{key.replace('-', '_')}") for key in keys}


def _no_plugin_home(*keys: str) -> dict[str, Entry]:
    return {key: NotImported() for key in keys}


def _code_capabilities(family: Family) -> tuple[Capability, ...]:
    """Return the capability that an option code of *family* needs: DHCPv6 codes go above 255."""
    return (Capability.OPTION_CODE_16_BIT,) if family == 6 else ()


def _network_settings(family: Family) -> tuple[str, ...]:
    """Return the scalar keys that a Subnet and a Shared Network of *family* share."""
    own = _DHCP4_LEASE if family == 4 else _PREFERRED_LIFETIMES
    rest = ("pd-allocator", "rapid-commit", "interface-id") if family == 6 else ()
    return (*_LIFETIMES, *own, *_LEASE, *_DDNS, *rest)


def _global(family: Family) -> dict[str, Entry]:
    own: tuple[str, ...] = (*_DHCP4_LEASE, "echo-client-id")
    if family == 6:
        own = (*_PREFERRED_LIFETIMES, "pd-allocator", "relay-supplied-options")
    if family == 4:
        protocol = {"stash-agent-options": Mapped("DHCPServer.stash_agent_options", (Capability.STASH_AGENT_OPTIONS,))}
    else:
        protocol = {
            "allow-address-registration": Mapped(
                "DHCPServer.allow_address_registration", (Capability.ADDRESS_REGISTRATION,)
            )
        }
    server_level = () if family == 4 else ("data-directory", "mac-sources")
    entries = {
        **_fields("DHCPServer", *_LIFETIMES, *_LEASE, *_DDNS, *own, "decline-probation-period"),
        "host-reservation-identifiers": Mapped(
            "DHCPServer.host_reservation_identifiers", (Capability.FLEX_ID_IDENTIFIER,)
        ),
        "option-data": Mapped("Option"),
        OPTION_DEF: Mapped("OptionDefinition"),
        "client-classes": Mapped("ClientClass"),
        f"subnet{family}": Mapped("Subnet"),
        "reservations": Mapped("HostReservation"),
        "shared-networks": Mapped("SharedNetwork", _OPTIONAL_PREFIX),
        "user-context": Mapped("DHCPServer.user_context", _USER_CONTEXT),
        "comment": _DEPRECATED["comment"],
        # The interface list links DHCPServer interfaces; the other keys are Kea socket settings.
        "interfaces-config": Mapped("DHCPServer.interfaces"),
        **protocol,
        # Server-level facts with no plugin home by design (#88 "Not plugin gaps").
        **_no_plugin_home(
            "lease-database",
            "hosts-database",
            "hosts-databases",
            "hooks-libraries",
            "control-sockets",
            "loggers",
            "dhcp-ddns",
            "expired-leases-processing",
            "multi-threading",
            "sanity-checks",
            "config-control",
            "server-tag",
            "dhcp-queue-control",
            "dhcp4o6-port",
            "statistic-default-sample-age",
            "statistic-default-sample-count",
            "parked-packet-limit",
            "compatibility",
            "early-global-reservations-lookup",
            "ip-reservations-unique",
            "reservations-lookup-first",
            *server_level,
        ),
    }
    if family == 6:
        entries["server-id"] = Mapped("DHCPServer.server_id", (Capability.SERVER_ID_FIELDS,))
    return entries


def _subnet(family: Family) -> dict[str, Entry]:
    entries = {
        **_fields("Subnet", *_network_settings(family)),
        "subnet": Mapped("Subnet.prefix"),
        "id": Mapped("Subnet.subnet_id", (Capability.SUBNET_ID_PER_SERVER,)),
        "relay": Mapped("Subnet.relay", (Capability.RELAY_ADDRESS_LIST,)),
        "option-data": Mapped("Option"),
        "pools": Mapped("Pool"),
        "reservations": Mapped("HostReservation"),
        **_fields("Subnet", *_CLASS_REFERENCES),
        "interface": Mapped("Subnet.server_interfaces"),
        "user-context": Mapped("Subnet.user_context", _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }
    if family == 4:
        gated = (Capability.DHCP4O6_SUBNET_SELECTION,)
        entries |= {
            key: Mapped(f"Subnet.dhcp{key.replace('-', '_')}", gated)
            for key in ("4o6-interface", "4o6-interface-id", "4o6-subnet")
        }
    else:
        entries["pd-pools"] = Mapped("PDPool")
    return entries


def _shared_network(family: Family) -> dict[str, Entry]:
    return {
        **_fields("SharedNetwork", *_network_settings(family), *_CLASS_REFERENCES),
        "name": Mapped("SharedNetwork.name", (*_OPTIONAL_PREFIX, Capability.NAME_PER_SERVER)),
        f"subnet{family}": Mapped("Subnet.shared_network", _OPTIONAL_PREFIX),
        "interface": Mapped("SharedNetwork.server_interfaces"),
        "relay": Mapped("SharedNetwork.relay", (Capability.RELAY_ADDRESS_LIST,)),
        "option-data": Mapped("Option"),
        "user-context": Mapped("SharedNetwork.user_context", _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }


def _pool() -> dict[str, Entry]:
    return {
        **_fields("Pool", "pool-id", *_CLASS_REFERENCES, *_DDNS),
        "pool": Mapped("Pool.ip_range"),
        "option-data": Mapped("Option"),
        "user-context": Mapped("Pool.user_context", _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }


def _pd_pool() -> dict[str, Entry]:
    return {
        **_fields("PDPool", "pool-id", *_CLASS_REFERENCES),
        # Kea gives each prefix as an address and a length; the plugin holds one NetBox Prefix.
        "prefix": Mapped("PDPool.prefix"),
        "prefix-len": Mapped("PDPool.prefix"),
        "delegated-len": Mapped("PDPool.delegated_length"),
        "excluded-prefix": Mapped("PDPool.excluded_prefix"),
        "excluded-prefix-len": Mapped("PDPool.excluded_prefix"),
        "option-data": Mapped("Option"),
        "user-context": Mapped("PDPool.user_context", _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }


def _reservation(family: Family) -> dict[str, Entry]:
    entries = {
        **_fields("HostReservation", "hw-address", "duid", "flex-id", "hostname"),
        "option-data": Mapped("Option"),
        "client-classes": Mapped("HostReservation.client_classes"),
        "user-context": Mapped("HostReservation.user_context", _USER_CONTEXT),
    }
    if family == 4:
        entries |= _fields("HostReservation", "circuit-id", "client-id", *_BOOT_FIELDS)
        entries |= {"ip-address": Mapped("HostReservation.ipv4_address")}
    else:
        entries |= {
            "ip-addresses": Mapped("HostReservation.ipv6_addresses"),
            "prefixes": Mapped("HostReservation.ipv6_prefixes"),
            "excluded-prefixes": Mapped("HostReservation.excluded_ipv6_prefixes"),
        }
    return entries


def _client_class(family: Family) -> dict[str, Entry]:
    entries = {
        **_fields("ClientClass", "test", "template-test", "only-in-additional-list", *_LIFETIMES),
        "name": Mapped("ClientClass.name", (Capability.NAME_PER_SERVER,)),
        "option-data": Mapped("Option"),
        "user-context": Mapped("ClientClass.user_context", _USER_CONTEXT),
        "only-if-required": Deprecated("only-in-additional-list"),
    }
    if family == 4:
        entries |= {**_fields("ClientClass", *_BOOT_FIELDS), OPTION_DEF: Mapped("OptionDefinition.client_class")}
    else:
        entries |= _fields("ClientClass", *_PREFERRED_LIFETIMES)
    return entries


def _option_definition(family: Family) -> dict[str, Entry]:
    return {
        **_fields("OptionDefinition", "name", "type", "array", "record-types", "encapsulate"),
        "code": Mapped("OptionDefinition.code", _code_capabilities(family)),
        "space": Mapped("OptionDefinition.space", (Capability.OPTION_SPACES,)),
        "user-context": Mapped("OptionDefinition.user_context", _USER_CONTEXT),
        "metadata": NotImported(),
        "comment": _DEPRECATED["comment"],
    }


def _option(family: Family) -> dict[str, Entry]:
    return {
        "name": Mapped("Option.definition", (Capability.OPTION_WITHOUT_DEFINITION,)),
        "code": Mapped("Option.definition", (Capability.OPTION_WITHOUT_DEFINITION, *_code_capabilities(family))),
        "space": Mapped("Option.definition", (Capability.OPTION_SPACES,)),
        "data": Mapped("Option.data"),
        "csv-format": Mapped("Option.csv_format"),
        "always-send": Mapped("Option.send_option"),
        "never-send": Mapped("Option.send_option"),
        "client-classes": Mapped("Option.client_classes"),
        "user-context": Mapped("Option.user_context", _USER_CONTEXT),
        "metadata": NotImported(),
        "comment": _DEPRECATED["comment"],
    }


def _interfaces(family: Family) -> dict[str, Entry]:
    """Return the ``interfaces-config`` keys: where the server serves DHCP, and how Kea opens its sockets."""
    socket_keys = ("dhcp-socket-type", "outbound-interface") if family == 4 else ()
    return {
        "interfaces": Mapped("DHCPServer.interfaces"),
        **_no_plugin_home(
            "re-detect",
            "service-sockets-require-all",
            "service-sockets-retry-wait-time",
            "service-sockets-max-retries",
            "user-context",
            *socket_keys,
        ),
    }


def _family(family: Family) -> dict[str, dict[str, Entry]]:
    tables = {
        f"Dhcp{family}": _global(family),
        "shared-networks": _shared_network(family),
        f"subnet{family}": _subnet(family),
        "pools": _pool(),
        "reservations": _reservation(family),
        "client-classes": _client_class(family),
        OPTION_DEF: _option_definition(family),
        "option-data": _option(family),
        "interfaces-config": _interfaces(family),
    }
    if family == 6:
        tables["pd-pools"] = _pd_pool()
    return tables


LEDGER: dict[Family, dict[str, dict[str, Entry]]] = {4: _family(4), 6: _family(6)}

_MERGED_LEASE_KEYS = (
    *_LIFETIMES,
    "renew-timer",
    "rebind-timer",
    "calculate-tee-times",
    "t1-percent",
    "t2-percent",
    "cache-threshold",
    "cache-max-age",
    "store-extended-info",
    "allocator",
    "adaptive-lease-time-threshold",
)
_MERGED_INTO_NETWORKS: dict[Family, frozenset[str]] = {
    4: frozenset({*_MERGED_LEASE_KEYS, "offer-lifetime"}),
    6: frozenset({*_MERGED_LEASE_KEYS, *_PREFERRED_LIFETIMES, "pd-allocator"}),
}

# Kea 3.2 merges into a Shared Network from the global configuration, and into a Subnet from its parent. The global
# configuration has no relay, so only a member Subnet takes one. Kea merges nothing into client classes, Pools and
# PD Pools.
MERGED_KEYS: dict[Family, dict[str, frozenset[str]]] = {
    4: {
        "client-classes": frozenset(),
        "shared-networks": _MERGED_INTO_NETWORKS[4],
        "subnet4": _MERGED_INTO_NETWORKS[4] | {"relay"},
        "pools": frozenset(),
    },
    6: {
        "client-classes": frozenset(),
        "shared-networks": _MERGED_INTO_NETWORKS[6],
        "subnet6": _MERGED_INTO_NETWORKS[6] | {"relay"},
        "pools": frozenset(),
        "pd-pools": frozenset(),
    },
}

# The values that Kea 3.2 returns for these keys on an object that declares none and into which Kea merges none.
KEA_DEFAULTS: dict[Family, dict[str, dict[str, object]]] = {
    4: {
        # Kea's unset next-server, not an address to bind.
        "client-classes": {"next-server": "0.0.0.0", "server-hostname": "", "boot-file-name": ""},  # noqa: S104
        "shared-networks": {"relay": {"ip-addresses": []}},
        "subnet4": {"4o6-interface": "", "4o6-interface-id": "", "4o6-subnet": ""},
        "pools": {},
    },
    6: {
        "client-classes": {},
        "shared-networks": {"relay": {"ip-addresses": []}, "rapid-commit": False},
        "subnet6": {"rapid-commit": False},
        "pools": {},
        "pd-pools": {},
    },
}


def differences(recorded: dict[Family, dict[str, set[str]]]) -> list[str]:
    """Return each disagreement between :data:`LEDGER` and the keys that Kea accepts, by family and object."""
    found = []
    for family, listed in LEDGER.items():
        accepted = recorded.get(family, {})
        for table in sorted(listed.keys() | accepted.keys()):
            name = f"{table} (DHCPv{family})"
            if table not in accepted:
                found.append(f"{name}: Kea has no such object")
                continue
            keys = listed.get(table, {})
            found.extend(f"{name}: {key} is not in the ledger" for key in sorted(accepted[table] - keys.keys()))
            found.extend(
                f"{name}: {key} is in the ledger, but Kea has no such key"
                for key in sorted(keys.keys() - accepted[table])
            )
    return found
