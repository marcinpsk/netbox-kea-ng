# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The parity ledger: what the DHCP Import does with each Kea key that it can meet.

:data:`LEDGER` lists each key of each Kea object once, by family and by the Kea object (a table of
``tests/kea_recordings/accepted-keys.json``). An entry is one of:

* :class:`Mapped`: the import writes the key to a netbox_dhcp model or field.
* :class:`NotImported`: the key is not imported, for a reason from the closed set of the run result.
* :class:`Pending`: a later ticket of #89 maps the key.
* :class:`Deprecated`: Kea rewrites the key to its replacement, so ``config-get`` never returns it.

An entry names each DHCP Plugin Capability (#88) that its write needs. :data:`MERGED_KEYS` lists the keys that
Kea merges into ``config-get`` from the parent object, which Declared Value inference uses.
It reads no database. ``test_dhcp_import_ledger.py`` compares it with the recordings of a real Kea.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .dhcp_import_report import Reason


class Capability(str, Enum):
    """A DHCP Plugin Capability that a key's write needs, named after its #88 gap."""

    SHARED_NETWORK_OPTIONAL_PREFIX = "shared_network_optional_prefix"
    SUBNET_ID_PER_SERVER = "subnet_id_per_server"
    NAME_PER_SERVER = "name_per_server"
    FLEX_ID_IDENTIFIER = "flex_id_identifier"
    USER_CONTEXT = "user_context"
    OPTION_SPACES = "option_spaces"
    OPTION_CODE_16_BIT = "option_code_16_bit"
    OPTION_WITHOUT_DEFINITION = "option_without_definition"
    SERVER_ID_FIELDS = "server_id_fields"
    RELAY_ADDRESS_LIST = "relay_address_list"


# The row of each capability in the #88 gap table.
GAPS: dict[Capability, int] = {
    Capability.SHARED_NETWORK_OPTIONAL_PREFIX: 1,
    Capability.SUBNET_ID_PER_SERVER: 2,
    Capability.NAME_PER_SERVER: 3,
    Capability.FLEX_ID_IDENTIFIER: 5,
    Capability.USER_CONTEXT: 6,
    Capability.OPTION_SPACES: 7,
    Capability.OPTION_CODE_16_BIT: 8,
    Capability.OPTION_WITHOUT_DEFINITION: 9,
    Capability.SERVER_ID_FIELDS: 10,
    Capability.RELAY_ADDRESS_LIST: 11,
}


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
    "reservations-global",
    "reservations-in-subnet",
    "reservations-out-of-pool",
)
_CLASS_REFERENCES = ("client-classes", "evaluate-additional-classes")
# The keys that Kea 3.2 rewrites, in every object that accepts them.
_DEPRECATED = {
    "client-class": Deprecated("client-classes"),
    "require-client-classes": Deprecated("evaluate-additional-classes"),
    "comment": Deprecated("user-context"),
}


def _fields(model: str, *keys: str) -> dict[str, Entry]:
    """Map each key to the *model* field of the same name."""
    return {key: Mapped(f"{model}.{key.replace('-', '_')}") for key in keys}


def _pending(ticket: int, *keys: str) -> dict[str, Entry]:
    return {key: Pending(ticket) for key in keys}


def _no_plugin_home(*keys: str) -> dict[str, Entry]:
    return {key: NotImported() for key in keys}


def _network_settings(family: int) -> tuple[str, ...]:
    """Return the scalar keys that a Subnet and a Shared Network of *family* share."""
    own = ("match-client-id", "authoritative", "offer-lifetime", *_BOOT_FIELDS) if family == 4 else _PREFERRED_LIFETIMES
    rest = ("pd-allocator", "rapid-commit", "interface-id") if family == 6 else ()
    return (*_LIFETIMES, *own, *_LEASE, *_DDNS, *rest)


def _global(family: int) -> dict[str, Entry]:
    own: tuple[str, ...] = ("match-client-id", "authoritative", "offer-lifetime", "echo-client-id", *_BOOT_FIELDS)
    if family == 6:
        own = (*_PREFERRED_LIFETIMES, "pd-allocator", "relay-supplied-options")
    server_level = (
        ("stash-agent-options",) if family == 4 else ("allow-address-registration", "data-directory", "mac-sources")
    )
    entries = {
        **_fields("DHCPServer", *_LIFETIMES, *_LEASE, *_DDNS, *own, "decline-probation-period"),
        "host-reservation-identifiers": Mapped(
            "DHCPServer.host_reservation_identifiers", (Capability.FLEX_ID_IDENTIFIER,), pending=94
        ),
        "option-data": Mapped("Option"),
        "option-def": Mapped("OptionDefinition", pending=100),
        "client-classes": Mapped("ClientClass"),
        f"subnet{family}": Mapped("Subnet"),
        "reservations": Mapped("HostReservation"),
        "shared-networks": Pending(107),
        "adaptive-lease-time-threshold": Pending(99),
        "user-context": Pending(94, _USER_CONTEXT),
        "comment": _DEPRECATED["comment"],
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
            "interfaces-config",
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
        entries["server-id"] = Mapped("DHCPServer.server_id", (Capability.SERVER_ID_FIELDS,), pending=94)
    return entries


def _subnet(family: int) -> dict[str, Entry]:
    entries = {
        **_fields("Subnet", *_network_settings(family)),
        "subnet": Mapped("Subnet.prefix"),
        "id": Pending(96, (Capability.SUBNET_ID_PER_SERVER,)),
        "relay": Mapped("Subnet.relay", (Capability.RELAY_ADDRESS_LIST,), pending=99),
        "option-data": Mapped("Option"),
        "pools": Mapped("Pool"),
        "reservations": Mapped("HostReservation"),
        **_pending(99, *_CLASS_REFERENCES, "adaptive-lease-time-threshold", "interface"),
        "user-context": Pending(99, _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }
    if family == 4:
        entries |= _no_plugin_home("4o6-interface", "4o6-interface-id", "4o6-subnet")
    else:
        entries["pd-pools"] = Pending(101)
    return entries


def _shared_network(family: int) -> dict[str, Entry]:
    return {
        **_pending(
            107,
            *_network_settings(family),
            *_CLASS_REFERENCES,
            "adaptive-lease-time-threshold",
            "interface",
            "option-data",
        ),
        "name": Pending(107, (Capability.NAME_PER_SERVER,)),
        f"subnet{family}": Pending(107, (Capability.SHARED_NETWORK_OPTIONAL_PREFIX,)),
        "relay": Pending(107, (Capability.RELAY_ADDRESS_LIST,)),
        "user-context": Pending(107, _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }


def _pool() -> dict[str, Entry]:
    return {
        "pool": Mapped("Pool.ip_range"),
        "option-data": Mapped("Option"),
        **_pending(99, "pool-id", *_CLASS_REFERENCES, *_DDNS),
        "user-context": Pending(99, _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }


def _pd_pool() -> dict[str, Entry]:
    return {
        **_pending(
            101,
            "prefix",
            "prefix-len",
            "delegated-len",
            "excluded-prefix",
            "excluded-prefix-len",
            "pool-id",
            *_CLASS_REFERENCES,
            "option-data",
        ),
        "user-context": Pending(101, _USER_CONTEXT),
        "metadata": NotImported(),
        **_DEPRECATED,
    }


def _reservation(family: int) -> dict[str, Entry]:
    entries = {
        **_fields("HostReservation", "hw-address", "duid", "flex-id", "hostname"),
        "option-data": Mapped("Option"),
        "client-classes": Pending(104),
        "user-context": Pending(104, _USER_CONTEXT),
    }
    if family == 4:
        entries |= _fields("HostReservation", "circuit-id", "client-id")
        entries |= {"ip-address": Mapped("HostReservation.ipv4_address"), **_pending(104, *_BOOT_FIELDS)}
    else:
        entries |= {
            "ip-addresses": Mapped("HostReservation.ipv6_addresses"),
            "prefixes": Mapped("HostReservation.ipv6_prefixes"),
            "excluded-prefixes": Pending(104),
        }
    return entries


def _client_class(family: int) -> dict[str, Entry]:
    entries = {
        **_fields("ClientClass", "test", "template-test", "only-in-additional-list", *_LIFETIMES),
        "name": Mapped("ClientClass.name", (Capability.NAME_PER_SERVER,), pending=106),
        "option-data": Mapped("Option"),
        "user-context": Pending(106, _USER_CONTEXT),
        "only-if-required": Deprecated("only-in-additional-list"),
    }
    if family == 4:
        entries |= {**_fields("ClientClass", *_BOOT_FIELDS), "option-def": Pending(100)}
    else:
        entries |= _fields("ClientClass", *_PREFERRED_LIFETIMES)
    return entries


def _option_definition(family: int) -> dict[str, Entry]:
    code = (Capability.OPTION_CODE_16_BIT,) if family == 6 else ()
    return {
        **_fields("OptionDefinition", "name", "type", "array", "record-types", "encapsulate"),
        "code": Mapped("OptionDefinition.code", code),
        "space": Mapped("OptionDefinition.space", (Capability.OPTION_SPACES,)),
        "user-context": Pending(100, _USER_CONTEXT),
        "metadata": NotImported(),
        "comment": _DEPRECATED["comment"],
    }


def _option(family: int) -> dict[str, Entry]:
    code = (Capability.OPTION_CODE_16_BIT,) if family == 6 else ()
    return {
        "name": Mapped("Option.definition", (Capability.OPTION_WITHOUT_DEFINITION,)),
        "code": Mapped("Option.definition", (Capability.OPTION_WITHOUT_DEFINITION, *code)),
        "space": Mapped("Option.definition", (Capability.OPTION_SPACES,)),
        "data": Mapped("Option.data"),
        "csv-format": Mapped("Option.csv_format"),
        "always-send": Mapped("Option.send_option"),
        "never-send": Mapped("Option.send_option"),
        "client-classes": Pending(100),
        "user-context": Pending(100, _USER_CONTEXT),
        "metadata": NotImported(),
        "comment": _DEPRECATED["comment"],
    }


def _family(family: int) -> dict[str, dict[str, Entry]]:
    tables = {
        f"Dhcp{family}": _global(family),
        "shared-networks": _shared_network(family),
        f"subnet{family}": _subnet(family),
        "pools": _pool(),
        "reservations": _reservation(family),
        "client-classes": _client_class(family),
        "option-def": _option_definition(family),
        "option-data": _option(family),
    }
    if family == 6:
        tables["pd-pools"] = _pd_pool()
    return tables


LEDGER: dict[int, dict[str, dict[str, Entry]]] = {family: _family(family) for family in (4, 6)}

_MERGED_INTO_NETWORKS = (
    "valid-lifetime",
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
# A Subnet also takes the derived minimum and maximum lifetimes and the relay of its Shared Network.
_MERGED_INTO_SUBNETS = (*_MERGED_INTO_NETWORKS, "min-valid-lifetime", "max-valid-lifetime", "relay")

# Kea 3.2 merges inherited values into Shared Networks and Subnets, and none into Pools and PD Pools.
MERGED_KEYS: dict[int, dict[str, frozenset[str]]] = {
    4: {
        "shared-networks": frozenset({*_MERGED_INTO_NETWORKS, "offer-lifetime"}),
        "subnet4": frozenset({*_MERGED_INTO_SUBNETS, "offer-lifetime"}),
        "pools": frozenset(),
    },
    6: {
        "shared-networks": frozenset({*_MERGED_INTO_NETWORKS, "preferred-lifetime", "pd-allocator"}),
        "subnet6": frozenset({*_MERGED_INTO_SUBNETS, *_PREFERRED_LIFETIMES, "pd-allocator"}),
        "pools": frozenset(),
        "pd-pools": frozenset(),
    },
}


def differences(recorded: dict[int, dict[str, set[str]]]) -> list[str]:
    """Return each disagreement between :data:`LEDGER` and the keys that Kea accepts, by family and object."""
    found = []
    for family in (4, 6):
        listed, accepted = LEDGER[family], recorded.get(family, {})
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
