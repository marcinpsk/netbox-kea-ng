# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The managed fields of each DHCP plugin model that the DHCP Import writes, and the Kea settings maps (ADR 0013).

On a mapped row, every run sets each managed field from Kea's Declared Values and clears a managed field that Kea
does not declare. A field behind a DHCP Plugin Capability counts only when the installed plugin has it. The import
leaves every other field alone. :data:`MANAGED_FIELDS` is the one list of these fields, and the apply step refuses a
write that does not match it. It reads no database and imports without netbox_dhcp.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING

from .. import kea_paths
from .dhcp_import_report import Capability

if TYPE_CHECKING:
    from .dhcp_plugin_capabilities import PluginCapabilities


def decimal(value):
    """Coerce a Kea numeric to ``Decimal`` via ``str`` (avoids float-precision noise)."""
    return None if value is None else Decimal(str(value))


def norm_ddns_replace(value):
    """Map Kea ``ddns-replace-client-name`` (hyphenated) to the plugin's underscored choice."""
    return value.replace("-", "_") if isinstance(value, str) else value


def relay_to_str(value):
    """Flatten a Kea ``relay`` (``{"ip-addresses": [...]}``) to the plugin's CSV string."""
    if isinstance(value, dict):
        addrs = value.get("ip-addresses") or []
    elif isinstance(value, list):
        addrs = value
    else:
        return value or None
    return ", ".join(addrs) if addrs else None


def server_id_type(value):
    """Reduce a Kea ``server-id`` map to its type."""
    return value.get("type") if isinstance(value, dict) else value


#: One Kea setting: its Kea key, the netbox_dhcp field and the transform of the value (``None``: the value as is).
FieldMap = tuple[tuple[str, str, Callable | None], ...]

DDNS_FIELDS: FieldMap = (
    ("ddns-send-updates", "ddns_send_updates", None),
    ("ddns-override-no-update", "ddns_override_no_update", None),
    ("ddns-override-client-update", "ddns_override_client_update", None),
    ("ddns-replace-client-name", "ddns_replace_client_name", norm_ddns_replace),
    ("ddns-generated-prefix", "ddns_generated_prefix", None),
    ("ddns-qualifying-suffix", "ddns_qualifying_suffix", None),
    ("ddns-update-on-renew", "ddns_update_on_renew", None),
    ("ddns-conflict-resolution-mode", "ddns_conflict_resolution_mode", None),
    ("ddns-ttl-percent", "ddns_ttl_percent", decimal),
    ("ddns-ttl", "ddns_ttl", None),
    ("ddns-ttl-min", "ddns_ttl_min", None),
    ("ddns-ttl-max", "ddns_ttl_max", None),
    ("hostname-char-set", "hostname_char_set", None),
    ("hostname-char-replacement", "hostname_char_replacement", None),
)

_LIFETIME_FIELDS: FieldMap = (
    ("valid-lifetime", "valid_lifetime", None),
    ("min-valid-lifetime", "min_valid_lifetime", None),
    ("max-valid-lifetime", "max_valid_lifetime", None),
    ("preferred-lifetime", "preferred_lifetime", None),
    ("min-preferred-lifetime", "min_preferred_lifetime", None),
    ("max-preferred-lifetime", "max_preferred_lifetime", None),
)

_BOOT_FIELDS: FieldMap = (
    ("next-server", "next_server", None),
    ("server-hostname", "server_hostname", None),
    ("boot-file-name", "boot_file_name", None),
)

#: The settings that a DHCP Server and a Subnet share.
COMMON_FIELDS: FieldMap = (
    *_LIFETIME_FIELDS,
    ("offer-lifetime", "offer_lifetime", None),
    ("renew-timer", "renew_timer", None),
    ("rebind-timer", "rebind_timer", None),
    ("match-client-id", "match_client_id", None),
    ("authoritative", "authoritative", None),
    ("reservations-global", "reservations_global", None),
    ("reservations-out-of-pool", "reservations_out_of_pool", None),
    ("reservations-in-subnet", "reservations_in_subnet", None),
    ("calculate-tee-times", "calculate_tee_times", None),
    ("t1-percent", "t1_percent", decimal),
    ("t2-percent", "t2_percent", decimal),
    ("cache-threshold", "cache_threshold", decimal),
    ("cache-max-age", "cache_max_age", None),
    ("store-extended-info", "store_extended_info", None),
    ("allocator", "allocator", None),
    ("pd-allocator", "pd_allocator", None),
    *DDNS_FIELDS,
    *_BOOT_FIELDS,
)

SUBNET_FIELDS: FieldMap = (
    *COMMON_FIELDS,
    ("relay", "relay", relay_to_str),
    ("interface-id", "interface_id", None),
    ("rapid-commit", "rapid_commit", None),
)

SERVER_FIELDS: FieldMap = (
    *COMMON_FIELDS,
    ("decline-probation-period", "decline_probation_period", None),
    ("echo-client-id", "echo_client_id", None),
    ("relay-supplied-options", "relay_supplied_options", None),
    (kea_paths.SERVER_ID, "server_id", server_id_type),
)

#: The settings that Kea declares on a client class.
CLIENT_CLASS_FIELDS: FieldMap = (*_LIFETIME_FIELDS, *_BOOT_FIELDS)

#: The settings that Kea declares on a Pool.
POOL_FIELDS: FieldMap = DDNS_FIELDS

#: The gated scalar globals of one daemon: Kea key, DHCPServer field and the capability that the field needs.
GATED_SERVER_FIELDS: tuple[tuple[str, str, Capability], ...] = (
    (kea_paths.ALLOW_ADDRESS_REGISTRATION, "allow_address_registration", Capability.ADDRESS_REGISTRATION),
    (kea_paths.STASH_AGENT_OPTIONS, "stash_agent_options", Capability.STASH_AGENT_OPTIONS),
)


def server_id_field(key: str) -> str:
    """Return the DHCPServer field of one ``server-id`` parameter of :data:`kea_paths.SERVER_ID_PARAMETERS`."""
    return f"server_id_{key.replace('-', '_')}"


@dataclass(frozen=True)
class ManagedField:
    """A field of a DHCP plugin model that Kea owns on a mapped row."""

    #: The netbox_dhcp model field.
    name: str
    #: Written only with it. Without it the field is neither written nor cleared.
    capability: Capability | None = None
    #: A many-to-many relation, written apart from the scalar fields.
    relation: bool = False


def _scalars(*names: str, capability: Capability | None = None) -> tuple[ManagedField, ...]:
    return tuple(ManagedField(name, capability) for name in names)


def _settings(field_map: FieldMap) -> tuple[ManagedField, ...]:
    return _scalars(*(attr for _key, attr, _transform in field_map))


def _relations(*names: str) -> tuple[ManagedField, ...]:
    return tuple(ManagedField(name, relation=True) for name in names)


#: The managed fields of each netbox_dhcp model, by model name.
MANAGED_FIELDS: dict[str, tuple[ManagedField, ...]] = {
    "DHCPServer": (
        *_settings(SERVER_FIELDS),
        ManagedField("host_reservation_identifiers"),
        ManagedField("family", Capability.SERVER_FAMILY),
        ManagedField("user_context", Capability.USER_CONTEXT),
        *_scalars(
            *(server_id_field(key) for key in kea_paths.SERVER_ID_PARAMETERS), capability=Capability.SERVER_ID_FIELDS
        ),
        *(ManagedField(attr, capability) for _key, attr, capability in GATED_SERVER_FIELDS),
        *_relations("device_interfaces", "virtual_machine_interfaces"),
    ),
    # marcinpsk/netbox-kea-ng#107 imports Shared Networks.
    "SharedNetwork": (),
    "Subnet": (*_scalars("prefix", "dhcp_server", "shared_network", "subnet_id"), *_settings(SUBNET_FIELDS)),
    "Pool": (
        *_scalars("subnet", "ip_range", "pool_id"),
        *_settings(POOL_FIELDS),
        *_relations("client_classes", "evaluate_additional_classes"),
    ),
    # marcinpsk/netbox-kea-ng#101 imports delegated-prefix Pools.
    "PDPool": (),
    "HostReservation": (
        *_scalars(
            "subnet",
            "dhcp_server",
            "hostname",
            "hw_address",
            "duid",
            "circuit_id",
            "client_id",
            "flex_id",
            "ipv4_address",
        ),
        *_relations("ipv6_addresses", "ipv6_prefixes"),
    ),
    "Option": _scalars("data", "csv_format", "send_option"),
    "OptionDefinition": _scalars(
        "space", "code", "family", "type", "array", "record_types", "encapsulate", "dhcp_server", "client_class"
    ),
    "ClientClass": (
        *_scalars("name", "dhcp_server", "test", "template_test", "only_in_additional_list"),
        ManagedField("user_context", Capability.USER_CONTEXT),
        *_settings(CLIENT_CLASS_FIELDS),
    ),
}


def managed_fields(model: str, capabilities: PluginCapabilities) -> tuple[ManagedField, ...]:
    """Return the managed fields of the netbox_dhcp *model* that the installed plugin can hold."""
    return tuple(
        managed
        for managed in MANAGED_FIELDS[model]
        if managed.capability is None or capabilities.has(managed.capability)
    )
