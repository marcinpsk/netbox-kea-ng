# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The fields that the Subnet and Shared Network forms manage, read from the parsed facts and written to Kea entries.

The reader gives the values that an edit form shows. It takes the typed facts that ``server_configuration`` parses,
so that module stays the only parser of the configuration (ADR 0003). The writers set the fields on a raw Kea entry
and keep every other key. The DHCP Options of these fields go through the option codec of ``dhcp_options``.
"""

from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .constants import Family
from .dhcp_options import (
    AmbiguousFormOption,
    InvalidAddress,
    address_list,
    address_list_data,
    form_managed_options,
    form_option_edit,
    form_option_fields,
    merge_option_edit,
    parse_dhcp_options,
)
from .kea import MalformedConfiguration, subnet_network
from .pools import parse_pool
from .subnet_settings import setting_key

if TYPE_CHECKING:
    from .server_configuration import SharedNetwork, SubnetConfiguration

logger = logging.getLogger(__name__)

_LIFETIMES = ("valid_lifetime", "min_valid_lifetime", "max_valid_lifetime", "renew_timer", "rebind_timer")


@dataclass(frozen=True)
class SharedNetworkEdit:
    """The Shared Network fields that the edit form manages. An empty value removes the field.

    The values that the form showed have the same type, so that an operation can compare them with the live values.
    """

    description: str
    interface: str
    relay_addresses: tuple[str, ...]
    dns_servers: tuple[str, ...]
    ntp_servers: tuple[str, ...]


@dataclass(frozen=True)
class SubnetFields:
    """The Subnet fields that the add form and the edit form both set.

    An empty value leaves the field out of a new Subnet. It removes the field from an edited Subnet, except a DHCP
    Option value that the edit form cannot show.
    """

    pools: tuple[str, ...]
    gateway: str
    dns_servers: tuple[str, ...]
    ntp_servers: tuple[str, ...]
    ddns_qualifying_suffix: str


@dataclass(frozen=True)
class SubnetEdit:
    """The Subnet fields that the edit form manages: the *fields* of both forms, the lifetimes and the timers.

    A lifetime or a timer of None keeps the live value. The values that the form showed have the same type, and there
    None is a value that Kea does not set.
    """

    fields: SubnetFields
    valid_lifetime: int | None
    min_valid_lifetime: int | None
    max_valid_lifetime: int | None
    renew_timer: int | None
    rebind_timer: int | None

    def written_by(self, edit: SubnetEdit) -> SubnetEdit:
        """Return these values with None for each lifetime and timer that *edit* keeps, because it cannot change them."""

        def written(value: int | None, new: int | None) -> int | None:
            return None if new is None else value

        return SubnetEdit(
            fields=self.fields,
            valid_lifetime=written(self.valid_lifetime, edit.valid_lifetime),
            min_valid_lifetime=written(self.min_valid_lifetime, edit.min_valid_lifetime),
            max_valid_lifetime=written(self.max_valid_lifetime, edit.max_valid_lifetime),
            renew_timer=written(self.renew_timer, edit.renew_timer),
            rebind_timer=written(self.rebind_timer, edit.rebind_timer),
        )


def shared_network_description(network: dict[str, Any]) -> str | None:
    """Return the Shared Network description, which Kea keeps as ``user-context.comment``.

    Kea rejects a ``description`` key on a Shared Network, and stores a config-file
    ``comment`` in ``user-context``. A comment that is not a string has no description.

    Raises:
        ValueError: If ``user-context`` is not an object.

    """
    context = network.get("user-context")
    if context is None:
        return None
    if not isinstance(context, dict):
        raise ValueError("A Shared Network user-context must be an object.")
    comment = context.get("comment")
    return comment if isinstance(comment, str) else None


def description_as_shown(text: str) -> str:
    """Return *text* as a text input shows it and Django cleans it: without line breaks and outer spaces."""
    return text.replace("\r", "").replace("\n", "").strip()


def shown_subnet(configuration: SubnetConfiguration, family: Family) -> SubnetEdit | None:
    """Return the values that the Subnet edit form shows for *configuration*.

    Return None when a DHCP Option that the form shows holds a value that is not an address list, or when more than
    one entry fits a form field.
    """
    settings = configuration.settings
    try:
        options = form_option_fields(configuration.options, family)
        gateway = address_list(options.get("gateway", ""))
        fields = SubnetFields(
            pools=tuple(pool.range for pool in configuration.pools),
            gateway=gateway[0] if gateway else "",
            dns_servers=address_list(options.get("dns_servers", "")),
            ntp_servers=address_list(options.get("ntp_servers", "")),
            ddns_qualifying_suffix=(settings.ddns_qualifying_suffix or "").strip(),
        )
    except (InvalidAddress, AmbiguousFormOption):
        logger.warning(
            "A DHCP Option of a Subnet has a value or an entry that the edit form cannot show", exc_info=True
        )
        return None
    return SubnetEdit(
        fields=fields,
        valid_lifetime=settings.valid_lifetime,
        min_valid_lifetime=settings.min_valid_lifetime,
        max_valid_lifetime=settings.max_valid_lifetime,
        renew_timer=settings.renew_timer,
        rebind_timer=settings.rebind_timer,
    )


def shown_shared_network(network: SharedNetwork, family: Family) -> SharedNetworkEdit | None:
    """Return the values that the Shared Network edit form shows for *network*.

    Return None when a DHCP Option that the form shows holds a value that is not an address list, or when more than
    one entry fits a form field.
    """
    try:
        options = form_option_fields(network.options, family)
        return SharedNetworkEdit(
            description=description_as_shown(network.description or ""),
            interface=(network.interface or "").strip(),
            relay_addresses=tuple(str(address) for address in network.relay_addresses),
            dns_servers=address_list(options.get("dns_servers", "")),
            ntp_servers=address_list(options.get("ntp_servers", "")),
        )
    except (InvalidAddress, AmbiguousFormOption):
        logger.warning(
            "A DHCP Option of Shared Network %r has a value or an entry that the edit form cannot show",
            network.name,
            exc_info=True,
        )
        return None


def write_subnet(entry: dict[str, Any], family: Family, edit: SubnetEdit, *, shown: SubnetEdit) -> None:
    """Set each field of *edit* that differs from *shown* on the raw Subnet *entry*, and keep every other key.

    *shown* holds the values that the form showed for *entry*. A field that the operator did not change keeps its
    exact live text. A lifetime or a timer of None keeps the live value.

    Raises:
        MalformedConfiguration: If the Subnet has a value that the edit cannot keep or replace safely.

    """
    fields, before = edit.fields, shown.fields
    _write_options(entry, family, _option_fields(fields, family), _option_fields(before, family))
    if fields.ddns_qualifying_suffix != before.ddns_qualifying_suffix:
        _write_text(entry, setting_key("ddns_qualifying_suffix"), fields.ddns_qualifying_suffix)
    if fields.pools != before.pools:
        live_pools = _pools_by_range(entry, family)
        entry["pools"] = [live_pools.get(pool, {"pool": pool}) for pool in fields.pools]
    for field in _LIFETIMES:
        value = getattr(edit, field)
        if value is not None and value != getattr(shown, field):
            entry[setting_key(field)] = value


# The values that the form shows for a new Subnet: no field is set.
_NEW_SUBNET_SHOWN = SubnetEdit(SubnetFields((), "", (), (), ""), None, None, None, None, None)


def new_subnet(family: Family, subnet_id: int, cidr: str, fields: SubnetFields) -> dict[str, Any]:
    """Return the entry of a new Subnet *cidr* with *subnet_id* and the fields of the add form."""
    entry: dict[str, Any] = {"subnet": cidr, "id": subnet_id}
    write_subnet(entry, family, SubnetEdit(fields, None, None, None, None, None), shown=_NEW_SUBNET_SHOWN)
    return entry


def write_shared_network(
    entry: dict[str, Any], family: Family, edit: SharedNetworkEdit, *, shown: SharedNetworkEdit
) -> None:
    """Set each field of *edit* that differs from *shown* on the raw Shared Network *entry*, and keep every other key.

    *shown* holds the values that the form showed for *entry*. A field that the operator did not change keeps its
    exact live text.

    Raises:
        MalformedConfiguration: If the Shared Network has a value that the edit cannot keep or replace safely.

    """
    try:
        # Refuse a malformed user-context also when the description did not change.
        shared_network_description(entry)
    except ValueError as exc:
        raise MalformedConfiguration(str(exc)) from exc
    if edit.description != shown.description:
        _write_description(entry, edit.description)
    if edit.interface != shown.interface:
        _write_text(entry, "interface", edit.interface)
    if edit.relay_addresses != shown.relay_addresses:
        if edit.relay_addresses:
            entry["relay"] = {"ip-addresses": list(edit.relay_addresses)}
        else:
            entry.pop("relay", None)
    _write_options(entry, family, _option_fields(edit, family), _option_fields(shown, family))


def _write_text(entry: dict[str, Any], key: str, value: str) -> None:
    """Set *key* to *value*. An empty *value* removes the key."""
    if value:
        entry[key] = value
    else:
        entry.pop(key, None)


def _option_fields(values: SubnetFields | SharedNetworkEdit, family: Family) -> dict[str, str]:
    """Return the option data of each form-managed DHCP Option field of *family* that *values* has, by form field.

    A Shared Network has no gateway field.
    """
    names = {field.name for field in dataclasses.fields(values)}
    data = {name: getattr(values, name) for name in form_managed_options(family) if name in names}
    return {name: value if isinstance(value, str) else address_list_data(value) for name, value in data.items()}


def _write_options(entry: dict[str, Any], family: Family, edited: dict[str, str], shown: dict[str, str]) -> None:
    """Merge each form field whose *edited* data differs from its *shown* data into ``option-data``.

    Raises:
        MalformedConfiguration: If ``option-data`` is not a valid DHCP Option list, or more than one entry fits a
            form field, also when no field changed.

    """
    options = entry.get("option-data", [])
    changed = {field: data for field, data in edited.items() if data != shown[field]}
    try:
        live = parse_dhcp_options(options)
        # Refuse a list that the form cannot read also when no field changed.
        form_option_fields(live, family)
        if changed:
            entry["option-data"] = merge_option_edit(form_option_edit(live, family, changed), options, family)
    except ValueError as exc:
        raise MalformedConfiguration(str(exc)) from exc


def _write_description(network: dict[str, Any], description: str) -> None:
    """Write *description* as ``user-context.comment``, and keep every other user-context key."""
    context = dict(network.get("user-context") or {})
    _write_text(context, "comment", description)
    if context:
        network["user-context"] = context
    else:
        network.pop("user-context", None)


def _pools_by_range(entry: dict[str, Any], family: Family) -> dict[str, dict[str, Any]]:
    """Return each live Pool entry of the Subnet *entry* by its range, so that a kept Pool keeps its live entry.

    Raises:
        MalformedConfiguration: If the Subnet has no valid CIDR, or a live Pool entry is not an object or has no range
            in the Subnet.

    """
    subnet_id = entry.get("id")
    try:
        network = subnet_network(entry.get("subnet"), family)
    except ValueError as exc:
        raise MalformedConfiguration(f"Subnet {subnet_id} has no valid CIDR.") from exc
    by_range: dict[str, dict[str, Any]] = {}
    for pool in entry.get("pools", []):
        if not isinstance(pool, dict):
            raise MalformedConfiguration(f"Subnet {subnet_id} has a Pool entry that is not an object.")
        try:
            by_range[parse_pool(pool.get("pool"), network).range] = pool
        except ValueError as exc:
            raise MalformedConfiguration(f"Subnet {subnet_id} has a malformed Pool {pool.get('pool')!r}.") from exc
    return by_range
