# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCP Plugin Capability probe: which #88 gaps the installed netbox_dhcp has closed (ADR 0013).

:func:`probe` reads the models of the installed plugin: fields, field types, choices, validators, nullability and
uniqueness constraints. It reads no plugin rows: the check of option data cleans unsaved Options, and NetBox reads the
custom fields of the model for that. :data:`CHECKS` is the reference: one check for each
:class:`~.dhcp_import_report.Capability`, in the shape of the "Capability the import checks" column of #88. Where
the plugin has no field yet, the check assumes the shape that #88 proposes. The apply step writes a gated fact only
when its capability is present, and reports it as unsupported otherwise.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from django.apps import apps
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import models

from ..decimal_text import parse_decimal
from ..dhcp_options import MAX_OPTION_CODE
from ..reservations import FLEX_ID
from .dhcp_import_report import Capability

PLUGIN_APP_LABEL = "netbox_dhcp"

#: Returns a netbox_dhcp model class by name.
ModelLookup = Callable[[str], type[models.Model]]

# The models that hold a Kea object with a user-context, and the models that hold a Kea name.
_KEA_OBJECT_MODELS = (
    "DHCPServer",
    "SharedNetwork",
    "Subnet",
    "Pool",
    "PDPool",
    "HostReservation",
    "ClientClass",
    "OptionDefinition",
    "Option",
)
_KEA_NAME_MODELS = ("ClientClass", "SharedNetwork")
_NETWORK_MODELS = ("Subnet", "SharedNetwork")


def _field(model: type[models.Model], name: str):
    try:
        return model._meta.get_field(name)
    except FieldDoesNotExist:
        return None


def _has_fields(model: type[models.Model], *names: str) -> bool:
    return all(_field(model, name) is not None for name in names)


def _unique_per_server(model: type[models.Model], name: str) -> bool:
    """Return whether *name* is not unique alone and a uniqueness constraint scopes it to its DHCP server.

    A unique expression is not read, so its model fails closed.
    """
    field = _field(model, name)
    if field is None or field.unique:
        return False
    if any(isinstance(c, models.UniqueConstraint) and c.expressions for c in model._meta.constraints):
        return False
    unique_sets = [
        set(constraint.fields)
        for constraint in model._meta.constraints
        if isinstance(constraint, models.UniqueConstraint)
    ]
    unique_sets.extend(set(fields) for fields in model._meta.unique_together)
    scoped = [fields for fields in unique_sets if name in fields]
    return bool(scoped) and all("dhcp_server" in fields for fields in scoped)


def _choice_values(field) -> set[str]:
    return {str(value) for value, _label in field.flatchoices}


def _server_family(model: ModelLookup) -> bool:
    field = _field(model("DHCPServer"), "family")
    return field is not None and {"4", "6"} <= _choice_values(field)


def _flex_id_identifier(model: ModelLookup) -> bool:
    field = _field(model("DHCPServer"), "host_reservation_identifiers")
    base = getattr(field, "base_field", None)
    return base is not None and FLEX_ID in _choice_values(base)


def _user_context(model: ModelLookup) -> bool:
    fields = [_field(model(name), "user_context") for name in _KEA_OBJECT_MODELS]
    # The import clears an undeclared user-context, so the field must be nullable or have a default.
    return all(
        field is not None and field.get_internal_type() == "JSONField" and (field.null or field.has_default())
        for field in fields
    )


def _option_spaces(model: ModelLookup) -> bool:
    field = _field(model("OptionDefinition"), "space")
    return field is not None and not field.choices


def _option_code_16_bit(model: ModelLookup) -> bool:
    field = _field(model("OptionDefinition"), "code")
    if field is None:
        return False
    try:
        field.run_validators(MAX_OPTION_CODE)
    except ValidationError:
        return False
    return True


def _option_without_definition(model: ModelLookup) -> bool:
    option = model("Option")
    definition = _field(option, "definition")
    return definition is not None and definition.null and _has_fields(option, "space", "code")


# Option data that Kea 3.2 accepts, each as the type and array flag of its Option Definition, the data and csv_format:
# one sample of each form that refuses_kea_data() names.
_KEA_OPTION_DATA = (
    ("ipv4-address", True, "c0:00:02:01", False),
    ("boolean", False, "1", True),
    ("int32", False, "0x10", True),
    ("fqdn", False, "localhost", True),
)
# The types whose data netbox-plugin-dhcp 0.2.0 also holds in the hexadecimal form of Kea.
_HEX_TEXT_TYPES = frozenset({"binary", "string"})
_INTEGER_RANGES = {
    "int8": range(-(2**7), 2**7),
    "int16": range(-(2**15), 2**15),
    "int32": range(-(2**31), 2**31),
    "uint8": range(2**8),
    "uint16": range(2**16),
    "uint32": range(2**32),
}
# The plugin splits the data of an array or a record at each comma.
_DATA_SEPARATOR = re.compile(r"\s*,\s*")
# Kea reads an integer in hexadecimal only with the prefix 0x, and without a sign.
_HEX_INTEGER = re.compile(r"0[xX][0-9a-fA-F]+")


def refuses_kea_data(
    kind: str, array: bool, record_types: Sequence[str] | None, data: str, csv_format: bool | None
) -> bool:
    """Return whether a DHCP plugin without :attr:`Capability.KEA_OPTION_DATA` refuses Kea option *data* (#88 gap 17).

    *kind*, *array* and *record_types* come from the Option Definition that the plugin checks the data against. The
    forms are the ones that the capability check samples: hexadecimal data with csv-format false for a type other than
    binary and string, a boolean 1 or 0, an integer in hexadecimal, and an FQDN of one label.
    """
    if csv_format is False:
        # The plugin checks hexadecimal data as text, so it holds digits that are an integer in the range of the type.
        return bool(data) and kind not in _HEX_TEXT_TYPES and not _decimal_in_range(data, kind)
    if kind == "record":
        fields = _DATA_SEPARATOR.split(data)
        types = list(record_types or ())
        if array and types:
            types += [types[-1]] * (len(fields) - len(types))
        return any(_refused_text(text, field_type) for text, field_type in zip(fields, types, strict=False))
    fields = _DATA_SEPARATOR.split(data) if array else [data]
    return any(_refused_text(text, kind) for text in fields)


def _refused_text(text: str, kind: str) -> bool:
    """Return whether the plugin refuses the Kea text *text* of one value of *kind*."""
    if kind == "boolean":
        return text in ("0", "1")
    if kind in _INTEGER_RANGES:
        return _HEX_INTEGER.fullmatch(text) is not None
    if kind == "fqdn":
        return bool(text) and "." not in text.rstrip(".")
    return False


def _decimal_in_range(text: str, kind: str) -> bool:
    """Return whether the plugin reads *text* as a decimal integer in the range of the integer type *kind*."""
    if kind not in _INTEGER_RANGES:
        return False
    try:
        return parse_decimal(text) in _INTEGER_RANGES[kind]
    except ValueError:
        return False


def _kea_option_data(model: ModelLookup) -> bool:
    if not (
        _has_fields(model("OptionDefinition"), "type", "array") and _has_fields(model("Option"), "data", "csv_format")
    ):
        return False
    for kind, array, data, csv_format in _KEA_OPTION_DATA:
        definition = model("OptionDefinition")(type=kind, array=array)
        try:
            model("Option")(definition=definition, data=data, csv_format=csv_format).clean()
        except ValidationError:
            return False
    return True


def _relay_address_list(model: ModelLookup) -> bool:
    fields = [_field(model(name), "relay") for name in _NETWORK_MODELS]
    # The import clears an undeclared relay, so the field must be nullable or have a default.
    return all(
        (base := getattr(field, "base_field", None)) is not None
        and "IPAddress" in base.get_internal_type()
        and (field.null or field.has_default())
        for field in fields
    )


def _shared_network_optional_prefix(model: ModelLookup) -> bool:
    field = _field(model("SharedNetwork"), "prefix")
    return field is not None and field.null


@dataclass(frozen=True)
class Check:
    """The check of one capability: what it reads (the reference text) and the predicate over the plugin models."""

    reads: str
    holds: Callable[[ModelLookup], bool]


CHECKS: dict[Capability, Check] = {
    Capability.SHARED_NETWORK_OPTIONAL_PREFIX: Check(
        "SharedNetwork.prefix is nullable. Whether a Subnet must still sit inside it is model code, not read.",
        _shared_network_optional_prefix,
    ),
    Capability.SUBNET_ID_PER_SERVER: Check(
        "Subnet.subnet_id is not unique alone, and each uniqueness constraint on it includes dhcp_server.",
        lambda model: _unique_per_server(model("Subnet"), "subnet_id"),
    ),
    Capability.NAME_PER_SERVER: Check(
        "ClientClass.name and SharedNetwork.name are not unique alone, and each uniqueness constraint on them "
        "includes dhcp_server.",
        lambda model: all(_unique_per_server(model(name), "name") for name in _KEA_NAME_MODELS),
    ),
    Capability.SERVER_FAMILY: Check("DHCPServer.family has the choices 4 and 6.", _server_family),
    Capability.FLEX_ID_IDENTIFIER: Check(
        "flex-id is a choice of DHCPServer.host_reservation_identifiers.", _flex_id_identifier
    ),
    Capability.USER_CONTEXT: Check(
        f"Each of {', '.join(_KEA_OBJECT_MODELS)} has a JSON field user_context that is nullable or has a default.",
        _user_context,
    ),
    Capability.OPTION_SPACES: Check(
        "OptionDefinition.space has no closed set of choices. Without it, a space that is one of the choices is held.",
        _option_spaces,
    ),
    Capability.OPTION_CODE_16_BIT: Check(
        f"The validators of OptionDefinition.code accept {MAX_OPTION_CODE}.", _option_code_16_bit
    ),
    Capability.OPTION_WITHOUT_DEFINITION: Check(
        "Option.definition is nullable, and Option has the fields space and code.", _option_without_definition
    ),
    Capability.SERVER_ID_FIELDS: Check(
        "DHCPServer has server_id_identifier, server_id_enterprise_id, server_id_htype and server_id_time.",
        lambda model: _has_fields(
            model("DHCPServer"),
            "server_id_identifier",
            "server_id_enterprise_id",
            "server_id_htype",
            "server_id_time",
        ),
    ),
    Capability.RELAY_ADDRESS_LIST: Check(
        "Subnet.relay and SharedNetwork.relay are arrays of IP addresses that are nullable or have a default.",
        _relay_address_list,
    ),
    Capability.DHCP4O6_SUBNET_SELECTION: Check(
        "Subnet has dhcp4o6_subnet, dhcp4o6_interface and dhcp4o6_interface_id.",
        lambda model: _has_fields(model("Subnet"), "dhcp4o6_subnet", "dhcp4o6_interface", "dhcp4o6_interface_id"),
    ),
    Capability.ADDRESS_REGISTRATION: Check(
        "DHCPServer has allow_address_registration.",
        lambda model: _has_fields(model("DHCPServer"), "allow_address_registration"),
    ),
    Capability.STASH_AGENT_OPTIONS: Check(
        "DHCPServer has stash_agent_options.", lambda model: _has_fields(model("DHCPServer"), "stash_agent_options")
    ),
    Capability.KEA_OPTION_DATA: Check(
        "Option.clean() accepts option data that Kea accepts: "
        + ", ".join(
            f"{data!r} for {kind}{' array' if array else ''} with csv_format {csv_format}"
            for kind, array, data, csv_format in _KEA_OPTION_DATA
        )
        + ".",
        _kea_option_data,
    ),
}


@dataclass(frozen=True)
class PluginCapabilities:
    """The DHCP Plugin Capabilities that the installed netbox_dhcp has.

    Without :attr:`Capability.OPTION_SPACES` the plugin holds only the option spaces of its closed choice set.
    """

    present: frozenset[Capability]
    # The choices of OptionDefinition.space.
    option_spaces: frozenset[str] = frozenset()

    def has(self, capability: Capability) -> bool:
        """Return whether the installed plugin has *capability*."""
        return capability in self.present

    def holds_space(self, space: str) -> bool:
        """Return whether the installed plugin holds an Option Definition in the Kea option space *space*."""
        return self.has(Capability.OPTION_SPACES) or space in self.option_spaces


def _plugin_model(name: str) -> type[models.Model]:
    return apps.get_model(PLUGIN_APP_LABEL, name)


def _space_choices(model: ModelLookup) -> frozenset[str]:
    field = _field(model("OptionDefinition"), "space")
    return frozenset(_choice_values(field)) if field is not None and field.choices else frozenset()


def probe(model: ModelLookup = _plugin_model) -> PluginCapabilities:
    """Return the capabilities of the plugin models that *model* looks up: by default, the installed netbox_dhcp."""
    present = frozenset(capability for capability, check in CHECKS.items() if check.holds(model))
    return PluginCapabilities(present, _space_choices(model))
