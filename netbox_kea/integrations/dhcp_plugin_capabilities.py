# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCP Plugin Capability probe: which #88 gaps the installed netbox_dhcp has closed (ADR 0013).

:func:`probe` reads the models of the installed plugin: fields, field types, choices, validators, nullability and
uniqueness constraints. It reads no plugin rows. The check of option data calls the data check of the plugin
(:func:`installed_data_rule`) and no site or custom validation. :data:`CHECKS` is the reference: one check for each
:class:`~.dhcp_import_report.Capability`, in the shape of the "Capability the import checks" column of #88. Where
the plugin has no field yet, the check assumes the shape that #88 proposes. The apply step writes a gated fact only
when its capability is present, and reports it as unsupported otherwise.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from django.apps import apps
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import models

from ..dhcp_options import MAX_OPTION_CODE
from ..reservations import FLEX_ID
from .dhcp_import_report import Capability

PLUGIN_APP_LABEL = "netbox_dhcp"

#: Returns a netbox_dhcp model class by name.
ModelLookup = Callable[[str], type[models.Model]]
#: Checks one value of option data against a type, as ``validate_data(data, type)`` of netbox_dhcp 0.2.0 does. It
#: raises ValidationError for a value that the plugin refuses.
DataRule = Callable[[str, str], None]

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


# Option data that Kea 3.2 accepts, each as the type and array flag of its Option Definition and the data.
_KEA_OPTION_DATA = (
    ("ipv4-address", True, "c0:00:02:01"),
    ("boolean", False, "1"),
    ("int32", False, "0x10"),
    ("fqdn", False, "localhost"),
)
# The plugin splits the data of an array or a record at each comma.
_DATA_SEPARATOR = re.compile(r"\s*,\s*")


def installed_data_rule() -> DataRule | None:
    """Return the data check of the installed netbox_dhcp, or ``None`` when it has none."""
    try:
        validators = importlib.import_module(f"{PLUGIN_APP_LABEL}.validators")
    except ImportError:
        return None
    return getattr(validators, "validate_data", None)


def _refusal(rule: DataRule, kind: str, array: bool, record_types: Sequence[str] | None, data: str) -> str | None:
    """Return why the data check *rule* refuses option *data* for an Option Definition (#88 gap 17), or ``None``.

    *kind*, *array* and *record_types* come from the Option Definition. The data is split into values as
    ``Option.clean()`` of netbox_dhcp 0.2.0 splits it, and *rule* checks each value. No site or custom validation runs.
    """
    try:
        _check_data(rule, kind, array, list(record_types or ()), data)
    except ValidationError as exc:
        return " ".join(exc.messages)
    return None


def _check_data(rule: DataRule, kind: str, array: bool, record_types: list[str], data: str) -> None:
    if kind != "record":
        for text in _DATA_SEPARATOR.split(data) if array else [data]:
            rule(text, kind)
        return
    fields = _DATA_SEPARATOR.split(data)
    if len(record_types) > len(fields) if array else len(record_types) != len(fields):
        raise ValidationError({"data": "The data has another number of values than the record types."})
    if array and record_types:
        record_types += [record_types[-1]] * (len(fields) - len(record_types))
    for text, field_type in zip(fields, record_types, strict=False):
        rule(text, field_type)


def _kea_option_data(model: ModelLookup, data_rule: DataRule | None) -> bool:
    if data_rule is None or not (
        _has_fields(model("OptionDefinition"), "type", "array") and _has_fields(model("Option"), "data")
    ):
        return False
    return all(_refusal(data_rule, kind, array, (), data) is None for kind, array, data in _KEA_OPTION_DATA)


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
    """The check of one capability: what it reads (the reference text) and its predicate over the plugin."""

    reads: str
    holds: Callable[[ModelLookup, DataRule | None], bool]


def _models(holds: Callable[[ModelLookup], bool]) -> Callable[[ModelLookup, DataRule | None], bool]:
    """Return a check that reads only the plugin models."""
    return lambda model, _data_rule: holds(model)


CHECKS: dict[Capability, Check] = {
    Capability.SHARED_NETWORK_OPTIONAL_PREFIX: Check(
        "SharedNetwork.prefix is nullable. Whether a Subnet must still sit inside it is model code, not read.",
        _models(_shared_network_optional_prefix),
    ),
    Capability.SUBNET_ID_PER_SERVER: Check(
        "Subnet.subnet_id is not unique alone, and each uniqueness constraint on it includes dhcp_server.",
        _models(lambda model: _unique_per_server(model("Subnet"), "subnet_id")),
    ),
    Capability.NAME_PER_SERVER: Check(
        "ClientClass.name and SharedNetwork.name are not unique alone, and each uniqueness constraint on them "
        "includes dhcp_server.",
        _models(lambda model: all(_unique_per_server(model(name), "name") for name in _KEA_NAME_MODELS)),
    ),
    Capability.SERVER_FAMILY: Check("DHCPServer.family has the choices 4 and 6.", _models(_server_family)),
    Capability.FLEX_ID_IDENTIFIER: Check(
        "flex-id is a choice of DHCPServer.host_reservation_identifiers.", _models(_flex_id_identifier)
    ),
    Capability.USER_CONTEXT: Check(
        f"Each of {', '.join(_KEA_OBJECT_MODELS)} has a JSON field user_context that is nullable or has a default.",
        _models(_user_context),
    ),
    Capability.OPTION_SPACES: Check(
        "OptionDefinition.space has no closed set of choices. Without it, a space that is one of the choices is held.",
        _models(_option_spaces),
    ),
    Capability.OPTION_CODE_16_BIT: Check(
        f"The validators of OptionDefinition.code accept {MAX_OPTION_CODE}.", _models(_option_code_16_bit)
    ),
    Capability.OPTION_WITHOUT_DEFINITION: Check(
        "Option.definition is nullable, and Option has the fields space and code.", _models(_option_without_definition)
    ),
    Capability.SERVER_ID_FIELDS: Check(
        "DHCPServer has server_id_identifier, server_id_enterprise_id, server_id_htype and server_id_time.",
        _models(
            lambda model: _has_fields(
                model("DHCPServer"),
                "server_id_identifier",
                "server_id_enterprise_id",
                "server_id_htype",
                "server_id_time",
            )
        ),
    ),
    Capability.RELAY_ADDRESS_LIST: Check(
        "Subnet.relay and SharedNetwork.relay are arrays of IP addresses that are nullable or have a default.",
        _models(_relay_address_list),
    ),
    Capability.DHCP4O6_SUBNET_SELECTION: Check(
        "Subnet has dhcp4o6_subnet, dhcp4o6_interface and dhcp4o6_interface_id.",
        _models(
            lambda model: _has_fields(model("Subnet"), "dhcp4o6_subnet", "dhcp4o6_interface", "dhcp4o6_interface_id")
        ),
    ),
    Capability.ADDRESS_REGISTRATION: Check(
        "DHCPServer has allow_address_registration.",
        _models(lambda model: _has_fields(model("DHCPServer"), "allow_address_registration")),
    ),
    Capability.STASH_AGENT_OPTIONS: Check(
        "DHCPServer has stash_agent_options.",
        _models(lambda model: _has_fields(model("DHCPServer"), "stash_agent_options")),
    ),
    Capability.KEA_OPTION_DATA: Check(
        "netbox_dhcp.validators.validate_data() accepts each value of option data that Kea accepts, with the data "
        "split as Option.clean() splits it: "
        + ", ".join(f"{data!r} for {kind}{' array' if array else ''}" for kind, array, data in _KEA_OPTION_DATA)
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
    # The data check of the plugin, which predicts the option data that it refuses (gap 17).
    data_rule: DataRule | None = None

    def has(self, capability: Capability) -> bool:
        """Return whether the installed plugin has *capability*."""
        return capability in self.present

    def data_refusal(self, kind: str, array: bool, record_types: Sequence[str] | None, data: str) -> str | None:
        """Return why the data check of the plugin refuses Kea option *data* for its Option Definition, or ``None``.

        Without the capability, an Option that it refuses is unsupported (gap 17). Without a data check, it refuses
        nothing.
        """
        return None if self.data_rule is None else _refusal(self.data_rule, kind, array, record_types, data)

    def holds_space(self, space: str) -> bool:
        """Return whether the installed plugin holds an Option Definition in the Kea option space *space*."""
        return self.has(Capability.OPTION_SPACES) or space in self.option_spaces


def _plugin_model(name: str) -> type[models.Model]:
    return apps.get_model(PLUGIN_APP_LABEL, name)


def _space_choices(model: ModelLookup) -> frozenset[str]:
    field = _field(model("OptionDefinition"), "space")
    return frozenset(_choice_values(field)) if field is not None and field.choices else frozenset()


def probe(model: ModelLookup = _plugin_model, data_rule: DataRule | None = None) -> PluginCapabilities:
    """Return the capabilities of the plugin models that *model* looks up and of the data check *data_rule*.

    By default, both come from the installed netbox_dhcp.
    """
    data_rule = data_rule if data_rule is not None else installed_data_rule()
    present = frozenset(capability for capability, check in CHECKS.items() if check.holds(model, data_rule))
    return PluginCapabilities(present, _space_choices(model), data_rule)
