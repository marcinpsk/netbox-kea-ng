# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""One row write protocol for every imported DHCP plugin row (#210), as a table through ``apply_plan``.

Each row of the table runs the real apply step against the real database and the installed netbox_dhcp. It asserts
the entries of the object and of its planned subtree, field for field with the message, the persisted fields and
relations of the mapped row, and the mapping state. Each row starts from the same database: its changes roll back.
"""

from __future__ import annotations

import copy
import ipaddress
import unittest
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from django.apps import apps
from django.db import DatabaseError, transaction
from django.db.models.signals import pre_save
from django.test import TestCase, override_settings
from extras.validators import CustomValidator

from netbox_kea.constants import Family
from netbox_kea.dhcp_options import DHCPOptionIdentity
from netbox_kea.integrations import dhcp_plugin
from netbox_kea.integrations.dhcp_import_plan import (
    InSubnetReservationKey,
    MappingSource,
    NamedKey,
    OptionDefinitionKey,
    OptionKey,
    PDPoolKey,
    PoolKey,
    SubnetKey,
    plan_family,
)
from netbox_kea.integrations.dhcp_import_report import Capability, Kind, Outcome, Reason
from netbox_kea.integrations.dhcp_plugin_capabilities import PluginCapabilities, probe
from netbox_kea.mappers.kea_to_dhcp import parse_dhcp_config
from netbox_kea.models import MAPPING_KINDS, KeaDhcpLink, next_confirmation_number
from netbox_kea.pools import Pool

from .test_integration_dhcp_plugin import _reservation_snapshot
from .utils import _make_db_server, imported_dhcp_server, optional_shared_network_prefix

DHCP_PLUGIN = "netbox_dhcp"
_SERVER = "row-write"
_MAC = "02:00:00:00:00:0a"

# One entry: kind, Kea path, outcome, reason, detail and capability.
_Entry = tuple[Kind, str, Outcome, Reason | None, str, Capability | None]

_FAILED = (Outcome.SKIPPED, Reason.WRITE_FAILED, "See server logs.", None)
_SKIPPED = (Outcome.SKIPPED, Reason.PARENT_NOT_IMPORTED, "", None)
_REFUSES = "The DHCP plugin refuses it: "


def _created(kind: Kind, path: str) -> _Entry:
    return (kind, path, Outcome.CREATED, None, "", None)


def _updated(kind: Kind, path: str) -> _Entry:
    return (kind, path, Outcome.UPDATED, None, "", None)


def _model(name: str):
    return apps.get_model(DHCP_PLUGIN, name)


class RefusePoolValidator(CustomValidator):
    """An operator's NetBox custom validator that refuses every Pool."""

    def validate(self, instance, request):
        """Refuse the Pool."""
        self.fail("This site adds no Pool.")


class RefuseOptionDataValidator(CustomValidator):
    """An operator's NetBox custom validator that refuses one Option data value."""

    def validate(self, instance, request):
        """Refuse the data 192.0.2.53."""
        if instance.data == "192.0.2.53":
            self.fail("This site does not use 192.0.2.53.", field="data")


class _Fixture:
    """The Server of one table row and the apply of one Kea configuration of its family."""

    def __init__(self, test: TestCase, family: Family, capabilities: PluginCapabilities) -> None:
        self.test = test
        self.family = family
        self.capabilities = capabilities
        self.server = _make_db_server(
            name=_SERVER, ca_url="https://kea.example.invalid", dhcp4=family == 4, dhcp6=family == 6
        )

    def apply(self, config: dict, server=None) -> dhcp_plugin.ImportSummary:
        config = copy.deepcopy(config)
        intent = parse_dhcp_config(config, self.family)
        intent.configuration_complete = True
        plan = plan_family(intent, _reservation_snapshot(config, self.family))
        return dhcp_plugin.apply_plan(server or self.server, plan, self.capabilities)

    def apply_cleanly(self, config: dict, server=None) -> None:
        """Apply *config* as a state before the run under test: it must not fail."""
        summary = self.apply(config, server)
        self.test.assertEqual(summary.errors, 0, summary.warnings)

    def link(self, key):
        return KeaDhcpLink.objects.filter(server=self.server, family=self.family, **key.source.columns()).first()

    def mapped(self, key) -> Any:
        link = self.link(key)
        return link.sys4_object if link is not None else None

    def dhcp_server(self):
        return imported_dhcp_server(self.server, self.family)

    def other_dhcp_server(self):
        return _model("DHCPServer").objects.create(name="other dhcp server")


@dataclass(frozen=True)
class _Row:
    """One scenario of one kind: the configuration of the run, and what the run must leave."""

    scenario: str
    key: Any
    config: dict
    # Every entry of the object and of its planned subtree, and of the *related* paths.
    entries: tuple[_Entry, ...]
    # The persisted fields and relations of the mapped row; None when the source has no mapping.
    state: dict | None
    # The state before the run; it returns the row that the mapping must still hold after the run, or None.
    before: Callable[[_Fixture, dict], Any] | None = None
    # A model whose pre_save receiver raises, for a write failure.
    refuse: str | None = None
    validators: dict | None = None
    # The capabilities of the run, from the probe of the installed plugin.
    capabilities: Callable[[PluginCapabilities], PluginCapabilities] = lambda found: found
    related: tuple[str, ...] = ()
    # Other facts that the run must leave: a label, a read of the fixture and the summary, and the expected value.
    facts: tuple[tuple[str, Callable[[_Fixture, Any], Any], Any], ...] = ()

    @property
    def kind(self) -> Kind:
        return self.key.kind


@contextmanager
def _refusing(model_name: str | None) -> Iterator[list]:
    """Make every save of *model_name* fail in the database layer, and collect the refused rows."""
    refused: list = []
    if model_name is None:
        yield refused
        return

    def refuse(sender, instance, **kwargs):
        refused.append(instance)
        raise DatabaseError(f"the {model_name} write fails")

    pre_save.connect(refuse, sender=_model(model_name), weak=False)
    try:
        yield refused
    finally:
        pre_save.disconnect(refuse, sender=_model(model_name))


@contextmanager
def _rolled_back() -> Iterator[None]:
    """Roll back every change of the block, so the next row starts from the same database."""
    with transaction.atomic():
        yield
        transaction.set_rollback(True)


def _keep_mapped(
    key, first: dict | None = None, *, change: Callable[[Any], None] | None = None
) -> Callable[[_Fixture, dict], Any]:
    """Return a state before the run: an earlier run of *first* (else of the row's configuration), then *change*.

    It returns the row that the mapping of *key* holds after the earlier run.
    """

    def before(fixture: _Fixture, config: dict):
        fixture.apply_cleanly(first if first is not None else config)
        row = fixture.mapped(key)
        if change is not None:
            change(row)
        return row

    return before


def _rename(name: str) -> Callable[[Any], None]:
    def change(row) -> None:
        type(row).objects.filter(pk=row.pk).update(name=name)

    return change


def _unmapped(server, *kinds: Kind, **values) -> Callable[[Any], None]:
    """Remove the mappings of *kinds* of *server*, as a release before them left them, and change the row."""

    def change(row) -> None:
        KeaDhcpLink.objects.filter(server=server, kind__in=[kind.value for kind in kinds]).delete()
        KeaDhcpLink.objects.filter(server=server).update(options_mapped=False)
        if values:
            type(row).objects.filter(pk=row.pk).update(**values)

    return change


def _names(relation) -> list[str]:
    return sorted(relation.values_list("name", flat=True))


_STATE: dict[Kind, Callable[[Any], dict]] = {
    Kind.OPTION_DEFINITION: lambda row: {"name": row.name, "code": row.code, "type": row.type},
    Kind.CLIENT_CLASS: lambda row: {"name": row.name, "test": row.test},
    Kind.SHARED_NETWORK: lambda row: {
        "name": row.name,
        "valid_lifetime": row.valid_lifetime,
        "prefix": row.prefix_id,
        "client_classes": _names(row.client_classes),
    },
    Kind.SUBNET: lambda row: {
        "prefix": str(row.prefix.prefix),
        "subnet_id": row.subnet_id,
        "valid_lifetime": row.valid_lifetime,
        "client_classes": _names(row.client_classes),
    },
    Kind.POOL: lambda row: {
        "range": f"{row.ip_range.start_address.ip}-{row.ip_range.end_address.ip}",
        "pool_id": row.pool_id,
        "subnet_id": row.subnet.subnet_id,
        "client_classes": _names(row.client_classes),
    },
    Kind.PD_POOL: lambda row: {
        "prefix": str(row.prefix.prefix),
        "delegated_length": row.delegated_length,
        "pool_id": row.pool_id,
        "client_classes": _names(row.client_classes),
    },
    Kind.RESERVATION: lambda row: {
        "hostname": row.hostname,
        "ipv4_address": str(row.ipv4_address.address),
        "hw_address": str(row.hw_address.mac_address).lower(),
        "subnet_id": row.subnet.subnet_id,
        "client_classes": _names(row.client_classes),
    },
    Kind.OPTION: lambda row: {
        "parent": row.assigned_object_type.model,
        "code": row.definition.code,
        "data": row.data,
        "client_classes": _names(row.client_classes),
        # One Option on its parent: a run that updates it writes no second row.
        "options_of_parent": type(row)
        .objects.filter(assigned_object_type=row.assigned_object_type, assigned_object_id=row.assigned_object_id)
        .count(),
    },
}


def _option_data(key, code: int) -> Callable[[_Fixture, Any], Any]:
    """Return a read of the data of each Option of *code* that the mapped row of *key* holds."""

    def read(fixture: _Fixture, summary) -> list[str]:
        from django.contrib.contenttypes.models import ContentType

        row = fixture.mapped(key)
        options = _model("Option").objects.filter(
            assigned_object_type=ContentType.objects.get_for_model(row),
            assigned_object_id=row.pk,
            definition__code=code,
        )
        return list(options.values_list("data", flat=True))

    return read


def _holder(model_name: str, name: str) -> Callable[[_Fixture, Any], Any]:
    """Return a read of the DHCP server of each row of *model_name* that holds *name*."""

    def read(fixture: _Fixture, summary) -> list[str]:
        return [row.dhcp_server.name for row in _model(model_name).objects.filter(name=name)]

    return read


def _errors(fixture: _Fixture, summary) -> int:
    return summary.errors


_LAB = {"name": "lab", "test": "member('KNOWN')"}

# ── Option Definition ────────────────────────────────────────────────────────

_DEF = "Dhcp4/option-def[code=230]"
_DEF_OPTION = "Dhcp4/option-data[code=230]"
_DEF_KEY = OptionDefinitionKey("dhcp4", 230)


def _definition(kind: str = "uint8") -> dict:
    return {
        "option-def": [{"name": "site-code", "code": 230, "type": kind, "space": "dhcp4"}],
        "option-data": [{"code": 230, "data": "5"}],
        "subnet4": [],
    }


def _operator_definition(**fields) -> Callable[[_Fixture, dict], Any]:
    """Return a state before the run: the imported DHCP server, with an unmapped definition of *fields*."""

    def before(fixture: _Fixture, config: dict):
        fixture.apply_cleanly({"subnet4": []})
        values = {"standard": False, "space": "dhcp4", "type": "uint8", "dhcp_server": fixture.dhcp_server(), **fields}
        return _model("OptionDefinition").objects.create(**values)

    return before


_HELD = (
    "The DHCP plugin holds one custom Option Definition for each space and code of a DHCP server, "
    "and another row holds it."
)
_UNIQUE_NAME = "Global custom option definitions must be uniqe in space and name"

_DEFINITION_ROWS = (
    _Row(
        "create",
        _DEF_KEY,
        _definition(),
        (_created(Kind.OPTION_DEFINITION, _DEF), _created(Kind.OPTION, _DEF_OPTION)),
        {"name": "site-code", "code": 230, "type": "uint8", "row": "new"},
        related=(_DEF_OPTION,),
    ),
    _Row(
        "update",
        _DEF_KEY,
        _definition("uint16"),
        (_updated(Kind.OPTION_DEFINITION, _DEF),),
        {"name": "site-code", "code": 230, "type": "uint16", "row": "kept"},
        before=_keep_mapped(_DEF_KEY, _definition()),
        related=(_DEF_OPTION,),
    ),
    _Row(
        "unchanged",
        _DEF_KEY,
        _definition(),
        (),
        {"name": "site-code", "code": 230, "type": "uint8", "row": "kept"},
        before=_keep_mapped(_DEF_KEY),
        related=(_DEF_OPTION,),
    ),
    _Row(
        "adopt",
        _DEF_KEY,
        _definition(),
        (_updated(Kind.OPTION_DEFINITION, _DEF), _created(Kind.OPTION, _DEF_OPTION)),
        # The name is not a managed field: an adopted definition keeps it.
        {"name": "legacy-code", "code": 230, "type": "uint8", "row": "kept"},
        before=_operator_definition(name="legacy-code", code=230, family=4, type="uint16"),
        related=(_DEF_OPTION,),
    ),
    _Row(
        "refusal",
        _DEF_KEY,
        _definition(),
        (
            (Kind.OPTION_DEFINITION, _DEF, Outcome.UNSUPPORTED, Reason.PLUGIN_GAP, _HELD, None),
            (
                Kind.OPTION,
                _DEF_OPTION,
                Outcome.UNSUPPORTED,
                Reason.PLUGIN_GAP,
                f"Its Option Definition is not imported. {_HELD}",
                None,
            ),
        ),
        None,
        # A definition of the other family holds the code on this DHCP server, so the run cannot adopt it.
        before=_operator_definition(name="other-family", code=230, family=6),
        related=(_DEF_OPTION,),
    ),
    _Row(
        "write failure",
        _DEF_KEY,
        _definition(),
        (
            (Kind.OPTION_DEFINITION, _DEF, *_FAILED),
            (
                Kind.OPTION,
                _DEF_OPTION,
                Outcome.SKIPPED,
                Reason.PARENT_NOT_IMPORTED,
                "Its Option Definition is not imported. See server logs.",
                None,
            ),
        ),
        None,
        refuse="OptionDefinition",
        related=(_DEF_OPTION,),
    ),
    _Row(
        "plugin ValidationError",
        _DEF_KEY,
        _definition(),
        (
            (
                Kind.OPTION_DEFINITION,
                _DEF,
                Outcome.SKIPPED,
                Reason.WRITE_FAILED,
                f"{_REFUSES}{_UNIQUE_NAME}",
                None,
            ),
            (
                Kind.OPTION,
                _DEF_OPTION,
                Outcome.SKIPPED,
                Reason.PARENT_NOT_IMPORTED,
                f"Its Option Definition is not imported. {_REFUSES}{_UNIQUE_NAME}",
                None,
            ),
        ),
        None,
        # Another code holds the name of the definition on this DHCP server.
        before=_operator_definition(name="site-code", code=231, family=4),
        related=(_DEF_OPTION,),
    ),
)

# ── Client class ─────────────────────────────────────────────────────────────

_CLASS = "Dhcp4/client-classes[name=lab]"
_CLASS_DEF = f"{_CLASS}/option-def[code=231]"
_CLASS_OPTION = f"{_CLASS}/option-data[code=231]"
_CLASS_KEY = NamedKey(Kind.CLIENT_CLASS, "lab")
_CLASS_NAME_TAKEN = (
    Outcome.UNSUPPORTED,
    Reason.PLUGIN_GAP,
    (
        "Another client class holds the name 'lab'. "
        "The DHCP plugin needs each client class name to be unique across all DHCP servers."
    ),
    Capability.NAME_PER_SERVER,
)


def _client_class(test: str = "member('KNOWN')", data: str = "5") -> dict:
    return {
        "client-classes": [
            {
                "name": "lab",
                "test": test,
                "option-def": [{"name": "lab-code", "code": 231, "type": "uint8", "space": "dhcp4"}],
                "option-data": [{"code": 231, "data": data}],
            }
        ],
        "subnet4": [],
    }


def _other_class(fixture: _Fixture, config: dict) -> None:
    _model("ClientClass").objects.create(name="lab", dhcp_server=fixture.other_dhcp_server())


def _released_class(fixture: _Fixture, config: dict):
    """Return the class that the released importer wrote before client classes had a mapping."""
    fixture.apply_cleanly({"subnet4": []})
    name = dhcp_plugin._released_client_class_name(fixture.server, "lab")
    return _model("ClientClass").objects.create(name=name, dhcp_server=fixture.dhcp_server(), test="old")


def _renamed_class_and_its_name_taken(fixture: _Fixture, config: dict):
    row = _keep_mapped(_CLASS_KEY, _client_class(), change=_rename("lab-renamed"))(fixture, config)
    _other_class(fixture, config)
    return row


_CLASS_ROWS = (
    _Row(
        "create",
        _CLASS_KEY,
        _client_class(),
        (
            _created(Kind.CLIENT_CLASS, _CLASS),
            _created(Kind.OPTION_DEFINITION, _CLASS_DEF),
            _created(Kind.OPTION, _CLASS_OPTION),
        ),
        {"name": "lab", "test": "member('KNOWN')", "row": "new"},
    ),
    _Row(
        "update",
        _CLASS_KEY,
        _client_class("member('UNKNOWN')"),
        (_updated(Kind.CLIENT_CLASS, _CLASS),),
        {"name": "lab", "test": "member('UNKNOWN')", "row": "kept"},
        before=_keep_mapped(_CLASS_KEY, _client_class()),
    ),
    _Row(
        "unchanged",
        _CLASS_KEY,
        _client_class(),
        (),
        {"name": "lab", "test": "member('KNOWN')", "row": "kept"},
        before=_keep_mapped(_CLASS_KEY),
    ),
    _Row(
        "adopt",
        _CLASS_KEY,
        _client_class(),
        (
            _updated(Kind.CLIENT_CLASS, _CLASS),
            _created(Kind.OPTION_DEFINITION, _CLASS_DEF),
            _created(Kind.OPTION, _CLASS_OPTION),
        ),
        {"name": "lab", "test": "member('KNOWN')", "row": "kept"},
        before=_released_class,
    ),
    _Row(
        "refusal",
        _CLASS_KEY,
        _client_class(),
        (
            (Kind.CLIENT_CLASS, _CLASS, *_CLASS_NAME_TAKEN),
            (Kind.OPTION, _CLASS_OPTION, *_SKIPPED),
            (Kind.OPTION_DEFINITION, _CLASS_DEF, *_SKIPPED),
        ),
        None,
        before=_other_class,
    ),
    _Row(
        "name conflict on an existing row",
        _CLASS_KEY,
        _client_class("member('UNKNOWN')", data="6"),
        (
            (Kind.CLIENT_CLASS, f"{_CLASS}/name", *_CLASS_NAME_TAKEN),
            _updated(Kind.CLIENT_CLASS, _CLASS),
            # The run still writes the children of the row.
            _updated(Kind.OPTION, _CLASS_OPTION),
        ),
        # The mapped row keeps its name and takes every other field.
        {"name": "lab-renamed", "test": "member('UNKNOWN')", "row": "kept"},
        before=_renamed_class_and_its_name_taken,
        facts=(
            ("the Option of the class takes Kea's data", _option_data(_CLASS_KEY, 231), ["6"]),
            ("the other row keeps the name and its DHCP server", _holder("ClientClass", "lab"), ["other dhcp server"]),
        ),
    ),
    _Row(
        "write failure",
        _CLASS_KEY,
        _client_class(),
        (
            (Kind.CLIENT_CLASS, _CLASS, *_FAILED),
            (Kind.OPTION, _CLASS_OPTION, *_SKIPPED),
            (Kind.OPTION_DEFINITION, _CLASS_DEF, *_SKIPPED),
        ),
        None,
        refuse="ClientClass",
    ),
)

# ── Shared Network ───────────────────────────────────────────────────────────

_NETWORK = "Dhcp4/shared-networks[name=office]"
_NETWORK_OPTION = f"{_NETWORK}/option-data[code=6]"
_NETWORK_KEY = NamedKey(Kind.SHARED_NETWORK, "office")
_NETWORK_NAME_TAKEN = (
    Outcome.UNSUPPORTED,
    Reason.PLUGIN_GAP,
    (
        "Another shared network holds the name 'office'. "
        "The DHCP plugin needs each shared network name to be unique across all DHCP servers."
    ),
    Capability.NAME_PER_SERVER,
)


def _shared_network(lifetime: int = 3600, data: str = "192.0.2.53") -> dict:
    network = {
        "name": "office",
        "valid-lifetime": lifetime,
        "client-classes": ["lab"],
        "option-data": [{"code": 6, "data": data}],
        "subnet4": [],
    }
    return {"client-classes": [_LAB], "shared-networks": [network], "subnet4": []}


def _other_network(fixture: _Fixture, config: dict) -> None:
    _model("SharedNetwork").objects.create(name="office", dhcp_server=fixture.other_dhcp_server())


def _renamed_network_and_its_name_taken(fixture: _Fixture, config: dict):
    row = _keep_mapped(_NETWORK_KEY, _shared_network(), change=_rename("office-renamed"))(fixture, config)
    _other_network(fixture, config)
    return row


def _without_optional_prefix(found: PluginCapabilities) -> PluginCapabilities:
    return replace(found, present=found.present - {Capability.SHARED_NETWORK_OPTIONAL_PREFIX})


_NETWORK_STATE = {"name": "office", "valid_lifetime": 3600, "prefix": None, "client_classes": ["lab"]}

_NETWORK_ROWS = (
    _Row(
        "create",
        _NETWORK_KEY,
        _shared_network(),
        (_created(Kind.SHARED_NETWORK, _NETWORK), _created(Kind.OPTION, _NETWORK_OPTION)),
        {**_NETWORK_STATE, "row": "new"},
    ),
    _Row(
        "update",
        _NETWORK_KEY,
        _shared_network(7200),
        (_updated(Kind.SHARED_NETWORK, _NETWORK),),
        {**_NETWORK_STATE, "valid_lifetime": 7200, "row": "kept"},
        before=_keep_mapped(_NETWORK_KEY, _shared_network()),
    ),
    _Row(
        "unchanged",
        _NETWORK_KEY,
        _shared_network(),
        (),
        {**_NETWORK_STATE, "row": "kept"},
        before=_keep_mapped(_NETWORK_KEY),
    ),
    _Row(
        "refusal",
        _NETWORK_KEY,
        _shared_network(),
        ((Kind.SHARED_NETWORK, _NETWORK, *_NETWORK_NAME_TAKEN), (Kind.OPTION, _NETWORK_OPTION, *_SKIPPED)),
        None,
        before=_other_network,
    ),
    _Row(
        "name conflict on an existing row",
        _NETWORK_KEY,
        _shared_network(7200, data="192.0.2.54"),
        (
            (Kind.SHARED_NETWORK, f"{_NETWORK}/name", *_NETWORK_NAME_TAKEN),
            _updated(Kind.SHARED_NETWORK, _NETWORK),
            # The run still writes the children of the row.
            _updated(Kind.OPTION, _NETWORK_OPTION),
        ),
        {**_NETWORK_STATE, "name": "office-renamed", "valid_lifetime": 7200, "row": "kept"},
        before=_renamed_network_and_its_name_taken,
        facts=(
            ("the Option of the Shared Network takes Kea's data", _option_data(_NETWORK_KEY, 6), ["192.0.2.54"]),
            (
                "the other row keeps the name and its DHCP server",
                _holder("SharedNetwork", "office"),
                ["other dhcp server"],
            ),
        ),
    ),
    _Row(
        "write failure",
        _NETWORK_KEY,
        _shared_network(),
        ((Kind.SHARED_NETWORK, _NETWORK, *_FAILED), (Kind.OPTION, _NETWORK_OPTION, *_SKIPPED)),
        None,
        refuse="SharedNetwork",
    ),
    _Row(
        "refusal without the optional-prefix capability",
        _NETWORK_KEY,
        _shared_network(),
        (
            (
                Kind.SHARED_NETWORK,
                _NETWORK,
                Outcome.UNSUPPORTED,
                Reason.PLUGIN_GAP,
                "The DHCP plugin needs a Prefix for each Shared Network, and a Kea Shared Network has none.",
                Capability.SHARED_NETWORK_OPTIONAL_PREFIX,
            ),
            (Kind.OPTION, _NETWORK_OPTION, *_SKIPPED),
        ),
        None,
        capabilities=_without_optional_prefix,
    ),
)

# ── Subnet ───────────────────────────────────────────────────────────────────

_SUBNET = "Dhcp4/subnet4[id=10]"
_SUBNET_OPTION = f"{_SUBNET}/option-data[code=6]"
_SUBNET_POOL = f"{_SUBNET}/pools[pool=192.0.2.10-192.0.2.20]"
_SUBNET_POOL_OPTION = f"{_SUBNET_POOL}/option-data[code=3]"
_SUBNET_RESERVATION = f"{_SUBNET}/reservations[hw-address={_MAC}]"
# The Reservation of Subnet 10 assigns two DHCP Options.
_RESERVATION_OPTIONS = tuple(f"{_SUBNET_RESERVATION}/option-data[code={code}]" for code in (6, 15))
_SUBNET_KEY = SubnetKey(10)


def _subnet(lifetime: int = 3600, *, reservations: bool = True, **extra) -> dict:
    subnet = {
        "id": 10,
        "subnet": "192.0.2.0/24",
        "valid-lifetime": lifetime,
        "client-classes": ["lab"],
        "option-data": [{"code": 6, "data": "192.0.2.53"}],
        "pools": [
            {
                "pool": "192.0.2.10-192.0.2.20",
                "pool-id": 7,
                "client-classes": ["lab"],
                "option-data": [{"code": 3, "data": "192.0.2.1"}],
            }
        ],
        **extra,
    }
    if reservations:
        subnet["reservations"] = [
            {
                "hw-address": _MAC,
                "ip-address": "192.0.2.30",
                "hostname": "host-a",
                "client-classes": ["lab"],
                "option-data": [{"code": 6, "data": "192.0.2.53"}, {"code": 15, "data": "host.example.org"}],
            }
        ]
    return {"client-classes": [_LAB], "subnet4": [subnet]}


def _subtree(entry: tuple, *, reservation: tuple) -> tuple[_Entry, ...]:
    """Return the entries of the children of Subnet 10: *entry* for each, and *reservation* for the Reservation."""
    return (
        (Kind.OPTION, _SUBNET_OPTION, *entry),
        (Kind.POOL, _SUBNET_POOL, *entry),
        (Kind.OPTION, _SUBNET_POOL_OPTION, *entry),
        (Kind.RESERVATION, _SUBNET_RESERVATION, *reservation),
        *((Kind.OPTION, path, *entry) for path in _RESERVATION_OPTIONS),
    )


def _other_server_holds_subnet_10(fixture: _Fixture, config: dict) -> None:
    other = _make_db_server(name="other", ca_url="https://other.example.invalid", dhcp6=False)
    fixture.apply_cleanly({"subnet4": [{"id": 10, "subnet": "203.0.113.0/24"}]}, server=other)


def _operator_subnet_holds_the_name(fixture: _Fixture, config: dict) -> None:
    """Add an operator Subnet that holds the name that the import gives Subnet 10, with another ID."""
    from ipam.models import Prefix
    from netaddr import IPNetwork

    _model("Subnet").objects.create(
        name=f"{_SERVER} DHCPv4 subnet 10",
        prefix=Prefix.objects.create(prefix=IPNetwork("198.51.100.0/24")),
        dhcp_server=fixture.other_dhcp_server(),
        subnet_id=99,
    )


def _renumbered(row) -> None:
    """Give the mapped row another Subnet ID, as a plugin that numbered it before the import held Kea's IDs."""
    type(row).objects.filter(pk=row.pk).update(subnet_id=77)


_TAKEN = (
    Outcome.UNSUPPORTED,
    Reason.SUBNET_ID_CLASH,
    (
        "Subnet 192.0.2.0/24 needs Subnet ID 10, which Subnet 'other DHCPv4 subnet 10' (203.0.113.0/24) holds. "
        "The DHCP plugin needs each Subnet ID to be unique across all DHCP servers."
    ),
    Capability.SUBNET_ID_PER_SERVER,
)
_SUBNET_NOT_IMPORTED = (Outcome.SKIPPED, Reason.PARENT_NOT_IMPORTED, "Subnet 10 was not imported.", None)
_SUBNET_NAME_TAKEN = f"{_REFUSES}Subnet with this Name already exists."
_SUBNET_STATE = {"prefix": "192.0.2.0/24", "subnet_id": 10, "valid_lifetime": 3600, "client_classes": ["lab"]}

_SUBNET_ROWS = (
    _Row(
        "create",
        _SUBNET_KEY,
        _subnet(),
        (
            _created(Kind.SUBNET, _SUBNET),
            *_subtree((Outcome.CREATED, None, "", None), reservation=(Outcome.CREATED, None, "", None)),
        ),
        {**_SUBNET_STATE, "row": "new"},
    ),
    _Row(
        "update",
        _SUBNET_KEY,
        _subnet(7200),
        (_updated(Kind.SUBNET, _SUBNET),),
        {**_SUBNET_STATE, "valid_lifetime": 7200, "row": "kept"},
        before=_keep_mapped(_SUBNET_KEY, _subnet()),
    ),
    _Row(
        "unchanged",
        _SUBNET_KEY,
        _subnet(),
        (),
        {**_SUBNET_STATE, "row": "kept"},
        before=_keep_mapped(_SUBNET_KEY),
    ),
    _Row(
        "renumbered by the Subnet ID settlement, no other change",
        _SUBNET_KEY,
        _subnet(),
        (_updated(Kind.SUBNET, _SUBNET),),
        {**_SUBNET_STATE, "row": "kept"},
        before=_keep_mapped(_SUBNET_KEY, change=_renumbered),
    ),
    _Row(
        "refusal: another Server holds its Subnet ID",
        _SUBNET_KEY,
        _subnet(),
        ((Kind.SUBNET, _SUBNET, *_TAKEN), *_subtree(_TAKEN, reservation=_TAKEN)),
        None,
        before=_other_server_holds_subnet_10,
        facts=(("a taken Subnet ID is no write failure", _errors, 0),),
    ),
    _Row(
        "write failure",
        _SUBNET_KEY,
        _subnet(),
        ((Kind.SUBNET, _SUBNET, *_FAILED), *_subtree(_SKIPPED, reservation=_SUBNET_NOT_IMPORTED)),
        None,
        refuse="Subnet",
    ),
    _Row(
        "plugin ValidationError",
        _SUBNET_KEY,
        _subnet(),
        (
            (Kind.SUBNET, _SUBNET, Outcome.SKIPPED, Reason.WRITE_FAILED, _SUBNET_NAME_TAKEN, None),
            *_subtree(_SKIPPED, reservation=_SUBNET_NOT_IMPORTED),
        ),
        None,
        before=_operator_subnet_holds_the_name,
    ),
)

# ── Pool ─────────────────────────────────────────────────────────────────────

_POOL_KEY = PoolKey(10, Pool(ipaddress.ip_address("192.0.2.10"), ipaddress.ip_address("192.0.2.20")))
_POOL_STATE = {"range": "192.0.2.10-192.0.2.20", "pool_id": 7, "subnet_id": 10, "client_classes": ["lab"]}


def _pool(pool_id: int = 7) -> dict:
    config = _subnet(reservations=False)
    config["subnet4"][0]["pools"][0]["pool-id"] = pool_id
    return config


def _legacy_pool(fixture: _Fixture, config: dict):
    """Return a Pool that an import wrote before Pools and Options had a mapping."""
    return _keep_mapped(_POOL_KEY, change=_unmapped(fixture.server, Kind.POOL, Kind.OPTION, pool_id=1))(fixture, config)


_POOL_ROWS = (
    _Row(
        "create",
        _POOL_KEY,
        _pool(),
        (_created(Kind.POOL, _SUBNET_POOL), _created(Kind.OPTION, _SUBNET_POOL_OPTION)),
        {**_POOL_STATE, "row": "new"},
    ),
    _Row(
        "update",
        _POOL_KEY,
        _pool(8),
        (_updated(Kind.POOL, _SUBNET_POOL),),
        {**_POOL_STATE, "pool_id": 8, "row": "kept"},
        before=_keep_mapped(_POOL_KEY, _pool()),
    ),
    _Row(
        "unchanged",
        _POOL_KEY,
        _pool(),
        (),
        {**_POOL_STATE, "row": "kept"},
        before=_keep_mapped(_POOL_KEY),
    ),
    _Row(
        "adopt",
        _POOL_KEY,
        _pool(),
        # Its Option adopts the unmapped Option of the same code, which holds Kea's value: it has no entry.
        (_updated(Kind.POOL, _SUBNET_POOL),),
        {**_POOL_STATE, "row": "kept"},
        before=_legacy_pool,
    ),
    _Row(
        "write failure",
        _POOL_KEY,
        _pool(),
        ((Kind.POOL, _SUBNET_POOL, *_FAILED), (Kind.OPTION, _SUBNET_POOL_OPTION, *_SKIPPED)),
        None,
        refuse="Pool",
    ),
    _Row(
        "plugin ValidationError",
        _POOL_KEY,
        _pool(),
        (
            (
                Kind.POOL,
                _SUBNET_POOL,
                Outcome.SKIPPED,
                Reason.WRITE_FAILED,
                f"{_REFUSES}This site adds no Pool.",
                None,
            ),
            (Kind.OPTION, _SUBNET_POOL_OPTION, *_SKIPPED),
        ),
        None,
        validators={"netbox_dhcp.pool": [f"{__name__}.RefusePoolValidator"]},
    ),
)

# ── Delegated-prefix Pool ────────────────────────────────────────────────────

_PD_SUBNET = "Dhcp6/subnet6[id=60]"
_PD_POOL = f"{_PD_SUBNET}/pd-pools[prefix=2001:db8:100::/48,delegated-len=56]"
_PD_POOL_OPTION = f"{_PD_POOL}/option-data[code=23]"
_PD_KEY = PDPoolKey(60, ipaddress.IPv6Network("2001:db8:100::/48"), 56)
_PD_STATE = {"prefix": "2001:db8:100::/48", "delegated_length": 56, "pool_id": 3, "client_classes": ["lab"]}


def _pd_pool(pool_id: int = 3, delegated_length: int = 56) -> dict:
    pd_pool = {
        "prefix": "2001:db8:100::",
        "prefix-len": 48,
        "delegated-len": delegated_length,
        "pool-id": pool_id,
        "client-classes": ["lab"],
        "option-data": [{"code": 23, "data": "2001:db8:100::53"}],
    }
    return {"client-classes": [_LAB], "subnet6": [{"id": 60, "subnet": "2001:db8:60::/64", "pd-pools": [pd_pool]}]}


_PD_SHORT = f"{_PD_SUBNET}/pd-pools[prefix=2001:db8:100::/48,delegated-len=40]"

_PD_POOL_ROWS = (
    _Row(
        "create",
        _PD_KEY,
        _pd_pool(),
        (_created(Kind.PD_POOL, _PD_POOL), _created(Kind.OPTION, _PD_POOL_OPTION)),
        {**_PD_STATE, "row": "new"},
    ),
    _Row(
        "update",
        _PD_KEY,
        _pd_pool(4),
        (_updated(Kind.PD_POOL, _PD_POOL),),
        {**_PD_STATE, "pool_id": 4, "row": "kept"},
        before=_keep_mapped(_PD_KEY, _pd_pool()),
    ),
    _Row(
        "unchanged",
        _PD_KEY,
        _pd_pool(),
        (),
        {**_PD_STATE, "row": "kept"},
        before=_keep_mapped(_PD_KEY),
    ),
    _Row(
        "write failure",
        _PD_KEY,
        _pd_pool(),
        ((Kind.PD_POOL, _PD_POOL, *_FAILED), (Kind.OPTION, _PD_POOL_OPTION, *_SKIPPED)),
        None,
        refuse="PDPool",
    ),
    _Row(
        "plugin ValidationError: the plugin cannot hold it",
        PDPoolKey(60, ipaddress.IPv6Network("2001:db8:100::/48"), 40),
        # Kea delegates /40 from a /48 prefix; the DHCP plugin refuses a delegated length shorter than the prefix.
        _pd_pool(delegated_length=40),
        (
            (
                Kind.PD_POOL,
                _PD_SHORT,
                Outcome.UNSUPPORTED,
                Reason.PLUGIN_GAP,
                f"{_REFUSES}Delegated length must not be shorter than the length of the prefix",
                None,
            ),
            (Kind.OPTION, f"{_PD_SHORT}/option-data[code=23]", *_SKIPPED),
        ),
        None,
    ),
)

# ── Reservation ──────────────────────────────────────────────────────────────

_RESERVATION_KEY = InSubnetReservationKey(10, "hw-address", _MAC)
_RESERVATION_STATE = {
    "hostname": "host-a",
    "ipv4_address": "192.0.2.30/24",
    "hw_address": _MAC,
    "subnet_id": 10,
    "client_classes": ["lab"],
}


def _reservation(hostname: str = "host-a") -> dict:
    config = _subnet()
    subnet = config["subnet4"][0]
    subnet["option-data"], subnet["pools"] = [], []
    subnet["reservations"][0]["hostname"] = hostname
    return config


def _legacy_reservation(fixture: _Fixture, config: dict):
    """Return a Reservation that an import wrote before Reservations and Options had a mapping."""
    change = _unmapped(fixture.server, Kind.RESERVATION, Kind.OPTION, hostname="legacy")
    return _keep_mapped(_RESERVATION_KEY, change=change)(fixture, config)


_RESERVATION_ROWS = (
    _Row(
        "create",
        _RESERVATION_KEY,
        _reservation(),
        (
            _created(Kind.RESERVATION, _SUBNET_RESERVATION),
            *(_created(Kind.OPTION, path) for path in _RESERVATION_OPTIONS),
        ),
        {**_RESERVATION_STATE, "row": "new"},
    ),
    _Row(
        "update",
        _RESERVATION_KEY,
        _reservation("host-b"),
        (_updated(Kind.RESERVATION, _SUBNET_RESERVATION),),
        {**_RESERVATION_STATE, "hostname": "host-b", "row": "kept"},
        before=_keep_mapped(_RESERVATION_KEY, _reservation()),
    ),
    _Row(
        "unchanged",
        _RESERVATION_KEY,
        _reservation(),
        (),
        {**_RESERVATION_STATE, "row": "kept"},
        before=_keep_mapped(_RESERVATION_KEY),
    ),
    _Row(
        "adopt",
        _RESERVATION_KEY,
        _reservation(),
        (_updated(Kind.RESERVATION, _SUBNET_RESERVATION),),
        {**_RESERVATION_STATE, "row": "kept"},
        before=_legacy_reservation,
    ),
    _Row(
        "write failure",
        _RESERVATION_KEY,
        _reservation(),
        (
            (Kind.RESERVATION, _SUBNET_RESERVATION, *_FAILED),
            *((Kind.OPTION, path, *_SKIPPED) for path in _RESERVATION_OPTIONS),
        ),
        None,
        refuse="HostReservation",
    ),
)

# ── DHCP Option ──────────────────────────────────────────────────────────────

_OPTION = f"{_SUBNET}/option-data[code=6,client-classes=lab]"
_OPTION_KEY = OptionKey(MappingSource.subnet(10), DHCPOptionIdentity("dhcp4", 6, frozenset({"lab"})))
_OPTION_STATE = {"parent": "subnet", "code": 6, "data": "192.0.2.53", "client_classes": ["lab"], "options_of_parent": 1}


def _option(data: str = "192.0.2.53") -> dict:
    config = _subnet(reservations=False)
    subnet = config["subnet4"][0]
    subnet["option-data"] = [{"code": 6, "data": data, "client-classes": ["lab"]}]
    subnet["pools"] = []
    return config


def _legacy_option(fixture: _Fixture, config: dict):
    """Return an Option that an import wrote before Options had a mapping."""
    return _keep_mapped(_OPTION_KEY, change=_unmapped(fixture.server, Kind.OPTION, data="192.0.2.99"))(fixture, config)


_OPTION_ROWS = (
    _Row("create", _OPTION_KEY, _option(), (_created(Kind.OPTION, _OPTION),), {**_OPTION_STATE, "row": "new"}),
    _Row(
        "update",
        _OPTION_KEY,
        _option("192.0.2.54"),
        (_updated(Kind.OPTION, _OPTION),),
        {**_OPTION_STATE, "data": "192.0.2.54", "row": "kept"},
        before=_keep_mapped(_OPTION_KEY, _option()),
    ),
    _Row(
        "unchanged",
        _OPTION_KEY,
        _option(),
        (),
        {**_OPTION_STATE, "row": "kept"},
        before=_keep_mapped(_OPTION_KEY),
    ),
    _Row(
        "adopt",
        _OPTION_KEY,
        _option(),
        (_updated(Kind.OPTION, _OPTION),),
        {**_OPTION_STATE, "row": "kept"},
        before=_legacy_option,
    ),
    _Row("write failure", _OPTION_KEY, _option(), ((Kind.OPTION, _OPTION, *_FAILED),), None, refuse="Option"),
    _Row(
        "plugin ValidationError",
        _OPTION_KEY,
        _option(),
        (
            (
                Kind.OPTION,
                _OPTION,
                Outcome.SKIPPED,
                Reason.WRITE_FAILED,
                f"{_REFUSES}This site does not use 192.0.2.53.",
                None,
            ),
        ),
        None,
        validators={"netbox_dhcp.option": [f"{__name__}.RefuseOptionDataValidator"]},
    ),
)


def _in_scope(path: str, paths: tuple[str, ...]) -> bool:
    return any(path == each or path.startswith(f"{each}/") for each in paths)


class RowWriteTableTest(TestCase):
    """Every kind of imported DHCP plugin row through one write protocol: one table, one method for each kind."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if not apps.is_installed(DHCP_PLUGIN):
            raise unittest.SkipTest(f"{DHCP_PLUGIN} not installed")
        super().setUpClass()

    def _assert_row(self, row: _Row, found: PluginCapabilities) -> None:
        model = _model(MAPPING_KINDS[row.kind][0])
        fixture = _Fixture(self, 6 if row.kind == Kind.PD_POOL else 4, row.capabilities(found))
        kept = row.before(fixture, row.config) if row.before is not None else None
        rows_before = model.objects.count()
        confirmed_before = next_confirmation_number()
        with _refusing(row.refuse) as refused, override_settings(CUSTOM_VALIDATORS=row.validators or {}):
            summary = fixture.apply(row.config)

        scope = (row.key.path(fixture.family), *row.related)
        # A plain dict gives a line diff; the counts still compare exactly.
        self.assertEqual(
            dict(
                Counter(
                    (entry.kind, entry.path, entry.outcome, entry.reason, entry.detail, entry.capability)
                    for entry in summary.entries
                    if _in_scope(entry.path, scope)
                )
            ),
            dict(Counter(row.entries)),
        )
        mapped = fixture.mapped(row.key)
        if row.state is None:
            self.assertIsNone(mapped)
            # The run wrote no row of the kind.
            self.assertEqual(model.objects.count(), rows_before)
        else:
            self.assertIsNotNone(mapped)
            state = {**_STATE[row.kind](mapped), "row": "kept" if kept is not None and kept.pk == mapped.pk else "new"}
            self.assertEqual(state, row.state)
            # The run adds a row only when it creates one.
            self.assertEqual(model.objects.count() - rows_before, 1 if row.state["row"] == "new" else 0)
            # The run confirmed the mapping with a number of its own.
            self.assertGreater(fixture.link(row.key).confirmation, confirmed_before)
        for label, read, expected in row.facts:
            self.assertEqual(read(fixture, summary), expected, label)
        if row.refuse is not None:
            # The receiver ran: the run tried to write the row.
            self.assertTrue(refused)

    def _assert_rows(self, rows: tuple[_Row, ...], found: PluginCapabilities) -> None:
        for row in rows:
            with self.subTest(kind=row.kind.value, scenario=row.scenario), _rolled_back():
                self._assert_row(row, found)

    def _plugin_0_2_0(self) -> PluginCapabilities:
        """Return the capabilities of the installed netbox-plugin-dhcp 0.2.0, which the refusal texts name."""
        found = probe()
        for capability in (
            Capability.NAME_PER_SERVER,
            Capability.SUBNET_ID_PER_SERVER,
            Capability.SHARED_NETWORK_OPTIONAL_PREFIX,
        ):
            self.assertFalse(found.has(capability), capability)
        return found

    def test_option_definition_rows(self):
        self._assert_rows(_DEFINITION_ROWS, self._plugin_0_2_0())

    def test_client_class_rows(self):
        self._assert_rows(_CLASS_ROWS, self._plugin_0_2_0())

    def test_shared_network_rows(self):
        # netbox-plugin-dhcp 0.2.0 writes no Shared Network, so the rows take the optional-prefix capability.
        found = optional_shared_network_prefix(self)
        self.assertTrue(found.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX))
        self._assert_rows(_NETWORK_ROWS, found)

    def test_subnet_rows(self):
        self._assert_rows(_SUBNET_ROWS, self._plugin_0_2_0())

    def test_pool_rows(self):
        self._assert_rows(_POOL_ROWS, self._plugin_0_2_0())

    def test_pd_pool_rows(self):
        self._assert_rows(_PD_POOL_ROWS, self._plugin_0_2_0())

    def test_reservation_rows(self):
        self._assert_rows(_RESERVATION_ROWS, self._plugin_0_2_0())

    def test_option_rows(self):
        self._assert_rows(_OPTION_ROWS, self._plugin_0_2_0())
