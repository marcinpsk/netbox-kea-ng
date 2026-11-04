# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The DHCPServer of one Server and family, its global settings and its interfaces.

* **One DHCPServer per Server and family** (Kea runs one daemon per family). It holds only its daemon's global
  configuration, maps to it, and links the interfaces that ``interfaces-config`` names.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from .. import event_scope, kea_paths
from ..reservations import FLEX_ID
from .dhcp_import_fields import GATED_SERVER_FIELDS, SERVER_FIELDS
from .dhcp_import_mappings import mapped_elsewhere, mapped_target, observe_mapping, unlinked
from .dhcp_import_plan import MAX_KEA_NAME_LENGTH, ServerKey
from .dhcp_import_report import Capability, Kind, Reason, not_written, unsupported
from .dhcp_import_summary import ImportSummary
from .dhcp_import_values import (
    Source,
    cleared,
    gated_values,
    is_unset,
    server_id_values,
    settings_fields,
    user_context_fields,
)
from .dhcp_import_write import FAILED, ManagedFieldsMismatch, managed_changes, relation_changes, save_changes
from .dhcp_plugin_capabilities import PluginCapabilities, plugin_model

if TYPE_CHECKING:
    from .dhcp_import_plan import PlannedServer


def _identifier_values(
    identifiers: tuple[str, ...], root: str, family: int, capabilities: PluginCapabilities, summary: ImportSummary
) -> list[str] | None:
    """Keep the Reservation identifier types that the DHCP plugin can hold; flex-id needs its capability."""
    field = plugin_model("DHCPServer")._meta.get_field("host_reservation_identifiers")
    valid = {value for value, _label in field.base_field.flatchoices}
    if capabilities.has(Capability.FLEX_ID_IDENTIFIER):
        valid.add(FLEX_ID)
    elif FLEX_ID in identifiers:
        path = kea_paths.setting(root, kea_paths.HOST_RESERVATION_IDENTIFIERS)
        detail = "The DHCP plugin has no flex-id Reservation identifier. The other identifier types import."
        summary.record(unsupported(family, Kind.SERVER, path, Capability.FLEX_ID_IDENTIFIER, detail))
    return [identifier for identifier in identifiers if identifier in valid] or None


def server_values(
    dhcp_server, planned: PlannedServer, family: int, capabilities: PluginCapabilities, summary: ImportSummary
) -> dict:
    """Return the managed DHCPServer fields of one family's global configuration, by field name.

    A field that Kea does not declare is cleared (``None`` for a gated field). A value that the field of
    *dhcp_server* refuses keeps the current value. A gated fact whose capability is missing is not a field here: it
    has an unsupported entry instead. The Reservation identifier types are missing when Kea's list is not valid.
    """
    settings = planned.global_settings
    root = planned.key.path(family)
    source = Source(family, Kind.SERVER, root)
    values = settings_fields(dhcp_server, settings, SERVER_FIELDS, summary, source)
    values |= server_id_values(settings.get(kea_paths.SERVER_ID), root, family, capabilities, summary)
    if planned.host_reservation_identifiers is not None:
        values["host_reservation_identifiers"] = _identifier_values(
            planned.host_reservation_identifiers, root, family, capabilities, summary
        )
    if capabilities.has(Capability.SERVER_FAMILY):
        values["family"] = family
    else:
        detail = "The DHCP plugin has no address family on a DHCP server."
        summary.record(unsupported(family, Kind.SERVER, root, Capability.SERVER_FAMILY, detail))
    values |= user_context_fields(dhcp_server, planned.user_context, capabilities, summary, source, "DHCP server")
    values |= gated_values(dhcp_server, settings, GATED_SERVER_FIELDS, capabilities, summary, source)
    return values


def apply_global_settings(
    dhcp_server, values: dict, summary: ImportSummary, family: int, capabilities: PluginCapabilities
) -> bool | None:
    """Make the managed fields of *dhcp_server* equal *values*, clearing each ``None`` (or unset) value.

    Each family has its own DHCPServer, so this family's configuration owns every managed field of it.
    Return whether a changed value was saved, or ``None`` after a failed save. The failure is recorded here.
    """
    desired = {attr: cleared(dhcp_server, attr) if is_unset(value) else value for attr, value in values.items()}
    # A Kea list that is not valid leaves the identifier types as they are.
    desired.setdefault("host_reservation_identifiers", dhcp_server.host_reservation_identifiers)
    changed: dict = {}
    try:
        changed = managed_changes(dhcp_server, desired, capabilities)
        if not changed:
            return False
        with event_scope.atomic():
            save_changes(dhcp_server, changed)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001
        summary.record(FAILED.entry(family, Kind.SERVER, ServerKey().path(family)))
        summary.warn(f"DHCPServer settings: {exc}")
        if changed:
            # Children diff against this instance, so it must hold the persisted values.
            dhcp_server.refresh_from_db(fields=list(changed))
        return None
    return True


def _interface_name(entry: str, family: int, summary: ImportSummary) -> str | None:
    """Return the interface name of one Kea interface list entry, recording the part that the plugin cannot hold."""
    path = kea_paths.interface(family, entry)
    if entry == "*":
        detail = "'*' selects every interface. The import links only the interfaces that Kea names."
        summary.record(not_written(family, Kind.SERVER, path, Reason.NO_PLUGIN_HOME, detail))
        return None
    name, separator, _address = entry.partition("/")
    if separator:
        detail = f"The address is a Kea socket setting with no DHCP plugin field. Interface {name} is linked."
        summary.record(not_written(family, Kind.SERVER, path, Reason.NO_PLUGIN_HOME, detail))
    return name


def link_interfaces(dhcp_server, entries: tuple[str, ...] | None, summary: ImportSummary, family: int) -> bool:
    """Link the device or virtual machine interfaces that the Kea interface list names. Return whether it changed.

    ``None`` (a list that is not valid) leaves the links alone. A name that matches no interface has an entry.
    """
    if entries is None:
        return False
    from dcim.models import Interface
    from virtualization.models import VMInterface

    names = {name: entry for entry in entries if (name := _interface_name(entry, family, summary)) is not None}
    device = Interface.objects.filter(device=dhcp_server.device_id, name__in=names) if dhcp_server.device_id else []
    vm = (
        VMInterface.objects.filter(virtual_machine=dhcp_server.virtual_machine_id, name__in=names)
        if dhcp_server.virtual_machine_id
        else []
    )
    wanted = {"device_interfaces": {i.pk for i in device}, "virtual_machine_interfaces": {i.pk for i in vm}}
    matched = {i.name for i in device} | {i.name for i in vm}
    for name, entry in names.items():
        if name not in matched:
            path = kea_paths.interface(family, entry)
            detail = no_interface_detail(dhcp_server, name)
            summary.record(not_written(family, Kind.SERVER, path, Reason.NO_MATCHING_INTERFACE, detail))
    if "*" in entries:
        # The DHCP plugin cannot hold "every interface", so the links that an operator made stay.
        return False
    relations = relation_changes(dhcp_server, wanted)
    if not relations:
        return False
    dhcp_server.snapshot()
    for relation, pks in relations.items():
        getattr(dhcp_server, relation).set(pks)
    return True


def _other_family(family: int) -> int:
    return 6 if family == 4 else 4


def _primary_family(server) -> int:
    """Return the family whose DHCPServer an upgrade adopts: DHCPv4, or DHCPv6 on a DHCPv6-only Server."""
    return 4 if server.dhcp4 else 6


def adoption_servers(server, dhcp_server) -> tuple[int, ...]:
    """Return *dhcp_server* and the DHCPServer that an import before #94 named after the Server, for both families.

    A DHCPServer that another Server maps is not that row, even when its name matches.
    """
    DHCPServer = plugin_model("DHCPServer")
    elsewhere = mapped_elsewhere(DHCPServer, server)
    legacy = DHCPServer.objects.filter(name=server.name).exclude(pk=dhcp_server.pk).exclude(pk__in=elsewhere)
    return (dhcp_server.pk, *legacy.values_list("pk", flat=True))


def _move_family_options(dhcp_server, adoption_servers: tuple[int, ...], family: int) -> None:
    """Move the global Options of *family* that an import before #94 wrote on the DHCPServer of both families."""
    from django.contrib.contenttypes.models import ContentType

    stale = plugin_model("Option").objects.filter(
        assigned_object_type=ContentType.objects.get_for_model(dhcp_server),
        assigned_object_id__in=[pk for pk in adoption_servers if pk != dhcp_server.pk],
        definition__family=family,
    )
    for option in stale:
        option.snapshot()
        option.assigned_object_id = dhcp_server.pk
        option.save()


def upsert_dhcp_server(server, family: int):
    """Get or create the DHCPServer of one family of *server* through its mapping, and whether it is new.

    The first run after an upgrade adopts the DHCPServer that an earlier import named after the Server, for the
    primary family. A new DHCPServer takes the device or virtual machine of the Server's other DHCPServer, and the
    global Options of its family that an earlier import wrote on that adopted row.
    """
    DHCPServer = plugin_model("DHCPServer")
    source = ServerKey().source
    created = False
    with event_scope.atomic():
        dhcp_server = mapped_target(server, family, source)
        if dhcp_server is None and family == _primary_family(server):
            dhcp_server = unlinked(DHCPServer.objects.filter(name=server.name)).first()
        if dhcp_server is None:
            other = mapped_target(server, _other_family(family), source)
            dhcp_server = DHCPServer(
                name=synthesized_name(server.name, f" DHCPv{family}"),
                description="Imported from Kea by netbox-kea",
                device_id=other.device_id if other is not None else None,
                virtual_machine_id=other.virtual_machine_id if other is not None else None,
            )
            dhcp_server.save()
            created = True
            _move_family_options(dhcp_server, adoption_servers(server, dhcp_server), family)
        observe_mapping(server, family, dhcp_server, source)
    return dhcp_server, created


_NAME_DIGEST_LENGTH = 12


def synthesized_name(scope: str, detail: str) -> str:
    """Return a DHCP plugin row name. A name too long for the plugin ends with a hash of all of it, to stay distinct."""
    name = f"{scope}{detail}"
    if len(name) <= MAX_KEA_NAME_LENGTH:
        return name
    digest = hashlib.sha256(name.encode()).hexdigest()[:_NAME_DIGEST_LENGTH]
    return f"{name[: MAX_KEA_NAME_LENGTH - _NAME_DIGEST_LENGTH - 1]}~{digest}"


def no_interface_detail(dhcp_server, name: str) -> str:
    """Return why *dhcp_server* has no interface *name*."""
    from dcim.models import Interface
    from virtualization.models import VMInterface

    if dhcp_server.device_id is None and dhcp_server.virtual_machine_id is None:
        return "The DHCP server is linked to no device or virtual machine."
    on_device = dhcp_server.device_id is not None and (
        Interface.objects.filter(device=dhcp_server.device_id, name=name).exists()
    )
    on_vm = dhcp_server.virtual_machine_id is not None and (
        VMInterface.objects.filter(virtual_machine=dhcp_server.virtual_machine_id, name=name).exists()
    )
    if on_device or on_vm:
        return f"The DHCP server does not list interface {name} of its device or virtual machine."
    return f"The DHCP server's device or virtual machine has no interface {name}."
