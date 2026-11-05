# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The settings values that the DHCP Import plans for a DHCP plugin row: declared, gated, user-context and server-id.

* **Tuning fields** (lifetimes, timers, lease/DDNS/BOOTP/network settings) are
  imported onto the ``DHCPServer`` (global), ``Subnet``, ``Pool`` (DDNS) and ``ClientClass``. A Subnet
  or client class gets only its Declared Values (:func:`.dhcp_import_plan.declared_values`),
  and every other field is cleared to inherit. A value that a member Subnet inherits
  from its Shared Network is never copied onto the Subnet, and is reported when the Shared Network was not imported.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.core.exceptions import ValidationError

from .. import kea_paths
from .dhcp_import_fields import GatedFieldMap, server_id_field
from .dhcp_import_report import Capability, Kind, Reason, not_written, unsupported
from .dhcp_import_summary import ImportSummary
from .dhcp_plugin_capabilities import PluginCapabilities


def is_unset(value) -> bool:
    """Return ``True`` for values treated as 'not configured' (None / empty str / empty list)."""
    return value is None or value == "" or value == []


@dataclass(frozen=True)
class Source:
    """The Kea object whose settings a field map reads, for the entry of a value that cannot be converted."""

    family: int
    kind: Kind
    path: str


def _not_converted(kea_key: str, error: Exception, summary: ImportSummary, source: Source) -> None:
    """Record a Kea value that the DHCP plugin field cannot hold."""
    path = kea_paths.setting(source.path, kea_key)
    detail = "The value cannot be converted to the DHCP plugin field."
    summary.record(not_written(source.family, source.kind, path, Reason.PLUGIN_GAP, detail))
    summary.warn(f"setting {kea_key}: {error}")


def cleared(obj, attr: str):
    """Return the value that clears field *attr* of *obj*: None when nullable, else the field's empty default."""
    db_field = obj._meta.get_field(attr)
    return None if db_field.null else db_field.get_default()


def settings_fields(obj, settings: dict, field_map, summary: ImportSummary, source: Source) -> dict:
    """Plan *obj*'s settings fields from its Declared Values. A key that *settings* lacks clears its field to inherit.

    A value that cannot be converted or that the plugin field refuses has an entry and leaves its field as it is.
    Return the desired fields without changing *obj*.
    """
    return {
        attr: declared_value(obj, attr, kea_key, settings[kea_key], transform, summary, source)
        if kea_key in settings
        else cleared(obj, attr)
        for kea_key, attr, transform in field_map
    }


def declared_value(obj, attr: str, kea_key: str, raw, transform, summary: ImportSummary, source: Source):
    """Return the value of field *attr* of *obj* for the Kea value *raw*. ``None`` clears the field.

    A value that *transform* cannot convert, or that the plugin field refuses, has an entry and keeps the current
    value of the field.
    """
    try:
        value = raw if transform is None else transform(raw)
    except Exception as exc:  # noqa: BLE001 — a bad scalar must not abort the import
        _not_converted(kea_key, exc, summary, source)
        return getattr(obj, attr)
    if value is None:
        return cleared(obj, attr)
    try:
        obj._meta.get_field(attr).clean(value, obj)
    except ValidationError as exc:
        _not_converted(kea_key, exc, summary, source)
        return getattr(obj, attr)
    return value


def _declares(raw, transform) -> bool:
    """Return whether the Kea value *raw* holds a value after *transform*. A value it cannot convert counts."""
    try:
        return not is_unset(raw if transform is None else transform(raw))
    except Exception:  # noqa: BLE001 (the value is reported, not converted)
        return True


def gated_values(
    obj, settings: dict, field_map: GatedFieldMap, capabilities: PluginCapabilities, summary, source: Source
) -> dict:
    """Plan the gated settings fields of *obj* as :func:`settings_fields` does, for each capability the plugin has.

    Without its capability a field is not planned, and a value that Kea declares for it is unsupported.
    """
    values: dict = {}
    for kea_key, attr, transform, capability in field_map:
        if capabilities.has(capability):
            values |= settings_fields(obj, settings, ((kea_key, attr, transform),), summary, source)
        elif kea_key in settings and _declares(settings[kea_key], transform):
            path = kea_paths.setting(source.path, kea_key)
            detail = f"The installed DHCP plugin cannot hold {kea_key}."
            summary.record(unsupported(source.family, source.kind, path, capability, detail))
    return values


def user_context_fields(
    obj, user_context: dict | None, capabilities: PluginCapabilities, summary, source: Source, holder: str
) -> dict:
    """Plan the ``user_context`` field of *obj*, or report a declared user-context as unsupported without it."""
    if capabilities.has(Capability.USER_CONTEXT):
        return {"user_context": user_context if user_context is not None else cleared(obj, "user_context")}
    if user_context is not None:
        path = kea_paths.setting(source.path, kea_paths.USER_CONTEXT)
        detail = f"The DHCP plugin has no user-context field on a {holder}."
        summary.record(unsupported(source.family, source.kind, path, Capability.USER_CONTEXT, detail))
    return {}


def server_id_values(raw, root: str, family: int, capabilities: PluginCapabilities, summary: ImportSummary) -> dict:
    """Return the ``server-id`` parameter fields of the DHCPServer; ``SERVER_FIELDS`` holds its type.

    Without the capability each parameter that Kea does not generate is unsupported.
    """
    server_id = raw if isinstance(raw, dict) else {}
    values = {}
    for key, generated in kea_paths.SERVER_ID_PARAMETERS.items():
        value = server_id.get(key, generated)
        declared = value != generated
        if capabilities.has(Capability.SERVER_ID_FIELDS):
            values[server_id_field(key)] = value if declared else None
        elif declared:
            path = kea_paths.setting(kea_paths.setting(root, kea_paths.SERVER_ID), key)
            detail = "The DHCP plugin keeps only the type of server-id."
            summary.record(unsupported(family, Kind.SERVER, path, Capability.SERVER_ID_FIELDS, detail))
    return values
