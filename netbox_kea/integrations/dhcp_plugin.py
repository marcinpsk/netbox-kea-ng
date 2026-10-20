# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Adapter to the optional NetBox DHCP plugin (``netbox_dhcp``, sys4).

This module applies the plans of :mod:`netbox_kea.integrations.dhcp_import_plan` to the DHCP plugin and
compares DHCP data. The mapping lifecycle module coordinates
its targets with native branching. Both modules resolve optional DHCP models lazily,
so netbox-kea imports cleanly when the DHCP plugin is absent. Call
:func:`is_available` before any other entry point. :func:`integration_refusal` is the
only rule that decides whether the integration runs for a Server.

v1 scope (import + diff, read-only against Kea):

* Imports the **data tier** of a Kea ``config-get`` into ``netbox_dhcp`` rows —
  ``DHCPServer``, ``Subnet``, ``Pool``, ``HostReservation`` — reusing netbox-kea's
  IPAM ownership claims so the DHCP-plugin rows **share** the same
  ``ipam.Prefix``/``IPRange``/``IPAddress`` and ``dcim.MACAddress`` objects the
  IPAM sync maintains.
* **One DHCPServer per Server and family** (Kea runs one daemon per family). It holds only its daemon's global
  configuration, maps to it, and links the interfaces that ``interfaces-config`` names.
* **Host reservations** come from the shared typed Reservation Snapshot. The
  adapter never parses raw ``reservation-get-page`` records. Valid records import
  even when the snapshot quarantines other records. A Global Reservation skips the
  IPAM sync, so the import creates no address rows for it and reports every reserved
  address it could not attach.  Delegated prefixes carry their own length, so they
  import as shared ``ipam.Prefix`` rows for every Scope.
* Each imported Subnet, Pool, Reservation, client class and custom Option Definition has a DHCP Import
  Mapping (:class:`netbox_kea.models.KeaDhcpLink`) to its Kea source, and a re-import finds the row
  through it, also after an operator renames the row. The first import after an upgrade maps each
  unmapped row that matches by structure. A Subnet without a Kea subnet ID, and its Pools, have no
  mapping identity and match by structure.
* A plugin Subnet holds Kea's subnet ID (:func:`settle_subnet_ids`). While the plugin keeps Subnet IDs
  unique across all servers, a Subnet whose ID another Server or family holds is reported as unsupported,
  with its Pools and In-Subnet Reservations.
* DHCP **options** (``option-data``) are imported at every scope we model —
  ``DHCPServer`` (global), ``Subnet``, ``Pool``, ``HostReservation`` — binding to
  the sys4-shipped standard ``OptionDefinition`` (by space+code), or to a
  server-scoped custom definition created from a Kea ``option-def``.  Options
  whose definition cannot be resolved are reported as unsupported, never fatal.
* **Tuning fields** (lifetimes, timers, lease/DDNS/BOOTP/network settings) are
  imported onto the ``DHCPServer`` (global), ``Subnet``, ``Pool`` (DDNS) and ``ClientClass``. A Subnet
  or client class gets only its Declared Values (:func:`.dhcp_import_plan.declared_values`),
  and every other field is cleared to inherit. A value that a member Subnet inherits
  from its Shared Network is reported, never copied onto the Subnet.
* **Ownership.** Every writer sets exactly the managed fields of :mod:`.dhcp_import_fields` on a mapped row, and
  :func:`_managed_changes` refuses a write that names another set. Unmanaged fields and unmapped rows stay.
* **Client classes** (``client-classes``) are imported as ``ClientClass`` rows
  (test/template-test, additional-list flag, BOOTP + lifetime settings, options) with
  their Kea name. While the plugin keeps class names unique across all servers, a class
  whose name another row holds is reported as unsupported (:mod:`.dhcp_plugin_capabilities`).
* **Deferred** (reported, not imported): shared-network grouping (the plugin's
  ``SharedNetwork`` requires a prefix Kea does not model — member subnets are
  flattened onto the ``DHCPServer``).
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass, field
from itertools import count
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..ipam_reconciliation import ClaimResult, RangeClaim, ReservationObservation, SyncReport
    from ..models import DhcpIntegrationConfig, Server
    from ..subnet_catalogue import CatalogueSnapshot
    from .dhcp_import_plan import (
        FamilyPlan,
        Planned,
        PlannedClientClass,
        PlannedServer,
        PlannedSubnet,
        PoolKey,
        ReservationKey,
    )

from django.apps import apps
from django.core.exceptions import ValidationError
from django.db.models.signals import post_delete

from .. import event_scope, kea_paths
from ..constants import IPNetworkValue
from ..dhcp_mapping_lifecycle import coordinated_import, mapped_target, observe_mapping, target_models
from ..dhcp_options import DHCPOption, option_identity
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import OptionDefIntent, ServerConfigIntent
from ..published_name import reservation_published_name
from ..reservations import FLEX_ID, TRAVERSAL_DIAGNOSTIC_CODES, InSubnetReservationScope, Reservation, identity_text
from ..subnet_catalogue import CatalogueUnavailable
from .dhcp_import_fields import (
    CLIENT_CLASS_FIELDS,
    GATED_SERVER_FIELDS,
    POOL_FIELDS,
    SERVER_FIELDS,
    SUBNET_FIELDS,
    managed_fields,
    server_id_field,
)
from .dhcp_import_plan import (
    MAX_KEA_NAME_LENGTH,
    InSubnetReservationKey,
    MappingSource,
    OptionDefinitionKey,
    keyed_reservations,
    plan_family,
)
from .dhcp_import_report import (
    Capability,
    ImportEntry,
    Kind,
    Outcome,
    Reason,
    not_written,
    subnet_id_clash,
    unsupported,
    written,
)
from .dhcp_plugin_capabilities import PLUGIN_APP_LABEL, PluginCapabilities, probe

logger = logging.getLogger(__name__)


def is_available() -> bool:
    """Return ``True`` when the optional NetBox DHCP plugin is installed."""
    return apps.is_installed(PLUGIN_APP_LABEL)


def integration_refusal(server: Server, switch: DhcpIntegrationConfig | None = None) -> str:
    """Return why the DHCP plugin integration does not run for *server*, or "" when it runs (ADR 0010).

    A caller that checks many Servers passes the *switch* row that it read once.
    """
    from ..models import DhcpIntegrationConfig

    if not is_available():
        return "The NetBox DHCP plugin (netbox_dhcp) is not installed."
    if not server.sync_dhcp_plugin_enabled:
        return "Enable 'Sync to DHCP plugin' on this server first."
    # Read last, so that a Server that opts out costs no query.
    if not (switch or DhcpIntegrationConfig.get()).enabled:
        return "The DHCP plugin integration is off for all Servers. Turn it on in DHCP Kea > Settings."
    return ""


def runs_for(server: Server, switch: DhcpIntegrationConfig | None = None) -> bool:
    """Return whether the DHCP plugin integration runs for *server*."""
    return not integration_refusal(server, switch)


def register_link_cleanup() -> None:
    """Remove mappings in the same database as a deleted supported DHCP target."""
    if not is_available():
        return
    for model in target_models():
        post_delete.connect(
            _delete_target_links,
            sender=model,
            dispatch_uid=f"netbox_kea.dhcp_target_links.{model._meta.label}",
        )


def _delete_target_links(sender, instance, using: str, **kwargs) -> None:
    from django.contrib.contenttypes.models import ContentType

    content_type = ContentType.objects.db_manager(using).get_for_model(sender)
    _link_model().objects.using(using).filter(object_type_id=content_type.pk, object_id=instance.pk).delete()


def _ownership_report() -> SyncReport:
    from ..ipam_reconciliation import SyncReport

    return SyncReport()


class ManagedFieldsMismatch(RuntimeError):
    """A writer's fields are not the managed fields of its model: a programming error that fails the run."""


def write_failed(family: int, kind: Kind, path: str) -> ImportEntry:
    """Return the entry of a fact whose write failed. The log holds the error."""
    return not_written(family, kind, path, Reason.WRITE_FAILED, "See server logs.")


def _skip_options(summary: ImportSummary, family: int, parent_path: str, options) -> None:
    """Record each DHCP Option of an object that was not imported."""
    for opt in options:
        summary.record(
            not_written(family, Kind.OPTION, kea_paths.option(parent_path, opt, family), Reason.PARENT_NOT_IMPORTED)
        )


class _Count:
    """A read-only count of the entries of one kind whose outcome or reason is one of the given values."""

    def __init__(self, kind: Kind, *matches: Outcome | Reason) -> None:
        self.kind = kind
        self.matches = matches

    def __get__(self, summary: ImportSummary | None, owner: type) -> int:
        return summary.count(self.kind, *self.matches) if summary is not None else 0


@dataclass
class ImportSummary:
    """The entries, IPAM ownership outcomes and warnings of one ``(server, family)`` import.

    Every DHCP fact count is a count of :attr:`entries`, so nothing is counted without an entry.
    """

    ownership: SyncReport = field(default_factory=_ownership_report)
    entries: list[ImportEntry] = field(default_factory=list)
    foreign_addresses_skipped: int = 0
    owner_disagreements: int = 0
    # Reserved addresses with no NetBox IP to attach. A Global Reservation has no
    # Subnet to size an address from, so the import never creates one for it.
    addresses_unattached: int = 0
    # IPAM reconciliation errors of the delegated-prefix phase; DHCP write failures are entries.
    ownership_errors: int = 0
    warnings: list[str] = field(default_factory=list)

    subnets_created = _Count(Kind.SUBNET, Outcome.CREATED)
    subnets_updated = _Count(Kind.SUBNET, Outcome.UPDATED)
    pools_created = _Count(Kind.POOL, Outcome.CREATED)
    reservations_created = _Count(Kind.RESERVATION, Outcome.CREATED)
    reservations_updated = _Count(Kind.RESERVATION, Outcome.UPDATED)
    reservations_quarantined = _Count(Kind.RESERVATION, Reason.INVALID_KEA_DATA)
    reservations_skipped = _Count(Kind.RESERVATION, Reason.PARENT_NOT_IMPORTED)
    options_created = _Count(Kind.OPTION, Outcome.CREATED)
    options_updated = _Count(Kind.OPTION, Outcome.UPDATED)
    options_skipped = _Count(Kind.OPTION, Outcome.UNSUPPORTED, Outcome.SKIPPED, Outcome.NOT_IMPORTED)
    option_defs_created = _Count(Kind.OPTION_DEFINITION, Outcome.CREATED)
    client_classes_created = _Count(Kind.CLIENT_CLASS, Outcome.CREATED)
    client_classes_updated = _Count(Kind.CLIENT_CLASS, Outcome.UPDATED)
    shared_networks_not_imported = _Count(Kind.SHARED_NETWORK, Outcome.NOT_IMPORTED)

    def record(self, entry: ImportEntry) -> None:
        """Add the entry of one Kea fact."""
        self.entries.append(entry)

    def count(self, kind: Kind, *matches: Outcome | Reason) -> int:
        """Return the number of entries of *kind* whose outcome or reason is one of *matches*."""
        return sum(
            entry.kind == kind and (entry.outcome in matches or entry.reason in matches) for entry in self.entries
        )

    @property
    def reservations_unread(self) -> bool:
        """Return whether the Reservation Snapshot could not be read in full."""
        return self.count(Kind.RESERVATION, Reason.READ_FAILED) > 0

    @property
    def errors(self) -> int:
        """Return the failed object writes and IPAM reconciliation errors. A failed Option counts as skipped."""
        failed = (
            entry.reason == Reason.WRITE_FAILED and entry.kind not in (Kind.OPTION, Kind.OPTION_DEFINITION)
            for entry in self.entries
        )
        return sum(failed) + self.ownership_errors

    def warn(self, message: str) -> None:
        """Record a non-fatal warning and log it."""
        self.warnings.append(message)
        logger.warning("DHCP-plugin import: %s", message)


# ─────────────────────────────────────────────────────────────────────────────
# Lazy model access
# ─────────────────────────────────────────────────────────────────────────────


def _model(name: str):
    """Return a ``netbox_dhcp`` model class by name (lazy; plugin must be installed)."""
    return apps.get_model(PLUGIN_APP_LABEL, name)


def _link_model():
    from ..models import KeaDhcpLink

    return KeaDhcpLink


# ─────────────────────────────────────────────────────────────────────────────
# IPAM / DCIM resolution (reuse netbox-kea sync helpers — share the same rows)
# ─────────────────────────────────────────────────────────────────────────────


def _reservation_addresses(
    reservation: Reservation, claims: ClaimResult, catalogue: CatalogueSnapshot, summary: ImportSummary
):
    """Attach the address objects returned by the whole-snapshot ownership claim."""
    ipv4_ip = None
    ipv6_ips = []
    unattached = []
    for address in reservation.addresses:
        result = claims.addresses[str(address)]
        if result.outcome == "error":
            raise RuntimeError("The reserved address could not be claimed")
        if result.outcome == "conflict":
            summary.foreign_addresses_skipped += 1
            summary.warn(
                f"reservation {reservation.identity.value}: manually curated NetBox IP {address} left unchanged"
            )
        elif result.outcome == "disagreement":
            summary.warn(f"reservation {reservation.identity.value}: owner disagreement for {address}; IPAM unchanged")
        if result.ip is None:
            unattached.append(str(address))
        elif address.version == 4:
            ipv4_ip = result.ip
        else:
            ipv6_ips.append(result.ip)
    if unattached:
        summary.addresses_unattached += len(unattached)
        summary.warn(
            f"reservation {reservation.identity.value}: reserved address(es) "
            f"{', '.join(unattached)} have no NetBox IP and were not attached"
        )
    hardware = reservation.identity.hardware_address
    mac_obj = None
    if hardware:
        try:
            hostname = reservation_published_name(reservation, catalogue)
        except CatalogueUnavailable:
            # The MAC description gets no name that the plugin cannot know; the DHCP row needs only the MAC.
            hostname = ""
        for address in reservation.addresses:
            mac_obj = claims.addresses[str(address)].resolved_macs.get((hardware, hostname))
            if mac_obj is not None:
                break
        if mac_obj is None:
            mac_obj = _resolve_mac(hardware, hostname)
    return ipv4_ip, ipv6_ips, mac_obj


def _resolve_mac(hw_address: str | None, hostname: str = ""):
    """Return the ``dcim.MACAddress`` row for *hw_address*, creating it when absent.

    Address claims return their resolved MAC rows. Global, addressless and curated
    Reservations can have no such result, so they resolve the DHCP identifier here.
    """
    if not hw_address:
        return None
    from ..sync import sync_mac_address

    return sync_mac_address(hw_address, hostname)


# ─────────────────────────────────────────────────────────────────────────────
# DHCP options (option-data → Option, binding to standard/custom OptionDefinition)
# ─────────────────────────────────────────────────────────────────────────────


def _send_option(opt: DHCPOption) -> str | None:
    """Map Kea ``always-send``/``never-send`` flags to the plugin's single choice."""
    if opt.always_send:
        return "always-send"
    if opt.never_send:
        return "never-send"
    return None


@dataclass
class CustomDefinitions:
    """The custom Option Definitions that one family of a Server declares, each written at most once a run."""

    server: Server
    declared: dict[OptionDefinitionKey, OptionDefIntent]
    # The DHCPServers whose unmapped rows of this family the import adopts (_adoption_servers).
    adoption_servers: tuple[int, ...]
    # The row of each written definition, or why it has none.
    written: dict[OptionDefinitionKey, object] = field(default_factory=dict)


@dataclass(frozen=True)
class _Unresolved:
    """Why an Option has no Option Definition: the reason and the detail of its entry."""

    reason: Reason
    detail: str


_NO_DEFINITION = _Unresolved(Reason.PLUGIN_GAP, "No matching Option Definition.")
_DEFINITION_NOT_WRITTEN = _Unresolved(Reason.PARENT_NOT_IMPORTED, "See server logs.")


def _option_definition_fields(def_intent: OptionDefIntent, family: int, dhcp_server) -> dict:
    """Return the managed fields of a custom Option Definition: all but its name, which stays as created or renamed."""
    return {
        "space": def_intent.space,
        "code": def_intent.code,
        "family": family,
        "type": def_intent.type,
        "array": def_intent.array,
        "record_types": list(def_intent.record_types) or None,
        "encapsulate": def_intent.encapsulate,
        "dhcp_server_id": dhcp_server.pk,
        # The plugin refuses a definition with both parents.
        "client_class_id": None,
    }


def _held_option_definition(held, family: int, key: OptionDefinitionKey, path: str, summary: ImportSummary):
    """Report a definition that another mapping holds on this DHCPServer, which the plugin cannot hold twice."""
    from django.contrib.contenttypes.models import ContentType

    holder = (
        _link_model()
        .objects.filter(object_type=ContentType.objects.get_for_model(held.model), object_id__in=held.values("pk"))
        .first()
    )
    limit = "The DHCP plugin holds one custom Option Definition for each space and code of a DHCP server"
    holder_text = f"the DHCPv{holder.family} import holds it" if holder is not None else "another row holds it"
    detail = f"{limit}, and {holder_text}."
    summary.record(not_written(family, Kind.OPTION_DEFINITION, path, Reason.PLUGIN_GAP, detail))
    summary.warn(f"option-def {key.space}:{key.code}: {detail}")
    return _Unresolved(Reason.PLUGIN_GAP, f"Option Definition {key.space}:{key.code} is not imported. {limit}.")


def _write_option_definition(
    definitions: CustomDefinitions,
    key: OptionDefinitionKey,
    family: int,
    dhcp_server,
    summary: ImportSummary,
    capabilities: PluginCapabilities,
):
    """Write the custom Option Definition of *key* through its mapping. Return the row, or why it has none."""
    OptionDefinition = _model("OptionDefinition")
    def_intent = definitions.declared[key]
    path = kea_paths.option_definition(family, key.space, key.code)
    fields = _option_definition_fields(def_intent, family, dhcp_server)
    outcome = None
    try:
        with event_scope.atomic():
            obj = mapped_target(definitions.server, family, key.source)
            if obj is None:
                same_key = OptionDefinition.objects.filter(standard=False, space=key.space, code=key.code)
                # Adopt a definition that an import created before Option Definitions had a mapping.
                adoptable = same_key.filter(dhcp_server__in=definitions.adoption_servers, family=family)
                obj = _unlinked(adoptable).first()
                held = same_key.filter(dhcp_server=dhcp_server)
                if obj is None and held.exists():
                    return _held_option_definition(held, family, key, path, summary)
            if obj is None:
                obj = OptionDefinition(name=def_intent.name, standard=False)
                _create_row(obj, fields, capabilities)
                outcome = Outcome.CREATED
            else:
                changes = _managed_changes(obj, fields, capabilities)
                if changes:
                    _save_changes(obj, changes)
                    outcome = Outcome.UPDATED
            observe_mapping(definitions.server, family, obj, key.source)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001 — a bad definition must not abort the import
        summary.record(write_failed(family, Kind.OPTION_DEFINITION, path))
        summary.warn(f"option-def code={key.code}: {exc}")
        return _DEFINITION_NOT_WRITTEN
    if outcome is not None:
        summary.record(written(family, Kind.OPTION_DEFINITION, path, outcome))
    return obj


def _resolve_option_definition(
    opt: DHCPOption, family: int, dhcp_server, definitions: CustomDefinitions, summary, capabilities: PluginCapabilities
):
    """Find (or write) the ``OptionDefinition`` a Kea ``option-data`` entry refers to.

    Prefers the sys4-shipped **standard** definition (by space+code, else space+name). Then a custom definition
    that this family declares in ``option-def``, written through its mapping. Then another custom definition of
    the DHCPServer. Returns why the option has no definition when it cannot be resolved: the DHCP plugin has
    none, or the custom definition could not be written.
    """
    OptionDefinition = _model("OptionDefinition")
    space = opt.space or kea_paths.default_space(family)

    standard = OptionDefinition.objects.filter(standard=True, space=space)
    if opt.code is not None:
        found = standard.filter(code=opt.code).first()
    elif opt.name:
        found = standard.filter(name=opt.name).first()
    else:
        found = None
    if found is not None:
        return found

    key: OptionDefinitionKey | None
    if opt.code is not None:
        key = OptionDefinitionKey(space, opt.code)
    else:
        declared = definitions.declared.items()
        key = next((each for each, intent in declared if each.space == space and intent.name == opt.name), None)
    if key is not None and key in definitions.declared:
        if key not in definitions.written:
            definitions.written[key] = _write_option_definition(
                definitions, key, family, dhcp_server, summary, capabilities
            )
        return definitions.written[key]

    custom = OptionDefinition.objects.filter(standard=False, dhcp_server=dhcp_server, space=space)
    if opt.code is not None:
        found = custom.filter(code=opt.code).first()
    elif opt.name:
        found = custom.filter(name=opt.name).first()
    return found if found is not None else _NO_DEFINITION


def _option_values(candidate, opt: DHCPOption) -> dict:
    """Return the managed fields of an Option as the DHCP plugin stores them, after ``Option.clean`` on *candidate*.

    The plugin's clean step normalizes some values, for example the CSV format of a binary option.
    """
    candidate.data = opt.data or ""
    candidate.csv_format = opt.csv_format
    candidate.send_option = _send_option(opt)
    candidate.clean()
    return {"data": candidate.data, "csv_format": candidate.csv_format, "send_option": candidate.send_option}


def upsert_options(
    parent_obj,
    options,
    family: int,
    dhcp_server,
    custom_defs: CustomDefinitions,
    summary: ImportSummary,
    parent_path: str,
    capabilities: PluginCapabilities,
) -> None:
    """Upsert DHCP-plugin ``Option`` rows for *options* assigned to *parent_obj*, the Kea object at *parent_path*.

    Idempotent: one Option per ``(parent, definition)``. An Option whose definition cannot be resolved, or whose
    data the plugin refuses, is reported and does not stop the import. An Option whose values did not change has
    no entry.
    """
    if not options:
        return
    from django.contrib.contenttypes.models import ContentType

    Option = _model("Option")
    ct = ContentType.objects.get_for_model(type(parent_obj))
    for opt in options:
        path = kea_paths.option(parent_path, opt, family)
        definition = _resolve_option_definition(opt, family, dhcp_server, custom_defs, summary, capabilities)
        if isinstance(definition, _Unresolved):
            summary.record(not_written(family, Kind.OPTION, path, definition.reason, definition.detail))
            summary.warn(f"option {option_identity(opt, family)}: no matching definition, skipped")
            continue
        outcome = None
        try:
            with event_scope.atomic():
                new = Option(definition=definition, assigned_object_type=ct, assigned_object_id=parent_obj.pk)
                desired = _option_values(new, opt)
                obj = Option.objects.filter(
                    assigned_object_type=ct, assigned_object_id=parent_obj.pk, definition=definition
                ).first()
                if obj is None:
                    _create_row(new, desired, capabilities)
                    outcome = Outcome.CREATED
                elif changes := _managed_changes(obj, desired, capabilities):
                    _save_changes(obj, changes)
                    outcome = Outcome.UPDATED
            if outcome is not None:
                summary.record(written(family, Kind.OPTION, path, outcome))
        except event_scope.EventDispatchError:
            raise
        except ManagedFieldsMismatch:
            raise
        except Exception as exc:  # noqa: BLE001 — one bad option must not abort the import
            summary.record(write_failed(family, Kind.OPTION, path))
            summary.warn(f"option {option_identity(opt, family)}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Managed fields (dhcp_import_fields): Kea owns them on a mapped row
# ─────────────────────────────────────────────────────────────────────────────


def _is_unset(value) -> bool:
    """Return ``True`` for values treated as 'not configured' (None / empty str / empty list)."""
    return value is None or value == "" or value == []


@dataclass(frozen=True)
class _Source:
    """The Kea object whose settings a field map reads, for the entry of a value that cannot be converted."""

    family: int
    kind: Kind
    path: str


def _not_converted(kea_key: str, error: Exception, summary: ImportSummary, source: _Source) -> None:
    """Record a Kea value that the DHCP plugin field cannot hold."""
    path = kea_paths.setting(source.path, kea_key)
    detail = "The value cannot be converted to the DHCP plugin field."
    summary.record(not_written(source.family, source.kind, path, Reason.PLUGIN_GAP, detail))
    summary.warn(f"setting {kea_key}: {error}")


def _cleared(obj, attr: str):
    """Return the value that clears field *attr* of *obj*: None when nullable, else the field's empty default."""
    db_field = obj._meta.get_field(attr)
    return None if db_field.null else db_field.get_default()


def _settings_fields(obj, settings: dict, field_map, summary: ImportSummary, source: _Source) -> dict:
    """Plan *obj*'s settings fields from its Declared Values. A key that *settings* lacks clears its field to inherit.

    A value that cannot be converted or that the plugin field refuses has an entry and leaves its field as it is.
    Return the desired fields without changing *obj*.
    """
    return {
        attr: _declared_value(obj, attr, kea_key, settings[kea_key], transform, summary, source)
        if kea_key in settings
        else _cleared(obj, attr)
        for kea_key, attr, transform in field_map
    }


def _declared_value(obj, attr: str, kea_key: str, raw, transform, summary: ImportSummary, source: _Source):
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
        return _cleared(obj, attr)
    try:
        obj._meta.get_field(attr).clean(value, obj)
    except ValidationError as exc:
        _not_converted(kea_key, exc, summary, source)
        return getattr(obj, attr)
    return value


def _managed_changes(obj, desired: dict, capabilities: PluginCapabilities) -> dict:
    """Return the managed fields of obj whose value differs from desired.

    *desired* must name each scalar managed field of the model that the installed plugin has, by field name or by
    the column name of a foreign key. Relations are not checked here.
    """
    model = type(obj).__name__
    named = {obj._meta.get_field(key).name for key in desired}
    expected = {field.name for field in managed_fields(model, capabilities) if not field.relation}
    if named != expected or len(named) != len(desired):
        raise ManagedFieldsMismatch(
            f"The {model} write does not match its managed fields: "
            f"missing {sorted(expected - named)}, unexpected {sorted(named - expected)}"
        )
    return {key: value for key, value in desired.items() if getattr(obj, key) != value}


def _create_row(obj, desired: dict, capabilities: PluginCapabilities) -> None:
    """Set the managed fields of the new row *obj* to *desired* and save it."""
    for name, value in _managed_changes(obj, desired, capabilities).items():
        setattr(obj, name, value)
    obj.save()


def _save_changes(obj, changes: dict) -> None:
    """Write *changes* to the loaded row *obj* after its change-log snapshot."""
    obj.snapshot()
    for name, value in changes.items():
        setattr(obj, name, value)
    obj.save()


def _relation_changes(obj, desired: dict[str, set[int]]) -> dict[str, set[int]]:
    """Return the many-to-many relations of *obj* whose rows differ from *desired*. A new row has no rows yet."""
    if obj.pk is None:
        return {name: pks for name, pks in desired.items() if pks}
    return {name: pks for name, pks in desired.items() if set(getattr(obj, name).values_list("pk", flat=True)) != pks}


# ─────────────────────────────────────────────────────────────────────────────
# Upserts
# ─────────────────────────────────────────────────────────────────────────────


def _server_id_values(raw, root: str, family: int, capabilities: PluginCapabilities, summary: ImportSummary) -> dict:
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


def _identifier_values(
    identifiers: tuple[str, ...], root: str, family: int, capabilities: PluginCapabilities, summary: ImportSummary
) -> list[str] | None:
    """Keep the Reservation identifier types that the DHCP plugin can hold; flex-id needs its capability."""
    field = _model("DHCPServer")._meta.get_field("host_reservation_identifiers")
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
    root = kea_paths.daemon(family)
    source = _Source(family, Kind.SERVER, root)
    values = _settings_fields(dhcp_server, settings, SERVER_FIELDS, summary, source)
    values |= _server_id_values(settings.get(kea_paths.SERVER_ID), root, family, capabilities, summary)
    if planned.host_reservation_identifiers is not None:
        values["host_reservation_identifiers"] = _identifier_values(
            planned.host_reservation_identifiers, root, family, capabilities, summary
        )
    if capabilities.has(Capability.SERVER_FAMILY):
        values["family"] = family
    else:
        detail = "The DHCP plugin has no address family on a DHCP server."
        summary.record(unsupported(family, Kind.SERVER, root, Capability.SERVER_FAMILY, detail))
    if capabilities.has(Capability.USER_CONTEXT):
        values["user_context"] = planned.user_context
    elif planned.user_context is not None:
        path = kea_paths.setting(root, kea_paths.USER_CONTEXT)
        detail = "The DHCP plugin has no user-context field on a DHCP server."
        summary.record(unsupported(family, Kind.SERVER, path, Capability.USER_CONTEXT, detail))
    for kea_key, attr, capability in GATED_SERVER_FIELDS:
        if capabilities.has(capability):
            values[attr] = settings.get(kea_key)
        elif kea_key in settings:
            detail = f"The DHCP plugin has no {kea_key} field."
            summary.record(unsupported(family, Kind.SERVER, kea_paths.setting(root, kea_key), capability, detail))
    return values


def _apply_global_settings(
    dhcp_server, values: dict, summary: ImportSummary, family: int, capabilities: PluginCapabilities
) -> bool | None:
    """Make the managed fields of *dhcp_server* equal *values*, clearing each ``None`` (or unset) value.

    Each family has its own DHCPServer, so this family's configuration owns every managed field of it.
    Return whether a changed value was saved, or ``None`` after a failed save. The failure is recorded here.
    """
    desired = {attr: _cleared(dhcp_server, attr) if _is_unset(value) else value for attr, value in values.items()}
    # A Kea list that is not valid leaves the identifier types as they are.
    desired.setdefault("host_reservation_identifiers", dhcp_server.host_reservation_identifiers)
    changed: dict = {}
    try:
        changed = _managed_changes(dhcp_server, desired, capabilities)
        if not changed:
            return False
        with event_scope.atomic():
            _save_changes(dhcp_server, changed)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001
        summary.record(write_failed(family, Kind.SERVER, kea_paths.daemon(family)))
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


def _link_interfaces(dhcp_server, entries: tuple[str, ...] | None, summary: ImportSummary, family: int) -> bool:
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
            detail = f"The DHCP server's device or virtual machine has no interface {name}."
            path = kea_paths.interface(family, entry)
            summary.record(not_written(family, Kind.SERVER, path, Reason.NO_MATCHING_INTERFACE, detail))
    if "*" in entries:
        # The DHCP plugin cannot hold "every interface", so the links that an operator made stay.
        return False
    relations = _relation_changes(dhcp_server, wanted)
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


def _adoption_servers(server, dhcp_server) -> tuple[int, ...]:
    """Return *dhcp_server* and the DHCPServer that an import before #94 named after the Server, for both families.

    A DHCPServer that another Server maps is not that row, even when its name matches.
    """
    from django.contrib.contenttypes.models import ContentType

    DHCPServer = _model("DHCPServer")
    mapped_elsewhere = (
        _link_model()
        .objects.filter(object_type=ContentType.objects.get_for_model(DHCPServer))
        .exclude(server=server)
        .values("object_id")
    )
    legacy = DHCPServer.objects.filter(name=server.name).exclude(pk=dhcp_server.pk).exclude(pk__in=mapped_elsewhere)
    return (dhcp_server.pk, *legacy.values_list("pk", flat=True))


def _move_family_options(dhcp_server, adoption_servers: tuple[int, ...], family: int) -> None:
    """Move the global Options of *family* that an import before #94 wrote on the DHCPServer of both families."""
    from django.contrib.contenttypes.models import ContentType

    stale = _model("Option").objects.filter(
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
    DHCPServer = _model("DHCPServer")
    source = MappingSource.server()
    created = False
    with event_scope.atomic():
        dhcp_server = mapped_target(server, family, source)
        if dhcp_server is None and family == _primary_family(server):
            dhcp_server = _unlinked(DHCPServer.objects.filter(name=server.name)).first()
        if dhcp_server is None:
            other = mapped_target(server, _other_family(family), source)
            dhcp_server = DHCPServer(
                name=_synthesized_name(server.name, f" DHCPv{family}"),
                description="Imported from Kea by netbox-kea",
                device_id=other.device_id if other is not None else None,
                virtual_machine_id=other.virtual_machine_id if other is not None else None,
            )
            dhcp_server.save()
            created = True
            _move_family_options(dhcp_server, _adoption_servers(server, dhcp_server), family)
        observe_mapping(server, family, dhcp_server, source)
    return dhcp_server, created


_NAME_DIGEST_LENGTH = 12


def _synthesized_name(scope: str, detail: str) -> str:
    """Return a DHCP plugin row name. A name too long for the plugin ends with a hash of all of it, to stay distinct."""
    name = f"{scope}{detail}"
    if len(name) <= MAX_KEA_NAME_LENGTH:
        return name
    digest = hashlib.sha256(name.encode()).hexdigest()[:_NAME_DIGEST_LENGTH]
    return f"{name[: MAX_KEA_NAME_LENGTH - _NAME_DIGEST_LENGTH - 1]}~{digest}"


def _released_client_class_name(server, kea_name: str) -> str:
    """Return the name that the released importer gave a Kea class, before a class had a mapping."""
    return f"{server.name}: {kea_name}"[:255]


def _client_class_fields(
    obj,
    dhcp_server,
    planned: PlannedClientClass,
    summary: ImportSummary,
    path: str,
    capabilities: PluginCapabilities,
    name_taken: bool,
) -> dict:
    """Plan the managed fields of one Client Class. A class whose Kea name is taken keeps its name."""
    intent = planned.intent
    fields = {
        "name": obj.name if name_taken else planned.key,
        "dhcp_server_id": dhcp_server.pk,
        "test": intent.test or "",
        "template_test": intent.template_test or "",
        "only_in_additional_list": intent.only_in_additional_list,
    }
    if capabilities.has(Capability.USER_CONTEXT):
        fields["user_context"] = (
            intent.user_context if intent.user_context is not None else _cleared(obj, "user_context")
        )
    elif intent.user_context is not None:
        detail = "The DHCP plugin has no user-context field on a client class."
        summary.record(
            unsupported(
                intent.family,
                Kind.CLIENT_CLASS,
                kea_paths.setting(path, kea_paths.USER_CONTEXT),
                Capability.USER_CONTEXT,
                detail,
            )
        )
    source = _Source(intent.family, Kind.CLIENT_CLASS, path)
    fields.update(_settings_fields(obj, planned.settings, CLIENT_CLASS_FIELDS, summary, source))
    return fields


def _class_name_taken(name: str, obj, dhcp_server, capabilities: PluginCapabilities) -> bool:
    """Return whether another client class holds *name* in the scope where the DHCP plugin keeps class names unique."""
    others = _model("ClientClass").objects.filter(name=name)
    if capabilities.has(Capability.NAME_PER_SERVER):
        others = others.filter(dhcp_server=dhcp_server)
    return (others.exclude(pk=obj.pk) if obj is not None else others).exists()


def _record_name_taken(
    summary: ImportSummary, family: int, path: str, name: str, capabilities: PluginCapabilities
) -> None:
    if capabilities.has(Capability.NAME_PER_SERVER):
        detail = f"Another client class of this DHCP server holds the name {name!r}."
        entry = not_written(family, Kind.CLIENT_CLASS, path, Reason.NOT_IN_SCOPE, detail)
    else:
        detail = (
            f"Another client class holds the name {name!r}. "
            "The DHCP plugin needs each client class name to be unique across all DHCP servers."
        )
        entry = unsupported(family, Kind.CLIENT_CLASS, path, Capability.NAME_PER_SERVER, detail)
    summary.record(entry)
    summary.warn(f"client-class {name}: {detail}")


def upsert_client_class(
    server,
    dhcp_server,
    planned: PlannedClientClass,
    custom_defs: CustomDefinitions,
    summary: ImportSummary,
    capabilities: PluginCapabilities,
):
    """Get/create the DHCP-plugin ``ClientClass`` for *planned* through its mapping. The row takes the Kea name."""
    ClientClass = _model("ClientClass")
    intent = planned.intent
    path = kea_paths.client_class(intent.family, planned.key)
    source = MappingSource.named(Kind.CLIENT_CLASS, planned.key)
    outcome = None
    try:
        with event_scope.atomic():
            obj = mapped_target(server, intent.family, source)
            if obj is None:
                # Adopt a row that the released importer created before client classes had a mapping.
                released = ClientClass.objects.filter(name=_released_client_class_name(server, planned.key))
                obj = _unlinked(released).first()
            name_taken = _class_name_taken(planned.key, obj, dhcp_server, capabilities)
            if obj is None and name_taken:
                _record_name_taken(summary, intent.family, path, planned.key, capabilities)
                _skip_options(summary, intent.family, path, intent.options)
                return None
            if obj is None:
                obj = ClientClass()
                fields = _client_class_fields(obj, dhcp_server, planned, summary, path, capabilities, name_taken=False)
                _create_row(obj, fields, capabilities)
                outcome = Outcome.CREATED
            else:
                fields = _client_class_fields(obj, dhcp_server, planned, summary, path, capabilities, name_taken)
                if changes := _managed_changes(obj, fields, capabilities):
                    _save_changes(obj, changes)
                    outcome = Outcome.UPDATED
            observe_mapping(server, intent.family, obj, source)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001 — one bad class must not abort the import
        summary.record(write_failed(intent.family, Kind.CLIENT_CLASS, path))
        summary.warn(f"client-class {intent.name}: {exc}")
        _skip_options(summary, intent.family, path, intent.options)
        return None

    if name_taken:
        _record_name_taken(summary, intent.family, kea_paths.setting(path, "name"), planned.key, capabilities)
    if outcome is not None:
        summary.record(written(intent.family, Kind.CLIENT_CLASS, path, outcome))
    upsert_options(obj, intent.options, intent.family, dhcp_server, custom_defs, summary, path, capabilities)
    return obj


def _subnet_name(server, planned: PlannedSubnet, network: IPNetworkValue) -> str:
    """Build a globally-unique name (NetBoxDHCPModelMixin requires unique ``name``)."""
    family = planned.intent.family
    if planned.key is not None:
        return _synthesized_name(server.name, f" DHCPv{family} subnet {planned.key}")
    return _synthesized_name(server.name, f" DHCPv{family} {network}")


def _pool_name(subnet_obj, pool_intent) -> str:
    """Build a unique pool name scoped to its parent subnet's (unique) name."""
    return _synthesized_name(subnet_obj.name, f" pool {pool_intent.pool}")


def _reservation_name(scope_name: str, reservation: Reservation) -> str:
    """Build a unique reservation name scoped to its parent's (unique) name."""
    identity = reservation.identity
    return _synthesized_name(scope_name, f" {identity_text(identity.identifier_type, identity.value)}")


def upsert_subnet(
    server,
    dhcp_server,
    planned: PlannedSubnet,
    summary: ImportSummary,
    claims: ClaimResult,
    renumbered: bool,
    capabilities: PluginCapabilities,
):
    """Get/create the DHCP-plugin ``Subnet`` for *planned*, tracked via ``KeaDhcpLink`` by its key.

    *renumbered* tells that :func:`settle_subnet_ids` gave the mapped row its Kea subnet ID in this run.
    Returns the ``netbox_dhcp.Subnet`` instance, or ``None`` on error.
    """
    Subnet = _model("Subnet")
    intent = planned.intent
    path = subnet_path(planned)
    source = _Source(intent.family, Kind.SUBNET, path)
    mapping = MappingSource.subnet(planned.key) if planned.key is not None else None

    existing = mapped_target(server, intent.family, mapping) if mapping is not None else None

    changed = False
    try:
        with event_scope.atomic():
            # Inside the try so one bad CIDR is counted as a per-subnet error, not fatal.
            network = subnet_network(intent.cidr, intent.family)
            result = claims.prefixes[str(network)]
            if result.prefix is None:
                raise RuntimeError("The Subnet Prefix could not be claimed")
            prefix_obj = result.prefix
            if result.outcome in {"conflict", "disagreement"}:
                summary.warn(f"subnet {network}: IPAM ownership {result.outcome}, Prefix left unchanged")
            if mapping is None:
                # A Subnet without a Kea subnet ID has no mapping identity. An unmapped Subnet stays as it is.
                unmapped = _unlinked(Subnet.objects.filter(dhcp_server=dhcp_server, prefix=prefix_obj)).first()
                if unmapped is not None:
                    return unmapped
            subnet_obj = existing if existing is not None else Subnet(name=_subnet_name(server, planned, network))
            fields = {
                "prefix_id": prefix_obj.pk,
                "dhcp_server_id": dhcp_server.pk,
                "shared_network_id": None,
                # settle_subnet_ids gave a mapped row its Kea subnet ID. Without one, the plugin numbers a new Subnet.
                "subnet_id": planned.key if planned.key is not None else subnet_obj.subnet_id,
                **_settings_fields(subnet_obj, planned.settings, SUBNET_FIELDS, summary, source),
            }
            if existing is None:
                _create_row(subnet_obj, fields, capabilities)
            elif changes := _managed_changes(subnet_obj, fields, capabilities):
                _save_changes(subnet_obj, changes)
                changed = True
            if mapping is not None:
                observe_mapping(server, intent.family, subnet_obj, mapping)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001 — one bad subnet must not abort the import
        summary.record(write_failed(intent.family, Kind.SUBNET, path))
        summary.warn(f"subnet {intent.cidr} (id={intent.kea_subnet_id}): {exc}")
        return None

    if existing is None:
        summary.record(written(intent.family, Kind.SUBNET, path, Outcome.CREATED))
    elif changed or renumbered:
        summary.record(written(intent.family, Kind.SUBNET, path, Outcome.UPDATED))
    return subnet_obj


def _report_inherited(summary: ImportSummary, planned: PlannedSubnet) -> None:
    """Record each value that a Subnet inherits from its Shared Network, which the import does not hold."""
    path = subnet_path(planned)
    detail = f"Kea applies the value of Shared Network {planned.intent.shared_network}, which is not imported."
    for key in planned.inherited:
        entry = not_written(
            planned.intent.family,
            Kind.SUBNET,
            kea_paths.setting(path, key),
            Reason.INHERITED_FROM_SHARED_NETWORK,
            detail,
        )
        summary.record(entry)


def _skip_subnet_children(summary: ImportSummary, planned: PlannedSubnet, taken: SubnetIdTaken | None = None) -> None:
    """Record the DHCP Options and Pools of a Subnet that was not imported. A *taken* ID is also why its Pools were not."""
    family, parent_path = planned.intent.family, subnet_path(planned)
    _skip_options(summary, family, parent_path, planned.intent.options)
    for planned_pool in planned.pools:
        path = kea_paths.pool(parent_path, planned_pool.intent.pool)
        if taken is None:
            summary.record(not_written(family, Kind.POOL, path, Reason.PARENT_NOT_IMPORTED))
        else:
            summary.record(taken.entry(family, Kind.POOL, path))
        _skip_options(summary, family, path, planned_pool.intent.options)


def subnet_path(planned: PlannedSubnet) -> str:
    """Return the Kea path of a planned Subnet."""
    return kea_paths.subnet(planned.intent.family, planned.key, planned.intent.cidr)


@dataclass(frozen=True)
class SubnetIdTaken:
    """Another row holds the Kea subnet ID of a planned Subnet, in the scope where the plugin keeps IDs unique."""

    detail: str
    per_server: bool

    def entry(self, family: int, kind: Kind, path: str) -> ImportEntry:
        """Return the entry of the Subnet, or of one of its Pools or In-Subnet Reservations, at *path*."""
        if self.per_server:
            return not_written(family, kind, path, Reason.NOT_IN_SCOPE, self.detail)
        return subnet_id_clash(family, kind, path, self.detail)


@dataclass
class SubnetIdSettlement:
    """What :func:`settle_subnet_ids` found and did, by Kea subnet ID."""

    taken: dict[int, SubnetIdTaken] = field(default_factory=dict)
    renumbered: set[int] = field(default_factory=set)
    # The Subnets that need a move that failed.
    failed: set[int] = field(default_factory=set)


def _freeing_moves(
    key: int, requester: int | None, holds: dict[int, int], wants: dict[int, int]
) -> dict[int, int] | None:
    """Return the moves (row to Subnet ID) that free *key* for the row *requester*, or ``None`` when a row keeps it.

    A mapped row wants the Kea subnet ID of its mapping, and frees its ID when it moves there. A chain that comes
    back to *requester* is a cycle. A chain that comes back to another row has two rows that want one ID.
    """
    moves: dict[int, int] = {}
    while (holder := holds.get(key)) is not None and holder != requester:
        wanted = wants.get(holder)
        if wanted is None or wanted == key or holder in moves:
            return None
        moves[holder] = wanted
        key = wanted
    return moves


def _subnet_id_taken(planned: PlannedSubnet, holder, capabilities: PluginCapabilities) -> SubnetIdTaken:
    claim = (
        f"Subnet {planned.intent.cidr} needs Subnet ID {planned.key}, which Subnet {holder.name!r} ({holder.prefix})"
    )
    if capabilities.has(Capability.SUBNET_ID_PER_SERVER):
        return SubnetIdTaken(f"{claim} of this DHCP server holds.", per_server=True)
    detail = f"{claim} holds. The DHCP plugin needs each Subnet ID to be unique across all DHCP servers."
    return SubnetIdTaken(detail, per_server=False)


def _move_subnet_ids(rows: dict, moves: dict[int, int], holds: dict[int, int]) -> None:
    """Give each row in *moves* (row to Subnet ID) its ID once no row in *holds* (ID to row) holds it.

    When only a cycle is left, one row of it first takes an ID that no row holds or wants.
    """
    holds, pending, parked = dict(holds), dict(moves), set()
    while pending:
        pk = next((pk for pk, number in pending.items() if number not in holds), None)
        if pk is not None:
            number = pending.pop(pk)
        else:
            # Distinct targets, each held by a pending row, form cycles: parking one row of each breaks it.
            pk = next((pk for pk in pending if pk not in parked), None)
            if pk is None or any(holds[number] not in pending for number in pending.values()):
                raise RuntimeError("The Subnet ID moves do not resolve")
            parked.add(pk)
            number = next(free for free in count(1) if free not in holds and free not in moves.values())
        row = rows[pk]
        if holds.get(row.subnet_id) == pk:
            del holds[row.subnet_id]
        row.snapshot()
        row.subnet_id = number
        row.save()
        holds[number] = pk


def settle_subnet_ids(
    server, dhcp_server, plan: FamilyPlan, capabilities: PluginCapabilities, summary: ImportSummary
) -> SubnetIdSettlement:
    """Give each mapped Subnet of *plan* its Kea subnet ID, and find each planned Subnet whose ID another row keeps.

    A row that an earlier importer let the plugin number moves to its Kea subnet ID. So can a mapped row of another
    family or Server that holds the ID. The capability probe decides the scope of the plugin's uniqueness rule:
    all DHCP servers, or *dhcp_server* only.
    """
    from django.contrib.contenttypes.models import ContentType

    from ..models import KeaDhcpLink

    Subnet = _model("Subnet")
    planned = {subnet.key: subnet for subnet in plan.subnets if subnet.key is not None}
    links = KeaDhcpLink.objects.filter(kind=Kind.SUBNET.value, object_type=ContentType.objects.get_for_model(Subnet))
    wants = dict(links.values_list("object_id", "kea_subnet_id"))
    ours = dict(
        links.filter(server=server, family=plan.family, kea_subnet_id__in=planned).values_list(
            "kea_subnet_id", "object_id"
        )
    )
    current = dict(Subnet.objects.filter(pk__in=ours.values()).values_list("pk", "subnet_id"))
    scope = Subnet.objects.all()
    if capabilities.has(Capability.SUBNET_ID_PER_SERVER):
        scope = scope.filter(dhcp_server=dhcp_server)
    holds = dict(scope.values_list("subnet_id", "pk"))

    result = SubnetIdSettlement()
    moves: dict[int, int] = {}
    dependent: set[int] = set()
    # A planned Subnet keeps its ID from a mapped row of another family or Server. A new Subnet has no row yet.
    claimed = {key: ours.get(key, -key) for key in planned}
    for key, subnet in planned.items():
        requester = ours[key] if ours.get(key) in current else None
        chain = _freeing_moves(key, requester, holds, wants)
        if chain is not None and requester is not None and current[requester] != key:
            chain[requester] = key
        if chain is None or any(claimed.get(number, pk) != pk for pk, number in chain.items()):
            holder = Subnet.objects.select_related("prefix").get(pk=holds[key])
            result.taken[key] = _subnet_id_taken(subnet, holder, capabilities)
            continue
        claimed.update({number: pk for pk, number in chain.items()})
        moves.update(chain)
        if chain:
            dependent.add(key)
        if requester in chain:
            result.renumbered.add(key)
    if not moves:
        return result
    try:
        with event_scope.atomic():
            _move_subnet_ids(Subnet.objects.in_bulk(moves), moves, holds)
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:
        # The Subnets that need a move fail. The others still import.
        logger.exception("DHCP-plugin import: the Subnets of %s could not take their Kea subnet IDs", server.name)
        summary.warn(f"Kea Subnets {sorted(dependent)} could not take their Kea subnet IDs: {exc}")
        result.failed, result.renumbered = dependent, set()
    return result


@dataclass(frozen=True)
class ClassReferences:
    """The client classes that this run imported for one family, for the class lists of its other Kea objects."""

    family: int
    # The names that Kea's client-classes of this family defines.
    defined: frozenset[str]
    # The row of each class that this run wrote, by Kea name.
    imported: dict[str, int]

    def resolve(
        self, names: tuple[str, ...], parent_path: str, key: str, kind: Kind, summary: ImportSummary
    ) -> set[int]:
        """Return the imported client class of each name in the class list *key* of the *kind* at *parent_path*.

        A name without an imported class has an entry and is left out. The import never creates a class for it.
        """
        found = set()
        for name in names:
            if name in self.imported:
                found.add(self.imported[name])
                continue
            path = kea_paths.class_reference(parent_path, key, name)
            if name in self.defined:
                detail = f"Client class {name} was not imported."
                summary.record(not_written(self.family, kind, path, Reason.PARENT_NOT_IMPORTED, detail))
            else:
                detail = f"The DHCP plugin has no row for {name}, a class that Kea's client-classes does not define."
                summary.record(not_written(self.family, kind, path, Reason.NO_PLUGIN_HOME, detail))
        return found


def _upsert_pool(
    server,
    family: int,
    subnet_obj,
    range_obj,
    planned_pool,
    classes: dict[str, set[int]],
    summary: ImportSummary,
    path: str,
    capabilities: PluginCapabilities,
) -> tuple:
    """Get or create one Pool and set its managed fields. Return it with its outcome (``None`` when unchanged)."""
    Pool = _model("Pool")
    intent = planned_pool.intent
    source = planned_pool.key.source
    same_range = Pool.objects.filter(subnet=subnet_obj, ip_range=range_obj)
    if source is None:
        # A Subnet without a Kea subnet ID gives its Pools no mapping identity. An unmapped Pool stays as it is.
        pool_obj = same_range.first()
        if pool_obj is not None:
            return pool_obj, None
    else:
        pool_obj = mapped_target(server, family, source)
        if pool_obj is None:
            # Adopt a Pool that an import created before Pools had a mapping.
            pool_obj = _unlinked(same_range).first()
    created = pool_obj is None
    if pool_obj is None:
        pool_obj = Pool(name=_pool_name(subnet_obj, intent))
    values = _Source(family, Kind.POOL, path)
    fields = {
        "subnet_id": subnet_obj.pk,
        "ip_range_id": range_obj.pk,
        "pool_id": _declared_value(pool_obj, "pool_id", kea_paths.POOL_ID, intent.pool_id, None, summary, values),
        **_settings_fields(pool_obj, intent.settings, POOL_FIELDS, summary, values),
    }
    relations = _relation_changes(pool_obj, classes)
    changes: dict = {}
    if created:
        _create_row(pool_obj, fields, capabilities)
    elif changes := _managed_changes(pool_obj, fields, capabilities):
        _save_changes(pool_obj, changes)
    elif relations:
        pool_obj.snapshot()
    for name, pks in relations.items():
        getattr(pool_obj, name).set(pks)
    if source is not None:
        observe_mapping(server, family, pool_obj, source)
    if created:
        return pool_obj, Outcome.CREATED
    return pool_obj, Outcome.UPDATED if changes or relations else None


def upsert_pools(
    server,
    subnet_obj,
    planned: PlannedSubnet,
    summary: ImportSummary,
    dhcp_server,
    custom_defs,
    claims,
    classes: ClassReferences,
    capabilities: PluginCapabilities,
) -> None:
    """Get/create DHCP-plugin ``Pool`` rows (and their options) for each planned Pool of *planned*."""
    intent = planned.intent
    parent_path = subnet_path(planned)
    for planned_pool in planned.pools:
        pool_intent = planned_pool.intent
        path = kea_paths.pool(parent_path, pool_intent.pool)
        try:
            with event_scope.atomic():
                pool = planned_pool.key.range if planned_pool.key is not None else None
                result = claims.ranges.get(f"{pool.start} - {pool.end}") if pool is not None else None
                if result is not None and result.outcome == "error":
                    raise RuntimeError("The allocation Pool could not be claimed")
                range_obj = result.ip_range if result else None
                if result is not None and result.outcome in {"conflict", "disagreement"}:
                    summary.warn(f"pool {pool_intent.pool}: IPAM ownership {result.outcome}, IP Range left unchanged")
                if range_obj is not None:
                    references = {
                        relation: classes.resolve(names, path, key, Kind.POOL, summary)
                        for relation, key, names in (
                            ("client_classes", kea_paths.CLIENT_CLASSES, pool_intent.client_classes),
                            (
                                "evaluate_additional_classes",
                                kea_paths.EVALUATE_ADDITIONAL_CLASSES,
                                pool_intent.evaluate_additional_classes,
                            ),
                        )
                    }
                    pool_obj, outcome = _upsert_pool(
                        server,
                        intent.family,
                        subnet_obj,
                        range_obj,
                        planned_pool,
                        references,
                        summary,
                        path,
                        capabilities,
                    )
        except event_scope.EventDispatchError:
            raise
        except ManagedFieldsMismatch:
            raise
        except Exception as exc:  # noqa: BLE001 — one bad pool must not abort the import
            summary.record(write_failed(intent.family, Kind.POOL, path))
            summary.warn(f"pool {pool_intent.pool} in {intent.cidr}: {exc}")
            continue
        if range_obj is None:
            summary.record(_unusable_pool(intent.family, path, planned_pool.key, result))
            summary.warn(f"pool {pool_intent.pool} in {intent.cidr}: unusable range, skipped")
            continue
        if outcome is not None:
            summary.record(written(intent.family, Kind.POOL, path, outcome))
        upsert_options(
            pool_obj, pool_intent.options, intent.family, dhcp_server, custom_defs, summary, path, capabilities
        )


def _unusable_pool(family: int, path: str, key: PoolKey | None, result: RangeClaim | None) -> ImportEntry:
    """Return the entry of a Pool that has no IP Range to attach."""
    if key is None:
        detail = "The range is not valid or not inside the Subnet."
        return not_written(family, Kind.POOL, path, Reason.INVALID_KEA_DATA, detail)
    if result is None:
        # The claim leaves out a range that a NetBox IP Range cannot hold.
        return not_written(
            family, Kind.POOL, path, Reason.PLUGIN_GAP, "The range is larger than a NetBox IP Range can hold."
        )
    if result.outcome in {"conflict", "disagreement"}:
        return not_written(family, Kind.POOL, path, Reason.IPAM_OWNERSHIP, f"IPAM ownership {result.outcome}.")
    return not_written(family, Kind.POOL, path, Reason.WRITE_FAILED, "The IP Range could not be claimed.")


def _unlinked(base):
    """Restrict *base* to the rows no Kea link claims yet."""
    from django.contrib.contenttypes.models import ContentType

    KeaDhcpLink = _link_model()
    claimed = KeaDhcpLink.objects.filter(
        object_type=ContentType.objects.get_for_model(base.model),
    ).values_list("object_id", flat=True)
    return base.exclude(pk__in=claimed)


def _find_reservation(base, reservation: Reservation, mac_obj):
    """Find an existing reservation with the same typed identity in the parent scope."""
    id_type = reservation.identity.identifier_type
    identifier = reservation.identity.value
    if id_type == "hw-address":
        return base.filter(hw_address=mac_obj).first() if mac_obj is not None else None
    if id_type == "duid":
        return base.filter(duid=identifier).first()
    if id_type == "circuit-id":
        return base.filter(circuit_id=identifier).first()
    if id_type == "client-id":
        return base.filter(client_id=identifier).first()
    if id_type == "flex-id":
        return base.filter(flex_id=identifier).first()
    return None


def _upsert_reservation(
    planned: Planned[ReservationKey, Reservation],
    subnet_obj,
    server,
    dhcp_server,
    custom_defs,
    summary,
    claims,
    catalogue,
    adoption_servers: tuple[int, ...],
    capabilities: PluginCapabilities,
):
    """Upsert one typed Reservation through its mapping while preserving its Global or In-Subnet Scope.

    The mapping holds the Reservation Identity: the Kea subnet ID of an In-Subnet Reservation, or none for a
    Global one, and the identifier. A Global Reservation has no Subnet, and ``netbox_dhcp`` derives a
    reservation's family from one, so its family lives in the ``KeaDhcpLink`` identity
    instead.  Without it one identifier shares a single row between DHCPv4 and DHCPv6,
    merging ``ipv4_address`` and ``ipv6_addresses``.

    Consumes IPAM claim results so the plugin reservation shares the same
    ``ipam.IPAddress``/``dcim.MACAddress`` rows the lease/reservation sync owns.

    Return the row and its state before the write (``None`` for a new row), or ``None`` after a failed write.
    """
    HostReservation = _model("HostReservation")
    reservation, key = planned.intent, planned.key
    scope = reservation.scope.subnet.cidr if isinstance(reservation.scope, InSubnetReservationScope) else "global"
    path = reservation_path(key, reservation.family)

    if subnet_obj is not None:
        base = HostReservation.objects.filter(subnet=subnet_obj)
        scope_name = subnet_obj.name
    else:
        base = HostReservation.objects.filter(dhcp_server__in=adoption_servers, subnet__isnull=True)
        scope_name = f"{server.name} DHCPv{reservation.family}"

    try:
        with event_scope.atomic():
            # Inside the try so a resolver failure is counted per-reservation, not fatal.
            ipv4_ip, ipv6_ips, mac_obj = _reservation_addresses(reservation, claims, catalogue, summary)
            if reservation.identity.identifier_type == "hw-address" and mac_obj is None:
                raise RuntimeError("The reservation hardware address could not be resolved.")
            linked = mapped_target(server, reservation.family, key.source)
            # Adopt a row that an import made before its Reservation had a mapping (a Global one: before the
            # mapping carried the family), so an upgrade maps that row instead of duplicating it.
            obj = linked if linked is not None else _find_reservation(_unlinked(base), reservation, mac_obj)
            # The relation reads give the state before the write and also drive the write.
            addresses = frozenset() if obj is None else frozenset(obj.ipv6_addresses.values_list("pk", flat=True))
            prefixes = {} if obj is None else dict(obj.ipv6_prefixes.values_list("pk", "prefix"))
            before = None if obj is None else _reservation_state(obj, addresses, prefixes)
            fields = {
                # The Reservation Scope is a managed field: a row that an operator moved returns to it.
                "subnet_id": subnet_obj.pk if subnet_obj is not None else None,
                "dhcp_server_id": None if subnet_obj is not None else dhcp_server.pk,
                # The DHCP row mirrors the stored Kea hostname, not the published name.
                "hostname": reservation.hostname or None,
                **_reservation_identifier_values(reservation, mac_obj),
                # One row holds one family. _reservation_addresses returns the other
                # family empty, which also splits a row an earlier import merged.
                "ipv4_address_id": ipv4_ip.pk if ipv4_ip is not None else None,
            }
            if obj is None:
                obj = HostReservation(name=_reservation_name(scope_name, reservation))
                _create_row(obj, fields, capabilities)
            else:
                changes = _managed_changes(obj, fields, capabilities)
                if linked is None and subnet_obj is None:
                    # Newly adopted: take the family-qualified name so the other family is free
                    # to create its own row under the unique-name constraint.
                    changes["name"] = _reservation_name(scope_name, reservation)
                if changes:
                    _save_changes(obj, changes)
                else:
                    # The relation writes below need the state before the run.
                    obj.snapshot()
            # An empty address list clears the previous IPv6 relations.
            wanted = {address.pk for address in ipv6_ips}
            obj.ipv6_addresses.remove(*(addresses - wanted))
            obj.ipv6_addresses.add(*(wanted - addresses))
            # Drop obsolete references before the delegated phase evaluates stale links.
            obj.ipv6_prefixes.remove(
                *(
                    pk
                    for pk, prefix in prefixes.items()
                    if ipaddress.ip_network(str(prefix)) not in reservation.delegated_prefixes
                )
            )
            observe_mapping(server, reservation.family, obj, key.source)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception:
        summary.record(write_failed(reservation.family, Kind.RESERVATION, path))
        logger.exception("Could not import reservation %s in %s", reservation.identity.value, scope)
        summary.warn(f"reservation {reservation.identity.value} in {scope} could not be imported. See server logs.")
        _skip_options(summary, reservation.family, path, reservation.options)
        return None
    upsert_options(obj, reservation.options, reservation.family, dhcp_server, custom_defs, summary, path, capabilities)
    return obj, before


def reservation_path(key: ReservationKey, family: int) -> str:
    """Return the Kea path of a keyed Reservation of *family*."""
    subnet_id = key.subnet_id if isinstance(key, InSubnetReservationKey) else None
    return kea_paths.reservation(family, subnet_id, key.identifier_type, key.value)


def _reservation_state(obj, addresses, prefixes) -> tuple:
    """Return the managed values of a DHCP plugin Reservation, to tell an update from an unchanged row."""
    return (
        obj.name,
        obj.subnet_id,
        obj.dhcp_server_id,
        obj.hostname,
        obj.hw_address_id,
        obj.duid,
        obj.circuit_id,
        obj.client_id,
        obj.flex_id,
        obj.ipv4_address_id,
        frozenset(addresses),
        frozenset(prefixes),
    )


def _relation_states(objs) -> dict[int, tuple[set, set]]:
    """Read the IPv6 addresses and Prefixes of every row in two queries, keyed by row."""
    states: dict[int, tuple[set, set]] = {obj.pk: (set(), set()) for obj in objs}
    if not states:
        # Without the DHCP plugin no row is imported, and its model does not exist.
        return states
    rows = _model("HostReservation").objects.filter(pk__in=states)
    for position, relation in enumerate(("ipv6_addresses", "ipv6_prefixes")):
        for pk, related in rows.values_list("pk", relation):
            if related is not None:
                states[pk][position].add(related)
    return states


def _record_address_claims(report: SyncReport, claims: ClaimResult) -> bool:
    """Keep ownership outcomes separate from the DHCP rows that consume them."""
    report.conflicts.update(claims.conflicts)
    complete = True
    for address, result in claims.addresses.items():
        if result.outcome == "error":
            complete = False
        elif result.outcome == "conflict":
            report.conflicts.add(address)
        elif result.outcome == "disagreement":
            report.disagreements.add(address)
    return complete


def _record_snapshot_diagnostics(observation: ReservationObservation, family: int, summary: ImportSummary) -> None:
    """Record each quarantined record, and one entry for a traversal that did not read every record."""
    snapshot = observation.snapshot
    traversal = []
    for diagnostic in snapshot.diagnostics:
        summary.warn(f"reservation {diagnostic.source_position}: {diagnostic.message}")
        if diagnostic.code in TRAVERSAL_DIAGNOSTIC_CODES:
            traversal.append(diagnostic.message)
            continue
        path = kea_paths.reservation_record(family, diagnostic.source_position)
        summary.record(not_written(family, Kind.RESERVATION, path, Reason.INVALID_KEA_DATA, diagnostic.message))
    if snapshot.traversal_truncated:
        detail = " ".join(traversal) or "The Reservation walk did not reach the last page."
        summary.record(
            not_written(family, Kind.RESERVATION, kea_paths.reservations(family), Reason.READ_FAILED, detail)
        )


def import_reservation_snapshot(
    server,
    dhcp_server,
    observation: ReservationObservation | None,
    custom_defs,
    summary: ImportSummary,
    *,
    family: int,
    adoption_servers: tuple[int, ...],
    capabilities: PluginCapabilities,
    subnet_ids: SubnetIdSettlement | None = None,
) -> None:
    """Import valid typed records and report quarantined Snapshot records.

    A Global Reservation may adopt an unmapped row of a DHCP server in *adoption_servers*. An In-Subnet
    Reservation of a Subnet that *subnet_ids* reports as taken or failed is not imported.
    """
    from ..ipam_reconciliation import DelegatedPrefixPhase, claim, reconcile

    if observation is None:
        summary.record(
            not_written(
                family,
                Kind.RESERVATION,
                kea_paths.reservations(family),
                Reason.READ_FAILED,
                "The Reservation Snapshot could not be read.",
            )
        )
        summary.ownership.incomplete.add("reservation")
        return
    snapshot = observation.snapshot
    _record_snapshot_diagnostics(observation, family, summary)
    claims = claim(server, snapshot.family, snapshot.records, force=False, catalogue=observation.catalogue)
    summary.owner_disagreements += sum(result.outcome == "disagreement" for result in claims.addresses.values())
    imported = []
    complete = snapshot.complete and not snapshot.diagnostics
    complete = _record_address_claims(summary.ownership, claims) and complete
    for planned in keyed_reservations(observation):
        reservation, key = planned.intent, planned.key
        if isinstance(key, InSubnetReservationKey):
            taken = subnet_ids.taken.get(key.subnet_id) if subnet_ids is not None else None
            if taken is not None:
                complete = False
                summary.record(taken.entry(family, Kind.RESERVATION, reservation_path(key, family)))
                continue
            if subnet_ids is not None and key.subnet_id in subnet_ids.failed:
                subnet_obj = None
            else:
                subnet_obj = mapped_target(server, reservation.family, MappingSource.subnet(key.subnet_id))
            if subnet_obj is None:
                complete = False
                summary.record(
                    not_written(
                        family,
                        Kind.RESERVATION,
                        reservation_path(key, family),
                        Reason.PARENT_NOT_IMPORTED,
                        f"Subnet {key.subnet_id} was not imported.",
                    )
                )
                summary.warn(f"reservation for unknown subnet-id {key.subnet_id} skipped")
                continue
        else:
            subnet_obj = None
        upserted = _upsert_reservation(
            planned,
            subnet_obj,
            server,
            dhcp_server,
            custom_defs,
            summary,
            claims,
            observation.catalogue,
            adoption_servers,
            capabilities,
        )
        if upserted is None:
            complete = False
        else:
            imported.append((planned, *upserted))
    try:
        with event_scope.atomic():
            phase = DelegatedPrefixPhase([planned.intent for planned, _, _ in imported], observation.cutoff, complete)
            report = reconcile(server, snapshot.family, [phase])
            _attach_delegated_prefixes([(planned.intent, obj) for planned, obj, _ in imported], report, summary)
        summary.ownership.merge(report)
        if complete:
            summary.ownership.completed_sources.add("reservation")
        else:
            summary.ownership.incomplete.add("reservation")
        summary.ownership_errors += report.errors + report.prefix_errors
        summary.owner_disagreements += len(report.disagreements)
        for address in sorted(report.conflicts):
            summary.warn(f"delegated prefix {address}: IPAM ownership conflict, Prefix left unchanged")
    except event_scope.EventDispatchError:
        raise
    except Exception:
        summary.record(
            not_written(
                family,
                Kind.RESERVATION,
                kea_paths.reservations(family),
                Reason.WRITE_FAILED,
                "Delegated Prefixes could not be attached. See server logs.",
            )
        )
        summary.ownership.incomplete.add("delegated-prefix")
        logger.exception("Could not attach delegated Prefixes after DHCP import")
        summary.warn("Delegated Prefixes could not be attached. See server logs.")
    relations = _relation_states(obj for _, obj, _ in imported)
    for planned, obj, before in imported:
        if before is None or before != _reservation_state(obj, *relations[obj.pk]):
            outcome = Outcome.CREATED if before is None else Outcome.UPDATED
            summary.record(written(family, Kind.RESERVATION, reservation_path(planned.key, family), outcome))


def _attach_delegated_prefixes(imported, report: SyncReport, summary: ImportSummary) -> None:
    """Attach each imported Reservation's reported Prefixes, and keep the old ones when a claim failed."""
    for reservation, obj in imported:
        if any(report.prefixes[str(prefix)].outcome == "error" for prefix in reservation.delegated_prefixes):
            summary.warn(
                f"reservation {reservation.identity.value}: delegated Prefix claim failed; "
                "existing reported Prefix attachments were retained"
            )
            continue
        prefixes = []
        for prefix in reservation.delegated_prefixes:
            result = report.prefixes[str(prefix)]
            if result.prefix is not None:
                prefixes.append(result.prefix)
        obj.ipv6_prefixes.set(prefixes)


def _reservation_identifier_values(reservation: Reservation, mac_obj) -> dict:
    """Return the identifier fields of a DHCP-plugin reservation: its single Kea identifier, the others cleared."""
    identity = reservation.identity
    values: dict = {"hw_address_id": None, "duid": None, "circuit_id": None, "client_id": None, "flex_id": None}
    # Each Kea identifier type names its plugin field.
    field_name = identity.identifier_type.replace("-", "_")
    if field_name == "hw_address":
        values["hw_address_id"] = mac_obj.pk
    else:
        values[field_name] = identity.value
    return values


def _claim_config_networks(server, plan: FamilyPlan):
    """Group every planned Subnet and Pool before claiming either source."""
    from ..ipam_reconciliation import PoolClaim, SubnetClaim, claim

    subnets: list[SubnetClaim] = []
    pools: list[PoolClaim] = []
    for planned in plan.subnets:
        try:
            network = subnet_network(planned.intent.cidr, planned.intent.family)
        except ValueError:
            continue
        subnets.append(SubnetClaim(network))
        pools.extend(PoolClaim(pool.key.range, network) for pool in planned.pools if pool.key is not None)
    return claim(server, plan.family, subnets, force=False), claim(server, plan.family, pools, force=False)


# The DHCP plugin writes of apply_plan: it adds and changes each model it writes.
_PLUGIN_WRITES = tuple(
    f"{PLUGIN_APP_LABEL}.{action}_{model}"
    for model in ("dhcpserver", "optiondefinition", "option", "clientclass", "subnet", "pool", "hostreservation")
    for action in ("add", "change")
)


def import_permissions(server) -> tuple[str, ...]:
    """Return the IPAM, DCIM and DHCP plugin permissions that :func:`apply_plan` can use.

    The import claims Subnets, Pools and Reservations, reconciles delegated Prefixes, and writes the DHCP plugin rows.
    """
    from ..ipam_reconciliation import (
        RESERVATION,
        DelegatedPrefixPhase,
        PoolPhase,
        SubnetPhase,
        claim_permissions,
        reconcile_permissions,
    )

    claims = claim_permissions(SubnetPhase.source, PoolPhase.source, RESERVATION)
    return tuple(dict.fromkeys((*claims, *reconcile_permissions(server, DelegatedPrefixPhase.source), *_PLUGIN_WRITES)))


def import_server_config(
    server,
    config: ServerConfigIntent,
    reservation_observation: ReservationObservation | None = None,
) -> ImportSummary:
    """Plan one parsed ``(server, family)`` Kea config, probe the installed DHCP plugin, and apply the plan to it."""
    return apply_plan(server, plan_family(config, reservation_observation), probe())


@coordinated_import
def apply_plan(server, plan: FamilyPlan, capabilities: PluginCapabilities) -> ImportSummary:
    """Apply the plan of one ``(server, family)`` to the DHCP plugin, writing a gated fact only with its *capabilities*.

    Idempotent: re-running finds each row through its ``KeaDhcpLink`` mapping and updates it rather than
    duplicating it.
    """
    summary = ImportSummary()
    root = kea_paths.daemon(plan.family)
    for dropped in plan.dropped:
        summary.record(not_written(plan.family, dropped.kind, dropped.path, Reason.INVALID_KEA_DATA, dropped.detail))
    dhcp_server, created = upsert_dhcp_server(server, plan.family)
    adoption_servers = _adoption_servers(server, dhcp_server)
    custom_defs = CustomDefinitions(
        server, {planned.key: planned.intent for planned in plan.option_definitions}, adoption_servers
    )

    values = server_values(dhcp_server, plan.server, plan.family, capabilities, summary)
    changed = _apply_global_settings(dhcp_server, values, summary, plan.family, capabilities)
    linked = _link_interfaces(dhcp_server, plan.server.interfaces, summary, plan.family)
    if changed is not None and (created or changed or linked):
        summary.record(written(plan.family, Kind.SERVER, root, Outcome.CREATED if created else Outcome.UPDATED))
    upsert_options(
        dhcp_server, plan.server.global_options, plan.family, dhcp_server, custom_defs, summary, root, capabilities
    )
    imported_classes = {}
    for planned_class in plan.client_classes:
        row = upsert_client_class(server, dhcp_server, planned_class, custom_defs, summary, capabilities)
        if row is not None:
            imported_classes[planned_class.key] = row.pk
    defined = frozenset(planned.key for planned in plan.client_classes)
    classes = ClassReferences(plan.family, defined, imported_classes)
    for planned_network in plan.shared_networks:
        summary.record(
            not_written(
                plan.family,
                Kind.SHARED_NETWORK,
                kea_paths.shared_network(plan.family, planned_network.key),
                Reason.NOT_IN_SCOPE,
                "Its values and DHCP Options are not imported. Its Subnets are imported without it.",
            )
        )

    prefix_claims, pool_claims = _claim_config_networks(server, plan)
    summary.owner_disagreements += sum(
        result.outcome == "disagreement" for result in (*prefix_claims.prefixes.values(), *pool_claims.ranges.values())
    )
    subnet_ids = settle_subnet_ids(server, dhcp_server, plan, capabilities, summary)
    for planned_subnet in plan.subnets:
        taken = subnet_ids.taken.get(planned_subnet.key) if planned_subnet.key is not None else None
        if taken is not None:
            summary.record(taken.entry(plan.family, Kind.SUBNET, subnet_path(planned_subnet)))
            summary.warn(f"subnet {planned_subnet.intent.cidr} (id={planned_subnet.key}): {taken.detail}")
            _skip_subnet_children(summary, planned_subnet, taken)
            continue
        if planned_subnet.key in subnet_ids.failed:
            summary.record(write_failed(plan.family, Kind.SUBNET, subnet_path(planned_subnet)))
            _skip_subnet_children(summary, planned_subnet)
            continue
        renumbered = planned_subnet.key in subnet_ids.renumbered
        subnet_obj = upsert_subnet(
            server, dhcp_server, planned_subnet, summary, prefix_claims, renumbered, capabilities
        )
        if subnet_obj is None:
            _skip_subnet_children(summary, planned_subnet)
            continue
        _report_inherited(summary, planned_subnet)
        upsert_options(
            subnet_obj,
            planned_subnet.intent.options,
            plan.family,
            dhcp_server,
            custom_defs,
            summary,
            subnet_path(planned_subnet),
            capabilities,
        )
        upsert_pools(
            server, subnet_obj, planned_subnet, summary, dhcp_server, custom_defs, pool_claims, classes, capabilities
        )
    for source, outcomes in (("subnet", prefix_claims.prefixes), ("pool", pool_claims.ranges)):
        if any(result.outcome == "error" for result in outcomes.values()):
            summary.ownership.incomplete.add(source)
        else:
            summary.ownership.completed_sources.add(source)
        summary.ownership.conflicts.update(
            address for address, result in outcomes.items() if result.outcome == "conflict"
        )
        summary.ownership.disagreements.update(
            address for address, result in outcomes.items() if result.outcome == "disagreement"
        )
    import_reservation_snapshot(
        server,
        dhcp_server,
        plan.reservations,
        custom_defs,
        summary,
        family=plan.family,
        adoption_servers=adoption_servers,
        capabilities=capabilities,
        subnet_ids=subnet_ids,
    )
    if not plan.configuration_complete:
        summary.ownership.incomplete.update({"subnet", "pool"})
    if (
        summary.errors
        or summary.reservations_skipped
        or summary.reservations_quarantined
        or summary.reservations_unread
    ):
        summary.ownership.incomplete.add("reservation")
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Stale-cleanup exclusion (so the IPAM sync never GCs rows the plugin references)
# ─────────────────────────────────────────────────────────────────────────────


def sys4_referenced_ip_ids() -> set[int]:
    """PKs of ``ipam.IPAddress`` rows referenced by any DHCP-plugin reservation."""
    if not is_available():
        return set()
    HostReservation = _model("HostReservation")
    ids: set[int] = set()
    ids.update(HostReservation.objects.exclude(ipv4_address__isnull=True).values_list("ipv4_address_id", flat=True))
    ids.update(HostReservation.objects.values_list("ipv6_addresses__id", flat=True))
    ids.discard(None)
    return ids


def sys4_referenced_prefix_ids() -> set[int]:
    """PKs of ``ipam.Prefix`` rows referenced by DHCP-plugin subnets/shared-networks/reservations."""
    if not is_available():
        return set()
    Subnet = _model("Subnet")
    SharedNetwork = _model("SharedNetwork")
    HostReservation = _model("HostReservation")
    ids: set[int] = set()
    ids.update(Subnet.objects.values_list("prefix_id", flat=True))
    ids.update(SharedNetwork.objects.values_list("prefix_id", flat=True))
    ids.update(HostReservation.objects.values_list("ipv6_prefixes__id", flat=True))
    ids.update(HostReservation.objects.values_list("excluded_ipv6_prefixes__id", flat=True))
    ids.discard(None)
    return ids


def sys4_referenced_iprange_ids() -> set[int]:
    """PKs of ``ipam.IPRange`` rows referenced by any DHCP-plugin pool."""
    if not is_available():
        return set()
    Pool = _model("Pool")
    ids = set(Pool.objects.values_list("ip_range_id", flat=True))
    ids.discard(None)
    return ids
