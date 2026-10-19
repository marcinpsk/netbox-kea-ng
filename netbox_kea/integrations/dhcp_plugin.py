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
* **Host reservations** come from the shared typed Reservation Snapshot. The
  adapter never parses raw ``reservation-get-page`` records. Valid records import
  even when the snapshot quarantines other records. A Global Reservation skips the
  IPAM sync, so the import creates no address rows for it and reports every reserved
  address it could not attach.  Delegated prefixes carry their own length, so they
  import as shared ``ipam.Prefix`` rows for every Scope.
* Subnet identity is tracked in :class:`netbox_kea.models.KeaDhcpLink` keyed by
  ``(server, family, kea_subnet_id)`` — Kea's subnet-id is unique only per
  ``(server, protocol)`` and cannot live in the plugin's globally-unique
  ``Subnet.subnet_id``.  Pools and In-Subnet reservations match structurally within
  their resolved parent subnet.  A Global Reservation has no parent subnet to carry a
  family, so its link is keyed by ``(server, family, kea_identity)`` instead.
* DHCP **options** (``option-data``) are imported at every scope we model —
  ``DHCPServer`` (global), ``Subnet``, ``Pool``, ``HostReservation`` — binding to
  the sys4-shipped standard ``OptionDefinition`` (by space+code), or to a
  server-scoped custom definition created from a Kea ``option-def``.  Options
  whose definition cannot be resolved are reported as unsupported, never fatal.
* **Tuning fields** (lifetimes, timers, lease/DDNS/BOOTP/network settings) are
  imported onto the ``DHCPServer`` (global) and ``Subnet``.  ``config-get`` returns
  these fully defaulted and inherited, so each subnet field is stored **only when
  it differs from the DHCPServer parent** (parent-diff suppression) — otherwise it
  is left blank to inherit, keeping the records minimal and faithful.
* **Client classes** (``client-classes``) are imported as ``ClientClass`` rows
  (test/template-test, additional-list flag, BOOTP + lifetime settings, options),
  named ``"<server>: <kea-name>"`` since the plugin requires a globally-unique name.
* **Deferred** (reported, not imported): shared-network grouping (the plugin's
  ``SharedNetwork`` requires a prefix Kea does not model — member subnets are
  flattened onto the ``DHCPServer``).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..ipam_reconciliation import ClaimResult, RangeClaim, ReservationObservation, SyncReport
    from ..models import DhcpIntegrationConfig, Server
    from ..subnet_catalogue import CatalogueSnapshot
    from .dhcp_import_plan import FamilyPlan, Planned, PlannedServer, PlannedSubnet, PoolKey, ReservationKey

from django.apps import apps
from django.db.models.signals import post_delete

from .. import event_scope, kea_paths
from ..constants import IPNetworkValue
from ..dhcp_mapping_lifecycle import coordinated_import
from ..dhcp_options import DHCPOption, option_identity
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import ClientClassIntent, OptionDefIntent, ServerConfigIntent
from ..published_name import reservation_published_name
from ..reservations import TRAVERSAL_DIAGNOSTIC_CODES, InSubnetReservationScope, Reservation
from ..subnet_catalogue import CatalogueUnavailable
from .dhcp_import_plan import (
    GlobalReservationKey,
    InSubnetReservationKey,
    OptionDefinitionKey,
    keyed_reservations,
    plan_family,
)
from .dhcp_import_report import ImportEntry, Kind, Outcome, Reason, not_written, written

logger = logging.getLogger(__name__)

PLUGIN_APP_LABEL = "netbox_dhcp"


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
    for name in ("Subnet", "HostReservation"):
        model = _model(name)
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


def _create_custom_option_def(def_intent: OptionDefIntent, family: int, dhcp_server, summary: ImportSummary):
    """Create a non-standard ``OptionDefinition`` for a Kea custom option, scoped to the server."""
    OptionDefinition = _model("OptionDefinition")
    space = def_intent.space
    path = kea_paths.option_definition(family, space, def_intent.code)
    try:
        obj = OptionDefinition(
            name=def_intent.name,
            family=family,
            space=space,
            code=def_intent.code,
            type=def_intent.type,
            array=def_intent.array,
            record_types=list(def_intent.record_types) or None,
            encapsulate=def_intent.encapsulate,
            standard=False,
            dhcp_server=dhcp_server,
        )
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001 — a bad definition must not abort the import
        summary.record(write_failed(family, Kind.OPTION_DEFINITION, path))
        summary.warn(f"option-def code={def_intent.code}: {exc}")
        return None
    else:
        summary.record(written(family, Kind.OPTION_DEFINITION, path, Outcome.CREATED))
        return obj


def _resolve_option_definition(opt: DHCPOption, family: int, dhcp_server, custom_defs, summary):
    """Find (or create) the ``OptionDefinition`` a Kea ``option-data`` entry refers to.

    Prefers the sys4-shipped **standard** definition (by space+code, else space+name);
    falls back to a server-scoped **custom** definition (existing, or created from a Kea
    ``option-def``). Returns why the option has no definition when it cannot be resolved: the DHCP plugin has
    none, or the custom definition could not be created.
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

    custom = OptionDefinition.objects.filter(standard=False, dhcp_server=dhcp_server, space=space)
    if opt.code is not None:
        found = custom.filter(code=opt.code).first()
    elif opt.name:
        found = custom.filter(name=opt.name).first()
    if found is not None:
        return found

    key = OptionDefinitionKey(space, opt.code) if opt.code is not None else None
    if key in custom_defs:
        def_intent = custom_defs[key]
        created = _create_custom_option_def(def_intent, family, dhcp_server, summary) if def_intent else None
        if created is None:
            # Not again for the next Option of this definition: the failure has its entry.
            custom_defs[key] = None
            return Reason.PARENT_NOT_IMPORTED
        return created
    return Reason.PLUGIN_GAP


def _option_values(obj) -> tuple:
    return (obj.data, obj.csv_format, obj.send_option)


def upsert_options(
    parent_obj, options, family: int, dhcp_server, custom_defs, summary: ImportSummary, parent_path: str
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
        definition = _resolve_option_definition(opt, family, dhcp_server, custom_defs, summary)
        if isinstance(definition, Reason):
            detail = "No matching Option Definition." if definition is Reason.PLUGIN_GAP else "See server logs."
            summary.record(not_written(family, Kind.OPTION, path, definition, detail))
            summary.warn(f"option {option_identity(opt, family)}: no matching definition, skipped")
            continue
        try:
            with event_scope.atomic():
                existing = Option.objects.filter(
                    assigned_object_type=ct, assigned_object_id=parent_obj.pk, definition=definition
                ).first()
                before = None if existing is None else _option_values(existing)
                if existing is None:
                    obj = Option(definition=definition, assigned_object_type=ct, assigned_object_id=parent_obj.pk)
                else:
                    obj = existing
                    obj.snapshot()
                obj.data = opt.data or ""
                obj.csv_format = opt.csv_format
                obj.send_option = _send_option(opt)
                obj.save()
            if before is None:
                summary.record(written(family, Kind.OPTION, path, Outcome.CREATED))
            elif before != _option_values(obj):
                summary.record(written(family, Kind.OPTION, path, Outcome.UPDATED))
        except event_scope.EventDispatchError:
            raise
        except Exception as exc:  # noqa: BLE001 — one bad option must not abort the import
            summary.record(write_failed(family, Kind.OPTION, path))
            summary.warn(f"option {option_identity(opt, family)}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Tuning fields (lifetimes/timers/lease/DDNS/BOOTP/network) — Kea key → sys4 field
# ─────────────────────────────────────────────────────────────────────────────


def _decimal(value):
    """Coerce a Kea numeric to ``Decimal`` via ``str`` (avoids float-precision noise)."""
    from decimal import Decimal

    return None if value is None else Decimal(str(value))


def _norm_ddns_replace(value):
    """Map Kea ``ddns-replace-client-name`` (hyphenated) to the plugin's underscored choice."""
    return value.replace("-", "_") if isinstance(value, str) else value


def _relay_to_str(value):
    """Flatten a Kea ``relay`` (``{"ip-addresses": [...]}``) to the plugin's CSV string."""
    if isinstance(value, dict):
        addrs = value.get("ip-addresses") or []
    elif isinstance(value, list):
        addrs = value
    else:
        return value or None
    return ", ".join(addrs) if addrs else None


def _server_id_type(value):
    """Reduce a Kea ``server-id`` dict to its ``type`` (the plugin stores only the type)."""
    return value.get("type") if isinstance(value, dict) else value


def _hr_identifiers(value: tuple[str, ...]) -> list[str] | None:
    """Keep only host-reservation identifier types the plugin's choice set knows."""
    valid = {"circuit-id", "hw-address", "duid", "client-id"}
    return [x for x in value if x in valid] or None


# (kea_key, sys4_attr, transform). Fields shared by DHCPServer + Subnet.
_COMMON_FIELDS: tuple[tuple[str, str, object], ...] = (
    ("valid-lifetime", "valid_lifetime", None),
    ("min-valid-lifetime", "min_valid_lifetime", None),
    ("max-valid-lifetime", "max_valid_lifetime", None),
    ("preferred-lifetime", "preferred_lifetime", None),
    ("min-preferred-lifetime", "min_preferred_lifetime", None),
    ("max-preferred-lifetime", "max_preferred_lifetime", None),
    ("offer-lifetime", "offer_lifetime", None),
    ("renew-timer", "renew_timer", None),
    ("rebind-timer", "rebind_timer", None),
    ("match-client-id", "match_client_id", None),
    ("authoritative", "authoritative", None),
    ("reservations-global", "reservations_global", None),
    ("reservations-out-of-pool", "reservations_out_of_pool", None),
    ("reservations-in-subnet", "reservations_in_subnet", None),
    ("calculate-tee-times", "calculate_tee_times", None),
    ("t1-percent", "t1_percent", _decimal),
    ("t2-percent", "t2_percent", _decimal),
    ("cache-threshold", "cache_threshold", _decimal),
    ("cache-max-age", "cache_max_age", None),
    ("store-extended-info", "store_extended_info", None),
    ("allocator", "allocator", None),
    ("pd-allocator", "pd_allocator", None),
    ("ddns-send-updates", "ddns_send_updates", None),
    ("ddns-override-no-update", "ddns_override_no_update", None),
    ("ddns-override-client-update", "ddns_override_client_update", None),
    ("ddns-replace-client-name", "ddns_replace_client_name", _norm_ddns_replace),
    ("ddns-generated-prefix", "ddns_generated_prefix", None),
    ("ddns-qualifying-suffix", "ddns_qualifying_suffix", None),
    ("ddns-update-on-renew", "ddns_update_on_renew", None),
    ("ddns-conflict-resolution-mode", "ddns_conflict_resolution_mode", None),
    ("ddns-ttl-percent", "ddns_ttl_percent", _decimal),
    ("ddns-ttl", "ddns_ttl", None),
    ("ddns-ttl-min", "ddns_ttl_min", None),
    ("ddns-ttl-max", "ddns_ttl_max", None),
    ("hostname-char-set", "hostname_char_set", None),
    ("hostname-char-replacement", "hostname_char_replacement", None),
    ("next-server", "next_server", None),
    ("server-hostname", "server_hostname", None),
    ("boot-file-name", "boot_file_name", None),
)

_SUBNET_FIELDS: tuple[tuple[str, str, object], ...] = (
    *_COMMON_FIELDS,
    ("relay", "relay", _relay_to_str),
    ("interface-id", "interface_id", None),
    ("rapid-commit", "rapid_commit", None),
)

_SERVER_FIELDS: tuple[tuple[str, str, object], ...] = (
    *_COMMON_FIELDS,
    ("decline-probation-period", "decline_probation_period", None),
    ("echo-client-id", "echo_client_id", None),
    ("relay-supplied-options", "relay_supplied_options", None),
    ("server-id", "server_id", _server_id_type),
)


def _is_unset(value) -> bool:
    """Return ``True`` for values treated as 'not configured' (None / empty str / empty list)."""
    return value is None or value == "" or value == []


@dataclass(frozen=True)
class _Source:
    """The Kea object whose settings a field map reads, for the entry of a value that cannot be converted."""

    family: int
    kind: Kind
    path: str


def _transform_value(transform, raw, kea_key: str, summary: ImportSummary, source: _Source):
    """Apply a field transform. A value that it cannot convert has an entry and gives ``None``."""
    if transform is None:
        return raw
    try:
        return transform(raw)
    except Exception as exc:  # noqa: BLE001 — a bad scalar must not abort the import
        path = kea_paths.setting(source.path, kea_key)
        detail = "The value cannot be converted to the DHCP plugin field."
        summary.record(not_written(source.family, source.kind, path, Reason.PLUGIN_GAP, detail))
        summary.warn(f"setting {kea_key}: {exc}")
        return None


def _server_values(planned: PlannedServer, model_fields: set[str], summary: ImportSummary, family: int) -> dict:
    """Return each value that *planned* sets for a field in *model_fields* of ``DHCPServer``, by field name."""
    settings = planned.global_settings
    source = _Source(family, Kind.SERVER, kea_paths.daemon(family))
    values = {
        attr: _transform_value(transform, settings[kea_key], kea_key, summary, source)
        for kea_key, attr, transform in _SERVER_FIELDS
        if attr in model_fields and kea_key in settings
    }
    identifiers = planned.host_reservation_identifiers
    if "host_reservation_identifiers" in model_fields and identifiers is not None:
        values["host_reservation_identifiers"] = _hr_identifiers(identifiers)
    return values


def _apply_global_settings(
    dhcp_server, planned: PlannedServer, summary: ImportSummary, *, primary: bool, family: int
) -> bool:
    """Populate ``DHCPServer`` global tuning fields from a Kea config block.

    netbox_dhcp has a single ``DHCPServer`` row spanning both protocols, so one
    family is authoritative.  The *primary* family (DHCPv4, or whichever family is
    enabled on a single-stack server) **mirrors** its values — re-import re-syncs a
    changed global value.  The secondary family only **fills gaps** (e.g. the
    DHCPv6-only ``preferred-lifetime``/``pd-allocator``) so it never clobbers the
    primary family's shared fields and dual-stack re-imports do not thrash.

    Known limitation: a change to a *secondary-only* field (e.g. DHCPv6
    ``preferred-lifetime``) on a dual-stack server is not re-synced, since the
    secondary family is fill-only for an already-set field.

    Return whether a changed value was saved. A failed save is recorded here.
    """
    model_fields = {f.name for f in dhcp_server._meta.get_fields()}
    changed: dict = {}
    for attr, value in _server_values(planned, model_fields, summary, family).items():
        if _is_unset(value):
            continue
        current = getattr(dhcp_server, attr, None)
        if primary:
            # This family owns the global config — mirror changed values on re-import.
            if current != value:
                changed[attr] = value
        elif _is_unset(current):
            # Secondary protocol only fills gaps the primary family did not set.
            changed[attr] = value
    if not changed:
        return False
    dhcp_server.snapshot()
    for attr, value in changed.items():
        setattr(dhcp_server, attr, value)
    try:
        with event_scope.atomic():
            dhcp_server.save()
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001
        path = kea_paths.daemon(family)
        summary.record(write_failed(family, Kind.SERVER, path))
        summary.warn(f"DHCPServer settings: {exc}")
        # Children diff against this instance, so it must hold the persisted values.
        dhcp_server.refresh_from_db(fields=list(changed))
        return False
    return True


def _inherited_settings_fields(obj, parent, settings: dict, field_map, summary: ImportSummary, source: _Source) -> dict:
    """Plan *obj*'s tuning fields from Kea, storing only genuine overrides.

    ``config-get`` returns every value fully inherited, so a field is stored on the
    child only when it is present and **differs** from the stored *parent*
    (parent-diff suppression).  A value equal to the parent — or one Kea no longer
    reports — is **cleared**, so a removed Kea override does not linger as stale data
    on re-import.  The ``model_fields`` guard skips fields *obj* does not have, so one
    field map serves models with different mixins (e.g. ``Subnet`` vs ``ClientClass``).
    Return the desired fields without changing *obj*.
    """
    model_fields = {f.name for f in obj._meta.get_fields()}
    fields = {}
    for kea_key, attr, transform in field_map:
        if attr not in model_fields:
            continue
        raw = settings.get(kea_key)
        value = _transform_value(transform, raw, kea_key, summary, source) if kea_key in settings else None
        # Store only a genuine override (present and differing from the parent);
        # otherwise clear it so the child inherits (and stale overrides don't linger).
        if not _is_unset(value) and value != getattr(parent, attr, None):
            desired = value
        else:
            # "Cleared" value: None for nullable fields, the field's empty default
            # (e.g. "" for a non-null CharField like hostname_char_set) otherwise.
            db_field = obj._meta.get_field(attr)
            desired = None if db_field.null else db_field.get_default()
        fields[attr] = desired
    return fields


# ─────────────────────────────────────────────────────────────────────────────
# Upserts
# ─────────────────────────────────────────────────────────────────────────────


def upsert_dhcp_server(server):
    """Get/create the ``netbox_dhcp.DHCPServer`` mirroring this Kea *server* (match by name), and whether it is new."""
    DHCPServer = _model("DHCPServer")
    return DHCPServer.objects.get_or_create(
        name=server.name,
        defaults={"description": "Imported from Kea by netbox-kea"},
    )


def _client_class_name(server, kea_name: str) -> str:
    """Namespace a Kea class name to this server (NetBoxDHCPModelMixin needs a unique name).

    Note: this namespaced name will NOT match the bare Kea class name referenced from
    a subnet's ``client-classes`` list or another class's ``test`` expression.  That is
    fine for the v1 import (those references are not imported), but a future push-back /
    reference-resolution phase must map the bare Kea name back to this namespaced row.
    """
    return f"{server.name}: {kea_name}"[:255]


def _client_class_changes(obj, dhcp_server, intent: ClientClassIntent, summary: ImportSummary, path: str) -> dict:
    """Plan the changed identity, expressions and inherited fields of one Client Class."""
    fields = {
        "dhcp_server_id": dhcp_server.pk,
        "test": intent.test or "",
        "template_test": intent.template_test or "",
    }
    if intent.only_in_additional_list is not None:
        fields["only_in_additional_list"] = intent.only_in_additional_list
    source = _Source(intent.family, Kind.CLIENT_CLASS, path)
    fields.update(_inherited_settings_fields(obj, dhcp_server, intent.settings, _COMMON_FIELDS, summary, source))
    return {name: value for name, value in fields.items() if getattr(obj, name) != value}


def upsert_client_class(
    server, dhcp_server, planned: Planned[str, ClientClassIntent], custom_defs, summary: ImportSummary
):
    """Get/create the DHCP-plugin ``ClientClass`` for *planned* (match by the namespaced Kea name of its key)."""
    ClientClass = _model("ClientClass")
    intent = planned.intent
    path = kea_paths.client_class(intent.family, planned.key)
    cc_name = _client_class_name(server, planned.key)
    obj = ClientClass.objects.filter(name=cc_name).first()
    created = obj is None
    if obj is None:
        obj = ClientClass(name=cc_name, dhcp_server=dhcp_server)
        changes = _client_class_changes(obj, dhcp_server, intent, summary, path)
    else:
        changes = _client_class_changes(obj, dhcp_server, intent, summary, path)
        if not changes:
            upsert_options(obj, intent.options, intent.family, dhcp_server, custom_defs, summary, path)
            return obj
        obj.snapshot()

    for name, value in changes.items():
        setattr(obj, name, value)

    try:
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001 — one bad class must not abort the import
        summary.record(write_failed(intent.family, Kind.CLIENT_CLASS, path))
        summary.warn(f"client-class {intent.name}: {exc}")
        _skip_options(summary, intent.family, path, intent.options)
        return None

    summary.record(written(intent.family, Kind.CLIENT_CLASS, path, Outcome.CREATED if created else Outcome.UPDATED))
    upsert_options(obj, intent.options, intent.family, dhcp_server, custom_defs, summary, path)
    return obj


def _linked_subnet(server, family: int, kea_subnet_id: int):
    """Return the DHCP-plugin Subnet previously linked for this Kea identity, or ``None``."""
    KeaDhcpLink = _link_model()
    link = KeaDhcpLink.objects.filter(server=server, family=family, kea_subnet_id=kea_subnet_id).first()
    return link.sys4_object if link is not None else None


def _subnet_name(server, planned: PlannedSubnet, network: IPNetworkValue) -> str:
    """Build a globally-unique name (NetBoxDHCPModelMixin requires unique ``name``)."""
    family = planned.intent.family
    if planned.key is not None:
        return f"{server.name} DHCPv{family} subnet {planned.key}"[:255]
    return f"{server.name} DHCPv{family} {network}"[:255]


def _pool_name(subnet_obj, pool_intent) -> str:
    """Build a unique pool name scoped to its parent subnet's (unique) name."""
    return f"{subnet_obj.name} pool {pool_intent.pool}"[:255]


def _reservation_name(scope_name: str, reservation: Reservation) -> str:
    """Build a unique reservation name scoped to its parent's (unique) name."""
    identity = reservation.identity
    return f"{scope_name} {identity.identifier_type}:{identity.value}"[:255]


def upsert_subnet(server, dhcp_server, planned: PlannedSubnet, summary: ImportSummary, claims: ClaimResult):
    """Get/create the DHCP-plugin ``Subnet`` for *planned*, tracked via ``KeaDhcpLink`` by its key.

    Returns the ``netbox_dhcp.Subnet`` instance, or ``None`` on error.
    """
    from ..dhcp_mapping_lifecycle import observe_mapping

    Subnet = _model("Subnet")
    intent = planned.intent
    path = subnet_path(planned)
    source = _Source(intent.family, Kind.SUBNET, path)

    existing = None
    if planned.key is not None:
        existing = _linked_subnet(server, intent.family, planned.key)

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
            if existing is not None:
                fields = {"prefix_id": prefix_obj.pk, "dhcp_server_id": dhcp_server.pk, "shared_network_id": None}
                fields.update(
                    _inherited_settings_fields(existing, dhcp_server, intent.settings, _SUBNET_FIELDS, summary, source)
                )
                changed = any(getattr(existing, name) != value for name, value in fields.items())
                if changed:
                    existing.snapshot()
                    for name, value in fields.items():
                        setattr(existing, name, value)
                    existing.save()
                subnet_obj = existing
            else:
                # Let the plugin auto-allocate its own (global) subnet_id; never write Kea's.
                subnet_obj = Subnet(
                    name=_subnet_name(server, planned, network),
                    prefix=prefix_obj,
                    dhcp_server=dhcp_server,
                    shared_network=None,
                )
                for name, value in _inherited_settings_fields(
                    subnet_obj, dhcp_server, intent.settings, _SUBNET_FIELDS, summary, source
                ).items():
                    setattr(subnet_obj, name, value)
                subnet_obj.save()
            if planned.key is not None:
                observe_mapping(server, intent.family, subnet_obj, subnet_id=planned.key)
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001 — one bad subnet must not abort the import
        summary.record(write_failed(intent.family, Kind.SUBNET, path))
        summary.warn(f"subnet {intent.cidr} (id={intent.kea_subnet_id}): {exc}")
        return None

    if existing is None:
        summary.record(written(intent.family, Kind.SUBNET, path, Outcome.CREATED))
    elif changed:
        summary.record(written(intent.family, Kind.SUBNET, path, Outcome.UPDATED))
    return subnet_obj


def _skip_subnet_children(summary: ImportSummary, planned: PlannedSubnet) -> None:
    """Record the DHCP Options and Pools of a Subnet that was not imported."""
    family, parent_path = planned.intent.family, subnet_path(planned)
    _skip_options(summary, family, parent_path, planned.intent.options)
    for planned_pool in planned.pools:
        path = kea_paths.pool(parent_path, planned_pool.intent.pool)
        summary.record(not_written(family, Kind.POOL, path, Reason.PARENT_NOT_IMPORTED))
        _skip_options(summary, family, path, planned_pool.intent.options)


def subnet_path(planned: PlannedSubnet) -> str:
    """Return the Kea path of a planned Subnet."""
    return kea_paths.subnet(planned.intent.family, planned.key, planned.intent.cidr)


def upsert_pools(subnet_obj, planned: PlannedSubnet, summary: ImportSummary, dhcp_server, custom_defs, claims):
    """Get/create DHCP-plugin ``Pool`` rows (and their options) for each planned Pool of *planned*."""
    Pool = _model("Pool")
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
                    pool_obj, created = Pool.objects.get_or_create(
                        subnet=subnet_obj,
                        ip_range=range_obj,
                        defaults={"name": _pool_name(subnet_obj, pool_intent)},
                    )
        except event_scope.EventDispatchError:
            raise
        except Exception as exc:  # noqa: BLE001 — one bad pool must not abort the import
            summary.record(write_failed(intent.family, Kind.POOL, path))
            summary.warn(f"pool {pool_intent.pool} in {intent.cidr}: {exc}")
            continue
        if range_obj is None:
            summary.record(_unusable_pool(intent.family, path, planned_pool.key, result))
            summary.warn(f"pool {pool_intent.pool} in {intent.cidr}: unusable range, skipped")
            continue
        if created:
            summary.record(written(intent.family, Kind.POOL, path, Outcome.CREATED))
        upsert_options(pool_obj, pool_intent.options, intent.family, dhcp_server, custom_defs, summary, path)


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


def _linked_reservation(server, key: GlobalReservationKey):
    """Return the DHCP-plugin reservation linked to this Kea Global identity, or ``None``."""
    KeaDhcpLink = _link_model()
    link = KeaDhcpLink.objects.filter(server=server, family=key.family, kea_identity=key.link_identity).first()
    return link.sys4_object if link is not None else None


def _link_reservation(server, key: GlobalReservationKey, obj) -> None:
    """Record the ``(server, family, identity)`` link for one Global Reservation.

    Keyed on the Kea identity rather than the row, so a link whose row was deleted is
    relinked instead of colliding with ``keadhcplink_unique_sys4_object``.
    """
    from ..dhcp_mapping_lifecycle import observe_mapping

    observe_mapping(server, key.family, obj, reservation_identity=key.link_identity)


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
):
    """Upsert one typed Reservation while preserving its Global or In-Subnet Scope.

    An In-Subnet Reservation matches by identifier inside its Subnet, which already
    fixes the family.  A Global Reservation has no Subnet, and ``netbox_dhcp`` derives a
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
        base = HostReservation.objects.filter(dhcp_server=dhcp_server, subnet__isnull=True)
        scope_name = f"{dhcp_server.name} DHCPv{reservation.family}"

    try:
        with event_scope.atomic():
            # Inside the try so a resolver failure is counted per-reservation, not fatal.
            ipv4_ip, ipv6_ips, mac_obj = _reservation_addresses(reservation, claims, catalogue, summary)
            if reservation.identity.identifier_type == "hw-address" and mac_obj is None:
                raise RuntimeError("The reservation hardware address could not be resolved.")
            linked = _linked_reservation(server, key) if isinstance(key, GlobalReservationKey) else None
            if linked is not None:
                obj = linked
            elif subnet_obj is not None:
                obj = _find_reservation(base, reservation, mac_obj)
            else:
                # Adopt a Global row imported before the link carried the family, so an
                # upgrade relinks that row instead of duplicating it.
                obj = _find_reservation(_unlinked(base), reservation, mac_obj)
            # The relation reads give the state before the write and also drive the write.
            addresses = frozenset() if obj is None else frozenset(obj.ipv6_addresses.values_list("pk", flat=True))
            prefixes = {} if obj is None else dict(obj.ipv6_prefixes.values_list("pk", "prefix"))
            before = None if obj is None else _reservation_state(obj, addresses, prefixes)
            if obj is None:
                obj = HostReservation(
                    subnet=subnet_obj,
                    dhcp_server=None if subnet_obj is not None else dhcp_server,
                    name=_reservation_name(scope_name, reservation),
                )
            else:
                obj.snapshot()
                if linked is None and subnet_obj is None:
                    # Newly adopted: take the family-qualified name so the other family is free
                    # to create its own row under the unique-name constraint.
                    obj.name = _reservation_name(scope_name, reservation)
            # The DHCP row mirrors the stored Kea hostname, not the published name.
            obj.hostname = reservation.hostname or None
            _apply_reservation_identifier(obj, reservation, mac_obj)
            # One row holds one family. _reservation_addresses returns the other
            # family empty, which also splits a row an earlier import merged.
            obj.ipv4_address = ipv4_ip
            obj.save()
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
            if isinstance(key, GlobalReservationKey):
                _link_reservation(server, key, obj)
    except event_scope.EventDispatchError:
        raise
    except Exception:
        summary.record(write_failed(reservation.family, Kind.RESERVATION, path))
        logger.exception("Could not import reservation %s in %s", reservation.identity.value, scope)
        summary.warn(f"reservation {reservation.identity.value} in {scope} could not be imported. See server logs.")
        _skip_options(summary, reservation.family, path, reservation.options)
        return None
    upsert_options(obj, reservation.options, reservation.family, dhcp_server, custom_defs, summary, path)
    return obj, before


def reservation_path(key: ReservationKey, family: int) -> str:
    """Return the Kea path of a keyed Reservation of *family*."""
    subnet_id = key.subnet_id if isinstance(key, InSubnetReservationKey) else None
    return kea_paths.reservation(family, subnet_id, key.identifier_type, key.value)


def _reservation_state(obj, addresses, prefixes) -> tuple:
    """Return the managed values of a DHCP plugin Reservation, to tell an update from an unchanged row."""
    return (
        obj.name,
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
) -> None:
    """Import valid typed records and report quarantined Snapshot records."""
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
            subnet_obj = _linked_subnet(server, reservation.family, key.subnet_id)
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
            planned, subnet_obj, server, dhcp_server, custom_defs, summary, claims, observation.catalogue
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


def _apply_reservation_identifier(obj, reservation: Reservation, mac_obj) -> None:
    """Set the single Kea identifier on a DHCP-plugin reservation (clearing the others)."""
    identity = reservation.identity
    obj.hw_address = mac_obj if identity.identifier_type == "hw-address" else None
    obj.duid = identity.value if identity.identifier_type == "duid" else None
    obj.circuit_id = identity.value if identity.identifier_type == "circuit-id" else None
    obj.client_id = identity.value if identity.identifier_type == "client-id" else None
    obj.flex_id = identity.value if identity.identifier_type == "flex-id" else None


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


# The DHCP plugin writes of apply_plan: it only creates Pools and custom OptionDefinitions.
_PLUGIN_WRITES = tuple(
    f"{PLUGIN_APP_LABEL}.{action}_{model}"
    for model, actions in (
        ("dhcpserver", ("add", "change")),
        ("optiondefinition", ("add",)),
        ("option", ("add", "change")),
        ("clientclass", ("add", "change")),
        ("subnet", ("add", "change")),
        ("pool", ("add",)),
        ("hostreservation", ("add", "change")),
    )
    for action in actions
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
    """Plan one parsed ``(server, family)`` Kea config and apply the plan to the DHCP plugin."""
    return apply_plan(server, plan_family(config, reservation_observation))


@coordinated_import
def apply_plan(server, plan: FamilyPlan) -> ImportSummary:
    """Apply the plan of one ``(server, family)`` to the DHCP plugin.

    Idempotent: re-running updates the same rows (subnets via ``KeaDhcpLink``,
    pools/reservations matched structurally) rather than duplicating them.
    """
    summary = ImportSummary()
    root = kea_paths.daemon(plan.family)
    for dropped in plan.dropped:
        summary.record(not_written(plan.family, dropped.kind, dropped.path, Reason.INVALID_KEA_DATA, dropped.detail))
    dhcp_server, created = upsert_dhcp_server(server)
    custom_defs: dict[OptionDefinitionKey, OptionDefIntent | None] = {
        planned.key: planned.intent for planned in plan.option_definitions
    }

    # Global (server-level) tuning fields + options + client classes. DHCPv4 (or the
    # only enabled family) is authoritative for the shared, single DHCPServer row.
    primary = plan.family == 4 or not server.dhcp4
    changed = _apply_global_settings(dhcp_server, plan.server, summary, primary=primary, family=plan.family)
    if created or changed:
        summary.record(written(plan.family, Kind.SERVER, root, Outcome.CREATED if created else Outcome.UPDATED))
    upsert_options(dhcp_server, plan.server.global_options, plan.family, dhcp_server, custom_defs, summary, root)
    for planned_class in plan.client_classes:
        upsert_client_class(server, dhcp_server, planned_class, custom_defs, summary)
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
    for planned_subnet in plan.subnets:
        subnet_obj = upsert_subnet(server, dhcp_server, planned_subnet, summary, prefix_claims)
        if subnet_obj is None:
            _skip_subnet_children(summary, planned_subnet)
            continue
        upsert_options(
            subnet_obj,
            planned_subnet.intent.options,
            plan.family,
            dhcp_server,
            custom_defs,
            summary,
            subnet_path(planned_subnet),
        )
        upsert_pools(subnet_obj, planned_subnet, summary, dhcp_server, custom_defs, pool_claims)
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
    import_reservation_snapshot(server, dhcp_server, plan.reservations, custom_defs, summary, family=plan.family)
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
