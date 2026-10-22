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
  ``DHCPServer``, ``Subnet``, ``Pool``, ``PDPool``, ``HostReservation`` — reusing netbox-kea's
  IPAM ownership claims so the DHCP-plugin rows **share** the same
  ``ipam.Prefix``/``IPRange``/``IPAddress`` and ``dcim.MACAddress`` objects the
  IPAM sync maintains.
* **Delegated-prefix Pools** (DHCPv6 ``pd-pools``) import as ``PDPool`` rows in their Subnet. Their prefix and
  excluded prefix are NetBox Prefixes that the import owns through the IPAM source ``pd-pool`` (ADR 0006). The
  ``pd-pool`` phase runs after the removal of Stale DHCP Import Objects, so it can deprecate a Prefix that only a
  removed PD Pool used. A PD Pool that the plugin refuses (``PDPool.clean``) is unsupported, and the run goes on.
* **One DHCPServer per Server and family** (Kea runs one daemon per family). It holds only its daemon's global
  configuration, maps to it, and links the interfaces that ``interfaces-config`` names.
* **Host reservations** come from the shared typed Reservation Snapshot. The
  adapter never parses raw ``reservation-get-page`` records. Valid records import
  even when the snapshot quarantines other records. A Global Reservation skips the
  IPAM sync, so the import creates no address rows for it and reports every reserved
  address it could not attach.  Delegated prefixes and the prefixes that they exclude carry their own length, so
  they import as shared ``ipam.Prefix`` rows for every Scope, under the IPAM source ``delegated-prefix``. The stale
  cleanup of ``delegated-prefix`` runs after the removal of Stale DHCP Import Objects, as the ``pd-pool`` phase does.
* Each imported Shared Network, Subnet, Pool, delegated-prefix Pool, Reservation, client class, custom Option
  Definition and DHCP Option has a DHCP Import Mapping (:class:`netbox_kea.models.KeaDhcpLink`) to its Kea source, and
  a re-import finds the row through it, also after an operator renames the row. The first import after an upgrade
  maps each unmapped row that matches by structure. No release imported delegated-prefix Pools before, so an unmapped PD Pool
  is an operator's row and stays. A Subnet without a Kea subnet ID, and its Pools and PD Pools, have no
  mapping identity. The import creates them, but an unmapped row that matches one by structure is not its own: the
  writer returns no row (:func:`_keep_unmapped`), so the import writes no field, DHCP Option or child of it.
* A plugin Subnet holds Kea's subnet ID (:func:`settle_subnet_ids`). While the plugin keeps Subnet IDs
  unique across all servers, a Subnet whose ID another Server or family holds is reported as unsupported,
  with its Pools, delegated-prefix Pools and In-Subnet Reservations.
* Every custom **Option Definition** that Kea declares is written before any DHCP Option, used or not: a global
  ``option-def`` to the ``DHCPServer``, and a client class ``option-def`` to its ``ClientClass``, each through its
  own mapping. A space or a code that the plugin cannot hold is unsupported (:mod:`.dhcp_plugin_capabilities`).
* DHCP **options** (``option-data``) are imported at every scope we model: ``DHCPServer`` (global),
  ``ClientClass``, ``Subnet``, ``Pool``, ``PDPool``, ``HostReservation``. Each binds to the sys4-shipped standard
  ``OptionDefinition`` (by space+code), or to a custom definition of its class or of the daemon. An Option keeps its
  Kea ``client-classes``, so the same definition with other classes is another Option. The mapping of an Option holds
  the source of its parent and its identity (ADR 0014), so a changed class set gives a new Option. An Option that an
  operator adds to a mapped parent has no mapping and stays. An option whose definition the plugin cannot hold is
  unsupported with the capability it needs, and an option whose class has no row is skipped. Neither is fatal.
* **Tuning fields** (lifetimes, timers, lease/DDNS/BOOTP/network settings) are
  imported onto the ``DHCPServer`` (global), ``Subnet``, ``Pool`` (DDNS) and ``ClientClass``. A Subnet
  or client class gets only its Declared Values (:func:`.dhcp_import_plan.declared_values`),
  and every other field is cleared to inherit. A value that a member Subnet inherits
  from its Shared Network is never copied onto the Subnet, and is reported when the Shared Network was not imported.
* **Ownership.** Every writer sets exactly the managed fields of :mod:`.dhcp_import_fields` on a mapped row, and
  :func:`_managed_changes` refuses a write that names another set. Unmanaged fields and unmapped rows stay.
* A Shared Network, a Subnet, a Pool, a PD Pool and a Reservation link the client classes of their class lists that
  the same run imported. A Shared Network and a Subnet link the DHCP server interface that their Kea ``interface``
  names, and report a name that matches none.
* **Client classes** (``client-classes``) are imported as ``ClientClass`` rows
  (test/template-test, additional-list flag, BOOTP + lifetime settings, options) with
  their Kea name. While the plugin keeps class names unique across all servers, a class
  whose name another row holds is reported as unsupported (:mod:`.dhcp_plugin_capabilities`).
* **Shared Networks** (``shared-networks``) are imported as ``SharedNetwork`` rows with their Kea name, settings,
  class lists, interface and options, before the Subnets, and never with a Prefix: a Kea Shared Network has none.
  Each member Subnet belongs to its Shared Network instead of the DHCPServer. Without the capability for an
  optional prefix (netbox-plugin-dhcp 0.2.0 requires one) every Shared Network is unsupported, and its member Subnets
  import onto the DHCPServer. Names follow the same uniqueness rule as client classes.
* **Removal.** A mapped row whose Kea source a Complete observation of its kind no longer reports is a Stale DHCP
  Import Object (:func:`remove_stale_objects`). The run removes it, children first, and reports it. An Incomplete
  observation keeps every row of its kind. A row whose delete would also delete a DHCP plugin row that the run keeps,
  that an Option still uses, or that a kept row names in a client class relation, stays. IPAM objects stay: ADR 0006 ownership decides them.
  The Subnet writes run first, so a kept Subnet that left a stale Shared Network no longer belongs to it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from collections import Counter
from dataclasses import dataclass, field, replace
from itertools import count
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from ..ipam_reconciliation import ClaimResult, DelegatedPrefixPhase, RangeClaim, ReservationObservation, SyncReport
    from ..models import DhcpIntegrationConfig, Server
    from ..subnet_catalogue import CatalogueSnapshot
    from .dhcp_import_plan import (
        FamilyPlan,
        PDPoolKey,
        Planned,
        PlannedClientClass,
        PlannedOptions,
        PlannedServer,
        PlannedSharedNetwork,
        PlannedSubnet,
        PoolKey,
        ReservationKey,
    )

from django.apps import apps
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.db.models.deletion import Collector, ProtectedError
from django.db.models.signals import post_delete

from .. import event_scope, kea_paths
from ..constants import Family, IPNetworkValue
from ..dhcp_mapping_lifecycle import (
    coordinated_import,
    mapped_target,
    mark_options_mapped,
    observe_mapping,
    options_mapped,
    target_models,
)
from ..dhcp_options import MAX_ONE_OCTET_OPTION_CODE, DHCPOption, option_identity
from ..kea import subnet_network
from ..mappers.kea_to_dhcp import OptionDefIntent, PDPoolIntent, PoolIntent, ServerConfigIntent
from ..published_name import reservation_published_name
from ..reservations import FLEX_ID, TRAVERSAL_DIAGNOSTIC_CODES, InSubnetReservationScope, Reservation, identity_text
from ..subnet_catalogue import CatalogueUnavailable
from .dhcp_import_fields import (
    CLIENT_CLASS_FIELDS,
    GATED_NETWORK_FIELDS,
    GATED_SERVER_FIELDS,
    GATED_SUBNET_FIELDS,
    MANAGED_FIELDS,
    NETWORK_FIELDS,
    POOL_FIELDS,
    SERVER_FIELDS,
    GatedFieldMap,
    managed_fields,
    server_id_field,
)
from .dhcp_import_plan import (
    MAX_KEA_NAME_LENGTH,
    REMOVAL_ORDER,
    InSubnetReservationKey,
    MappingSource,
    OptionDefinitionKey,
    keyed_reservations,
    kind_path,
    mapped_kinds,
    observations,
    plan_family,
    planned_options,
)
from .dhcp_import_report import (
    KIND_LABELS,
    Capability,
    ImportEntry,
    Kind,
    Outcome,
    Reason,
    counted,
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


def _keep_unmapped(summary: ImportSummary, family: int, kind: Kind, path: str) -> None:
    """Record a Kea object without a mapping identity that matched an unmapped DHCP plugin row by structure.

    The import does not own that row, so its writer returns no row, and the caller writes no child of it (ADR 0013).
    """
    detail = (
        "Its Kea Subnet has no subnet ID, so it has no DHCP Import Mapping. The unmapped row that matches it stays as "
        "it is, with its DHCP Options and its children."
    )
    summary.record(not_written(family, kind, path, Reason.NOT_IN_SCOPE, detail))


def _skip_options(summary: ImportSummary, family: int, parent_path: str, planned: PlannedOptions) -> None:
    """Record each DHCP Option of the object at *parent_path*, which was not imported."""
    for path in planned.paths(parent_path, family):
        summary.record(not_written(family, Kind.OPTION, path, Reason.PARENT_NOT_IMPORTED))


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
    pd_pools_created = _Count(Kind.PD_POOL, Outcome.CREATED)
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
    shared_networks_created = _Count(Kind.SHARED_NETWORK, Outcome.CREATED)
    shared_networks_updated = _Count(Kind.SHARED_NETWORK, Outcome.UPDATED)

    @property
    def shared_networks_unsupported(self) -> int:
        """Return the Shared Networks that the DHCP plugin refused whole, not one setting of an imported one."""
        # The path of the Shared Network ends with its name step; the path of one of its settings does not.
        return sum(
            entry.kind == Kind.SHARED_NETWORK and entry.outcome == Outcome.UNSUPPORTED and entry.path.endswith("]")
            for entry in self.entries
        )

    @property
    def removed(self) -> int:
        """Return the number of Stale DHCP Import Objects that the run removed."""
        return sum(entry.outcome == Outcome.REMOVED for entry in self.entries)

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
    """The custom Option Definitions that one family of a Server declares, each written once a run before any Option.

    *declared* holds the definitions of the daemon and of each client class.
    """

    server: Server
    declared: dict[OptionDefinitionKey, OptionDefIntent]
    # The DHCPServers whose unmapped rows of this family the import adopts (_adoption_servers).
    adoption_servers: tuple[int, ...]
    # The row of each written definition, or why it has none.
    written: dict[OptionDefinitionKey, object] = field(default_factory=dict)


@dataclass(frozen=True)
class OptionReferences:
    """What the DHCP Options of one family can reference: the custom Option Definitions and the client classes."""

    definitions: CustomDefinitions
    classes: ClassReferences

    @property
    def server(self) -> Server:
        """Return the Server whose import writes the Options."""
        return self.definitions.server


@dataclass(frozen=True)
class _Unresolved:
    """Why an Option has no Option Definition that the DHCP plugin holds: its reason, detail and capability."""

    reason: Reason
    detail: str
    capability: Capability | None = None

    def entry(self, family: int, kind: Kind, path: str) -> ImportEntry:
        """Return the entry of the fact at *path* that this reason stops."""
        if self.capability is not None:
            return unsupported(family, kind, path, self.capability, self.detail)
        return not_written(family, kind, path, self.reason, self.detail)


_DEFINITION_NOT_WRITTEN = _Unresolved(Reason.PARENT_NOT_IMPORTED, "See server logs.")


def _code_and_space_gap(space: str, code: int, family: int, capabilities: PluginCapabilities) -> _Unresolved | None:
    """Return why the DHCP plugin cannot hold an option *code* in *space*, in the order of the parity ledger."""
    if family == 6 and code > MAX_ONE_OCTET_OPTION_CODE and not capabilities.has(Capability.OPTION_CODE_16_BIT):
        detail = (
            f"The installed DHCP plugin cannot hold the option code {code}, which is above {MAX_ONE_OCTET_OPTION_CODE}."
        )
        return _Unresolved(Reason.PLUGIN_GAP, detail, Capability.OPTION_CODE_16_BIT)
    if not capabilities.holds_space(space):
        detail = f"The installed DHCP plugin cannot hold the option space {space}."
        return _Unresolved(Reason.PLUGIN_GAP, detail, Capability.OPTION_SPACES)
    return None


def _without_definition(opt: DHCPOption, space: str, family: int, capabilities: PluginCapabilities):
    """Return why the DHCP plugin cannot hold *opt*, which has no Option Definition, or ``None`` when it can."""
    if not capabilities.has(Capability.OPTION_WITHOUT_DEFINITION):
        detail = "The DHCP plugin has no Option Definition for it and cannot hold an option without one."
        return _Unresolved(Reason.PLUGIN_GAP, detail, Capability.OPTION_WITHOUT_DEFINITION)
    if opt.code is None:
        return _Unresolved(Reason.INVALID_KEA_DATA, "No Option Definition gives its name a code.")
    return _code_and_space_gap(space, opt.code, family, capabilities)


def _option_definition_fields(
    obj, def_intent: OptionDefIntent, family: int, parent_field: dict, capabilities: PluginCapabilities, summary, source
) -> dict:
    """Return the managed fields of a custom Option Definition: all but its name, which stays as created or renamed.

    *parent_field* sets its parent: the DHCPServer or the client class. The plugin refuses a definition with both.
    """
    return {
        "space": def_intent.space,
        "code": def_intent.code,
        "family": family,
        "type": def_intent.type,
        "array": def_intent.array,
        "record_types": list(def_intent.record_types) or None,
        "encapsulate": def_intent.encapsulate,
        "dhcp_server_id": None,
        "client_class_id": None,
        **parent_field,
        **_user_context_fields(obj, def_intent.user_context, capabilities, summary, source, "Option Definition"),
    }


def _held_option_definition(held, family: int, key: OptionDefinitionKey, path: str, summary: ImportSummary):
    """Report a definition that another mapping holds on this parent, which the plugin cannot hold twice."""
    from django.contrib.contenttypes.models import ContentType

    holder = (
        _link_model()
        .objects.filter(object_type=ContentType.objects.get_for_model(held.model), object_id__in=held.values("pk"))
        .first()
    )
    parent = "DHCP server" if key.client_class is None else "client class"
    limit = f"The DHCP plugin holds one custom Option Definition for each space and code of a {parent}"
    holder_text = f"the DHCPv{holder.family} import holds it" if holder is not None else "another row holds it"
    detail = f"{limit}, and {holder_text}."
    summary.record(not_written(family, Kind.OPTION_DEFINITION, path, Reason.PLUGIN_GAP, detail))
    summary.warn(f"option-def {key.space}:{key.code}: {detail}")
    return _Unresolved(Reason.PLUGIN_GAP, f"Option Definition {key.space}:{key.code} is not imported. {limit}.")


def _write_option_definition(
    definitions: CustomDefinitions,
    key: OptionDefinitionKey,
    family: int,
    parent,
    summary: ImportSummary,
    capabilities: PluginCapabilities,
):
    """Write the custom Option Definition of *key* to *parent*, a DHCPServer or a client class, through its mapping.

    Return the row, or why it has none. A space or code that the plugin cannot hold is unsupported.
    """
    OptionDefinition = _model("OptionDefinition")
    def_intent = definitions.declared[key]
    path = key.source.path(family)
    gap = _code_and_space_gap(key.space, key.code, family, capabilities)
    if gap is not None:
        summary.record(gap.entry(family, Kind.OPTION_DEFINITION, path))
        return _Unresolved(gap.reason, f"Its Option Definition is not imported. {gap.detail}", gap.capability)
    in_class = key.client_class is not None
    parent_field = {"client_class_id": parent.pk} if in_class else {"dhcp_server_id": parent.pk}
    source = _Source(family, Kind.OPTION_DEFINITION, path)
    outcome = None
    try:
        with event_scope.atomic():
            obj = mapped_target(definitions.server, family, key.source)
            if obj is None:
                same_key = OptionDefinition.objects.filter(standard=False, space=key.space, code=key.code)
                held = same_key.filter(client_class=parent) if in_class else same_key.filter(dhcp_server=parent)
                # Adopt a definition that an import created before Option Definitions had a mapping.
                adoptable = held if in_class else same_key.filter(dhcp_server__in=definitions.adoption_servers)
                obj = _unlinked(adoptable.filter(family=family)).first()
                if obj is None and held.exists():
                    return _held_option_definition(held, family, key, path, summary)
            created = obj is None
            if created:
                obj = OptionDefinition(name=def_intent.name, standard=False)
            fields = _option_definition_fields(obj, def_intent, family, parent_field, capabilities, summary, source)
            if created:
                _create_row(obj, fields, capabilities)
                outcome = Outcome.CREATED
            elif changes := _managed_changes(obj, fields, capabilities):
                _save_changes(obj, changes)
                outcome = Outcome.UPDATED
            observe_mapping(definitions.server, family, obj, key.source)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001 (a bad definition must not abort the import)
        summary.record(write_failed(family, Kind.OPTION_DEFINITION, path))
        summary.warn(f"option-def code={key.code}: {exc}")
        return _DEFINITION_NOT_WRITTEN
    if outcome is not None:
        summary.record(written(family, Kind.OPTION_DEFINITION, path, outcome))
    return obj


def _class_not_imported(name: str) -> str:
    """Return the detail of a fact whose client class *name* Kea defines but this run did not import."""
    return f"Client class {name} was not imported."


def _skip_class_definitions(
    definitions: CustomDefinitions, planned: PlannedClientClass, summary: ImportSummary
) -> None:
    """Record each custom Option Definition of a client class that was not imported."""
    for planned_definition in planned.option_definitions:
        reason = _Unresolved(Reason.PARENT_NOT_IMPORTED, _class_not_imported(planned.key))
        definitions.written[planned_definition.key] = reason
        path = planned_definition.key.source.path(planned.intent.family)
        summary.record(reason.entry(planned.intent.family, Kind.OPTION_DEFINITION, path))


def _declared_key(opt: DHCPOption, space: str, owner: str | None, definitions: CustomDefinitions):
    """Return the key of the custom Option Definition of *opt* that *owner* declares (``None``: the daemon), if any."""
    if opt.code is not None:
        key = OptionDefinitionKey(space, opt.code, owner)
        return key if key in definitions.declared else None
    return next(
        (
            each
            for each, intent in definitions.declared.items()
            if each.client_class == owner and each.space == space and intent.name == opt.name
        ),
        None,
    )


def _resolve_option_definition(
    opt: DHCPOption,
    family: int,
    definitions: CustomDefinitions,
    capabilities: PluginCapabilities,
    class_name: str | None,
):
    """Find the ``OptionDefinition`` a Kea ``option-data`` entry refers to.

    As in Kea, a custom definition comes first: one that the client class *class_name* of the option declares, then
    one that the daemon declares. A declared definition that the import could not write stays the answer. Then the
    sys4-shipped **standard** definition (by space+code, else space+name). A custom definition that Kea does not
    declare is never used. Returns ``None`` for an option that the plugin holds without a definition, or why the
    option cannot be imported.
    """
    OptionDefinition = _model("OptionDefinition")
    space = opt.space or kea_paths.default_space(family)
    owners = (None,) if class_name is None else (class_name, None)
    for owner in owners:
        key = _declared_key(opt, space, owner, definitions)
        if key is not None:
            return definitions.written[key]

    standard = OptionDefinition.objects.filter(standard=True, space=space)
    if opt.code is not None:
        found = standard.filter(code=opt.code).first()
    elif opt.name:
        found = standard.filter(name=opt.name).first()
    else:
        found = None
    return found if found is not None else _without_definition(opt, space, family, capabilities)


def option_values(
    candidate, opt: DHCPOption, family: int, capabilities: PluginCapabilities, summary, source: _Source
) -> dict:
    """Return the managed fields of an Option as the DHCP plugin stores them, after ``Option.clean`` on *candidate*.

    The plugin's clean step normalizes some values, for example the CSV format of a binary option. An option
    without an Option Definition keeps its Kea space and code (gap 9).
    """
    candidate.data = opt.data or ""
    candidate.csv_format = opt.csv_format
    candidate.send_option = _send_option(opt)
    own: dict = {}
    if capabilities.has(Capability.OPTION_WITHOUT_DEFINITION):
        definition = candidate.definition
        own = {
            "space": opt.space or kea_paths.default_space(family),
            "code": definition.code if definition is not None else opt.code,
        }
        for name, value in own.items():
            setattr(candidate, name, value)
    candidate.clean()
    return {
        "definition_id": candidate.definition_id,
        "data": candidate.data,
        "csv_format": candidate.csv_format,
        "send_option": candidate.send_option,
        **own,
        **_user_context_fields(candidate, opt.user_context, capabilities, summary, source, "DHCP Option"),
    }


@dataclass(frozen=True)
class _PlannedOption:
    """A Kea option that the DHCP plugin can hold, with its DHCP Import Mapping source (``None``: none)."""

    option: DHCPOption
    path: str
    space: str
    code: int | None
    definition: Any
    classes: frozenset[int]
    source: MappingSource | None


def _option_code(row) -> tuple:
    """Return the space and code of the Option *row*: from its definition, or its own fields without one (gap 9)."""
    if row.definition_id is not None:
        return row.definition.space, row.definition.code
    return row.space, row.code


def _paired_rows(planned: list[_PlannedOption], rows: list) -> list:
    """Return the unmapped Option of *rows* that each planned option without a mapped row adopts, or ``None``.

    First a row with the same definition and the same client classes, then an unpaired row with the same definition,
    in order. A row pairs by space and code, not by its definition row. A row that an import wrote before options had
    classes is updated, not duplicated.
    """
    classes = {row.pk: {each.pk for each in row.client_classes.all()} for row in rows}
    codes = {row.pk: _option_code(row) for row in rows}
    free = list(rows)
    paired: list = [None] * len(planned)
    for exact in (True, False):
        for index, item in enumerate(planned):
            if paired[index] is not None:
                continue
            row = next(
                (
                    row
                    for row in free
                    if codes[row.pk] == (item.space, item.code) and (not exact or classes[row.pk] == item.classes)
                ),
                None,
            )
            if row is not None:
                paired[index] = row
                free.remove(row)
    return paired


def _write_option(item: _PlannedOption, row, parent_obj, ct, family: int, references, summary, capabilities) -> None:
    """Create the Option of *item* on *parent_obj*, or update its *row*, with its client classes and its mapping."""
    Option = _model("Option")
    source = _Source(family, Kind.OPTION, item.path)
    outcome = None
    try:
        with event_scope.atomic():
            new = Option(definition=item.definition, assigned_object_type=ct, assigned_object_id=parent_obj.pk)
            desired = option_values(new, item.option, family, capabilities, summary, source)
            obj = new if row is None else row
            relations = _relation_changes(obj, {"client_classes": set(item.classes)})
            changes: dict = {}
            if row is None:
                _create_row(new, desired, capabilities)
                outcome = Outcome.CREATED
            elif changes := _managed_changes(row, desired, capabilities):
                _save_changes(row, changes)
            elif relations:
                row.snapshot()
            for name, pks in relations.items():
                getattr(obj, name).set(pks)
            if row is not None and (changes or relations):
                outcome = Outcome.UPDATED
            if item.source is not None:
                observe_mapping(references.server, family, obj, item.source)
        if outcome is not None:
            summary.record(written(family, Kind.OPTION, item.path, outcome))
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001 (one bad option must not abort the import)
        summary.record(write_failed(family, Kind.OPTION, item.path))
        summary.warn(f"option {option_identity(item.option, family)}: {exc}")


def upsert_options(
    parent_obj,
    planned_set: PlannedOptions,
    family: int,
    references: OptionReferences,
    summary: ImportSummary,
    parent_path: str,
    capabilities: PluginCapabilities,
) -> None:
    """Upsert DHCP-plugin ``Option`` rows for the options of *planned_set* (:func:`.dhcp_import_plan.planned_options`).

    They are assigned to *parent_obj*, the Kea object at *parent_path*. One Option per Kea option: the same definition
    with other client classes is another Option. Each Option has a DHCP Import Mapping from its key, and a re-import
    finds the row through it. Until the mapping of the object records that its Options are mapped (the first run that
    reaches it after the upgrade), an Option without a mapped row adopts an unmapped Option of *parent_obj*
    (:func:`_paired_rows`). The adoptions and that record are written before the Options, whatever their writes do. After that, every unmapped Option is an operator's and stays. An Option without a mapping
    source pairs with an unmapped Option on every run, so it is updated in place and never removed. The options of a
    client class also resolve its own Option Definitions. An Option whose definition cannot be resolved, whose class
    has no row, or whose data the plugin refuses, is reported and does not stop the import. An Option whose values did
    not change has no entry.
    """
    server, parent = references.server, planned_set.parent
    if not planned_set.options:
        if parent is not None:
            mark_options_mapped(server, family, parent)
        return
    from django.contrib.contenttypes.models import ContentType

    ct = ContentType.objects.get_for_model(type(parent_obj))
    class_name = planned_set.class_name
    planned: list[_PlannedOption] = []
    paths = planned_set.paths(parent_path, family)
    for opt, key, path in zip(planned_set.options, planned_set.keys, paths, strict=True):
        definition = _resolve_option_definition(opt, family, references.definitions, capabilities, class_name)
        if isinstance(definition, _Unresolved):
            summary.record(definition.entry(family, Kind.OPTION, path))
            summary.warn(f"option {option_identity(opt, family)}: skipped. {definition.detail}")
            continue
        classes = references.classes.option_classes(opt.client_classes, path, summary)
        if classes is not None:
            space = opt.space or kea_paths.default_space(family)
            code = definition.code if definition is not None else opt.code
            source = key.source if key is not None else None
            planned.append(_PlannedOption(opt, path, space, code, definition, classes, source))
    mapped = [mapped_target(server, family, item.source) if item.source is not None else None for item in planned]
    adopts = parent is not None and not options_mapped(server, family, parent)
    # An Option without a source pairs on every run; one with a source only while its object adopts.
    pairing = [
        item for item, row in zip(planned, mapped, strict=True) if row is None and (item.source is None or adopts)
    ]
    unmapped = []
    if pairing:
        unmapped = list(
            _unlinked(_model("Option").objects.filter(assigned_object_type=ct, assigned_object_id=parent_obj.pk))
            .select_related("definition")
            .prefetch_related("client_classes")
            .order_by("pk")
        )
    paired = dict(zip(map(id, pairing), _paired_rows(pairing, unmapped), strict=True))
    # The adoption decisions hold before any write, so a write that fails leaves the adopted row mapped.
    with event_scope.atomic():
        for item in pairing:
            if item.source is not None and paired[id(item)] is not None:
                observe_mapping(server, family, paired[id(item)], item.source)
        if parent is not None:
            mark_options_mapped(server, family, parent)
    for item, row in zip(planned, mapped, strict=True):
        target = row if row is not None else paired.get(id(item))
        _write_option(item, target, parent_obj, ct, family, references, summary, capabilities)


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


def _declares(raw, transform) -> bool:
    """Return whether the Kea value *raw* holds a value after *transform*. A value it cannot convert counts."""
    try:
        return not _is_unset(raw if transform is None else transform(raw))
    except Exception:  # noqa: BLE001 (the value is reported, not converted)
        return True


def gated_values(
    obj, settings: dict, field_map: GatedFieldMap, capabilities: PluginCapabilities, summary, source: _Source
) -> dict:
    """Plan the gated settings fields of *obj* as :func:`_settings_fields` does, for each capability the plugin has.

    Without its capability a field is not planned, and a value that Kea declares for it is unsupported.
    """
    values: dict = {}
    for kea_key, attr, transform, capability in field_map:
        if capabilities.has(capability):
            values |= _settings_fields(obj, settings, ((kea_key, attr, transform),), summary, source)
        elif kea_key in settings and _declares(settings[kea_key], transform):
            path = kea_paths.setting(source.path, kea_key)
            detail = f"The installed DHCP plugin cannot hold {kea_key}."
            summary.record(unsupported(source.family, source.kind, path, capability, detail))
    return values


def _user_context_fields(
    obj, user_context: dict | None, capabilities: PluginCapabilities, summary, source: _Source, holder: str
) -> dict:
    """Plan the ``user_context`` field of *obj*, or report a declared user-context as unsupported without it."""
    if capabilities.has(Capability.USER_CONTEXT):
        return {"user_context": user_context if user_context is not None else _cleared(obj, "user_context")}
    if user_context is not None:
        path = kea_paths.setting(source.path, kea_paths.USER_CONTEXT)
        detail = f"The DHCP plugin has no user-context field on a {holder}."
        summary.record(unsupported(source.family, source.kind, path, Capability.USER_CONTEXT, detail))
    return {}


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
    values |= _user_context_fields(dhcp_server, planned.user_context, capabilities, summary, source, "DHCP server")
    values |= gated_values(dhcp_server, settings, GATED_SERVER_FIELDS, capabilities, summary, source)
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
            path = kea_paths.interface(family, entry)
            detail = _no_interface_detail(dhcp_server, name)
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
    source = _Source(intent.family, Kind.CLIENT_CLASS, path)
    fields |= _user_context_fields(obj, intent.user_context, capabilities, summary, source, "client class")
    fields.update(_settings_fields(obj, planned.settings, CLIENT_CLASS_FIELDS, summary, source))
    return fields


def _name_taken(kind: Kind, name: str, obj, dhcp_server, capabilities: PluginCapabilities) -> bool:
    """Return whether another row of *kind* holds *name* in the scope where the DHCP plugin keeps the names unique."""
    from ..models import MAPPING_KINDS

    others = _model(MAPPING_KINDS[kind][0]).objects.filter(name=name)
    if capabilities.has(Capability.NAME_PER_SERVER):
        others = others.filter(dhcp_server=dhcp_server)
    return (others.exclude(pk=obj.pk) if obj is not None else others).exists()


def _record_name_taken(
    summary: ImportSummary, family: int, kind: Kind, path: str, name: str, capabilities: PluginCapabilities
) -> None:
    label = KIND_LABELS[kind].lower()
    if capabilities.has(Capability.NAME_PER_SERVER):
        detail = f"Another {label} of this DHCP server holds the name {name!r}."
        entry = not_written(family, kind, path, Reason.NOT_IN_SCOPE, detail)
    else:
        detail = (
            f"Another {label} holds the name {name!r}. "
            f"The DHCP plugin needs each {label} name to be unique across all DHCP servers."
        )
        entry = unsupported(family, kind, path, Capability.NAME_PER_SERVER, detail)
    summary.record(entry)
    summary.warn(f"{label} {name}: {detail}")


def _upsert_named(
    server,
    dhcp_server,
    kind: Kind,
    name: str,
    family: int,
    options: PlannedOptions,
    summary: ImportSummary,
    capabilities: PluginCapabilities,
    *,
    write: Callable[[Any, bool], tuple[Any, Outcome | None]],
    adopt: Callable[[], Any],
    skip_children: Callable[[], None],
):
    """Get or create the row of the client class or Shared Network *name* through its mapping, and write it.

    *write(row, name_taken)* writes the row (``None``: a new one) and returns it with its outcome. A row that the
    mapping does not find can be *adopt*-ed. Another row that holds the name stops a new row, and a mapped row keeps
    its name. When no row is written, the DHCP Options and the other children (*skip_children*) are skipped. Return the
    row, or ``None``.
    """
    source = MappingSource.named(kind, name)
    path = source.path(family)
    try:
        with event_scope.atomic():
            obj = mapped_target(server, family, source)
            if obj is None:
                obj = adopt()
            name_taken = _name_taken(kind, name, obj, dhcp_server, capabilities)
            if obj is None and name_taken:
                _record_name_taken(summary, family, kind, path, name, capabilities)
                _skip_options(summary, family, path, options)
                skip_children()
                return None
            obj, outcome = write(obj, name_taken)
            observe_mapping(server, family, obj, source)
    except event_scope.EventDispatchError:
        raise
    except ManagedFieldsMismatch:
        raise
    except Exception as exc:  # noqa: BLE001 (one bad object must not abort the import)
        summary.record(write_failed(family, kind, path))
        summary.warn(f"{KIND_LABELS[kind].lower()} {name}: {exc}")
        _skip_options(summary, family, path, options)
        skip_children()
        return None
    if name_taken:
        _record_name_taken(summary, family, kind, kea_paths.setting(path, "name"), name, capabilities)
    if outcome is not None:
        summary.record(written(family, kind, path, outcome))
    return obj


def upsert_client_class(
    server,
    dhcp_server,
    planned: PlannedClientClass,
    definitions: CustomDefinitions,
    summary: ImportSummary,
    capabilities: PluginCapabilities,
):
    """Get/create the DHCP-plugin ``ClientClass`` for *planned* through its mapping, with its Option Definitions.

    The row takes the Kea name. Its DHCP Options are written after every class row exists (:func:`apply_plan`).
    """
    ClientClass = _model("ClientClass")
    intent = planned.intent
    path = kea_paths.client_class(intent.family, planned.key)

    def adopt():
        # Adopt a row that the released importer created before client classes had a mapping.
        released = ClientClass.objects.filter(name=_released_client_class_name(server, planned.key))
        return _unlinked(released).first()

    def write(obj, name_taken: bool):
        created = obj is None
        if created:
            obj = ClientClass()
        fields = _client_class_fields(obj, dhcp_server, planned, summary, path, capabilities, name_taken)
        return obj, _write_child(obj, created, fields, {}, capabilities)

    obj = _upsert_named(
        server,
        dhcp_server,
        Kind.CLIENT_CLASS,
        planned.key,
        intent.family,
        planned_options(planned, intent.family, definitions.declared),
        summary,
        capabilities,
        write=write,
        adopt=adopt,
        skip_children=lambda: _skip_class_definitions(definitions, planned, summary),
    )
    if obj is None:
        return None
    for planned_definition in planned.option_definitions:
        definitions.written[planned_definition.key] = _write_option_definition(
            definitions, planned_definition.key, intent.family, obj, summary, capabilities
        )
    return obj


def _shared_network_fields(
    obj, dhcp_server, planned: PlannedSharedNetwork, summary: ImportSummary, path: str, capabilities, name_taken: bool
) -> dict:
    """Plan the managed fields of one Shared Network. A Shared Network whose Kea name is taken keeps its name."""
    source = _Source(planned.intent.family, Kind.SHARED_NETWORK, path)
    return {
        "name": obj.name if name_taken else planned.key,
        "dhcp_server_id": dhcp_server.pk,
        **_settings_fields(obj, planned.settings, NETWORK_FIELDS, summary, source),
        **gated_values(obj, planned.settings, GATED_NETWORK_FIELDS, capabilities, summary, source),
        **_user_context_fields(obj, planned.intent.user_context, capabilities, summary, source, "Shared Network"),
    }


def upsert_shared_network(
    server,
    dhcp_server,
    planned: PlannedSharedNetwork,
    references: OptionReferences,
    summary: ImportSummary,
    capabilities: PluginCapabilities,
):
    """Get or create the DHCP plugin ``SharedNetwork`` of *planned* through its mapping, with its DHCP Options.

    The row takes the Kea name and no Prefix: a Kea Shared Network has none. Without the capability for an optional
    prefix the Shared Network is unsupported. Return the row, or ``None`` when it was not written.
    """
    intent = planned.intent
    path = kea_paths.shared_network(intent.family, planned.key)
    options = planned_options(planned, intent.family, references.definitions.declared)
    if not capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX):
        detail = "The DHCP plugin needs a Prefix for each Shared Network, and a Kea Shared Network has none."
        capability = Capability.SHARED_NETWORK_OPTIONAL_PREFIX
        summary.record(unsupported(intent.family, Kind.SHARED_NETWORK, path, capability, detail))
        _skip_options(summary, intent.family, path, options)
        return None

    def write(obj, name_taken: bool):
        created = obj is None
        if created:
            # The import never links a Prefix to a Shared Network; a Prefix that an operator sets stays.
            obj = _model("SharedNetwork")(prefix_id=None)
        fields = _shared_network_fields(obj, dhcp_server, planned, summary, path, capabilities, name_taken)
        relations = references.classes.relations(intent, path, Kind.SHARED_NETWORK, summary)
        relations["server_interfaces"] = _network_interface(
            dhcp_server, planned.settings.get(kea_paths.INTERFACE), path, Kind.SHARED_NETWORK, intent.family, summary
        )
        return obj, _write_child(obj, created, fields, relations, capabilities)

    obj = _upsert_named(
        server,
        dhcp_server,
        Kind.SHARED_NETWORK,
        planned.key,
        intent.family,
        options,
        summary,
        capabilities,
        write=write,
        adopt=lambda: None,
        skip_children=lambda: None,
    )
    if obj is not None:
        upsert_options(obj, options, intent.family, references, summary, path, capabilities)
    return obj


def _import_shared_networks(server, dhcp_server, plan: FamilyPlan, references: OptionReferences, summary, capabilities):
    """Write every Shared Network of *plan* before its Subnets. Return the row of each imported one by Kea name."""
    rows = {}
    for planned in plan.shared_networks:
        row = upsert_shared_network(server, dhcp_server, planned, references, summary, capabilities)
        if row is not None:
            rows[planned.key] = row
    return rows


def _subnet_name(server, planned: PlannedSubnet, network: IPNetworkValue) -> str:
    """Build a globally-unique name (NetBoxDHCPModelMixin requires unique ``name``)."""
    family = planned.intent.family
    if planned.key is not None:
        return _synthesized_name(server.name, f" DHCPv{family} subnet {planned.key}")
    return _synthesized_name(server.name, f" DHCPv{family} {network}")


def _pool_name(subnet_obj, pool_intent) -> str:
    """Build a unique pool name scoped to its parent subnet's (unique) name."""
    return _synthesized_name(subnet_obj.name, f" pool {pool_intent.pool}")


def _pd_pool_name(subnet_obj, key: PDPoolKey) -> str:
    """Build a unique PD Pool name scoped to its parent subnet's (unique) name."""
    return _synthesized_name(subnet_obj.name, f" pd pool {key.prefix} delegated /{key.delegated_length}")


def _reservation_name(scope_name: str, reservation: Reservation) -> str:
    """Build a unique reservation name scoped to its parent's (unique) name."""
    identity = reservation.identity
    return _synthesized_name(scope_name, f" {identity_text(identity.identifier_type, identity.value)}")


def _served_by(dhcp_server) -> Q:
    """Return the Subnets of *dhcp_server*: its own, and the members of its Shared Networks."""
    return Q(dhcp_server=dhcp_server) | Q(shared_network__dhcp_server=dhcp_server)


def upsert_subnet(
    server,
    dhcp_server,
    planned: PlannedSubnet,
    summary: ImportSummary,
    claims: ClaimResult,
    renumbered: bool,
    capabilities: PluginCapabilities,
    classes: ClassReferences,
    shared_network,
    keep_membership: bool,
):
    """Get/create the DHCP-plugin ``Subnet`` for *planned*, tracked via ``KeaDhcpLink`` by its key.

    *renumbered* tells that :func:`settle_subnet_ids` gave the mapped row its Kea subnet ID in this run. A member of
    the imported *shared_network* belongs to it. With *keep_membership*, a stored Subnet keeps its parent. Else the
    Subnet belongs to *dhcp_server*: the DHCP plugin holds one of the two. Returns the ``netbox_dhcp.Subnet``
    instance, or ``None`` on error or for an unmapped row that it keeps.
    """
    Subnet = _model("Subnet")
    intent = planned.intent
    path = subnet_path(planned)
    source = _Source(intent.family, Kind.SUBNET, path)
    mapping = MappingSource.subnet(planned.key) if planned.key is not None else None

    existing = mapped_target(server, intent.family, mapping) if mapping is not None else None

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
            if (
                mapping is None
                and _unlinked(Subnet.objects.filter(_served_by(dhcp_server), prefix=prefix_obj)).exists()
            ):
                # A Subnet without a Kea subnet ID has no mapping identity. An unmapped Subnet stays as it is.
                _keep_unmapped(summary, intent.family, Kind.SUBNET, path)
                return None
            subnet_obj = existing if existing is not None else Subnet(name=_subnet_name(server, planned, network))
            fields = {
                "prefix_id": prefix_obj.pk,
                **_subnet_parent(existing, dhcp_server, shared_network, keep_membership),
                # settle_subnet_ids gave a mapped row its Kea subnet ID. Without one, the plugin numbers a new Subnet.
                "subnet_id": planned.key if planned.key is not None else subnet_obj.subnet_id,
                **_settings_fields(subnet_obj, planned.settings, NETWORK_FIELDS, summary, source),
                **gated_values(subnet_obj, planned.settings, GATED_SUBNET_FIELDS, capabilities, summary, source),
                **_user_context_fields(subnet_obj, intent.user_context, capabilities, summary, source, "Subnet"),
            }
            wanted = classes.relations(intent, path, Kind.SUBNET, summary)
            wanted["server_interfaces"] = _network_interface(
                dhcp_server, planned.settings.get(kea_paths.INTERFACE), path, Kind.SUBNET, intent.family, summary
            )
            outcome = _write_child(subnet_obj, existing is None, fields, wanted, capabilities)
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

    if outcome is None and renumbered:
        outcome = Outcome.UPDATED
    if outcome is not None:
        summary.record(written(intent.family, Kind.SUBNET, path, outcome))
    return subnet_obj


def _subnet_parent(existing, dhcp_server, shared_network, keep_membership: bool) -> dict:
    """Return the parent fields of a Subnet: its imported Shared Network, its stored parent, or *dhcp_server*."""
    if shared_network is not None:
        return {"dhcp_server_id": None, "shared_network_id": shared_network.pk}
    if keep_membership and existing is not None:
        return {"dhcp_server_id": existing.dhcp_server_id, "shared_network_id": existing.shared_network_id}
    return {"dhcp_server_id": dhcp_server.pk, "shared_network_id": None}


def _network_interface(dhcp_server, name, path: str, kind: Kind, family: int, summary: ImportSummary) -> set[int]:
    """Return the DHCP server interface that the Kea ``interface`` of the Subnet or Shared Network at *path* names.

    A name that matches no interface of *dhcp_server* has an entry. The import creates no interface.
    """
    if not name:
        return set()
    found = set(dhcp_server.interfaces.filter(name=name).values_list("pk", flat=True))
    if not found:
        entry = not_written(
            family,
            kind,
            kea_paths.setting(path, kea_paths.INTERFACE),
            Reason.NO_MATCHING_INTERFACE,
            _no_interface_detail(dhcp_server, name),
        )
        summary.record(entry)
    return found


def _no_interface_detail(dhcp_server, name: str) -> str:
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


def _report_inherited(summary: ImportSummary, planned: PlannedSubnet, capabilities: PluginCapabilities) -> None:
    """Record each value that a Subnet inherits from its Shared Network, which this run did not import."""
    path = subnet_path(planned)
    name = planned.intent.shared_network
    if capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX):
        detail = f"Kea applies the value of Shared Network {name}, which was not imported."
    else:
        detail = f"Kea applies the value of Shared Network {name}, which the installed DHCP plugin cannot hold."
    for key in planned.inherited:
        entry = not_written(
            planned.intent.family,
            Kind.SUBNET,
            kea_paths.setting(path, key),
            Reason.INHERITED_FROM_SHARED_NETWORK,
            detail,
        )
        summary.record(entry)


def _skip_subnet_children(
    summary: ImportSummary,
    planned: PlannedSubnet,
    declared: Mapping[OptionDefinitionKey, OptionDefIntent],
    taken: SubnetIdTaken | None = None,
) -> None:
    """Record the DHCP Options, Pools and PD Pools of a Subnet that was not imported.

    A *taken* ID is also why its Pools and PD Pools were not.
    """
    family, parent_path = planned.intent.family, subnet_path(planned)
    _skip_options(summary, family, parent_path, planned_options(planned, family, declared))
    children = [
        (Kind.POOL, pool_path(parent_path, pool, family), planned_options(pool, family, declared))
        for pool in planned.pools
    ]
    children += [
        (Kind.PD_POOL, pd_pool_path(parent_path, pool.key), planned_options(pool, family, declared))
        for pool in planned.pd_pools
    ]
    for kind, path, options in children:
        if taken is None:
            summary.record(not_written(family, kind, path, Reason.PARENT_NOT_IMPORTED))
        else:
            summary.record(taken.entry(family, kind, path))
        _skip_options(summary, family, path, options)


def subnet_path(planned: PlannedSubnet) -> str:
    """Return the Kea path of a planned Subnet."""
    return kea_paths.subnet(planned.intent.family, planned.key, planned.intent.cidr)


def pool_path(parent_path: str, planned: Planned[PoolKey | None, PoolIntent], family: int) -> str:
    """Return the Kea path of a planned Pool of the Subnet at *parent_path*: the path of its source, if it has one."""
    source = planned.key.source if planned.key is not None else None
    return source.path(family) if source is not None else kea_paths.pool(parent_path, planned.intent.pool)


def pd_pool_path(parent_path: str, key: PDPoolKey) -> str:
    """Return the Kea path of a planned delegated-prefix Pool of the Subnet at *parent_path*."""
    return kea_paths.pd_pool(parent_path, str(key.prefix), key.delegated_length)


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
        scope = scope.filter(_served_by(dhcp_server))
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
                detail = _class_not_imported(name)
                summary.record(not_written(self.family, kind, path, Reason.PARENT_NOT_IMPORTED, detail))
            else:
                detail = f"The DHCP plugin has no row for {name}, a class that Kea's client-classes does not define."
                summary.record(not_written(self.family, kind, path, Reason.NO_PLUGIN_HOME, detail))
        return found

    def option_classes(self, names: tuple[str, ...], path: str, summary: ImportSummary) -> frozenset[int] | None:
        """Return the imported client class of each name of the DHCP Option at *path*, or ``None`` to skip it.

        An option whose class has no row is not imported: without the class it would reach more clients.
        """
        missing = next((name for name in names if name not in self.imported), None)
        if missing is None:
            return frozenset(self.imported[name] for name in names)
        if missing in self.defined:
            cause = _class_not_imported(missing)
        else:
            cause = f"The DHCP plugin has no row for {missing}, a class that Kea's client-classes does not define."
        detail = f"{cause} Without the class the option would reach more clients."
        summary.record(not_written(self.family, Kind.OPTION, path, Reason.PARENT_NOT_IMPORTED, detail))
        return None

    def relations(self, intent, parent_path: str, kind: Kind, summary: ImportSummary) -> dict[str, set[int]]:
        """Return the imported client classes of the class lists of the Shared Network, Subnet or Pool *intent*.

        A list that is not valid (``None``) is left out, so its relation stays as it is.
        """
        lists = (
            ("client_classes", kea_paths.CLIENT_CLASSES, intent.client_classes),
            ("evaluate_additional_classes", kea_paths.EVALUATE_ADDITIONAL_CLASSES, intent.evaluate_additional_classes),
        )
        return {
            relation: self.resolve(names, parent_path, key, kind, summary)
            for relation, key, names in lists
            if names is not None
        }


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
    """Get or create one Pool and set its managed fields. Return it with its outcome (``None`` when unchanged).

    The row is ``None`` for an unmapped Pool that it keeps (:func:`_keep_unmapped`).
    """
    Pool = _model("Pool")
    intent = planned_pool.intent
    source = planned_pool.key.source
    same_range = Pool.objects.filter(subnet=subnet_obj, ip_range=range_obj)
    if source is None:
        if same_range.exists():
            # A Subnet without a Kea subnet ID gives its Pools no mapping identity. An unmapped Pool stays as it is.
            _keep_unmapped(summary, family, Kind.POOL, path)
            return None, None
        pool_obj = None
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
        **_user_context_fields(pool_obj, intent.user_context, capabilities, summary, values, "Pool"),
    }
    outcome = _write_child(pool_obj, created, fields, classes, capabilities)
    if source is not None:
        observe_mapping(server, family, pool_obj, source)
    return pool_obj, outcome


def _write_child(row, created: bool, fields: dict, wanted: dict[str, set[int]], capabilities) -> Outcome | None:
    """Write the managed fields and relations of a DHCP plugin *row*. Return its outcome.

    The outcome is ``None`` for a row that did not change.
    """
    relations = _relation_changes(row, wanted)
    changes: dict = {}
    if created:
        _create_row(row, fields, capabilities)
    elif changes := _managed_changes(row, fields, capabilities):
        _save_changes(row, changes)
    elif relations:
        row.snapshot()
    for name, pks in relations.items():
        getattr(row, name).set(pks)
    if created:
        return Outcome.CREATED
    return Outcome.UPDATED if changes or relations else None


def upsert_pools(
    server,
    subnet_obj,
    planned: PlannedSubnet,
    summary: ImportSummary,
    references: OptionReferences,
    claims,
    capabilities: PluginCapabilities,
) -> None:
    """Get/create DHCP-plugin ``Pool`` rows (and their options) for each planned Pool of *planned*."""
    intent = planned.intent
    parent_path = subnet_path(planned)
    for planned_pool in planned.pools:
        pool_intent = planned_pool.intent
        path = pool_path(parent_path, planned_pool, intent.family)
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
                    classes = references.classes.relations(pool_intent, path, Kind.POOL, summary)
                    pool_obj, outcome = _upsert_pool(
                        server,
                        intent.family,
                        subnet_obj,
                        range_obj,
                        planned_pool,
                        classes,
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
            _skip_options(summary, intent.family, path, pool_intent.options)
            continue
        if range_obj is None:
            summary.record(_unusable_pool(intent.family, path, planned_pool.key, result))
            summary.warn(f"pool {pool_intent.pool} in {intent.cidr}: unusable range, skipped")
            _skip_options(summary, intent.family, path, pool_intent.options)
            continue
        options = planned_options(planned_pool, intent.family, references.definitions.declared)
        if pool_obj is None:
            _skip_options(summary, intent.family, path, options)
            continue
        if outcome is not None:
            summary.record(written(intent.family, Kind.POOL, path, outcome))
        upsert_options(pool_obj, options, intent.family, references, summary, path, capabilities)


def _pd_pool_prefixes(claims: ClaimResult, planned: Planned[PDPoolKey, PDPoolIntent], summary: ImportSummary) -> tuple:
    """Return the claimed NetBox Prefixes of a PD Pool: its prefix and its excluded prefix (``None`` without one).

    Raise when a claim gave no Prefix.
    """
    found: list = []
    for network in (planned.key.prefix, planned.intent.excluded_prefix):
        if network is None:
            found.append(None)
            continue
        result = claims.prefixes[str(network)]
        if result.prefix is None:
            raise RuntimeError(f"The Prefix {network} could not be claimed")
        if result.outcome in {"conflict", "disagreement"}:
            summary.warn(f"pd pool prefix {network}: IPAM ownership {result.outcome}, Prefix left unchanged")
        found.append(result.prefix)
    return tuple(found)


def _upsert_pd_pool(
    server,
    family: int,
    subnet_obj,
    prefixes: tuple,
    planned: Planned[PDPoolKey, PDPoolIntent],
    classes: dict[str, set[int]],
    summary: ImportSummary,
    path: str,
    capabilities: PluginCapabilities,
) -> tuple:
    """Get or create one PD Pool and set its managed fields. Return it with its outcome (``None`` when unchanged).

    It adopts no unmapped row: no release imported PD Pools before, so such a row is an operator's. The row is
    ``None`` for an unmapped PD Pool that it keeps (:func:`_keep_unmapped`). The DHCP plugin checks the row when it
    saves it, so a PD Pool that the plugin cannot hold raises ``ValidationError``.
    """
    PDPool = _model("PDPool")
    key, intent = planned.key, planned.intent
    prefix_obj, excluded_obj = prefixes
    source = key.source
    if source is None:
        same = PDPool.objects.filter(subnet=subnet_obj, prefix=prefix_obj, delegated_length=key.delegated_length)
        if same.exists():
            # A Subnet without a Kea subnet ID gives its PD Pools no mapping identity. An unmapped one stays as it is.
            _keep_unmapped(summary, family, Kind.PD_POOL, path)
            return None, None
        row = None
    else:
        row = mapped_target(server, family, source)
    created = row is None
    if row is None:
        row = PDPool(name=_pd_pool_name(subnet_obj, key))
    values = _Source(family, Kind.PD_POOL, path)
    fields = {
        "subnet_id": subnet_obj.pk,
        "prefix_id": prefix_obj.pk,
        "delegated_length": key.delegated_length,
        "excluded_prefix_id": excluded_obj.pk if excluded_obj is not None else None,
        "pool_id": _declared_value(row, "pool_id", kea_paths.POOL_ID, intent.pool_id, None, summary, values),
        **_user_context_fields(row, intent.user_context, capabilities, summary, values, "delegated-prefix Pool"),
    }
    outcome = _write_child(row, created, fields, classes, capabilities)
    if source is not None:
        observe_mapping(server, family, row, source)
    return row, outcome


def upsert_pd_pools(
    server,
    subnet_obj,
    planned: PlannedSubnet,
    summary: ImportSummary,
    references: OptionReferences,
    claims: ClaimResult,
    capabilities: PluginCapabilities,
) -> None:
    """Get/create DHCP-plugin ``PDPool`` rows (and their options) for each planned delegated-prefix Pool of *planned*.

    A PD Pool that the DHCP plugin refuses is unsupported with the plugin's reason, and its options are skipped.
    """
    family, parent_path = planned.intent.family, subnet_path(planned)
    for planned_pd_pool in planned.pd_pools:
        key, intent = planned_pd_pool.key, planned_pd_pool.intent
        path = pd_pool_path(parent_path, key)
        options = planned_options(planned_pd_pool, family, references.definitions.declared)
        try:
            with event_scope.atomic():
                prefixes = _pd_pool_prefixes(claims, planned_pd_pool, summary)
                classes = references.classes.relations(intent, path, Kind.PD_POOL, summary)
                row, outcome = _upsert_pd_pool(
                    server, family, subnet_obj, prefixes, planned_pd_pool, classes, summary, path, capabilities
                )
        except event_scope.EventDispatchError:
            raise
        except ManagedFieldsMismatch:
            raise
        except ValidationError as exc:
            detail = f"The DHCP plugin refuses the delegated-prefix Pool: {' '.join(exc.messages)}"
            summary.record(not_written(family, Kind.PD_POOL, path, Reason.PLUGIN_GAP, detail))
            summary.warn(f"pd pool {key.prefix} in {planned.intent.cidr}: {detail}")
            _skip_options(summary, family, path, options)
            continue
        except Exception as exc:  # noqa: BLE001 — one bad PD Pool must not abort the import
            summary.record(write_failed(family, Kind.PD_POOL, path))
            summary.warn(f"pd pool {key.prefix} in {planned.intent.cidr}: {exc}")
            _skip_options(summary, family, path, options)
            continue
        if row is None:
            _skip_options(summary, family, path, options)
            continue
        if outcome is not None:
            summary.record(written(family, Kind.PD_POOL, path, outcome))
        upsert_options(row, options, family, references, summary, path, capabilities)


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
    references: OptionReferences,
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
    ``ipam.IPAddress``/``dcim.MACAddress`` rows the lease/reservation sync owns. The client classes refer to the
    classes that the same run imported. The delegated and excluded Prefixes attach after their claim
    (:func:`_attach_delegated_prefixes`).

    Return the row and its state before the write (``None`` for a new row), or ``None`` after a failed write.
    """
    HostReservation = _model("HostReservation")
    reservation, key = planned.intent, planned.key
    scope = reservation.scope.subnet.cidr if isinstance(reservation.scope, InSubnetReservationScope) else "global"
    path = reservation_path(key, reservation.family)
    options = planned_options(planned, reservation.family, references.definitions.declared)

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
            classes = references.classes.resolve(
                reservation.client_classes, path, kea_paths.CLIENT_CLASSES, Kind.RESERVATION, summary
            )
            linked = mapped_target(server, reservation.family, key.source)
            # Adopt a row that an import made before its Reservation had a mapping (a Global one: before the
            # mapping carried the family), so an upgrade maps that row instead of duplicating it.
            obj = linked if linked is not None else _find_reservation(_unlinked(base), reservation, mac_obj)
            created = obj is None
            if created:
                related: dict[str, dict[int, Any]] = {name: {} for name in _RESERVATION_RELATIONS}
                before = None
                obj = HostReservation(name=_reservation_name(scope_name, reservation))
            else:
                # The relation reads give the state before the write and also drive the write.
                related = _reservation_relations(obj)
                before = _reservation_state(
                    obj, {name: frozenset(rows) for name, rows in related.items()}, capabilities
                )
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
                **_reservation_boot_values(reservation),
                **_user_context_fields(
                    obj,
                    reservation.user_context,
                    capabilities,
                    summary,
                    _Source(reservation.family, Kind.RESERVATION, path),
                    "Reservation",
                ),
            }
            if created:
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
            addresses = set(related["ipv6_addresses"])
            wanted = {address.pk for address in ipv6_ips}
            obj.ipv6_addresses.remove(*(addresses - wanted))
            obj.ipv6_addresses.add(*(wanted - addresses))
            if classes != set(related["client_classes"]):
                obj.client_classes.set(classes)
            # Drop obsolete references before the delegated phase evaluates stale links.
            for relation, networks in _reported_prefixes(reservation).items():
                current = related[relation]
                getattr(obj, relation).remove(
                    *(pk for pk, prefix in current.items() if ipaddress.ip_network(str(prefix)) not in networks)
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
        _skip_options(summary, reservation.family, path, options)
        return None
    upsert_options(obj, options, reservation.family, references, summary, path, capabilities)
    return obj, before


def reservation_path(key: ReservationKey, family: int) -> str:
    """Return the Kea path of a keyed Reservation of *family*."""
    subnet_id = key.subnet_id if isinstance(key, InSubnetReservationKey) else None
    return kea_paths.reservation(family, subnet_id, key.identifier_type, key.value)


def _reservation_boot_values(reservation: Reservation) -> dict:
    """Return the DHCPv4 boot fields of a DHCP plugin Reservation. Kea's unset value (and DHCPv6) is ``None``."""
    return {
        "next_server": str(reservation.next_server) if reservation.next_server is not None else None,
        "server_hostname": reservation.server_hostname or None,
        "boot_file_name": reservation.boot_file_name or None,
    }


def _reported_prefixes(reservation: Reservation) -> dict[str, tuple]:
    """Return the networks of each Prefix relation of a DHCP plugin Reservation: delegated and excluded prefixes."""
    return {
        "ipv6_prefixes": reservation.delegated_prefixes,
        "excluded_ipv6_prefixes": tuple(pair.excluded for pair in reservation.excluded_prefixes),
    }


# The managed many-to-many relations of a DHCP plugin Reservation.
_RESERVATION_RELATIONS = tuple(managed.name for managed in MANAGED_FIELDS["HostReservation"] if managed.relation)


def _reservation_relations(obj) -> dict[str, dict[int, Any]]:
    """Read each managed relation of the DHCP plugin Reservation *obj*: each related pk, with its Prefix if it has one.

    One query for each relation.
    """
    related: dict[str, dict[int, Any]] = {}
    for name in _RESERVATION_RELATIONS:
        rows = getattr(obj, name)
        if rows.model._meta.label == "ipam.Prefix":
            related[name] = dict(rows.values_list("pk", "prefix"))
        else:
            related[name] = dict.fromkeys(rows.values_list("pk", flat=True))
    return related


def _reservation_state(obj, relations: dict[str, frozenset[int]], capabilities: PluginCapabilities) -> tuple:
    """Return the name, the managed values and the managed relations of a DHCP plugin Reservation.

    It tells an update from an unchanged row.
    """
    scalars = tuple(
        getattr(obj, obj._meta.get_field(managed.name).attname)
        for managed in managed_fields("HostReservation", capabilities)
        if not managed.relation
    )
    return obj.name, scalars, relations


def _relation_states(objs) -> dict[int, dict[str, frozenset[int]]]:
    """Read the managed relations of every row in one query for each relation, keyed by row."""
    pks = [obj.pk for obj in objs]
    if not pks:
        # Without the DHCP plugin no row is imported, and its model does not exist.
        return {}
    states: dict[int, dict[str, set[int]]] = {pk: {name: set() for name in _RESERVATION_RELATIONS} for pk in pks}
    rows = _model("HostReservation").objects.filter(pk__in=pks)
    for name in _RESERVATION_RELATIONS:
        for pk, related in rows.values_list("pk", name):
            if related is not None:
                states[pk][name].add(related)
    return {pk: {name: frozenset(related) for name, related in state.items()} for pk, state in states.items()}


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
    references: OptionReferences,
    summary: ImportSummary,
    *,
    family: int,
    adoption_servers: tuple[int, ...],
    capabilities: PluginCapabilities,
    subnet_ids: SubnetIdSettlement | None = None,
) -> DelegatedPrefixStep | None:
    """Import valid typed records and report quarantined Snapshot records.

    A Global Reservation may adopt an unmapped row of a DHCP server in *adoption_servers*. An In-Subnet
    Reservation of a Subnet that *subnet_ids* reports as taken or failed is not imported.

    Return the delegated-prefix step of the imported Reservations for :func:`reconcile_delegated_prefixes`, or
    ``None`` when no Snapshot was read or their Prefixes could not be attached.
    """
    from ..ipam_reconciliation import DelegatedPrefixClaim, DelegatedPrefixPhase, claim

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
        return None
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
            references,
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
    records = [planned.intent for planned, _, _ in imported]
    networks = dict.fromkeys(
        network for record in records for each in _reported_prefixes(record).values() for network in each
    )
    step: DelegatedPrefixStep | None = None
    try:
        with event_scope.atomic():
            prefix_claims = claim(
                server, snapshot.family, [DelegatedPrefixClaim(network) for network in networks], force=False
            )
            _attach_delegated_prefixes([(planned.intent, obj) for planned, obj, _ in imported], prefix_claims, summary)
        failed = frozenset(address for address, result in prefix_claims.prefixes.items() if result.outcome == "error")
        step = DelegatedPrefixStep(DelegatedPrefixPhase(records, observation.cutoff, complete and not failed), failed)
        if complete:
            summary.ownership.completed_sources.add("reservation")
        else:
            summary.ownership.incomplete.add("reservation")
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
    relations = _relation_states([obj for _, obj, _ in imported])
    for planned, obj, before in imported:
        if before is None or before != _reservation_state(obj, relations[obj.pk], capabilities):
            outcome = Outcome.CREATED if before is None else Outcome.UPDATED
            summary.record(written(family, Kind.RESERVATION, reservation_path(planned.key, family), outcome))
    return step


@dataclass(frozen=True)
class DelegatedPrefixStep:
    """The delegated-prefix phase of the imported Reservations, and the Prefixes whose claim failed before attachment."""

    phase: DelegatedPrefixPhase
    failed: frozenset[str]


def reconcile_delegated_prefixes(
    server, family: Family, step: DelegatedPrefixStep, unobserved: set[Kind], summary: ImportSummary
) -> None:
    """Link the delegated and excluded Prefixes of the imported Reservations again, and drop the stale links (ADR 0006).

    It runs after :func:`remove_stale_objects`: a removed Reservation no longer uses its Prefixes, so the cleanup can
    deprecate them. A Reservation that Kea no longer reports and that is still in NetBox (*unobserved*, see
    :func:`unobserved_kinds`) still uses its Prefixes, so the phase is then not complete and drops no link. A Prefix
    whose claim failed before attachment counts as one error, also when this claim of it succeeds.
    """
    from ..ipam_reconciliation import reconcile

    complete = step.phase.complete and Kind.RESERVATION not in unobserved
    report = reconcile(server, family, [replace(step.phase, complete=complete)])
    _record_report(summary, report)
    summary.ownership_errors += sum(report.prefixes[address].outcome != "error" for address in step.failed)
    for address in sorted(report.conflicts):
        summary.warn(f"delegated prefix {address}: IPAM ownership conflict, Prefix left unchanged")


def _attach_delegated_prefixes(imported, claims: ClaimResult, summary: ImportSummary) -> None:
    """Attach each imported Reservation's delegated and excluded Prefixes, and keep the old ones when a claim failed."""
    for reservation, obj in imported:
        reported = _reported_prefixes(reservation)
        if any(claims.prefixes[str(prefix)].outcome == "error" for each in reported.values() for prefix in each):
            summary.warn(
                f"reservation {reservation.identity.value}: delegated or excluded Prefix claim failed; "
                "existing reported Prefix attachments were retained"
            )
            continue
        for relation, networks in reported.items():
            results = (claims.prefixes[str(prefix)] for prefix in networks)
            getattr(obj, relation).set([result.prefix for result in results if result.prefix is not None])


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
    """Group every planned Subnet, Pool and delegated-prefix Pool prefix before claiming any of the three sources."""
    from ..ipam_reconciliation import PDPoolClaim, PoolClaim, SubnetClaim, claim

    subnets: list[SubnetClaim] = []
    pools: list[PoolClaim] = []
    for planned in plan.subnets:
        try:
            network = subnet_network(planned.intent.cidr, planned.intent.family)
        except ValueError:
            continue
        subnets.append(SubnetClaim(network))
        pools.extend(PoolClaim(pool.key.range, network) for pool in planned.pools if pool.key is not None)
    prefixes = [PDPoolClaim(prefix) for prefix in pd_pool_prefixes(plan)]
    return (
        claim(server, plan.family, subnets, force=False),
        claim(server, plan.family, pools, force=False),
        claim(server, plan.family, prefixes, force=False),
    )


def pd_pool_prefixes(plan: FamilyPlan) -> list:
    """Return the prefix and the excluded prefix of each planned delegated-prefix Pool, each once, in plan order."""
    networks = (
        network
        for subnet in plan.subnets
        for pd_pool in subnet.pd_pools
        for network in (pd_pool.key.prefix, pd_pool.intent.excluded_prefix)
        if network is not None
    )
    return list(dict.fromkeys(networks))


def reconcile_pd_pool_prefixes(server, plan: FamilyPlan, unobserved: set[Kind], summary: ImportSummary) -> None:
    """Link the Prefixes of every planned delegated-prefix Pool again, and drop the stale ``pd-pool`` links (ADR 0006).

    It runs after :func:`remove_stale_objects`: a removed PD Pool no longer uses its Prefix, so the cleanup can
    deprecate it. Only a Complete observation of delegated-prefix Pools, with a cutoff, drops a link. A PD Pool that
    Kea no longer reports and that is still in NetBox (*unobserved*) still uses its Prefixes, so the phase is then not
    complete.
    """
    from ..ipam_reconciliation import PDPoolPhase, reconcile

    complete = observations(plan)[Kind.PD_POOL].complete and Kind.PD_POOL not in unobserved
    report = reconcile(server, plan.family, [PDPoolPhase(pd_pool_prefixes(plan), plan.cutoff, complete)])
    _record_report(summary, report)


def _record_report(summary: ImportSummary, report: SyncReport) -> None:
    """Add the ownership work, the errors and the owner disagreements of one ``reconcile`` call to *summary*."""
    summary.ownership.merge(report)
    summary.ownership_errors += report.errors + report.prefix_errors
    summary.owner_disagreements += len(report.disagreements)


def unobserved_kinds(server, plan: FamilyPlan) -> set[Kind]:
    """Return the kinds that still have a mapped DHCP plugin row whose Kea source *plan* does not observe.

    After :func:`remove_stale_objects`, such a row stayed: its kind was not observed in full, its removal failed or
    was blocked, another writer confirmed its mapping after the cutoff, or the plan has no cutoff.
    """
    observed = observations(plan)
    return {
        kind
        for kind, rows in mapped_rows(server, plan.family).items()
        if any(source not in observed[kind].sources for source in rows)
    }


# ─────────────────────────────────────────────────────────────────────────────
# Stale DHCP Import Objects: removal after a Complete observation of their kind
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _StaleRow:
    """A mapped row whose Kea source the run did not observe."""

    source: MappingSource
    # A DHCP plugin model instance; the plugin is optional, so its models have no static type here.
    target: Any


def _row_key(obj) -> tuple:
    return obj._meta.concrete_model, obj.pk


def _goes_with_parent(model) -> bool:
    """Return whether rows of *model* go with a deleted parent: models outside the DHCP plugin, Options, through rows.

    A mapped Option goes only when it is stale itself (:func:`_removal_plan`).
    """
    return model._meta.app_label != PLUGIN_APP_LABEL or model._meta.auto_created or model is _model("Option")


def _mapped_option_keys() -> frozenset[tuple]:
    """Return the row key of each Option that a mapping holds, of any Server and family.

    An operator can assign the Option of another Server to an object of this one.
    """
    from ..models import KeaDhcpLink

    links = KeaDhcpLink.objects.filter(kind=Kind.OPTION.value)
    return frozenset((_model("Option"), pk) for pk in links.values_list("object_id", flat=True))


def _counted_rows(rows: list) -> str:
    """Return the number of *rows* of each model, for the detail of an entry."""
    models = Counter(row._meta.concrete_model for row in rows)
    return ", ".join(
        counted(count, model._meta.verbose_name, model._meta.verbose_name_plural) for model, count in models.items()
    )


class _FootprintCollector(Collector):
    """A delete collector that leaves out the Options that the removal deletes before its row."""

    def __init__(self, using: str, deleted_first: frozenset[int]) -> None:
        super().__init__(using=using)
        self.deleted_first = deleted_first

    def related_objects(self, related_model, related_fields, objs):
        """Return the related rows of *objs*, without the Options that go first."""
        rows = super().related_objects(related_model, related_fields, objs)
        return rows.exclude(pk__in=self.deleted_first) if related_model is _model("Option") else rows


def _collected(collector: Collector) -> list:
    rows = [obj for objects in collector.data.values() for obj in objects]
    rows.extend(obj for queryset in collector.fast_deletes for obj in queryset)
    return rows


def _owner_key(option) -> tuple:
    """Return the row key of the object that *option* is assigned to."""
    return option.assigned_object_type.model_class()._meta.concrete_model, option.assigned_object_id


def _option_goes_with(option, stale: dict, mapped_options: frozenset[tuple]) -> tuple | None:
    """Return the row whose removal takes *option*: the Option when it is stale, its owner when it is unmapped.

    Return ``None`` for a mapped Option that the run keeps: no removal takes it.
    """
    own = _row_key(option)
    if own in stale:
        return own
    return None if own in mapped_options else _owner_key(option)


def _class_relation_rows(target) -> list:
    """Return the DHCP plugin rows that name *target* in a many-to-many relation, such as ``client_classes``."""
    rows: dict[tuple, Any] = {}
    for model in apps.get_app_config(PLUGIN_APP_LABEL).get_models():
        for relation in model._meta.many_to_many:
            if relation.related_model is target._meta.concrete_model:
                rows.update((_row_key(row), row) for row in model.objects.filter(**{relation.name: target}))
    return list(rows.values())


@dataclass(frozen=True)
class _RemovalPlan:
    """The read-only plan of the delete of one stale row, with its evidence as row keys."""

    # The Options to delete before the row: each uses a definition that the delete removes, and it or its owner goes.
    options_first: tuple = ()
    # The other stale rows that the delete removes.
    cascaded: frozenset = frozenset()
    # The other stale rows that must go too, or the delete would remove or change a kept row: the rows that it
    # removes, the rows that name it in a class relation, and the stale Options, or the owners, that go with it.
    relies_on: frozenset = frozenset()
    # Why the row stays whatever else the run removes, for its entry. Empty when only kept stale rows can block it.
    blocked: str = ""


def _removal_plan(target, stale: dict, mapped_options: frozenset[tuple]) -> _RemovalPlan:
    """Plan the delete of the stale row *target* against every *stale* row of the run. It writes nothing.

    A row outside *stale* is kept: when the delete would remove it, when it uses a row that the delete removes, or when
    it names the row in a many-to-many relation (without it, that row would reach more clients), the row stays. Each
    stale row with such a part is evidence in ``relies_on``. A stale Option goes alone, and an unmapped Option goes with
    the object that it is assigned to. A mapped Option of *mapped_options* outside *stale* is kept.
    """
    Option = _model("Option")
    own = _row_key(target)
    first: dict[int, Any] = {}
    while True:
        collector = _FootprintCollector(target._state.db, frozenset(first))
        try:
            collector.collect([target])
            break
        except ProtectedError as error:
            removed = {own, *(_row_key(obj) for obj in _collected(collector)), *stale}
            protected = list(error.protected_objects)
            going = [
                obj
                for obj in protected
                if isinstance(obj, Option) and _option_goes_with(obj, stale, mapped_options) in removed
            ]
            if len(going) < len(protected):
                users = [obj for obj in protected if obj not in going]
                return _RemovalPlan(blocked=f"It is kept while it is in use by {_counted_rows(users)}.")
            first.update((obj.pk, obj) for obj in going)
    rows = _collected(collector)
    footprint = {own, *(_row_key(obj) for obj in rows)}
    # Counts only: any viewer of the Server reads the run, without permission on the rows.
    kept = [
        obj
        for obj in rows
        if _row_key(obj) not in stale
        and _row_key(obj) != own
        and (_row_key(obj) in mapped_options or not _goes_with_parent(obj._meta.concrete_model))
    ]
    if kept:
        return _RemovalPlan(blocked=f"It is kept because its removal would also remove {_counted_rows(kept)}.")
    cascaded = frozenset(_row_key(obj) for obj in rows if _row_key(obj) != own and _row_key(obj) in stale)
    relies_on = {*cascaded, *(_option_goes_with(obj, stale, mapped_options) for obj in first.values())}
    users = []
    for obj in _class_relation_rows(target):
        goes_with = _option_goes_with(obj, stale, mapped_options) if isinstance(obj, Option) else _row_key(obj)
        if goes_with is not None and (goes_with in stale or goes_with in footprint):
            relies_on.add(goes_with)
        else:
            users.append(obj)
    if users:
        return _RemovalPlan(blocked=f"It is kept while a class list of {_counted_rows(users)} names it.")
    return _RemovalPlan(tuple(first.values()), cascaded, frozenset(relies_on & stale.keys() - {own}))


def _keep_dependents(start: tuple, dependents: dict, alive: set, kept: dict, detail: str) -> list[tuple]:
    """Keep every row of *alive* that relies on the row *start*, directly or through other rows, with *detail*.

    Return the rows that it kept, in the order that it found them.
    """
    found: list[tuple] = []
    work = [start]
    while work:
        for key in dependents.get(work.pop(), ()):
            if key in alive:
                alive.discard(key)
                kept[key] = detail
                found.append(key)
                work.append(key)
    return found


def _dependents(plans: dict[tuple, _RemovalPlan]) -> dict[tuple, set[tuple]]:
    """Return the rows whose plan relies on each row: the reverse index of ``relies_on``."""
    index: dict[tuple, set[tuple]] = {}
    for key, plan in plans.items():
        for each in plan.relies_on:
            index.setdefault(each, set()).add(key)
    return index


def _relied_on_detail(row: _StaleRow, what: str) -> str:
    return f"It is kept because its removal relies on the removal of {_counted_rows([row.target])}, which {what}."


def _removal_set(
    stale: dict[tuple, _StaleRow], mapped_options: frozenset[tuple]
) -> tuple[dict[tuple, _RemovalPlan], dict[tuple, str]]:
    """Return the largest subset of stale rows whose deletion removes or changes no kept row.

    Return the plan of each row of that subset, and why each other stale row stays. Each plan is read once; a row that
    stays keeps every row that relies on it, through the reverse index.
    """
    plans = {key: _removal_plan(row.target, stale, mapped_options) for key, row in stale.items()}
    kept = {key: plan.blocked for key, plan in plans.items() if plan.blocked}
    alive = set(plans) - kept.keys()
    dependents = _dependents(plans)
    for key in list(kept):
        _keep_dependents(key, dependents, alive, kept, _relied_on_detail(stale[key], "is kept"))
    return {key: plan for key, plan in plans.items() if key in alive}, kept


def _components(plans: dict[tuple, _RemovalPlan]) -> list[list[tuple]]:
    """Return the strongly connected components of the ``relies_on`` graph, each after every component it relies on.

    Rows that rely on each other form one component. Tarjan's algorithm, without recursion, gives the components in
    this order. The rows and edges follow the order of *plans*, so the result does not change between runs.
    """
    order = {key: position for position, key in enumerate(plans)}

    def edges(key: tuple):
        return iter(sorted(plans[key].relies_on & plans.keys(), key=order.__getitem__))

    index: dict[tuple, int] = {}
    low: dict[tuple, int] = {}
    stack: list[tuple] = []
    on_stack: set[tuple] = set()
    components: list[list[tuple]] = []

    def visit(key: tuple) -> None:
        index[key] = low[key] = len(index)
        stack.append(key)
        on_stack.add(key)

    for root in plans:
        if root in index:
            continue
        visit(root)
        work = [(root, edges(root))]
        while work:
            key, successors = work[-1]
            for successor in successors:
                if successor not in index:
                    visit(successor)
                    work.append((successor, edges(successor)))
                    break
                if successor in on_stack:
                    low[key] = min(low[key], index[successor])
            else:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[key])
                if low[key] == index[key]:
                    component = []
                    while (member := stack.pop()) != key:
                        on_stack.discard(member)
                        component.append(member)
                    on_stack.discard(key)
                    components.append(sorted([*component, key], key=order.__getitem__))
    return components


def _delete_component(
    keys: list[tuple], plans: dict, removable: dict, removed: set, family: int, summary: ImportSummary
) -> tuple[list[tuple], tuple | None]:
    """Delete the rows of one component in one transaction, all or nothing, through the ORM.

    The ORM delete runs the guards, the mapping cleanup and the change log. Return the rows that the component
    removed, and ``None``; or no rows and the row whose delete failed, which has a write-failed entry.
    """
    gone: list[tuple] = []
    current = keys[0]
    try:
        with event_scope.atomic():
            for current in keys:
                if current in removed or current in gone:
                    continue
                plan = plans[current]
                # An Option that the delete of its own owner already removed is gone.
                for option in _model("Option").objects.filter(pk__in=[option.pk for option in plan.options_first]):
                    option.delete()
                removable[current].target.delete()
                gone += [current, *(each for each in plan.cascaded if each not in removed and each not in gone)]
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:  # noqa: BLE001 (one failed removal must not abort the import)
        source = removable[current].source
        summary.record(write_failed(family, source.kind, source.path(family)))
        summary.warn(f"stale {source.kind.value} {source.path(family)}: {exc}")
        return [], current
    return gone, None


def mapped_rows(server, family: int, confirmed_before: int | None = None) -> dict[Kind, dict[MappingSource, Any]]:
    """Return the DHCP plugin row of each mapping of *family* whose kind a run can remove, by kind and Kea source.

    A mapping whose row is gone has none. With *confirmed_before*, a cutoff of the confirmation sequence, only the
    mappings confirmed with a lower number count.
    """
    from ..models import KeaDhcpLink

    rows: dict[Kind, dict[MappingSource, Any]] = {kind: {} for kind in mapped_kinds(family)}
    links = KeaDhcpLink.objects.filter(server=server, family=family, kind__in=[kind.value for kind in rows])
    if confirmed_before is not None:
        links = links.filter(confirmation__lt=confirmed_before)
    for link in links.prefetch_related("sys4_object").order_by("pk"):
        if link.sys4_object is not None:
            source = MappingSource(Kind(link.kind), link.kea_subnet_id, link.kea_identity)
            rows[source.kind][source] = link.sys4_object
    return rows


def _stale_rows(server, plan: FamilyPlan, observed) -> dict[Kind, list[_StaleRow]]:
    """Return the mapped rows of each kind whose Kea source the plan does not observe.

    A mapping confirmed with a number at or above the cutoff of the plan belongs to a newer read, so it is never stale
    here. The import lock keeps two runs of one Server apart; the cutoff covers the other writers, such as an ADR 0008
    merge or revert replay in main. A plan without a cutoff can judge no mapping.
    """
    if plan.cutoff is None:
        return {}
    return {
        kind: [_StaleRow(source, row) for source, row in rows.items() if source not in observed[kind].sources]
        for kind, rows in mapped_rows(server, plan.family, confirmed_before=plan.cutoff).items()
    }


def remove_stale_objects(server, plan: FamilyPlan, summary: ImportSummary) -> None:
    """Remove each Stale DHCP Import Object of one family, children first, and report it.

    An Incomplete observation keeps each row that it cannot judge (:meth:`KindObservation.gap`), with one entry for
    each kind that says why. Before any write, :func:`_removal_set` finds the stale rows whose deletion removes or
    changes no kept row, and no mapped Option that the run keeps; each other stale row is kept and reported. Rows that rely on each other form one component, which goes in one transaction, all or nothing,
    after every component that it relies on. When a component fails, every pending row that relies on it, directly or
    through other rows, is kept too. IPAM objects stay: the DHCP plugin rows only reference them.
    """
    observed = observations(plan)
    stale = _stale_rows(server, plan, observed)
    removable: dict[tuple, _StaleRow] = {}
    for kind in mapped_kinds(plan.family):
        unjudged: list[_StaleRow] = []
        reasons: list[str] = []
        for row in stale.get(kind, []):
            gap = observed[kind].gap(row.source)
            if gap:
                unjudged.append(row)
                reasons.extend(gap)
            else:
                removable[_row_key(row.target)] = row
        if unjudged:
            label = KIND_LABELS[kind]
            kept = counted(len(unjudged), f"mapped {label} row was", f"mapped {label} rows were")
            detail = f"{' '.join(dict.fromkeys(reasons))} {kept} kept."
            summary.record(
                not_written(plan.family, kind, kind_path(plan.family, kind), Reason.INCOMPLETE_OBSERVATION, detail)
            )
    plans, staying = _removal_set(removable, _mapped_option_keys())
    for key, detail in staying.items():
        _record_kept(removable[key], detail, plan.family, summary)
    # A deleted instance has no pk, so every key comes from before the deletes.
    dependents = _dependents(plans)
    pending = set(plans)
    removed: set[tuple] = set()
    for component in _components(plans):
        if not pending.issuperset(component):
            # A failed component that it relies on keeps it.
            continue
        pending.difference_update(component)
        gone, failed = _delete_component(component, plans, removable, removed, plan.family, summary)
        if failed is None:
            removed.update(gone)
            for source in (removable[each].source for each in gone):
                summary.record(written(plan.family, source.kind, source.path(plan.family), Outcome.REMOVED))
            continue
        together = _together_detail(removable[failed])
        for key in component:
            if key != failed:
                _record_kept(removable[key], together, plan.family, summary)
        relied_on: dict[tuple, str] = {}
        for key in component:
            detail = _relied_on_detail(removable[key], "failed" if key == failed else "is kept")
            for each in _keep_dependents(key, dependents, pending, relied_on, detail):
                _record_kept(removable[each], detail, plan.family, summary)


def _together_detail(row: _StaleRow) -> str:
    return f"It is kept because it is removed together with {_counted_rows([row.target])}, whose removal failed."


def _record_kept(row: _StaleRow, detail: str, family: int, summary: ImportSummary) -> None:
    summary.record(not_written(family, row.source.kind, row.source.path(family), Reason.REMOVAL_BLOCKED, detail))


# The DHCP plugin rows that apply_plan adds and changes.
_PLUGIN_UPSERTS = tuple(
    f"{PLUGIN_APP_LABEL}.{action}_{model}"
    for model in (
        "dhcpserver",
        "optiondefinition",
        "option",
        "clientclass",
        "sharednetwork",
        "subnet",
        "pool",
        "pdpool",
        "hostreservation",
    )
    for action in ("add", "change")
)


def _removal_permissions() -> tuple[str, ...]:
    """Return the delete permission of each model that a stale removal deletes, Options included."""
    from ..models import MAPPING_KINDS

    return tuple(f"{PLUGIN_APP_LABEL}.delete_{MAPPING_KINDS[kind][0].lower()}" for kind in REMOVAL_ORDER)


def import_permissions(server) -> tuple[str, ...]:
    """Return the IPAM, DCIM and DHCP plugin permissions that :func:`apply_plan` can use.

    The import claims Subnets, Pools, delegated-prefix Pool Prefixes and Reservations, reconciles the delegated Prefixes
    and the delegated-prefix Pool Prefixes, writes the DHCP plugin rows, and removes Stale DHCP Import Objects.
    """
    from ..ipam_reconciliation import (
        RESERVATION,
        DelegatedPrefixPhase,
        PDPoolPhase,
        PoolPhase,
        SubnetPhase,
        claim_permissions,
        reconcile_permissions,
    )

    claims = claim_permissions(SubnetPhase.source, PoolPhase.source, PDPoolPhase.source, RESERVATION)
    reconciles = reconcile_permissions(server, DelegatedPrefixPhase.source, PDPoolPhase.source)
    return tuple(dict.fromkeys((*claims, *reconciles, *_PLUGIN_UPSERTS, *_removal_permissions())))


def import_server_config(
    server,
    config: ServerConfigIntent,
    reservation_observation: ReservationObservation | None = None,
) -> ImportSummary:
    """Plan one parsed ``(server, family)`` Kea config, probe the installed DHCP plugin, and apply the plan to it."""
    return apply_plan(server, plan_family(config, reservation_observation), probe())


def _import_definitions_and_classes(
    server, dhcp_server, plan: FamilyPlan, adoption_servers: tuple[int, ...], summary, capabilities
) -> tuple[OptionReferences, dict]:
    """Write every custom Option Definition and client class of *plan*, before any DHCP Option references them.

    Return what the Options can reference, and the row of each imported client class by Kea name.
    """
    definitions = CustomDefinitions(server, plan.declared_definitions, adoption_servers)
    for planned in plan.option_definitions:
        definitions.written[planned.key] = _write_option_definition(
            definitions, planned.key, plan.family, dhcp_server, summary, capabilities
        )
    rows = {}
    for planned_class in plan.client_classes:
        row = upsert_client_class(server, dhcp_server, planned_class, definitions, summary, capabilities)
        if row is not None:
            rows[planned_class.key] = row
    defined = frozenset(planned.key for planned in plan.client_classes)
    classes = ClassReferences(plan.family, defined, {name: row.pk for name, row in rows.items()})
    return OptionReferences(definitions, classes), rows


@coordinated_import
def apply_plan(server, plan: FamilyPlan, capabilities: PluginCapabilities) -> ImportSummary:
    """Apply the plan of one ``(server, family)`` to the DHCP plugin, writing a gated fact only with its *capabilities*.

    Idempotent: re-running finds each row through its ``KeaDhcpLink`` mapping and updates it rather than
    duplicating it.
    """
    summary = ImportSummary()
    root = kea_paths.daemon(plan.family)
    invalid = (
        not_written(plan.family, dropped.kind, dropped.path, Reason.INVALID_KEA_DATA, dropped.detail)
        for dropped in plan.dropped
    )
    for entry in (*invalid, *plan.not_imported):
        summary.record(entry)
    dhcp_server, created = upsert_dhcp_server(server, plan.family)
    adoption_servers = _adoption_servers(server, dhcp_server)

    values = server_values(dhcp_server, plan.server, plan.family, capabilities, summary)
    changed = _apply_global_settings(dhcp_server, values, summary, plan.family, capabilities)
    linked = _link_interfaces(dhcp_server, plan.server.interfaces, summary, plan.family)
    if changed is not None and (created or changed or linked):
        summary.record(written(plan.family, Kind.SERVER, root, Outcome.CREATED if created else Outcome.UPDATED))
    references, class_rows = _import_definitions_and_classes(
        server, dhcp_server, plan, adoption_servers, summary, capabilities
    )
    declared = references.definitions.declared
    planned_classes = {planned.key: planned for planned in plan.client_classes}
    global_options = planned_options(plan.server, plan.family, declared)
    upsert_options(dhcp_server, global_options, plan.family, references, summary, root, capabilities)
    for name, row in class_rows.items():
        path = kea_paths.client_class(plan.family, name)
        class_options = planned_options(planned_classes[name], plan.family, declared)
        upsert_options(row, class_options, plan.family, references, summary, path, capabilities)
    networks = _import_shared_networks(server, dhcp_server, plan, references, summary, capabilities)

    prefix_claims, pool_claims, pd_pool_claims = _claim_config_networks(server, plan)
    summary.owner_disagreements += sum(
        result.outcome == "disagreement" for result in (*prefix_claims.prefixes.values(), *pool_claims.ranges.values())
    )
    subnet_ids = settle_subnet_ids(server, dhcp_server, plan, capabilities, summary)
    for planned_subnet in plan.subnets:
        taken = subnet_ids.taken.get(planned_subnet.key) if planned_subnet.key is not None else None
        if taken is not None:
            summary.record(taken.entry(plan.family, Kind.SUBNET, subnet_path(planned_subnet)))
            summary.warn(f"subnet {planned_subnet.intent.cidr} (id={planned_subnet.key}): {taken.detail}")
            _skip_subnet_children(summary, planned_subnet, declared, taken)
            continue
        if planned_subnet.key in subnet_ids.failed:
            summary.record(write_failed(plan.family, Kind.SUBNET, subnet_path(planned_subnet)))
            _skip_subnet_children(summary, planned_subnet, declared)
            continue
        renumbered = planned_subnet.key in subnet_ids.renumbered
        name = planned_subnet.intent.shared_network
        network = networks.get(name)
        # A member of a Shared Network that this run could hold but did not write keeps its stored parent.
        keep = name is not None and network is None and capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX)
        subnet_obj = upsert_subnet(
            server,
            dhcp_server,
            planned_subnet,
            summary,
            prefix_claims,
            renumbered,
            capabilities,
            references.classes,
            network,
            keep,
        )
        if subnet_obj is None:
            _skip_subnet_children(summary, planned_subnet, declared)
            continue
        if network is None:
            _report_inherited(summary, planned_subnet, capabilities)
        upsert_options(
            subnet_obj,
            planned_options(planned_subnet, plan.family, declared),
            plan.family,
            references,
            summary,
            subnet_path(planned_subnet),
            capabilities,
        )
        upsert_pools(server, subnet_obj, planned_subnet, summary, references, pool_claims, capabilities)
        upsert_pd_pools(server, subnet_obj, planned_subnet, summary, references, pd_pool_claims, capabilities)
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
    delegated_step = import_reservation_snapshot(
        server,
        dhcp_server,
        plan.reservations,
        references,
        summary,
        family=plan.family,
        adoption_servers=adoption_servers,
        capabilities=capabilities,
        subnet_ids=subnet_ids,
    )
    remove_stale_objects(server, plan, summary)
    unobserved = unobserved_kinds(server, plan)
    if delegated_step is not None:
        reconcile_delegated_prefixes(server, plan.family, delegated_step, unobserved, summary)
    if plan.family == 6:
        reconcile_pd_pool_prefixes(server, plan, unobserved, summary)
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
    """PKs of ``ipam.Prefix`` rows referenced by DHCP-plugin subnets/shared-networks/PD pools/reservations."""
    if not is_available():
        return set()
    Subnet = _model("Subnet")
    SharedNetwork = _model("SharedNetwork")
    PDPool = _model("PDPool")
    HostReservation = _model("HostReservation")
    ids: set[int] = set()
    ids.update(Subnet.objects.values_list("prefix_id", flat=True))
    ids.update(SharedNetwork.objects.values_list("prefix_id", flat=True))
    ids.update(PDPool.objects.values_list("prefix_id", flat=True))
    ids.update(PDPool.objects.values_list("excluded_prefix_id", flat=True))
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
