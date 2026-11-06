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
* **Writes.** Every row except the DHCPServer goes through :func:`.dhcp_import_write.write_row`, with one small
  adapter class for its kind in the ``dhcp_import_*`` module of that kind. The protocol finds the row through its
  mapping or adopts an unmapped one, writes it, observes the mapping, reports a failure, and skips the planned subtree
  of an object that it does not write.
* **Ownership.** Every writer sets exactly the managed fields of :mod:`.dhcp_import_fields` on a mapped row, and
  :mod:`.dhcp_import_write` refuses a write that names another set. Unmanaged fields and unmapped rows stay.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.apps import apps

from ..dhcp_mapping_lifecycle import coordinated_import
from ..mappers.kea_to_dhcp import ServerConfigIntent
from .dhcp_import_networks import (
    ClassReferences,
    claim_config_networks,
    import_shared_networks,
    reconcile_pd_pool_prefixes,
    report_inherited,
    settle_subnet_ids,
    upsert_client_class,
    upsert_pd_pools,
    upsert_pools,
    upsert_subnet,
)
from .dhcp_import_options import CustomDefinitions, OptionReferences, upsert_options, write_option_definition
from .dhcp_import_plan import REMOVAL_ORDER, observations, plan_family, planned_options
from .dhcp_import_report import Capability, Kind, Outcome, Reason, not_written, written
from .dhcp_import_reservations import import_reservation_snapshot, reconcile_delegated_prefixes
from .dhcp_import_server import (
    adoption_servers,
    apply_global_settings,
    link_interfaces,
    server_values,
    upsert_dhcp_server,
)
from .dhcp_import_stale import remove_stale_objects, stale_judgment, unobserved_kinds
from .dhcp_import_summary import ImportSummary
from .dhcp_import_write import WriteScope
from .dhcp_plugin_capabilities import PLUGIN_APP_LABEL, PluginCapabilities, plugin_model, probe

if TYPE_CHECKING:
    from ..ipam_reconciliation import ReservationObservation
    from ..ipam_sources import ObjectField
    from ..models import DhcpIntegrationConfig, Server
    from .dhcp_import_plan import FamilyPlan


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
    if not server.dhcp4 and not server.dhcp6:
        # Server.save() does not call clean(), so a row can have no family.
        return "Enable DHCPv4 or DHCPv6 on this server first."
    # Read last, so that a Server that opts out costs no query.
    if not (switch or DhcpIntegrationConfig.get()).enabled:
        return "The DHCP plugin integration is off for all Servers. Turn it on in DHCP Kea > Settings."
    return ""


def runs_for(server: Server, switch: DhcpIntegrationConfig | None = None) -> bool:
    """Return whether the DHCP plugin integration runs for *server*."""
    return not integration_refusal(server, switch)


def scheduled_import_runs_for(server: Server) -> bool:
    """Return whether the periodic sync job runs the DHCP Import of *server*, whatever the IPAM sync settings."""
    from ..models import DhcpIntegrationConfig
    from .dhcp_import import supported_plugin_installed

    switch = DhcpIntegrationConfig.get()
    return switch.scheduled_import_enabled and runs_for(server, switch) and supported_plugin_installed()


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
        PDPoolPhase,
        PoolPhase,
        ReservationPrefixPhase,
        SubnetPhase,
        claim_permissions,
        reconcile_permissions,
    )
    from ..ipam_sources import RESERVATION

    claims = claim_permissions(SubnetPhase.source, PoolPhase.source, PDPoolPhase.source, RESERVATION)
    reconciles = reconcile_permissions(server, ReservationPrefixPhase.source, PDPoolPhase.source)
    return tuple(dict.fromkeys((*claims, *reconciles, *_PLUGIN_UPSERTS, *_removal_permissions())))


def import_server_config(
    server,
    config: ServerConfigIntent,
    reservation_observation: ReservationObservation | None = None,
) -> ImportSummary:
    """Plan one parsed ``(server, family)`` Kea config, probe the installed DHCP plugin, and apply the plan to it."""
    return apply_plan(server, plan_family(config, reservation_observation), probe())


def _import_definitions_and_classes(
    scope: WriteScope, dhcp_server, plan: FamilyPlan, adoption_servers: tuple[int, ...]
) -> tuple[OptionReferences, dict]:
    """Write every custom Option Definition and client class of *plan*, before any DHCP Option references them.

    Return what the Options can reference, and the row of each imported client class by Kea name.
    """
    definitions = CustomDefinitions(plan.declared_definitions, adoption_servers)
    for planned in plan.option_definitions:
        write_option_definition(scope, definitions, planned.key, dhcp_server)
    rows = {}
    for planned_class in plan.client_classes:
        row = upsert_client_class(scope, dhcp_server, planned_class, definitions)
        if row is not None:
            rows[planned_class.key.name] = row
    defined = frozenset(planned.key.name for planned in plan.client_classes)
    classes = ClassReferences(plan.family, defined, {name: row.pk for name, row in rows.items()})
    return OptionReferences(definitions, classes), rows


@coordinated_import
def apply_plan(server, plan: FamilyPlan, capabilities: PluginCapabilities) -> ImportSummary:
    """Apply the plan of one ``(server, family)`` to the DHCP plugin, writing a gated fact only with its *capabilities*.

    Idempotent: re-running finds each row through its ``KeaDhcpLink`` mapping and updates it rather than
    duplicating it.
    """
    from ..ipam_sources import POOL, RESERVATION, SUBNET

    summary = ImportSummary()
    scope = WriteScope(server, plan.family, summary, capabilities)
    root = plan.server.key.path(plan.family)
    invalid = (
        not_written(plan.family, dropped.kind, dropped.path, Reason.INVALID_KEA_DATA, dropped.detail)
        for dropped in plan.dropped
    )
    for entry in (*invalid, *plan.not_imported):
        summary.record(entry)
    dhcp_server, created = upsert_dhcp_server(server, plan.family)
    adopting = adoption_servers(server, dhcp_server)

    values = server_values(dhcp_server, plan.server, plan.family, capabilities, summary)
    changed = apply_global_settings(dhcp_server, values, summary, plan.family, capabilities)
    linked = link_interfaces(dhcp_server, plan.server.interfaces, summary, plan.family)
    if changed is not None and (created or changed or linked):
        summary.record(written(plan.family, Kind.SERVER, root, Outcome.CREATED if created else Outcome.UPDATED))
    references, class_rows = _import_definitions_and_classes(scope, dhcp_server, plan, adopting)
    declared = references.definitions.declared
    planned_classes = {planned.key.name: planned for planned in plan.client_classes}
    upsert_options(scope, dhcp_server, planned_options(plan.server, plan.family, declared), references)
    for name, row in class_rows.items():
        upsert_options(scope, row, planned_options(planned_classes[name], plan.family, declared), references)
    networks = import_shared_networks(scope, dhcp_server, plan, references)

    prefix_claims, pool_claims, pd_pool_claims = claim_config_networks(server, plan)
    summary.owner_disagreements += sum(
        result.outcome == "disagreement" for result in (*prefix_claims.prefixes.values(), *pool_claims.ranges.values())
    )
    subnet_ids = settle_subnet_ids(server, dhcp_server, plan, capabilities, summary)
    for planned_subnet in plan.subnets:
        name = planned_subnet.intent.shared_network
        network = networks.get(name)
        # A member of a Shared Network that this run could hold but did not write keeps its stored parent.
        keep = name is not None and network is None and capabilities.has(Capability.SHARED_NETWORK_OPTIONAL_PREFIX)
        subnet_obj = upsert_subnet(
            scope, dhcp_server, planned_subnet, prefix_claims, subnet_ids, references, network, keep
        )
        if subnet_obj is None:
            continue
        if network is None:
            report_inherited(summary, planned_subnet, capabilities)
        upsert_options(scope, subnet_obj, planned_options(planned_subnet, plan.family, declared), references)
        upsert_pools(scope, subnet_obj, planned_subnet, references, pool_claims)
        upsert_pd_pools(scope, subnet_obj, planned_subnet, references, pd_pool_claims)
    for source, outcomes in ((SUBNET, prefix_claims.prefixes), (POOL, pool_claims.ranges)):
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
        scope, dhcp_server, plan.reservations, references, adoption_servers=adopting, subnet_ids=subnet_ids
    )
    observed = observations(plan)
    judgment = stale_judgment(server, plan, observed)
    unobserved = unobserved_kinds(judgment, remove_stale_objects(judgment, plan.family, summary))
    if delegated_step is not None:
        reconcile_delegated_prefixes(server, plan.family, delegated_step, unobserved, summary)
    if plan.family == 6:
        reconcile_pd_pool_prefixes(server, plan, observed, unobserved, summary)
    if not plan.configuration_complete:
        summary.ownership.incomplete.update({SUBNET, POOL})
    if (
        summary.errors
        or summary.reservations_skipped
        or summary.reservations_quarantined
        or summary.reservations_unread
    ):
        summary.ownership.incomplete.add(RESERVATION)
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Stale-cleanup exclusion (so the IPAM sync never GCs rows the plugin references)
# ─────────────────────────────────────────────────────────────────────────────


# The DHCP plugin model fields that reference each kind of owned object.
_REFERENCES: dict[ObjectField, tuple[tuple[str, str], ...]] = {
    "ip_address": (("HostReservation", "ipv4_address"), ("HostReservation", "ipv6_addresses")),
    "prefix": (
        ("Subnet", "prefix"),
        ("SharedNetwork", "prefix"),
        ("PDPool", "prefix"),
        ("PDPool", "excluded_prefix"),
        ("HostReservation", "ipv6_prefixes"),
        ("HostReservation", "excluded_ipv6_prefixes"),
    ),
    "ip_range": (("Pool", "ip_range"),),
}


def references(object_field: ObjectField, pk: int) -> bool:
    """Return whether a DHCP plugin row references the IP address, Prefix or IP Range *pk* of *object_field*."""
    if not is_available():
        return False
    return any(plugin_model(model).objects.filter(**{name: pk}).exists() for model, name in _REFERENCES[object_field])
