# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Reservations that the DHCP Import writes, and their delegated and excluded Prefixes.

* **Host reservations** come from the shared typed Reservation Snapshot. The
  adapter never parses raw ``reservation-get-page`` records. Valid records import
  even when the snapshot quarantines other records. A Global Reservation skips the
  IPAM sync, so the import creates no address rows for it and reports every reserved
  address it could not attach.  Delegated prefixes and the prefixes that they exclude carry their own length, so
  they import as shared ``ipam.Prefix`` rows for every Scope, under the IPAM source ``reservation-prefix``. The stale
  cleanup of ``reservation-prefix`` runs after the removal of Stale DHCP Import Objects, as the ``pd-pool`` phase does.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from functools import cached_property
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError

from .. import event_scope, ip_parse, kea_paths
from ..constants import Family
from ..published_name import reservation_published_name
from ..reservations import TRAVERSAL_DIAGNOSTIC_CODES, Reservation, identity_text
from ..subnet_catalogue import CatalogueUnavailable
from .dhcp_import_fields import MANAGED_FIELDS
from .dhcp_import_mappings import mapped_target, unlinked
from .dhcp_import_networks import SubnetIdSettlement, record_report
from .dhcp_import_options import OptionReferences, option_paths, upsert_options
from .dhcp_import_plan import InSubnetReservationKey, SubnetKey, keyed_reservations, planned_options
from .dhcp_import_report import Kind, Outcome, Reason, not_written, written
from .dhcp_import_server import synthesized_name
from .dhcp_import_summary import ImportSummary
from .dhcp_import_values import Source, user_context_fields
from .dhcp_import_write import LateOutcome, NotWritten, RowAdapter, RowState, WriteScope, row_state, write_row
from .dhcp_plugin_capabilities import plugin_model

if TYPE_CHECKING:
    from ..ipam_reconciliation import ClaimResult, ReservationObservation, ReservationPrefixPhase, SyncReport
    from ..subnet_catalogue import CatalogueSnapshot
    from .dhcp_import_plan import Planned, PlannedOptions, ReservationKey

logger = logging.getLogger(__name__)


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


def _reservation_name(scope_name: str, reservation: Reservation) -> str:
    """Build a unique reservation name scoped to its parent's (unique) name."""
    identity = reservation.identity
    return synthesized_name(scope_name, f" {identity_text(identity.identifier_type, identity.value)}")


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


@dataclass(frozen=True)
class _ReservationAdapter(RowAdapter):
    """One typed Reservation, in its Global or In-Subnet Scope (*subnet_obj*, ``None`` for a Global one).

    The mapping holds the Reservation Identity: the Kea subnet ID of an In-Subnet Reservation, or none for a
    Global one, and the identifier. A Global Reservation has no Subnet, and ``netbox_dhcp`` derives a
    reservation's family from one, so its family lives in the ``KeaDhcpLink`` identity
    instead.  Without it one identifier shares a single row between DHCPv4 and DHCPv6,
    merging ``ipv4_address`` and ``ipv6_addresses``.

    It consumes the IPAM claim results, so the plugin reservation shares the same ``ipam.IPAddress`` and
    ``dcim.MACAddress`` rows that the lease and Reservation sync owns. The client classes refer to the classes that the
    same run imported. The delegated and excluded Prefixes attach after their claim (:func:`_attach_delegated_prefixes`),
    so the caller records the outcome. *stopped* is why its Subnet was not written.
    """

    scope: WriteScope
    key: ReservationKey
    reservation: Reservation
    subnet_obj: Any
    dhcp_server: Any
    references: OptionReferences
    claims: ClaimResult
    catalogue: CatalogueSnapshot
    adoption_servers: tuple[int, ...]
    options: PlannedOptions
    stopped: NotWritten | None
    # The relations of the stored row that state() read: each related pk, with its Prefix if it has one.
    _stored: dict[str, dict[int, Any]] = field(default_factory=dict, init=False, repr=False, compare=False)

    late_outcome = True

    @cached_property
    def _addresses(self) -> tuple:
        """Return the claimed IPv4 address, the IPv6 addresses and the MAC address row of the Reservation."""
        ipv4_ip, ipv6_ips, mac_obj = _reservation_addresses(
            self.reservation, self.claims, self.catalogue, self.scope.summary
        )
        if self.reservation.identity.hardware_address is not None and mac_obj is None:
            raise RuntimeError("The reservation hardware address could not be resolved.")
        return ipv4_ip, ipv6_ips, mac_obj

    def _scope_name(self) -> str:
        if self.subnet_obj is not None:
            return self.subnet_obj.name
        return f"{self.scope.server.name} DHCPv{self.reservation.family}"

    def blocked(self) -> NotWritten | None:
        """Return why the Subnet was not written, or why the DHCP plugin cannot hold the identifier."""
        return self.stopped or _identifier_gap(self.reservation)

    def adopt(self):
        """Return the row that an import made before its Reservation had a mapping (a Global one: before the family).

        So an upgrade maps that row instead of duplicating it.
        """
        HostReservation = plugin_model("HostReservation")
        if self.subnet_obj is not None:
            base = HostReservation.objects.filter(subnet=self.subnet_obj)
        else:
            base = HostReservation.objects.filter(dhcp_server__in=self.adoption_servers, subnet__isnull=True)
        return _find_reservation(unlinked(base), self.reservation, self._addresses[2])

    def new_row(self):
        """Return a new Reservation with a name that is unique in its Scope."""
        return plugin_model("HostReservation")(name=_reservation_name(self._scope_name(), self.reservation))

    def fields(self, row) -> dict:
        """Return the managed fields of the Reservation. Its Scope is managed: a row that an operator moved returns."""
        reservation, subnet_obj = self.reservation, self.subnet_obj
        ipv4_ip, _ipv6_ips, mac_obj = self._addresses
        source = Source(reservation.family, Kind.RESERVATION, self.key.path(reservation.family))
        return {
            "subnet_id": subnet_obj.pk if subnet_obj is not None else None,
            "dhcp_server_id": None if subnet_obj is not None else self.dhcp_server.pk,
            # The DHCP row mirrors the stored Kea hostname, not the published name.
            "hostname": reservation.hostname or None,
            **_reservation_identifier_values(reservation, mac_obj),
            # One row holds one family. _reservation_addresses returns the other
            # family empty, which also splits a row an earlier import merged.
            "ipv4_address_id": ipv4_ip.pk if ipv4_ip is not None else None,
            **_reservation_boot_values(reservation),
            **user_context_fields(
                row, reservation.user_context, self.scope.capabilities, self.scope.summary, source, "Reservation"
            ),
        }

    def relations(self, row) -> dict[str, set[int]]:
        """Return the IPv6 addresses, the client classes and the kept delegated and excluded Prefixes.

        A Prefix that Kea no longer reports goes before the delegated phase evaluates stale links. The reported
        Prefixes attach after their claim.
        """
        path = self.key.path(self.reservation.family)
        classes = self.references.classes.resolve(
            self.reservation.client_classes, path, kea_paths.CLIENT_CLASSES, Kind.RESERVATION, self.scope.summary
        )
        # An empty address list clears the previous IPv6 relations.
        relations = {"ipv6_addresses": {address.pk for address in self._addresses[1]}, "client_classes": classes}
        for relation, networks in _reported_prefixes(self.reservation).items():
            # state() read the relations of a stored row; a new row has none.
            current = self._stored[relation] if row.pk is not None else {}
            relations[relation] = {pk for pk, prefix in current.items() if ip_parse.ip_network(str(prefix)) in networks}
        return relations

    def state(self, row) -> RowState:
        """Return the state of the stored *row*. The one read of its relations also gives the Prefixes it keeps."""
        self._stored.update(_reservation_relations(row))
        relations = {name: frozenset(rows) for name, rows in self._stored.items()}
        return row_state(row, self.scope.capabilities, relations)

    def adoption_fields(self, row) -> dict:
        """Return the family-qualified name of an adopted Global row, so the other family can create its own row."""
        return {"name": _reservation_name(self._scope_name(), self.reservation)} if self.subnet_obj is None else {}

    def descendants(self) -> Iterator[tuple[Kind, str]]:
        """Yield the DHCP Options of the Reservation."""
        yield from option_paths(self.options, self.reservation.family)


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


def _relation_states(objs) -> dict[int, dict[str, frozenset[int]]]:
    """Read the managed relations of every row in one query for each relation, keyed by row."""
    pks = [obj.pk for obj in objs]
    if not pks:
        # Without the DHCP plugin no row is imported, and its model does not exist.
        return {}
    states: dict[int, dict[str, set[int]]] = {pk: {name: set() for name in _RESERVATION_RELATIONS} for pk in pks}
    rows = plugin_model("HostReservation").objects.filter(pk__in=pks)
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


def _reservation_subnet(
    scope: WriteScope, key: InSubnetReservationKey, subnet_ids: SubnetIdSettlement | None
) -> tuple[Any, NotWritten | None]:
    """Return the Subnet row of an In-Subnet Reservation, or why its Subnet was not written.

    A Subnet whose Kea subnet ID another row keeps gives its own reason. A Subnet whose write failed, or that has no
    mapped row, was not imported.
    """
    taken = subnet_ids.taken.get(key.subnet_id) if subnet_ids is not None else None
    if taken is not None:
        return None, taken
    subnet_obj = None
    if subnet_ids is None or key.subnet_id not in subnet_ids.failed:
        subnet_obj = mapped_target(scope.server, scope.family, SubnetKey(key.subnet_id).source)
    if subnet_obj is None:
        return None, NotWritten(Reason.PARENT_NOT_IMPORTED, f"Subnet {key.subnet_id} was not imported.")
    return subnet_obj, None


def import_reservation_snapshot(
    scope: WriteScope,
    dhcp_server,
    observation: ReservationObservation | None,
    references: OptionReferences,
    *,
    adoption_servers: tuple[int, ...],
    subnet_ids: SubnetIdSettlement | None = None,
) -> DelegatedPrefixStep | None:
    """Import valid typed records and report quarantined Snapshot records.

    A Global Reservation may adopt an unmapped row of a DHCP server in *adoption_servers*. An In-Subnet
    Reservation of a Subnet that *subnet_ids* reports as taken or failed is not imported.

    Return the delegated-prefix step of the imported Reservations for :func:`reconcile_delegated_prefixes`, or
    ``None`` when no Snapshot was read or their Prefixes could not be attached.
    """
    from ..ipam_reconciliation import ReservationPrefixClaim, ReservationPrefixPhase, claim
    from ..ipam_sources import RESERVATION, RESERVATION_PREFIX

    server, family, summary, capabilities = scope.server, scope.family, scope.summary, scope.capabilities
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
        summary.ownership.incomplete.add(RESERVATION)
        return None
    snapshot = observation.snapshot
    _record_snapshot_diagnostics(observation, family, summary)
    claims = claim(server, snapshot.family, snapshot.records, force=False, catalogue=observation.catalogue)
    summary.owner_disagreements += sum(result.outcome == "disagreement" for result in claims.addresses.values())
    imported: list[tuple[Planned[ReservationKey, Reservation], LateOutcome]] = []
    complete = snapshot.complete and not snapshot.diagnostics
    complete = _record_address_claims(summary.ownership, claims) and complete
    for planned in keyed_reservations(observation):
        reservation, key = planned.intent, planned.key
        subnet_obj, stopped = None, None
        if isinstance(key, InSubnetReservationKey):
            subnet_obj, stopped = _reservation_subnet(scope, key, subnet_ids)
        options = planned_options(planned, family, references.definitions.declared)
        adapter = _ReservationAdapter(
            scope,
            key,
            reservation,
            subnet_obj,
            dhcp_server,
            references,
            claims,
            observation.catalogue,
            adoption_servers,
            options,
            stopped,
        )
        result = write_row(adapter)
        if isinstance(result, NotWritten):
            complete = False
            continue
        upsert_options(scope, result.row, options, references)
        imported.append((planned, result))
    records = [planned.intent for planned, _ in imported]
    networks = dict.fromkeys(
        network for record in records for each in _reported_prefixes(record).values() for network in each
    )
    step: DelegatedPrefixStep | None = None
    try:
        with event_scope.atomic():
            prefix_claims = claim(
                server, snapshot.family, [ReservationPrefixClaim(network) for network in networks], force=False
            )
            _attach_delegated_prefixes(
                [(planned.intent, late.row) for planned, late in imported], prefix_claims, summary
            )
        failed = frozenset(address for address, result in prefix_claims.prefixes.items() if result.outcome == "error")
        step = DelegatedPrefixStep(ReservationPrefixPhase(records, observation.cutoff, complete and not failed), failed)
        if complete:
            summary.ownership.completed_sources.add(RESERVATION)
        else:
            summary.ownership.incomplete.add(RESERVATION)
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
        summary.ownership.incomplete.add(RESERVATION_PREFIX)
        logger.exception("Could not attach delegated Prefixes after DHCP import")
        summary.warn("Delegated Prefixes could not be attached. See server logs.")
    relations = _relation_states([late.row for _, late in imported])
    for planned, late in imported:
        if late.before is None or late.before != row_state(late.row, capabilities, relations[late.row.pk]):
            outcome = Outcome.CREATED if late.before is None else Outcome.UPDATED
            summary.record(written(family, Kind.RESERVATION, planned.key.path(family), outcome))
    return step


@dataclass(frozen=True)
class DelegatedPrefixStep:
    """The delegated-prefix phase of the imported Reservations, and the Prefixes whose claim failed before attachment."""

    phase: ReservationPrefixPhase
    failed: frozenset[str]


def reconcile_delegated_prefixes(
    server, family: Family, step: DelegatedPrefixStep, unobserved: set[Kind], summary: ImportSummary
) -> None:
    """Link the delegated and excluded Prefixes of the imported Reservations again, and drop the stale links (ADR 0006).

    It runs after :func:`.dhcp_import_stale.remove_stale_objects`: a removed Reservation no longer uses its Prefixes,
    so the cleanup can deprecate them. A Reservation that Kea no longer reports and that is still in NetBox
    (*unobserved*, see :func:`.dhcp_import_stale.unobserved_kinds`) still uses its Prefixes, so the phase is then not
    complete and drops no link. A Prefix whose claim failed before attachment counts as one error, also when this claim
    of it succeeds.
    """
    from ..ipam_reconciliation import reconcile

    complete = step.phase.complete and Kind.RESERVATION not in unobserved
    report = reconcile(server, family, [replace(step.phase, complete=complete)])
    record_report(summary, report)
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


def _identifier_field(reservation: Reservation) -> str:
    """Return the DHCP plugin field of the Kea identifier of *reservation*: each Kea identifier type names it."""
    return reservation.identity.identifier_type.replace("-", "_")


def _identifier_gap(reservation: Reservation) -> NotWritten | None:
    """Return why the DHCP plugin cannot hold the identifier text of *reservation*, or ``None``."""
    field_name = _identifier_field(reservation)
    destination = plugin_model("HostReservation")._meta.get_field(field_name)
    if field_name == "hw_address":
        try:
            destination.related_model._meta.get_field("mac_address").to_python(reservation.identity.value)
        except ValidationError:
            return NotWritten(Reason.PLUGIN_GAP, "The DHCP plugin holds a hardware address as a 6-octet MAC Address.")
        return None
    limit = destination.max_length
    if len(reservation.identity.value) <= limit:
        return None
    return NotWritten(
        Reason.PLUGIN_GAP,
        f"The DHCP plugin holds a {reservation.identity.identifier_type} of at most {limit} characters.",
    )


def _reservation_identifier_values(reservation: Reservation, mac_obj) -> dict:
    """Return the identifier fields of a DHCP-plugin reservation: its single Kea identifier, the others cleared."""
    identity = reservation.identity
    values: dict = {"hw_address_id": None, "duid": None, "circuit_id": None, "client_id": None, "flex_id": None}
    field_name = _identifier_field(reservation)
    if field_name == "hw_address":
        values["hw_address_id"] = mac_obj.pk
    else:
        values[field_name] = identity.value
    return values
