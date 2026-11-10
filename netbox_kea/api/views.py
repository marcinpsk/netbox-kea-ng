# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
# SPDX-License-Identifier: Apache-2.0
import logging
from typing import cast

from django.utils import timezone
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from .. import constants, filtersets, models, reservation_reads
from ..constants import Family, LeaseState
from ..decimal_text import parse_decimal
from ..kea import LeaseQueryGuardError, lease_query_guard_message
from ..leases import LeaseQuery, LeaseQueryError, LeaseSnapshot, lease_record_data, parse_lease_query
from ..read_failure import ReadFailure, ReadFailureKind, attempt
from ..reservations import (
    Reservation,
    ReservationIdentity,
    ReservationSnapshot,
    reservation_query_mode,
    reservation_record_data,
)
from .serializers import ServerSerializer

logger = logging.getLogger(__name__)


#: The response of a failed Kea read, by its kind.
_FAILURE_RESPONSES: dict[ReadFailureKind, tuple[str, int]] = {
    "unreachable": ("Could not connect to Kea server.", status.HTTP_502_BAD_GATEWAY),
    "refused": ("An internal error occurred", status.HTTP_502_BAD_GATEWAY),
    "unsupported": ("An internal error occurred", status.HTTP_502_BAD_GATEWAY),
    "malformed": ("An internal error occurred", status.HTTP_502_BAD_GATEWAY),
    "misconfigured": ("Server configuration error.", status.HTTP_500_INTERNAL_SERVER_ERROR),
}


def _failure_response(failure: ReadFailure) -> Response:
    """Return the response of a failed Kea read."""
    detail, code = _FAILURE_RESPONSES[failure.kind]
    return Response({"detail": detail}, status=code)


def _reservation_snapshot_data(snapshot: ReservationSnapshot) -> dict:
    """Return one normalized REST page without raw rejected Kea data."""
    return {
        "count": len(snapshot.records),
        "results": [reservation_record_data(record) for record in snapshot.records],
        "diagnostics": [
            {
                "code": diagnostic.code,
                "message": diagnostic.message,
                "source_position": diagnostic.source_position,
            }
            for diagnostic in snapshot.diagnostics
        ],
        "complete": snapshot.complete,
        "next_cursor": snapshot.next_cursor,
    }


def _lease_snapshot_data(snapshot: LeaseSnapshot) -> dict:
    """Return one normalized Lease observation without raw Kea values or display labels."""
    return {
        "count": len(snapshot.records),
        "results": [lease_record_data(lease, evaluated_at=snapshot.evaluated_at) for lease in snapshot.records],
        "diagnostics": [
            {
                "code": diagnostic.code,
                "field": diagnostic.field,
                "message": diagnostic.message,
                "source_position": diagnostic.source_position,
                "kinds": list(diagnostic.kinds),
            }
            for diagnostic in snapshot.diagnostics
        ],
        "complete": snapshot.complete,
        "next_cursor": None if snapshot.next_cursor is None else str(snapshot.next_cursor),
        "query": snapshot.query.model_dump(),
        "coverage": snapshot.coverage,
        "evaluated_at": snapshot.evaluated_at.isoformat(),
    }


def _single_reservation_response(version: int, reservation: Reservation | None) -> Response:
    if version not in (4, 6):
        raise ValueError(f"version must be 4 or 6, got {version!r}")
    snapshot = ReservationSnapshot(
        family=cast(Family, version),
        records=(reservation,) if reservation is not None else (),
        diagnostics=(),
        complete=True,
        next_cursor=None,
        read_started=timezone.now(),
    )
    return Response(_reservation_snapshot_data(snapshot))


def _parse_lease_state(raw_state) -> tuple[LeaseState | None, str | None]:
    """Return the lease state of a Kea state code and an optional parameter error."""
    if raw_state in (None, ""):
        return None, None
    try:
        return constants.LEASE_STATES[parse_decimal(raw_state)], None
    except (IndexError, ValueError):
        return None, f"state must be a Kea lease state code from 0 to {len(constants.LEASE_STATES) - 1}."


# The REST Lease search parameters of each family, with their Lease Query selectors.
_LEASE_SELECTORS: dict[Family, dict[str, str]] = {
    4: {
        "ip_address": constants.BY_IP,
        "hw_address": constants.BY_HW_ADDRESS,
        "client_id": constants.BY_CLIENT_ID,
        "hostname": constants.BY_HOSTNAME,
        "subnet_id": constants.BY_SUBNET_ID,
    },
    6: {
        "ip_address": constants.BY_IP,
        "duid": constants.BY_DUID,
        "hostname": constants.BY_HOSTNAME,
        "subnet_id": constants.BY_SUBNET_ID,
    },
}


class _LeaseParameterError(ValueError):
    """The REST Lease search parameters do not give exactly one valid selector and a valid state."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        # The response reads this public text, never str() of a caught exception (CodeQL py/stack-trace-exposure).
        self.detail = detail


def _lease_query(params, version: Family) -> LeaseQuery:
    """Return the Lease Query of the REST Lease search parameters.

    Raises:
        _LeaseParameterError: If the parameters are refused; the message says why.

    """
    selectors = _LEASE_SELECTORS[version]
    other: Family = 6 if version == 4 else 4
    for name in _LEASE_SELECTORS[other].keys() - selectors.keys():
        if params.get(name):
            raise _LeaseParameterError(f"{name} is only supported for DHCPv{other}.")
    given = [name for name in selectors if params.get(name)]
    if len(given) != 1:
        raise _LeaseParameterError(f"Give exactly one of these parameters: {', '.join(selectors)}.")
    lease_state, state_error = _parse_lease_state(params.get("state"))
    if state_error is not None:
        raise _LeaseParameterError(state_error)
    name = given[0]
    try:
        return parse_lease_query(version, selectors[name], params[name], lease_state)
    except LeaseQueryError as exc:
        raise _LeaseParameterError(f"{'state' if exc.field == 'state' else name}: {exc}") from exc


class ServerViewSet(NetBoxModelViewSet):
    """DRF viewset providing CRUD endpoints for Server objects."""

    queryset = models.Server.objects.prefetch_related("tags").order_by("-pk")
    filterset_class = filtersets.ServerFilterSet
    serializer_class = ServerSerializer

    # ─────────────────────────────────────────────────────────────────────
    # Lease search actions
    # ─────────────────────────────────────────────────────────────────────

    @action(detail=True, methods=["get"], url_path="leases4", url_name="leases4")
    def leases4(self, request, pk=None, format=None):  # noqa: A002 - DRF format-suffix keyword
        """Search DHCPv4 leases on this server.

        Query parameters (exactly one of the first five):
        - ``ip_address``: exact IP lookup
        - ``hw_address``: lookup by hardware address (requires lease_cmds hook)
        - ``client_id``: lookup by client ID (requires lease_cmds hook)
        - ``hostname``: lookup by hostname (requires lease_cmds hook)
        - ``subnet_id``: lookup all leases in a subnet (requires lease_cmds hook)
        - ``state``: keep only the leases in this Kea state code; a subnet lookup takes only 0 or 1

        The response is one normalized Lease observation with its query scope and coverage.
        """
        return self._lease_search(request, version=4)

    @action(detail=True, methods=["get"], url_path="leases6", url_name="leases6")
    def leases6(self, request, pk=None, format=None):  # noqa: A002 - DRF format-suffix keyword
        """Search DHCPv6 leases on this server.

        Query parameters (exactly one of the first four):
        - ``ip_address``: exact IP lookup
        - ``duid``: lookup by DUID (requires lease_cmds hook)
        - ``hostname``: lookup by hostname (requires lease_cmds hook)
        - ``subnet_id``: lookup all leases in a subnet (requires lease_cmds hook)
        - ``state``: keep only the leases in this Kea state code; a subnet lookup takes only 0 or 1

        The response is one normalized Lease observation with its query scope and coverage.
        """
        return self._lease_search(request, version=6)

    def _lease_search(self, request, version: Family) -> Response:
        """Dispatch a lease search to Kea and return its normalized Lease Snapshot."""
        server = self.get_object()
        try:
            query = _lease_query(request.query_params, version)
        except _LeaseParameterError as exc:
            return Response({"detail": exc.detail}, status=status.HTTP_400_BAD_REQUEST)

        def lease_search() -> LeaseSnapshot:
            with server.get_client(version=version) as client:
                return client.lease_search(query, server_id=server.pk)

        try:
            snapshot = attempt(f"The DHCPv{version} Lease API search of Server {server.pk}", lease_search)
        except LeaseQueryGuardError as exc:
            logger.info("Rejected unsafe Subnet lease API query on server %s", server.name)
            return Response(
                {"detail": lease_query_guard_message(exc, query.state)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            logger.exception("Unexpected error fetching leases from %s", server.name)
            return Response({"detail": "An internal error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if isinstance(snapshot, ReadFailure):
            return _failure_response(snapshot)
        return Response(_lease_snapshot_data(snapshot))

    # ─────────────────────────────────────────────────────────────────────
    # Reservation search actions
    # ─────────────────────────────────────────────────────────────────────

    @action(detail=True, methods=["get"], url_path="reservations4", url_name="reservations4")
    def reservations4(self, request, pk=None, format=None):  # noqa: A002 - DRF format-suffix keyword
        """Search DHCPv4 host reservations on this server.

        Select exactly one bounded page, exact identity, scoped address, or
        hostname query. Results use the family-neutral Reservation schema.
        """
        return self._reservation_search(request, version=4)

    @action(detail=True, methods=["get"], url_path="reservations6", url_name="reservations6")
    def reservations6(self, request, pk=None, format=None):  # noqa: A002 - DRF format-suffix keyword
        """Search DHCPv6 host reservations on this server.

        Select exactly one bounded page, exact identity, scoped address, or
        hostname query. Results use the family-neutral Reservation schema.
        """
        return self._reservation_search(request, version=6)

    def _reservation_search(self, request, version: Family) -> Response:
        """Dispatch a reservation search to Kea and return JSON results."""
        server = self.get_object()
        params = request.query_params

        hostname = params.get("hostname")

        try:
            # Selectors need a value, but getlist: `page=1&page=` must still select page.
            query_mode = reservation_query_mode([name for name in params if any(params.getlist(name))])
        except ValueError:
            return Response(
                {"detail": "Select exactly one Reservation query: page, identity, scoped address, or hostname."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if query_mode == "page":
            return self._reservation_page_response(server, params, version)
        if query_mode == "identity":
            return self._reservation_identity_response(server, params, version)
        if query_mode == "address":
            return self._reservation_address_response(server, params, version)
        if query_mode == "hostname":
            return self._reservation_hostname_response(server, hostname, version)
        raise AssertionError(f"Unsupported Reservation query mode {query_mode!r}")

    def _reservation_page_response(self, server, params, version: Family) -> Response:
        """Return one validated and normalized bounded Reservation page."""
        # An empty value is what an unset form field posts, and the mode selector above
        # already ignores one, so the reader must ignore it too instead of failing.
        raw_limit = params.get("limit", "")
        try:
            limit = parse_decimal(raw_limit) if raw_limit else 100
        except (TypeError, ValueError):
            return Response({"detail": "limit must be an integer."}, status=status.HTTP_400_BAD_REQUEST)
        if not 1 <= limit <= 500:
            return Response(
                {"detail": "limit must be between 1 and 500."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            snapshot = attempt(
                f"The DHCPv{version} Reservation API page of Server {server.pk}",
                lambda: reservation_reads.read_page(server, version, cursor=params.get("cursor") or None, limit=limit),
            )
        except ValueError:
            logger.info("Rejected invalid Reservation page parameters for server %s", server.name)
            return Response({"detail": "Invalid Reservation page parameters."}, status=status.HTTP_400_BAD_REQUEST)
        if isinstance(snapshot, ReadFailure):
            return _failure_response(snapshot)
        return Response(_reservation_snapshot_data(snapshot))

    def _reservation_identity_response(self, server, params, version: Family) -> Response:
        """Return one exact Reservation Identity target."""
        identifier_type = params.get("identifier_type")
        identifier = params.get("identifier")
        if not identifier_type or not identifier:
            return Response(
                {"detail": "identifier_type and identifier are both required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        def read() -> Reservation | None:
            scope_name = params.get("scope")
            if scope_name == "global":
                # An empty value is an unset form field, not a Subnet selection. Read every
                # repeat: get() returns the last one, so a trailing empty would cancel a real one.
                if any(params.getlist("subnet_id")):
                    raise ValueError("A Global Reservation query cannot select a Subnet.")
                subnet_id = None
            elif scope_name == "in-subnet":
                subnet_id = parse_decimal(params.get("subnet_id", ""))
            else:
                raise ValueError("scope must be global or in-subnet.")
            identity = ReservationIdentity(identifier_type, identifier)
            return reservation_reads.read_by_identity(server, version, subnet_id, identity)

        try:
            reservation = attempt(f"The DHCPv{version} Reservation API identity read of Server {server.pk}", read)
        except (TypeError, ValueError):
            return Response({"detail": "Invalid Reservation identity selector."}, status=status.HTTP_400_BAD_REQUEST)
        if isinstance(reservation, ReadFailure):
            return _failure_response(reservation)
        return _single_reservation_response(version, reservation)

    def _reservation_address_response(self, server, params, version: Family) -> Response:
        """Resolve one In-Subnet address to its canonical Reservation."""

        def read() -> Reservation | None:
            subnet_id = parse_decimal(params.get("subnet_id", ""))
            return reservation_reads.read_by_address(server, version, subnet_id, params.get("ip_address"))

        try:
            reservation = attempt(f"The DHCPv{version} Reservation API address read of Server {server.pk}", read)
        except (TypeError, ValueError):
            return Response({"detail": "Invalid scoped address selector."}, status=status.HTTP_400_BAD_REQUEST)
        if isinstance(reservation, ReadFailure):
            return _failure_response(reservation)
        return _single_reservation_response(version, reservation)

    def _reservation_hostname_response(self, server, hostname: str, version: Family) -> Response:
        """Return one normalized hostname Reservation Snapshot."""
        if not hostname:
            return Response({"detail": "Invalid hostname selector."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            snapshot = attempt(
                f"The DHCPv{version} Reservation API hostname read of Server {server.pk}",
                lambda: reservation_reads.read_by_hostname(server, version, hostname),
            )
        except ValueError:
            return Response({"detail": "Invalid hostname selector."}, status=status.HTTP_400_BAD_REQUEST)
        if isinstance(snapshot, ReadFailure):
            return _failure_response(snapshot)
        return Response(_reservation_snapshot_data(snapshot))
