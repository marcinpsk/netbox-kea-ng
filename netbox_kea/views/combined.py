# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from typing import Any, cast
from urllib.parse import urlencode

from django.contrib import messages
from django.forms import ChoiceField, Field
from django.http import HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views import View

from .. import forms, server_configuration, subnet_catalogue, tables
from ..constants import Family
from ..models import Server
from ..reservation_transfer import export_reservation_document
from ..utilities import export_table
from ._base import ConditionalLoginRequiredMixin, _catalogue_subnet_row, _enrich_subnet_statistics, _shared_network_row
from .fan_out import fan_out
from .notices import Notice, notice
from .reservations import ReservationQuery
from .reservations import empty_text as reservation_empty_text
from .reservations import fetch as fetch_reservations
from .reservations import present as present_reservations
from .server_scope import SELECTION_FIELD, ServerScope, resolve

_LEASE_SEARCH_FIELDS = ("q", "by", "state")


def _search_value_label(field: Field, value: str) -> str:
    """Return the choice label of *value*, or *value* itself for free text or an unknown choice."""
    if not isinstance(field, ChoiceField):
        return value
    # The lease search forms use flat (value, label) choices.
    return dict(cast("list[tuple[str, str]]", field.choices)).get(value, value)


class _CombinedViewMixin(ConditionalLoginRequiredMixin, View):
    """Resolve the Server Scope once before a combined page reads live data."""

    active_tab: str = "overview"
    dhcp_version: Family | None = None
    server_scope: ServerScope
    has_combined_export = True

    def get(self, request: HttpRequest) -> HttpResponse:
        """Resolve the Server Scope and show an explicit state for an invalid selection."""
        self.server_scope = resolve(request, self.dhcp_version)
        if self.server_scope.is_invalid:
            return render(request, "netbox_kea/combined_base.html", self._combined_context(request))
        is_export = self.has_combined_export and "export" in request.GET
        if is_export and self.server_scope.missing_family and not self.server_scope.is_all:
            names = ", ".join(server.name for server in self.server_scope.missing_family)
            messages.warning(request, f"Export refused: DHCPv{self.dhcp_version} is not enabled on {names}.")
            query = request.GET.copy()
            query.pop("export")
            return redirect(f"{request.path}?{query.urlencode()}")
        # A download stays on a section that supports combined exports.
        if self.server_scope.is_one and not self.server_scope.missing_family and not is_export:
            target = self._single_server_url(request)
            if request.headers.get("HX-Request") == "true":
                response = HttpResponse()
                response["HX-Redirect"] = target
                return response
            return redirect(target)
        return self.get_server_scoped(request)

    def _single_server_url(self, request: HttpRequest) -> str:
        """Keep only query fields that the canonical Server tab understands."""
        server = self.server_scope.servers[0]
        if self.active_tab == "overview":
            return server.get_absolute_url()
        compatible = {"sort", "per_page"}
        if self.active_tab.startswith("leases"):
            # The chooser has no per-Server Lease cursor.
            compatible.update(_LEASE_SEARCH_FIELDS)
        elif self.active_tab.startswith("reservations"):
            # Combined table pagination is not a per-Server Reservation cursor.
            compatible.update(forms.ReservationSearchForm.base_fields)
        else:
            compatible.add("page")
        query = request.GET.copy()
        for key in list(query):
            if key not in compatible:
                query.pop(key)
        url = reverse(f"plugins:netbox_kea:server_{self.active_tab}", args=[server.pk])
        return url + (f"?{query.urlencode()}" if query else "")

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Render a combined section within its resolved Server Scope."""
        raise NotImplementedError

    def _filter_fields(self) -> set[str]:
        """Return the query fields that filter or order this combined section; pagination is not one."""
        if self.active_tab == "overview":
            return set()
        fields = {"sort", "per_page"}
        if self.active_tab.startswith("leases"):
            fields.update(_LEASE_SEARCH_FIELDS)
        elif self.active_tab.startswith("reservations"):
            fields.update(forms.ReservationSearchForm.base_fields)
        elif self.active_tab.startswith("subnets"):
            fields.update(forms.SubnetSearchForm.base_fields)
        return fields

    def _combined_context(self, request: HttpRequest) -> dict[str, Any]:
        """Build context vars shared by every combined view."""
        server_scope_warnings: list[tuple[str, str]] = []
        # All permitted Servers skip a Server without the family; only an explicit selection reports it.
        if not self.server_scope.is_all:
            server_scope_warnings.extend(
                (server.name, f"DHCPv{self.dhcp_version} is not enabled on this Server.")
                for server in self.server_scope.missing_family
            )
        filter_fields = self._filter_fields()
        return {
            "server_scope": self.server_scope,
            "server_selector_fields": [
                (SELECTION_FIELD, "1"),
                *((key, request.GET[key]) for key in request.GET if key in filter_fields),
            ],
            "server_scope_warnings": server_scope_warnings,
            "active_tab": self.active_tab,
        }


class CombinedDashboardView(_CombinedViewMixin):
    """Combined overview: lists all Kea servers with their configuration summary.

    Intentionally makes no live Kea API calls so the page loads quickly
    regardless of server availability.
    """

    active_tab = "overview"
    template_name = "netbox_kea/combined_overview.html"

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Render the overview with the Servers in the resolved Server Scope."""
        ctx = self._combined_context(request)
        ctx["page_title"] = "All Kea Servers"
        return render(request, self.template_name, ctx)


def _filter_subnets(subnets: list[dict[str, Any]], q: str, subnet_id: int | None) -> list[dict[str, Any]]:
    """Filter a list of subnet dicts by free-text CIDR query and/or exact subnet ID.

    Filtering is done in-memory because subnets are fetched via config-get (no server-side search).

    Args:
        subnets: List of subnet dicts (keys: id, subnet, server_name, ...).
        q: Free-text query; matched case-insensitively against the ``subnet`` CIDR string.
        subnet_id: If non-None, only subnets with this exact ``id`` are returned.

    """
    result = subnets
    if subnet_id is not None:
        result = [s for s in result if s.get("id") == subnet_id]
    if q:
        q_lower = q.lower()
        result = [s for s in result if q_lower in s.get("subnet", "").lower()]
    return result


def _fetch_subnets_from_server(
    server: "Server",
    version: Family,
) -> tuple[list[dict[str, Any]], Notice | None]:
    """Fetch safe Subnet Catalogue facts for one server, tagged for the combined table, and its Notice."""
    snapshot = subnet_catalogue.display(server, version)
    if snapshot.unavailable:
        return [], notice(snapshot)
    result = [
        _catalogue_subnet_row(subnet, server, version, can_change=False)
        for subnet in (*snapshot.subnets, *snapshot.configured_subnets)
    ]

    _enrich_subnet_statistics(result, server, version)
    return result, notice(snapshot)


class _CombinedSubnetsView(_CombinedViewMixin):
    """Base view: fetch subnets from all selected servers concurrently."""

    template_name = "netbox_kea/combined_subnets.html"
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Merge subnet lists from all queried servers into one table."""
        ctx = self._combined_context(request)
        servers = self.server_scope.query_servers

        all_subnets: list[dict[str, Any]] = []
        read = fan_out(servers, "catalogue", lambda server: _fetch_subnets_from_server(server, self.dhcp_version))
        notices = read.notices
        for server, (subnets, found) in read.results:
            all_subnets.extend(subnets)
            notices.add(server, found)

        # Annotate can_change per server so subnet pool/action controls render correctly.
        writable_pks = set(
            Server.objects.restrict(request.user, "change")
            .filter(pk__in=[s.pk for s in servers])
            .values_list("pk", flat=True)
        )
        for subnet in all_subnets:
            can_change = subnet.get("server_pk") in writable_pks
            subnet["can_change"] = bool(subnet.get("identity_verified")) and can_change
            subnet["can_edit_options"] = subnet["can_change"] and bool(subnet.get("configuration_available"))

        table_cls = tables.GlobalSubnetTable4 if self.dhcp_version == 4 else tables.GlobalSubnetTable6

        search_form = forms.SubnetSearchForm(request.GET or None)
        if search_form.is_valid():
            all_subnets = _filter_subnets(
                all_subnets,
                q=search_form.cleaned_data.get("q", ""),
                subnet_id=search_form.cleaned_data.get("subnet_id"),
            )

        table = table_cls(all_subnets, user=request.user)
        table.configure(request)

        if "export" in request.GET:
            return export_table(table, filename=f"kea-dhcpv{self.dhcp_version}-subnets.csv")

        ctx.update(
            {
                "table": table,
                "search_form": search_form,
                "errors": notices.errors,
                "warnings": notices.warnings,
                "dhcp_version": self.dhcp_version,
                "page_title": f"DHCPv{self.dhcp_version} Subnets",
            }
        )
        return render(request, self.template_name, ctx)


class CombinedSubnets4View(_CombinedSubnetsView):
    """Combined DHCPv4 subnets across all selected servers."""

    dhcp_version = 4
    active_tab = "subnets4"


class CombinedSubnets6View(_CombinedSubnetsView):
    """Combined DHCPv6 subnets across all selected servers."""

    dhcp_version = 6
    active_tab = "subnets6"


class _CombinedSharedNetworksView(_CombinedViewMixin):
    """Base view: fetch shared networks from all selected servers concurrently."""

    template_name = "netbox_kea/combined_shared_networks.html"
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Merge shared network lists from all queried servers into one table."""
        ctx = self._combined_context(request)
        servers = self.server_scope.query_servers

        all_networks: list[dict[str, Any]] = []
        writable_pks = set(
            Server.objects.restrict(request.user, "change")
            .filter(pk__in=[s.pk for s in servers])
            .values_list("pk", flat=True)
        )

        # An unavailable Server Configuration is a Snapshot with no facts and an error Notice.
        read = fan_out(servers, "configuration", lambda server: server_configuration.display(server, self.dhcp_version))
        notices = read.notices
        for server, snapshot in read.results:
            notices.add(server, notice(snapshot))
            all_networks.extend(
                _shared_network_row(
                    network,
                    server,
                    self.dhcp_version,
                    can_change=server.pk in writable_pks,
                    include_server_name=True,
                )
                for network in snapshot.shared_networks
            )

        table = tables.GlobalSharedNetworkTable(all_networks, user=request.user)
        table.configure(request)

        if "export" in request.GET:
            return export_table(table, filename=f"kea-dhcpv{self.dhcp_version}-shared-networks.csv")

        ctx.update(
            {
                "table": table,
                "errors": notices.errors,
                "warnings": notices.warnings,
                "dhcp_version": self.dhcp_version,
                "page_title": f"DHCPv{self.dhcp_version} Shared Networks",
            }
        )
        return render(request, self.template_name, ctx)


class CombinedSharedNetworks4View(_CombinedSharedNetworksView):
    """Combined DHCPv4 shared networks across all selected servers."""

    dhcp_version = 4
    active_tab = "shared_networks4"


class CombinedSharedNetworks6View(_CombinedSharedNetworksView):
    """Combined DHCPv6 shared networks across all selected servers."""

    dhcp_version = 6
    active_tab = "shared_networks6"


class _CombinedReservationsView(_CombinedViewMixin):
    """Base view: fetch reservations from all selected servers concurrently."""

    template_name = "netbox_kea/combined_reservations.html"
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Merge reservation lists from all queried servers into one table."""
        ctx = self._combined_context(request)
        servers = self.server_scope.query_servers

        is_export = "export" in request.GET
        search_form = forms.ReservationSearchForm(request.GET or None)
        filters = search_form.cleaned_data if search_form.is_valid() else {}
        export_format = request.GET.get("export", "")
        if is_export and export_format not in ("yaml", "json"):
            return HttpResponse("Reservation export format must be YAML or JSON.", status=400)

        if is_export:
            queries = {server.pk: ReservationQuery(full=True) for server in servers}
        else:
            writable_pks = set(
                Server.objects.restrict(request.user, "change")
                .filter(pk__in=[server.pk for server in servers])
                .values_list("pk", flat=True)
            )
            queries = {
                server.pk: ReservationQuery(
                    cursor=request.GET.get(f"reservation_cursor_{server.pk}"),
                    mutations=server.pk in writable_pks,
                    **filters,
                )
                for server in servers
                if request.GET.get(f"reservation_cursor_{server.pk}") != "done"
            }
        read = fan_out(
            [server for server in servers if server.pk in queries],
            "reservation",
            lambda server: fetch_reservations(server, self.dhcp_version, queries[server.pk]),
        )
        notices = read.notices

        if is_export:
            loaded = [server_read.loaded for _server, server_read in read.results]
            snapshots = [item for item in loaded if not isinstance(item, Notice)]
            if notices.errors or len(snapshots) < len(loaded) or any(not snapshot.complete for snapshot in snapshots):
                return HttpResponse(
                    "The combined Reservation Snapshot is incomplete and cannot be exported.", status=409
                )
            records = tuple(record for snapshot in snapshots for record in snapshot.records)
            content = export_reservation_document(records, export_format)
            response = HttpResponse(
                content,
                content_type="application/json" if export_format == "json" else "application/yaml",
            )
            response["Content-Disposition"] = (
                f'attachment; filename="kea-dhcpv{self.dhcp_version}-reservations.{export_format}"'
            )
            return response

        # Present in the main thread so Django ORM queries see the test transaction.
        all_records: list[dict[str, Any]] = []
        mutation_unavailable_servers: list[tuple[str, str]] = []
        snapshots = []
        partial = bool(notices.errors)
        next_query = request.GET.copy()
        next_query.pop("page", None)
        has_next = False
        for server, server_read in read.results:
            presented = present_reservations(request.user, server, server_read, return_url=request.get_full_path())
            notices.add(server, presented.notice)
            all_records.extend(presented.rows)
            partial = partial or presented.partial
            if presented.rows and presented.mutation_unavailable_reason:
                mutation_unavailable_servers.append((server.name, presented.mutation_unavailable_reason))
            if presented.snapshot is None:
                continue
            snapshots.append(presented.snapshot)
            if presented.next_cursor is None:
                next_query[f"reservation_cursor_{server.pk}"] = "done"
            else:
                next_query[f"reservation_cursor_{server.pk}"] = presented.next_cursor
                has_next = True

        table_cls = tables.GlobalReservationTable4 if self.dhcp_version == 4 else tables.GlobalReservationTable6
        table = table_cls(
            all_records,
            user=request.user,
            empty_text=reservation_empty_text(ReservationQuery(**filters).filtered, partial),
        )
        table.configure(request)

        ctx.update(
            {
                "table": table,
                "search_form": search_form,
                "errors": notices.errors,
                "mutation_unavailable_servers": mutation_unavailable_servers,
                "reservation_diagnostics": notices.record_diagnostics,
                "snapshot_complete": not notices.errors and all(snapshot.complete for snapshot in snapshots),
                # A failed Server read is already in the error list, so only a read Snapshot can be incomplete.
                "snapshot_incomplete": any(not snapshot.complete for snapshot in snapshots),
                "next_page_url": f"{request.path}?{next_query.urlencode()}" if has_next else None,
                "dhcp_version": self.dhcp_version,
                "page_title": f"DHCPv{self.dhcp_version} Reservations",
            }
        )
        return render(request, self.template_name, ctx)


class CombinedReservations4View(_CombinedReservationsView):
    """Combined DHCPv4 reservations across all selected servers."""

    dhcp_version = 4
    active_tab = "reservations4"


class CombinedReservations6View(_CombinedReservationsView):
    """Combined DHCPv6 reservations across all selected servers."""

    dhcp_version = 6
    active_tab = "reservations6"


class _LeaseServerChooserView(_CombinedViewMixin):
    """Choose one Server in the Server Scope for a lease search."""

    has_combined_export = False
    template_name = "netbox_kea/combined_leases.html"
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """List the Servers that serve the requested family without reading Kea."""
        ctx = self._combined_context(request)
        # Django forms read the last value of a repeated field, so the chooser does too.
        search = {key: value for key in _LEASE_SEARCH_FIELDS if (value := request.GET.get(key))}
        search_suffix = f"?{urlencode(search)}" if search else ""
        fields = (forms.Leases4SearchForm if self.dhcp_version == 4 else forms.Leases6SearchForm).base_fields
        ctx.update(
            {
                "pending_search": [
                    (fields[key].label, _search_value_label(fields[key], value)) for key, value in search.items()
                ],
                "lease_servers": [
                    (
                        server,
                        reverse(f"plugins:netbox_kea:server_leases{self.dhcp_version}", args=[server.pk])
                        + search_suffix,
                    )
                    for server in self.server_scope.query_servers
                ],
                "dhcp_version": self.dhcp_version,
                "page_title": f"DHCPv{self.dhcp_version} Leases",
            }
        )
        return render(request, self.template_name, ctx)


class CombinedLeases4View(_LeaseServerChooserView):
    """Server chooser for DHCPv4 leases."""

    dhcp_version = 4
    active_tab = "leases4"


class CombinedLeases6View(_LeaseServerChooserView):
    """Server chooser for DHCPv6 leases."""

    dhcp_version = 6
    active_tab = "leases6"
