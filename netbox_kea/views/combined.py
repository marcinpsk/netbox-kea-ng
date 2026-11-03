# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from typing import Any, cast

from django.contrib import messages
from django.forms import ChoiceField, Field
from django.http import HttpResponse, QueryDict
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from django.views import View

from .. import forms, server_configuration, subnet_catalogue, tables
from ..constants import Family
from ..models import Server
from ..reservation_transfer import export_reservation_document
from ..subnet_catalogue import CatalogueSnapshot
from ..sync_run_result import latest
from ..utilities import export_table
from ._base import (
    ConditionalLoginRequiredMixin,
    _catalogue_subnet_row,
    _enrich_subnet_statistics,
    _filter_subnets,
    _shared_network_row,
)
from .fan_out import fan_out
from .notices import Notice, ServerNotices, notice
from .read_age import read_age_context, refresh_requested
from .reservations import ReservationQuery, ReservationRead
from .reservations import empty_text as reservation_empty_text
from .reservations import fetch as fetch_reservations
from .reservations import present as present_reservations
from .server_scope import SELECTION_FIELD, ServerScope, resolve
from .workspace import (
    WORKSPACE_SECTIONS,
    WorkspaceSection,
    family_filters,
    subsections,
    top_section,
    top_sections,
    view_section,
    with_query,
    with_return_url,
    workspace_filters,
)


def _search_value_label(field: Field, value: str) -> str:
    """Return the choice label of *value*, or *value* itself for free text or an unknown choice."""
    if not isinstance(field, ChoiceField):
        return value
    # The lease search forms use flat (value, label) choices.
    return dict(cast("list[tuple[str, str]]", field.choices)).get(value, value)


class _CombinedViewMixin(ConditionalLoginRequiredMixin, View):
    """Resolve the Server Scope once before a combined page reads live data."""

    workspace_section = "overview"
    workspace_subsection: str | None = None
    dhcp_version: Family
    server_scope: ServerScope
    has_combined_export = True

    @property
    def section(self) -> WorkspaceSection:
        """Return the Workspace Section of this combined page."""
        return view_section(self)

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
            return redirect(self.section.combined_url(self.dhcp_version) + "?" + query.urlencode())
        # A download stays on a section that supports combined exports.
        if self.server_scope.is_one and not is_export:
            server = self.server_scope.servers[0]
            target = with_query(
                self.section.server_url(server.pk, self.dhcp_version), workspace_filters(request.GET, self.section)
            )
            if request.headers.get("HX-Request") == "true":
                response = HttpResponse()
                response["HX-Redirect"] = target
                return response
            return redirect(target)
        return self.get_server_scoped(request)

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Render a combined section within its resolved Server Scope."""
        raise NotImplementedError

    def _combined_context(self, request: HttpRequest) -> dict[str, Any]:
        """Build context vars shared by every combined view."""
        server_scope_warnings: list[tuple[str, str]] = []
        # All permitted Servers skip a Server without the family; only an explicit selection reports it.
        if not self.server_scope.is_all:
            server_scope_warnings.extend(
                (server.name, f"DHCPv{self.dhcp_version} is not enabled on this Server.")
                for server in self.server_scope.missing_family
            )
        section = self.section
        parent = top_section(section)
        filters = workspace_filters(request.GET, section)
        family = self.dhcp_version
        scope_label = (
            "Invalid Server selection"
            if self.server_scope.is_invalid
            else "All Servers"
            if self.server_scope.is_all
            else self.server_scope.servers[0].name
            if self.server_scope.is_one
            else f"{len(self.server_scope.servers)} Servers selected"
        )

        def scope_url(entry: WorkspaceSection, version: Family, query: QueryDict | None = None) -> str:
            # Use the resolver's normalized IDs, or its raw invalid selection.
            url = entry.combined_url(version)
            if self.server_scope.server_qs:
                url += f"?{self.server_scope.server_qs}"
            return with_query(url, query) if query is not None else url

        combined_subsections = [entry for entry in subsections(parent) if entry.combined_route]
        return {
            "server_scope": self.server_scope,
            "server_selector_fields": [
                (SELECTION_FIELD, "1"),
                *((key, value) for key, values in filters.lists() for value in values),
            ],
            "server_scope_all_url": with_query(request.path, filters),
            "server_scope_warnings": server_scope_warnings,
            "workspace_title": f"{scope_label} · {parent.label} · DHCPv{family}",
            "workspace_scope_label": scope_label,
            "workspace_section_label": parent.label,
            "workspace_section": parent.key,
            "workspace_subsection": section.key,
            "workspace_family": family,
            "workspace_sections": [(entry.key, entry.label, scope_url(entry, family)) for entry in top_sections()],
            "workspace_families": [
                (version, scope_url(section, version, family_filters(request.GET, section, version)))
                for version in (4, 6)
            ],
            "workspace_subsections": [
                (entry.key, entry.subsection_label or entry.label, scope_url(entry, family))
                for entry in combined_subsections
            ]
            if len(combined_subsections) > 1
            else [],
        }


class CombinedDashboardView(_CombinedViewMixin):
    """Combined overview: lists all Kea servers with their configuration summary.

    Intentionally makes no live Kea API calls so the page loads quickly
    regardless of server availability.
    """

    dhcp_version: Family = 4
    has_combined_export = False
    template_name = "netbox_kea/combined_overview.html"

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Render the overview with the Servers in the resolved Server Scope."""
        ctx = self._combined_context(request)
        ctx["page_title"] = "All Kea Servers"
        path = request.get_full_path()
        ctx["server_cards"] = [
            (
                server,
                *(
                    with_return_url(WORKSPACE_SECTIONS[key].server_url(server.pk, self.dhcp_version), path)
                    for key in ("overview", "reservations", "subnets")
                ),
            )
            for server in self.server_scope.servers
        ]
        return render(request, self.template_name, ctx)


class CombinedDashboard6View(CombinedDashboardView):
    """Combined overview with DHCPv6 selected in the workspace shell."""

    dhcp_version = 6


class _ConfigurationServerChooserView(_CombinedViewMixin):
    """Choose a permitted Server for family-specific DHCP configuration."""

    workspace_section = "configuration"
    has_combined_export = False
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """List only selected Servers that serve this family, without reading Kea."""
        ctx = self._combined_context(request)
        ctx["configuration_servers"] = [
            (
                server,
                with_return_url(self.section.server_url(server.pk, self.dhcp_version), request.get_full_path()),
            )
            for server in self.server_scope.query_servers
        ]
        return render(request, "netbox_kea/combined_configuration.html", ctx)


class CombinedConfiguration4View(_ConfigurationServerChooserView):
    """Server chooser for DHCPv4 configuration."""


class CombinedConfiguration6View(_ConfigurationServerChooserView):
    """Server chooser for DHCPv6 configuration."""

    dhcp_version = 6


class _CombinedSyncView(_CombinedViewMixin):
    """Show recorded sync results for selected Servers without reading Kea."""

    workspace_section = "sync"
    has_combined_export = False
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Show the latest job of each Server and the Sync Run Result of the Server in it."""
        ctx = self._combined_context(request)
        rows = []
        for server in self.server_scope.query_servers:
            url = with_return_url(self.section.server_url(server.pk, self.dhcp_version), request.get_full_path())
            rows.append((server, *latest(server.pk), url))
        ctx["sync_results"] = rows
        return render(request, "netbox_kea/combined_sync.html", ctx)


class CombinedSync4View(_CombinedSyncView):
    """Recorded sync results with DHCPv4 selected."""


class CombinedSync6View(_CombinedSyncView):
    """Recorded sync results with DHCPv6 selected."""

    dhcp_version = 6


def _fetch_subnets_from_server(
    server: "Server",
    version: Family,
    *,
    live: bool,
) -> tuple[list[dict[str, Any]], Notice | None]:
    """Fetch safe Subnet Catalogue facts for one server, tagged for the combined table, and its Notice.

    With *live*, for an export, the utilization is read live.
    """
    snapshot = subnet_catalogue.display(server, version)
    if snapshot.unavailable:
        return [], notice(snapshot)
    result = [
        _catalogue_subnet_row(subnet, server, version, can_change=False)
        for subnet in (*snapshot.subnets, *snapshot.configured_subnets)
    ]

    _enrich_subnet_statistics(result, server, version, live=live)
    return result, notice(snapshot)


class _CombinedSubnetsView(_CombinedViewMixin):
    """Base view: fetch subnets from all selected servers concurrently."""

    workspace_section = "subnets"
    template_name = "netbox_kea/combined_subnets.html"
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """Merge subnet lists from all queried servers into one table."""
        ctx = self._combined_context(request)
        servers = self.server_scope.query_servers

        all_subnets: list[dict[str, Any]] = []
        live = "export" in request.GET
        read = fan_out(
            servers, "catalogue", lambda server: _fetch_subnets_from_server(server, self.dhcp_version, live=live)
        )
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
            subnet["return_url"] = request.get_full_path()
            subnet["record_url"] = with_return_url(
                self.section.server_url(subnet["server_pk"], self.dhcp_version),
                request.get_full_path(),
            )
            can_change = subnet.get("server_pk") in writable_pks
            subnet["can_change"] = bool(subnet.get("identity_verified")) and can_change
            subnet["can_edit_options"] = subnet["can_change"] and bool(subnet.get("configuration_available"))

        table_cls = tables.GlobalSubnetTable4 if self.dhcp_version == 4 else tables.GlobalSubnetTable6

        search_form = forms.SubnetSearchForm(request.GET or None)
        all_subnets = _filter_subnets(all_subnets, search_form)

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


class CombinedSubnets6View(_CombinedSubnetsView):
    """Combined DHCPv6 subnets across all selected servers."""

    dhcp_version = 6


class _CombinedSharedNetworksView(_CombinedViewMixin):
    """Base view: fetch shared networks from all selected servers concurrently."""

    workspace_section = "subnets"
    workspace_subsection = "shared_networks"
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

        for row in all_networks:
            row["return_url"] = request.get_full_path()
            row["record_url"] = with_return_url(
                self.section.server_url(row["server_pk"], self.dhcp_version),
                request.get_full_path(),
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


class CombinedSharedNetworks6View(_CombinedSharedNetworksView):
    """Combined DHCPv6 shared networks across all selected servers."""

    dhcp_version = 6


class _CombinedReservationsView(_CombinedViewMixin):
    """Base view: fetch reservations from all selected servers concurrently."""

    workspace_section = "reservations"
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
                    refresh=refresh_requested(request),
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
            for row in presented.rows:
                row["record_url"] = with_return_url(
                    self.section.server_url(server.pk, self.dhcp_version),
                    request.get_full_path(),
                )
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

        # A Catalogue only feeds the Subnet ID filter, so its errors do not make the Reservations incomplete.
        reservations_read = not notices.errors
        self._offer_subnets(
            search_form, servers, read.results, exhausted=[s for s in servers if s.pk not in queries], notices=notices
        )
        table_cls = tables.GlobalReservationTable4 if self.dhcp_version == 4 else tables.GlobalReservationTable6
        table = table_cls(
            all_records,
            user=request.user,
            empty_text=reservation_empty_text(ReservationQuery(**filters).filtered, partial),
        )
        table.configure(request)

        # One line shows the oldest read of the Servers in scope, and its Refresh reads each of them again.
        oldest = min((snapshot.read_started for snapshot in snapshots), default=None)
        ctx.update(
            {
                **read_age_context(oldest),
                "table": table,
                "search_form": search_form,
                "errors": notices.errors,
                "warnings": notices.warnings,
                "mutation_unavailable_servers": mutation_unavailable_servers,
                "reservation_diagnostics": notices.record_diagnostics,
                "snapshot_complete": reservations_read and all(snapshot.complete for snapshot in snapshots),
                # A failed Server read is already in the error list, so only a read Snapshot can be incomplete.
                "snapshot_incomplete": any(not snapshot.complete for snapshot in snapshots),
                "next_page_url": f"{request.path}?{next_query.urlencode()}" if has_next else None,
                "dhcp_version": self.dhcp_version,
                "page_title": f"DHCPv{self.dhcp_version} Reservations",
            }
        )
        return render(request, self.template_name, ctx)

    def _offer_subnets(
        self,
        search_form: forms.ReservationSearchForm,
        servers: list[Server],
        results: list[tuple[Server, ReservationRead]],
        *,
        exhausted: list[Server],
        notices: ServerNotices,
    ) -> None:
        """Offer the Subnet IDs of every selected Server, and report a Catalogue that could not be read."""
        catalogues: dict[int, CatalogueSnapshot | None] = {
            server.pk: server_read.catalogue for server, server_read in results
        }
        # A Server whose Reservations are exhausted is not read on later pages, but its Subnets stay choices.
        catalogue_read = fan_out(
            exhausted, "catalogue", lambda server: subnet_catalogue.display(server, self.dhcp_version)
        )
        notices.errors.extend(catalogue_read.notices.errors)
        for server, read_snapshot in catalogue_read.results:
            catalogues[server.pk] = read_snapshot
            notices.add(server, notice(read_snapshot))
        search_form.offer_subnets(
            forms.combined_subnet_id_options(
                (server.name, snapshot.subnet_choices)
                for server in servers
                if (snapshot := catalogues.get(server.pk)) is not None
            )
        )


class CombinedReservations4View(_CombinedReservationsView):
    """Combined DHCPv4 reservations across all selected servers."""

    dhcp_version = 4


class CombinedReservations6View(_CombinedReservationsView):
    """Combined DHCPv6 reservations across all selected servers."""

    dhcp_version = 6


class _LeaseServerChooserView(_CombinedViewMixin):
    """Choose one Server in the Server Scope for a lease search."""

    workspace_section = "leases"
    has_combined_export = False
    template_name = "netbox_kea/combined_leases.html"
    dhcp_version: Family = 4

    def get_server_scoped(self, request: HttpRequest) -> HttpResponse:
        """List the Servers that serve the requested family without reading Kea."""
        ctx = self._combined_context(request)
        filters = workspace_filters(request.GET, self.section)
        fields = self.section.search_forms[self.dhcp_version].base_fields
        ctx.update(
            {
                "pending_search": [
                    (fields[key].label, _search_value_label(fields[key], value))
                    for key in filters
                    if key in fields and (value := filters.getlist(key)[-1])
                ],
                "lease_servers": [
                    (
                        server,
                        with_return_url(
                            with_query(self.section.server_url(server.pk, self.dhcp_version), filters),
                            request.get_full_path(),
                        ),
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


class CombinedLeases6View(_LeaseServerChooserView):
    """Server chooser for DHCPv6 leases."""

    dhcp_version = 6
