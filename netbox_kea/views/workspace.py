# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Workspace Sections and the canonical Server workspace navigation."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django import forms as django_forms
from django.conf import settings
from django.http import HttpRequest, HttpResponse, QueryDict
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from utilities.views import ObjectPermissionRequiredMixin

from .. import constants, forms
from ..constants import Family, validate_family
from ..models import Server
from ._base import _safe_return_url

PAGINATION = "page"
TABLE_FIELDS = ("sort", "per_page")


@dataclass(frozen=True)
class SubnetSearch:
    """A search value that names one Subnet of one Server and family, and the query fields that carry it."""

    fields: tuple[str, ...]
    text: str
    by_cidr: bool


def _no_subnet_search(query: QueryDict) -> SubnetSearch | None:
    return None


def _subnet_id_search(query: QueryDict) -> SubnetSearch | None:
    return SubnetSearch(("subnet_id",), query.get("subnet_id", ""), by_cidr=False) if "subnet_id" in query else None


def _lease_subnet_search(query: QueryDict) -> SubnetSearch | None:
    by = query.get("by")
    if by not in (constants.BY_SUBNET, constants.BY_SUBNET_ID):
        return None
    return SubnetSearch(("q", "by"), query.get("q", ""), by_cidr=by == constants.BY_SUBNET)


@dataclass(frozen=True)
class WorkspaceSection:
    """One Workspace Section or subsection: its routes, native tab and search filters.

    A route takes the family as its ``family`` route parameter; a Server route with *family_in_query* takes it as
    a query field.
    """

    key: str
    label: str
    server_route: str
    combined_route: str | None
    native_tab: str | None = None
    search_forms: dict[Family, type[django_forms.Form]] = field(default_factory=dict)
    parent: str | None = None
    subnet_search: Callable[[QueryDict], SubnetSearch | None] = _no_subnet_search
    # Filter fields that are valid only together, so an invalid one drops all of them.
    paired_fields: frozenset[str] = frozenset()
    # The label of a top-level section among its own subsections, when it differs from its section tab.
    subsection_label: str | None = None
    family_in_query: bool = False

    @property
    def filter_fields(self) -> frozenset[str]:
        """Return the fields of the search form and the table fields; pagination is never a filter."""
        searched = {name for form in self.search_forms.values() for name in form.base_fields}
        return frozenset((searched | set(TABLE_FIELDS)) - {PAGINATION})

    def server_url(self, pk: int, family: Family) -> str:
        """Return the list of this section on one Server for *family*."""
        if self.family_in_query:
            return reverse(f"plugins:netbox_kea:{self.server_route}", args=[pk]) + f"?family={family}"
        if "{family}" in self.server_route:
            return reverse(f"plugins:netbox_kea:{self.server_route.format(family=family)}", args=[pk])
        return reverse(f"plugins:netbox_kea:{self.server_route}", kwargs={"pk": pk, "family": family})

    def combined_url(self, family: Family) -> str:
        """Return the combined page of this section for *family*."""
        if self.combined_route is None:
            raise ValueError(f"The Workspace Section {self.key} has no combined page.")
        if "{family}" in self.combined_route:
            return reverse(f"plugins:netbox_kea:{self.combined_route.format(family=family)}")
        return reverse(f"plugins:netbox_kea:{self.combined_route}", kwargs={"family": family})


WORKSPACE_SECTIONS = {
    section.key: section
    for section in (
        WorkspaceSection("overview", "Overview", "server", "combined_overview{family}", "status", family_in_query=True),
        WorkspaceSection(
            "leases",
            "Leases",
            "server_leases",
            "combined_leases{family}",
            "leases_tab",
            {4: forms.Leases4SearchForm, 6: forms.Leases6SearchForm},
            subnet_search=_lease_subnet_search,
            paired_fields=frozenset(("q", "by")),
        ),
        WorkspaceSection(
            "subnets",
            "Subnets",
            "server_subnets",
            "combined_subnets{family}",
            "subnets_tab",
            {4: forms.SubnetSearchForm, 6: forms.SubnetSearchForm},
            subnet_search=_subnet_id_search,
        ),
        WorkspaceSection(
            "shared_networks",
            "Shared Networks",
            "server_shared_networks",
            "combined_shared_networks{family}",
            parent="subnets",
        ),
        WorkspaceSection(
            "reservations",
            "Reservations",
            "server_reservations",
            "combined_reservations{family}",
            "reservations_tab",
            {4: forms.ReservationSearchForm, 6: forms.ReservationSearchForm},
            subnet_search=_subnet_id_search,
        ),
        WorkspaceSection(
            "configuration",
            "Configuration",
            "server_option_def",
            "combined_configuration{family}",
            "option_def_tab",
            subsection_label="Option Definitions",
        ),
        WorkspaceSection("options", "Server Options", "server_dhcp_options_edit", None, parent="configuration"),
        WorkspaceSection(
            "sync", "Sync", "server_sync_status", "combined_sync{family}", "sync_status", family_in_query=True
        ),
    )
}


def top_sections() -> list[WorkspaceSection]:
    """Return the Workspace Sections without their subsections, in navigation order."""
    return [section for section in WORKSPACE_SECTIONS.values() if section.parent is None]


def subsections(section: WorkspaceSection) -> list[WorkspaceSection]:
    """Return the top-level *section* and its subsections, in navigation order."""
    return [section, *(child for child in WORKSPACE_SECTIONS.values() if child.parent == section.key)]


def subsection_nav(section: WorkspaceSection, pk: int, family: Family) -> list[tuple[str, str, str, bool]]:
    """Return the key, label, Server URL and current state of each subsection beside *section*."""
    return [
        (entry.key, entry.subsection_label or entry.label, entry.server_url(pk, family), entry.key == section.key)
        for entry in subsections(top_section(section))
    ]


def top_section(section: WorkspaceSection) -> WorkspaceSection:
    """Return the top-level section of *section*."""
    return WORKSPACE_SECTIONS[section.parent] if section.parent else section


def scope_section(section: WorkspaceSection) -> WorkspaceSection:
    """Return the section that a scope change opens: a subsection without a combined page opens its parent."""
    return section if section.combined_route else top_section(section)


def view_section(view: Any) -> WorkspaceSection:
    """Return the Workspace Section that a view class or instance declares."""
    subsection = getattr(view, "workspace_subsection", None)
    return WORKSPACE_SECTIONS[subsection or str(getattr(view, "workspace_section", "overview"))]


def workspace_filters(query: QueryDict, section: WorkspaceSection) -> QueryDict:
    """Keep the filter fields of *section*: every sort value, and the last value of a search field."""
    fields = section.filter_fields
    result = QueryDict(mutable=True)
    for key in query:
        if key in fields:
            values = query.getlist(key)
            # NetBox sorts a table by each sort value; a Django form reads the last value of a field.
            result.setlist(key, values if key in TABLE_FIELDS else values[-1:])
    return result


def drop_invalid_filters(query: QueryDict, section: WorkspaceSection, family: Family) -> bool:
    """Remove each search field that the search form of *family* refuses, with its paired fields."""
    form_class = section.search_forms.get(family)
    if form_class is None:
        return False
    form = form_class(query)
    if form.is_valid():
        return False
    invalid = set(form.errors)
    if invalid & (section.paired_fields | {"__all__"}):
        invalid.update(section.paired_fields)
    for key in invalid:
        query.pop(key, None)
    return True


def family_filters(query: QueryDict, section: WorkspaceSection, family: Family, selected: Family) -> QueryDict:
    """Keep the filters of *section* that mean the same in *family*, without a Kea read.

    Kea gives Subnet IDs per family, so a Subnet-bound field stays only in the *selected* family.
    """
    result = workspace_filters(query, section)
    if family == selected:
        return result
    if (search := section.subnet_search(result)) is not None:
        for key in search.fields:
            result.pop(key, None)
    drop_invalid_filters(result, section, family)
    return result


def with_query(url: str, query: QueryDict) -> str:
    """Append *query* to *url*, which can already hold query fields."""
    return url + (("&" if "?" in url else "?") + query.urlencode() if query else "")


def with_return_url(url: str, return_url: str) -> str:
    """Carry the previous workspace alongside the target's own query fields."""
    if not return_url:
        return url
    parsed = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != "return_url"]
    return urlunsplit(parsed._replace(query=urlencode([*query, ("return_url", return_url)])))


def selected_family(request: HttpRequest, server: Server, view: Any) -> Family:
    """Read the route's family, or the explicit selection on a native Server page."""
    match = request.resolver_match
    if match is not None and "family" in match.kwargs:
        return validate_family(match.kwargs["family"])
    family = getattr(view, "dhcp_version", None)
    if family in (4, 6):
        return cast(Family, family)
    selected = request.GET.get("family")
    if selected in ("4", "6"):
        return 4 if selected == "4" else 6
    return 4 if server.dhcp4 else 6


def server_family_url(request: HttpRequest, server: Server, view: Any, name: str) -> str:
    """Retain the selected family when navigating to a native Server route."""
    url = reverse(f"plugins:netbox_kea:{name}", args=[server.pk]) + f"?family={selected_family(request, server, view)}"
    return with_return_url(url, _safe_return_url(request, ""))


def server_context(request: HttpRequest, server: Server) -> dict[str, Any]:
    """Build the shared shell from the Server page's section and requested family."""
    match = request.resolver_match
    view = getattr(match.func, "view_class", None) if match else None
    family = selected_family(request, server, view)
    section = view_section(view)
    scoped = scope_section(section)
    return_url = _safe_return_url(request, "")

    def family_url(version: Family) -> str:
        url = with_return_url(section.server_url(server.pk, version), return_url)
        return with_query(url, family_filters(request.GET, section, version, family))

    switch_query = workspace_filters(request.GET, scoped)
    switch_query["section"] = scoped.key
    switch_query["family"] = str(family)
    if match and set(match.kwargs) - {"pk", "family"}:
        switch_query["record_selection"] = "1"
    if return_url:
        switch_query["return_url"] = return_url
    switch_url = reverse("plugins:netbox_kea:server_switch", args=[server.pk])
    switches = []
    for choice in Server.objects.restrict(request.user, "view").exclude(pk=server.pk).order_by("name"):
        switch_query["target"] = str(choice.pk)
        switches.append((choice.name, switch_url + "?" + switch_query.urlencode()))

    return {
        "workspace_scope_label": server.name,
        "workspace_return_url": return_url,
        "workspace_section": top_section(section).key,
        "workspace_family": family,
        "workspace_sections": [
            (entry.key, entry.label, with_return_url(entry.server_url(server.pk, family), return_url))
            for entry in top_sections()
        ],
        "workspace_families": [(version, family_url(version)) for version in (4, 6)],
        "workspace_subsections": [],
        "workspace_server_switches": switches,
        "workspace_all_servers_url": with_query(scoped.combined_url(family), workspace_filters(request.GET, scoped)),
    }


class FamilyRouteMixin:
    """Read the address family of a view from its ``family`` route parameter."""

    kwargs: dict[str, Any]

    @property
    def dhcp_version(self) -> Family:
        """Return the address family of the route."""
        return validate_family(self.kwargs["family"])

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Keep the family out of the handler arguments, so that a handler reads it from ``dhcp_version``."""
        kwargs.pop("family", None)
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]


class ServerFamilyMixin:
    """Refuse a disabled family before a Server view reads or changes Kea."""

    workspace_section = "overview"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Use the native permitted Server scope before showing the disabled state."""
        if not request.user.is_authenticated and settings.LOGIN_REQUIRED:
            return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]
        if isinstance(self, ObjectPermissionRequiredMixin) and not self.has_permission():
            return self.handle_no_permission()
        if request.method not in ("GET", "HEAD", "OPTIONS") and (refusal := self.server_scope_access(request)):
            return refusal
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=kwargs["pk"])
        family = selected_family(request, server, self)
        if not (server.dhcp4 if family == 4 else server.dhcp6):
            if request.method not in ("GET", "HEAD", "OPTIONS") and (
                refusal := self.disabled_family_access(request, server)
            ):
                return refusal
            if request.headers.get("HX-Request") == "true":
                response = HttpResponse()
                response["HX-Refresh"] = "true"
                return response
            context = server_context(request, server)
            enabled = next(
                (
                    (family, url)
                    for family, url in context["workspace_families"]
                    if (server.dhcp4 if family == 4 else server.dhcp6)
                ),
                None,
            )
            return render(
                request,
                "netbox_kea/server_protocol_disabled.html",
                {"object": server, "enabled_family": enabled},
            )
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]

    def server_scope_access(self, request: HttpRequest) -> HttpResponse | None:
        """Keep object-independent action refusals before the Server lookup."""
        return None

    def disabled_family_access(self, request: HttpRequest, server: Server) -> HttpResponse | None:
        """Keep an action's extra permission refusal before the disabled state."""
        return None
