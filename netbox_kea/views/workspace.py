# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Shared section definitions and canonical Server workspace navigation."""

from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.http import HttpRequest, HttpResponse, QueryDict
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from utilities.views import ObjectPermissionRequiredMixin

from ..constants import Family
from ..models import Server
from ._base import _safe_return_url

SECTIONS = (
    ("overview", "Overview"),
    ("leases", "Leases"),
    ("subnets", "Subnets"),
    ("reservations", "Reservations"),
    ("configuration", "Configuration"),
    ("sync", "Sync"),
)


def server_section_url(server: Server, section: str, family: Family) -> str:
    """Return the canonical list or Overview of one Server section and family."""
    names = {
        "overview": "server",
        "leases": f"server_leases{family}",
        "subnets": f"server_subnets{family}",
        "shared_networks": f"server_shared_networks{family}",
        "reservations": f"server_reservations{family}",
        "configuration": f"server_option_def{family}",
        "options": f"server_dhcp{family}_options_edit",
        "sync": "server_sync_status",
    }
    url = reverse(f"plugins:netbox_kea:{names[section]}", args=[server.pk])
    return url + (f"?family={family}" if section in ("overview", "sync") else "")


def workspace_filters(query: QueryDict, section: str) -> QueryDict:
    """Keep section filters and table preferences; pagination belongs to its Server."""
    fields = {"sort", "per_page"}
    if section == "leases":
        fields.update(("q", "by", "state"))
    elif section == "reservations":
        fields.update(("q", "subnet_id", "scope"))
    elif section == "subnets":
        fields.update(("q", "subnet_id"))
    result = query.copy()
    for key in list(result):
        if key not in fields:
            result.pop(key)
    return result


def with_return_url(url: str, return_url: str) -> str:
    """Carry the previous workspace alongside the target's own query fields."""
    if not return_url:
        return url
    parsed = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != "return_url"]
    return urlunsplit(parsed._replace(query=urlencode([*query, ("return_url", return_url)])))


def selected_family(request: HttpRequest, server: Server, view: Any) -> Family:
    """Read the route's family, or the explicit selection on a native Server page."""
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
    section = getattr(view, "workspace_section", "overview")
    subsection = getattr(view, "workspace_subsection", None)
    return_url = _safe_return_url(request, "")

    def section_url(key: str, version: Family) -> str:
        return with_return_url(server_section_url(server, key, version), return_url)

    def family_url(version: Family) -> str:
        url = section_url(subsection or section, version)
        query = workspace_filters(request.GET, subsection or section)
        suffix = query.urlencode()
        return url + (("&" if "?" in url else "?") + suffix if suffix else "")

    switch_section = "configuration" if subsection == "options" else subsection or section
    switch_query = workspace_filters(request.GET, switch_section)
    switch_query["section"] = switch_section
    switch_query["family"] = str(family)
    if match and set(match.kwargs) - {"pk"}:
        switch_query["record_selection"] = "1"
    if return_url:
        switch_query["return_url"] = return_url
    switch_url = reverse("plugins:netbox_kea:server_switch", args=[server.pk])
    switches = []
    for choice in Server.objects.restrict(request.user, "view").exclude(pk=server.pk).order_by("name"):
        switch_query["target"] = str(choice.pk)
        switches.append((choice.name, switch_url + "?" + switch_query.urlencode()))
    all_url = reverse(f"plugins:netbox_kea:combined_{switch_section}{family}")
    all_filters = workspace_filters(request.GET, switch_section)
    if all_filters:
        all_url += "?" + all_filters.urlencode()

    return {
        "workspace_scope_label": server.name,
        "workspace_return_url": return_url,
        "workspace_section": section,
        "workspace_family": family,
        "workspace_sections": [(key, label, section_url(key, family)) for key, label in SECTIONS],
        "workspace_families": [(version, family_url(version)) for version in (4, 6)],
        "workspace_subsections": [],
        "workspace_server_switches": switches,
        "workspace_all_servers_url": all_url,
    }


class ServerFamilyMixin:
    """Refuse a disabled family before a Server view reads or changes Kea."""

    dhcp_version: Family
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
