# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Validate navigation state before opening the same section on another Server."""

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, QueryDict
from django.shortcuts import get_object_or_404, redirect
from django.views import View

from .. import subnet_catalogue
from ..constants import Family
from ..decimal_text import parse_decimal
from ..models import Server
from ._base import safe_return_url
from .notices import notice, show_notices
from .server_scope import ServerAccessMixin, permitted_servers
from .workspace import (
    WORKSPACE_SECTIONS,
    WorkspaceSection,
    drop_invalid_filters,
    scope_section,
    with_query,
    with_return_url,
    workspace_filters,
)


def _checked_filters(request: HttpRequest, target: Server, section: WorkspaceSection, family: Family) -> QueryDict:
    """Keep valid filters and confirm every Subnet search against fresh target identities."""
    query = workspace_filters(request.GET, section)
    if drop_invalid_filters(query, section, family):
        messages.warning(request, "Invalid search filters dropped when switching Servers.")
    search = section.subnet_search(query)
    if search is None or not search.text:
        return query
    identity = subnet_catalogue.read_identity(target, family)
    show_notices(request, notice(identity.snapshot))
    try:
        subnet = (
            identity.snapshot.find_by_cidr(search.text)
            if search.by_cidr
            else identity.find_by_id(parse_decimal(search.text))
        )
        confirmed = isinstance(subnet, subnet_catalogue.VerifiedSubnet)
    except (subnet_catalogue.CatalogueUnavailable, ValueError):
        confirmed = False
    if not confirmed:
        for key in search.fields:
            query.pop(key, None)
        messages.warning(request, "Subnet filter dropped: the target Server did not confirm this Subnet.")
    return query


class ServerSwitchView(ServerAccessMixin, View):
    """Switch only between viewable Servers and canonical workspace sections."""

    server_action = "view"
    # The switch leaves its Server, so the disabled family of that Server does not apply.
    family_scoped = False

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Keep compatible search filters and reset all Server pagination."""
        targets = request.GET.getlist("target")
        try:
            target_pk = parse_decimal(targets[0]) if len(targets) == 1 else 0
        except ValueError:
            return HttpResponseBadRequest("Invalid target Server.")
        if not 0 < target_pk <= 2**63 - 1:
            return HttpResponseBadRequest("Invalid target Server.")
        target = get_object_or_404(permitted_servers(request.user), pk=target_pk)
        key = request.GET.get("section", "overview")
        family = request.GET.get("family", "4")
        if key not in WORKSPACE_SECTIONS or family not in ("4", "6"):
            return HttpResponseBadRequest("Invalid workspace section or DHCP family.")
        section = scope_section(WORKSPACE_SECTIONS[key])
        version: Family = 4 if family == "4" else 6
        if request.GET.get("record_selection") == "1":
            messages.warning(
                request, "Record selection dropped: switching Servers opens the section, so select a record again."
            )
        query = (
            _checked_filters(request, target, section, version)
            if (target.dhcp4 if version == 4 else target.dhcp6)
            else workspace_filters(request.GET, section)
        )
        url = with_query(section.server_url(target.pk, version), query)
        return redirect(with_return_url(url, safe_return_url(request, "")))
