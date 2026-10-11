# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Validate navigation state before opening the same section on another Server."""

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, QueryDict
from django.shortcuts import get_object_or_404, redirect
from django.views import View

from .. import constants, forms, subnet_catalogue
from ..constants import Family
from ..decimal_text import parse_decimal
from ..models import Server
from ._base import ConditionalLoginRequiredMixin, _safe_return_url
from .notices import notice, show_notices
from .workspace import SECTIONS, server_section_url, with_return_url, workspace_filters


def _checked_filters(request: HttpRequest, target: Server, section: str, family: Family) -> QueryDict:
    """Keep valid filters and confirm every Subnet search against fresh target identities."""
    query = workspace_filters(request.GET, section)
    form_types = {
        "leases": forms.Leases4SearchForm if family == 4 else forms.Leases6SearchForm,
        "reservations": forms.ReservationSearchForm,
        "subnets": forms.SubnetSearchForm,
    }
    if section not in form_types:
        return query
    form = form_types[section](query)
    if not form.is_valid():
        invalid = set(form.errors)
        if section == "leases" and invalid & {"q", "by", "__all__"}:
            invalid.update(("q", "by"))
        for key in invalid:
            query.pop(key, None)
        messages.warning(request, "Invalid search filters dropped when switching Servers.")
    lease_subnet = section == "leases" and query.get("by") in (constants.BY_SUBNET, constants.BY_SUBNET_ID)
    subnet_text = query.get("q") if lease_subnet else query.get("subnet_id")
    if not subnet_text:
        return query
    identity = subnet_catalogue.read_identity(target, family)
    show_notices(request, notice(identity.snapshot))
    try:
        subnet = (
            identity.snapshot.find_by_cidr(subnet_text)
            if lease_subnet and query["by"] == constants.BY_SUBNET
            else identity.find_by_id(parse_decimal(subnet_text))
        )
        confirmed = isinstance(subnet, subnet_catalogue.VerifiedSubnet)
    except (subnet_catalogue.CatalogueUnavailable, ValueError):
        confirmed = False
    if not confirmed:
        for key in ("q", "by") if lease_subnet else ("subnet_id",):
            query.pop(key, None)
        messages.warning(request, "Subnet filter dropped: the target Server did not confirm this Subnet.")
    return query


class ServerSwitchView(ConditionalLoginRequiredMixin, View):
    """Switch only between viewable Servers and canonical workspace sections."""

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Keep compatible search filters and reset all Server pagination."""
        permitted = Server.objects.restrict(request.user, "view")
        get_object_or_404(permitted, pk=pk)
        targets = request.GET.getlist("target")
        try:
            target_pk = parse_decimal(targets[0]) if len(targets) == 1 else 0
        except ValueError:
            return HttpResponseBadRequest("Invalid target Server.")
        if not 0 < target_pk <= 2**63 - 1:
            return HttpResponseBadRequest("Invalid target Server.")
        target = get_object_or_404(permitted, pk=target_pk)
        section = request.GET.get("section", "overview")
        family = request.GET.get("family", "4")
        if section not in {key for key, _ in SECTIONS} | {"shared_networks"} or family not in ("4", "6"):
            return HttpResponseBadRequest("Invalid workspace section or DHCP family.")
        version: Family = 4 if family == "4" else 6
        if request.GET.get("record_selection") == "1":
            messages.warning(
                request, "Record selection dropped: switching Servers opens the section, so select a record again."
            )
        url = server_section_url(target, section, version)
        query = (
            _checked_filters(request, target, section, version)
            if (target.dhcp4 if version == 4 else target.dhcp6)
            else workspace_filters(request.GET, section)
        )
        if query:
            url += ("&" if "?" in url else "?") + query.urlencode()
        return redirect(with_return_url(url, _safe_return_url(request, "")))
