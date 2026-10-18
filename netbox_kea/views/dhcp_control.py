# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from typing import Any

from django.http import HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from netbox.views import generic

from .. import forms, runtime_change
from ..constants import Family
from ..models import Server
from ._base import _KeaChangeMixin, _run_change
from .workspace import ServerFamilyMixin, server_family_url


class _BaseServerDHCPEnableView(_KeaChangeMixin, ServerFamilyMixin, generic.ObjectView):
    """Confirmation view to re-enable a Kea DHCP service that was previously disabled."""

    workspace_section = "overview"

    queryset = Server.objects.all()
    dhcp_version: Family
    template_name = "netbox_kea/server_dhcp_enable.html"

    def get_extra_context(self, request: HttpRequest, instance: Server) -> dict[str, Any]:
        return {"dhcp_version": self.dhcp_version}

    def post(self, request: HttpRequest, pk: int, **kwargs: Any) -> HttpResponse:
        instance = self.get_object(pk=pk)
        _run_change(
            request,
            f"DHCPv{self.dhcp_version} service re-enabled on {instance}.",
            lambda: runtime_change.enable_dhcp(instance, self.dhcp_version),
        )
        return redirect(server_family_url(request, instance, self, "server"))


class ServerDHCP4EnableView(_BaseServerDHCPEnableView):
    """Re-enable DHCPv4 processing."""

    dhcp_version = 4


class ServerDHCP6EnableView(_BaseServerDHCPEnableView):
    """Re-enable DHCPv6 processing."""

    dhcp_version = 6


class _BaseServerDHCPDisableView(_KeaChangeMixin, ServerFamilyMixin, generic.ObjectView):
    """Confirmation form to temporarily disable a Kea DHCP service."""

    workspace_section = "overview"

    queryset = Server.objects.all()
    dhcp_version: Family
    template_name = "netbox_kea/server_dhcp_disable.html"

    def get_extra_context(self, request: HttpRequest, instance: Server) -> dict[str, Any]:
        form = forms.DHCPDisableForm(request.POST or None)
        return {"dhcp_version": self.dhcp_version, "form": form}

    def post(self, request: HttpRequest, pk: int, **kwargs: Any) -> HttpResponse:
        instance = self.get_object(pk=pk)
        form = forms.DHCPDisableForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                self.get_extra_context(request, instance) | {"object": instance},
            )
        max_period = form.cleaned_data.get("max_period")
        period = f" for up to {max_period}s" if max_period else ""
        _run_change(
            request,
            f"DHCPv{self.dhcp_version} disabled on {instance}{period}.",
            lambda: runtime_change.disable_dhcp(instance, self.dhcp_version, max_period),
            applied_warning=True,
        )
        return redirect(server_family_url(request, instance, self, "server"))


class ServerDHCP4DisableView(_BaseServerDHCPDisableView):
    """Disable DHCPv4 processing."""

    dhcp_version = 4


class ServerDHCP6DisableView(_BaseServerDHCPDisableView):
    """Disable DHCPv6 processing."""

    dhcp_version = 6
