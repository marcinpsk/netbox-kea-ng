# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from typing import Any

from django.contrib import messages
from django.http import HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from netbox.views import generic
from utilities.htmx import htmx_partial
from utilities.views import register_model_view

from .. import config_write, forms, managed_fields, server_configuration, tables
from ..constants import Family
from ..models import Server
from ..utilities import export_table
from ._base import (
    ConditionalLoginRequiredMixin,
    _KeaChangeMixin,
    _run_change,
    _safe_return_url,
)
from .notices import notice, show_notices
from .server_scope import writable_servers
from .subnet_lists import fetch_shared_networks, present_shared_networks
from .subnets import _SUBNETS_TAB, subnets_nav_context
from .workspace import ServerFamilyMixin

# ─────────────────────────────────────────────────────────────────────────────
# Shared Networks views
# ─────────────────────────────────────────────────────────────────────────────


class BaseServerSharedNetworksView(ServerFamilyMixin, generic.ObjectChildrenView):
    """Read-only tab listing shared networks from the Kea config."""

    workspace_section = "subnets"
    workspace_subsection = "shared_networks"

    table = tables.SharedNetworkTable
    queryset = Server.objects.all()
    template_name = "netbox_kea/server_shared_networks.html"
    dhcp_version: Family

    def get(self, request: HttpRequest, **kwargs: Any) -> HttpResponse:
        """Render the Shared Network table, or export it."""
        instance = self.get_object(**kwargs)
        presented = present_shared_networks(
            instance,
            fetch_shared_networks(instance, self.dhcp_version),
            writable=writable_servers(request.user, [instance]),
            return_url=_safe_return_url(request, request.get_full_path()),
        )
        table_data = self.prep_table_data(request, presented.rows, instance)
        table = self.get_table(table_data, request, False)

        if "export" in request.GET:
            return export_table(
                table,
                filename=f"kea-dhcpv{self.dhcp_version}-shared-networks.csv",
                use_selected_columns=request.GET["export"] == "table",
            )

        if htmx_partial(request):
            return render(
                request,
                "netbox_kea/inc/list_table_htmx.html",
                {"object": instance, "table": table, "notice": presented.notice},
            )

        show_notices(request, presented.notice)
        return render(
            request,
            self.get_template_name(),
            {
                "object": instance,
                "base_template": f"{instance._meta.app_label}/{instance._meta.model_name}.html",
                "table": table,
                "table_config": f"{table.name}_config",
                "return_url": request.get_full_path(),
                "add_url": reverse(
                    f"plugins:netbox_kea:server_shared_network{self.dhcp_version}_add",
                    args=[instance.pk],
                ),
                **subnets_nav_context(instance.pk, "shared_networks", self.dhcp_version),
            },
        )


@register_model_view(Server, "shared_networks6")
class ServerSharedNetworks6View(BaseServerSharedNetworksView):
    """DHCPv6 shared networks view (rendered under the shared Subnets tab)."""

    dhcp_version = 6


@register_model_view(Server, "shared_networks4")
class ServerSharedNetworks4View(BaseServerSharedNetworksView):
    """DHCPv4 shared networks view (rendered under the shared Subnets tab)."""

    dhcp_version = 4


class BaseServerSharedNetworkAddView(_KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Add a new shared network to a Kea server.

    Subclasses set ``dhcp_version`` to 4 or 6.
    """

    workspace_section = "subnets"
    workspace_subsection = "shared_networks"

    dhcp_version: Family

    def _success_url(self, server: Server) -> str:
        return reverse(f"plugins:netbox_kea:server_shared_networks{self.dhcp_version}", args=[server.pk])

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the add-network form."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        form = forms.SharedNetworkForm()
        return render(
            request,
            "netbox_kea/server_shared_network_add.html",
            {
                "object": server,
                "server": server,
                "form": form,
                "dhcp_version": self.dhcp_version,
                "cancel_url": _safe_return_url(request, self._success_url(server)),
                "tab": self.tab,
            },
        )

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Validate and create the shared network."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        form = forms.SharedNetworkForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                "netbox_kea/server_shared_network_add.html",
                {
                    "object": server,
                    "server": server,
                    "form": form,
                    "dhcp_version": self.dhcp_version,
                    "cancel_url": _safe_return_url(request, self._success_url(server)),
                    "tab": self.tab,
                },
            )
        name = form.cleaned_data["name"]
        _run_change(
            request,
            f"Shared network '{name}' created.",
            lambda: config_write.add_shared_network(server, self.dhcp_version, name),
        )
        return redirect(_safe_return_url(request, self._success_url(server)))


class ServerSharedNetwork6AddView(BaseServerSharedNetworkAddView):
    """Add a new DHCPv6 shared network."""

    dhcp_version = 6
    tab = _SUBNETS_TAB


class ServerSharedNetwork4AddView(BaseServerSharedNetworkAddView):
    """Add a new DHCPv4 shared network."""

    dhcp_version = 4
    tab = _SUBNETS_TAB


class BaseServerSharedNetworkDeleteView(_KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Delete a shared network from a Kea server.

    The network name is passed as a URL kwarg ``network_name``.  Subnets that
    belonged to the deleted network fall back to the global address pool.
    """

    workspace_section = "subnets"
    workspace_subsection = "shared_networks"

    dhcp_version: Family

    def _success_url(self, server: Server) -> str:
        return reverse(f"plugins:netbox_kea:server_shared_networks{self.dhcp_version}", args=[server.pk])

    def get(self, request: HttpRequest, pk: int, network_name: str) -> HttpResponse:
        """Render the delete-confirmation page."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        return render(
            request,
            "netbox_kea/server_shared_network_delete.html",
            {
                "object": server,
                "server": server,
                "network_name": network_name,
                "dhcp_version": self.dhcp_version,
                "cancel_url": _safe_return_url(request, self._success_url(server)),
                "tab": self.tab,
            },
        )

    def post(self, request: HttpRequest, pk: int, network_name: str) -> HttpResponse:
        """Delete the shared network."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        _run_change(
            request,
            f"Shared network '{network_name}' deleted.",
            lambda: config_write.delete_shared_network(server, self.dhcp_version, network_name),
        )
        return redirect(_safe_return_url(request, self._success_url(server)))


class ServerSharedNetwork6DeleteView(BaseServerSharedNetworkDeleteView):
    """Delete a DHCPv6 shared network."""

    dhcp_version = 6
    tab = _SUBNETS_TAB


class ServerSharedNetwork4DeleteView(BaseServerSharedNetworkDeleteView):
    """Delete a DHCPv4 shared network."""

    dhcp_version = 4
    tab = _SUBNETS_TAB


class BaseServerSharedNetworkEditView(_KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Edit a Shared Network's managed configuration fields."""

    workspace_section = "subnets"
    workspace_subsection = "shared_networks"

    dhcp_version: Family

    def _success_url(self, server: Server) -> str:
        return reverse(f"plugins:netbox_kea:server_shared_networks{self.dhcp_version}", args=[server.pk])

    def get(self, request: HttpRequest, pk: int, network_name: str) -> HttpResponse:
        """Render the edit form pre-populated with current values."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        configuration = server_configuration.for_verification(server, self.dhcp_version)
        show_notices(request, notice(configuration))
        network = server_configuration.editable_shared_network(configuration, network_name)
        shown = None if network is None else managed_fields.shown_shared_network(network, self.dhcp_version)
        if shown is None:
            messages.error(request, f"Shared network '{network_name}' not found or could not be retrieved.")
            return redirect(_safe_return_url(request, self._success_url(server)))

        form = forms.SharedNetworkEditForm(
            initial={"name": network_name, **forms.SharedNetworkEditForm.initial_for(shown)}
        )
        return render(
            request,
            "netbox_kea/server_shared_network_edit.html",
            {
                "object": server,
                "form": form,
                "network_name": network_name,
                "dhcp_version": self.dhcp_version,
                "cancel_url": _safe_return_url(request, self._success_url(server)),
                "tab": self.tab,
            },
        )

    def post(self, request: HttpRequest, pk: int, network_name: str) -> HttpResponse:
        """Validate form and apply the shared network update."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        form = forms.SharedNetworkEditForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                "netbox_kea/server_shared_network_edit.html",
                {
                    "object": server,
                    "form": form,
                    "network_name": network_name,
                    "dhcp_version": self.dhcp_version,
                    "cancel_url": _safe_return_url(request, self._success_url(server)),
                    "tab": self.tab,
                },
            )

        edit, shown = form.to_edit(), form.shown()
        _run_change(
            request,
            f"Shared network '{network_name}' updated.",
            lambda: config_write.edit_shared_network(server, self.dhcp_version, network_name, edit, shown=shown),
        )
        return redirect(_safe_return_url(request, self._success_url(server)))


class ServerSharedNetwork6EditView(BaseServerSharedNetworkEditView):
    """Edit a DHCPv6 shared network."""

    dhcp_version = 6
    tab = _SUBNETS_TAB


class ServerSharedNetwork4EditView(BaseServerSharedNetworkEditView):
    """Edit a DHCPv4 shared network."""

    dhcp_version = 4
    tab = _SUBNETS_TAB
