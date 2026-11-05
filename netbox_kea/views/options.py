# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode as _urlencode

from django.contrib import messages
from django.http import HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from utilities.views import register_model_view

from .. import config_write, forms, server_configuration
from ..config_write import ConfigChangeOutcome
from ..constants import Family
from ..dhcp_options import (
    DHCPOption,
    DHCPOptionConflict,
    DHCPOptionEdit,
    DHCPOptionNameChange,
    option_row_edit,
    posted_snapshot,
)
from ..models import Server
from ..read_failure import ReadFailure, attempt
from ..utilities import OptionalViewTab
from ._base import (
    ConditionalLoginRequiredMixin,
    LazyClient,
    _KeaChangeMixin,
    _run_change,
    _safe_return_url,
    daemon_version,
)
from .notices import notice, show_notices
from .subnets import _NO_SUBNET_CIDR, _SUBNETS_TAB, _displayed_subnet
from .workspace import WORKSPACE_SECTIONS, FamilyRouteMixin, ServerFamilyMixin, subsection_nav

# One Config tab for both sections and both families; ServerOptionDefView owns it.
_CONFIG_TAB = OptionalViewTab(label="Config", weight=1050, is_enabled=lambda s: s.dhcp4 or s.dhcp6)


def config_nav_context(server_pk: int, section: str, dhcp_version: Family) -> dict[str, Any]:
    """Build the Config tab and the subsection navigation of the Configuration section.

    ``section`` is ``"options"`` (the server DHCP Option editor) or ``"configuration"`` (the Option Definitions).
    """
    return {
        "tab": _CONFIG_TAB,
        "dhcp_version": dhcp_version,
        "subsection_nav": subsection_nav(WORKSPACE_SECTIONS[section], server_pk, dhcp_version),
    }


def _run_option_change(
    request: HttpRequest, confirmed: str, change: Callable[[DHCPOptionEdit], ConfigChangeOutcome], formset: Any
) -> bool:
    """Run the option change of the valid bound form, or keep its named conflict on the form."""
    try:
        rows = forms.option_rows(formset)
        edit = option_row_edit(rows, posted_snapshot(rows))
        _run_change(request, confirmed, lambda: change(edit))
    except (DHCPOptionConflict, DHCPOptionNameChange) as exc:
        formset._non_form_errors = formset.error_class([exc.message])
        return False
    return True


class ServerSubnetOptionsEditView(
    FamilyRouteMixin, _KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View
):
    """Edit the DHCP Options of one Subnet."""

    workspace_section = "subnets"

    tab = _SUBNETS_TAB

    def _get_subnet_from_config(
        self, request: HttpRequest, server: Server, subnet_id: int
    ) -> server_configuration.DeclaredSubnet | None:
        """Return the one complete declared Subnet with this ID from a live read."""
        snapshot = server_configuration.for_verification(server, self.dhcp_version)
        show_notices(request, notice(snapshot))
        matches = [subnet for subnet in snapshot.subnets if subnet.declared_subnet_id == subnet_id]
        if len(matches) != 1 or not matches[0].complete:
            return None
        return matches[0]

    def get(self, request, pk: int, subnet_id: int):
        """Render the DHCP Option form of the Subnet."""
        server = get_object_or_404(
            Server.objects.restrict(request.user, "change"),
            pk=pk,
        )
        return_url = _safe_return_url(
            request, reverse("plugins:netbox_kea:server_subnets", kwargs={"pk": pk, "family": self.dhcp_version})
        )
        catalogue, verified = _displayed_subnet(request, server, self.dhcp_version, subnet_id)
        if verified is None:
            reason = ", because the subnet_cmds hook is not loaded" if not catalogue.subnet_cmds_available else ""
            messages.error(
                request,
                f"Kea did not confirm the identity of Subnet {subnet_id}{reason}. "
                "NetBox changes the DHCP Options of a Subnet only after Kea confirms its identity.",
            )
            return redirect(return_url)
        subnet = self._get_subnet_from_config(request, server, subnet_id)
        if subnet is None:
            messages.error(request, "Could not load subnet configuration from Kea. The form cannot be displayed.")
            return redirect(return_url)
        initial = [opt.form_initial() for opt in subnet.configuration.options]
        formset = forms.DHCPOptionRowFormSet(initial=initial)
        form = forms.SubnetConfirmForm(initial={"subnet_cidr": subnet.declared_cidr}, family=self.dhcp_version)
        return self._render(request, server, subnet_id, subnet.declared_cidr, formset, form, return_url)

    def _render(
        self,
        request: HttpRequest,
        server: Server,
        subnet_id: int,
        subnet_cidr: str,
        formset: Any,
        form: forms.SubnetConfirmForm,
        return_url: str,
    ) -> HttpResponse:
        return render(
            request,
            "netbox_kea/server_subnet_options_edit.html",
            {
                "object": server,
                "server": server,
                "subnet_id": subnet_id,
                "subnet_cidr": subnet_cidr,
                "dhcp_version": self.dhcp_version,
                "formset": formset,
                "form": form,
                "return_url": return_url,
                "tab": self.tab,
            },
        )

    def post(self, request, pk: int, subnet_id: int):
        """Write the DHCP Options of the Subnet."""
        server = get_object_or_404(
            Server.objects.restrict(request.user, "change"),
            pk=pk,
        )
        return_url = _safe_return_url(
            request, reverse("plugins:netbox_kea:server_subnets", kwargs={"pk": pk, "family": self.dhcp_version})
        )
        formset = forms.DHCPOptionRowFormSet(request.POST)
        form = forms.SubnetConfirmForm(request.POST, family=self.dhcp_version)
        if not form.is_valid():
            messages.error(request, _NO_SUBNET_CIDR)
            return redirect(return_url)
        cidr: str = form.cleaned_data["subnet_cidr"]
        if not formset.is_valid():
            return self._render(request, server, subnet_id, cidr, formset, form, return_url)
        if not _run_option_change(
            request,
            f"Subnet {subnet_id} options updated.",
            lambda edit: config_write.set_subnet_options(server, self.dhcp_version, subnet_id, cidr, edit),
            formset,
        ):
            return self._render(request, server, subnet_id, cidr, formset, form, return_url)
        return redirect(return_url)


# ─────────────────────────────────────────────────────────────────────────────
# Server-Level DHCP Options Management
# ─────────────────────────────────────────────────────────────────────────────


class ServerDHCPOptionsEditView(
    FamilyRouteMixin, _KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View
):
    """Edit the server-global DHCP Options of one family."""

    workspace_section = "configuration"
    workspace_subsection = "options"

    def _get_options_from_config(self, request: HttpRequest, server: Server) -> tuple[DHCPOption, ...] | None:
        """Return the complete server DHCP Option list from a live read, or None."""
        snapshot = server_configuration.for_verification(server, self.dhcp_version)
        show_notices(request, notice(snapshot))
        # An unavailable Snapshot has no complete global option list.
        return snapshot.global_options if snapshot.global_options_complete else None

    def get(self, request, pk: int):
        """Render the server DHCP Option form."""
        server = get_object_or_404(
            Server.objects.restrict(request.user, "change"),
            pk=pk,
        )
        existing = self._get_options_from_config(request, server)
        if existing is None:
            messages.error(request, "Could not load server options from Kea. The form cannot be displayed.")
            return redirect(reverse("plugins:netbox_kea:server", args=[pk]))
        initial = [opt.form_initial() for opt in existing]
        formset = forms.DHCPOptionRowFormSet(initial=initial)
        return render(
            request,
            "netbox_kea/server_dhcp_options_edit.html",
            {
                "object": server,
                "server": server,
                "formset": formset,
                "return_url": reverse("plugins:netbox_kea:server", args=[pk]),
                **config_nav_context(server.pk, "options", self.dhcp_version),
            },
        )

    def post(self, request, pk: int):
        """Write the server DHCP Options."""
        server = get_object_or_404(
            Server.objects.restrict(request.user, "change"),
            pk=pk,
        )
        return_url = reverse("plugins:netbox_kea:server", args=[pk])
        formset = forms.DHCPOptionRowFormSet(request.POST)
        if not formset.is_valid():
            return render(
                request,
                "netbox_kea/server_dhcp_options_edit.html",
                {
                    "object": server,
                    "server": server,
                    "formset": formset,
                    "return_url": return_url,
                    **config_nav_context(server.pk, "options", self.dhcp_version),
                },
            )

        if not _run_option_change(
            request,
            f"DHCPv{self.dhcp_version} server options updated.",
            lambda edit: config_write.set_server_options(server, self.dhcp_version, edit),
            formset,
        ):
            return render(
                request,
                "netbox_kea/server_dhcp_options_edit.html",
                {
                    "object": server,
                    "server": server,
                    "formset": formset,
                    "return_url": return_url,
                    **config_nav_context(server.pk, "options", self.dhcp_version),
                },
            )
        return redirect(return_url)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3c: IPAddress → Kea Reservation panel
# ─────────────────────────────────────────────────────────────────────────────


class IPAddressKeaReservationsView(ConditionalLoginRequiredMixin, View):
    """Show Kea servers with pre-filled 'Create reservation' links for a NetBox IPAddress.

    Accessible at /plugins/kea/ip-addresses/<id>/kea-reservations/.
    Rendered as a standalone page and also embedded via the IPAddress template extension.
    """

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:  # noqa: D102
        from ipam.models import IPAddress as NbIP

        nb_ip = get_object_or_404(NbIP.objects.restrict(request.user, "view"), pk=pk)
        ip_str = str(nb_ip.address.ip)
        is_v6 = ":" in ip_str
        version = 6 if is_v6 else 4

        if version == 4:
            servers = Server.objects.restrict(request.user, "change").filter(dhcp4=True)
        else:
            servers = Server.objects.restrict(request.user, "change").filter(dhcp6=True)

        server_links = []
        for server in servers:
            base_url = reverse("plugins:netbox_kea:server_reservation_add", kwargs={"pk": server.pk, "family": version})
            ip_param = "ip_addresses" if version == 6 else "ip_address"
            params = _urlencode(
                {
                    ip_param: ip_str,
                    "hostname": nb_ip.dns_name or "",
                }
            )
            server_links.append(
                {
                    "server": server,
                    "url": f"{base_url}?{params}",
                }
            )

        return render(
            request,
            "netbox_kea/ip_kea_reservations.html",
            {
                "object": nb_ip,
                "nb_ip": nb_ip,
                "server_links": server_links,
                "version": version,
            },
        )


def _daemon_online(server: Server, version: Family) -> bool:
    """Return whether the DHCP daemon of *version* answers ``version-get``. A failed read is offline."""
    with LazyClient(server, version) as client:
        read = attempt(f"The DHCPv{version} status badge read of Server {server.pk}", lambda: daemon_version(client))
    return not isinstance(read, ReadFailure)


class CombinedServerStatusBadgeView(ConditionalLoginRequiredMixin, View):
    """HTMX endpoint: lightweight status fragment for one server.

    Returns a small HTML snippet containing one badge per enabled DHCP
    protocol (v4/v6).  Each badge shows "Online" or "Offline" based on
    whether ``version-get`` can reach the Kea daemon. An answer stays in the display cache for the status TTL; a
    failed read is not stored.

    Intended to be called with ``hx-get`` / ``hx-trigger="load"`` from the
    combined dashboard so the main page stays fast.
    """

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Return status badge fragment for server *pk*."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)

        families: tuple[tuple[Family, bool], ...] = ((4, server.dhcp4), (6, server.dhcp6))
        statuses = [
            {"version": version, "online": _daemon_online(server, version)} for version, enabled in families if enabled
        ]

        return render(
            request,
            "netbox_kea/server_status_badge.html",
            {"server": server, "statuses": statuses},
        )


# ---------------------------------------------------------------------------
# Option Definition views
# ---------------------------------------------------------------------------


@register_model_view(Server, "option_def_tab", path="dhcp4/option-def", kwargs={"family": 4})
class ServerOptionDefView(FamilyRouteMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """List the Option Definitions of one family of a Kea Server."""

    workspace_section = "configuration"

    tab = _CONFIG_TAB

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the Option Definition list."""
        server = get_object_or_404(Server.objects.restrict(request.user, "view"), pk=pk)
        snapshot = server_configuration.display(server, self.dhcp_version)
        show_notices(request, notice(snapshot))
        # Add delete URLs here because templates do not construct dynamic URL names.
        can_change = Server.objects.restrict(request.user, "change").filter(pk=server.pk).exists()
        enriched_defs = []
        for opt in snapshot.option_definitions:
            entry = {
                "code": opt.code,
                "name": opt.name,
                "space": opt.space,
                "type": opt.type,
                "array": opt.array,
                "encapsulate": opt.encapsulate,
                "record_types": opt.record_types,
            }
            if can_change:
                entry["delete_url"] = reverse(
                    "plugins:netbox_kea:server_option_def_delete",
                    kwargs={"pk": server.pk, "family": self.dhcp_version, "code": opt.code, "space": opt.space},
                )
            enriched_defs.append(entry)
        ctx: dict[str, Any] = {
            "object": server,
            "server": server,
            "option_defs": enriched_defs,
            "can_change": can_change,
            # An unavailable Snapshot shows its error instead of an empty list.
            "definitions_known": not snapshot.unavailable,
            **config_nav_context(server.pk, "configuration", self.dhcp_version),
        }
        if can_change:
            ctx["add_url"] = reverse(
                "plugins:netbox_kea:server_option_def_add", kwargs={"pk": server.pk, "family": self.dhcp_version}
            )
        return render(request, "netbox_kea/server_option_def_list.html", ctx)


class ServerOptionDefAddView(FamilyRouteMixin, _KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View):
    """Add a custom option definition to a Kea server."""

    workspace_section = "configuration"

    tab = _CONFIG_TAB

    def _success_url(self, server: Server) -> str:
        return reverse("plugins:netbox_kea:server_option_def", kwargs={"pk": server.pk, "family": self.dhcp_version})

    def get(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Render the add Option Definition form."""
        server = get_object_or_404(Server.objects.restrict(request.user, "change"), pk=pk)
        form = forms.OptionDefForm(initial={"space": f"dhcp{self.dhcp_version}"})
        return render(
            request,
            "netbox_kea/server_option_def_add.html",
            {
                "object": server,
                "server": server,
                "form": form,
                "dhcp_version": self.dhcp_version,
                "cancel_url": self._success_url(server),
                "tab": self.tab,
            },
        )

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Validate and create the option definition."""
        server = get_object_or_404(Server.objects.restrict(request.user, "change"), pk=pk)
        form = forms.OptionDefForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                "netbox_kea/server_option_def_add.html",
                {
                    "object": server,
                    "server": server,
                    "form": form,
                    "dhcp_version": self.dhcp_version,
                    "cancel_url": self._success_url(server),
                    "tab": self.tab,
                },
            )
        option_def = {
            "name": form.cleaned_data["name"],
            "code": form.cleaned_data["code"],
            "type": form.cleaned_data["type"],
            "space": form.cleaned_data["space"],
        }
        if form.cleaned_data.get("array"):
            option_def["array"] = True
        _run_change(
            request,
            f"Option definition '{option_def['name']}' (code {option_def['code']}) added.",
            lambda: config_write.add_option_definition(server, self.dhcp_version, option_def),
        )
        return redirect(self._success_url(server))


class ServerOptionDefDeleteView(
    FamilyRouteMixin, _KeaChangeMixin, ServerFamilyMixin, ConditionalLoginRequiredMixin, View
):
    """Delete a custom option definition from a Kea server.

    The option code and space are passed as URL kwargs.
    """

    workspace_section = "configuration"

    tab = _CONFIG_TAB

    def _success_url(self, server: Server) -> str:
        return reverse("plugins:netbox_kea:server_option_def", kwargs={"pk": server.pk, "family": self.dhcp_version})

    def get(self, request: HttpRequest, pk: int, code: int, space: str) -> HttpResponse:
        """Render the delete-confirmation page."""
        server = get_object_or_404(Server.objects.restrict(request.user, "change"), pk=pk)
        return render(
            request,
            "netbox_kea/server_option_def_delete.html",
            {
                "object": server,
                "server": server,
                "code": code,
                "space": space,
                "dhcp_version": self.dhcp_version,
                "cancel_url": self._success_url(server),
                "tab": self.tab,
            },
        )

    def post(self, request: HttpRequest, pk: int, code: int, space: str) -> HttpResponse:
        """Delete the option definition."""
        server = get_object_or_404(Server.objects.restrict(request.user, "change"), pk=pk)
        _run_change(
            request,
            f"Option definition code={code} space={space} deleted.",
            lambda: config_write.delete_option_definition(server, self.dhcp_version, code, space),
        )
        return redirect(self._success_url(server))
