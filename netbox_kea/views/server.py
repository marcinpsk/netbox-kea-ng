# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import logging
from dataclasses import dataclass
from typing import Any

import requests
from django.http.request import HttpRequest
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.urls import reverse
from netbox.views import generic
from utilities.exceptions import PermissionsViolation
from utilities.views import register_model_view

from .. import forms, server_configuration, tables
from ..constants import Family
from ..dhcp_options import DHCPOption, option_name
from ..filtersets import ServerFilterSet
from ..kea import DaemonStatus, DaemonVersion, KeaException
from ..models import Server
from ..server_connection import connection_values, validate_connection_change
from ..utilities import (
    format_duration,
)
from ._base import LazyClient, _safe_return_url, daemon_status, daemon_version
from .notices import Notice, inline_notices, notice
from .workspace import ServerFamilyMixin, server_context, with_return_url

logger = logging.getLogger(__name__)


def _status_rows(status: DaemonStatus, version: DaemonVersion) -> dict[str, Any]:
    """Return the rows that the Overview shows for the status and version facts of one daemon."""
    rows: dict[str, Any] = {
        "PID": status.pid,
        "Uptime": format_duration(status.uptime) or "",
        "Time since reload": format_duration(status.reload) or "",
        "Version": version.extended or "unknown",
    }
    if (ha := status.high_availability) is not None:
        rows.update(
            {
                "HA mode": ha.mode,
                "HA local role": ha.local_role,
                "HA local state": ha.local_state,
                "HA remote connection interrupted": str(ha.remote_connection_interrupted),
                "HA remote age (seconds)": ha.remote_age,
                "HA remote role": ha.remote_role,
                "HA remote last state": ha.remote_last_state,
                "HA remote in touch": ha.remote_in_touch,
                "HA remote unacked clients": ha.remote_unacked_clients,
                "HA remote unacked clients left": ha.remote_unacked_clients_left,
                "HA remote connecting clients": ha.remote_connecting_clients,
            }
        )
    return rows


@dataclass(frozen=True)
class GlobalOptionRow:
    """One server-global DHCP Option entry of the status page, with the name that the page shows for it."""

    name: str | None
    option: DHCPOption


def _get_global_options(server: Server) -> tuple[dict[str, list[GlobalOptionRow]], list[Notice | None]]:
    """Return one row per server-global DHCP Option entry for each enabled DHCP version that has entries.

    A failed read is logged and skipped, so the status partial always renders. It shows the Snapshot diagnostics
    through the inline notice channel.
    """
    families: dict[str, Family] = {}
    if server.dhcp4:
        families["DHCPv4"] = 4
    if server.dhcp6:
        families["DHCPv6"] = 6

    result: dict[str, list[GlobalOptionRow]] = {}
    notices: list[Notice | None] = []
    for label, version in families.items():
        snapshot = server_configuration.display(server, version)
        notices.append(found := notice(snapshot))
        reasons = "; ".join(found.lines) if found is not None else ""
        if snapshot.unavailable:
            logger.warning("Global DHCP Options are unavailable for %s: %s", label, reasons)
            continue
        if not snapshot.global_options_complete:
            logger.warning("Global DHCP Options are incomplete for %s: %s", label, reasons)
        if snapshot.global_options:
            result[label] = [
                GlobalOptionRow(option_name(option, version), option) for option in snapshot.global_options
            ]
    return result, notices


@register_model_view(Server)
class ServerView(ServerFamilyMixin, generic.ObjectView):
    """Detail view for a single Kea Server."""

    queryset = Server.objects.all()


@register_model_view(Server, "edit")
class ServerEditView(generic.ObjectEditView):
    """Create/edit view for a Kea Server."""

    queryset = Server.objects.all()
    template_name = "netbox_kea/server_edit.html"
    form = forms.ServerForm


@register_model_view(Server, "delete")
class ServerDeleteView(generic.ObjectDeleteView):
    """Delete confirmation view for a Kea Server."""

    template_name = "netbox_kea/server_delete.html"

    queryset = Server.objects.all()

    def get(self, request, *args, **kwargs):
        """Keep the scope inside the native modal's selected deletion form."""
        response = super().get(request, *args, **kwargs)
        if request.headers.get("HX-Request") != "true" or response.status_code != 200:
            return response
        content = response.content.decode(response.charset)
        form_start = content.find("<form ")
        if form_start < 0:
            return response
        obj = self.get_object(**kwargs)
        context = server_context(request, obj)
        context["workspace_shell_id"] = "kea-modal-workspace-shell"
        shell = render_to_string("netbox_kea/inc/workspace_shell.html", context, request=request)
        form_end = content.index(">", form_start) + 1
        content = content[:form_end] + shell + content[form_end:]
        url = reverse("plugins:netbox_kea:server_delete", args=[obj.pk])
        family = context["workspace_family"]
        response.content = content.replace(f'action="{url}"', f'action="{url}?family={family}"')
        return response


class ServerListView(generic.ObjectListView):
    """Paginated list view for all Kea Servers."""

    queryset = Server.objects.all()
    table = tables.ServerTable
    filterset = ServerFilterSet
    filterset_form = forms.ServerFilterForm


class ServerBulkDeleteView(generic.BulkDeleteView):
    """Bulk-delete view for Kea Server objects."""

    queryset = Server.objects.all()
    table = tables.ServerTable


class ServerBulkEditView(generic.BulkEditView):
    """Bulk-edit view for Kea Server objects."""

    queryset = Server.objects.all()
    filterset = ServerFilterSet
    table = tables.ServerTable
    form = forms.ServerBulkEditForm

    def _update_objects(self, form, request):
        """Check native updated candidates inside the bulk transaction and permission scope."""
        before = {
            server.pk: connection_values(server) for server in self.queryset.filter(pk__in=form.cleaned_data["pk"])
        }
        updated = super()._update_objects(form, request)
        if self.queryset.filter(pk__in=[server.pk for server in updated]).count() != len(updated):
            raise PermissionsViolation
        for server in updated:
            validate_connection_change(server, before[server.pk])
        return updated


class ServerBulkImportView(generic.BulkImportView):
    """Bulk-import CSV/YAML data to create Server objects."""

    queryset = Server.objects.all()
    model_form = forms.ServerImportForm
    table = tables.ServerTable


@register_model_view(Server, "status")
class ServerStatusRedirectView(generic.ObjectView):
    """Send the former Status entry point to the Server Overview."""

    queryset = Server.objects.all()

    def get(self, request: HttpRequest, **kwargs):
        """Preserve native view permission checks before redirecting."""
        return redirect(self.get_object(**kwargs).get_absolute_url())


@register_model_view(Server, "status_data")
class ServerStatusView(generic.ObjectView):
    """Server status tab: shows daemon uptime, versions and HA state."""

    queryset = Server.objects.all()
    template_name = "netbox_kea/server_status.html"

    def _get_statuses(self, server: Server) -> dict[str, dict[str, Any]]:
        """Return the status rows of the Control Agent (when present) and of each enabled DHCP service.

        A daemon that cannot be read is logged and left out, so the page still renders.
        """
        targets: list[tuple[str, Family | None]] = []
        if server.has_control_agent:
            targets.append(("Control Agent", None))
        if server.dhcp6:
            targets.append(("DHCPv6", 6))
        if server.dhcp4:
            targets.append(("DHCPv4", 4))
        result: dict[str, dict[str, Any]] = {}
        for name, target in targets:
            try:
                with LazyClient(server, target) as client:
                    result[name] = _status_rows(daemon_status(client), daemon_version(client))
            except (KeaException, requests.RequestException, ValueError, RuntimeError):  # noqa: PERF203
                logger.exception("Failed to fetch the %s status of server %s", name, server.pk)
        return result

    def get_extra_context(self, request: HttpRequest, instance: Server) -> dict[str, Any]:
        """Fetch the status, through the display cache, and the global options, and expose them to the template."""
        statuses = self._get_statuses(instance)

        service_urls: dict[str, dict[str, str]] = {}
        if instance.dhcp4:
            service_urls["DHCPv4"] = {
                "enable_url": reverse("plugins:netbox_kea:server_dhcp4_enable", args=[instance.pk]),
                "disable_url": reverse("plugins:netbox_kea:server_dhcp4_disable", args=[instance.pk]),
                "options_url": reverse("plugins:netbox_kea:server_dhcp4_options_edit", args=[instance.pk]),
            }
        if instance.dhcp6:
            service_urls["DHCPv6"] = {
                "enable_url": reverse("plugins:netbox_kea:server_dhcp6_enable", args=[instance.pk]),
                "disable_url": reverse("plugins:netbox_kea:server_dhcp6_disable", args=[instance.pk]),
                "options_url": reverse("plugins:netbox_kea:server_dhcp6_options_edit", args=[instance.pk]),
            }

        # Build the services list from the configured service URLs (config-driven),
        # not from live status data. This ensures enable/disable buttons always render
        # even when the status fetch fails.
        return_url = _safe_return_url(request, "")
        services = [
            {
                "name": name,
                "status_data": statuses.get(name, {}),
                **{key: with_return_url(url, return_url) for key, url in urls.items()},
            }
            for name, urls in service_urls.items()
        ]
        # Prepend Control Agent row if configured (no enable/disable URLs for CA).
        if instance.has_control_agent:
            services.insert(0, {"name": "Control Agent", "status_data": statuses.get("Control Agent", {})})

        global_options, notices = _get_global_options(instance)
        can_change = Server.objects.restrict(request.user, "change").filter(pk=instance.pk).exists()
        return {
            "services": services,
            "global_options": global_options,
            "inline_notices": inline_notices(*notices),
            "can_change_server": can_change,
        }
