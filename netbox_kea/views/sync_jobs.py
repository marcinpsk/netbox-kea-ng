# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Views for Kea IPAM sync job management."""

from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import View
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from ..integrations import dhcp_plugin
from ..jobs import KeaIpamSyncJob
from ..models import Server, SyncConfig
from ..sync_plan import LEASE, POOL, RESERVATION, SUBNET, SYNC_SOURCES, global_source_enabled, source_sync_enabled
from ..sync_run_result import jobs_of, latest, read
from .dhcp_plugin_sync import sync_nav_context
from .settings_page import section_url, visible_sections
from .workspace import ServerFamilyMixin, server_family_url

logger = logging.getLogger(__name__)

_JOB_HISTORY_COUNT = 5  # rows shown in the per-server tab mini-table
_SOURCE_LABELS = {
    LEASE: "Leases",
    RESERVATION: "Reservations",
    SUBNET: "Prefixes",
    POOL: "IP Ranges",
}


class SyncJobsView(LoginRequiredMixin, View):
    """Plugin-level Sync Jobs page: the cross-server job table, with a link to the Settings page."""

    template_name = "netbox_kea/sync_jobs.html"

    def get(self, request):
        """Render the sync jobs overview page with the server table."""
        servers = list(Server.objects.restrict(request.user, "view").order_by("name"))
        allowed_server_pks = set(Server.objects.restrict(request.user, "change").values_list("pk", flat=True))
        return render(
            request,
            self.template_name,
            {
                "rows": [(server, *latest(server.pk)) for server in servers],
                "allowed_server_pks": allowed_server_pks,
                "can_view_settings": bool(visible_sections(request.user)),
            },
        )


@register_model_view(Server, "sync_status")
class ServerSyncStatusView(ServerFamilyMixin, generic.ObjectView):
    """Per-server Sync Status tab."""

    workspace_section = "sync"

    queryset = Server.objects.all()
    tab = ViewTab(label="Sync", weight=1005)
    template_name = "netbox_kea/server_sync_status.html"

    def get_extra_context(self, request, instance):
        """Return recent sync jobs and status context for the template."""
        recent_jobs = list(jobs_of(instance.pk)[:_JOB_HISTORY_COUNT])
        latest_job = recent_jobs[0] if recent_jobs else None

        jobs_list_url = reverse("core:job_list") + f"?object_type=netbox_kea.server&object_id={instance.pk}"
        sync_cfg = SyncConfig.get()
        # The badges omit the Server switch: the Controls card shows it on its own.
        type_badges = [
            {
                "label": _SOURCE_LABELS[source],
                "global_on": sync_cfg.sync_enabled and global_source_enabled(source, sync_cfg),
                "server_on": sync_cfg.sync_enabled and source_sync_enabled(instance, source, sync_cfg),
            }
            for source in SYNC_SOURCES
        ]
        return {
            "recent_jobs": recent_jobs,
            "latest_job": latest_job,
            "latest_result": read(latest_job).get(instance.pk) if latest_job is not None else None,
            "jobs_list_url": jobs_list_url,
            "can_change_server": Server.objects.restrict(request.user, "change").filter(pk=instance.pk).exists(),
            "server_edit_url": server_family_url(request, instance, self, "server_edit"),
            "sync_toggle_url": server_family_url(request, instance, self, "server_sync_toggle"),
            "sync_now_url": server_family_url(request, instance, self, "server_sync_now"),
            "sync_cfg": sync_cfg,
            "type_badges": type_badges,
            "sync_settings_url": section_url(request.user, SyncConfig),
            **sync_nav_context(request, instance, self, "ipam", integration_runs=dhcp_plugin.runs_for(instance)),
        }


class ServerSyncNowView(LoginRequiredMixin, View):
    """POST-only: enqueue KeaIpamSyncJob for one server immediately."""

    def post(self, request, pk):
        """Enqueue a one-off sync job for the given server."""
        if not request.user.has_perm("netbox_kea.change_server"):
            return HttpResponseForbidden()
        server = get_object_or_404(Server.objects.restrict(request.user, "change"), pk=pk)
        try:
            KeaIpamSyncJob.enqueue(instance=server, user=request.user, server_pk=server.pk)
            messages.success(request, f"Sync job enqueued for {server.name}.")
        except Exception:
            logger.exception("Failed to enqueue sync job for server %s", server.name)
            messages.error(request, "An internal error occurred when enqueuing the sync job.")
        return HttpResponseRedirect(server_family_url(request, server, self, "server_sync_status"))


class ServerSyncToggleView(LoginRequiredMixin, View):
    """POST-only: toggle Server.sync_enabled for one server."""

    def post(self, request, pk):
        """Toggle the sync_enabled flag for the given server."""
        if not request.user.has_perm("netbox_kea.change_server"):
            return HttpResponseForbidden()
        server = get_object_or_404(Server.objects.restrict(request.user, "change"), pk=pk)
        server.snapshot()
        server.sync_enabled = not server.sync_enabled
        try:
            server.save(update_fields=["sync_enabled"])
        except Exception:
            logger.exception("Failed to toggle sync for server %s", server.name)
            messages.error(request, "An internal error occurred when toggling sync.")
            return HttpResponseRedirect(server_family_url(request, server, self, "server_sync_status"))
        state = "enabled" if server.sync_enabled else "disabled"
        messages.success(request, f"IPAM sync {state} for {server.name}.")
        return HttpResponseRedirect(server_family_url(request, server, self, "server_sync_status"))


def _replace_auto_jobs_view(model, replacement_view) -> None:
    """Replace NetBox's auto-registered ``jobs`` view in the registry with our own.

    NetBox's ``JobsMixin.__init_subclass__`` registers a default ``ObjectJobsView``
    for every job-aware model. That view filters by ``object_type+object_id`` and
    therefore cannot show periodic (system) jobs whose ``object_id`` is NULL.
    We swap the entry so the per-server "Jobs" tab points at our subclass instead.
    """
    from netbox.registry import registry

    app_label = model._meta.app_label
    model_name = model._meta.model_name
    # Ensure the nested registry structure exists so the fallback append below
    # actually mutates the registry (chained .get() with defaults would create
    # a detached list and silently drop the registration).
    app_views = registry["views"].setdefault(app_label, {})
    views = app_views.setdefault(model_name, [])
    for entry in views:
        if entry.get("name") == "jobs":
            entry["view"] = replacement_view
            entry["kwargs"] = {"model": model}
            return
    views.append(
        {
            "name": "jobs",
            "view": replacement_view,
            "path": "jobs",
            "detail": True,
            "kwargs": {"model": model},
        }
    )


class ServerJobsView(View):
    """Per-server Jobs tab, including periodic (unbound) Kea sync jobs.

    The default :class:`netbox.views.generic.ObjectJobsView` only shows jobs
    whose ``object_id`` matches the server. Periodic ``KeaIpamSyncJob`` runs
    are stored unbound (``object_id=NULL``) and name their Servers only in
    their Sync Run Results, so they are invisible there. This subclass lists
    ``sync_run_result.jobs_of()``, matching core's ``ObjectJobsView`` shape
    so the existing ``core/object_jobs.html`` template works unchanged.
    """

    tab = ViewTab(
        label="Jobs",
        badge=lambda obj: jobs_of(obj.pk).count(),
        permission="core.view_job",
        weight=11000,
    )

    def get(self, request, model, **kwargs):
        """Render the Jobs tab using core's object_jobs template + JobTable."""
        if not request.user.has_perm("core.view_job"):
            raise PermissionDenied
        from core.tables import JobTable

        obj = get_object_or_404(model.objects.restrict(request.user, "view"), **kwargs)
        jobs = jobs_of(obj.pk)
        table = JobTable(data=jobs, orderable=False)
        table.configure(request)

        base_template = f"{model._meta.app_label}/{model._meta.model_name}.html"
        return render(
            request,
            "core/object_jobs.html",
            {
                "object": obj,
                "table": table,
                "base_template": base_template,
                "tab": self.tab,
            },
        )


_replace_auto_jobs_view(Server, ServerJobsView)
