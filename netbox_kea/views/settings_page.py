# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Settings page: one section for each runtime settings singleton (ADR 0010)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from django import forms as django_forms
from django.contrib import messages
from django.contrib.auth import get_permission_codename
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.forms import modelform_factory
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.views import View

from ..integrations import dhcp_plugin
from ..models import DhcpIntegrationConfig, DisplayCacheConfig, KeaClientConfig, SettingsSingleton, SyncConfig


def _always() -> bool:
    return True


def _dhcp_plugin_installed() -> bool:
    # Look up is_available on each call, so that a test can patch it.
    return dhcp_plugin.is_available()


@dataclass(frozen=True)
class SettingsSection:
    """One singleton on the Settings page. Its model's permissions decide who sees and who changes it."""

    slug: str
    model: type[SettingsSingleton]
    #: The text of the section's item in the Settings menu group.
    menu_text: str
    #: The include that renders the form. The default renders each field in model order.
    template_name: str = "netbox_kea/inc/settings_fields.html"
    #: False hides the section, its menu item and its save, for a setting whose integration is not installed.
    available: Callable[[], bool] = _always
    #: One sentence under the heading, for a fact about the whole section rather than one field.
    description: str = ""

    def _permission(self, action: str) -> str:
        options = self.model._meta
        return f"{options.app_label}.{get_permission_codename(action, options)}"

    @property
    def view_permission(self) -> str:
        """Return the permission that shows the section."""
        return self._permission("view")

    @property
    def change_permission(self) -> str:
        """Return the permission that saves the section."""
        return self._permission("change")

    @property
    def form_class(self) -> type[django_forms.ModelForm]:
        """Return a form of every editable field of the model. The model fields give the validators and the help."""
        return modelform_factory(self.model, fields="__all__")

    @property
    def title(self) -> str:
        """Return the heading of the section."""
        return str(self.model._meta.verbose_name)


SECTIONS = (
    SettingsSection("sync", SyncConfig, "Sync", template_name="netbox_kea/inc/settings_sync.html"),
    SettingsSection("kea-client", KeaClientConfig, "Kea Client"),
    SettingsSection(
        "display-cache",
        DisplayCacheConfig,
        "Display Cache",
        description="A save of this section makes every cached entry unused, also when no value changes.",
    ),
    SettingsSection("dhcp-integration", DhcpIntegrationConfig, "DHCP Plugin", available=_dhcp_plugin_installed),
)
_BY_SLUG = {section.slug: section for section in SECTIONS}


def visible_sections(user) -> list[SettingsSection]:
    """Return the available sections that *user* may view."""
    return [section for section in SECTIONS if section.available() and user.has_perm(section.view_permission)]


@dataclass(frozen=True)
class _ShownSection:
    section: SettingsSection
    form: django_forms.ModelForm
    can_change: bool


class SettingsView(LoginRequiredMixin, View):
    """Show each section that the user may view, and save one section per POST."""

    template_name = "netbox_kea/settings.html"

    def get(self, request) -> HttpResponse:
        """Render every visible section; a user who can view no section gets 403."""
        return self._render(request)

    def post(self, request) -> HttpResponse:
        """Save the posted section. It needs the view and the change permission of the section's model."""
        section = _BY_SLUG.get(request.POST.get("section", ""))
        if section is None or not section.available():
            return HttpResponseBadRequest("Unknown settings section.")
        if not request.user.has_perms((section.view_permission, section.change_permission)):
            raise PermissionDenied
        instance = section.model.get()
        instance.snapshot()
        form = section.form_class(request.POST, instance=instance, prefix=section.slug)
        if not form.is_valid():
            return self._render(request, form)
        instance.save()
        messages.success(request, f"{section.title} saved.")
        return redirect("plugins:netbox_kea:settings")

    def _render(self, request, posted: django_forms.ModelForm | None = None) -> HttpResponse:
        shown = []
        for section in visible_sections(request.user):
            can_change = request.user.has_perm(section.change_permission)
            if posted is not None and posted.prefix == section.slug:
                form = posted
            else:
                form = section.form_class(instance=section.model.get(), prefix=section.slug)
            if not can_change:
                for field in form.fields.values():
                    field.disabled = True
            shown.append(_ShownSection(section, form, can_change))
        if not shown:
            raise PermissionDenied
        return render(request, self.template_name, {"sections": shown})
