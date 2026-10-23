# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Settings page: one tab for each runtime settings singleton (ADR 0010)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from django import forms as django_forms
from django.contrib import messages
from django.contrib.auth import get_permission_codename
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.forms import modelform_factory
from django.http import Http404, HttpResponse
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
    """One singleton in its tab of the Settings page. Its model's permissions decide who sees and who changes it."""

    slug: str
    model: type[SettingsSingleton]
    #: The text of the section's tab.
    tab_text: str
    #: The include that renders the form. The default renders each field in model order.
    template_name: str = "netbox_kea/inc/settings_fields.html"
    #: False hides the section, its tab and its save, for a setting whose integration is not installed.
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


def visible_sections(user) -> list[SettingsSection]:
    """Return the available sections that *user* may view."""
    return [section for section in SECTIONS if section.available() and user.has_perm(section.view_permission)]


class SettingsView(LoginRequiredMixin, View):
    """Open the first tab that the user may view."""

    def get(self, request) -> HttpResponse:
        """Redirect to the first visible tab; a user who can view no section gets 403."""
        sections = visible_sections(request.user)
        if not sections:
            raise PermissionDenied
        return redirect("plugins:netbox_kea:settings_section", section=sections[0].slug)


class SettingsSectionView(LoginRequiredMixin, View):
    """Show one section in its tab, and save that section on POST."""

    template_name = "netbox_kea/settings.html"

    def get(self, request, section: str) -> HttpResponse:
        """Render the tab of *section*."""
        tabs, shown = self._tab(request, section)
        return self._render(request, tabs, shown, shown.form_class(instance=shown.model.get(), prefix=shown.slug))

    def post(self, request, section: str) -> HttpResponse:
        """Save the section. It needs the view and the change permission of the section's model."""
        tabs, shown = self._tab(request, section)
        if not request.user.has_perm(shown.change_permission):
            raise PermissionDenied
        instance = shown.model.get()
        instance.snapshot()
        form = shown.form_class(request.POST, instance=instance, prefix=shown.slug)
        if not form.is_valid():
            return self._render(request, tabs, shown, form)
        instance.save()
        messages.success(request, f"{shown.title} saved.")
        return redirect("plugins:netbox_kea:settings_section", section=shown.slug)

    @staticmethod
    def _tab(request, slug: str) -> tuple[list[SettingsSection], SettingsSection]:
        """Return the visible sections and the one of *slug*: 403 without a visible section, else 404 for *slug*."""
        tabs = visible_sections(request.user)
        if not tabs:
            raise PermissionDenied
        shown = next((section for section in tabs if section.slug == slug), None)
        if shown is None:
            raise Http404("Unknown settings section.")
        return tabs, shown

    def _render(
        self, request, tabs: list[SettingsSection], shown: SettingsSection, form: django_forms.ModelForm
    ) -> HttpResponse:
        can_change = request.user.has_perm(shown.change_permission)
        if not can_change:
            for field in form.fields.values():
                field.disabled = True
        context = {"tabs": tabs, "section": shown, "form": form, "can_change": can_change}
        return render(request, self.template_name, context)
