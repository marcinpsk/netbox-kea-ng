# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
# SPDX-FileCopyrightText: 2023 Lasse Bang Mikkelsen <lbm@lbm.dk>
# SPDX-License-Identifier: Apache-2.0
from django.utils.text import format_lazy
from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

from .views.settings_page import SECTIONS, SettingsSection

_items = (
    PluginMenuItem(
        link="plugins:netbox_kea:combined",
        link_text="Kea Workspace",
        permissions=["netbox_kea.view_server"],
    ),
    PluginMenuItem(
        link="plugins:netbox_kea:server_list",
        link_text="Servers",
        permissions=["netbox_kea.view_server"],
        buttons=(
            PluginMenuButton(
                link="plugins:netbox_kea:server_add",
                title="Add",
                icon_class="mdi mdi-plus-thick",
                permissions=["netbox_kea.add_server"],
            ),
        ),
    ),
    PluginMenuItem(
        link="plugins:netbox_kea:sync_jobs",
        link_text="Sync Jobs",
        permissions=["netbox_kea.view_server"],
    ),
)


def _settings_item(section: SettingsSection) -> PluginMenuItem:
    """Link to the section on the Settings page, for a user who can view the section."""
    item = PluginMenuItem(
        link="plugins:netbox_kea:settings", link_text=section.menu_text, permissions=[section.view_permission]
    )
    item.url = format_lazy("{}#{}", item.url, section.slug)
    return item


def _settings_items() -> tuple[PluginMenuItem, ...]:
    """Return one item for each available section. NetBox builds the menu once, after the app registry is ready."""
    return tuple(_settings_item(section) for section in SECTIONS if section.available())


# Top-level menu: surfaces a dedicated "DHCP Kea" section in the NetBox sidebar
# instead of nesting under the generic "Plugins" group. NetBox renders a
# ``menu`` (PluginMenu) in preference to ``menu_items`` when both are present.
menu = PluginMenu(
    label="DHCP Kea",
    icon_class="mdi mdi-server-network",
    groups=(("Management", _items), ("Settings", _settings_items())),
)
