# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2023-2024 Devon Mar <devon-mar@users.noreply.github.com>
# SPDX-License-Identifier: Apache-2.0
import logging

from django.conf import settings
from netbox.plugins import PluginConfig

from . import branching

__version__ = "3.10.3"

logger = logging.getLogger(__name__)

#: The PLUGINS_CONFIG keys that the Settings page now holds. migrate copies each one once (ADR 0010).
REMOVED_SETTINGS = (
    "kea_timeout",
    "lease_query_max_unpaged_leases",
    "stale_ip_cleanup",
    "sync_interval_minutes",
    "sync_enabled",
    "sync_leases_enabled",
    "sync_reservations_enabled",
    "sync_prefixes_enabled",
    "sync_ip_ranges_enabled",
    "sync_max_leases_per_server",
)


def warn_removed_settings() -> None:
    """Log one warning for each removed key that PLUGINS_CONFIG still sets; the value has no effect."""
    configured = settings.PLUGINS_CONFIG.get("netbox_kea", {})
    for key in REMOVED_SETTINGS:
        if key in configured:
            logger.warning(
                "PLUGINS_CONFIG['netbox_kea']['%s'] is ignored. migrate copied it once to the Settings page"
                " (DHCP Kea > Settings): change it there, and remove it from the configuration.",
                key,
            )


class NetBoxKeaConfig(PluginConfig):
    """NetBox plugin configuration for the Kea DHCP integration."""

    name = "netbox_kea"
    verbose_name = "NetBox Kea NG"
    description = "Kea integration for NetBox"
    version = __version__
    author = "Marcin Zieba"
    author_email = "marcinpsk@gmail.com"
    base_url = "kea"
    middleware = ("netbox_kea.branching.BranchRefusalMiddleware",)

    def ready(self) -> None:
        """Register optional integrations after Django is fully initialised."""
        super().ready()
        warn_removed_settings()
        branching.register()
        from .dhcp_mapping_lifecycle import register as register_mapping_lifecycle
        from .integrations.dhcp_plugin import register_link_cleanup

        register_link_cleanup()
        register_mapping_lifecycle()


config = NetBoxKeaConfig
