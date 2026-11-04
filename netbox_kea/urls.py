# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
# SPDX-License-Identifier: Apache-2.0
from django.urls import include, path, register_converter
from utilities.urls import get_model_urls

from .constants import Family, validate_family
from .views import (
    combined,
    dhcp_control,
    dhcp_plugin_sync,
    leases,
    options,
    reservation_mutations,
    reservations,
    server,
    server_switch,
    settings_page,
    shared_networks,
    subnets,
    sync_jobs,
    sync_views,
)


class FamilyConverter:
    """Match the address family of a route, 4 or 6, as an int."""

    regex = "[46]"

    def to_python(self, value: str) -> Family:
        """Return the family of the path text."""
        return validate_family(int(value))

    def to_url(self, value: int) -> str:
        """Return the path text of the family, or refuse a value that is not a family."""
        return str(validate_family(value))


register_converter(FamilyConverter, "family")

urlpatterns = (
    path("servers/<int:pk>/switch/", server_switch.ServerSwitchView.as_view(), name="server_switch"),
    path("combined/", combined.CombinedDashboardView.as_view(), {"family": 4}, name="combined"),
    path(
        "combined/overview<family:family>/",
        combined.CombinedDashboardView.as_view(),
        name="combined_overview",
    ),
    path(
        "combined/configuration<family:family>/",
        combined.CombinedConfigurationView.as_view(),
        name="combined_configuration",
    ),
    path("combined/sync<family:family>/", combined.CombinedSyncView.as_view(), name="combined_sync"),
    path("combined/leases<family:family>/", combined.CombinedLeasesView.as_view(), name="combined_leases"),
    path("combined/subnets<family:family>/", combined.CombinedSubnetsView.as_view(), name="combined_subnets"),
    path(
        "combined/shared-networks<family:family>/",
        combined.CombinedSharedNetworksView.as_view(),
        name="combined_shared_networks",
    ),
    path(
        "combined/reservations<family:family>/",
        combined.CombinedReservationsView.as_view(),
        name="combined_reservations",
    ),
    path(
        "combined/server-status-badge/<int:pk>/",
        options.CombinedServerStatusBadgeView.as_view(),
        name="combined_server_status_badge",
    ),
    path("settings/", settings_page.SettingsView.as_view(), name="settings"),
    path("settings/<slug:section>/", settings_page.SettingsSectionView.as_view(), name="settings_section"),
    path("sync-jobs/", sync_jobs.SyncJobsView.as_view(), name="sync_jobs"),
    path("servers/<int:pk>/sync-now/", sync_jobs.ServerSyncNowView.as_view(), name="server_sync_now"),
    path("servers/<int:pk>/sync-toggle/", sync_jobs.ServerSyncToggleView.as_view(), name="server_sync_toggle"),
    path(
        "servers/<int:pk>/dhcp-plugin/sync/",
        dhcp_plugin_sync.ServerDhcpPluginSyncNowView.as_view(),
        name="server_dhcp_plugin_sync",
    ),
    path("servers/", server.ServerListView.as_view(), name="server_list"),
    path("servers/add/", server.ServerEditView.as_view(), name="server_add"),
    path(
        "servers/delete/",
        server.ServerBulkDeleteView.as_view(),
        name="server_bulk_delete",
    ),
    path(
        "servers/edit/",
        server.ServerBulkEditView.as_view(),
        name="server_bulk_edit",
    ),
    path(
        "servers/import/",
        server.ServerBulkImportView.as_view(),
        name="server_bulk_import",
    ),
    path(
        "servers/<int:pk>/reservation/check-ip/",
        sync_views.ReservationCheckNetboxIPView.as_view(),
        name="reservation_check_ip",
    ),
    path("servers/<int:pk>/subnets<family:family>/", subnets.ServerSubnetsView.as_view(), name="server_subnets"),
    path(
        "servers/<int:pk>/subnets<family:family>/add/",
        subnets.ServerSubnetAddView.as_view(),
        name="server_subnet_add",
    ),
    path(
        "servers/<int:pk>/subnets<family:family>/<int:subnet_id>/edit/",
        subnets.ServerSubnetEditView.as_view(),
        name="server_subnet_edit",
    ),
    path(
        "servers/<int:pk>/subnets<family:family>/<int:subnet_id>/delete/",
        subnets.ServerSubnetDeleteView.as_view(),
        name="server_subnet_delete",
    ),
    path(
        "servers/<int:pk>/subnets<family:family>/<int:subnet_id>/wipe/",
        subnets.ServerSubnetWipeView.as_view(),
        name="server_subnet_wipe_leases",
    ),
    path(
        "servers/<int:pk>/subnets<family:family>/<int:subnet_id>/options/",
        options.ServerSubnetOptionsEditView.as_view(),
        name="server_subnet_options_edit",
    ),
    path(
        "servers/<int:pk>/subnets<family:family>/<int:subnet_id>/pools/add/",
        subnets.ServerSubnetPoolAddView.as_view(),
        name="server_subnet_pool_add",
    ),
    path(
        "servers/<int:pk>/subnets<family:family>/<int:subnet_id>/pools/<path:pool>/delete/",
        subnets.ServerSubnetPoolDeleteView.as_view(),
        name="server_subnet_pool_delete",
    ),
    path(
        "servers/<int:pk>/shared_networks<family:family>/",
        shared_networks.ServerSharedNetworksView.as_view(),
        name="server_shared_networks",
    ),
    path(
        "servers/<int:pk>/shared-networks<family:family>/add/",
        shared_networks.ServerSharedNetworkAddView.as_view(),
        name="server_shared_network_add",
    ),
    path(
        "servers/<int:pk>/shared-networks<family:family>/<str:network_name>/edit/",
        shared_networks.ServerSharedNetworkEditView.as_view(),
        name="server_shared_network_edit",
    ),
    path(
        "servers/<int:pk>/shared-networks<family:family>/<str:network_name>/delete/",
        shared_networks.ServerSharedNetworkDeleteView.as_view(),
        name="server_shared_network_delete",
    ),
    path(
        "servers/<int:pk>/leases<family:family>/",
        leases.ServerLeasesView.as_view(),
        name="server_leases",
    ),
    path(
        "servers/<int:pk>/leases<family:family>/add/",
        leases.ServerLeaseAddView.as_view(),
        name="server_lease_add",
    ),
    path(
        "servers/<int:pk>/leases<family:family>/delete/",
        leases.ServerLeasesDeleteView.as_view(),
        name="server_leases_delete",
    ),
    path(
        "servers/<int:pk>/leases<family:family>/sync/",
        sync_views.ServerLeaseSyncView.as_view(),
        name="server_lease_sync",
    ),
    path(
        "servers/<int:pk>/leases<family:family>/import/",
        sync_views.ServerLeaseBulkImportView.as_view(),
        name="server_lease_bulk_import",
    ),
    path(
        "servers/<int:pk>/leases<family:family>/<path:ip_address>/edit/",
        leases.ServerLeaseEditView.as_view(),
        name="server_lease_edit",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/",
        reservations.ServerReservationsView.as_view(),
        name="server_reservations",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/add/",
        reservation_mutations.ServerReservationAddView.as_view(),
        name="server_reservation_add",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/published-name/",
        reservation_mutations.ServerReservationPublishedNameView.as_view(),
        name="server_reservation_published_name",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/bulk-sync/",
        sync_views.ServerReservationBulkSyncView.as_view(),
        name="server_reservation_bulk_sync",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/import/",
        sync_views.ServerReservationBulkImportView.as_view(),
        name="server_reservation_bulk_import",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/<int:subnet_id>/edit/",
        reservation_mutations.ServerReservationEditView.as_view(),
        name="server_reservation_edit",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/<int:subnet_id>/delete/",
        reservation_mutations.ServerReservationDeleteView.as_view(),
        name="server_reservation_delete",
    ),
    path(
        "servers/<int:pk>/reservations<family:family>/<int:subnet_id>/sync/",
        sync_views.ServerReservationSyncView.as_view(),
        name="server_reservation_sync",
    ),
    path(
        "servers/<int:pk>/dhcp<family:family>/enable/",
        dhcp_control.ServerDHCPEnableView.as_view(),
        name="server_dhcp_enable",
    ),
    path(
        "servers/<int:pk>/dhcp<family:family>/disable/",
        dhcp_control.ServerDHCPDisableView.as_view(),
        name="server_dhcp_disable",
    ),
    path(
        "servers/<int:pk>/dhcp<family:family>/options/",
        options.ServerDHCPOptionsEditView.as_view(),
        name="server_dhcp_options_edit",
    ),
    path(
        "servers/<int:pk>/dhcp<family:family>/option-def/",
        options.ServerOptionDefView.as_view(),
        name="server_option_def",
    ),
    path(
        "servers/<int:pk>/dhcp<family:family>/option-def/add/",
        options.ServerOptionDefAddView.as_view(),
        name="server_option_def_add",
    ),
    path(
        "servers/<int:pk>/dhcp<family:family>/option-def/<int:code>/<str:space>/delete/",
        options.ServerOptionDefDeleteView.as_view(),
        name="server_option_def_delete",
    ),
    path("servers/<int:pk>/", include(get_model_urls("netbox_kea", "server"))),
    path(
        "ip-addresses/<int:pk>/kea-reservations/",
        options.IPAddressKeaReservationsView.as_view(),
        name="ipaddress_kea_reservations",
    ),
)
