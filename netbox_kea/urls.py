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
    path("combined/", combined.CombinedDashboardView.as_view(), name="combined"),
    path("combined/overview4/", combined.CombinedDashboardView.as_view(), name="combined_overview4"),
    path("combined/overview6/", combined.CombinedDashboard6View.as_view(), name="combined_overview6"),
    path("combined/configuration4/", combined.CombinedConfiguration4View.as_view(), name="combined_configuration4"),
    path("combined/configuration6/", combined.CombinedConfiguration6View.as_view(), name="combined_configuration6"),
    path("combined/sync4/", combined.CombinedSync4View.as_view(), name="combined_sync4"),
    path("combined/sync6/", combined.CombinedSync6View.as_view(), name="combined_sync6"),
    path("combined/leases4/", combined.CombinedLeases4View.as_view(), name="combined_leases4"),
    path("combined/leases6/", combined.CombinedLeases6View.as_view(), name="combined_leases6"),
    path("combined/subnets4/", combined.CombinedSubnets4View.as_view(), name="combined_subnets4"),
    path("combined/subnets6/", combined.CombinedSubnets6View.as_view(), name="combined_subnets6"),
    path(
        "combined/shared-networks4/",
        combined.CombinedSharedNetworks4View.as_view(),
        name="combined_shared_networks4",
    ),
    path(
        "combined/shared-networks6/",
        combined.CombinedSharedNetworks6View.as_view(),
        name="combined_shared_networks6",
    ),
    path(
        "combined/reservations4/",
        combined.CombinedReservations4View.as_view(),
        name="combined_reservations4",
    ),
    path(
        "combined/reservations6/",
        combined.CombinedReservations6View.as_view(),
        name="combined_reservations6",
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
        "servers/<int:pk>/leases6/delete/",
        leases.ServerLeases6DeleteView.as_view(),
        name="server_leases6_delete",
    ),
    path(
        "servers/<int:pk>/leases4/delete/",
        leases.ServerLeases4DeleteView.as_view(),
        name="server_leases4_delete",
    ),
    path(
        "servers/<int:pk>/reservation/check-ip/",
        sync_views.ReservationCheckNetboxIPView.as_view(),
        name="reservation_check_ip",
    ),
    path(
        "servers/<int:pk>/reservations4/add/",
        reservation_mutations.ServerReservation4AddView.as_view(),
        name="server_reservation4_add",
    ),
    path(
        "servers/<int:pk>/reservations4/published-name/",
        reservation_mutations.ServerReservation4PublishedNameView.as_view(),
        name="server_reservation4_published_name",
    ),
    path(
        "servers/<int:pk>/reservations4/<int:subnet_id>/edit/",
        reservation_mutations.ServerReservation4EditView.as_view(),
        name="server_reservation4_edit",
    ),
    path(
        "servers/<int:pk>/reservations4/<int:subnet_id>/delete/",
        reservation_mutations.ServerReservation4DeleteView.as_view(),
        name="server_reservation4_delete",
    ),
    path(
        "servers/<int:pk>/reservations6/add/",
        reservation_mutations.ServerReservation6AddView.as_view(),
        name="server_reservation6_add",
    ),
    path(
        "servers/<int:pk>/reservations6/published-name/",
        reservation_mutations.ServerReservation6PublishedNameView.as_view(),
        name="server_reservation6_published_name",
    ),
    path(
        "servers/<int:pk>/reservations6/<int:subnet_id>/edit/",
        reservation_mutations.ServerReservation6EditView.as_view(),
        name="server_reservation6_edit",
    ),
    path(
        "servers/<int:pk>/reservations6/<int:subnet_id>/delete/",
        reservation_mutations.ServerReservation6DeleteView.as_view(),
        name="server_reservation6_delete",
    ),
    path(
        "servers/<int:pk>/leases4/sync/",
        sync_views.ServerLease4SyncView.as_view(),
        name="server_lease4_sync",
    ),
    path(
        "servers/<int:pk>/leases6/sync/",
        sync_views.ServerLease6SyncView.as_view(),
        name="server_lease6_sync",
    ),
    path(
        "servers/<int:pk>/reservations4/<int:subnet_id>/sync/",
        sync_views.ServerReservation4SyncView.as_view(),
        name="server_reservation4_sync",
    ),
    path(
        "servers/<int:pk>/reservations6/<int:subnet_id>/sync/",
        sync_views.ServerReservation6SyncView.as_view(),
        name="server_reservation6_sync",
    ),
    path(
        "servers/<int:pk>/reservations4/bulk-sync/",
        sync_views.ServerReservation4BulkSyncView.as_view(),
        name="server_reservation4_bulk_sync",
    ),
    path(
        "servers/<int:pk>/reservations6/bulk-sync/",
        sync_views.ServerReservation6BulkSyncView.as_view(),
        name="server_reservation6_bulk_sync",
    ),
    path(
        "servers/<int:pk>/reservations4/import/",
        sync_views.ServerReservation4BulkImportView.as_view(),
        name="server_reservation4_bulk_import",
    ),
    path(
        "servers/<int:pk>/reservations6/import/",
        sync_views.ServerReservation6BulkImportView.as_view(),
        name="server_reservation6_bulk_import",
    ),
    path(
        "servers/<int:pk>/leases4/import/",
        sync_views.ServerLease4BulkImportView.as_view(),
        name="server_lease4_bulk_import",
    ),
    path(
        "servers/<int:pk>/leases6/import/",
        sync_views.ServerLease6BulkImportView.as_view(),
        name="server_lease6_bulk_import",
    ),
    path(
        "servers/<int:pk>/dhcp4/enable/",
        dhcp_control.ServerDHCP4EnableView.as_view(),
        name="server_dhcp4_enable",
    ),
    path(
        "servers/<int:pk>/dhcp4/disable/",
        dhcp_control.ServerDHCP4DisableView.as_view(),
        name="server_dhcp4_disable",
    ),
    path(
        "servers/<int:pk>/dhcp6/enable/",
        dhcp_control.ServerDHCP6EnableView.as_view(),
        name="server_dhcp6_enable",
    ),
    path(
        "servers/<int:pk>/dhcp6/disable/",
        dhcp_control.ServerDHCP6DisableView.as_view(),
        name="server_dhcp6_disable",
    ),
    path(
        "servers/<int:pk>/dhcp4/options/",
        options.ServerDHCP4OptionsEditView.as_view(),
        name="server_dhcp4_options_edit",
    ),
    path(
        "servers/<int:pk>/dhcp6/options/",
        options.ServerDHCP6OptionsEditView.as_view(),
        name="server_dhcp6_options_edit",
    ),
    path(
        "servers/<int:pk>/dhcp4/option-def/add/",
        options.ServerOptionDef4AddView.as_view(),
        name="server_option_def4_add",
    ),
    path(
        "servers/<int:pk>/dhcp6/option-def/add/",
        options.ServerOptionDef6AddView.as_view(),
        name="server_option_def6_add",
    ),
    path(
        "servers/<int:pk>/dhcp4/option-def/<int:code>/<str:space>/delete/",
        options.ServerOptionDef4DeleteView.as_view(),
        name="server_option_def4_delete",
    ),
    path(
        "servers/<int:pk>/dhcp6/option-def/<int:code>/<str:space>/delete/",
        options.ServerOptionDef6DeleteView.as_view(),
        name="server_option_def6_delete",
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
    path("servers/<int:pk>/", include(get_model_urls("netbox_kea", "server"))),
    path(
        "ip-addresses/<int:pk>/kea-reservations/",
        options.IPAddressKeaReservationsView.as_view(),
        name="ipaddress_kea_reservations",
    ),
)
