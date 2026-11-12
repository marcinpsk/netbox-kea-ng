# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""NetBox plugin template extensions for netbox-kea-ng.

Injects a Kea panel onto the NetBox IPAddress detail page, providing
quick links to create host reservations on configured Kea servers, and
a banner on every plugin page while a netbox-branching branch is active.
"""

from django.urls import reverse
from netbox.plugins import PluginTemplateExtension

from . import branching
from .views.options import reservation_links


class BranchBanner(PluginTemplateExtension):
    """Says, on each plugin page in a branch, where the page's data comes from and that changes are refused."""

    def navbar(self):  # noqa: D102
        branch = branching.active_branch()
        match = getattr(self.context["request"], "resolver_match", None)
        if branch is None or match is None or not branching.plugin_owned(match.func):
            return ""
        return self.render("netbox_kea/inc/branch_banner.html", extra_context={"branch": branch})


class IPAddressKeaPanel(PluginTemplateExtension):
    """Renders a 'Kea Reservations' panel on the IPAddress detail page.

    Appears on the right side of the page, listing the Kea servers of the IP's address family that the user may
    change, with pre-filled 'Create Reservation' links.
    """

    model = "ipam.ipaddress"  # NetBox <= 4.0
    models = ["ipam.ipaddress"]  # NetBox >= 4.1

    def right_page(self):  # noqa: D102
        nb_ip = self.context.get("object")
        if nb_ip is None:
            return ""
        if not nb_ip.address or not nb_ip.address.ip:
            return ""

        links = reservation_links(self.context["request"].user, nb_ip)
        return self.render(
            "netbox_kea/inc/ip_kea_panel.html",
            extra_context={
                "server_links": links.entries,
                "in_branch": links.in_branch,
                "version": links.family,
                "kea_page_url": reverse(
                    "plugins:netbox_kea:ipaddress_kea_reservations",
                    args=[nb_ip.pk],
                ),
            },
        )
