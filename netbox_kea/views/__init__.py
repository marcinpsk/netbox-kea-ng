# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Views package for netbox_kea.

Importing every submodule here is what makes their ``register_model_view``
decorators run, so NetBox knows the Server tabs before ``urls.py`` asks
``get_model_urls`` for them.
"""

from . import (
    _base,
    combined,
    dhcp_control,
    dhcp_plugin_sync,
    fan_out,
    leases,
    manual_sync_presenter,
    notices,
    options,
    read_age,
    reservation_mutations,
    reservations,
    server,
    server_scope,
    server_switch,
    settings_page,
    shared_networks,
    subnets,
    sync_jobs,
    sync_views,
    workspace,
)
