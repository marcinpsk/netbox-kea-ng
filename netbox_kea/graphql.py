# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2023-2026 Devon Mar <devon-mar@users.noreply.github.com>
# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING, Annotated

import strawberry
import strawberry_django
from netbox.graphql.types import NetBoxObjectType

from . import models
from .views.server_scope import permitted_servers

if TYPE_CHECKING:
    # strawberry.lazy resolves the type at runtime; this is for the linters.
    from ipam.graphql.types import VRFType


@strawberry_django.type(
    models.Server,
    fields=(
        "id",
        "name",
        "ca_url",
        "ca_username",
        "dhcp4_username",
        "dhcp6_username",
        "ssl_verify",
        "client_cert_path",
        "client_key_path",
        "ca_file_path",
        "dhcp6",
        "dhcp4",
        "dhcp4_url",
        "dhcp6_url",
        "has_control_agent",
        "sync_enabled",
        "sync_leases_enabled",
        "sync_reservations_enabled",
        "sync_prefixes_enabled",
        "sync_ip_ranges_enabled",
        "sync_deprecate_prefixes_and_ranges",
        "sync_dhcp_plugin_enabled",
        "sync_vrf",
        "ipam_first_complete_at",
    ),
)
class ServerType(NetBoxObjectType):
    """GraphQL type for the Server model."""

    # Without the annotation strawberry_django resolves the FK to a placeholder
    # DjangoModelType that exposes no fields at all.
    sync_vrf: Annotated["VRFType", strawberry.lazy("ipam.graphql.types")] | None


@strawberry.type
class Query:
    """GraphQL root query type exposing Kea server objects."""

    @strawberry.field
    def server(self, id: int, info: strawberry.types.Info) -> ServerType:  # noqa: A002 - published GraphQL argument name
        """Return a single Server by primary key."""
        return permitted_servers(info.context.request.user).get(pk=id)

    server_list: list[ServerType] = strawberry_django.field()


schema = [Query]
