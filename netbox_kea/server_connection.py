# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Validate live connectivity when a submission creates or changes a Server connection."""

from functools import partial

from django.core.exceptions import ValidationError

from .constants import Family
from .kea import KeaCommand
from .models import KeaConnection, Server
from .read_failure import ReadFailure, attempt

#: The effective connection of each DHCP family, in probe order, or None when the family is disabled.
ServiceConnections = dict[Family, KeaConnection | None]
#: The Server field that enables each DHCP family, in probe order. A probe error goes on this field.
_SERVICE_FIELDS: dict[Family, str] = {6: "dhcp6", 4: "dhcp4"}


def service_connections(server: Server) -> ServiceConnections:
    """Capture the effective connections before native submission validation mutates the Server."""
    return {
        family: server.kea_connection(family) if getattr(server, field) else None
        for family, field in _SERVICE_FIELDS.items()
    }


def _version_get(server: Server, family: Family) -> object:
    """Send ``version-get`` to the DHCP daemon of *family*."""
    with server.get_client(version=family) as client:
        return client.command(KeaCommand.VERSION_GET, family)


def validate_connection_change(server: Server, before: ServiceConnections | None) -> None:
    """Probe each enabled family on creation, else each enabled family whose connection changed. None means creation."""
    for family, connection in service_connections(server).items():
        if connection is None or (before is not None and before[family] == connection):
            continue
        checked = attempt(
            f"The DHCPv{family} connectivity check of a Server submission", partial(_version_get, server, family)
        )
        if isinstance(checked, ReadFailure):
            if checked.kind == "malformed":
                raise ValidationError({_SERVICE_FIELDS[family]: "An internal error occurred."})
            raise ValidationError({_SERVICE_FIELDS[family]: f"Unable to reach the Kea DHCPv{family} service."})
