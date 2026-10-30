# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Validate live connectivity when a submission creates or changes a Server connection."""

from functools import partial
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError

from .constants import Family
from .kea import KeaCommand
from .read_failure import ReadFailure, attempt

if TYPE_CHECKING:
    from .models import Server

CONNECTION_FIELDS = (
    "ca_url",
    "ca_username",
    "ca_password",
    "dhcp4_url",
    "dhcp4_username",
    "dhcp4_password",
    "dhcp6_url",
    "dhcp6_username",
    "dhcp6_password",
    "ssl_verify",
    "ca_file_path",
    "client_cert_path",
    "client_key_path",
    "has_control_agent",
    "dhcp4",
    "dhcp6",
)
ConnectionValues = tuple[str | bool, ...]


def connection_values(server: "Server") -> ConnectionValues:
    """Capture the normalized connection values before native submission validation mutates the Server."""
    return tuple(getattr(server, field) for field in CONNECTION_FIELDS)


def _version_get(server: "Server", family: Family) -> object:
    """Send ``version-get`` to the DHCP daemon of *family*."""
    return server.get_client(version=family).command(KeaCommand.VERSION_GET, family)


def validate_connection_change(server: "Server", before: ConnectionValues | None) -> None:
    """Probe enabled services on creation or an actual connection change. None means creation."""
    if before is not None and connection_values(server) == before:
        return
    services: tuple[tuple[str, Family], ...] = (("dhcp6", 6), ("dhcp4", 4))
    for field, family in services:
        if not getattr(server, field):
            continue
        checked = attempt(
            f"The DHCPv{family} connectivity check of a Server submission", partial(_version_get, server, family)
        )
        if isinstance(checked, ReadFailure):
            if checked.kind == "malformed":
                raise ValidationError({field: "An internal error occurred."})
            raise ValidationError({field: f"Unable to reach the Kea DHCPv{family} service."})
