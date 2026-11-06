# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Client Identifier rule: one hexadecimal grammar, and Kea's octet bounds for a Lease and for a Reservation."""

from __future__ import annotations

import re
from typing import Literal

ClientIdentifierKind = Literal["hw-address", "duid", "client-id"]

# Kea 3.2.0 octet bounds, probed with `kea-dhcp4 -t` and `kea-dhcp6 -t`.
LEASE_OCTETS: dict[ClientIdentifierKind, tuple[int, int]] = {
    "hw-address": (1, 20),
    "duid": (3, 130),
    "client-id": (2, 255),
}
RESERVATION_OCTETS: dict[ClientIdentifierKind, tuple[int, int]] = {**LEASE_OCTETS, "client-id": (1, 255)}

_LABELS: dict[ClientIdentifierKind, str] = {"hw-address": "hardware address", "duid": "DUID", "client-id": "client ID"}


def octets_message(kind: ClientIdentifierKind, octets: tuple[int, int]) -> str:
    """Return the instruction for a *kind* value within the *octets* bounds."""
    return f"Enter a {_LABELS[kind]} of {octets[0]} to {octets[1]} hexadecimal octets."


def normalize_hex(value: str, octets: tuple[int, int]) -> str:
    """Return *value* as lowercase colon-separated octets, within the inclusive *octets* bounds.

    The value can use colon, dash or dot separators, or none. Like Kea, each colon or dash
    group is one octet of one or two digits.

    Raises:
        ValueError: If *value* is not hexadecimal octets within the bounds.

    """
    if ":" in value or "-" in value:
        groups = re.split(r"[:-]", value)
        if any(re.fullmatch(r"[0-9A-Fa-f]{1,2}", group) is None for group in groups):
            raise ValueError("The identifier is not hexadecimal octets.")
        compact = "".join(group.zfill(2) for group in groups)
    else:
        compact = value.replace(".", "")
        if not compact or len(compact) % 2 or re.fullmatch(r"[0-9A-Fa-f]+", compact) is None:
            raise ValueError("The identifier is not hexadecimal octets.")
    minimum, maximum = octets
    if not minimum <= len(compact) // 2 <= maximum:
        raise ValueError("The identifier has an unsupported number of octets.")
    return ":".join(compact[index : index + 2].lower() for index in range(0, len(compact), 2))
