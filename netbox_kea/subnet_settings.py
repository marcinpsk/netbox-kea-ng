# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Subnet Settings and the Kea key of each scalar field, which the reader and the writers share."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .constants import IPAddressValue


@dataclass(frozen=True)
class ReservationFlags:
    """The reservation flags that Kea applies to one Subnet, after inheritance."""

    #: Kea applies Global Reservations.
    global_: bool
    #: Kea applies In-Subnet Reservations.
    in_subnet: bool
    #: Kea gives an In-Subnet reserved address only when no Pool of the Subnet holds it.
    out_of_pool: bool


@dataclass(frozen=True)
class DeclaredReservationFlags:
    """The reservation flags that one configuration level sets. None: the level does not set the flag."""

    global_: bool | None = None
    in_subnet: bool | None = None
    out_of_pool: bool | None = None


#: The Kea key of each reservation flag, the same at the global, Shared Network and Subnet levels.
RESERVATION_FLAG_KEYS: dict[str, str] = {
    "global_": "reservations-global",
    "in_subnet": "reservations-in-subnet",
    "out_of_pool": "reservations-out-of-pool",
}
#: The value of each flag that Kea applies when no level of the configuration sets it.
KEA_RESERVATION_FLAGS = ReservationFlags(global_=False, in_subnet=True, out_of_pool=False)


def inherited_reservation_flags(*levels: DeclaredReservationFlags) -> ReservationFlags:
    """Return each flag from the first of *levels* that sets it (the Subnet first), else Kea's default."""
    values: dict[str, bool] = {}
    for field in RESERVATION_FLAG_KEYS:
        declared = (value for level in levels if (value := getattr(level, field)) is not None)
        values[field] = next(declared, getattr(KEA_RESERVATION_FLAGS, field))
    return ReservationFlags(**values)


@dataclass(frozen=True)
class SubnetSettings:
    """Effective typed DHCP settings that the repository currently consumes."""

    valid_lifetime: int | None = None
    min_valid_lifetime: int | None = None
    max_valid_lifetime: int | None = None
    preferred_lifetime: int | None = None
    min_preferred_lifetime: int | None = None
    max_preferred_lifetime: int | None = None
    offer_lifetime: int | None = None
    renew_timer: int | None = None
    rebind_timer: int | None = None
    allocator: str | None = None
    pd_allocator: str | None = None
    ddns_qualifying_suffix: str | None = None
    interface_id: str | None = None
    relay_addresses: tuple[IPAddressValue, ...] = ()
    client_classes: tuple[str, ...] = ()
    require_client_classes: tuple[str, ...] = ()
    reservation_flags: DeclaredReservationFlags = DeclaredReservationFlags()


# integer: a non-negative integer. string: a non-empty string. string_or_empty: a string that can be empty.
ValueKind = Literal["integer", "string", "string_or_empty"]


@dataclass(frozen=True)
class SettingKey:
    """The Kea key of one scalar Subnet Settings field and the kind of its value."""

    key: str
    kind: ValueKind


# Each scalar field of SubnetSettings. The relay, class and reservation flag keys have their own shapes, so their code
# is by hand.
SETTING_KEYS: dict[str, SettingKey] = {
    "valid_lifetime": SettingKey("valid-lifetime", "integer"),
    "min_valid_lifetime": SettingKey("min-valid-lifetime", "integer"),
    "max_valid_lifetime": SettingKey("max-valid-lifetime", "integer"),
    "preferred_lifetime": SettingKey("preferred-lifetime", "integer"),
    "min_preferred_lifetime": SettingKey("min-preferred-lifetime", "integer"),
    "max_preferred_lifetime": SettingKey("max-preferred-lifetime", "integer"),
    "offer_lifetime": SettingKey("offer-lifetime", "integer"),
    "renew_timer": SettingKey("renew-timer", "integer"),
    "rebind_timer": SettingKey("rebind-timer", "integer"),
    "allocator": SettingKey("allocator", "string"),
    "pd_allocator": SettingKey("pd-allocator", "string"),
    "ddns_qualifying_suffix": SettingKey("ddns-qualifying-suffix", "string_or_empty"),
    "interface_id": SettingKey("interface-id", "string"),
}


def setting_key(field: str) -> str:
    """Return the Kea key of the scalar Subnet Settings field *field*."""
    return SETTING_KEYS[field].key
