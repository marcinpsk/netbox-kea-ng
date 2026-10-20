# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Kea configuration paths: the text that names one Kea object in a DHCP Import result.

A path starts at the daemon configuration and names each step by the Kea key and the identity of the entry, for
example ``Dhcp4/subnet4[id=20]/option-data[code=150]``. An entry without an identity is named by its position, for
example ``Dhcp4/subnet4[3]``. A path is display text: values are not escaped, and nothing parses a path back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .dhcp_options import DHCPOption


def _step(key: str, identity: str | int) -> str:
    return f"{key}[{identity}]"


def daemon(family: int) -> str:
    """Return the path of the configuration of one daemon."""
    return f"Dhcp{family}"


def subnet(family: int, subnet_id: int | None, cidr: str | None = None) -> str:
    """Return the path of a Subnet by its Kea subnet ID, or by its CIDR when Kea gave no ID."""
    identity = f"id={subnet_id}" if subnet_id is not None else f"subnet={cidr}"
    return f"{daemon(family)}/{_step(f'subnet{family}', identity)}"


def subnet_entry(parent: str, family: int, index: int) -> str:
    """Return the path of the Subnet entry at *index* of the daemon or Shared Network at *parent*."""
    return f"{parent}/{_step(f'subnet{family}', index)}"


def shared_network(family: int, name: str) -> str:
    """Return the path of a Shared Network by its name."""
    return f"{daemon(family)}/{_step('shared-networks', f'name={name}')}"


def shared_network_entry(family: int, index: int) -> str:
    """Return the path of the Shared Network entry at *index*."""
    return f"{daemon(family)}/{_step('shared-networks', index)}"


def pool(subnet_path: str, text: str) -> str:
    """Return the path of a Pool by its Kea text inside the Subnet at *subnet_path*."""
    return f"{subnet_path}/{_step('pools', f'pool={text}')}"


def pool_collection(subnet_path: str) -> str:
    """Return the path of the Pool collection of the Subnet at *subnet_path*."""
    return f"{subnet_path}/pools"


def pool_entry(subnet_path: str, index: int) -> str:
    """Return the path of the Pool entry at *index* of the Subnet at *subnet_path*."""
    return f"{subnet_path}/{_step('pools', index)}"


def client_class(family: int, name: str) -> str:
    """Return the path of a client class by its name."""
    return f"{daemon(family)}/{_step('client-classes', f'name={name}')}"


def client_class_entry(family: int, index: int) -> str:
    """Return the path of the client class entry at *index*."""
    return f"{daemon(family)}/{_step('client-classes', index)}"


def default_space(family: int) -> str:
    """Return the Kea and DHCP plugin default option space of a family."""
    return f"dhcp{family}"


def option_definition(family: int, space: str, code: int) -> str:
    """Return the path of a custom Option Definition by its space and code. The default space is left out."""
    identity = f"code={code}" if space == default_space(family) else f"space={space},code={code}"
    return f"{daemon(family)}/{_step('option-def', identity)}"


def option_definition_collection(family: int) -> str:
    """Return the path of the Option Definition collection."""
    return f"{daemon(family)}/option-def"


def option_definition_entry(family: int, index: int) -> str:
    """Return the path of the Option Definition entry at *index*."""
    return f"{daemon(family)}/{_step('option-def', index)}"


def option(parent: str, option: DHCPOption, family: int) -> str:
    """Return the path of a DHCP Option of the object at *parent*, by its code (else its name) and client classes."""
    identity = f"code={option.code}" if option.code is not None else f"name={option.name}"
    if option.space not in (None, default_space(family)):
        identity = f"space={option.space},{identity}"
    if option.client_classes:
        identity = f"{identity},client-classes={'|'.join(sorted(option.client_classes))}"
    return f"{parent}/{_step('option-data', identity)}"


def setting(parent: str, key: str) -> str:
    """Return the path of the configuration key *key* of the object at *parent*."""
    return f"{parent}/{key}"


def option_collection(parent: str) -> str:
    """Return the path of the DHCP Option collection of the object at *parent*."""
    return f"{parent}/option-data"


def option_entry(parent: str, index: int) -> str:
    """Return the path of the DHCP Option entry at *index* of the object at *parent*."""
    return f"{parent}/{_step('option-data', index)}"


def reservations(family: int, subnet_id: int | None = None) -> str:
    """Return the path of the Reservations of a Subnet, or of the Global Reservations without *subnet_id*."""
    parent = daemon(family) if subnet_id is None else subnet(family, subnet_id)
    return f"{parent}/reservations"


def reservation(family: int, subnet_id: int | None, identifier_type: str, value: str) -> str:
    """Return the path of a Reservation by its Scope and Reservation Identity."""
    return f"{reservations(family, subnet_id)}[{identifier_type}={value}]"


def reservation_record(family: int, source_position: str) -> str:
    """Return the path of a Reservation record by its position in the reservation-get-page reply, in any Scope."""
    return f"{daemon(family)}/reservation-get-page/{source_position}"
