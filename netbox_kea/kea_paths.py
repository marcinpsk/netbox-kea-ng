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

#: The Kea key of the free-form context that an operator attaches to a Kea object.
USER_CONTEXT = "user-context"
# Global keys of the daemon configuration that the DHCP Import reads by name.
SERVER_ID = "server-id"
HOST_RESERVATION_IDENTIFIERS = "host-reservation-identifiers"
ALLOW_ADDRESS_REGISTRATION = "allow-address-registration"
STASH_AGENT_OPTIONS = "stash-agent-options"
INTERFACES_CONFIG = "interfaces-config"
SHARED_NETWORKS = "shared-networks"
CLIENT_CLASSES = "client-classes"
EVALUATE_ADDITIONAL_CLASSES = "evaluate-additional-classes"
#: The custom Option Definitions of the daemon or of a client class.
OPTION_DEF = "option-def"
POOL_ID = "pool-id"
OPTION_DATA = "option-data"
#: The DHCPv6 delegated-prefix Pools of a Subnet, and the keys of one that the DHCP Import reads by name.
PD_POOLS = "pd-pools"
PREFIX = "prefix"
PREFIX_LEN = "prefix-len"
DELEGATED_LEN = "delegated-len"
EXCLUDED_PREFIX = "excluded-prefix"
EXCLUDED_PREFIX_LEN = "excluded-prefix-len"
#: The Subnet key that names the interface of its directly connected clients.
INTERFACE = "interface"
ADAPTIVE_LEASE_TIME_THRESHOLD = "adaptive-lease-time-threshold"
#: The ``server-id`` keys besides its type, each with the value that tells Kea to generate it.
SERVER_ID_PARAMETERS = {"identifier": "", "enterprise-id": 0, "htype": 0, "time": 0}


def _step(key: str, identity: str | int) -> str:
    return f"{key}[{identity}]"


def every_entry(path: str) -> str:
    """Return the path that names every entry of the collection at *path*."""
    return _step(path, "*")


def daemon(family: int) -> str:
    """Return the path of the configuration of one daemon."""
    return f"Dhcp{family}"


def subnet_collection(family: int) -> str:
    """Return the key of the Subnet collection of a daemon or Shared Network of *family*."""
    return f"subnet{family}"


def subnet(family: int, subnet_id: int | None, cidr: str | None = None) -> str:
    """Return the path of a Subnet by its Kea subnet ID, or by its CIDR when Kea gave no ID."""
    identity = f"id={subnet_id}" if subnet_id is not None else f"subnet={cidr}"
    return f"{daemon(family)}/{_step(subnet_collection(family), identity)}"


def subnet_entry(parent: str, family: int, index: int) -> str:
    """Return the path of the Subnet entry at *index* of the daemon or Shared Network at *parent*."""
    return f"{parent}/{_step(subnet_collection(family), index)}"


def shared_network(family: int, name: str) -> str:
    """Return the path of a Shared Network by its name."""
    return f"{daemon(family)}/{_step(SHARED_NETWORKS, f'name={name}')}"


def shared_network_entry(family: int, index: int) -> str:
    """Return the path of the Shared Network entry at *index*."""
    return f"{daemon(family)}/{_step(SHARED_NETWORKS, index)}"


def pool(subnet_path: str, text: str) -> str:
    """Return the path of a Pool by its Kea text inside the Subnet at *subnet_path*."""
    return f"{subnet_path}/{_step('pools', f'pool={text}')}"


def pool_collection(subnet_path: str) -> str:
    """Return the path of the Pool collection of the Subnet at *subnet_path*."""
    return f"{subnet_path}/pools"


def pool_entry(subnet_path: str, index: int) -> str:
    """Return the path of the Pool entry at *index* of the Subnet at *subnet_path*."""
    return f"{subnet_path}/{_step('pools', index)}"


def pd_pool(subnet_path: str, prefix: str, delegated_length: int) -> str:
    """Return the path of a delegated-prefix Pool by its prefix and delegated length inside the Subnet at *subnet_path*."""
    return f"{subnet_path}/{_step(PD_POOLS, f'{PREFIX}={prefix},{DELEGATED_LEN}={delegated_length}')}"


def pd_pool_collection(subnet_path: str) -> str:
    """Return the path of the delegated-prefix Pool collection of the Subnet at *subnet_path*."""
    return f"{subnet_path}/{PD_POOLS}"


def pd_pool_entry(subnet_path: str, index: int) -> str:
    """Return the path of the delegated-prefix Pool entry at *index* of the Subnet at *subnet_path*."""
    return f"{subnet_path}/{_step(PD_POOLS, index)}"


def client_class(family: int, name: str) -> str:
    """Return the path of a client class by its name."""
    return f"{daemon(family)}/{_step(CLIENT_CLASSES, f'name={name}')}"


def class_reference(parent: str, key: str, name: str) -> str:
    """Return the path of the class *name* in the class list *key* of the object at *parent*."""
    return f"{parent}/{_step(key, name)}"


def client_class_entry(family: int, index: int) -> str:
    """Return the path of the client class entry at *index*."""
    return f"{daemon(family)}/{_step(CLIENT_CLASSES, index)}"


def default_space(family: int) -> str:
    """Return the Kea and DHCP plugin default option space of a family."""
    return f"dhcp{family}"


def _definition_parent(family: int, class_name: str | None) -> str:
    """Return the path of the object that declares an Option Definition: the daemon, or the client class."""
    return daemon(family) if class_name is None else client_class(family, class_name)


def option_definition(family: int, space: str, code: int, class_name: str | None = None) -> str:
    """Return the path of a custom Option Definition of the daemon or of the client class *class_name*.

    The default space is left out.
    """
    identity = f"code={code}" if space == default_space(family) else f"space={space},code={code}"
    return f"{_definition_parent(family, class_name)}/{_step(OPTION_DEF, identity)}"


def option_definition_collection(family: int, class_name: str | None = None) -> str:
    """Return the path of the Option Definition collection of the daemon or of the client class *class_name*."""
    return f"{_definition_parent(family, class_name)}/{OPTION_DEF}"


def option_definition_entry(family: int, index: int, class_name: str | None = None) -> str:
    """Return the path of the Option Definition entry at *index* of the daemon or of the client class *class_name*."""
    return f"{_definition_parent(family, class_name)}/{_step(OPTION_DEF, index)}"


def option(parent: str, option: DHCPOption, family: int) -> str:
    """Return the path of a DHCP Option of the object at *parent*, by its code (else its name) and client classes."""
    identity = f"code={option.code}" if option.code is not None else f"name={option.name}"
    if option.space not in (None, default_space(family)):
        identity = f"space={option.space},{identity}"
    if option.client_classes:
        identity = f"{identity},client-classes={'|'.join(sorted(option.client_classes))}"
    return f"{parent}/{_step(OPTION_DATA, identity)}"


def interface(family: int, entry: str) -> str:
    """Return the path of one entry of the interface list of a daemon."""
    return f"{daemon(family)}/{INTERFACES_CONFIG}/{_step('interfaces', entry)}"


def setting(parent: str, key: str) -> str:
    """Return the path of the configuration key *key* of the object at *parent*."""
    return f"{parent}/{key}"


def option_collection(parent: str) -> str:
    """Return the path of the DHCP Option collection of the object at *parent*."""
    return f"{parent}/{OPTION_DATA}"


def option_entry(parent: str, index: int) -> str:
    """Return the path of the DHCP Option entry at *index* of the object at *parent*."""
    return f"{parent}/{_step(OPTION_DATA, index)}"


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
