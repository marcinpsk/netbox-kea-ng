# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one parse of IP address and network text in the plugin.

``ipaddress`` accepts an IPv6 scope zone (``fe80::1%eth0``) and keeps it in the value. Kea and NetBox IPAM cannot
use such a value, and netaddr refuses it. Each function parses the text with ``ipaddress``, so the error messages
and the ``strict`` rule stay the same, and then validates the same text with netaddr.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Annotated, Any

import netaddr
from pydantic import BeforeValidator

from .constants import IPAddressValue, IPNetworkValue


def _text(text: object) -> str:
    if not isinstance(text, str):
        raise TypeError(f"IP address or network text must be a str, not {type(text).__name__}.")
    return text


def _validate_address(text: str, version: int, kind: str) -> None:
    if not (netaddr.valid_ipv4(text) if version == 4 else netaddr.valid_ipv6(text)):
        raise ValueError(f"{text!r} does not appear to be an {kind} address")


def _validate_network(text: str, kind: str) -> None:
    try:
        netaddr.IPNetwork(text)
    except (netaddr.AddrFormatError, ValueError):
        raise ValueError(f"{text!r} does not appear to be an {kind} network") from None


def ip_address(text: str) -> IPAddressValue:
    """Return the IPv4 or IPv6 address of *text*.

    Raises:
        TypeError: If *text* is not a str.
        ValueError: If *text* is not an address, or it has an IPv6 scope zone.

    """
    address = ipaddress.ip_address(_text(text))
    _validate_address(text, address.version, "IPv4 or IPv6")
    return address


def ipv4_address(text: str) -> ipaddress.IPv4Address:
    """Return the IPv4 address of *text*.

    Raises:
        TypeError: If *text* is not a str.
        ValueError: If *text* is not an IPv4 address.

    """
    address = ipaddress.IPv4Address(_text(text))
    _validate_address(text, 4, "IPv4")
    return address


def ipv6_address(text: str) -> ipaddress.IPv6Address:
    """Return the IPv6 address of *text*.

    Raises:
        TypeError: If *text* is not a str.
        ValueError: If *text* is not an IPv6 address, or it has a scope zone.

    """
    address = ipaddress.IPv6Address(_text(text))
    _validate_address(text, 6, "IPv6")
    return address


def ip_network(text: str, *, strict: bool = True) -> IPNetworkValue:
    """Return the IPv4 or IPv6 network of *text*; *strict* refuses host bits, as in ``ipaddress``.

    Raises:
        TypeError: If *text* is not a str.
        ValueError: If *text* is not a network, or it has an IPv6 scope zone.

    """
    network = ipaddress.ip_network(_text(text), strict=strict)
    _validate_network(text, "IPv4 or IPv6")
    return network


def ipv4_network(text: str, *, strict: bool = True) -> ipaddress.IPv4Network:
    """Return the IPv4 network of *text*; *strict* refuses host bits, as in ``ipaddress``.

    Raises:
        TypeError: If *text* is not a str.
        ValueError: If *text* is not an IPv4 network.

    """
    network = ipaddress.IPv4Network(_text(text), strict=strict)
    _validate_network(text, "IPv4")
    return network


def ipv6_network(text: str, *, strict: bool = True) -> ipaddress.IPv6Network:
    """Return the IPv6 network of *text*; *strict* refuses host bits, as in ``ipaddress``.

    Raises:
        TypeError: If *text* is not a str.
        ValueError: If *text* is not an IPv6 network, or it has a scope zone.

    """
    network = ipaddress.IPv6Network(_text(text), strict=strict)
    _validate_network(text, "IPv6")
    return network


def _model_text(parse: Callable[[str], object]) -> BeforeValidator:
    def validate(value: Any) -> Any:
        # The pydantic type parses the text after this check, so a valid value stays text here.
        if isinstance(value, str):
            parse(value)
        return value

    return BeforeValidator(validate)


# The pydantic field types: pydantic parses text with ipaddress, so each one first refuses text that the parse refuses.
IPAddressField = Annotated[IPAddressValue, _model_text(ip_address)]
IPv4AddressField = Annotated[ipaddress.IPv4Address, _model_text(ipv4_address)]
IPv6AddressField = Annotated[ipaddress.IPv6Address, _model_text(ipv6_address)]
IPv6NetworkField = Annotated[ipaddress.IPv6Network, _model_text(ipv6_network)]
