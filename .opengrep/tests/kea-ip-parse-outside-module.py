# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-ip-parse-outside-module. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
import ipaddress
import ipaddress as ip
from ipaddress import IPv4Address, IPv6Network, ip_address

import netaddr
from ipam.models import IPAddress as IPAddressModel
from netaddr import IPAddress, IPNetwork

from netbox_kea import ip_parse


def bad_address(text):
    # ruleid: kea-ip-parse-outside-module
    return ipaddress.ip_address(text)


def bad_network(text):
    # ruleid: kea-ip-parse-outside-module
    return ipaddress.ip_network(text, strict=False)


def bad_interface(text):
    # ruleid: kea-ip-parse-outside-module
    return ipaddress.ip_interface(text)


def bad_family_constructors(text):
    # ruleid: kea-ip-parse-outside-module
    v4 = ipaddress.IPv4Address(text)
    # ruleid: kea-ip-parse-outside-module
    v6 = ipaddress.IPv6Address(text)
    # ruleid: kea-ip-parse-outside-module
    n4 = ipaddress.IPv4Network(text, strict=True)
    # ruleid: kea-ip-parse-outside-module
    n6 = ipaddress.IPv6Network(f"{text}/64")
    # ruleid: kea-ip-parse-outside-module
    i6 = ipaddress.IPv6Interface(text)
    return v4, v6, n4, n6, i6


def bad_literal():
    # ruleid: kea-ip-parse-outside-module
    return ipaddress.IPv4Address("255.255.255.255")


def bad_keyword(text):
    # ruleid: kea-ip-parse-outside-module
    return ipaddress.ip_network(address=text)


def bad_aliases(text):
    # ruleid: kea-ip-parse-outside-module
    address = ip_address(text)
    # ruleid: kea-ip-parse-outside-module
    network = IPv6Network(text)
    # ruleid: kea-ip-parse-outside-module
    other = ip.ip_network(text)
    return address, network, other


def bad_netaddr(text, version):
    # ruleid: kea-ip-parse-outside-module
    address = netaddr.IPAddress(text)
    # ruleid: kea-ip-parse-outside-module
    page = IPAddress(text, version=version)
    return address, page


def good_netaddr_values(address, length):
    # ok: kea-ip-parse-outside-module
    return netaddr.IPAddress(0), IPNetwork(f"{address}/{length}"), IPAddressModel(address=IPNetwork(address))


def good_parse(text):
    # ok: kea-ip-parse-outside-module
    return ip_parse.ip_address(text), ip_parse.ipv6_network(text, strict=False)


def good_int_literal():
    # ok: kea-ip-parse-outside-module
    return ipaddress.IPv4Address(0), IPv4Address(4294967295)


def good_address_and_length(address, length):
    # ok: kea-ip-parse-outside-module
    return ipaddress.IPv6Network((address, length))


def good_type_use(value):
    # ok: kea-ip-parse-outside-module
    return isinstance(value, ipaddress.IPv4Address), ipaddress.summarize_address_range(value, value)
