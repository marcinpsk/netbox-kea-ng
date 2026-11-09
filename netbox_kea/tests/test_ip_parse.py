# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import importlib
import ipaddress
import pkgutil
from typing import Annotated, Any, get_args, get_origin

from django.test import SimpleTestCase
from pydantic import BaseModel, ValidationError

import netbox_kea
from netbox_kea import ip_parse
from netbox_kea.leases import LeaseIdentity

_ADDRESS_PARSES = (ip_parse.ip_address, ip_parse.ipv6_address)
_NETWORK_PARSES = (ip_parse.ip_network, ip_parse.ipv6_network)
_FIELD_TYPES = (
    ip_parse.IPAddressField,
    ip_parse.IPv4AddressField,
    ip_parse.IPv6AddressField,
    ip_parse.IPv6NetworkField,
)
_IP_TYPES = (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)


class TestIPParse(SimpleTestCase):
    """Each parse gives the ipaddress value and refuses an IPv6 scope zone, which Kea and NetBox IPAM cannot use."""

    def test_a_scope_zone_is_refused_by_each_parse(self):
        for parse in _ADDRESS_PARSES:
            for text in ("fe80::1%eth0", "fe80::1%1"):
                with self.subTest(parse=parse.__name__, text=text):
                    with self.assertRaises(ValueError) as ctx:
                        parse(text)
                    self.assertIn(repr(text), str(ctx.exception))
        for parse in _NETWORK_PARSES:
            for text, strict in (("fe80::%eth0/64", True), ("fe80::1%eth0/64", False)):
                with self.subTest(parse=parse.__name__, text=text), self.assertRaises(ValueError):
                    parse(text, strict=strict)

    def test_valid_text_gives_the_ipaddress_value(self):
        for parse, text, expected in (
            (ip_parse.ip_address, "10.0.0.1", ipaddress.IPv4Address("10.0.0.1")),
            (ip_parse.ip_address, "FE80::1", ipaddress.IPv6Address("fe80::1")),
            (ip_parse.ip_address, "::ffff:10.0.0.1", ipaddress.IPv6Address("::ffff:10.0.0.1")),
            (ip_parse.ipv4_address, "10.0.0.1", ipaddress.IPv4Address("10.0.0.1")),
            (ip_parse.ipv6_address, "2001:db8::1", ipaddress.IPv6Address("2001:db8::1")),
            (ip_parse.ip_network, "10.0.0.0/8", ipaddress.IPv4Network("10.0.0.0/8")),
            (ip_parse.ip_network, "10.0.0.0/255.0.0.0", ipaddress.IPv4Network("10.0.0.0/8")),
            (ip_parse.ipv4_network, "10.0.0.0/8", ipaddress.IPv4Network("10.0.0.0/8")),
            (ip_parse.ipv6_network, "2001:db8::/32", ipaddress.IPv6Network("2001:db8::/32")),
        ):
            with self.subTest(parse=parse.__name__, text=text):
                value = parse(text)
                self.assertEqual(value, expected)
                self.assertIs(type(value), type(expected))

    def test_the_ipaddress_rules_and_messages_stay(self):
        for parse, text, message in (
            (ip_parse.ip_address, "10.0.0.256", "'10.0.0.256' does not appear to be an IPv4 or IPv6 address"),
            (ip_parse.ip_address, "1", "'1' does not appear to be an IPv4 or IPv6 address"),
            (ip_parse.ip_address, " 10.0.0.1", "' 10.0.0.1' does not appear to be an IPv4 or IPv6 address"),
            (ip_parse.ipv4_address, "2001:db8::1", "Expected 4 octets in '2001:db8::1'"),
            (ip_parse.ipv6_address, "10.0.0.1", "At least 3 parts expected in '10.0.0.1'"),
            (ip_parse.ip_network, "10/8", "'10/8' does not appear to be an IPv4 or IPv6 network"),
            (ip_parse.ip_network, "10.0.0.0/ 8", "'10.0.0.0/ 8' does not appear to be an IPv4 or IPv6 network"),
            (ip_parse.ip_network, "10.0.0.5/8", "10.0.0.5/8 has host bits set"),
            (ip_parse.ipv6_network, "2001:db8::1/64", "2001:db8::1/64 has host bits set"),
        ):
            with self.subTest(parse=parse.__name__, text=text):
                with self.assertRaises(ValueError) as ctx:
                    parse(text)
                self.assertEqual(str(ctx.exception), message)

    def test_strict_false_keeps_the_network_of_host_bits(self):
        self.assertEqual(ip_parse.ip_network("10.0.0.5/8", strict=False), ipaddress.IPv4Network("10.0.0.0/8"))
        self.assertEqual(ip_parse.ipv6_network("2001:db8::1/64", strict=False), ipaddress.IPv6Network("2001:db8::/64"))

    def test_a_value_that_is_not_text_is_a_type_error(self):
        for parse, value in ((ip_parse.ip_address, 167772161), (ip_parse.ip_network, ipaddress.ip_network("::/0"))):
            with self.subTest(parse=parse.__name__), self.assertRaises(TypeError):
                parse(value)


def _unguarded(annotation: Any, metadata: tuple[Any, ...] = ()) -> bool:
    """Return whether *annotation* holds an ipaddress type without the text check of an ip_parse field type."""
    validators = [get_args(field_type)[1] for field_type in _FIELD_TYPES]
    if any(item is validator for item in metadata for validator in validators):
        return False
    if get_origin(annotation) is Annotated:
        inner, *rest = get_args(annotation)
        return _unguarded(inner, tuple(rest))
    if annotation in _IP_TYPES:
        return True
    return any(_unguarded(arg) for arg in get_args(annotation))


def _models() -> list[type[BaseModel]]:
    for module in pkgutil.walk_packages(netbox_kea.__path__, "netbox_kea."):
        if not module.name.startswith(("netbox_kea.tests", "netbox_kea.migrations")):
            importlib.import_module(module.name)
    found, pending = [], list(BaseModel.__subclasses__())
    while pending:
        model = pending.pop()
        pending.extend(model.__subclasses__())
        if model.__module__.startswith("netbox_kea.") and not model.__module__.startswith("netbox_kea.tests"):
            found.append(model)
    return found


class TestModelFieldsRefuseAScopeZone(SimpleTestCase):
    """A pydantic model parses JSON text with ipaddress, so each IP field uses an ip_parse field type."""

    def test_every_ip_field_of_a_plugin_model_uses_an_ip_parse_field_type(self):
        models = _models()
        self.assertIn(LeaseIdentity, models)
        unguarded = [
            f"{model.__module__}.{model.__qualname__}.{name}"
            for model in models
            for name, field in model.model_fields.items()
            if _unguarded(field.annotation, tuple(field.metadata))
        ]
        self.assertEqual(unguarded, [])

    def test_the_guard_finds_a_plain_ipaddress_field(self):
        self.assertTrue(_unguarded(ipaddress.IPv6Address | None))
        self.assertTrue(_unguarded(tuple[ipaddress.IPv4Network, ...]))
        self.assertFalse(_unguarded(ip_parse.IPAddressField | None))

    def test_json_text_with_a_scope_zone_is_refused(self):
        identity = LeaseIdentity(family=6, kind="address", address=ipaddress.IPv6Address("fe80::1"))
        text = identity.model_dump_json()
        self.assertEqual(LeaseIdentity.model_validate_json(text), identity)
        with self.assertRaises(ValidationError):
            LeaseIdentity.model_validate_json(text.replace('"fe80::1"', '"fe80::1%eth0"'))
