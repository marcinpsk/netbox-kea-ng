# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The fields of the Subnet and Shared Network forms: the writers, and the round trip through the real parser.

The writers edit a raw Kea entry. The round trip parses the written entry with ``server_configuration`` and shows it
with the reader, so the reader and the writers cannot disagree. The view and ``config_write`` tests cover the same
fields end to end.
"""

import copy
import ipaddress
import json
from dataclasses import fields as dataclass_fields
from dataclasses import replace

from django.test import SimpleTestCase, TestCase

from netbox_kea import server_configuration
from netbox_kea.constants import Family
from netbox_kea.kea import CandidateConfiguration, MalformedConfiguration, SubnetDefinition
from netbox_kea.managed_fields import (
    SharedNetworkEdit,
    SubnetEdit,
    SubnetFields,
    new_subnet,
    shown_shared_network,
    shown_subnet,
    write_shared_network,
    write_subnet,
)

from .utils import _make_db_server

_FAMILIES: tuple[Family, ...] = (4, 6)
_NO_FIELDS = SubnetFields(pools=(), gateway="", dns_servers=(), ntp_servers=(), ddns_qualifying_suffix="")
# Every managed field empty: a form-managed DHCP Option is removed, and every lifetime keeps its live value.
_BLANK = SubnetEdit(
    fields=_NO_FIELDS,
    valid_lifetime=None,
    min_valid_lifetime=None,
    max_valid_lifetime=None,
    renew_timer=None,
    rebind_timer=None,
)
_FORM_FIELDS = frozenset(field.name for field in dataclass_fields(SubnetFields))


def _edit(**values) -> SubnetEdit:
    """Return the blank edit with *values*, given by the name of a form field, a lifetime or a timer."""
    fields = {name: value for name, value in values.items() if name in _FORM_FIELDS}
    lifetimes = {name: value for name, value in values.items() if name not in _FORM_FIELDS}
    return replace(_BLANK, fields=replace(_BLANK.fields, **fields), **lifetimes)


def _written(live: dict, version: Family = 4, **fields) -> dict:
    """Return a copy of the Subnet *live* that ``write_subnet`` edited with the form *fields*.

    The form showed the values that the reader gives for *live*.
    """
    entry = copy.deepcopy(live)
    write_subnet(entry, version, _edit(**fields), shown=_shown_subnet(live, version))
    return entry


def _shown_subnet(entry: dict, version: Family) -> SubnetEdit:
    """Return the values that the edit form shows for the raw Subnet *entry*, through the real parser."""
    network = ipaddress.ip_network(entry["subnet"], strict=False)
    definition = SubnetDefinition(version, entry["id"], network, json.dumps(entry, sort_keys=True))
    configuration = server_configuration.definition_configuration(definition)
    assert configuration is not None, "the parser refused the Subnet"
    shown = shown_subnet(configuration, version)
    assert shown is not None, "the edit form cannot show the Subnet"
    return shown


class SubnetWriterTests(SimpleTestCase):
    """``write_subnet`` sets the form fields on the Subnet that Kea returned, and keeps every other key."""

    def _options(self, existing: list, version: Family = 4, **fields) -> list:
        subnet = "10.0.0.0/24" if version == 4 else "2001:db8::/48"
        return _written({"id": 42, "subnet": subnet, "option-data": existing}, version, **fields)["option-data"]

    def test_the_writer_keeps_every_field_that_the_form_does_not_manage(self):
        live = {
            "id": 42,
            "subnet": "10.0.0.0/24",
            "relay": {"ip-addresses": ["10.0.0.254"]},
            "allocator": "random",
            "client-class": "premium",
            "pools": [{"pool": "10.0.0.50-10.0.0.99", "option-data": []}],
            "option-data": [{"name": "routers", "data": "10.0.0.1"}, {"name": "domain-name", "data": "example.org"}],
            "valid-lifetime": 7200,
            "ddns-qualifying-suffix": "old.example.org.",
        }
        written = _written(live, pools=("10.0.0.100-10.0.0.110",), gateway="10.0.0.2", ddns_qualifying_suffix="")
        self.assertEqual(
            written,
            {
                "id": 42,
                "subnet": "10.0.0.0/24",
                "relay": {"ip-addresses": ["10.0.0.254"]},
                "allocator": "random",
                "client-class": "premium",
                "pools": [{"pool": "10.0.0.100-10.0.0.110"}],
                "option-data": [
                    {"name": "routers", "data": "10.0.0.2"},
                    {"name": "domain-name", "data": "example.org"},
                ],
                "valid-lifetime": 7200,
            },
        )

    def test_a_kept_pool_keeps_its_pool_level_keys(self):
        live = {
            "id": 42,
            "subnet": "10.0.0.0/24",
            "pools": [{"pool": "10.0.0.50 - 10.0.0.99", "client-class": "lab"}, {"pool": "10.0.0.100-10.0.0.110"}],
        }
        written = _written(live, pools=("10.0.0.50-10.0.0.99", "10.0.0.120-10.0.0.130"))
        self.assertEqual(
            written["pools"],
            [{"pool": "10.0.0.50-10.0.0.99", "client-class": "lab"}, {"pool": "10.0.0.120-10.0.0.130"}],
        )

    def test_a_lifetime_or_timer_is_set_with_the_subnet_parameter_name_and_none_keeps_it(self):
        live = {
            "id": 42,
            "subnet": "10.0.0.0/24",
            "valid-lifetime": 3600,
            "min-valid-lifetime": 1800,
            "max-valid-lifetime": 7200,
            "renew-timer": 900,
            "rebind-timer": 1500,
        }
        kept = _written(live)
        self.assertEqual({key: kept[key] for key in live}, live)
        values = {
            "valid_lifetime": 4000,
            "min_valid_lifetime": 2000,
            "max_valid_lifetime": 8000,
            "renew_timer": 600,
            "rebind_timer": 900,
        }
        written = _written(live, **values)
        self.assertEqual(
            {key: written[key] for key in live},
            {
                "id": 42,
                "subnet": "10.0.0.0/24",
                "valid-lifetime": 4000,
                "min-valid-lifetime": 2000,
                "max-valid-lifetime": 8000,
                "renew-timer": 600,
                "rebind-timer": 900,
            },
        )
        # Kea refuses the lease field valid-lft in a Subnet as a spurious parameter.
        self.assertFalse({"valid-lft", "min-valid-lft", "max-valid-lft"} & set(written))

    def test_a_ddns_suffix_is_set_or_removed(self):
        live = {"id": 42, "subnet": "10.0.0.0/24", "ddns-qualifying-suffix": "old.example.org."}
        self.assertEqual(
            _written(live, ddns_qualifying_suffix="new.example.org.")["ddns-qualifying-suffix"], "new.example.org."
        )
        self.assertNotIn("ddns-qualifying-suffix", _written(live))

    def test_the_writer_keeps_the_cidr_text_that_kea_declares(self):
        live = {"id": 7, "subnet": "2001:0DB8:0000:0000::5/64"}
        self.assertEqual(_written(live, version=6)["subnet"], "2001:0DB8:0000:0000::5/64")

    def test_the_values_that_the_form_showed_keep_the_options_and_empty_fields_remove_them(self):
        existing = [
            {"code": 3, "data": "198.18.0.1", "never-send": True},
            {"code": 6, "data": "198.18.0.53", "never-send": True},
            {"code": 42, "data": "198.18.0.123", "never-send": True},
        ]
        shown = {"gateway": "198.18.0.1", "dns_servers": ("198.18.0.53",), "ntp_servers": ("198.18.0.123",)}
        self.assertEqual(self._options(existing, **shown), existing)
        self.assertEqual(self._options(existing), [])

    def test_code_only_and_suppression_options_round_trip(self):
        """A DNS option written by code is replaced, not duplicated; a never-send entry survives an empty field."""
        existing = [
            {"code": 6, "data": "10.0.0.53", "always-send": True},
            {"code": 42, "never-send": True},
            {"name": "domain-name-servers", "space": "vendor-4491", "data": "10.0.0.99"},
        ]
        self.assertEqual(
            self._options(existing, dns_servers=("10.0.0.53",)),
            [
                {"code": 6, "data": "10.0.0.53", "always-send": True},
                {"code": 42, "never-send": True},
                {"name": "domain-name-servers", "space": "vendor-4491", "data": "10.0.0.99"},
            ],
        )

    def test_other_family_option_names_remain_unmanaged(self):
        existing = [{"name": "dns-servers", "data": "192.0.2.53"}, {"name": "sntp-servers", "data": "192.0.2.123"}]
        self.assertEqual(
            self._options(existing, dns_servers=("198.18.0.53",)),
            [*existing, {"name": "domain-name-servers", "data": "198.18.0.53"}],
        )

    def test_equivalent_csv_preserves_encoding_flags(self):
        for data in ("198.18.0.53,198.18.0.54", "198.18.0.53, 198.18.0.54"):
            with self.subTest(data=data):
                existing = [{"code": 6, "data": data, "csv-format": True, "never-send": True}]
                self.assertEqual(self._options(existing, dns_servers=("198.18.0.53", "198.18.0.54")), existing)

    def test_class_tagged_entries_are_not_managed_by_the_form(self):
        """Kea allows one entry per class tag; the form edits only the untagged default."""
        tagged = [
            {"code": 6, "data": "10.0.1.53", "client-classes": ["class-a"]},
            {"code": 6, "data": "10.0.2.53", "client-classes": ["class-b"]},
            {"name": "domain-name-servers", "data": "10.0.0.53"},
        ]
        self.assertEqual(
            self._options(tagged, dns_servers=("10.0.0.54",)),
            [*tagged[:2], {"name": "domain-name-servers", "data": "10.0.0.54"}],
        )

    def test_an_empty_field_keeps_a_value_that_the_form_cannot_show(self):
        """The form cannot show binary data or a router list, so an empty field must not delete them."""
        for existing in (
            [{"code": 6, "data": "0A000035", "csv-format": False}],
            [{"code": 3, "data": "10.0.0.1, 10.0.0.2"}],
        ):
            with self.subTest(existing=existing):
                self.assertEqual(self._options(existing), existing)

    def test_a_changed_value_drops_the_old_encoding_flag(self):
        """Form text is CSV, so csv-format false no longer describes the new value."""
        existing = [{"code": 6, "data": "0A000035", "csv-format": False}]
        self.assertEqual(self._options(existing, dns_servers=("10.0.0.53",)), [{"code": 6, "data": "10.0.0.53"}])

    def test_a_dhcpv6_subnet_replaces_its_dns_option_and_keeps_the_others(self):
        existing = [
            {"name": "dns-servers", "data": "2001:db8::53"},
            {"name": "domain-search", "data": "example.com"},
        ]
        self.assertEqual(
            self._options(existing, version=6, dns_servers=("2001:db8::54",)),
            [{"name": "dns-servers", "data": "2001:db8::54"}, {"name": "domain-search", "data": "example.com"}],
        )

    def test_a_live_pool_entry_that_the_writer_cannot_keep_raises(self):
        """The update replaces the Pool list, so a skipped live entry would be deleted from Kea."""
        for label, entry in (
            ("not an object", "10.0.0.50-10.0.0.99"),
            ("no range", {"pool": "not a pool"}),
            ("outside the Subnet", {"pool": "10.0.1.50-10.0.1.99"}),
        ):
            live = {"id": 42, "subnet": "10.0.0.0/24", "pools": [{"pool": "10.0.0.10-10.0.0.20"}, entry]}
            # The reader cannot show this Subnet, so the shown values are given.
            with self.subTest(label), self.assertRaises(MalformedConfiguration):
                write_subnet(live, 4, _edit(pools=("10.0.0.10-10.0.0.20",)), shown=_BLANK)

    def test_an_unchanged_field_keeps_its_live_text_and_a_changed_field_is_written(self):
        live = {
            "id": 42,
            "subnet": "10.0.0.0/24",
            "pools": [{"pool": "10.0.0.10 - 10.0.0.20"}],
            "option-data": [{"name": "routers", "data": " 10.0.0.1"}, {"code": 6, "data": "192.0.2.53 ,192.0.2.54"}],
            "ddns-qualifying-suffix": " example.org. ",
            "valid-lifetime": 3600,
        }
        shown = _shown_subnet(live, 4)
        unchanged = copy.deepcopy(live)
        write_subnet(unchanged, 4, replace(shown, valid_lifetime=None), shown=shown)
        self.assertEqual(unchanged, live)
        changed = copy.deepcopy(live)
        fields = replace(shown.fields, pools=("10.0.0.30-10.0.0.40",), ddns_qualifying_suffix="new.example.org.")
        write_subnet(changed, 4, replace(shown, fields=fields, valid_lifetime=7200), shown=shown)
        self.assertEqual(
            changed,
            {
                **live,
                "pools": [{"pool": "10.0.0.30-10.0.0.40"}],
                "ddns-qualifying-suffix": "new.example.org.",
                "valid-lifetime": 7200,
            },
        )


class NewSubnetTests(SimpleTestCase):
    """``new_subnet`` writes the fields of the add form on a new Subnet entry. A field without a value adds no key."""

    def test_a_subnet_without_fields_holds_only_its_cidr_and_id(self):
        self.assertEqual(new_subnet(4, 10, "10.99.0.0/24", _NO_FIELDS), {"subnet": "10.99.0.0/24", "id": 10})

    def test_a_dhcpv6_subnet_carries_no_gateway(self):
        fields = replace(_NO_FIELDS, gateway="2001:db8::1")
        self.assertEqual(new_subnet(6, 20, "2001:db8:99::/48", fields), {"subnet": "2001:db8:99::/48", "id": 20})


# A Subnet with every managed field set, and with keys that no form manages.
_LIVE_SUBNET = {
    4: {
        "id": 20,
        "subnet": "10.0.20.0/24",
        "pools": [{"pool": "10.0.20.10-10.0.20.20", "client-class": "lab"}],
        "option-data": [{"name": "routers", "data": "10.0.20.1"}, {"name": "domain-name", "data": "example.org"}],
        "relay": {"ip-addresses": ["198.51.100.1"]},
        "valid-lifetime": 3600,
        "ddns-qualifying-suffix": "old.example.org.",
    },
    6: {
        "id": 20,
        "subnet": "2001:db8:20::/64",
        "pools": [{"pool": "2001:db8:20::100-2001:db8:20::1ff"}],
        "option-data": [
            {"name": "dns-servers", "data": "2001:db8::53"},
            {"name": "domain-search", "data": "example.org"},
        ],
        "valid-lifetime": 3600,
    },
}
_SUBNET_EDITS = {
    4: SubnetEdit(
        fields=SubnetFields(
            pools=("10.0.20.10-10.0.20.20", "10.0.20.100-10.0.20.110"),
            gateway="10.0.20.254",
            dns_servers=("192.0.2.53", "192.0.2.54"),
            ntp_servers=("192.0.2.123",),
            ddns_qualifying_suffix="new.example.org.",
        ),
        valid_lifetime=7200,
        min_valid_lifetime=3600,
        max_valid_lifetime=14400,
        renew_timer=1800,
        rebind_timer=3150,
    ),
    6: SubnetEdit(
        fields=SubnetFields(
            pools=("2001:db8:20::200-2001:db8:20::2ff",),
            gateway="",
            dns_servers=("2001:db8::54",),
            ntp_servers=("2001:db8::123",),
            ddns_qualifying_suffix="v6.example.org.",
        ),
        valid_lifetime=7200,
        min_valid_lifetime=3600,
        max_valid_lifetime=14400,
        renew_timer=1800,
        rebind_timer=3150,
    ),
}


class SubnetRoundTripTests(SimpleTestCase):
    """A Subnet written with an edit, parsed by ``server_configuration`` and shown, gives the edit back."""

    def test_the_written_subnet_shows_the_edit(self):
        for version in _FAMILIES:
            blank = replace(_BLANK, **dict.fromkeys(("valid_lifetime", "renew_timer"), 900))
            blank_live = {key: value for key, value in _LIVE_SUBNET[version].items() if key != "valid-lifetime"}
            for label, live, edit in (
                ("every field", _LIVE_SUBNET[version], _SUBNET_EDITS[version]),
                ("empty", blank_live, blank),
            ):
                with self.subTest(version=version, edit=label):
                    entry = copy.deepcopy(live)
                    write_subnet(entry, version, edit, shown=_shown_subnet(live, version))
                    self.assertEqual(_shown_subnet(entry, version), edit)


_LIVE_NETWORK = {
    4: {
        "name": "office",
        "subnet4": [],
        "user-context": {"comment": "Office", "owner": "noc"},
        "interface": "eth0",
        "relay": {"ip-addresses": ["192.0.2.1"]},
        "option-data": [{"name": "domain-name-servers", "data": "192.0.2.53"}, {"name": "domain-name", "data": "x"}],
        "valid-lifetime": 7200,
    },
    6: {
        "name": "office",
        "subnet6": [],
        "relay": {"ip-addresses": ["2001:db8::1"]},
        "option-data": [{"name": "sntp-servers", "data": "2001:db8::123"}],
    },
}
_NETWORK_EDITS = {
    4: SharedNetworkEdit("Office LAN", "eth1", ("192.0.2.2", "192.0.2.3"), ("192.0.2.54",), ("192.0.2.123",)),
    6: SharedNetworkEdit("Lab", "eth2", ("2001:db8::2",), ("2001:db8::53", "2001:db8::54"), ()),
}


class SharedNetworkRoundTripTests(TestCase):
    """A Shared Network written with an edit, parsed by ``server_configuration`` and shown, gives the edit back."""

    def setUp(self):
        self.server = _make_db_server()

    def _shown(self, candidate: CandidateConfiguration) -> SharedNetworkEdit | None:
        snapshot = server_configuration.candidate_snapshot(self.server, candidate)
        network = server_configuration.editable_shared_network(snapshot, "office")
        assert network is not None, "the parser refused the written Shared Network"
        return shown_shared_network(network, candidate.family)

    def test_the_written_shared_network_shows_the_edit(self):
        for version in _FAMILIES:
            for label, edit in (
                ("every field", _NETWORK_EDITS[version]),
                ("empty", SharedNetworkEdit("", "", (), (), ())),
            ):
                with self.subTest(version=version, edit=label):
                    daemon = {"shared-networks": [copy.deepcopy(_LIVE_NETWORK[version])]}
                    candidate = CandidateConfiguration(version, {f"Dhcp{version}": daemon})
                    shown = self._shown(candidate)
                    write_shared_network(candidate.shared_network("office"), version, edit, shown=shown)
                    self.assertEqual(self._shown(candidate), edit)


class SharedNetworkWriterTests(SimpleTestCase):
    """``write_shared_network`` refuses a live entry that it cannot keep or replace safely."""

    _SHOWN = SharedNetworkEdit("", "", (), (), ())

    def test_a_live_entry_that_the_writer_cannot_keep_raises(self):
        edit = SharedNetworkEdit("", "", ("192.0.2.1",), (), ())
        for label, live in (
            ("user-context not an object", {"name": "office", "user-context": "text"}),
            ("option-data not a list", {"name": "office", "option-data": None}),
            ("two entries for one form field", {"name": "office", "option-data": [{"code": 6}, {"code": 6}]}),
            ("relay not an object", {"name": "office", "relay": "192.0.2.9"}),
        ):
            with self.subTest(label), self.assertRaises(MalformedConfiguration):
                write_shared_network(live, 4, edit, shown=self._SHOWN)
