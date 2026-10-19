# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Shared test utilities for netbox_kea view tests.

Import from this module instead of duplicating scaffold code in each test file.
"""

import re
from typing import TYPE_CHECKING

import requests
from django.contrib import messages as django_messages
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext, TestContextDecorator
from django.urls import reverse
from netaddr import IPNetwork
from users.models import ObjectPermission

from netbox_kea.models import (
    DhcpIntegrationConfig,
    DisplayCacheConfig,
    IPAMOwnershipLink,
    KeaClientConfig,
    Server,
    SettingsSingleton,
    SyncConfig,
    next_confirmation_number,
)

from .kea_stub import stub_kea

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse


class SettingsRowOverride(TestContextDecorator):
    """Set fields of a settings row for a block, a test method or each test of a class, and restore them after.

    On a class it applies before each ``setUp``, as ``override_settings`` does.
    """

    def __init__(self, model: type[SettingsSingleton], **values) -> None:
        super().__init__()
        self.model, self.values = model, values
        self._saved: list[dict] = []

    def enable(self) -> None:
        row = self.model.get()
        self._saved.append({name: getattr(row, name) for name in self.values})
        self._write(self.values)

    def disable(self) -> None:
        self._write(self._saved.pop())

    def _write(self, values: dict) -> None:
        if self.model.objects.filter(pk=1).update(**values) != 1:
            raise RuntimeError(f"{self.model.__name__} has no row")


def with_kea_client_config(**values) -> SettingsRowOverride:
    """Override fields of the KeaClientConfig row, such as ``lease_query_max_unpaged_leases=0`` (no guard)."""
    return SettingsRowOverride(KeaClientConfig, **values)


def with_sync_config(**values) -> SettingsRowOverride:
    """Override fields of the SyncConfig row, such as ``stale_ip_cleanup``."""
    return SettingsRowOverride(SyncConfig, **values)


def with_dhcp_integration_config(**values) -> SettingsRowOverride:
    """Override fields of the DhcpIntegrationConfig row, such as ``enabled=False`` (the global switch off)."""
    return SettingsRowOverride(DhcpIntegrationConfig, **values)


def with_display_cache_config(**values) -> SettingsRowOverride:
    """Override fields of the DisplayCacheConfig row, such as ``configuration_ttl=0`` (no configuration cache)."""
    return SettingsRowOverride(DisplayCacheConfig, **values)


User = get_user_model()

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


_ACTIVE_TAB = re.compile(r'<a [^>]*class="nav-link active"[^>]*>\s*([^<]+?)\s*<')


def active_tabs(response) -> list[str]:
    """Return the label of each object tab that the rendered page marks active."""
    return _ACTIVE_TAB.findall(response.content.decode())


def linked_dhcp_targets(server):
    """Create one linked target of each DHCP Import Mapping kind, with object IDs that collide across models.

    The Pool and the In-Subnet Reservation sit in a Subnet that has no mapping, so deleting a linked Subnet
    reaches no other target.
    """
    from django.apps import apps
    from ipam.models import IPRange, Prefix

    from netbox_kea.models import KeaDhcpLink

    def model(name):
        return apps.get_model("netbox_dhcp", name)

    dhcp_server = model("DHCPServer").objects.create(name=server.name)
    subnets = [
        model("Subnet").objects.create(
            pk=100 + index,
            name=f"linked-subnet-{index}",
            subnet_id=100 + index,
            dhcp_server=dhcp_server,
            prefix=Prefix.objects.create(prefix=IPNetwork(f"198.18.{index}.0/24")),
        )
        for index in range(3)
    ]
    ip_range = IPRange.objects.create(
        start_address=IPNetwork("198.18.2.10/24"), end_address=IPNetwork("198.18.2.20/24")
    )
    shared_prefix = Prefix.objects.create(prefix=IPNetwork("198.18.10.0/24"))
    reservation_model = model("HostReservation")
    targets = [
        (subnets[0], {"kind": "subnet", "kea_subnet_id": 1}),
        (subnets[1], {"kind": "subnet", "kea_subnet_id": 2}),
        (
            reservation_model.objects.create(
                pk=100, name="linked-global-reservation", dhcp_server=dhcp_server, duid="00:01:02:03"
            ),
            {"kind": "reservation", "kea_identity": "duid:00:01:02:03"},
        ),
        (
            model("SharedNetwork").objects.create(
                pk=100, name="linked-shared-network", dhcp_server=dhcp_server, prefix=shared_prefix
            ),
            {"kind": "shared_network", "kea_identity": "office"},
        ),
        (
            model("Pool").objects.create(pk=100, name="linked-pool", subnet=subnets[2], ip_range=ip_range),
            {"kind": "pool", "kea_subnet_id": 3, "kea_identity": "198.18.2.10-198.18.2.20"},
        ),
        (
            reservation_model.objects.create(pk=101, name="linked-in-subnet-reservation", subnet=subnets[2], duid="04"),
            {"kind": "reservation", "kea_subnet_id": 3, "kea_identity": "duid:04"},
        ),
        (
            model("ClientClass").objects.create(pk=100, name="linked-client-class", dhcp_server=dhcp_server),
            {"kind": "client_class", "kea_identity": "voip"},
        ),
        (
            # The DHCP plugin seeds its standard Option Definitions, so this ID is out of their range.
            model("OptionDefinition").objects.create(
                pk=1000,
                name="linked-option-definition",
                family=4,
                space="dhcp4",
                code=222,
                type="uint8",
                dhcp_server=dhcp_server,
            ),
            {"kind": "option_definition", "kea_identity": "dhcp4:222"},
        ),
    ]
    return tuple(
        (target, KeaDhcpLink.objects.create(server=server, family=4, sys4_object=target, **source))
        for target, source in targets
    )


_INT_PK_RE = re.compile(r"/servers/(\d+)/")


def lease_phase(server: Server, family, subnet_prefix_lengths, max_leases: int | None = None):
    """Read the stubbed Lease Snapshot of *server* and return its address lease phase; call it inside ``stub_kea``."""
    from netbox_kea.ipam_reconciliation import LeasePhase, read_leases

    return LeasePhase(read_leases(server, family, max_leases), subnet_prefix_lengths)


def save_key_without_certificate(server: Server) -> str:
    """Save a client key without a certificate, which ``Server.clean()`` refuses, and return the expected message.

    ``.update()`` skips validation, as a bulk update or a direct database change does. ``get_client()`` then raises
    ``ValueError`` before it sends anything.
    """
    Server.objects.filter(pk=server.pk).update(client_key_path="/tls/client.key", client_cert_path="")
    return f"The Kea client settings of Server {server.name} are invalid. Check the client certificate and key."


def _make_db_server(**kwargs) -> Server:
    """Create a persisted Server fixture with sensible defaults."""
    defaults = {
        "name": "test-kea",
        "ca_url": "https://kea.example.com",
        "dhcp4": True,
        "dhcp6": True,
        "has_control_agent": True,
    }
    defaults.update(kwargs)
    return Server.objects.create(**defaults)


def ownership_link(ip, server: Server, source: str = "reservation", **fields) -> IPAMOwnershipLink:
    """Link the NetBox IP address *ip* to *source* of *server* (ADR 0006), with empty-hostname facts."""
    address = IPNetwork(str(ip.address))
    return IPAMOwnershipLink.objects.create(
        server=server,
        family=address.version,
        source=source,
        ip_address=ip,
        facts={"hostname": "", "prefix_length": address.prefixlen},
        confirmation=next_confirmation_number(),
        **fields,
    )


def prefix_ownership_link(prefix, server: Server, source: str = "lease-prefix") -> IPAMOwnershipLink:
    """Link the NetBox Prefix *prefix* to *source* of *server* (ADR 0006), with its prefix length as the facts."""
    network = IPNetwork(str(prefix.prefix))
    return IPAMOwnershipLink.objects.create(
        server=server,
        family=network.version,
        source=source,
        prefix=prefix,
        facts={"prefix_length": network.prefixlen},
        confirmation=next_confirmation_number(),
    )


_WRITE_VERBS = ("INSERT", "UPDATE", "DELETE")

# What NetBox's events pipeline received while a test routes EVENTS_PIPELINE to record_dispatched_events.
DISPATCHED_EVENTS: list = []


def record_dispatched_events(events: list) -> None:
    """Stand in for NetBox's events pipeline: record each event that a request flushes for dispatch."""
    DISPATCHED_EVENTS.extend(events)


def _refusal_receivers(signal) -> set[str]:
    """Return the label of each model whose branch refusal receiver *signal* has connected."""
    prefix = "netbox_kea.refuse_in_branch."
    return {key[0].removeprefix(prefix) for key, *_rest in signal.receivers if str(key[0]).startswith(prefix)}


def _grant(models, actions, *, user=None, group=None, constraints=None, enabled=True) -> ObjectPermission:
    """Create a real ObjectPermission for *models* and *actions*, and give it to *user* or *group*."""
    permission = ObjectPermission.objects.create(
        name=f"grant-{ObjectPermission.objects.count()}",
        actions=list(actions),
        constraints=constraints,
        enabled=enabled,
    )
    permission.object_types.add(*(ContentType.objects.get_for_model(model) for model in models))
    if user is not None:
        permission.users.add(user)
    if group is not None:
        permission.groups.add(group)
    return permission


def _sync_page_urls(server: Server) -> tuple[str, str, str]:
    """Return the pages that read SyncConfig: the Settings page, the Sync Jobs page and the Server's Sync tab."""
    return (
        reverse("plugins:netbox_kea:settings"),
        reverse("plugins:netbox_kea:sync_jobs"),
        reverse("plugins:netbox_kea:server_sync_status", args=[server.pk]),
    )


def _get_with_writes(client: Client, url: str) -> tuple["_MonkeyPatchedWSGIResponse", list[str]]:
    """GET ``url`` and return the response with each INSERT, UPDATE or DELETE statement it ran."""
    with CaptureQueriesContext(connection) as captured:
        response = client.get(url)
    writes = [
        query["sql"] for query in captured.captured_queries if query["sql"].lstrip().upper().startswith(_WRITE_VERBS)
    ]
    return response, writes


def _page_data(response) -> dict[str, str]:
    """Return the data that a browser posts for the form of *response*: each field that the page rendered."""
    form, page = response.context["form"], response.content.decode()
    return {
        name: "" if form[name].value() is None else str(form[name].value())
        for name in form.fields
        if f'name="{form[name].html_name}"' in page
    }


# ─────────────────────────────────────────────────────────────────────────────
# Shared base class
# ─────────────────────────────────────────────────────────────────────────────


class _ViewTestBase(TestCase):
    """Creates a superuser and a single Server for use in all view tests. The lease-query guard is off."""

    @classmethod
    def setUpTestData(cls):
        # Class level, so a class or method override of a subclass applies after it.
        KeaClientConfig.objects.filter(pk=1).update(lease_query_max_unpaged_leases=0)

    def setUp(self):
        self.user = User.objects.create_superuser(
            username="kea_testuser",
            email="kea_test@example.com",
            password="kea_testpass",
        )
        self.client.force_login(self.user)
        self.server = _make_db_server()

    def _fresh_client(self) -> None:
        """Log in with a new test client, so no message of an earlier request is still stored."""
        self.client = Client()
        self.client.force_login(self.user)

    def _assert_no_none_pk_redirect(self, response):
        """Assert that a redirect URL never contains the string ``None`` as a pk."""
        if hasattr(response, "url"):
            self.assertNotIn(
                "servers/None",
                response.url,
                f"Redirect went to bad URL: {response.url}",
            )

    def _assert_help_names_the_read_modify_write(self, response):
        """Assert that the page names the four commands of the read-modify-write once, in their order."""
        chain = " → ".join(
            f"<code>{command}</code>" for command in ("config-get", "config-test", "config-set", "config-write")
        )
        self.assertEqual(re.sub(r"\s+", " ", response.content.decode()).count(chain), 1)

    def _assert_redirect_to_integer_pk(self, response):
        """Assert that a redirect URL contains an integer server pk."""
        self._assert_no_none_pk_redirect(response)
        self.assertIsNotNone(
            _INT_PK_RE.search(response.url),
            f"Expected /servers/<int>/ in redirect URL, got: {response.url}",
        )

    def _make_request(self):
        """Return a RequestFactory request pre-loaded with a FallbackStorage message backend."""
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.get("/")
        request.user = self.user
        request.session = "session"
        storage = FallbackStorage(request)
        request._messages = storage
        return request

    @staticmethod
    def _call_version(call_args):
        """Extract the 'version' argument from a mock call_args (kwargs or positional)."""
        kwargs = call_args.kwargs or call_args[1]
        args = call_args.args or call_args[0]
        return kwargs.get("version") or (args[0] if args else None)


_UNCONFIRMED = "Kea did not confirm the change. Check the server configuration before retrying."
#: The message of an unconfirmed Runtime Change, before its diagnostics (ADR 0011).
UNCONFIRMED_RUNTIME = (
    "Kea did not confirm the change. Check the Server before you try again. NetBox recorded nothing for this change."
)
#: The message of a change whose Kea client cannot be built.
INVALID_SERVER_SETTINGS = (
    "The change was not sent to Kea, because the Server settings are not valid. "
    "NetBox could not build a Kea client from the Server connection settings."
)


def _read_modify_write_cases(confirmed: str) -> tuple:
    """Each outcome and rejection of a read-modify-write view: (label, Kea replies, Server fields, the message)."""
    lost = requests.ReadTimeout("read timed out")
    restart = "It is live, but it may not survive a Kea restart, because Kea did not save it to disk."
    return (
        ("applied, persisted", {}, {}, (django_messages.SUCCESS, confirmed)),
        ("applied, not requested", {}, {"persist_config": False}, (django_messages.SUCCESS, confirmed)),
        (
            "applied, failed",
            {"config-write": {"result": 1, "text": "Unable to open file"}},
            {},
            (django_messages.WARNING, f"{confirmed} {restart} config-write failed: Unable to open file"),
        ),
        (
            "unknown, persisted",
            {"config-set": lost},
            {},
            (django_messages.WARNING, f"{_UNCONFIRMED} Kea's reply to the change was lost or unreadable."),
        ),
        (
            "unknown, failed",
            {"config-set": lost, "config-write": lost},
            {},
            (
                django_messages.WARNING,
                (
                    f"{_UNCONFIRMED} Kea also could not save its running configuration to disk. "
                    "Kea's reply to the change was lost or unreadable. The reply to config-write was lost or unreadable."
                ),
            ),
        ),
        (
            "unknown, not requested",
            {"config-set": {"result": 1, "text": "hook initialization failed"}},
            {"persist_config": False},
            (django_messages.WARNING, f"{_UNCONFIRMED} Kea replied: hook initialization failed"),
        ),
        (
            "config-test rejected",
            {"config-test": {"result": 1, "text": "subnet overlaps"}},
            {},
            (
                django_messages.ERROR,
                "Kea's config-test rejected the change, so it was not applied. Kea replied: subnet overlaps",
            ),
        ),
        (
            "not sent",
            {"config-test": requests.ConnectionError("https://kea-internal.example.invalid refused")},
            {},
            (
                django_messages.ERROR,
                "The change was not sent to Kea. Kea did not return a usable reply to config-test.",
            ),
        ),
        (
            "invalid client configuration",
            {},
            {"client_cert_path": "/etc/kea/client.pem"},
            (
                django_messages.ERROR,
                (
                    "The change was not sent to Kea, because the Server settings are not valid. "
                    "NetBox could not build a Kea client from the Server connection settings."
                ),
            ),
        ),
    )


class _ReadModifyWriteMessages(_ViewTestBase):
    """One HTTP POST per Configuration Change outcome and per rejection, for a read-modify-write view."""

    def _assert_one_message_per_case(self, url: str, data: dict, responses: dict, confirmed: str) -> None:
        original = {"persist_config": self.server.persist_config, "client_cert_path": self.server.client_cert_path}
        ok = {"result": 0}
        for label, replies, fields, expected in _read_modify_write_cases(confirmed):
            with self.subTest(label):
                self._fresh_client()
                for field, value in {**original, **fields}.items():
                    setattr(self.server, field, value)
                self.server.save()
                base = {"config-test": ok, "config-set": ok, "config-write": ok, **responses}
                with stub_kea({**base, **replies}) as kea:
                    response = self.client.post(url, data)
                self.assertEqual(response.status_code, 302)
                sent = [
                    (message.level, str(message)) for message in django_messages.get_messages(response.wsgi_request)
                ]
                self.assertEqual(sent, [expected])
                applied = label.startswith(("applied", "unknown"))
                self.assertEqual("config-set" in kea.commands(), applied)
                self.assertEqual("config-write" in kea.commands(), applied and "not requested" not in label)
