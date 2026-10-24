# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for netbox_kea.models — Server model validation and client factory.

All Kea HTTP calls are mocked; these tests require no running services.
"""

import importlib
import os
import tempfile
import uuid
from io import StringIO
from ipaddress import ip_network
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

from django.apps import apps
from django.conf import settings
from django.contrib import messages as django_messages
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.state import ProjectState
from django.db.models import ProtectedError
from django.test import RequestFactory, SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from netbox.models import NetBoxModel

import netbox_kea
from netbox_kea.kea import KeaClient, KeaCommand
from netbox_kea.models import (
    DhcpIntegrationConfig,
    DisplayCacheConfig,
    IPAMOwnershipLink,
    IPAMOwnershipSource,
    KeaClientConfig,
    KeaDhcpLink,
    Server,
    SyncConfig,
    next_confirmation_number,
)
from netbox_kea.reservations import MAX_IDENTITY_LENGTH
from netbox_kea.tests.kea_stub import record_transport, stub_kea
from netbox_kea.tests.utils import _make_db_server, with_kea_client_config

_SEED = importlib.import_module("netbox_kea.migrations.0018_seed_syncconfig")

_VERSION_OK = {"result": 0, "arguments": {"version": "2.5.0"}}


def _make_server(**kwargs) -> Server:
    """Return an unsaved Server instance with sensible defaults."""
    defaults = {
        "name": "test-server",
        "ca_url": "http://kea:8000",
        "dhcp4": True,
        "dhcp6": True,
    }
    defaults.update(kwargs)
    return Server(**defaults)


class TestContentTypeCleanup(TestCase):
    def test_remove_stale_contenttypes_deletes_an_obsolete_model(self):
        stale = ContentType.objects.create(app_label="netbox_kea", model="obsolete_dhcp_mapping")
        current = ContentType.objects.get_for_model(Server)

        call_command("remove_stale_contenttypes", interactive=False, stdout=StringIO())

        self.assertFalse(ContentType.objects.filter(pk=stale.pk).exists())
        self.assertTrue(ContentType.objects.filter(pk=current.pk).exists())


class TestServerStr(SimpleTestCase):
    """Tests for Server.__str__."""

    def test_str_returns_name(self):
        server = _make_server(name="my-kea")
        self.assertEqual(str(server), "my-kea")


class TestServerGetClient(TestCase):
    """Tests for Server.get_client() — URL selection logic."""

    def test_no_version_uses_ca_url(self):
        server = _make_server()
        client = server.get_client()
        self.assertIsInstance(client, KeaClient)
        self.assertEqual(client.url, "http://kea:8000")

    def test_version4_falls_back_to_ca_url(self):
        server = _make_server(dhcp4_url=None)
        client = server.get_client(version=4)
        self.assertEqual(client.url, "http://kea:8000")

    def test_version4_uses_dhcp4_url_override(self):
        server = _make_server(dhcp4_url="http://kea-v4:8001")
        client = server.get_client(version=4)
        self.assertEqual(client.url, "http://kea-v4:8001")

    def test_version6_falls_back_to_ca_url(self):
        server = _make_server(dhcp6_url=None)
        client = server.get_client(version=6)
        self.assertEqual(client.url, "http://kea:8000")

    def test_version6_uses_dhcp6_url_override(self):
        server = _make_server(dhcp6_url="http://kea-v6:8002")
        client = server.get_client(version=6)
        self.assertEqual(client.url, "http://kea-v6:8002")

    def test_dual_url_v4_and_v6_independent(self):
        server = _make_server(dhcp4_url="http://v4:1", dhcp6_url="http://v6:2")
        self.assertEqual(server.get_client(version=4).url, "http://v4:1")
        self.assertEqual(server.get_client(version=6).url, "http://v6:2")

    def test_get_client_passes_credentials(self):
        server = _make_server(ca_username="admin", ca_password="secret")
        client = server.get_client()
        self.assertIsNotNone(client._session.auth)

    def _sent_tls(self, server: Server) -> dict:
        """Send version-get with an environment CA bundle; return the TLS settings that reached the transport."""
        client = server.get_client(version=4)
        transport = record_transport(client, [_VERSION_OK])
        with patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": "/env/bundle.pem"}):
            client.command(KeaCommand.VERSION_GET, 4)
        return transport.sent[-1]

    def test_get_client_ssl_verify_false(self):
        sent = self._sent_tls(_make_server(ca_url="https://kea:8000", ssl_verify=False))
        self.assertIs(sent["verify"], False)

    def test_get_client_ca_file_path(self):
        sent = self._sent_tls(_make_server(ca_url="https://kea:8000", ca_file_path="/certs/ca.pem", ssl_verify=True))
        self.assertEqual(sent["verify"], "/certs/ca.pem")

    def test_get_client_ssl_verify_uses_the_environment_bundle(self):
        sent = self._sent_tls(_make_server(ca_url="https://kea:8000", ssl_verify=True))
        self.assertEqual(sent["verify"], "/env/bundle.pem")

    def test_get_client_cert_key_pair(self):
        server = _make_server(ca_url="https://kea:8000", client_cert_path="/cert.pem", client_key_path="/key.pem")
        sent = self._sent_tls(server)
        self.assertEqual(sent["cert"], ("/cert.pem", "/key.pem"))

    def test_get_client_uses_configured_timeout(self):
        """The default timeout of the KeaClientConfig row."""
        server = _make_server()
        client = server.get_client()
        self.assertEqual(client.timeout, 30)

    @with_kea_client_config(kea_timeout=5)
    def test_get_client_custom_timeout(self):
        server = _make_server()
        client = server.get_client()
        self.assertEqual(client.timeout, 5)

    @with_kea_client_config(lease_query_max_unpaged_leases=250)
    def test_get_client_uses_configured_unpaged_lease_limit(self):
        client = _make_server().get_client()
        self.assertEqual(client.max_unpaged_leases, 250)

    @with_kea_client_config(lease_query_max_unpaged_leases=0)
    def test_get_client_can_explicitly_disable_unpaged_lease_guard(self):
        client = _make_server().get_client()
        self.assertIsNone(client.max_unpaged_leases)

    def test_v4_uses_dhcp4_credentials_when_set(self):
        """When dhcp4_url and dhcp4_username/dhcp4_password are set, v4 client uses them."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp4_url="http://kea-v4:8001",
            dhcp4_username="v4-user",
            dhcp4_password="v4-pass",
        )
        client = server.get_client(version=4)
        self.assertIsNotNone(client._session.auth)
        self.assertEqual(client._session.auth.username, "v4-user")
        self.assertEqual(client._session.auth.password, "v4-pass")

    def test_v4_no_dhcp4_url_always_uses_ca_credentials(self):
        """When dhcp4_url is not set, v4 client always uses CA credentials even if per-protocol creds exist."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp4_username="v4-user",
            dhcp4_password="v4-pass",
        )
        client = server.get_client(version=4)
        self.assertIsNotNone(client._session.auth)
        self.assertEqual(client._session.auth.username, "ca-user")
        self.assertEqual(client._session.auth.password, "ca-pass")

    def test_v4_falls_back_to_ca_credentials_when_v4_creds_empty(self):
        """When dhcp4_url is set but dhcp4 creds are blank, v4 client falls back to CA creds."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp4_url="http://kea-v4:8001",
            dhcp4_username="",
            dhcp4_password="",
        )
        client = server.get_client(version=4)
        self.assertIsNotNone(client._session.auth)
        self.assertEqual(client._session.auth.username, "ca-user")
        self.assertEqual(client._session.auth.password, "ca-pass")

    def test_v6_uses_dhcp6_credentials_when_set(self):
        """When dhcp6_url and dhcp6_username/dhcp6_password are set, v6 client uses them."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp6_url="http://kea-v6:8002",
            dhcp6_username="v6-user",
            dhcp6_password="v6-pass",
        )
        client = server.get_client(version=6)
        self.assertIsNotNone(client._session.auth)
        self.assertEqual(client._session.auth.username, "v6-user")
        self.assertEqual(client._session.auth.password, "v6-pass")

    def test_v6_falls_back_to_ca_credentials_when_v6_creds_empty(self):
        """When dhcp6_url is set but dhcp6 creds are blank, v6 client falls back to CA creds."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp6_url="http://kea-v6:8002",
            dhcp6_username="",
            dhcp6_password="",
        )
        client = server.get_client(version=6)
        self.assertIsNotNone(client._session.auth)
        self.assertEqual(client._session.auth.username, "ca-user")
        self.assertEqual(client._session.auth.password, "ca-pass")

    def test_no_version_uses_ca_credentials(self):
        """When version=None, always use CA credentials."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp4_url="http://kea-v4:8001",
            dhcp4_username="v4-user",
            dhcp4_password="v4-pass",
        )
        client = server.get_client()
        self.assertEqual(client._session.auth.username, "ca-user")

    def test_v4_partial_override_falls_back_per_field(self):
        """When dhcp4_url set and only dhcp4_username provided, password falls back to ca_password."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp4_url="http://kea-v4:8001",
            dhcp4_username="v4-user",
            dhcp4_password="",
        )
        client = server.get_client(version=4)
        self.assertIsNotNone(client._session.auth)
        self.assertEqual(client._session.auth.username, "v4-user")
        self.assertEqual(client._session.auth.password, "ca-pass")

    def test_v6_partial_override_falls_back_per_field(self):
        """When dhcp6_url set and only dhcp6_password provided, username falls back to ca_username."""
        server = _make_server(
            ca_username="ca-user",
            ca_password="ca-pass",
            dhcp6_url="http://kea-v6:8002",
            dhcp6_username="",
            dhcp6_password="v6-pass",
        )
        client = server.get_client(version=6)
        self.assertIsNotNone(client._session.auth)
        self.assertEqual(client._session.auth.username, "ca-user")
        self.assertEqual(client._session.auth.password, "v6-pass")


class TestGetClientSendService(TestCase):
    """get_client() decides whether ``service`` is sent, and command() honours it end-to-end.

    ``has_control_agent`` is the single source of truth: a Control Agent routes by
    ``service`` (send it); a direct DHCP-daemon connection must omit it (Kea 3.2.0+
    rejects a mismatched service). This holds regardless of *which* URL is used —
    a protocol-specific ``dhcp{4,6}_url`` may itself point at a per-protocol Control
    Agent (before Kea 3.1.8) or a bare daemon socket (Kea 3.0+).
    """

    def _sent_body(self, client):
        """Send lease4-get through the real client against the HTTP-boundary stub; return the sent body."""
        with stub_kea({"lease4-get": {"result": 0, "arguments": {}}}) as kea:
            client.command(KeaCommand.LEASE4_GET, 4)
        return kea.bodies("lease4-get")[0]

    def test_control_agent_sends_service(self):
        # ca_url + has_control_agent → CA endpoint → service is included.
        client = _make_server(ca_url="https://kea.example.com", has_control_agent=True).get_client(version=4)
        self.assertTrue(client.send_service)
        self.assertEqual(self._sent_body(client)["service"], ["dhcp4"])

    def test_direct_daemon_omits_service(self):
        # ca_url points straight at a daemon (no Control Agent) → service dropped.
        client = _make_server(ca_url="https://kea-daemon.example.com", has_control_agent=False).get_client(version=4)
        self.assertFalse(client.send_service)
        self.assertNotIn("service", self._sent_body(client))

    def test_protocol_url_control_agent_still_routes_by_service(self):
        # A protocol-specific URL pointing at a per-protocol Control Agent (before Kea 3.1.8)
        # must KEEP service so the CA can route to the daemon (regression for the case
        # where every dhcp{4,6}_url was wrongly treated as a bare daemon).
        client = _make_server(dhcp4_url="https://kea-v4-ca.example.com", has_control_agent=True).get_client(version=4)
        self.assertTrue(client.send_service)
        self.assertEqual(self._sent_body(client)["service"], ["dhcp4"])

    def test_protocol_url_direct_daemon_omits_service(self):
        # A protocol-specific bare daemon socket (Kea 3.0+, no Control Agent) → service dropped.
        client = _make_server(dhcp6_url="https://kea-v6.example.com", has_control_agent=False).get_client(version=6)
        self.assertFalse(client.send_service)


class TestServerCleanFieldValidation(TestCase):
    """Tests for local Server.clean() field validation."""

    # Patch super().clean() to avoid NetBox DB introspection in these field-only tests.
    def setUp(self):
        patcher = patch.object(NetBoxModel, "clean", return_value=None)
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_dhcp4_false_and_dhcp6_false_raises(self):
        server = _make_server(dhcp4=False, dhcp6=False)
        with self.assertRaises(ValidationError) as ctx:
            server.clean()
        self.assertIn("dhcp6", ctx.exception.message_dict)

    def test_cert_without_key_raises(self):
        server = _make_server(client_cert_path="/cert.pem", client_key_path=None)
        with self.assertRaises(ValidationError) as ctx:
            server.clean()
        self.assertIn("client_cert_path", ctx.exception.message_dict)

    def test_key_without_cert_raises(self):
        server = _make_server(client_cert_path=None, client_key_path="/key.pem")
        with self.assertRaises(ValidationError) as ctx:
            server.clean()
        self.assertIn("client_cert_path", ctx.exception.message_dict)

    def test_ca_file_with_ssl_verify_false_raises(self):
        server = _make_server(ca_file_path="/ca.pem", ssl_verify=False)
        with self.assertRaises(ValidationError) as ctx:
            server.clean()
        self.assertIn("ca_file_path", ctx.exception.message_dict)

    def test_nonexistent_cert_path_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "missing.pem")
            server = _make_server(client_cert_path=missing, client_key_path=missing)
            with self.assertRaises(ValidationError) as ctx:
                server.clean()
        self.assertIn("client_cert_path", ctx.exception.message_dict)

    def test_nonexistent_key_path_raises(self):
        """A cert that exists plus a key that does not must name the key field."""
        with tempfile.TemporaryDirectory() as tmp:
            cert = Path(tmp) / "cert.pem"
            cert.write_text("")
            server = _make_server(client_cert_path=str(cert), client_key_path=str(Path(tmp) / "missing-key.pem"))
            with self.assertRaises(ValidationError) as ctx:
                server.clean()
        self.assertIn("client_key_path", ctx.exception.message_dict)


class TestServerHasControlAgentDefault(SimpleTestCase):
    """Test that has_control_agent defaults to True."""

    def test_has_control_agent_default_true(self):
        server = Server(name="s", ca_url="http://kea:8000", dhcp4=True)
        self.assertTrue(server.has_control_agent)


# ---------------------------------------------------------------------------
# to_objectchange — password censoring
# ---------------------------------------------------------------------------


class TestServerToObjectchangePasswordCensoring(TestCase):
    """to_objectchange() must censor passwords correctly in pre/post change data.

    Uses a real saved Server row so NetBoxModel.to_objectchange() builds the
    prechange_data / postchange_data dicts from actual model serialisation.
    server.snapshot() sets _prechange_snapshot; changing a field without saving
    lets postchange_data reflect the new in-memory value.
    """

    def _make_server(self, **kwargs) -> Server:
        return _make_db_server(**kwargs)

    def test_unchanged_password_masked_as_censor_token(self):
        """When pre and post passwords are the same, post shows CENSOR_TOKEN (not CHANGED)."""
        from netbox.constants import CENSOR_TOKEN, CENSOR_TOKEN_CHANGED

        server = self._make_server(ca_password="secret")
        server.snapshot()  # _prechange_snapshot = current state ("secret")
        result = server.to_objectchange("update")
        self.assertEqual(result.postchange_data["ca_password"], CENSOR_TOKEN)
        self.assertNotEqual(result.postchange_data["ca_password"], CENSOR_TOKEN_CHANGED)

    def test_changed_password_masked_as_censor_token_changed(self):
        """When post password differs from pre password, post shows CENSOR_TOKEN_CHANGED."""
        from netbox.constants import CENSOR_TOKEN_CHANGED

        server = self._make_server(ca_password="old-secret")
        server.snapshot()  # pre-state: "old-secret"
        server.ca_password = "new-secret"  # change in-memory; don't save
        result = server.to_objectchange("update")
        self.assertEqual(result.postchange_data["ca_password"], CENSOR_TOKEN_CHANGED)

    def test_pre_password_always_masked_as_censor_token(self):
        """prechange_data password is always replaced with CENSOR_TOKEN."""
        from netbox.constants import CENSOR_TOKEN

        server = self._make_server(ca_password="old-secret")
        server.snapshot()
        server.ca_password = "new-secret"
        result = server.to_objectchange("update")
        self.assertEqual(result.prechange_data["ca_password"], CENSOR_TOKEN)

    def test_unset_password_is_not_masked(self):
        """An empty password must stay empty, not read as a secret in the change log.

        The columns are NOT NULL, so an unset password is "" rather than None.
        Stamping CENSOR_TOKEN on it would tell an operator a password exists.
        """
        from netbox.constants import CENSOR_TOKEN, CENSOR_TOKEN_CHANGED

        server = self._make_server(ca_password="")
        server.snapshot()
        result = server.to_objectchange("update")
        self.assertEqual(result.prechange_data["ca_password"], "")
        self.assertNotIn(result.postchange_data["ca_password"], (CENSOR_TOKEN, CENSOR_TOKEN_CHANGED))

    def test_setting_a_password_on_an_empty_field_reads_as_changed(self):
        """Going from unset to set must still be reported as a change."""
        from netbox.constants import CENSOR_TOKEN_CHANGED

        server = self._make_server(ca_password="")
        server.snapshot()
        server.ca_password = "new-secret"
        result = server.to_objectchange("update")
        self.assertEqual(result.prechange_data["ca_password"], "")
        self.assertEqual(result.postchange_data["ca_password"], CENSOR_TOKEN_CHANGED)

    def test_clearing_a_password_shows_the_removal(self):
        """Set -> blank must censor the old value and leave the new one visibly empty."""
        from netbox.constants import CENSOR_TOKEN

        server = self._make_server(ca_password="old-secret")
        server.snapshot()
        server.ca_password = ""
        result = server.to_objectchange("update")
        self.assertEqual(result.prechange_data["ca_password"], CENSOR_TOKEN)
        self.assertEqual(result.postchange_data["ca_password"], "")

    def test_delete_of_a_server_without_a_password_reports_blank(self):
        """The delete snapshot must not imply a password existed.

        This is the last of the four changelog states the black-box suite asserts.
        """
        server = self._make_server(ca_password="")
        server.snapshot()
        result = server.to_objectchange("delete")
        self.assertEqual(result.prechange_data["ca_password"], "")

    def test_no_prechange_data_does_not_raise(self):
        """to_objectchange("create") has no _prechange_snapshot → prechange_data is None,
        postchange password is masked as CENSOR_TOKEN_CHANGED (nothing to compare against)."""
        from netbox.constants import CENSOR_TOKEN_CHANGED

        server = self._make_server(ca_password="secret")
        # No snapshot() → no _prechange_snapshot attribute → prechange_data stays None.
        result = server.to_objectchange("create")
        self.assertIsNone(result.prechange_data)
        masked = result.postchange_data.get("ca_password")
        self.assertNotEqual(masked, "secret", "Password must be masked in postchange_data")
        self.assertEqual(masked, CENSOR_TOKEN_CHANGED)

    def test_dhcp4_password_masked_in_change_log(self):
        """dhcp4_password is censored in both prechange and postchange data."""
        from netbox.constants import CENSOR_TOKEN

        server = self._make_server(dhcp4_password="v4-secret")
        server.snapshot()
        result = server.to_objectchange("update")
        self.assertEqual(result.prechange_data["dhcp4_password"], CENSOR_TOKEN)
        self.assertEqual(result.postchange_data["dhcp4_password"], CENSOR_TOKEN)

    def test_dhcp6_password_masked_in_change_log(self):
        """dhcp6_password is censored in both prechange and postchange data."""
        from netbox.constants import CENSOR_TOKEN

        server = self._make_server(dhcp6_password="v6-secret")
        server.snapshot()
        result = server.to_objectchange("update")
        self.assertEqual(result.prechange_data["dhcp6_password"], CENSOR_TOKEN)
        self.assertEqual(result.postchange_data["dhcp6_password"], CENSOR_TOKEN)


# ---------------------------------------------------------------------------
class TestSyncConfig(TestCase):
    """Tests for the SyncConfig singleton model, whose row the migrations create."""

    def test_get_reads_the_migrated_row_and_writes_nothing(self):
        with self.assertNumQueries(1):
            cfg = SyncConfig.get()
        expected = _SEED.configured_values()
        self.assertEqual({name: getattr(cfg, name) for name in expected}, expected)

    def test_get_returns_the_stored_values(self):
        SyncConfig.objects.filter(pk=1).update(interval_minutes=10, sync_enabled=False)
        cfg = SyncConfig.get()
        self.assertEqual(cfg.interval_minutes, 10)
        self.assertFalse(cfg.sync_enabled)

    def test_get_raises_when_the_row_is_missing(self):
        SyncConfig.objects.all().delete()
        with self.assertRaises(SyncConfig.DoesNotExist):
            SyncConfig.get()
        self.assertFalse(SyncConfig.objects.exists())

    def test_save_forces_pk_to_1(self):
        cfg = SyncConfig(interval_minutes=10)
        cfg.pk = 999
        cfg.save()
        self.assertEqual(cfg.pk, 1)
        self.assertEqual(SyncConfig.objects.count(), 1)

    def test_save_second_instance_merges_to_singleton(self):
        SyncConfig(interval_minutes=20).save()
        self.assertEqual(SyncConfig.objects.count(), 1)
        self.assertEqual(SyncConfig.objects.get(pk=1).interval_minutes, 20)

    def test_delete_raises_type_error(self):
        cfg = SyncConfig.get()
        with self.assertRaises(TypeError):
            cfg.delete()


class TestServerSyncEnabled(TestCase):
    def test_sync_enabled_defaults_to_true(self):
        server = _make_db_server()
        self.assertTrue(server.sync_enabled)

    def test_sync_enabled_can_be_set_false(self):
        server = _make_db_server()
        server.sync_enabled = False
        server.save(update_fields=["sync_enabled"])
        server.refresh_from_db()
        self.assertFalse(server.sync_enabled)


class TestKeaDhcpLinkIdentity(TestCase):
    """A link row carries the identity columns of its kind, and each identity shape is unique.

    The partial unique constraints are conditional, so a row that fits no shape would escape every one of them.
    """

    def setUp(self):
        self.server = _make_db_server(name="kea-link-identity")
        self.object_type = ContentType.objects.get_for_model(Server)

    def _link(self, kind, object_id=None, family=4, **identity) -> KeaDhcpLink:
        return KeaDhcpLink(
            confirmation=next_confirmation_number(),
            server=self.server,
            family=family,
            kind=kind,
            object_type=self.object_type,
            object_id=self.server.pk if object_id is None else object_id,
            **identity,
        )

    def test_a_mapping_without_a_confirmation_number_validates_but_is_never_stored(self):
        unstamped = self._link("subnet", kea_subnet_id=7)
        unstamped.confirmation = None

        # A replayed payload has no number, so the native full_clean() before its save must accept it.
        unstamped.full_clean()
        # Outside a replay nothing stamps it, and the column has no default.
        with self.assertRaises(IntegrityError), transaction.atomic():
            unstamped.save()
        self.assertFalse(KeaDhcpLink.objects.filter(server=self.server).exists())

    def test_each_kind_stores_its_identity_columns(self):
        accepted = {
            "subnet": {"kea_subnet_id": 7},
            "pool": {"kea_subnet_id": 7, "kea_identity": "10.0.0.10-10.0.0.20"},
            "reservation": {"kea_subnet_id": 7, "kea_identity": "hw-address:aa:bb:cc:dd:ee:ff"},
            "shared_network": {"kea_identity": "office"},
            "client_class": {"kea_identity": "voip"},
            "option_definition": {"kea_identity": "dhcp4:222"},
        }
        for object_id, (kind, identity) in enumerate(accepted.items(), start=1):
            with self.subTest(kind=kind):
                self._link(kind, object_id=object_id, **identity).save()
                stored = KeaDhcpLink.objects.get(object_id=object_id)
                self.assertEqual(
                    (stored.kea_subnet_id, stored.kea_identity),
                    (identity.get("kea_subnet_id"), identity.get("kea_identity")),
                )
        self._link("reservation", object_id=99, kea_identity="hw-address:aa:bb:cc:dd:ee:ff").save()
        self.assertIsNone(KeaDhcpLink.objects.get(object_id=99).kea_subnet_id)

    def test_a_kind_without_its_identity_columns_is_rejected(self):
        rejected = {
            "subnet with an identity": ("subnet", {"kea_subnet_id": 7, "kea_identity": "hw-address:aa:bb"}),
            "subnet without an ID": ("subnet", {}),
            "pool without a range": ("pool", {"kea_subnet_id": 7}),
            "pool without a Subnet": ("pool", {"kea_identity": "10.0.0.10-10.0.0.20"}),
            "reservation without an identifier": ("reservation", {"kea_subnet_id": 7}),
            "empty reservation identity": ("reservation", {"kea_identity": ""}),
            "neither identity column": ("reservation", {}),
            "shared network in a Subnet": ("shared_network", {"kea_subnet_id": 7, "kea_identity": "office"}),
            "client class in a Subnet": ("client_class", {"kea_subnet_id": 7, "kea_identity": "voip"}),
            "option definition in a Subnet": ("option_definition", {"kea_subnet_id": 7, "kea_identity": "dhcp4:222"}),
            "empty client class name": ("client_class", {"kea_identity": ""}),
            "server with an identity": ("server", {"kea_identity": "Dhcp4"}),
            "server in a Subnet": ("server", {"kea_subnet_id": 7}),
            "unknown kind": ("not_a_kind", {"kea_identity": "Dhcp4"}),
        }
        for label, (kind, identity) in rejected.items():
            with self.subTest(label), self.assertRaises(IntegrityError), transaction.atomic():
                self._link(kind, **identity).save()

    def test_each_identity_shape_is_unique_within_its_kind(self):
        duplicates = {
            "subnet": {"kea_subnet_id": 7},
            "pool": {"kea_subnet_id": 7, "kea_identity": "10.0.0.10-10.0.0.20"},
            "reservation": {"kea_identity": "duid:01:02"},
            "client_class": {"kea_identity": "voip"},
        }
        for object_id, (kind, identity) in enumerate(duplicates.items(), start=1):
            with self.subTest(kind=kind):
                self._link(kind, object_id=object_id, **identity).save()
                with self.assertRaises(IntegrityError), transaction.atomic():
                    self._link(kind, object_id=object_id + 100, **identity).save()

    def test_one_identity_can_map_once_per_scope_kind_and_family(self):
        # A Global and an In-Subnet Reservation of one identifier, and one name of two kinds or families.
        sources = [
            ("reservation", 4, {"kea_identity": "duid:01:02"}),
            ("reservation", 4, {"kea_subnet_id": 7, "kea_identity": "duid:01:02"}),
            ("reservation", 4, {"kea_subnet_id": 8, "kea_identity": "duid:01:02"}),
            ("client_class", 4, {"kea_identity": "office"}),
            ("shared_network", 4, {"kea_identity": "office"}),
            ("client_class", 6, {"kea_identity": "office"}),
            ("subnet", 4, {"kea_subnet_id": 7}),
            ("pool", 4, {"kea_subnet_id": 7, "kea_identity": "10.0.0.10-10.0.0.20"}),
        ]
        for object_id, (kind, family, identity) in enumerate(sources, start=1):
            self._link(kind, object_id=object_id, family=family, **identity).save()

        self.assertEqual(KeaDhcpLink.objects.filter(server=self.server).count(), len(sources))

    def test_the_longest_identity_of_each_kind_is_stored(self):
        """Kea accepts a 128-octet Client ID and full-length IPv6 Pools, so the column must hold what they form."""
        from netbox_kea.integrations.dhcp_import_plan import (
            MAX_KEA_NAME_LENGTH,
            MappingSource,
            OptionDefinitionKey,
            PoolKey,
            reservation_key,
        )
        from netbox_kea.integrations.dhcp_import_report import Kind
        from netbox_kea.pools import parse_pool
        from netbox_kea.reservations import GlobalReservationScope, IPv4Reservation, ReservationIdentity

        reservation = IPv4Reservation(
            scope=GlobalReservationScope(),
            identity=ReservationIdentity("client-id", "ab" * 128),
            addresses=(),
        )
        pool = parse_pool(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", ip_network("ffff::/16")
        )
        name = "n" * MAX_KEA_NAME_LENGTH
        sources = [
            reservation_key(reservation).source,
            PoolKey(7, pool).source,
            OptionDefinitionKey(name, 65_535).source,
            MappingSource.named(Kind.CLIENT_CLASS, name),
        ]
        self.assertEqual(len(sources[0].kea_identity), MAX_IDENTITY_LENGTH)
        for object_id, source in enumerate(sources, start=1):
            with self.subTest(kind=source.kind):
                self._link(object_id=object_id, **source.columns()).save()
                self.assertEqual(KeaDhcpLink.objects.get(object_id=object_id).kea_identity, source.kea_identity)


class TestChangeLoggedModelsInTheChangeLogApi(TestCase):
    """The change log API serializes each changed object, so a change-logged model needs a REST serializer."""

    def test_the_change_log_api_lists_a_dhcp_import_mapping_change(self):
        from netbox.context_managers import event_tracking
        from rest_framework.test import APIClient

        user = get_user_model().objects.create_superuser("changelog-admin", "a@a.com", "pass")
        server = _make_db_server(name="kea-changelog")
        request = RequestFactory().post("/plugins/kea/")
        request.user, request.id = user, uuid.uuid4()
        with event_tracking(request):
            link = KeaDhcpLink.objects.create(
                confirmation=next_confirmation_number(),
                server=server,
                family=4,
                kind="subnet",
                kea_subnet_id=1,
                object_type=ContentType.objects.get_for_model(Server),
                object_id=server.pk,
            )
        api = APIClient(raise_request_exception=False)
        api.force_authenticate(user=user)

        response = api.get(reverse("core-api:objectchange-list"))

        self.assertEqual(response.status_code, 200, response.content[:300])
        (change,) = response.json()["results"]
        self.assertEqual(change["changed_object"], {"id": link.pk, "display": str(link)})

    def test_every_change_logged_model_has_a_serializer(self):
        from netbox.models.features import ChangeLoggingMixin
        from utilities.api import get_serializer_for_model

        logged = [
            model for model in apps.get_app_config("netbox_kea").get_models() if issubclass(model, ChangeLoggingMixin)
        ]
        self.assertIn(KeaDhcpLink, logged)
        for model in logged:
            with self.subTest(model=model.__name__):
                get_serializer_for_model(model)


class TestMigrationState(TestCase):
    """The recorded migrations describe the current netbox_kea models."""

    def test_models_have_no_unmigrated_changes(self):
        try:
            call_command("makemigrations", "netbox_kea", "--check", "--dry-run", "--no-input", verbosity=0)
        except SystemExit:
            self.fail("netbox_kea models changed with no matching migration. Run makemigrations.")

    def test_ownership_metadata_is_excluded_from_generated_fields(self):
        ownership = apps.get_model("netbox_kea", "IPAMOwnershipLink")
        for name, attribute in (
            ("family", "choices"),
            ("source", "choices"),
            ("facts", "help_text"),
            ("confirmation", "help_text"),
            ("stale_mark", "help_text"),
        ):
            with self.subTest(field=name):
                field = ownership._meta.get_field(name)
                self.assertTrue(getattr(field, attribute))
                self.assertNotIn(attribute, field.deconstruct()[3])

    def test_ownership_schema_drift_is_detected(self):
        loader = MigrationLoader(None)
        changed = ProjectState.from_apps(apps)
        changed.models["netbox_kea", "ipamownershiplink"].fields["source"].max_length += 1

        changes = MigrationAutodetector(loader.project_state(), changed).changes(
            graph=loader.graph, trim_to_apps={"netbox_kea"}
        )
        operations = [operation for migration in changes["netbox_kea"] for operation in migration.operations]

        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0].describe(), "Alter field source on ipamownershiplink")
        self.assertEqual(operations[0].field.max_length, 17)


class _MigrationTestCase(TransactionTestCase):
    """Base for tests that move the netbox_kea schema and data between migrations."""

    def _fixture_teardown(self):
        """Flush cross-plugin foreign keys while preserving normal post-migrate setup."""
        for database in self._databases_names(include_mirrors=False):
            call_command(
                "flush",
                verbosity=0,
                interactive=False,
                database=database,
                reset_sequences=False,
                allow_cascade=True,
            )


class TestKeaDhcpLinkConstraintMigration(_MigrationTestCase):
    """Current migrations must accept every KeaDhcpLink row a released deployment can hold."""

    _RELEASED = "0013_server_sync_dhcp_plugin_enabled_keadhcplink"

    def test_data_repair_uses_the_schema_editor_database_alias(self):
        migration = importlib.import_module("netbox_kea.migrations.0015_keadhcplink_one_identity_kind")

        class RoutedQuery:
            deleted = False

            def filter(self, *_conditions):
                return self

            def delete(self):
                self.deleted = True

        class Manager:
            alias = None
            query = RoutedQuery()

            def using(self, alias):
                self.alias = alias
                return self.query

            def filter(self, *_conditions):
                raise AssertionError("The migration used the default database manager.")

        class HistoricalLink:
            objects = Manager()

        class HistoricalApps:
            @staticmethod
            def get_model(app_label, model_name):
                self.assertEqual((app_label, model_name), ("netbox_kea", "KeaDhcpLink"))
                return HistoricalLink

        class Connection:
            alias = "migration-target"

        class SchemaEditor:
            connection = Connection()

        migration.remove_invalid_identity_links(HistoricalApps(), SchemaEditor())

        self.assertEqual(HistoricalLink.objects.alias, "migration-target")
        self.assertTrue(HistoricalLink.objects.query.deleted)

    def test_0016_replaces_null_credentials_with_blanks(self):
        """A row holding real NULLs, written before 0016, must survive the NOT NULL change.

        Rolls the schema back to 0015 so the columns are genuinely nullable, writes NULLs
        through raw SQL, then migrates forward and reads the values back.
        """
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        migration_0016 = importlib.import_module("netbox_kea.migrations.0016_charfield_blank_not_null")
        fields = migration_0016.OPTIONAL_TEXT_FIELDS

        executor = MigrationExecutor(connection)
        current = executor.loader.graph.leaf_nodes("netbox_kea")
        self.assertEqual(len(current), 1, f"netbox_kea migrations must have one leaf, found {current}.")

        def restore_migration_state():
            restore = MigrationExecutor(connection)
            restore.loader.build_graph()
            restore.migrate(current)

        self.addCleanup(restore_migration_state)

        server = _make_db_server(name="null-credentials")
        executor.migrate([("netbox_kea", "0015_keadhcplink_one_identity_kind")])

        columns = ", ".join(f"{field} = NULL" for field in fields)
        with connection.cursor() as cursor:
            # The interpolated names are the migration's own constant tuple, not input.
            cursor.execute(f"UPDATE netbox_kea_server SET {columns} WHERE id = %s", [server.pk])  # noqa: S608
            cursor.execute(f"SELECT {fields[0]} FROM netbox_kea_server WHERE id = %s", [server.pk])  # noqa: S608
            self.assertIsNone(cursor.fetchone()[0], "the rollback did not leave a genuinely nullable column")

        forward = MigrationExecutor(connection)
        forward.loader.build_graph()
        forward.migrate(current)

        server.refresh_from_db()
        for field in fields:
            self.assertEqual(getattr(server, field), "", f"{field} was not blanked by 0016")

    def test_a_subnet_keyed_link_written_before_0014_survives_the_constraint(self):
        """Release 1.9.0 stops at 0013, where the only writer always sets kea_subnet_id."""
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        server = _make_db_server(name="released-link")
        object_type = ContentType.objects.get_for_model(Server)
        executor = MigrationExecutor(connection)
        # Target the newest migration on disk, so a later one cannot narrow this cover.
        current = executor.loader.graph.leaf_nodes("netbox_kea")
        self.assertEqual(len(current), 1, f"netbox_kea migrations must have one leaf, found {current}.")

        def restore_migration_state():
            restore = MigrationExecutor(connection)
            restore.loader.build_graph()
            restore.migrate(current)

        self.addCleanup(restore_migration_state)
        executor.migrate([("netbox_kea", self._RELEASED)])
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO netbox_kea_keadhcplink "
                "(server_id, family, kea_subnet_id, object_type_id, object_id, created, last_synced) "
                "VALUES (%s, 4, 7, %s, %s, NOW(), NOW())",
                [server.pk, object_type.pk, server.pk],
            )
            # Fire the deferred foreign-key triggers the insert queued, or PostgreSQL
            # refuses to ALTER the table while the test transaction still holds them.
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        # The forward migration is the assertion: AddConstraint raises here if a
        # released row can violate keadhcplink_one_identity_kind.
        executor.loader.build_graph()
        executor.migrate(current)

        link = KeaDhcpLink.objects.get(server=server)
        self.assertEqual((link.kind, link.kea_subnet_id, link.kea_identity), ("subnet", 7, None))

    def _migrate_to(self, name):
        """Move the netbox_kea schema to *name*, and back to the newest migration at cleanup."""
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        executor = MigrationExecutor(connection)
        current = executor.loader.graph.leaf_nodes("netbox_kea")
        self.assertEqual(len(current), 1, f"netbox_kea migrations must have one leaf, found {current}.")

        def restore_migration_state():
            restore = MigrationExecutor(connection)
            restore.loader.build_graph()
            restore.migrate(current)

        self.addCleanup(restore_migration_state)
        executor.migrate([("netbox_kea", name)])
        return current

    def test_0028_gives_each_released_mapping_the_kind_of_its_source(self):
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        server = _make_db_server(name="released-mappings")
        object_type = ContentType.objects.get_for_model(Server)
        current = self._migrate_to("0027_displaycacheconfig")
        with connection.cursor() as cursor:
            for object_id, subnet_id, identity in ((1, 7, None), (2, None, "duid:01:02:03")):
                cursor.execute(
                    "INSERT INTO netbox_kea_keadhcplink (server_id, family, kea_subnet_id, kea_identity, "
                    "object_type_id, object_id, created, last_synced, last_updated) "
                    "VALUES (%s, 4, %s, %s, %s, %s, NOW(), NOW(), NOW())",
                    [server.pk, subnet_id, identity, object_type.pk, object_id],
                )
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

        forward = MigrationExecutor(connection)
        forward.loader.build_graph()
        forward.migrate(current)

        self.assertEqual(
            set(KeaDhcpLink.objects.filter(server=server).values_list("object_id", "kind")),
            {(1, "subnet"), (2, "reservation")},
        )
        self.assertIsNone(KeaDhcpLink.objects.get(server=server, object_id=2).kea_subnet_id)

    def test_0028_reversed_removes_the_mappings_that_the_older_schema_cannot_hold(self):
        server = _make_db_server(name="newer-mappings")
        object_type = ContentType.objects.get_for_model(Server)
        held = {"subnet": {"kea_subnet_id": 7}, "reservation": {"kea_identity": "duid:01:02:03"}}
        unheld = {
            "pool": {"kea_subnet_id": 7, "kea_identity": "10.0.0.10-10.0.0.20"},
            "client_class": {"kea_identity": "voip"},
        }
        for object_id, (kind, identity) in enumerate({**held, **unheld}.items(), start=1):
            KeaDhcpLink.objects.create(
                confirmation=next_confirmation_number(),
                server=server,
                family=4,
                kind=kind,
                object_type=object_type,
                object_id=object_id,
                **identity,
            )
        # An In-Subnet Reservation sets both identity columns, which the older check constraint refuses.
        KeaDhcpLink.objects.create(
            confirmation=next_confirmation_number(),
            server=server,
            family=4,
            kind="reservation",
            kea_subnet_id=7,
            kea_identity="duid:01:02:03",
            object_type=object_type,
            object_id=10,
        )

        self._migrate_to("0027_displaycacheconfig")

        from django.db import connection

        with connection.cursor() as cursor:
            cursor.execute("SELECT object_id FROM netbox_kea_keadhcplink WHERE server_id = %s", [server.pk])
            self.assertEqual({row[0] for row in cursor.fetchall()}, {1, 2})

    def test_0028_reversed_accepts_every_mapping_kind_and_ownership_source(self):
        from django.db import connection
        from ipam.models import Prefix

        identity_shapes = {
            "server": ((None, None),),
            "shared_network": ((None, "shared"),),
            "subnet": ((7, None),),
            "pool": ((7, "198.18.0.10-198.18.0.20"),),
            "pd_pool": ((7, "2001:db8::/48:64"),),
            "reservation": ((None, "duid:01:02:03"), (7, "duid:01:02:03")),
            "client_class": ((None, "voip"),),
            "option_definition": ((None, "voip:dhcp6:1234"),),
            "option": ((None, '["dhcpserver",null,"dhcp6",23,[],0]'), (7, '["subnet",7,"dhcp6",23,[],0]')),
        }
        kinds = dict(KeaDhcpLink._meta.get_field("kind").choices)
        self.assertEqual(
            set(identity_shapes),
            set(kinds),
            "Add the identity shape AND a reverse cleanup for each new mapping kind.",
        )
        server = _make_db_server(name="all-mapping-kinds")
        object_type = ContentType.objects.get_for_model(Server)
        max_length = KeaDhcpLink._meta.get_field("kea_identity").max_length
        expected_mappings = []
        object_id = 0
        for kind in kinds:
            for subnet_id, identity in identity_shapes[kind]:
                identities = (None,) if identity is None else (identity, "a" * 393, "b" * 394, "c" * max_length)
                for value in identities:
                    object_id += 1
                    KeaDhcpLink.objects.create(
                        confirmation=next_confirmation_number(),
                        server=server,
                        family=6,
                        kind=kind,
                        kea_subnet_id=subnet_id,
                        kea_identity=value,
                        object_type=object_type,
                        object_id=object_id,
                    )
                    if kind == "subnet" or (kind == "reservation" and subnet_id is None and len(value) <= 393):
                        expected_mappings.append((object_id, subnet_id, value))
        prefixes = []
        for index, source in enumerate(IPAMOwnershipSource.values, start=1):
            prefix = Prefix.objects.create(prefix=f"2001:db8:{index}::/64", description="Owned Prefix", status="active")
            prefixes.append((prefix.pk, prefix.description, prefix.status))
            IPAMOwnershipLink.objects.create(server=server, family=6, source=source, prefix=prefix, confirmation=1)

        self._migrate_to("0027_displaycacheconfig")

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT object_id, kea_subnet_id, kea_identity FROM netbox_kea_keadhcplink WHERE server_id = %s",
                [server.pk],
            )
            self.assertCountEqual(cursor.fetchall(), expected_mappings)
            cursor.execute("SELECT source FROM netbox_kea_ipamownershiplink WHERE server_id = %s", [server.pk])
            self.assertEqual(
                {row[0] for row in cursor.fetchall()},
                set(IPAMOwnershipSource.values) - {IPAMOwnershipSource.PD_POOL},
            )
            cursor.execute(
                "SELECT id, description, status FROM ipam_prefix WHERE id = ANY(%s)", [[p[0] for p in prefixes]]
            )
            self.assertCountEqual(cursor.fetchall(), prefixes)

    def test_0028_reversed_removes_the_family_mappings_that_the_older_schema_cannot_hold(self):
        server = _make_db_server(name="family-mappings")
        object_type = ContentType.objects.get_for_model(Server)
        KeaDhcpLink.objects.create(
            confirmation=next_confirmation_number(),
            server=server,
            family=4,
            kind="subnet",
            kea_subnet_id=7,
            object_type=object_type,
            object_id=1,
        )
        KeaDhcpLink.objects.create(
            confirmation=next_confirmation_number(),
            server=server,
            family=4,
            kind="server",
            object_type=object_type,
            object_id=2,
        )

        self._migrate_to("0027_displaycacheconfig")

        from django.db import connection

        with connection.cursor() as cursor:
            cursor.execute("SELECT object_id FROM netbox_kea_keadhcplink WHERE server_id = %s", [server.pk])
            self.assertEqual({row[0] for row in cursor.fetchall()}, {1})

    def test_0029_reversed_removes_the_option_mappings_that_the_older_schema_cannot_hold(self):
        from django.db import connection

        server = _make_db_server(name="option-mappings")
        object_type = ContentType.objects.get_for_model(Server)
        for object_id, kind, identity in ((1, "subnet", None), (2, "option", '["subnet",null,"dhcp4",6,[],0]')):
            KeaDhcpLink.objects.create(
                confirmation=next_confirmation_number(),
                server=server,
                family=4,
                kind=kind,
                kea_subnet_id=7,
                kea_identity=identity,
                object_type=object_type,
                object_id=object_id,
            )

        self._migrate_to("0028_dhcp_import")

        with connection.cursor() as cursor:
            cursor.execute("SELECT object_id, kind FROM netbox_kea_keadhcplink WHERE server_id = %s", [server.pk])
            self.assertEqual(cursor.fetchall(), [(1, "subnet")])

    def test_0029_gives_an_existing_mapping_a_confirmation_below_every_cutoff(self):
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        server = _make_db_server(name="confirmed-mappings")
        object_type = ContentType.objects.get_for_model(Server)
        current = self._migrate_to("0028_dhcp_import")
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO netbox_kea_keadhcplink (server_id, family, kind, kea_subnet_id, object_type_id, "
                "object_id, created, last_synced, last_updated) "
                "VALUES (%s, 4, 'subnet', 7, %s, %s, NOW(), NOW(), NOW())",
                [server.pk, object_type.pk, server.pk],
            )
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        # A read that is in progress during the upgrade took its cutoff before the migration.
        cutoff = next_confirmation_number()

        forward = MigrationExecutor(connection)
        forward.loader.build_graph()
        forward.migrate(current)

        confirmation = KeaDhcpLink.objects.get(server=server).confirmation
        self.assertLess(confirmation, cutoff)
        # 1 is the lowest number of the sequence, so also every later cutoff is higher.
        self.assertLess(confirmation, 1)

    def test_an_identityless_link_is_removed_before_the_constraint_is_added(self):
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        server = _make_db_server(name="identityless-link")
        object_type = ContentType.objects.get_for_model(Server)
        executor = MigrationExecutor(connection)
        current = executor.loader.graph.leaf_nodes("netbox_kea")

        def restore_migration_state():
            restore = MigrationExecutor(connection)
            restore.loader.build_graph()
            restore.migrate(current)

        self.addCleanup(restore_migration_state)
        executor.migrate([("netbox_kea", "0014_keadhcplink_kea_identity")])
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO netbox_kea_keadhcplink "
                "(server_id, family, kea_subnet_id, kea_identity, object_type_id, object_id, created, last_synced) "
                "VALUES (%s, 4, NULL, NULL, %s, %s, NOW(), NOW())",
                [server.pk, object_type.pk, server.pk],
            )

        executor.loader.build_graph()
        executor.migrate(current)

        self.assertFalse(KeaDhcpLink.objects.filter(server=server).exists())
        self.assertTrue(Server.objects.filter(pk=server.pk).exists())


class TestNoModelAdvertisesDocsItDoesNotShip(SimpleTestCase):
    """NetBox renders a Help button for any NetBoxModel, shipped docs or not.

    `generic/object_edit.html` gates it on `settings.DOCS_ROOT and object.docs_url`, and
    `NetBoxModel.docs_url` builds the URL from the app label unconditionally, so it is
    never empty. Core models ship a page under that path; a plugin model does not, and the
    button lands on a 404.

    NetBox's plugin documentation offers three answers, and all three pass here: return
    None to hide the button, return an absolute URL somebody else serves (its example is
    ReadTheDocs), or ship the page. Only a static path this package does not ship fails.
    """

    def test_every_model_either_suppresses_the_help_button_or_ships_its_page(self):
        package = Path(netbox_kea.__file__).parent
        offenders = []
        for model in apps.get_app_config("netbox_kea").get_models():
            if not issubclass(model, NetBoxModel):
                continue
            url = model().docs_url
            # None hides the button, and an absolute URL is served somewhere this
            # package cannot check. Only a local static path is ours to ship.
            if url is None or urlparse(url).scheme:
                continue
            if not url.startswith(settings.STATIC_URL):
                offenders.append(f"{model.__name__} advertises {url}, which is neither absolute nor static")
                continue
            page = package / "static" / url.removeprefix(settings.STATIC_URL).strip("/") / "index.html"
            if not page.is_file():
                offenders.append(f"{model.__name__} advertises {url}, but {page} does not exist")

        self.assertEqual(offenders, [], offenders)

    def test_the_scan_reads_a_real_model_list(self):
        """No NetBoxModel found would make the test above pass without checking anything."""
        models = [m for m in apps.get_app_config("netbox_kea").get_models() if issubclass(m, NetBoxModel)]

        self.assertIn(Server, models)


class TestSyncVrfProtectsTheVrf(TestCase):
    """A VRF that a Server syncs into cannot be deleted while the Server uses it (ADR 0007).

    With netbox-branching, a SET_NULL here would null main's Server row from a branch.
    """

    def setUp(self):
        from ipam.models import VRF
        from rest_framework.test import APIClient

        self.vrf = VRF.objects.create(name="sync target")
        self.server = _make_db_server(sync_vrf=self.vrf)
        self.user = get_user_model().objects.create_superuser(username="vrf-admin", password="unused")
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.user)

    def _assert_unchanged(self):
        from ipam.models import VRF

        self.assertTrue(VRF.objects.filter(pk=self.vrf.pk).exists(), "the VRF was deleted")
        self.server.refresh_from_db()
        self.assertEqual(self.server.sync_vrf_id, self.vrf.pk)

    def test_the_orm_delete_raises_protected_error(self):
        with self.assertRaises(ProtectedError) as refused:
            self.vrf.delete()

        self.assertEqual(list(refused.exception.protected_objects), [self.server])
        self._assert_unchanged()

    def test_the_vrf_delete_view_shows_the_server_that_protects_it(self):
        self.client.force_login(self.user)

        response = self.client.post(reverse("ipam:vrf_delete", kwargs={"pk": self.vrf.pk}), {"confirm": True})

        self.assertRedirects(response, self.vrf.get_absolute_url(), fetch_redirect_response=False)
        shown = [str(message) for message in django_messages.get_messages(response.wsgi_request)]
        self.assertEqual(len(shown), 1, shown)
        self.assertIn(f"Unable to delete <strong>{self.vrf}</strong>", shown[0])
        self.assertIn(self.server.get_absolute_url(), shown[0])
        self._assert_unchanged()

    def test_the_vrf_delete_api_answers_409(self):
        response = self.api_client.delete(reverse("ipam-api:vrf-detail", kwargs={"pk": self.vrf.pk}))

        self.assertEqual(response.status_code, 409, response.content)
        self.assertIn(f"{self.server} ({self.server.pk})", response.json()["detail"])
        self._assert_unchanged()


class _UpgradeTestCase(_MigrationTestCase):
    """Roll netbox_kea back to ``_BEFORE``, and migrate it forward again in the test and at cleanup."""

    _BEFORE: tuple[str, str]

    def _roll_back_apps(self):
        """Migrate netbox_kea back to ``_BEFORE``, and return the models of that state."""
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        executor = MigrationExecutor(connection)
        current = executor.loader.graph.leaf_nodes("netbox_kea")
        self.assertEqual(len(current), 1, f"netbox_kea migrations must have one leaf, found {current}.")

        def migrate_to_current():
            forward = MigrationExecutor(connection)
            forward.loader.build_graph()
            forward.migrate(current)

        self._migrate_to_current = migrate_to_current
        self.addCleanup(migrate_to_current)
        executor.migrate([self._BEFORE])
        return executor.loader.project_state([self._BEFORE]).apps


class TestSyncConfigSeedMigration(_UpgradeTestCase):
    """The migration creates the SyncConfig row and applies the backfill, so a GET only reads it."""

    _BEFORE = ("netbox_kea", "0017_alter_server_sync_vrf")
    _TOGGLES = _SEED.TYPE_TOGGLES
    #: The type toggles that _CONFIG gives a new row or a row whose backfill has not run.
    _CONFIGURED_TOGGLES = {
        "sync_leases_enabled": False,
        "sync_reservations_enabled": True,
        "sync_prefixes_enabled": True,
        "sync_ip_ranges_enabled": False,
    }
    _CONFIG = {
        "netbox_kea": {
            "sync_interval_minutes": 17,
            "sync_enabled": False,
            "sync_leases_enabled": False,
            "sync_ip_ranges_enabled": False,
        }
    }

    def _roll_back(self):
        """Migrate netbox_kea back to the release before the seed, and return that SyncConfig model."""
        return self._roll_back_apps().get_model("netbox_kea", "SyncConfig")

    def _upgrade(self):
        with override_settings(PLUGINS_CONFIG=self._CONFIG):
            self._migrate_to_current()
        return SyncConfig.objects.get(pk=1)

    def _assert_sync_pages_write_nothing(self):
        from netbox_kea.tests.utils import _get_with_writes, _sync_page_urls

        server = _make_db_server(name="seed-upgrade")
        self.client.force_login(get_user_model().objects.create_superuser("seed", "seed@example.com", "pass"))
        for url in _sync_page_urls(server):
            with self.subTest(url=url):
                response, writes = _get_with_writes(self.client, url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(writes, [])

    def test_upgrade_without_a_row_creates_it_from_plugins_config(self):
        historical = self._roll_back()
        historical.objects.all().delete()

        cfg = self._upgrade()

        self.assertEqual(cfg.interval_minutes, 17)
        self.assertFalse(cfg.sync_enabled)
        self.assertEqual({name: getattr(cfg, name) for name in self._TOGGLES}, self._CONFIGURED_TOGGLES)
        self._assert_sync_pages_write_nothing()

    def test_upgrade_applies_the_backfill_that_has_not_run(self):
        historical = self._roll_back()
        updated = historical.objects.filter(pk=1).update(
            interval_minutes=9, sync_enabled=True, backfill_applied=False, **dict.fromkeys(self._TOGGLES, True)
        )
        self.assertEqual(updated, 1, "the database held no SyncConfig row before the upgrade")

        cfg = self._upgrade()

        # The backfill changes only the type toggles that PLUGINS_CONFIG disables.
        self.assertEqual(cfg.interval_minutes, 9)
        self.assertTrue(cfg.sync_enabled)
        self.assertEqual({name: getattr(cfg, name) for name in self._TOGGLES}, self._CONFIGURED_TOGGLES)
        self._assert_sync_pages_write_nothing()

    def test_upgrade_keeps_a_row_whose_backfill_has_run(self):
        historical = self._roll_back()
        updated = historical.objects.filter(pk=1).update(
            interval_minutes=9, sync_enabled=True, backfill_applied=True, **dict.fromkeys(self._TOGGLES, True)
        )
        self.assertEqual(updated, 1, "the database held no SyncConfig row before the upgrade")

        cfg = self._upgrade()

        self.assertEqual(cfg.interval_minutes, 9)
        self.assertTrue(cfg.sync_enabled)
        self.assertEqual({name: getattr(cfg, name) for name in self._TOGGLES}, dict.fromkeys(self._TOGGLES, True))
        self._assert_sync_pages_write_nothing()

    def test_upgrade_without_a_row_refuses_an_invalid_interval_by_name(self):
        """A value the database constraint refuses must not fail as an IntegrityError, nor be truncated or coerced."""
        historical = self._roll_back()
        historical.objects.all().delete()

        for interval in (0, 1441, 2.5, "10", True):
            with self.subTest(interval=interval):
                config = {"netbox_kea": {**self._CONFIG["netbox_kea"], "sync_interval_minutes": interval}}
                with override_settings(PLUGINS_CONFIG=config):
                    with self.assertRaisesMessage(ImproperlyConfigured, "sync_interval_minutes"):
                        self._migrate_to_current()
                self.assertFalse(historical.objects.exists())

    def test_upgrade_refuses_a_switch_that_is_not_a_bool_by_name(self):
        """No startup check guards these keys now, and the string "false" is truthy."""
        historical = self._roll_back()
        for backfill_applied, key in (
            (None, "sync_enabled"),
            (None, "sync_leases_enabled"),
            (False, "sync_prefixes_enabled"),
        ):
            for value in ("false", 0, None):
                with self.subTest(row=backfill_applied, key=key, value=value):
                    historical.objects.all().delete()
                    if backfill_applied is not None:
                        historical.objects.create(pk=1, backfill_applied=backfill_applied)
                    config = {"netbox_kea": {**self._CONFIG["netbox_kea"], key: value}}
                    with override_settings(PLUGINS_CONFIG=config):
                        with self.assertRaisesMessage(ImproperlyConfigured, f"['{key}'] must be True or False"):
                            self._migrate_to_current()

    def test_upgrade_with_a_row_ignores_an_invalid_interval(self):
        """The interval only seeds a new row, so a value no run reads must not block the upgrade."""
        historical = self._roll_back()
        historical.objects.filter(pk=1).update(interval_minutes=9, backfill_applied=False)
        config = {"netbox_kea": {**self._CONFIG["netbox_kea"], "sync_interval_minutes": 0}}

        with override_settings(PLUGINS_CONFIG=config):
            self._migrate_to_current()

        cfg = SyncConfig.objects.get(pk=1)
        self.assertEqual(cfg.interval_minutes, 9)
        self.assertEqual({name: getattr(cfg, name) for name in self._TOGGLES}, self._CONFIGURED_TOGGLES)

    def test_downgrade_marks_the_backfill_as_applied(self):
        """The seed already applied the backfill, so the restored flag must not let it run again."""
        historical = self._roll_back()

        self.assertIs(historical.objects.get(pk=1).backfill_applied, True)


class TestSettingsCopyMigration(_UpgradeTestCase):
    """Migration 0025 copies each moved PLUGINS_CONFIG value into its settings row once (ADR 0010)."""

    _BEFORE = ("netbox_kea", "0024_syncconfig_created_syncconfig_last_updated")
    _MIGRATION = "0025_keaclientconfig_and_sync_settings"

    def _upgrade(self, values: dict) -> None:
        with override_settings(PLUGINS_CONFIG={"netbox_kea": values}):
            self._migrate_to_current()

    def test_an_install_keeps_its_configured_values(self):
        historical = self._roll_back_apps().get_model("netbox_kea", "SyncConfig")
        historical.objects.filter(pk=1).update(interval_minutes=9)

        self._upgrade(
            {
                "kea_timeout": 10,
                "lease_query_max_unpaged_leases": 0,
                "stale_ip_cleanup": "deprecate",
                "sync_max_leases_per_server": 7,
                "sync_interval_minutes": 17,
            }
        )

        client, sync = KeaClientConfig.get(), SyncConfig.get()
        self.assertEqual((client.kea_timeout, client.lease_query_max_unpaged_leases), (10, 0))
        self.assertEqual((sync.stale_ip_cleanup, sync.sync_max_leases_per_server), ("deprecate", 7))
        self.assertEqual(sync.interval_minutes, 9, "0018 seeded the interval; 0025 must not copy it again")
        # After the upgrade the rows hold the values, and a changed configuration has no effect.
        with override_settings(PLUGINS_CONFIG={"netbox_kea": {"kea_timeout": 20}}):
            self.assertEqual(_make_server().get_client(version=4).timeout, 10)

    def test_a_missing_key_keeps_the_model_default(self):
        self._roll_back_apps()

        self._upgrade({"not_a_setting": 1})

        defaults_client, defaults_sync = KeaClientConfig(), SyncConfig()
        client, sync = KeaClientConfig.get(), SyncConfig.get()
        self.assertEqual(
            (client.kea_timeout, client.lease_query_max_unpaged_leases),
            (defaults_client.kea_timeout, defaults_client.lease_query_max_unpaged_leases),
        )
        self.assertEqual(
            (sync.stale_ip_cleanup, sync.sync_max_leases_per_server),
            (defaults_sync.stale_ip_cleanup, defaults_sync.sync_max_leases_per_server),
        )

    def test_an_invalid_value_fails_the_upgrade_and_names_the_key_the_rule_and_the_value(self):
        """bool is not an integer, and Django would truncate a float or coerce a string, so each is refused."""
        from django.db import connection
        from django.db.migrations.recorder import MigrationRecorder

        self._roll_back_apps()
        bad = {
            "kea_timeout": ("an integer of at least 1", [0, -1, True, 2.5, "30", None]),
            "lease_query_max_unpaged_leases": ("an integer of at least 0", [-1, False, "1000", None]),
            "stale_ip_cleanup": ("one of remove, deprecate, none", ["delete", "Remove", 1, None, ["remove"]]),
            "sync_max_leases_per_server": ("an integer of at least 0", [-1, True, 1e5, "50000"]),
        }
        for key, (allowed, values) in bad.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    message = f"PLUGINS_CONFIG['netbox_kea']['{key}'] must be {allowed}, got {value!r}."
                    with self.assertRaisesMessage(ImproperlyConfigured, message):
                        self._upgrade({key: value})
                    applied = MigrationRecorder(connection).applied_migrations()
                    self.assertNotIn(("netbox_kea", self._MIGRATION), applied)


class TestDhcpIntegrationMigration(_UpgradeTestCase):
    """Migration 0026 creates the DHCP Plugin Integration row with the switch on, so an upgrade keeps the integration."""

    _BEFORE = ("netbox_kea", "0025_keaclientconfig_and_sync_settings")

    def test_an_upgrade_creates_the_row_with_the_integration_on(self):
        historical = self._roll_back_apps()
        self.assertNotIn("dhcpintegrationconfig", historical.all_models["netbox_kea"])

        self._migrate_to_current()

        self.assertIs(DhcpIntegrationConfig.get().enabled, True)


class TestDisplayCacheMigration(_UpgradeTestCase):
    """Migration 0027 creates the Display Cache row with the default TTL of each read kind."""

    _BEFORE = ("netbox_kea", "0026_dhcpintegrationconfig")

    def test_an_upgrade_creates_the_row_with_the_default_ttls(self):
        historical = self._roll_back_apps()
        self.assertNotIn("displaycacheconfig", historical.all_models["netbox_kea"])

        self._migrate_to_current()

        row = DisplayCacheConfig.get()
        self.assertEqual(
            (row.configuration_ttl, row.reservations_ttl, row.leases_ttl, row.status_ttl), (300, 300, 30, 15)
        )
