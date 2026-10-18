# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Runtime Change outcomes of ``runtime_change``, through a real Server and a real ``KeaClient`` (ADR 0011).

Only ``requests.Session.post`` is stubbed. Each test asserts the commands that reached Kea, because no operation
may read Kea after the send to classify the change.
"""

import ipaddress
import json
import socket
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import requests
from django.test import TestCase
from urllib3.exceptions import ProtocolError

from netbox_kea import runtime_change
from netbox_kea.change_outcome import ChangeRejected
from netbox_kea.leases import DHCPv4LeaseRequest, LeaseEdit, shown_lease
from netbox_kea.models import Server
from netbox_kea.runtime_change import LeaseDeleteOutcome, RuntimeChangeOutcome

from .kea_stub import (
    LeaseDaemon,
    _http_response,
    _post_error,
    _refused_connection,
    _tls_errors,
    redirect_to_netrc_host,
    stub_kea,
    typed_lease,
)
from .utils import _make_db_server, with_kea_client_config

_RECORDINGS = Path(__file__).with_name("kea_recordings")
_CONTROL_AGENT = json.loads((_RECORDINGS / "control-agent.json").read_text())
_LEASE = json.loads((_RECORDINGS / "dhcp4.json").read_text())["leases"]["changes"]["before"]["arguments"]
_PREFIX = json.loads((_RECORDINGS / "dhcp6.json").read_text())["leases"]["changes"]["before"]["arguments"]
_SHOWN = shown_lease(typed_lease(_LEASE))
_CREATION = DHCPv4LeaseRequest(address=ipaddress.IPv4Address("192.0.2.50"), hw_address="aa:bb:cc:00:00:50")
_RENAME = LeaseEdit(hostname="renamed.example.org")
_LOST = "Kea's reply to the change was lost or unreadable."
_HOOK_NOT_LOADED = (
    "Kea does not support this command. "
    "The required hook library may not be loaded, for example host_cmds, lease_cmds or subnet_cmds."
)


def _forward_failure(family: int) -> dict[str, Any]:
    """The answer that a real Control Agent sent when it could not forward a command to the daemon."""
    return _CONTROL_AGENT[f"network{family}-add"]


def _reset_during_reply() -> requests.ConnectionError:
    return requests.ConnectionError(ProtocolError("Connection aborted.", ConnectionResetError(104, "reset")))


@dataclass(frozen=True)
class _Operation:
    """One Runtime Change, the write command that it sends, and the read before the write."""

    name: str
    run: Callable[[Server], RuntimeChangeOutcome]
    write: str
    read: str | None = None

    def responses(self, reply: Any) -> dict[str, Any]:
        """Answer the read before the write from a daemon that holds the shown Lease, and the write with *reply*."""
        held = LeaseDaemon(4, _LEASE).responses() if self.read else {}
        return {**held, self.write: reply}

    @property
    def before(self) -> list[str]:
        return [self.read] if self.read else []


_OPERATIONS = (
    _Operation("add_lease", lambda server: runtime_change.add_lease(server, 4, _CREATION), "lease4-add"),
    _Operation(
        "edit_lease",
        lambda server: runtime_change.edit_lease(server, 4, _SHOWN, _RENAME),
        "lease4-update",
        "lease4-get",
    ),
    _Operation(
        "delete_lease", lambda server: runtime_change.delete_lease(server, 4, _SHOWN), "lease4-del", "lease4-get"
    ),
    _Operation("wipe_leases", lambda server: runtime_change.wipe_leases(server, 4, 10), "lease4-wipe"),
    _Operation("enable_dhcp", lambda server: runtime_change.enable_dhcp(server, 4), "dhcp-enable"),
    _Operation("disable_dhcp", lambda server: runtime_change.disable_dhcp(server, 4, None), "dhcp-disable"),
)
_LEASE_WRITES = tuple(operation for operation in _OPERATIONS if operation.write.startswith("lease"))
_READS_FIRST = tuple(operation for operation in _OPERATIONS if operation.read)
_SERVICE_CHANGES = tuple(operation for operation in _OPERATIONS if operation.write.startswith("dhcp"))


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class ApplicationTests(TestCase):
    """Each operation gives applied, unknown or a rejection by the shared rules, and reads nothing after the send."""

    def setUp(self):
        self.server = _make_db_server()

    def _result(self, operation: _Operation, reply: Any) -> tuple[RuntimeChangeOutcome, list[str]]:
        with stub_kea(operation.responses(reply)) as kea:
            outcome = operation.run(self.server)
        return outcome, kea.commands()

    def _rejection(self, operation: _Operation, responses: dict[str, Any]) -> tuple[ChangeRejected, list[str]]:
        with stub_kea(responses) as kea, self.assertRaises(ChangeRejected) as raised:
            operation.run(self.server)
        return raised.exception, kea.commands()

    def test_a_success_reply_is_applied(self):
        for operation in _OPERATIONS:
            with self.subTest(operation.name):
                outcome, commands = self._result(operation, {"result": 0, "text": "done"})
                self.assertEqual(outcome.application, "applied")
                self.assertEqual(outcome.diagnostics, ())
                self.assertEqual(commands, [*operation.before, operation.write])

    def test_a_connect_failure_is_not_sent(self):
        refused = _refused_connection()
        for operation in _OPERATIONS:
            for failure in (refused, requests.ConnectTimeout("connect timed out")):
                with self.subTest(operation.name, failure=type(failure).__name__):
                    rejection, commands = self._rejection(operation, operation.responses(failure))
                    self.assertEqual(rejection.reason, "not-sent")
                    self.assertEqual(rejection.diagnostics, ("Kea could not be reached.",))
                    self.assertEqual(commands, [*operation.before, operation.write])

    def test_an_http_401_answer_is_not_sent(self):
        """The web server in front of Kea refused the credentials, so Kea did not run the command (ADR 0011)."""
        for operation in _OPERATIONS:
            with self.subTest(operation.name):
                reply = _http_response({"error": "Unauthorized"}, status=401)
                rejection, commands = self._rejection(operation, operation.responses(reply))
                self.assertEqual(rejection.reason, "not-sent")
                self.assertEqual(
                    rejection.diagnostics,
                    ("Kea refused the credentials (HTTP 401). Check the user name and password of the Server.",),
                )
                self.assertEqual(commands, [*operation.before, operation.write])

    def test_any_other_http_error_is_unknown(self):
        """A proxy can forward the command and then block Kea's reply, for example with HTTP 403."""
        for operation in _OPERATIONS:
            for status in (403, 500, 502, 503):
                with self.subTest(operation.name, status=status):
                    outcome, _commands = self._result(operation, _http_response({"error": "down"}, status=status))
                    self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", (_LOST,)))

    def test_a_tls_failure_is_unknown_and_names_the_tls_connection(self):
        """A TLS 1.2 server can renegotiate after it received the command, so no TLS error proves "not sent"."""
        errors = _tls_errors()
        diagnostics = {
            "verify": (
                "The TLS connection to Kea failed: NetBox could not verify the certificate of Kea."
                " Check the TLS settings of the Server."
            ),
            "handshake": "The TLS connection to Kea failed. Check the TLS settings of the Server.",
        }
        for operation in _OPERATIONS:
            for name, diagnostic in diagnostics.items():
                with self.subTest(operation.name, failure=name):
                    outcome, commands = self._result(operation, errors[name])
                    self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", (diagnostic,)))
                    self.assertEqual(commands, [*operation.before, operation.write])

    def test_an_invalid_url_is_not_sent(self):
        errors = {
            "missing schema": _post_error("kea.example.invalid/"),
            "invalid schema": _post_error("ftp://kea.example.invalid/"),
            "invalid url": _post_error("http://"),
        }
        self.assertEqual(
            [type(error).__name__ for error in errors.values()], ["MissingSchema", "InvalidSchema", "InvalidURL"]
        )
        for operation in _OPERATIONS:
            for name, error in errors.items():
                with self.subTest(operation.name, failure=name):
                    rejection, _commands = self._rejection(operation, operation.responses(error))
                    self.assertEqual(rejection.reason, "not-sent")
                    self.assertEqual(rejection.diagnostics, ("The URL of the Server is not valid.",))

    def test_a_failed_read_before_the_write_is_not_sent(self):
        failures = {
            "connect": _refused_connection(),
            "read timeout": requests.ReadTimeout("read timed out"),
            "kea failure": {"result": 1, "text": "lease database unavailable"},
            "malformed": [{"result": 0}, {"result": 0}],
        }
        for operation in _READS_FIRST:
            for name, failure in failures.items():
                with self.subTest(operation.name, failure=name):
                    responses = {**operation.responses({"result": 0}), "lease4-get": failure}
                    rejection, commands = self._rejection(operation, responses)
                    self.assertEqual(rejection.reason, "not-sent")
                    self.assertEqual(commands, ["lease4-get"])
                    if name == "kea failure":
                        self.assertEqual(rejection.diagnostics, ("Kea replied: lease database unavailable",))

    def test_a_read_timeout_after_the_send_is_unknown(self):
        for operation in _OPERATIONS:
            for failure in (requests.ReadTimeout("read timed out"), _reset_during_reply()):
                with self.subTest(operation.name, failure=type(failure).__name__):
                    outcome, commands = self._result(operation, failure)
                    self.assertEqual(outcome.application, "unknown")
                    self.assertEqual(outcome.diagnostics, (_LOST,))
                    self.assertEqual(commands, [*operation.before, operation.write])

    def test_an_encode_failure_after_the_send_is_unknown(self):
        """requests sent the write, then failed to encode the .netrc credentials of the redirect target (ADR 0011)."""
        self.server.ca_url = "http://kea.example.invalid/"
        with redirect_to_netrc_host() as sent:
            outcome = runtime_change.enable_dhcp(self.server, 4)
        self.assertEqual(len(sent), 1)
        self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", (_LOST,)))

    def test_a_malformed_reply_is_unknown(self):
        for operation in _OPERATIONS:
            for name, reply in (("two entries", [{"result": 0}, {"result": 0}]), ("empty", [])):
                with self.subTest(operation.name, reply=name):
                    outcome, commands = self._result(operation, reply)
                    self.assertEqual(outcome.application, "unknown")
                    self.assertEqual(outcome.diagnostics, (_LOST,))
                    self.assertEqual(commands, [*operation.before, operation.write])

    def test_result_2_in_a_reply_of_two_entries_is_unknown(self):
        """Result 2 is a rejection only in a well-formed reply; this reply is malformed (ADR 0011)."""
        for operation in _OPERATIONS:
            for reply in (
                [{"result": 0, "text": "done"}, {"result": 2, "text": "not supported"}],
                [{"result": 2, "text": "not supported"}, {"result": 0, "text": "done"}],
            ):
                with self.subTest(operation.name, first=reply[0]["result"]):
                    outcome, commands = self._result(operation, reply)
                    self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", (_LOST,)))
                    self.assertEqual(commands, [*operation.before, operation.write])

    def test_a_recorded_control_agent_forward_failure_is_unknown(self):
        recorded = _forward_failure(4)
        for operation in _OPERATIONS:
            with self.subTest(operation.name):
                outcome, commands = self._result(operation, recorded)
                self.assertEqual(outcome.application, "unknown")
                self.assertEqual(outcome.diagnostics, (f"Kea replied: {recorded['text']}",))
                self.assertEqual(commands, [*operation.before, operation.write])

    def test_result_5_is_unknown(self):
        for operation in _OPERATIONS:
            with self.subTest(operation.name):
                outcome, _commands = self._result(operation, {"result": 5, "text": "fatal"})
                self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", ("Kea replied: fatal",)))

    def test_result_1_on_a_lease_write_is_unknown_with_kea_text(self):
        failure = {"result": 1, "text": "Lease for address 192.0.2.50 already exists."}
        for operation in _LEASE_WRITES:
            with self.subTest(operation.name):
                outcome, commands = self._result(operation, failure)
                self.assertEqual(outcome.application, "unknown")
                self.assertEqual(outcome.diagnostics, ("Kea replied: Lease for address 192.0.2.50 already exists.",))
                self.assertEqual(commands, [*operation.before, operation.write])

    def test_result_2_is_a_rejection_for_every_operation(self):
        """Kea runs no handler for a command that its hooks do not support (ADR 0011)."""
        for operation in _OPERATIONS:
            with self.subTest(operation.name):
                responses = operation.responses({"result": 2, "text": f"'{operation.write}' command not supported."})
                rejection, commands = self._rejection(operation, responses)
                self.assertEqual(rejection.reason, "kea-rejected")
                self.assertEqual(
                    rejection.diagnostics,
                    (f"{_HOOK_NOT_LOADED} Kea replied: '{operation.write}' command not supported.",),
                )
                self.assertEqual(commands, [*operation.before, operation.write])

    def test_result_128_on_a_lease_write_shows_the_guidance_and_kea_reply(self):
        for operation in _LEASE_WRITES:
            with self.subTest(operation.name):
                outcome, _commands = self._result(operation, {"result": 128, "text": "Connection refused"})
                self.assertEqual(outcome.application, "unknown")
                self.assertEqual(
                    outcome.diagnostics,
                    (
                        (
                            "Cannot reach the Kea daemon. Check that the service is running and the server URL is reachable. "
                            "Kea replied: Connection refused"
                        ),
                    ),
                )

    def test_result_1_on_a_service_change_is_a_rejection_with_kea_text(self):
        for operation in _SERVICE_CHANGES:
            with self.subTest(operation.name):
                responses = operation.responses({"result": 1, "text": "max-period must be positive"})
                rejection, commands = self._rejection(operation, responses)
                self.assertEqual(rejection.reason, "kea-rejected")
                self.assertEqual(rejection.diagnostics, ("Kea replied: max-period must be positive",))
                self.assertEqual(commands, [operation.write])

    def test_the_forwarding_text_from_a_direct_daemon_is_an_ordinary_failure(self):
        self.server.has_control_agent = False
        recorded = _forward_failure(4)
        for operation in _SERVICE_CHANGES:
            with self.subTest(operation.name):
                rejection, _commands = self._rejection(operation, operation.responses(recorded))
                self.assertEqual(rejection.reason, "kea-rejected")

    def test_an_invalid_client_configuration_sends_nothing(self):
        self.server.client_cert_path = "/etc/kea/client.pem"
        for operation in _OPERATIONS:
            with self.subTest(operation.name):
                rejection, commands = self._rejection(operation, operation.responses({"result": 0}))
                self.assertEqual(rejection.reason, "invalid-client-configuration")
                self.assertEqual(commands, [])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class LeaseTargetTests(TestCase):
    """A Lease edit or delete changes only the Lease that the page showed (ADR 0011, target-changed)."""

    def setUp(self):
        self.server = _make_db_server()

    def _rejection(self, run: Callable[[], Any], daemon: LeaseDaemon) -> tuple[ChangeRejected, list[str]]:
        with stub_kea(daemon.responses()) as kea, self.assertRaises(ChangeRejected) as raised:
            run()
        return raised.exception, kea.commands()

    def test_an_edit_sends_the_fresh_body_with_only_the_written_field_changed(self):
        shown = shown_lease(typed_lease(_PREFIX))
        daemon = LeaseDaemon(6, _PREFIX)
        with stub_kea(daemon.responses()) as kea:
            outcome = runtime_change.edit_lease(self.server, 6, shown, _RENAME)

        self.assertEqual(outcome, RuntimeChangeOutcome("applied"))
        self.assertEqual(kea.commands(), ["lease6-get", "lease6-update"])
        self.assertEqual(
            kea.bodies("lease6-get")[0]["arguments"], {"ip-address": "2001:db8:100:600::", "type": "IA_PD"}
        )
        expire = _PREFIX["cltt"] + _PREFIX["valid-lft"]
        sent = kea.bodies("lease6-update")[0]["arguments"]
        self.assertEqual(sent, {**_PREFIX, "hostname": "renamed.example.org", "expire": expire})
        self.assertNotIn("force-create", sent)

    def test_a_delete_returns_the_lease_that_the_fresh_read_observed(self):
        shown = shown_lease(typed_lease(_PREFIX))
        daemon = LeaseDaemon(6, _PREFIX)
        with stub_kea(daemon.responses()) as kea:
            outcome = runtime_change.delete_lease(self.server, 6, shown)

        self.assertEqual(outcome, LeaseDeleteOutcome("applied", lease=typed_lease(_PREFIX)))
        self.assertEqual(
            kea.bodies("lease6-del")[0]["arguments"], {"ip-address": "2001:db8:100:600::", "type": "IA_PD"}
        )
        self.assertEqual(daemon.leases, {})

    def test_a_fresh_read_that_contradicts_the_shown_lease_is_target_changed(self):
        shown = shown_lease(typed_lease(_PREFIX))
        cases = {
            "client binding": {"iaid": 31},
            "Subnet": {"subnet-id": 11},
            "prefix length": {"prefix-len": 60},
            "hostname": {"hostname": "changed.example.org"},
        }
        for words, change in cases.items():
            with self.subTest(words):
                daemon = LeaseDaemon(6, {**_PREFIX, **change})
                rejection, commands = self._rejection(
                    lambda: runtime_change.edit_lease(self.server, 6, shown, _RENAME), daemon
                )
                self.assertEqual(rejection.reason, "target-changed")
                self.assertEqual(
                    rejection.diagnostics,
                    (f"Its {words} changed in Kea after the form was shown. Reload the form and try again.",),
                )
                self.assertEqual(commands, ["lease6-get"])

    def test_a_delete_compares_the_binding_but_not_the_hostname(self):
        daemon = LeaseDaemon(4, {**_LEASE, "hostname": "renamed-by-dhcp.example.org"})
        with stub_kea(daemon.responses()) as kea:
            outcome = runtime_change.delete_lease(self.server, 4, _SHOWN)
        self.assertEqual(outcome.application, "applied")
        self.assertEqual(kea.commands(), ["lease4-get", "lease4-del"])

        daemon = LeaseDaemon(4, {**_LEASE, "hw-address": "08:08:08:08:08:09"})
        rejection, commands = self._rejection(lambda: runtime_change.delete_lease(self.server, 4, _SHOWN), daemon)
        self.assertEqual(rejection.reason, "target-changed")
        self.assertEqual(
            rejection.diagnostics,
            ("Its client binding changed in Kea after the list was shown. Reload the list and try again.",),
        )
        self.assertEqual(commands, ["lease4-get"])

    def test_a_lease_that_is_gone_before_the_send_is_target_changed_and_not_created_again(self):
        for name, run in (
            ("edit", lambda: runtime_change.edit_lease(self.server, 4, _SHOWN, _RENAME)),
            ("delete", lambda: runtime_change.delete_lease(self.server, 4, _SHOWN)),
        ):
            with self.subTest(name):
                rejection, commands = self._rejection(run, LeaseDaemon(4))
                self.assertEqual(rejection.reason, "target-changed")
                self.assertEqual(rejection.diagnostics[0], "Kea no longer holds it.")
                self.assertEqual(commands, ["lease4-get"])

    def test_result_3_on_lease_del_is_target_changed(self):
        daemon = LeaseDaemon(4, _LEASE)
        daemon.before("lease4-del", lambda held: held.leases.clear())
        rejection, commands = self._rejection(lambda: runtime_change.delete_lease(self.server, 4, _SHOWN), daemon)
        self.assertEqual(rejection.reason, "target-changed")
        self.assertEqual(rejection.diagnostics, ("Kea reports that it no longer holds it.",))
        self.assertEqual(commands, ["lease4-get", "lease4-del"])

    def test_result_4_on_lease_update_is_target_changed(self):
        daemon = LeaseDaemon(4, _LEASE)
        daemon.before("lease4-update", lambda held: held.leases.clear())
        rejection, commands = self._rejection(
            lambda: runtime_change.edit_lease(self.server, 4, _SHOWN, _RENAME), daemon
        )
        self.assertEqual(rejection.reason, "target-changed")
        self.assertEqual(
            rejection.diagnostics,
            ("Kea reports that it was deleted or changed after the check. Reload the form and try again.",),
        )
        self.assertEqual(commands, ["lease4-get", "lease4-update"])
        self.assertEqual(daemon.leases, {})

    def test_a_fresh_read_with_an_unreadable_lease_is_not_sent(self):
        malformed = {"result": 0, "text": "IPv4 lease found.", "arguments": {**_LEASE, "state": "assigned"}}
        for name, run in (
            ("edit", lambda: runtime_change.edit_lease(self.server, 4, _SHOWN, _RENAME)),
            ("delete", lambda: runtime_change.delete_lease(self.server, 4, _SHOWN)),
        ):
            with self.subTest(name), stub_kea({"lease4-get": malformed}) as kea:
                with self.assertRaises(ChangeRejected) as raised:
                    run()
                self.assertEqual(raised.exception.reason, "not-sent")
                self.assertEqual(raised.exception.diagnostics, ("Kea returned a lease that could not be read.",))
                self.assertEqual(kea.commands(), ["lease4-get"])

    def test_an_edit_that_writes_nothing_is_refused_before_kea(self):
        with stub_kea({}) as kea, self.assertRaises(ValueError):
            runtime_change.edit_lease(self.server, 4, _SHOWN, LeaseEdit())
        self.assertEqual(kea.commands(), [])

    def test_an_operation_refuses_a_lease_of_another_family(self):
        with stub_kea({}) as kea:
            for run in (
                lambda: runtime_change.add_lease(self.server, 6, _CREATION),
                lambda: runtime_change.edit_lease(self.server, 6, _SHOWN, _RENAME),
                lambda: runtime_change.delete_lease(self.server, 6, _SHOWN),
            ):
                with self.assertRaises(ValueError):
                    run()
        self.assertEqual(kea.commands(), [])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class SentArgumentsTests(TestCase):
    """The operations send the arguments of the request, and nothing after the write."""

    def setUp(self):
        self.server = _make_db_server()

    def test_an_add_sends_only_the_facts_of_the_request(self):
        daemon = LeaseDaemon(4)
        with stub_kea(daemon.responses()) as kea:
            outcome = runtime_change.add_lease(self.server, 4, _CREATION)
        self.assertEqual(outcome, RuntimeChangeOutcome("applied"))
        self.assertEqual(
            kea.bodies("lease4-add")[0]["arguments"], {"ip-address": "192.0.2.50", "hw-address": "aa:bb:cc:00:00:50"}
        )
        self.assertIsNotNone(daemon.lease("192.0.2.50"))

    def test_a_wipe_of_an_empty_subnet_is_applied(self):
        with stub_kea({"lease6-wipe": {"result": 3, "text": "Deleted 0 IPv6 lease(s) from subnet(s) 7"}}) as kea:
            outcome = runtime_change.wipe_leases(self.server, 6, 7)
        self.assertEqual(outcome, RuntimeChangeOutcome("applied"))
        self.assertEqual(kea.bodies("lease6-wipe")[0]["arguments"], {"subnet-id": 7})

    def test_a_disable_sends_its_max_period(self):
        with stub_kea({"dhcp-disable": {"result": 0, "text": "DHCPv6 service disabled for 300 seconds"}}) as kea:
            outcome = runtime_change.disable_dhcp(self.server, 6, 300)
        self.assertEqual(outcome, RuntimeChangeOutcome("applied"))
        self.assertEqual(
            kea.bodies("dhcp-disable")[0],
            {"command": "dhcp-disable", "service": ["dhcp6"], "arguments": {"max-period": 300}},
        )


class _RedirectingKea(BaseHTTPRequestHandler):
    """A web server that answers a command with HTTP 303 and would answer the redirect target with a success."""

    paths: list[str]

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["Content-Length"]))
        self.paths.append(f"POST {self.path}")
        self.send_response(303)
        self.send_header("Location", "/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self.paths.append(f"GET {self.path}")
        body = json.dumps([{"result": 0, "text": "done"}]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Keep the test output clean."""


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class RedirectTests(TestCase):
    """NetBox does not follow a redirect for a command: the target cannot say what the first request did (ADR 0011)."""

    def test_a_redirect_answer_is_unknown_and_sends_no_second_request(self):
        handler = type("Handler", (_RedirectingKea,), {"paths": []})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        kea = _make_db_server(ca_url=f"http://127.0.0.1:{server.server_address[1]}/")

        outcome = runtime_change.enable_dhcp(kea, 4)

        self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", (_LOST,)))
        self.assertEqual(handler.paths, ["POST /"])

    def test_a_redirect_answer_through_the_stub_is_unknown(self):
        server = _make_db_server()
        for operation in _OPERATIONS:
            with self.subTest(operation.name):
                reply = _http_response([{"result": 0, "text": "done"}], status=303)
                with stub_kea(operation.responses(reply)) as kea:
                    outcome = operation.run(server)
                self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", (_LOST,)))
                self.assertEqual(kea.commands(), [*operation.before, operation.write])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class RetryTests(TestCase):
    """A command is sent once: a retry after the bytes left NetBox would hide that Kea received the first one."""

    def test_the_client_session_never_retries(self):
        client = _make_db_server().get_client(version=4)
        self.addCleanup(client.close)
        # requests' default adapter: Retry(0, read=False). The client mounts no other adapter.
        self.assertEqual([adapter.max_retries.total for adapter in client._session.adapters.values()], [0, 0])

    def test_a_connection_dropped_after_the_send_is_unknown_and_not_sent_again(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(5)
        self.addCleanup(listener.close)
        received: list[bytes] = []

        def drop_after_the_request() -> None:
            connection, _address = listener.accept()
            received.append(connection.recv(65536))
            connection.close()
            # A retry would open a second connection here.
            with suppress(OSError):
                second, _address = listener.accept()
                received.append(second.recv(65536))
                second.close()

        thread = threading.Thread(target=drop_after_the_request, daemon=True)
        thread.start()
        kea = _make_db_server(ca_url=f"http://127.0.0.1:{listener.getsockname()[1]}/")

        outcome = runtime_change.enable_dhcp(kea, 4)
        thread.join(timeout=10)

        self.assertEqual((outcome.application, outcome.diagnostics), ("unknown", (_LOST,)))
        self.assertEqual(len(received), 1)
        self.assertTrue(received[0].startswith(b"POST / "), received[0])
