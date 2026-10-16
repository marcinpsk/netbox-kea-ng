# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Runtime Change outcomes of ``runtime_change``, through a real Server and a real ``KeaClient`` (ADR 0011).

Only ``requests.Session.post`` is stubbed. Each test asserts the commands that reached Kea, because no operation
may read Kea after the send to classify the change.
"""

import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass
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

from .kea_stub import LeaseDaemon, _refused_connection, stub_kea, typed_lease
from .utils import _make_db_server, with_kea_client_config

_RECORDINGS = Path(__file__).with_name("kea_recordings")
_CONTROL_AGENT = json.loads((_RECORDINGS / "control-agent.json").read_text())
_LEASE = json.loads((_RECORDINGS / "dhcp4.json").read_text())["leases"]["changes"]["before"]["arguments"]
_PREFIX = json.loads((_RECORDINGS / "dhcp6.json").read_text())["leases"]["changes"]["before"]["arguments"]
_SHOWN = shown_lease(typed_lease(_LEASE))
_CREATION = DHCPv4LeaseRequest(address=ipaddress.IPv4Address("192.0.2.50"), hw_address="aa:bb:cc:00:00:50")
_RENAME = LeaseEdit(hostname="renamed.example.org")
_LOST = "Kea's reply to the change was lost or unreadable."


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

    def test_a_malformed_reply_is_unknown(self):
        for operation in _OPERATIONS:
            for name, reply in (("two entries", [{"result": 0}, {"result": 0}]), ("empty", [])):
                with self.subTest(operation.name, reply=name):
                    outcome, commands = self._result(operation, reply)
                    self.assertEqual(outcome.application, "unknown")
                    self.assertEqual(outcome.diagnostics, (_LOST,))
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

    def test_result_128_on_a_lease_write_shows_the_fixed_guidance(self):
        for operation in _LEASE_WRITES:
            with self.subTest(operation.name):
                outcome, _commands = self._result(operation, {"result": 128, "text": "Connection refused"})
                self.assertEqual(outcome.application, "unknown")
                self.assertEqual(
                    outcome.diagnostics,
                    (
                        "Cannot reach the Kea daemon. Check that the service is running and the server URL is reachable.",
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
