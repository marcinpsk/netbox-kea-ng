# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one classifier of a failed Kea read (ADR 0015), through a real KeaClient with only the HTTP send stubbed."""

import logging
from collections.abc import Callable
from typing import Any
from unittest import TestCase

import requests

from netbox_kea.kea import KeaCommand, LeaseQueryGuardError, LeaseQueryTooBroad
from netbox_kea.read_failure import ReadFailure, attempt
from netbox_kea.tests.kea_stub import _raw_http_response, kea_client, stub_kea

_URL = "http://kea.example.invalid:8000"


def _config_get(**options: Any) -> Callable[[], object]:
    """Return a read that builds a client with *options* and sends ``config-get``."""
    return lambda: kea_client(_URL, **options).command(KeaCommand.CONFIG_GET, 4)


class AttemptTest(TestCase):
    """Each kind comes from one real failure, with its ReadFailure and its one log line."""

    def test_each_failure_gives_its_kind_and_log_level(self):
        cases = (
            (
                "an error result",
                {"result": 1, "text": "Configuration not found"},
                {},
                ReadFailure("refused", "The read", "Kea replied: Configuration not found"),
                logging.WARNING,
                True,
            ),
            (
                "a missing hook library",
                {"result": 2, "text": "'config-get' command not supported."},
                {},
                ReadFailure(
                    "unsupported",
                    "The read",
                    "Kea does not support this command. The required hook library may not be loaded, for example"
                    " host_cmds, lease_cmds or subnet_cmds. Kea replied: 'config-get' command not supported.",
                ),
                logging.INFO,
                False,
            ),
            (
                "a connection error",
                requests.ConnectionError("Connection refused"),
                {},
                ReadFailure("unreachable", "The read"),
                logging.WARNING,
                True,
            ),
            (
                "a body that is not JSON",
                _raw_http_response(b"<html>proxy error</html>"),
                {},
                ReadFailure("malformed", "The read"),
                logging.WARNING,
                True,
            ),
            (
                "a key without a certificate",
                {"result": 0, "arguments": {}},
                {"client_key": "/tls/client.key"},
                ReadFailure("misconfigured", "The read"),
                logging.WARNING,
                False,
            ),
        )
        for name, reply, options, expected, level, traceback in cases:
            with self.subTest(name):
                with (
                    stub_kea({"config-get": reply}),
                    self.assertLogs("netbox_kea.read_failure", level=logging.DEBUG) as logs,
                ):
                    failure = attempt("The read", _config_get(**options))
                self.assertEqual(failure, expected)
                (record,) = logs.records
                self.assertEqual(record.levelno, level)
                self.assertEqual(record.exc_info is not None, traceback)
                self.assertTrue(record.getMessage().startswith(f"The read failed ({expected.kind})"))

    def test_a_read_that_succeeds_returns_its_value_and_logs_nothing(self):
        with stub_kea({"config-get": {"result": 0, "arguments": {}}}), self.assertNoLogs("netbox_kea.read_failure"):
            replies = attempt("The read", _config_get())
        self.assertEqual(replies, [{"result": 0, "arguments": {}}])

    def test_every_other_exception_raises(self):
        for error in (ValueError("a caller bug"), LeaseQueryTooBroad(10, 5)):
            with self.subTest(type(error).__name__):
                with self.assertRaises(type(error)) as raised:
                    attempt("The read", _raise(error))
                self.assertIs(raised.exception, error)
        self.assertTrue(issubclass(LeaseQueryTooBroad, LeaseQueryGuardError))


def _raise(error: Exception) -> Callable[[], object]:
    def read() -> object:
        raise error

    return read
