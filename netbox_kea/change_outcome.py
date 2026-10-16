# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Application rules that Configuration Changes and Runtime Changes share (ADR 0005, ADR 0011).

A change is applied, unknown, or rejected. ``ChangeRejected`` is the rejection: the change is not live, as far as
NetBox can tell. ``before_change`` runs a step before the change, and ``mutate`` sends the change and classifies
what Kea did with it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Literal, TypeVar

import requests
from urllib3.exceptions import MaxRetryError, NewConnectionError

from .constants import Family
from .kea import KeaClient, KeaException, KeaTLSFileError, kea_error_message

if TYPE_CHECKING:
    from .models import Server

logger = logging.getLogger(__name__)

Application = Literal["applied", "unknown"]
RejectionReason = Literal[
    "kea-rejected", "config-test-rejected", "not-sent", "invalid-client-configuration", "target-changed"
]

# Kea result 5: Kea could not return to a working configuration.
_RESULT_FATAL = 5

READ_UNUSABLE = "Kea did not return a usable reply to the read before the change."
_REPLY_LOST = "Kea's reply to the change was lost or unreadable."

T = TypeVar("T")


class ChangeRejected(Exception):
    """A change that is not live, as far as NetBox can tell."""

    def __init__(self, reason: RejectionReason, diagnostics: tuple[str, ...]) -> None:
        """Keep the reason and the diagnostics that explain it."""
        super().__init__(reason, *diagnostics)
        self.reason = reason
        self.diagnostics = diagnostics


def build_client(server: Server, family: Family) -> KeaClient:
    """Return the client of *server* for *family*. A client that cannot be built means that the change was not sent."""
    try:
        return server.get_client(version=family)
    except ValueError as exc:
        logger.warning("Could not build a DHCPv%s client for Server %s", family, server.pk, exc_info=True)
        raise ChangeRejected(
            "invalid-client-configuration",
            ("NetBox could not build a Kea client from the Server connection settings.",),
        ) from exc


def read_before(read: Callable[[], T]) -> T:
    """Run the read that comes before the change. A failure means that the change was not sent."""
    return before_change(read, READ_UNUSABLE)


def before_change(step: Callable[[], T], unusable: str) -> T:
    """Run a step before the change. A failure means that the change was not sent; *unusable* explains a bad reply."""
    try:
        return step()
    except KeaException as exc:
        logger.warning("A step before a change failed: %s", exc)
        raise ChangeRejected("not-sent", (kea_error_message(exc),)) from exc
    except KeaTLSFileError as exc:
        raise _missing_tls_file(exc) from exc
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        logger.warning("A step before a change failed", exc_info=True)
        raise ChangeRejected("not-sent", (unusable,)) from exc


#: What a failure result of the change means: "reject" (the change is not live), "unknown", or a check read that
#: returns whether the failed command left the target unchanged (ADR 0005).
FailurePolicy = Literal["reject", "unknown"] | Callable[[], bool]


def mutate(
    client: KeaClient, family: Family, send: Callable[[], None], *, on_failure: FailurePolicy
) -> tuple[Application, tuple[str, ...]]:
    """Send one command that can change Kea, and classify what Kea did with it.

    A lost reply, a Control Agent forward failure and result 5 are unknown whatever *on_failure* says.
    """
    try:
        send()
    except KeaException as exc:
        logger.warning("A change failed: %s", exc)
        diagnostic = kea_error_message(exc)
        if exc.response.get("result") == _RESULT_FATAL or client.forwarding_failed(exc, family):
            return "unknown", (diagnostic,)
        if on_failure == "reject":
            raise ChangeRejected("kea-rejected", (diagnostic,)) from exc
        if isinstance(on_failure, str):
            return "unknown", (diagnostic,)
        try:
            unchanged = on_failure()
        except (KeaException, OSError, ValueError, RuntimeError):
            logger.warning("The check read after a failed change failed", exc_info=True)
            return "unknown", (diagnostic, "The read after the failure did not succeed.")
        if unchanged:
            raise ChangeRejected("kea-rejected", (diagnostic,)) from exc
        return "unknown", (diagnostic, "The read after the failure shows the change.")
    except KeaTLSFileError as exc:
        raise _missing_tls_file(exc) from exc
    except requests.RequestException as exc:
        if never_sent(exc):
            logger.warning("A change could not connect to Kea", exc_info=True)
            raise ChangeRejected("not-sent", ("Kea could not be reached.",)) from exc
        logger.warning("The reply to a change was lost or unreadable", exc_info=True)
        return "unknown", (_REPLY_LOST,)
    except (ValueError, RuntimeError):
        logger.warning("The reply to a change was malformed", exc_info=True)
        return "unknown", (_REPLY_LOST,)
    return "applied", ()


def never_sent(exc: requests.RequestException) -> bool:
    """Return whether the request failed while it connected, before any byte reached Kea."""
    if isinstance(exc, requests.ConnectTimeout):
        return True
    if not isinstance(exc, requests.ConnectionError):
        return False
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        if isinstance(current, NewConnectionError):
            return True
        # requests passes urllib3's MaxRetryError as an argument, not as the cause.
        pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        if isinstance(current, MaxRetryError) and current.reason is not None:
            pending.append(current.reason)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return False


def _missing_tls_file(exc: KeaTLSFileError) -> ChangeRejected:
    """Return the rejection for a TLS file that requests could not find before it sent anything."""
    logger.warning("A TLS file of the Server is missing", exc_info=exc)
    return ChangeRejected(
        "invalid-client-configuration", ("A TLS certificate, key or CA file of the Server could not be found.",)
    )
