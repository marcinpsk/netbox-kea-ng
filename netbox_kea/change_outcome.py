# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Application rules that Configuration Changes and Runtime Changes share (ADR 0005, ADR 0011).

A change is applied, unknown, or rejected. ``ChangeRejected`` is the rejection: the change is not live, as far as
NetBox can tell. ``before_change`` runs a step before the change, and ``mutate`` sends the change and classifies
what Kea did with it.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Callable, Iterator
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
_UNREACHABLE = "Kea could not be reached."

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

    A lost reply, a Control Agent forward failure and result 5 are unknown, and result 2 is a rejection, whatever
    *on_failure* says.
    """
    try:
        send()
    except KeaException as exc:
        logger.warning("A change failed: %s", exc)
        diagnostic = kea_error_message(exc)
        if exc.response.get("result") == _RESULT_FATAL or client.forwarding_failed(exc, family):
            return "unknown", (diagnostic,)
        # Result 2: no hook supports the command, so Kea ran no handler for it (ADR 0011).
        if on_failure == "reject" or exc.unsupported_command:
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
        reason = never_sent(exc)
        if reason is not None:
            logger.warning("A change did not reach Kea", exc_info=True)
            raise ChangeRejected("not-sent", (reason,)) from exc
        logger.warning("The reply to a change was lost or unreadable", exc_info=True)
        return "unknown", (_REPLY_LOST,)
    except (ValueError, RuntimeError):
        logger.warning("The reply to a change was malformed", exc_info=True)
        return "unknown", (_REPLY_LOST,)
    return "applied", ()


def never_sent(exc: requests.RequestException) -> str | None:
    """Return why Kea did not run the request, or None when Kea can have run it.

    Kea did not run it when the connection failed, NetBox could not verify Kea's TLS certificate, the URL is not
    valid, or the web server in front of Kea refused the credentials with HTTP 401 (ADR 0011).
    """
    if isinstance(
        exc, (requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema, requests.exceptions.MissingSchema)
    ):
        return "The URL of the Server is not valid."
    if isinstance(exc, requests.HTTPError) and exc.response is not None and exc.response.status_code == 401:
        return "Kea refused the credentials (HTTP 401). Check the user name and password of the Server."
    if isinstance(exc, requests.ConnectTimeout):
        return _UNREACHABLE
    if not isinstance(exc, requests.ConnectionError):
        return None
    for current in _causes(exc):
        if isinstance(current, NewConnectionError):
            return _UNREACHABLE
        if isinstance(current, ssl.SSLCertVerificationError):
            return "NetBox could not verify the TLS certificate of Kea. Check the TLS settings of the Server."
    return None


def _causes(exc: BaseException) -> Iterator[BaseException]:
    """Yield *exc* and each error that it wraps, through urllib3's MaxRetryError too."""
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        yield current
        # requests passes urllib3's MaxRetryError as an argument, not as the cause.
        pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        if isinstance(current, MaxRetryError) and current.reason is not None:
            pending.append(current.reason)
        if current.__cause__ is not None:
            pending.append(current.__cause__)


def _missing_tls_file(exc: KeaTLSFileError) -> ChangeRejected:
    """Return the rejection for a TLS file that requests could not find before it sent anything."""
    logger.warning("A TLS file of the Server is missing", exc_info=exc)
    return ChangeRejected(
        "invalid-client-configuration", ("A TLS certificate, key or CA file of the Server could not be found.",)
    )
