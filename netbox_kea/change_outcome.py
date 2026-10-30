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
from .kea import KeaClient, KeaException, KeaRequestEncodingError, KeaTLSFileError, kea_error_message
from .malformed import MalformedKeaReply
from .read_failure import ReadFailure, attempt

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
    client = attempt(f"The DHCPv{family} client of Server {server.pk}", lambda: server.get_client(version=family))
    if isinstance(client, ReadFailure):
        raise ChangeRejected(
            "invalid-client-configuration",
            ("NetBox could not build a Kea client from the Server connection settings.",),
        )
    return client


def read_before(read: Callable[[], T]) -> T:
    """Run the read that comes before the change. A failure means that the change was not sent."""
    return before_change(read, READ_UNUSABLE)


def before_change(step: Callable[[], T], unusable: str) -> T:
    """Run a step that sends a Kea command before the change. A failure means that the change was not sent.

    Kea's answer explains a refusal, *unusable* explains every other failure, and a TLS file or credential failure is
    an invalid client configuration.
    """

    def settings_checked() -> T:
        try:
            return step()
        except (KeaTLSFileError, KeaRequestEncodingError) as exc:
            raise _client_setting_failure(exc) from exc

    result = attempt("A step before a change", settings_checked)
    if isinstance(result, ReadFailure):
        raise ChangeRejected("not-sent", (result.reply or unusable,))
    return result


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
        # A check read can also raise CatalogueUnavailable, a RuntimeError, when its observation is incomplete.
        except (KeaException, OSError, MalformedKeaReply, ValueError, RuntimeError):
            logger.warning("The check read after a failed change failed", exc_info=True)
            return "unknown", (diagnostic, "The read after the failure did not succeed.")
        if unchanged:
            raise ChangeRejected("kea-rejected", (diagnostic,)) from exc
        return "unknown", (diagnostic, "The read after the failure shows the change.")
    except (KeaTLSFileError, KeaRequestEncodingError) as exc:
        raise _client_setting_failure(exc) from exc
    except requests.RequestException as exc:
        reason = never_sent(exc)
        if reason is not None:
            logger.warning("A change did not reach Kea", exc_info=True)
            raise ChangeRejected("not-sent", (reason,)) from exc
        logger.warning("The reply to a change was lost or unreadable", exc_info=True)
        return "unknown", (_tls_failure(exc) or _REPLY_LOST,)
    except (MalformedKeaReply, ValueError, RuntimeError):
        logger.warning("The reply to a change was malformed", exc_info=True)
        return "unknown", (_REPLY_LOST,)
    return "applied", ()


def never_sent(exc: requests.RequestException) -> str | None:
    """Return why Kea did not run the request, or None when Kea can have run it.

    Kea did not run it when the connection failed, the URL is not valid, or the web server in front of Kea refused
    the credentials with HTTP 401. A TLS failure is never proof: a TLS 1.2 server can renegotiate after it received
    the command (ADR 0011).
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
    return None


def _tls_failure(exc: requests.RequestException) -> str | None:
    """Return the diagnostic of a TLS failure of the connection to Kea, or None for another failure."""
    causes = list(_causes(exc))
    if any(isinstance(current, ssl.SSLCertVerificationError) for current in causes):
        return (
            "The TLS connection to Kea failed: NetBox could not verify the certificate of Kea."
            " Check the TLS settings of the Server."
        )
    if isinstance(exc, requests.exceptions.SSLError) or any(isinstance(current, ssl.SSLError) for current in causes):
        return "The TLS connection to Kea failed. Check the TLS settings of the Server."
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


def _client_setting_failure(exc: KeaTLSFileError | KeaRequestEncodingError) -> ChangeRejected:
    """Return the rejection for a client setting that stopped requests before it sent anything."""
    logger.warning("A client setting of the Server stopped the request", exc_info=exc)
    if isinstance(exc, KeaRequestEncodingError):
        diagnostic = "NetBox cannot send the user name or password of the Server: it is not Latin-1 text."
    else:
        diagnostic = "A TLS certificate, key or CA file of the Server could not be found."
    return ChangeRejected("invalid-client-configuration", (diagnostic,))
