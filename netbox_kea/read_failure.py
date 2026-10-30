# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one classifier of a failed Kea read, the read-side twin of ``change_outcome`` (ADR 0015).

:func:`attempt` runs a read and returns its value, or a :class:`ReadFailure` with the kind of the failure. It writes
the one log line of the failure. A caller maps the kind to its own presentation and catches nothing itself.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, TypeVar

import requests

from .kea import KeaClientSettingsError, KeaException, kea_error_message
from .malformed import MalformedKeaReply

logger = logging.getLogger(__name__)

#: ``unsupported``: Kea does not provide the command, because its hook library is not loaded.
#: ``refused``: Kea answered with another failure result.
#: ``unreachable``: the transport, a TLS file or the credential encoding failed, so nothing usable came back.
#: ``malformed``: Kea answered, but NetBox cannot use the reply or a record in it.
#: ``misconfigured``: the client settings of the Server are not valid, so nothing was sent.
ReadFailureKind = Literal["unsupported", "refused", "unreachable", "malformed", "misconfigured"]

T = TypeVar("T")


@dataclass(frozen=True)
class ReadFailure:
    """One failed Kea read: its kind, Kea's answer, and the label of the read."""

    kind: ReadFailureKind
    #: What the caller read, for example "DHCPv4 Reservations of Server 3".
    label: str
    #: Kea's answer with operator guidance (``kea_error_message()``) for ``unsupported`` and ``refused``, else empty.
    reply: str = ""


def attempt(label: str, read: Callable[[], T]) -> T | ReadFailure:
    """Run *read* and return its value, or the :class:`ReadFailure` of a Kea, transport, reply or settings failure.

    Every other exception, such as a refused Lease query (``LeaseQueryGuardError``) or a ``ValueError``, raises.
    """
    try:
        return read()
    except KeaException as exc:
        if exc.unsupported_command:
            logger.info("%s failed (unsupported): %s", label, exc)
            return ReadFailure("unsupported", label, kea_error_message(exc))
        logger.warning("%s failed (refused)", label, exc_info=True)
        return ReadFailure("refused", label, kea_error_message(exc))
    except requests.RequestException:
        logger.warning("%s failed (unreachable)", label, exc_info=True)
        return ReadFailure("unreachable", label)
    except MalformedKeaReply:
        logger.warning("%s failed (malformed)", label, exc_info=True)
        return ReadFailure("malformed", label)
    except KeaClientSettingsError as exc:
        logger.warning("%s failed (misconfigured): %s", label, exc)
        return ReadFailure("misconfigured", label)
