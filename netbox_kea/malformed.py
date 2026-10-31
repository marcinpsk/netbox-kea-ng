# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The base of every error for a Kea reply that NetBox cannot use (ADR 0015)."""


class MalformedKeaReply(Exception):
    """Kea answered, but NetBox cannot use the reply or a record in it.

    It is neither a ``RuntimeError`` nor a ``ValueError``, so a handler of those never takes a malformed reply for a
    bug, and a bug never reads as a malformed reply.
    """
