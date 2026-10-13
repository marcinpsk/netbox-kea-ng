# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The read age line of a cached table and its Refresh control (ADR 0009, ``inc/read_age.html``)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from django.http import HttpRequest
from django.utils import timezone

#: The request header of the Refresh control. A page that gets it reads Kea live and replaces its cached entries.
REFRESH_HEADER = "X-Kea-Refresh"


def refresh_requested(request: HttpRequest) -> bool:
    """Return whether the request comes from the Refresh control."""
    return request.headers.get(REFRESH_HEADER) == "true"


def read_age_context(read_started: datetime | None) -> dict[str, Any]:
    """Return the template context of the read age line: the whole seconds since *read_started*, or ``None``."""
    age = None if read_started is None else max(0, int((timezone.now() - read_started).total_seconds()))
    return {"read_age": age, "refresh_headers": json.dumps({REFRESH_HEADER: "true"})}
