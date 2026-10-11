# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Run browser checks of static documentation assets without a NetBox server."""

import pytest


@pytest.fixture(scope="session", autouse=True)
def nb_api() -> None:
    """Override the integration harness API fixture, which these pages do not use."""
