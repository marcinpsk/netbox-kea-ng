# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-change-mapper-outside-base. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
# The rule excludes views/_base.py by path, which `opengrep test` does not apply, so every mapper here is flagged.
from netbox_kea.change_outcome import ChangeRejected


# ruleid: kea-change-mapper-outside-base
def _run_change(request, confirmed, change):
    try:
        outcome = change()
    # ok: kea-change-rejection-caught-outside-mapper
    except ChangeRejected as rejection:
        messages.error(request, rejection.reason)
        return None
    return outcome


# ok: kea-change-mapper-outside-base
def _run_subnet_change(request, change):
    return _run_change(request, "Saved.", change)
