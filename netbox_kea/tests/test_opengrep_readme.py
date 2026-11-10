# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""scripts/opengrep_readme.py on the repository and on a temporary copy of the ruleset."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "opengrep_readme.py"


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT, "--root", root, *args], capture_output=True, text=True, timeout=60, check=False
    )


def _copy(root: Path, message: str | None = None) -> Path:
    """Copy the ruleset and the README into *root*; with *message*, give the first rule that message."""
    (root / ".opengrep").mkdir()
    shutil.copy(REPOSITORY_ROOT / ".opengrep" / "README.md", root / ".opengrep" / "README.md")
    ruleset = yaml.safe_load((REPOSITORY_ROOT / ".opengrep" / "kea-rules.yaml").read_text(encoding="utf-8"))
    if message is not None:
        ruleset["rules"][0]["message"] = message
    (root / ".opengrep" / "kea-rules.yaml").write_text(yaml.safe_dump(ruleset), encoding="utf-8")
    return root


def test_the_readme_rules_table_matches_the_ruleset():
    result = _run(REPOSITORY_ROOT, "--check")

    assert result.returncode == 0, result.stderr


def test_a_changed_message_makes_the_check_fail_until_the_script_writes_the_table(tmp_path):
    root = _copy(tmp_path, "A `new` message.")

    stale = _run(root, "--check")
    written = _run(root)

    assert (stale.returncode, stale.stderr) == (1, ".opengrep/README.md is stale: run scripts/opengrep_readme.py\n")
    assert written.returncode == 1
    assert _run(root, "--check").returncode == 0
    readme = (root / ".opengrep" / "README.md").read_text(encoding="utf-8")
    assert (
        "| `kea-row-return-url-empty-fallback` | error | every scanned file; not `**/tests/**` | A `new` message. |"
        in readme.splitlines()
    )


def test_the_scope_leaves_out_the_rule_test_fixture():
    readme = (REPOSITORY_ROOT / ".opengrep" / "README.md").read_text(encoding="utf-8")

    row = next(line for line in readme.splitlines() if line.startswith("| `kea-http-call-outside-client` |"))

    assert row.split(" | ")[2] == "`netbox_kea/**`; not `netbox_kea/kea.py`, `netbox_kea/tests/**`"


def test_markup_outside_a_code_span_is_refused(tmp_path):
    root = _copy(tmp_path, "Call _private() here.")

    result = _run(root, "--check")

    assert result.returncode == 2
    assert "kea-row-return-url-empty-fallback: put '_' in a code span" in result.stderr


def test_an_unclosed_code_span_is_refused(tmp_path):
    root = _copy(tmp_path, "Call `name() here.")

    result = _run(root, "--check")

    assert result.returncode == 2
    assert "kea-row-return-url-empty-fallback: the message has an unclosed code span." in result.stderr
