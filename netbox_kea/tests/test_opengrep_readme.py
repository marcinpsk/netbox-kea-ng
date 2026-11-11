# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""scripts/opengrep_readme.py on the repository and on a temporary copy of the ruleset."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "opengrep_readme.py"
FIRST_RULE = "kea-row-return-url-empty-fallback"


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT, "--root", root, *args], capture_output=True, text=True, timeout=60, check=False
    )


def _copy(root: Path, **first_rule) -> Path:
    """Copy the ruleset and the README into *root*, with *first_rule* set on the first rule."""
    (root / ".opengrep").mkdir()
    shutil.copy(REPOSITORY_ROOT / ".opengrep" / "README.md", root / ".opengrep" / "README.md")
    ruleset = yaml.safe_load((REPOSITORY_ROOT / ".opengrep" / "kea-rules.yaml").read_text(encoding="utf-8"))
    ruleset["rules"][0].update(first_rule)
    (root / ".opengrep" / "kea-rules.yaml").write_text(yaml.safe_dump(ruleset), encoding="utf-8")
    return root


def _row(root: Path, rule_id: str) -> str:
    readme = (root / ".opengrep" / "README.md").read_text(encoding="utf-8")
    return next(line for line in readme.splitlines() if line.startswith(f"| `{rule_id}` |"))


def test_the_readme_rules_table_matches_the_ruleset():
    result = _run(REPOSITORY_ROOT, "--check")

    assert result.returncode == 0, result.stderr


def test_a_changed_message_makes_the_check_fail_until_the_script_writes_the_table(tmp_path):
    root = _copy(tmp_path, message="A `new` message.")

    stale = _run(root, "--check")
    written = _run(root)

    assert (stale.returncode, stale.stderr) == (1, ".opengrep/README.md is stale: run scripts/opengrep_readme.py\n")
    assert (written.returncode, written.stderr) == (0, ".opengrep/README.md: wrote the Rules table\n")
    assert _run(root, "--check").returncode == 0
    assert (
        _row(root, FIRST_RULE)
        == f"| `{FIRST_RULE}` | error | every scanned file; not `**/tests/**` | A `new` message. |"
    )


def test_the_scope_leaves_out_the_rule_test_fixture(tmp_path):
    root = _copy(tmp_path, paths={"include": ["netbox_kea/**", f"{FIRST_RULE}.py"], "exclude": ["netbox_kea/kea.py"]})

    _run(root)

    assert _row(root, FIRST_RULE).split(" | ")[2] == "`netbox_kea/**`; not `netbox_kea/kea.py`"


def test_a_pipe_in_a_path_or_a_message_stays_in_its_cell(tmp_path):
    root = _copy(tmp_path, paths={"include": ["a|b.py"]}, message="Match `a|b`.")

    _run(root)

    assert _row(root, FIRST_RULE) == f"| `{FIRST_RULE}` | error | `a\\|b.py` | Match `a\\|b`. |"


def test_whitespace_inside_a_code_span_is_kept(tmp_path):
    root = _copy(tmp_path, message="Match `r'a  b'`.")

    _run(root)

    assert _row(root, FIRST_RULE).endswith("| Match `r'a  b'`. |")


def test_a_code_span_can_end_in_a_backslash(tmp_path):
    root = _copy(tmp_path, message="Match `path\\`.")

    _run(root)

    assert _row(root, FIRST_RULE).endswith("| Match `path\\`. |")


def test_a_marker_inside_a_message_is_not_a_marker_line(tmp_path):
    root = _copy(tmp_path, message="Use `<!-- END generated -->` here.")

    _run(root)

    assert _run(root, "--check").returncode == 0
    assert _row(root, FIRST_RULE).endswith("| Use `<!-- END generated -->` here. |")


@pytest.mark.parametrize(
    ("message", "error"),
    [
        ("Call _private() here.", "put '_' in a code span"),
        ("Call `name() here.", "the message has an unclosed code span."),
        ("Use \\`<b>\\`.", "use single unescaped backticks for a code span."),
        ("Use ``a`b``.", "use single unescaped backticks for a code span."),
    ],
)
def test_a_message_that_github_would_render_differently_is_refused(tmp_path, message, error):
    root = _copy(tmp_path, message=message)

    result = _run(root, "--check")

    assert result.returncode == 2
    assert f"error: {FIRST_RULE}: {error}" in result.stderr
