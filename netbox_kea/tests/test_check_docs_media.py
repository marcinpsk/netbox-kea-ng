# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""scripts/check_docs_media.py on a temporary documentation tree."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "check_docs_media.py"
_PNG = b"\x89PNG\r\n\x1a\n"


def _docs_tree(root: Path, pages: dict[str, str], screenshots: tuple[str, ...]) -> Path:
    docs = root / "guide"
    for name, text in pages.items():
        (docs / name).parent.mkdir(parents=True, exist_ok=True)
        (docs / name).write_text(text, encoding="utf-8")
    for name in screenshots:
        image = docs / "assets" / "screenshots" / name
        image.parent.mkdir(parents=True, exist_ok=True)
        image.write_bytes(_PNG)
    return docs


def _check(docs: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(docs)], capture_output=True, text=True, timeout=30, check=False
    )


_PAGE = (
    "# Leases\n\n"
    "![The lease table](assets/screenshots/leases-light.png#only-light)\n"
    "![The lease table](assets/screenshots/leases-dark.png#only-dark)\n"
)


def test_a_tree_whose_pages_and_screenshots_match_passes(tmp_path: Path) -> None:
    docs = _docs_tree(
        tmp_path,
        {"leases.md": _PAGE, "sub/other.md": '![Logo](../assets/logo.png)\n![Remote](https://example.com/a.png "t")\n'},
        ("leases-light.png", "leases-dark.png"),
    )

    result = _check(docs)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "2 referenced screenshots exist, and each has a page.\n"


def test_a_page_that_refers_to_a_missing_screenshot_fails(tmp_path: Path) -> None:
    docs = _docs_tree(tmp_path, {"leases.md": _PAGE}, ("leases-light.png",))

    result = _check(docs)

    assert result.returncode == 1
    assert result.stderr == "missing: leases-dark.png (referenced by leases.md)\n"


def test_a_screenshot_that_no_page_refers_to_fails(tmp_path: Path) -> None:
    docs = _docs_tree(tmp_path, {"leases.md": _PAGE}, ("leases-light.png", "leases-dark.png", "subnets-light.png"))

    result = _check(docs)

    assert result.returncode == 1
    assert result.stderr == "unreferenced: subnets-light.png\n"


def test_a_screenshot_in_a_subdirectory_counts_as_captured(tmp_path: Path) -> None:
    docs = _docs_tree(tmp_path, {"index.md": "# Home\n"}, ("old/leases-light.png",))

    result = _check(docs)

    assert result.returncode == 1
    assert result.stderr == "unreferenced: old/leases-light.png\n"


def test_a_documentation_directory_that_does_not_exist_is_a_usage_error(tmp_path: Path) -> None:
    result = _check(tmp_path / "missing")

    assert result.returncode == 2
    assert "is not a directory" in result.stderr
