# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""scripts/check_docs_media.py on a temporary built site."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "check_docs_media.py"
_PNG = b"\x89PNG\r\n\x1a\n"


def _tree(root: Path, pages: dict[str, str], captured: tuple[str, ...], published: tuple[str, ...] | None = None):
    """Write the HTML pages and the PNGs of a built site, and the captured PNGs; return both directories."""
    site, shots = root / "site", root / "screenshots"
    for name, body in pages.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_text(f"<!doctype html><html><body>{body}</body></html>", encoding="utf-8")
    shots.mkdir(parents=True, exist_ok=True)
    for name in captured:
        (shots / name).write_bytes(_PNG)
    for name in captured if published is None else published:
        (site / "assets" / "screenshots" / name).parent.mkdir(parents=True, exist_ok=True)
        (site / "assets" / "screenshots" / name).write_bytes(_PNG)
    return site, shots


def _check(site: Path, shots: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(site), str(shots)], capture_output=True, text=True, timeout=30, check=False
    )


_LEASES = (
    '<img alt="Leases" src="../assets/screenshots/leases-light.png#only-light">'
    "<img alt='Leases' src='../assets/screenshots/leases-dark.png#only-dark' />"
)


def test_a_site_whose_pages_and_captures_match_passes(tmp_path: Path) -> None:
    site, shots = _tree(
        tmp_path,
        {
            "leases/index.html": _LEASES,
            "index.html": '<img src="assets/logo.png"><img src="https://example.com/a.png">',
        },
        ("leases-light.png", "leases-dark.png"),
    )

    result = _check(site, shots)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "2 screenshots on the site pages exist, and each capture is on a page.\n"


def test_a_page_that_shows_a_screenshot_the_site_lacks_fails(tmp_path: Path) -> None:
    site, shots = _tree(tmp_path, {"leases/index.html": _LEASES}, ("leases-light.png",))

    result = _check(site, shots)

    assert result.returncode == 1
    assert result.stderr == "missing: leases-dark.png (shown by leases/index.html)\n"


def test_a_captured_screenshot_that_no_page_shows_fails(tmp_path: Path) -> None:
    site, shots = _tree(
        tmp_path, {"leases/index.html": _LEASES}, ("leases-light.png", "leases-dark.png", "subnets-light.png")
    )

    result = _check(site, shots)

    assert result.returncode == 1
    assert result.stderr == "unreferenced: subnets-light.png\n"


def test_a_relative_src_resolves_against_its_own_page(tmp_path: Path) -> None:
    # From a nested page, "assets/..." without "../" names a file that the site does not hold.
    page = '<img src="assets/screenshots/leases-light.png">'
    site, shots = _tree(tmp_path, {"guide/leases/index.html": page}, ("leases-light.png",))

    result = _check(site, shots)

    assert result.returncode == 1
    assert result.stderr == "unreferenced: leases-light.png\n"


def test_a_nested_page_two_levels_down_finds_its_screenshot(tmp_path: Path) -> None:
    page = '<img src="../../assets/screenshots/leases-light.png">'
    site, shots = _tree(tmp_path, {"guide/leases/index.html": page}, ("leases-light.png",))

    assert _check(site, shots).returncode == 0


def test_an_image_inside_an_html_comment_is_not_on_the_page(tmp_path: Path) -> None:
    page = '<!-- <img src="../assets/screenshots/leases-light.png"> -->'
    site, shots = _tree(tmp_path, {"leases/index.html": page}, ("leases-light.png",))

    result = _check(site, shots)

    assert result.returncode == 1
    assert result.stderr == "unreferenced: leases-light.png\n"


def test_a_directory_that_does_not_exist_is_a_usage_error(tmp_path: Path) -> None:
    result = _check(tmp_path / "missing", tmp_path)

    assert result.returncode == 2
    assert "is not a directory" in result.stderr
