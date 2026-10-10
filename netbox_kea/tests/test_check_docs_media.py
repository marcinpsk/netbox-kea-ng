# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""scripts/check_docs_media.py on a temporary documentation tree."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

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


#: Each Markdown form of an image that refers to assets/screenshots/form.png.
_IMAGE_FORMS = {
    "inline with a double-quoted title": '![Alt](assets/screenshots/form.png "Title")\n',
    "inline with a single-quoted title": "![Alt](assets/screenshots/form.png 'Title')\n",
    "inline in angle brackets": "![Alt](<assets/screenshots/form.png>)\n",
    "full reference": "![Alt][shot]\n\n[shot]: assets/screenshots/form.png\n",
    "collapsed reference": "![Shot][]\n\n[shot]: assets/screenshots/form.png 'Title'\n",
    "shortcut reference": "![Shot]\n\n[Shot]: <assets/screenshots/form.png>\n",
    "HTML img with double quotes": '<img alt="Alt" src="assets/screenshots/form.png#only-light">\n',
    "HTML img with single quotes": "<img src='assets/screenshots/form.png' width=600>\n",
}


@pytest.mark.parametrize("page", _IMAGE_FORMS.values(), ids=_IMAGE_FORMS)
def test_each_image_form_counts_as_a_reference(tmp_path: Path, page: str) -> None:
    referenced = _docs_tree(tmp_path, {"page.md": page}, ("form.png",))
    missing = _docs_tree(tmp_path / "missing", {"page.md": page}, ())

    assert _check(referenced).returncode == 0, _check(referenced).stderr
    assert _check(missing).stderr == "missing: form.png (referenced by page.md)\n"


#: Images that only a code sample shows: they refer to nothing.
_CODE_SAMPLES = {
    "backtick fence": "```markdown\n![Alt](assets/screenshots/form.png)\n```\n",
    "tilde fence": "~~~\n<img src='assets/screenshots/form.png'>\n~~~\n",
    "longer closing fence": "````\n```\n![Alt](assets/screenshots/form.png)\n```\n`````\n",
    "inline code": "Write `![Alt](assets/screenshots/form.png)` to show an image.\n",
    "double-backtick inline code": "Write ``![Alt](assets/screenshots/form.png)`` to show it.\n",
}


@pytest.mark.parametrize("page", _CODE_SAMPLES.values(), ids=_CODE_SAMPLES)
def test_an_image_in_code_is_not_a_reference(tmp_path: Path, page: str) -> None:
    docs = _docs_tree(tmp_path, {"page.md": page}, ("form.png",))

    result = _check(docs)

    assert result.returncode == 1
    assert result.stderr == "unreferenced: form.png\n"


def test_an_unused_reference_definition_is_not_a_reference(tmp_path: Path) -> None:
    docs = _docs_tree(tmp_path, {"page.md": "[shot]: assets/screenshots/form.png\n"}, ("form.png",))

    assert _check(docs).stderr == "unreferenced: form.png\n"
