#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Check that the site pages and the captured screenshots match.

`zensical build --strict` does not fail on a missing image. This check fails when a page
refers to a screenshot that does not exist, and when a captured screenshot has no page that
refers to it. It reads inline images, reference images with their definitions, and HTML
`<img src>`. It ignores fenced code blocks and inline code, but not indented code blocks.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

#: The screenshot directory, relative to the documentation directory.
SCREENSHOTS = Path("assets") / "screenshots"

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_INLINE_CODE = re.compile(r"(`+)(?!`).*?(?<!`)\1(?!`)", re.DOTALL)
_TITLE = r"""(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?"""
_DESTINATION = r"(?:<([^>\n]*)>|([^\s)<>]+))"
_INLINE_IMAGE = re.compile(rf"!\[[^\]]*\]\(\s*{_DESTINATION}{_TITLE}\s*\)")
#: `![alt][label]`, `![alt][]` and `![alt]`, not followed by `(` or `:`.
_REFERENCE_IMAGE = re.compile(r"!\[([^\]]*)\](?:\[([^\]]*)\])?(?![(:\[])")
_DEFINITION = re.compile(rf"^ {{0,3}}\[([^\]]+)\]:[ \t]*{_DESTINATION}", re.MULTILINE)
_HTML_IMAGE = re.compile(r"""<img\b[^>]*?\ssrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)


def _without_code(text: str) -> str:
    """Return *text* without fenced code blocks and inline code spans."""
    kept: list[str] = []
    fence = ""
    for line in text.splitlines(keepends=True):
        opener = _FENCE.match(line)
        if fence:
            # A closing fence repeats the opening character at least as often, and holds nothing else.
            if opener and len(opener.group(1)) >= len(fence) and not line.strip().strip(fence[0]):
                fence = ""
            continue
        if opener:
            fence = opener.group(1)
            continue
        kept.append(line)
    return _INLINE_CODE.sub("", "".join(kept))


def _label(text: str) -> str:
    return " ".join(text.split()).casefold()


def image_targets(text: str) -> list[str]:
    """Return the target of each image in the Markdown *text*."""
    text = _without_code(text)
    targets = [angled or bare for angled, bare in _INLINE_IMAGE.findall(text)]
    definitions = {_label(label): angled or bare for label, angled, bare in _DEFINITION.findall(text)}
    for alt, label in _REFERENCE_IMAGE.findall(text):
        target = definitions.get(_label(label or alt))
        if target is not None:
            targets.append(target)
    targets.extend(next(value for value in match if value) for match in _HTML_IMAGE.findall(text))
    return targets


def referenced_screenshots(docs_dir: Path) -> dict[Path, list[str]]:
    """Return each screenshot that a page refers to, with the pages that refer to it."""
    screenshots = (docs_dir / SCREENSHOTS).resolve()
    references: dict[Path, list[str]] = {}
    for page in sorted(docs_dir.rglob("*.md")):
        for target in image_targets(page.read_text(encoding="utf-8")):
            if "://" in target:
                continue
            image = (page.parent / target.split("#", 1)[0].split("?", 1)[0]).resolve()
            if image.is_relative_to(screenshots):
                references.setdefault(image, []).append(page.relative_to(docs_dir).as_posix())
    return references


def problems(docs_dir: Path) -> list[str]:
    """Return one message for each missing or unreferenced screenshot."""
    references = referenced_screenshots(docs_dir)
    screenshots = (docs_dir / SCREENSHOTS).resolve()
    captured = set(screenshots.rglob("*.png")) if screenshots.is_dir() else set()
    found = []
    for image, pages in sorted(references.items()):
        if not image.is_file():
            found.append(f"missing: {image.relative_to(screenshots).as_posix()} (referenced by {', '.join(pages)})")
    found.extend(
        f"unreferenced: {image.relative_to(screenshots).as_posix()}" for image in sorted(captured - set(references))
    )
    return found


def main(argv: list[str] | None = None) -> int:
    """Print each problem and return 1 when there is one."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("docs_dir", nargs="?", type=Path, default=Path("docs/guide"), help="the site pages")
    docs_dir = parser.parse_args(argv).docs_dir
    if not docs_dir.is_dir():
        parser.error(f"{docs_dir} is not a directory")
    found = problems(docs_dir)
    if found:
        sys.stderr.write("".join(f"{message}\n" for message in found))
        return 1
    sys.stdout.write(f"{len(referenced_screenshots(docs_dir))} referenced screenshots exist, and each has a page.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
