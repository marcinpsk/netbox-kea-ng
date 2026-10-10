#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Check that the built site and the captured screenshots match.

`zensical build --strict` does not fail on a missing image. Run this check on the built site: it
reads the `<img src>` of every HTML page, so the renderer has already resolved each Markdown form,
code block and comment. It fails when a page shows a screenshot that the site does not hold, and
when a captured screenshot is on no page.
"""

from __future__ import annotations

import argparse
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

#: The screenshot directory, relative to the site root.
SCREENSHOTS = Path("assets") / "screenshots"


class _ImageSources(HTMLParser):
    """Collect the src of each img element; a comment is not an element."""

    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "img":
            self.sources.extend(value for name, value in attrs if name == "src" and value)


def _image_paths(page: Path, site_dir: Path) -> list[Path]:
    """Return the local file of each image on *page*, resolved as a browser resolves it."""
    parser = _ImageSources()
    parser.feed(page.read_text(encoding="utf-8"))
    paths = []
    for source in parser.sources:
        url = urlsplit(source)
        if url.scheme or url.netloc or not url.path:
            continue
        base = site_dir if url.path.startswith("/") else page.parent
        paths.append((base / unquote(url.path).lstrip("/")).resolve())
    return paths


def referenced_screenshots(site_dir: Path) -> dict[Path, list[str]]:
    """Return each screenshot path, relative to the screenshot directory, with the pages that show it."""
    screenshots = (site_dir / SCREENSHOTS).resolve()
    references: dict[Path, list[str]] = {}
    for page in sorted(site_dir.rglob("*.html")):
        for image in _image_paths(page, site_dir.resolve()):
            if image.is_relative_to(screenshots):
                pages = references.setdefault(image.relative_to(screenshots), [])
                pages.append(page.relative_to(site_dir).as_posix())
    return references


def problems(site_dir: Path, captured_dir: Path) -> list[str]:
    """Return one message for each missing or unreferenced screenshot."""
    references = referenced_screenshots(site_dir)
    found = [
        f"missing: {image.as_posix()} (shown by {', '.join(pages)})"
        for image, pages in sorted(references.items())
        if not (site_dir / SCREENSHOTS / image).is_file()
    ]
    captured = {image.relative_to(captured_dir) for image in captured_dir.rglob("*.png")}
    found.extend(f"unreferenced: {image.as_posix()}" for image in sorted(captured - set(references)))
    return found


def main(argv: list[str] | None = None) -> int:
    """Print each problem and return 1 when there is one."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("site_dir", type=Path, help="the built site, for example site")
    parser.add_argument("captured_dir", type=Path, help="the captured screenshots, docs/guide/assets/screenshots")
    arguments = parser.parse_args(argv)
    for directory in (arguments.site_dir, arguments.captured_dir):
        if not directory.is_dir():
            parser.error(f"{directory} is not a directory")
    found = problems(arguments.site_dir, arguments.captured_dir)
    if found:
        sys.stderr.write("".join(f"{message}\n" for message in found))
        return 1
    count = len(referenced_screenshots(arguments.site_dir))
    sys.stdout.write(f"{count} screenshots on the site pages exist, and each capture is on a page.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
