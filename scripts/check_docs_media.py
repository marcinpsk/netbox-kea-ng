#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Check that the built site and the captured screenshots match.

`zensical build --strict` does not fail on a missing image. Run this check on the built site: it
reads the `<img src>` of every HTML page, so the renderer has already resolved each Markdown form,
code block and comment. It fails when a local image of a page is not a file inside the site, and when a
captured screenshot is on no page.

Not checked: `srcset` and `<picture><source>` candidates.
Not checked: root-relative URLs (`/...`), which depend on the `site_url` path.
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


def _images(page: Path) -> list[tuple[str, Path]]:
    """Return each local image of *page*: its src, and its file, resolved as a browser resolves it."""
    parser = _ImageSources()
    parser.feed(page.read_text(encoding="utf-8"))
    images = []
    for source in parser.sources:
        url = urlsplit(source)
        if url.scheme or url.netloc or not url.path or url.path.startswith("/"):
            continue
        images.append((source, (page.parent / unquote(url.path)).resolve()))
    return images


def problems(site_dir: Path, captured_dir: Path) -> list[str]:
    """Return one message for each image that the site lacks and each capture that no page shows."""
    site = site_dir.resolve()
    screenshots = (site_dir / SCREENSHOTS).resolve()
    found = []
    shown = set()
    for page in sorted(site_dir.rglob("*.html")):
        for source, image in _images(page):
            if not image.is_relative_to(site) or not image.is_file():
                found.append(f"missing: {source} (shown by {page.relative_to(site_dir).as_posix()})")
            elif image.is_relative_to(screenshots):
                shown.add(image.relative_to(screenshots))
    captured = {image.relative_to(captured_dir) for image in captured_dir.rglob("*.png")}
    found.extend(f"unreferenced: {image.as_posix()}" for image in sorted(captured - shown))
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
    count = len(list(arguments.captured_dir.rglob("*.png")))
    sys.stdout.write(f"Each local image of the site exists, and each of the {count} captures is on a page.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
