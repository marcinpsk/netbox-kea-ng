# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Play documentation recordings only when at least half of the video is visible."""

import base64
import subprocess
from pathlib import Path

import imageio_ffmpeg
import pytest
from playwright.sync_api import Page, expect

_AUTOPLAY = Path(__file__).resolve().parents[2] / "docs/guide/assets/js/autoplay-videos.js"


@pytest.fixture(scope="session")
def recording(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Encode a small real recording instead of replacing the browser media methods."""
    output = tmp_path_factory.mktemp("docs-autoplay") / "recording.mp4"
    subprocess.run(
        [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:s=160x80:r=10",
            "-t",
            "2",
            "-an",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            str(output),
        ],
        check=True,
        timeout=30,
    )
    return "data:video/mp4;base64," + base64.b64encode(output.read_bytes()).decode("ascii")


def _move_video(page: Page, top: int) -> None:
    """Wait for real intersection delivery and rendering after moving the video."""
    page.evaluate(
        """async top => {
            const video = document.querySelector("video");
            video.style.top = `${top}px`;
            await new Promise(resolve => {
                const observer = new IntersectionObserver(() => {
                    observer.disconnect();
                    resolve();
                });
                observer.observe(video);
            });
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        }""",
        top,
    )


def _load_video(page: Page, recording: str, top: int = 650) -> None:
    page.set_viewport_size({"width": 800, "height": 600})
    page.set_content(
        f'<video muted loop playsinline preload="auto" src="{recording}" '
        f'style="position:fixed;top:{top}px;left:0;width:400px;height:200px"></video>'
    )
    page.wait_for_function('document.querySelector("video").readyState >= 2')
    page.add_script_tag(path=_AUTOPLAY)
    _move_video(page, top)


@pytest.mark.parametrize("initial_top", [550, 650])
def test_recording_stays_paused_when_less_than_half_is_visible(page: Page, recording: str, initial_top: int) -> None:
    _load_video(page, recording, top=initial_top)
    # The 200-pixel video starts at 550 in a 600-pixel viewport: only a quarter is visible.
    _move_video(page, 550)
    expect(page.locator("video")).to_have_js_property("paused", True)


def test_recording_plays_at_half_and_pauses_below_half(page: Page, recording: str) -> None:
    _load_video(page, recording)
    video = page.locator("video")
    _move_video(page, 500)
    expect(video).to_have_js_property("paused", False)
    page.wait_for_function('document.querySelector("video").currentTime > 0')
    _move_video(page, 550)
    expect(video).to_have_js_property("paused", True)
    _move_video(page, 450)
    expect(video).to_have_js_property("paused", False)
    _move_video(page, 650)
    expect(video).to_have_js_property("paused", True)


def test_reduced_motion_keeps_visible_recordings_paused(page: Page, recording: str) -> None:
    page.emulate_media(reduced_motion="reduce")
    _load_video(page, recording, top=450)
    expect(page.locator("video")).to_have_js_property("paused", True)
