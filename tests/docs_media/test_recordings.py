# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The documentation recordings, one test per workflow that a page of docs/guide/ shows as a clip.

Each test checks the state of the view at each step, so a broken view fails the run instead of
publishing a clip of an error. Each recording changes one lease of subnet 2, and its fixture
removes the change afterwards, so the screenshots and a second run see the demo data again.
"""

from collections.abc import Callable
from contextlib import AbstractContextManager

from playwright.sync_api import Locator, Page, expect

from ..conftest import REQUEST_TIMEOUT
from .conftest import RECORDED_EDIT_HOSTNAME, RECORDED_EDIT_LEASE, RECORDED_RESERVE_LEASE, RECORDED_SUBNET_ID, DemoData
from .recording import Clip

_TIMEOUT = REQUEST_TIMEOUT * 1000
Recorder = Callable[..., AbstractContextManager[Clip]]


def _search(plugin_base: str, demo_data: DemoData) -> str:
    return f"{plugin_base}/servers/{demo_data.campus.id}/leases4/?q={RECORDED_SUBNET_ID}&by=subnet_id"


def _row(page: Page, address: str) -> Locator:
    row = page.locator("table.object-list > tbody > tr").filter(has_text=address)
    expect(row).to_have_count(1)
    return row


def test_sync_lease(plugin_base: str, demo_data: DemoData, recorded_sync: str, record: Recorder) -> None:
    with record("sync-lease", _search(plugin_base, demo_data), gif=True) as clip:
        row = _row(clip.page, recorded_sync)
        clip.click(row.get_by_role("button", name="Sync", exact=True))
        # The reply replaces the button with a link to the new IP address.
        synced = row.get_by_role("link", name=f"{recorded_sync}/")
        expect(synced).to_have_count(1, timeout=_TIMEOUT)
        clip.click(synced)
        marker = clip.page.get_by_text("[kea-sync: ")
        expect(marker).not_to_have_count(0)
        clip.point(marker.first)


def test_reserve_lease(plugin_base: str, demo_data: DemoData, recorded_reservation: str, record: Recorder) -> None:
    _address, mac, hostname = RECORDED_RESERVE_LEASE
    with record("reserve-lease", _search(plugin_base, demo_data)) as clip:
        page = clip.page
        clip.click(_row(page, recorded_reservation).get_by_role("link", name="+ Reserve"))
        # The link opens the Reservation form with the values of the lease.
        expect(page.locator("#id_ip_address")).to_have_value(recorded_reservation)
        expect(page.locator("#id_identifier")).to_have_value(mac)
        expect(page.locator("#id_hostname")).to_have_value(hostname)
        clip.point(page.locator("#id_identifier"))
        clip.click(page.get_by_role("button", name="Save"))
        expect(page.locator(".toast-body", has_text="Reservation created.")).to_have_count(1, timeout=_TIMEOUT)
        expect(page.locator(".toast-body", has_text="could not persist")).to_have_count(0)
        # The save returns to the lease search, where the lease is now reserved.
        reserved = _row(page, recorded_reservation).get_by_text("Reserved", exact=True)
        expect(reserved).to_be_visible()
        clip.point(reserved)


def test_edit_lease(plugin_base: str, demo_data: DemoData, recorded_edit: str, record: Recorder) -> None:
    hostname = RECORDED_EDIT_LEASE[2]
    with record("edit-lease", _search(plugin_base, demo_data)) as clip:
        page = clip.page
        row = _row(page, recorded_edit)
        expect(row).to_contain_text(hostname)
        clip.click(row.locator(".dropdown-toggle"))
        clip.click(row.get_by_role("link", name="Edit lease"))
        field = page.locator("#id_hostname")
        expect(field).to_have_value(hostname)
        clip.type(field, RECORDED_EDIT_HOSTNAME)
        clip.click(page.get_by_role("button", name="Save"))
        expect(page.locator(".toast-body", has_text=f"Lease {recorded_edit} updated.")).to_have_count(1)
        # The save returns to the lease search, which reads the lease from Kea again.
        edited = _row(page, recorded_edit).get_by_text(RECORDED_EDIT_HOSTNAME, exact=True)
        expect(edited).to_be_visible()
        clip.point(edited)
