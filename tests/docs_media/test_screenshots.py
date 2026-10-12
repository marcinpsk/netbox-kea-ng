# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The documentation screenshots, one test per view that a page of docs/guide/ shows.

Each test checks that the view shows the demo data before it writes the images, so a broken
view fails the run instead of publishing an empty table or an error page.
"""

import re
from collections.abc import Callable

from playwright.sync_api import Page, expect

from .conftest import DELEGATED_PREFIX, LEASES4, LEASES6, RESERVATIONS4, SYNCED4, DemoData

_ROWS = "table.object-list > tbody > tr"


def _open(page: Page, url: str) -> None:
    response = page.goto(url)
    assert response is not None and response.ok, f"{url} answered {response and response.status}"
    page.wait_for_load_state("networkidle")
    if "/plugins/kea/" in url:
        shell = page.locator("#kea-workspace-shell")
        expect(shell.get_by_label("Server Scope")).to_be_visible()
        expect(shell.get_by_role("navigation", name="DHCP family").get_by_role("link")).to_have_count(2)
        expect(shell.get_by_role("navigation", name="Workspace sections").get_by_role("link")).to_have_text(
            ["Overview", "Leases", "Subnets", "Reservations", "Configuration", "Sync"]
        )


def test_server_status(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/servers/{demo_data.campus.id}/")
    # The view draws a card for each daemon also when status-get fails, so require its rows.
    expect(page.get_by_text("No status data available.")).to_have_count(0)
    for daemon in ("DHCPv4", "DHCPv6"):
        card = page.locator(".card").filter(
            has=page.locator(".card-header", has_text=re.compile(f"^\\s*{daemon}(?!:)"))
        )
        expect(card).to_have_count(1)
        expect(card.locator("tr", has=page.locator("th", has_text="Version")).locator("code")).to_have_text(
            re.compile(r"^\d+\.\d+\.\d+")
        )
        expect(card.locator("tr", has=page.locator("th", has_text="PID")).locator("td")).to_have_text(
            re.compile(r"^\d+$")
        )
    changing = page.locator("tr").filter(has=page.locator("th", has_text=re.compile("^(Uptime|Time since reload)$")))
    capture("server-status", mask=[changing.locator("td")])


def test_combined_dashboard(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/combined/")
    online = {demo_data.campus.name: ("DHCPv4", "DHCPv6"), demo_data.branch.name: ("DHCPv4",)}
    for name, daemons in online.items():
        header = page.locator(".card-header").filter(has=page.get_by_role("link", name=name, exact=True))
        badges = header.locator(".badge")
        expect(badges).to_have_text([f"{daemon} Online" for daemon in daemons])
    expect(page.get_by_text("Offline")).to_have_count(0)
    capture("combined-dashboard")


def test_workspace_selection(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/combined/subnets4/?server={demo_data.campus.id}&server={demo_data.branch.id}")
    shell = page.locator("#kea-workspace-shell")
    expect(shell.get_by_label("Server Scope")).to_have_text("2 Servers selected")
    expect(page.locator(_ROWS).filter(has_text="192.0.2.0/24")).to_have_count(2)
    capture("workspace-selection")


def test_server_switch(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/servers/{demo_data.campus.id}/subnets4/")
    shell = page.locator("#kea-workspace-shell")
    shell.get_by_role("button", name="Switch Server", exact=True).click()
    expect(
        shell.get_by_role("navigation", name="Switch Server").get_by_role(
            "link",
            name=demo_data.branch.name,
            exact=True,
        )
    ).to_be_visible()
    capture("server-switch")


def test_lease_search(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/servers/{demo_data.campus.id}/leases4/?q=1&by=subnet_id")
    rows = page.locator(_ROWS)
    expect(rows).to_have_count(sum(address.startswith("192.0.2.") for address, _mac, _name in LEASES4))
    expect(rows.locator('a.badge:has-text("Synced")')).to_have_count(len(SYNCED4))
    expect(rows.filter(has_text=RESERVATIONS4[0][0]).get_by_text("Reserved", exact=True)).to_be_visible()
    capture("lease-search")


def test_dhcpv6_leases(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/servers/{demo_data.campus.id}/leases6/?q=1&by=subnet_id")
    rows = page.locator(_ROWS)
    expect(rows).to_have_count(len(LEASES6) + 1)
    prefix, length, _duid, _hostname = DELEGATED_PREFIX
    expect(rows.filter(has_text=f"{prefix}/{length}")).to_have_count(1)
    capture("dhcpv6-leases")


def test_lease_edit(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    address, _mac, hostname = LEASES4[1]
    _open(page, f"{plugin_base}/servers/{demo_data.campus.id}/leases4/{address}/edit/")
    expect(page.locator("#id_hostname")).to_have_value(hostname)
    capture("lease-edit")


def test_reservations(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/servers/{demo_data.campus.id}/reservations4/")
    rows = page.locator(_ROWS)
    for _address, mac, _hostname in RESERVATIONS4:
        expect(rows.filter(has_text=mac)).to_have_count(1)
    capture("reservations")


def test_subnets(page: Page, plugin_base: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{plugin_base}/servers/{demo_data.campus.id}/subnets4/")
    expect(page.locator(_ROWS).filter(has_text="192.0.2.0/24")).to_have_count(1)
    capture("subnets")


def test_synced_ip_address(page: Page, netbox_url: str, demo_data: DemoData, capture: Callable[..., None]) -> None:
    _open(page, f"{netbox_url}/ipam/ip-addresses/{demo_data.synced_ip_id}/")
    expect(page.get_by_text("[kea-sync: ")).not_to_have_count(0)
    capture("synced-ip-address")
