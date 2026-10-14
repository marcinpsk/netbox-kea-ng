# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Keyboard, viewport and theme behavior of the shared Kea workspace shell."""

import re
from urllib.parse import urlencode, urlsplit

import pytest
from playwright.sync_api import Locator, Page, expect


def _no_page_scroll(page: Page) -> None:
    geometry = page.evaluate("""() => ({
        page: document.documentElement.scrollWidth, viewport: window.innerWidth,
        overflow: [...document.querySelectorAll('#page-content *')]
            .filter(el => el.getBoundingClientRect().right > window.innerWidth)
            .slice(0, 8).map(el => ({tag: el.tagName, classes: el.className}))
    })""")
    assert geometry["page"] <= geometry["viewport"], geometry


def _visible_focus(control: Locator) -> None:
    expect(control).to_be_focused()
    expect(control).to_be_in_viewport()
    focus = control.evaluate("""el => {
        const style = getComputedStyle(el);
        return {visible: el.matches(':focus-visible'), width: parseFloat(style.outlineWidth),
            style: style.outlineStyle, color: style.outlineColor, shadow: style.boxShadow};
    }""")
    assert focus["visible"]
    assert (focus["width"] >= 1 and focus["style"] != "none") or focus["shadow"] != "none", focus
    assert focus["color"] not in ("transparent", "rgba(0, 0, 0, 0)"), focus


def _tab_to(page: Page, control: Locator) -> None:
    for _ in range(80):
        page.keyboard.press("Tab")
        if control.evaluate("el => el === document.activeElement"):
            _visible_focus(control)
            return
    pytest.fail("Keyboard navigation did not reach the workspace control.")


@pytest.mark.parametrize("mode", ["light", "dark"])
@pytest.mark.parametrize("width", [1280, 390], ids=["desktop", "narrow"])
@pytest.mark.parametrize("scope", ["server", "combined"])
def test_workspace_keyboard_layout_and_theme(
    page: Page,
    plugin_base: str,
    kea_server,
    nb_api,
    kea_url: str,
    kea_dhcp6_url: str,
    track_http_errors: list,
    mode: str,
    width: int,
    scope: str,
) -> None:
    """Tab through the shell, operate its dropdown and follow family and section links."""
    second = nb_api.plugins.kea.servers.create(
        name="documentation" * 7,
        ca_url=kea_url,
        dhcp6_url=kea_dhcp6_url,
        has_control_agent=False,
    )
    try:
        page.set_viewport_size({"width": width, "height": 800})
        page.add_init_script(f"localStorage.setItem('netbox-color-mode', '{mode}');")
        previous = f"{plugin_base}/combined/subnets4/?server={kea_server.id}&server={second.id}"
        if scope == "server":
            path = urlsplit(previous).path + "?" + urlsplit(previous).query
            url = f"{plugin_base}/servers/{second.id}/subnets4/?" + urlencode({"return_url": path})
        else:
            url = previous
        page.goto(url)
        page.wait_for_load_state("networkidle")
        expect(page.locator("html")).to_have_attribute("data-bs-theme", mode)
        shell = page.locator("#kea-workspace-shell")
        _no_page_scroll(page)
        bounds = shell.bounding_box()
        assert bounds and bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= width

        if scope == "server":
            _tab_to(page, shell.get_by_role("link", name="Back to workspace", exact=True))
            toggle = shell.get_by_role("button", name="Switch Server", exact=True)
        else:
            toggle = shell.get_by_role("button", name=re.compile(r"Servers"))
        _tab_to(page, toggle)
        page.keyboard.press("Enter")
        expect(toggle).to_have_attribute("aria-expanded", "true")
        _no_page_scroll(page)
        if scope == "server":
            choice = shell.get_by_role("navigation", name="Switch Server").get_by_role(
                "link",
                name=kea_server.name,
                exact=True,
            )
        else:
            choice = shell.get_by_role("checkbox", name=re.compile(second.name))
        _tab_to(page, choice)
        if scope == "combined":
            expect(choice).to_be_checked()
            page.keyboard.press("Space")
            expect(choice).not_to_be_checked()
            page.keyboard.press("Space")
            expect(choice).to_be_checked()
            _tab_to(page, shell.get_by_role("button", name="Apply", exact=True))
        page.keyboard.press("Escape")
        expect(toggle).to_have_attribute("aria-expanded", "false")
        expect(toggle).to_be_focused()
        _tab_to(page, shell.get_by_role("link", name="DHCPv4", exact=True))
        page.keyboard.press("Tab")
        family = shell.get_by_role("link", name="DHCPv6", exact=True)
        _visible_focus(family)
        page.keyboard.press("Enter")
        page.wait_for_url(re.compile(r"/subnets6/"))
        page.wait_for_load_state("networkidle")
        expect(shell.get_by_role("link", name="DHCPv6", exact=True)).to_have_attribute("aria-current", "page")
        _no_page_scroll(page)
        sections = shell.get_by_role("navigation", name="Workspace sections")
        _tab_to(page, sections.get_by_role("link", name="Overview", exact=True))
        for label in ("Leases", "Subnets", "Reservations", "Configuration", "Sync"):
            page.keyboard.press("Tab")
            _visible_focus(sections.get_by_role("link", name=label, exact=True))
        page.keyboard.press("Enter")
        page.wait_for_url(re.compile(r"/(?:sync6|sync_status)/"))
        page.wait_for_load_state("networkidle")
        expect(shell.get_by_role("link", name="Sync", exact=True)).to_have_attribute("aria-current", "page")
        expect(page.locator("html")).to_have_attribute("data-bs-theme", mode)
        assert not track_http_errors, track_http_errors
    finally:
        second.delete()


@pytest.mark.parametrize("mode", ["light", "dark"])
def test_server_switch_menu_fits_narrow_viewport(
    page: Page,
    plugin_base: str,
    kea_server,
    nb_api,
    kea_url: str,
    kea_dhcp6_url: str,
    mode: str,
) -> None:
    """An unbroken Server name stays readable and selectable in the narrow switcher."""
    target = nb_api.plugins.kea.servers.create(
        name="documentation" * 7,
        ca_url=kea_url,
        dhcp6_url=kea_dhcp6_url,
        has_control_agent=False,
    )
    try:
        page.set_viewport_size({"width": 390, "height": 800})
        page.add_init_script(f"localStorage.setItem('netbox-color-mode', '{mode}');")
        page.goto(f"{plugin_base}/servers/{kea_server.id}/subnets4/")
        shell = page.locator("#kea-workspace-shell")
        shell.get_by_role("button", name="Switch Server", exact=True).click()
        menu = shell.get_by_role("navigation", name="Switch Server")
        link = menu.get_by_role("link", name=target.name, exact=True)
        expect(link).to_be_visible()
        bounds = menu.bounding_box()
        assert bounds and bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= 390, bounds
        _no_page_scroll(page)
        link.click()
        page.wait_for_url(re.compile(rf"/servers/{target.id}/subnets4/"))
        expect(shell.get_by_label("Server Scope")).to_have_text(target.name)
        _no_page_scroll(page)
    finally:
        target.delete()


@pytest.mark.parametrize("mode", ["light", "dark"])
def test_each_tab_row_marks_its_active_tab(page: Page, plugin_base: str, kea_server, mode: str) -> None:
    """The active tab of the section row and of the Subnets row carries a primary underline, a tint and a bold label."""
    page.add_init_script(f"localStorage.setItem('netbox-color-mode', '{mode}');")
    page.goto(f"{plugin_base}/servers/{kea_server.id}/subnets4/")
    expect(page.locator("html")).to_have_attribute("data-bs-theme", mode)
    tabs = page.evaluate("""() => {
        const primary = getComputedStyle(document.body).getPropertyValue('--tblr-primary').trim();
        const probe = document.createElement('i');
        probe.style.color = primary;
        document.body.append(probe);
        const underline = getComputedStyle(probe).color;
        probe.remove();
        return {underline, rows: [...document.querySelectorAll('.kea-tabs')].map(row => [...row.querySelectorAll('.nav-link')]
            .map(link => {
                const style = getComputedStyle(link);
                return {label: link.textContent.trim(), active: link.classList.contains('active'),
                    background: style.backgroundColor, weight: Number(style.fontWeight), shadow: style.boxShadow};
            }))};
    }""")
    actives = [tab for row in tabs["rows"] for tab in row if tab["active"]]
    assert [tab["label"] for tab in actives] == ["Subnets", "Subnets"], actives
    inactive = next(tab for row in tabs["rows"] for tab in row if not tab["active"])
    for tab in actives:
        assert tab["shadow"].startswith(tabs["underline"]) and tab["shadow"].endswith("inset"), (tab, tabs["underline"])
        assert "-3px" in tab["shadow"], tab
        assert tab["weight"] >= 600, tab
        assert tab["background"] != inactive["background"], (tab, inactive)
    assert inactive["shadow"] == "none" and inactive["weight"] < 600, inactive
