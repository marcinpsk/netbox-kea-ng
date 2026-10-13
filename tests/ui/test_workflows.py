# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2026 Andrew Backeby <andrew@backeby.eu>
# SPDX-License-Identifier: Apache-2.0
"""Browser workflow tests: navigation, badge enrichment, and CRUD lifecycles.

They share the ``tests/ui`` harness with ``test_ui.py`` and run against the compose
stack that ``tests/test_setup.sh`` starts. See AGENTS.md for how to start it.
"""

import ipaddress
import re
import subprocess
import sys
import warnings
from collections.abc import Iterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
import requests
from playwright.sync_api import Locator, Page, expect

if TYPE_CHECKING:
    # The unit suite execs this file standalone, where a relative import has no
    # package to resolve against. Keep every cross-module import behind this guard.
    from .conftest import _DualEndpointKeaClient

#: Mirrors the start of every block that netbox_kea/ipam_marker.py writes. This suite cannot import the
#: package (it needs Django), so a guard in the unit suite keeps the two in step.
_KEA_SYNC_MARKER_PREFIX = "[kea-sync: "

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _check_no_django_error(page: Page) -> None:
    """Fail immediately if the page shows a Django error page."""
    title = page.title()
    assert "Server Error" not in title, f"Django 500 at {page.url}"
    assert "Page not found" not in title, f"Django 404 at {page.url}"


def _dismiss_debug_toolbar(page: Page) -> None:
    """Remove the Django Debug Toolbar overlay so it doesn't intercept clicks."""
    page.evaluate("() => { const el = document.getElementById('djDebug'); if (el) el.remove(); }")


def _submit_and_wait_nav(page: Page, js: str) -> None:
    """Run a form-submitting JS snippet and wait for the resulting navigation.

    Replaces the deprecated/racy ``page.expect_navigation()``: capture the current
    URL, run the submit, then wait for the URL to change (these submits always
    redirect to a different page) and for the network to settle.
    """
    prev_url = page.url
    page.evaluate(js)
    page.wait_for_url(lambda u: u != prev_url)
    page.wait_for_load_state("networkidle")


def _assert_no_none_pk(page: Page) -> None:
    """Fail if the URL contains the tell-tale pk=None pattern (regression guard)."""
    assert not re.search(r"/None(?:[/?#]|$)", page.url), f"URL contains /None — pk=None bug triggered at {page.url}"


def _subnet_cidr_for_id(page: Page, subnet_id: int) -> str:
    """Return the subnet CIDR for *subnet_id*, read from the reservation add form's Subnet dropdown.

    The reservation form takes a CIDR, but the edit/delete routes are still keyed by
    subnet id. Reading the mapping off the page keeps the test independent of whatever
    subnets the live Kea happens to be configured with.
    """
    cidr = page.evaluate(
        """(subnetId) => {
            const opts = [...document.querySelectorAll('select[name="subnet_cidr"] option')];
            const match = opts.find((o) => o.textContent.trim().endsWith(`(ID ${subnetId})`));
            return match ? match.value : '';
        }""",
        subnet_id,
    )
    assert cidr, f"Subnet id {subnet_id} is not offered on the reservation add form"
    return cidr


def _assert_no_http_errors(errors: list) -> None:
    """Fail on any tracked 4xx or 5xx response.

    ``track_http_errors`` records every response at 400 and above. Asserting only on
    5xx let a 400 or 403 after a form submit pass as success.
    """
    assert not errors, f"4xx/5xx responses during test: {errors}"


def _tail_container_logs(service: str = "netbox", lines: int = 30) -> str:
    """Return the last N lines from one Compose service's stderr (Django log).

    Filtering on the service label rather than the container name: the stack also runs
    netbox-worker and netbox-housekeeping, whose names contain "netbox" too.
    """
    try:
        name = (
            subprocess.check_output(
                [
                    "docker",
                    "ps",
                    "--filter",
                    f"label=com.docker.compose.service={service}",
                    "--format",
                    "{{.Names}}",
                ],
                timeout=5,
            )
            .decode()
            .strip()
            .split("\n")[0]
        )
        return subprocess.check_output(
            ["docker", "logs", "--tail", str(lines), name],
            stderr=subprocess.STDOUT,
            timeout=5,
        ).decode()
    except Exception:  # noqa: BLE001 - diagnostics only; never fail a test
        return ""


# ---------------------------------------------------------------------------
# TestServerList — no live Kea needed
# ---------------------------------------------------------------------------


class TestServerList:
    """Server list page and bulk-action sanity checks."""

    def test_page_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        track_http_errors: list,
    ) -> None:
        page.goto(f"{plugin_base}/servers/")
        _check_no_django_error(page)
        # Confirm the server list rendered: URL is correct and page has a table or add link
        assert "/plugins/kea/servers" in page.url
        expect(page.locator("a[href*='/servers/add/']").first).to_be_visible()
        _assert_no_http_errors(track_http_errors)

    @pytest.mark.parametrize(
        ("action", "label"),
        [("_edit", r"edit.?selected"), ("_delete", r"delete.?selected")],
    )
    def test_bulk_action_without_a_selection_reaches_no_broken_url(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        action: str,
        label: str,
        track_http_errors: list,
    ) -> None:
        """A bulk action with nothing checked once submitted an empty selection and
        landed on ``/servers/None``.

        NetBox 4.6 renders the button disabled, which makes the action unreachable.
        NetBox 4.3 leaves it enabled, so the guard has to be the outcome of the click,
        not the state of the control.
        """
        page.goto(f"{plugin_base}/servers/")
        _check_no_django_error(page)

        button = page.get_by_role("button", name=re.compile(label, re.IGNORECASE))
        expect(button).to_be_visible()
        if button.is_disabled():
            assert page.locator(f'button[name="{action}"]:not([disabled])').count() == 0
        else:
            button.click()
            page.wait_for_load_state("networkidle")
        _assert_no_none_pk(page)
        _check_no_django_error(page)
        assert not [error for error in track_http_errors if error[0] == 404], (
            f"Got 404 from the empty {action} selection: {track_http_errors}"
        )
        _assert_no_http_errors(track_http_errors)

    def test_import_button_loads_form_not_404(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        track_http_errors: list,
    ) -> None:
        """Regression: clicking 'Import' on the server list must load the import form, not 404.

        Before the fix, ``/plugins/kea/servers/import/`` had no URL pattern and
        returned 404 immediately.
        """
        page.goto(f"{plugin_base}/servers/")
        _check_no_django_error(page)

        # Verify the Import link is rendered on the page (not missing)
        import_link = page.locator('a[href*="/servers/import/"]')
        expect(import_link).to_be_visible()

        # Navigate directly — the Django Debug Toolbar overlay blocks pointer
        # events on this link (same issue as other action buttons in the suite).
        page.goto(f"{plugin_base}/servers/import/")
        page.wait_for_load_state("networkidle")

        _check_no_django_error(page)
        _assert_no_none_pk(page)
        assert "/servers/import" in page.url, f"Expected import URL, got {page.url}"

        _assert_no_http_errors(track_http_errors)


# ---------------------------------------------------------------------------
# TestAddServerForm — no live Kea needed for GET
# ---------------------------------------------------------------------------


class TestAddServerForm:
    """Add-server form render and basic validation."""

    def test_form_get_renders_required_fields(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        track_http_errors: list,
    ) -> None:
        page.goto(f"{plugin_base}/servers/add/")
        _check_no_django_error(page)

        expect(page.get_by_label("Name", exact=True)).to_be_visible()
        expect(page.get_by_label("CA / Server URL", exact=True)).to_be_visible()
        expect(page.locator("#id_ca_username")).to_be_visible()
        # Checkboxes use IDs reliably across NetBox versions
        expect(page.locator("#id_dhcp4")).to_be_visible()
        expect(page.locator("#id_dhcp6")).to_be_visible()
        expect(page.locator("#id_has_control_agent")).to_be_visible()
        _assert_no_http_errors(track_http_errors)

    def test_form_missing_name_rerenders_not_none_url(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        track_http_errors: list,
    ) -> None:
        """Submitting without a name must re-render the form, NOT redirect to /servers/None."""
        page.goto(f"{plugin_base}/servers/add/")
        page.get_by_label("CA / Server URL", exact=True).fill("http://not-real")
        page.locator('[name="_create"]').click()
        page.wait_for_load_state("networkidle")

        _assert_no_none_pk(page)
        _check_no_django_error(page)
        # Either stayed on /add/ or back on add form — never on /servers/None
        assert "servers/None" not in page.url
        # An invalid form re-renders with 200, so any 4xx/5xx here is a real fault.
        _assert_no_http_errors(track_http_errors)


# ---------------------------------------------------------------------------
# Server tabs
# ---------------------------------------------------------------------------


class TestKeaServerTabs:
    """Every Server tab renders against the harness Kea daemons."""

    @pytest.mark.parametrize("family", [4, 6])
    def test_switch_with_missing_subnet_and_state_filter_keeps_browser_history(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        nb_api,
        kea_url: str,
        kea_dhcp6_url: str,
        track_http_errors: list,
        family: int,
    ) -> None:
        """Dropping an unconfirmed Subnet keeps the state filter and one Back step."""
        second = nb_api.plugins.kea.servers.create(
            name=f"{kea_server.name}-missing-subnet",
            ca_url=kea_url,
            dhcp6_url=kea_dhcp6_url,
            has_control_agent=False,
        )
        try:
            page.goto(f"{plugin_base}/servers/{kea_server.id}/leases{family}/?by=subnet_id&q=999999&state=0")
            page.wait_for_load_state("networkidle")
            source_url = page.url
            shell = page.locator("#kea-workspace-shell")
            shell.get_by_role("button", name="Switch Server", exact=True).click()
            shell.get_by_role("navigation", name="Switch Server").get_by_role(
                "link", name=second.name, exact=True
            ).click()
            page.wait_for_url(re.compile(rf"/servers/{second.id}/leases{family}/"))
            page.wait_for_load_state("networkidle")
            expect(shell.get_by_label("Server Scope")).to_have_text(second.name)
            expect(
                page.get_by_text("Subnet filter dropped: the target Server did not confirm this Subnet.", exact=True)
            ).to_be_visible()
            expect(page.locator("#id_state")).to_have_value("0")
            expect(page.locator("#id_q")).to_have_value("")
            target_url = page.url
            page.go_back()
            expect(page).to_have_url(source_url)
            page.go_forward()
            expect(page).to_have_url(target_url)
            _assert_no_http_errors(track_http_errors)
        finally:
            second.delete()

    @pytest.mark.parametrize("width", [1280, 390], ids=["desktop", "narrow"])
    @pytest.mark.parametrize("family", [4, 6])
    def test_switch_servers_keeps_section_search_and_previous_workspace(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        nb_api,
        kea_url: str,
        kea_dhcp6_url: str,
        track_http_errors: list,
        width: int,
        family: int,
    ) -> None:
        """Switch on Subnets and filtered Leases, then restore the previous selection."""
        second = nb_api.plugins.kea.servers.create(
            name=f"{kea_server.name}-switch",
            ca_url=kea_url,
            dhcp6_url=kea_dhcp6_url,
            has_control_agent=False,
        )
        try:
            page.set_viewport_size({"width": width, "height": 720})
            previous = f"{plugin_base}/combined/subnets{family}/?server={kea_server.id}&server={second.id}"
            previous_path = urlparse(previous).path + "?" + urlparse(previous).query
            for section in ("subnets", "leases"):
                filters = {"return_url": previous_path}
                if section == "leases":
                    filters.update({"sort": "ip_address", "per_page": "50"})
                page.goto(f"{plugin_base}/servers/{kea_server.id}/{section}{family}/?{urlencode(filters)}")
                if section == "leases":
                    with page.expect_response(re.compile(r"value_control=1")):
                        page.locator("#id_by").select_option(label="Hostname")
                    page.locator("#id_q").fill("scope-switch-client")
                    page.locator("#lease-search-btn").click()
                    page.wait_for_url(re.compile(r"q=scope-switch-client"))
                page.wait_for_load_state("networkidle")
                source_url = page.url
                shell = page.locator("#kea-workspace-shell")
                assert shell.get_by_role("button", name="Switch Server", exact=True).count() == 1, shell.aria_snapshot()
                shell.get_by_role("button", name="Switch Server", exact=True).click()
                shell.get_by_role("navigation", name="Switch Server").get_by_role(
                    "link", name=second.name, exact=True
                ).click()
                page.wait_for_url(re.compile(rf"/servers/{second.id}/{section}{family}/"))
                expect(shell.get_by_label("Server Scope")).to_have_text(second.name)
                expect(shell.get_by_role("link", name=f"DHCPv{family}", exact=True)).to_have_attribute(
                    "aria-current", "page"
                )
                query = parse_qs(urlparse(page.url).query)
                assert query["return_url"] == [previous_path]
                if section == "leases":
                    assert query["q"] == ["scope-switch-client"]
                    assert query["by"] == ["hostname"]
                    assert query["sort"] == ["ip_address"]
                    assert query["per_page"] == ["50"]
                    expect(page.locator("#id_q")).to_have_value("scope-switch-client")
                target_url = page.url
                page.go_back()
                expect(page).to_have_url(source_url)
                page.go_forward()
                expect(page).to_have_url(target_url)
                shell.get_by_role("link", name="Back to workspace", exact=True).click()
                expect(page).to_have_url(previous)
            _assert_no_http_errors(track_http_errors)
        finally:
            second.delete()

    def test_lease_search_updates_family_links_and_native_form_context(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """HTMX search keeps filters on family switches and family on native forms."""
        server_url = f"{plugin_base}/servers/{kea_server.id}/"
        page.goto(f"{server_url}leases4/")
        with page.expect_response(re.compile(r"value_control=1")):
            page.locator("#id_by").select_option(label="Hostname")
        page.locator("#id_q").fill("printer.example")
        page.locator("#lease-search-btn").click()
        page.wait_for_url(re.compile(r"q=printer"))
        page.get_by_role("navigation", name="DHCP family").get_by_role("link", name="DHCPv6", exact=True).click()
        page.wait_for_load_state("networkidle")
        assert urlparse(page.url).path.endswith("/leases6/")
        assert parse_qs(urlparse(page.url).query)["q"] == ["printer.example"]
        assert parse_qs(urlparse(page.url).query)["by"] == ["hostname"]
        expect(page.locator("#id_q")).to_have_value("printer.example")
        for action in ("Edit", "Delete"):
            page.goto(f"{server_url}subnets6/")
            if action == "Delete":
                control = page.locator('[hx-get][hx-target="#htmx-modal-content"]').filter(
                    has_text=re.compile(r"^\s*Delete\s*$")
                )
                target = control.get_attribute("hx-get") or control.get_attribute("href")
                assert target and parse_qs(urlparse(target).query)["family"] == ["6"]
                control.click()
                shell = page.locator("#kea-modal-workspace-shell")
            else:
                control = page.get_by_role("button", name=action, exact=True)
                control.click()
                shell = page.locator("#kea-workspace-shell")
            expect(shell.get_by_role("link", name="DHCPv6", exact=True)).to_have_attribute("aria-current", "page")
        page.goto(f"{server_url}sync_status/?family=6")
        page.locator("p").filter(has_text="Server overrides").get_by_role("link", name="configure", exact=True).click()
        expect(page.locator("#kea-workspace-shell").get_by_role("link", name="DHCPv6", exact=True)).to_have_attribute(
            "aria-current", "page"
        )
        for label in ("Journal", "Changelog", "Jobs"):
            page.goto(f"{server_url}leases6/")
            page.get_by_role("link", name=label, exact=True).click()
            expect(
                page.locator("#kea-workspace-shell").get_by_role("link", name="DHCPv6", exact=True)
            ).to_have_attribute("aria-current", "page")
            page.get_by_role("navigation", name="Workspace sections").get_by_role(
                "link", name="Leases", exact=True
            ).click()
            page.wait_for_load_state("networkidle")
            assert urlparse(page.url).path.endswith("/leases6/")
        _assert_no_http_errors(track_http_errors)

    def test_server_detail_page_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Detail page of a live Kea server loads without errors."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/")
        _check_no_django_error(page)
        expect(page.get_by_role("heading", name=kea_server.name)).to_be_visible()
        _assert_no_http_errors(track_http_errors)

    def test_server_status_url_opens_overview(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/status/")
        expect(page).to_have_url(f"{plugin_base}/servers/{server_id}/")
        _check_no_django_error(page)
        expect(page.locator("#kea-server-status").get_by_text("Uptime", exact=True).first).to_be_visible()
        expect(page.get_by_role("link", name="Status", exact=True)).to_have_count(0)
        _assert_no_http_errors(track_http_errors)

        # The helper returns "" for every failure, so an empty result proves nothing.
        logs = _tail_container_logs()
        if logs:
            assert "ERROR" not in logs, f"Unexpected server errors after Overview:\n{logs}"

    @pytest.mark.parametrize("width", [1280, 390], ids=["desktop", "narrow"])
    @pytest.mark.parametrize("mode", ["light", "dark"])
    def test_server_workspace_keeps_scope_on_sections_and_forms(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
        width: int,
        mode: str,
    ) -> None:
        """One Server keeps usable shared navigation on sections and mutation forms."""
        server_url = f"{plugin_base}/servers/{kea_server.id}/"
        labels = ("Overview", "Leases", "Subnets", "Reservations", "Configuration", "Sync")
        page.set_viewport_size({"width": width, "height": 360})
        page.add_init_script(f"localStorage.setItem('netbox-color-mode', '{mode}');")
        page.goto(server_url)
        for family in (4, 6):
            page.get_by_role("navigation", name="DHCP family").get_by_role(
                "link", name=f"DHCPv{family}", exact=True
            ).click()
            for label in labels:
                page.get_by_role("navigation", name="Workspace sections").get_by_role(
                    "link", name=label, exact=True
                ).click()
                page.wait_for_load_state("networkidle")
                shell = page.locator("#kea-workspace-shell")
                expect(shell.get_by_label("Server Scope")).to_have_text(kea_server.name)
                expect(page.locator("html")).to_have_attribute("data-bs-theme", mode)
                expect(shell.get_by_role("link", name=f"DHCPv{family}", exact=True)).to_have_attribute(
                    "aria-current", "page"
                )
                sections = shell.get_by_role("navigation", name="Workspace sections")
                assert sections.get_by_role("link").all_text_contents() == list(labels)
                expect(sections.get_by_role("link", name=label, exact=True)).to_have_attribute("aria-current", "page")
                expect(page.get_by_role("link", name="Journal", exact=True)).to_be_visible()
                expect(page.get_by_role("link", name="Changelog", exact=True)).to_be_visible()
                expect(page.get_by_role("link", name="Jobs", exact=True)).to_be_visible()
                expect(page.get_by_role("link", name="Status", exact=True)).to_have_count(0)
                if label == "Overview":
                    for daemon in ("DHCPv4", "DHCPv6"):
                        status = page.locator("#kea-server-status .card").filter(
                            has=page.locator(".card-header", has_text=re.compile(rf"^\s*{daemon}(?!:)"))
                        )
                        expect(status.get_by_text("Uptime", exact=True)).to_be_visible()
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_function("window.scrollY > 0")
                geometry = shell.evaluate("""el => {
                    const rect = el.getBoundingClientRect();
                    const navbar = document.querySelector('header.navbar.sticky-top');
                    const navbarBottom = navbar && getComputedStyle(navbar).display !== 'none'
                        ? navbar.getBoundingClientRect().bottom : 0;
                    return {top: rect.top, bottom: rect.bottom, navbarBottom, height: window.innerHeight};
                }""")
                assert geometry["top"] >= geometry["navbarBottom"] - 1
                assert geometry["bottom"] <= geometry["height"]
                sections.get_by_role("link", name="Overview", exact=True).focus()
                page.keyboard.press("Tab")
                expect(sections.get_by_role("link", name="Leases", exact=True)).to_be_focused()
            for route in (
                f"leases{family}/add/",
                f"reservations{family}/add/",
                f"subnets{family}/add/",
                f"subnets{family}/1/pools/add/",
                f"subnets{family}/1/options/",
                f"shared-networks{family}/add/",
                f"dhcp{family}/option-def/add/",
                f"dhcp{family}/options/",
                f"edit/?family={family}",
                f"delete/?family={family}",
            ):
                response = page.goto(f"{server_url}{route}")
                assert response is not None and response.ok
                shell = page.locator("#kea-workspace-shell")
                expect(shell.get_by_label("Server Scope")).to_have_text(kea_server.name)
                expect(shell.get_by_role("link", name=f"DHCPv{family}", exact=True)).to_have_attribute(
                    "aria-current", "page"
                )
                expect(page.locator('form[method="post"]:visible').first).to_be_visible()
                _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

    def test_server_leases4_tab(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/leases4/")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

    def test_server_leases6_tab(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/leases6/")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

    def test_server_subnets4_tab(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/subnets4/")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

    def test_server_subnets6_tab(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/subnets6/")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

    def test_edit_server_via_form(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Editing a server via the edit form redirects to a real integer-pk URL."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/edit/")
        _check_no_django_error(page)

        name_field = page.get_by_label("Name", exact=True)
        original = name_field.input_value()
        name_field.fill(f"{original}-edited")
        # force=True bypasses Django Debug Toolbar overlay pointer-event interception
        page.locator('[name="_update"]').click(force=True)
        page.wait_for_load_state("networkidle")

        _assert_no_none_pk(page)
        _check_no_django_error(page)
        assert re.search(r"/servers/\d+", page.url), f"Expected redirect to integer-pk detail URL, got: {page.url}"
        _assert_no_http_errors(track_http_errors)

    def test_bulk_edit_selected_server_reaches_edit_page(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Selecting a server and clicking 'Edit Selected' reaches /servers/edit/."""
        page.goto(f"{plugin_base}/servers/")
        _dismiss_debug_toolbar(page)
        # Select the first row checkbox
        page.locator("table input[type=checkbox]").first.check()
        page.get_by_role("button", name=re.compile(r"edit.?selected", re.IGNORECASE)).click()
        page.wait_for_load_state("networkidle")

        _assert_no_none_pk(page)
        _check_no_django_error(page)
        assert "servers/edit" in page.url, f"Expected /servers/edit/ after bulk edit, got: {page.url}"
        _assert_no_http_errors(track_http_errors)

    def test_delete_server_via_confirmation_form(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        nb_http: requests.Session,
        netbox_url: str,
        track_http_errors: list,
    ) -> None:
        """Confirming server deletion removes it from NetBox."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/delete/")
        _check_no_django_error(page)

        # Submit via JS — djDebug intercepts pointer events.
        _submit_and_wait_nav(
            page,
            "var forms = document.querySelectorAll('form[method=\"post\"]'); forms[forms.length - 1].submit()",
        )

        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

        # Verify the API agrees the server is gone
        resp = nb_http.get(f"{netbox_url}/api/plugins/kea/servers/{server_id}/", timeout=5)
        assert resp.status_code == 404, f"Server {server_id} should be deleted but API returned {resp.status_code}"


# ---------------------------------------------------------------------------
# TestCombinedViews — navigation checks, no live Kea required
# ---------------------------------------------------------------------------


class TestCombinedViews:
    """Combined multi-server views load and show the expected structure."""

    COMBINED_TABS = [
        ("combined", "combined/"),
        ("combined_leases4", "combined/leases4/"),
        ("combined_leases6", "combined/leases6/"),
        ("combined_reservations4", "combined/reservations4/"),
        ("combined_reservations6", "combined/reservations6/"),
        ("combined_subnets4", "combined/subnets4/"),
        ("combined_subnets6", "combined/subnets6/"),
    ]

    @pytest.mark.parametrize(
        ("_tab_name", "path"),
        COMBINED_TABS,
        ids=[name for name, _path in COMBINED_TABS],
    )
    def test_combined_tab_loads(
        self,
        _tab_name: str,
        path: str,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        track_http_errors: list,
    ) -> None:
        page.goto(f"{plugin_base}/{path}")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

    def test_combined_dashboard_has_navigation_tabs(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        track_http_errors: list,
    ) -> None:
        """Combined dashboard must render tab links for all sub-views."""
        page.goto(f"{plugin_base}/combined/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        sections = page.get_by_role("navigation", name="Workspace sections")
        for label in ("Overview", "Leases", "Subnets", "Reservations", "Configuration", "Sync"):
            link = sections.get_by_role("link", name=label, exact=True)
            expect(link).to_be_visible()
        families = page.get_by_role("navigation", name="DHCP family")
        expect(families.get_by_role("link", name="DHCPv4", exact=True)).to_be_visible()
        expect(families.get_by_role("link", name="DHCPv6", exact=True)).to_be_visible()
        _assert_no_http_errors(track_http_errors)


# ---------------------------------------------------------------------------
# TestCombinedViewsWithKea — column/table structure with a real server
# ---------------------------------------------------------------------------


class TestCombinedViewsWithKea:
    """Combined view content checks that require a live Kea server fixture."""

    @pytest.mark.parametrize("section", ["leases", "configuration", "sync"])
    @pytest.mark.parametrize("family", [4, 6])
    def test_chooser_returns_to_selected_workspace(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        nb_api,
        kea_url: str,
        kea_dhcp6_url: str,
        track_http_errors: list,
        section: str,
        family: int,
    ) -> None:
        """Every chooser restores the selected Servers and the Lease search."""
        second = nb_api.plugins.kea.servers.create(
            name=f"{kea_server.name}-chooser",
            ca_url=kea_url,
            dhcp6_url=kea_dhcp6_url,
            has_control_agent=False,
        )
        try:
            query = [("server", str(kea_server.id)), ("server", str(second.id))]
            if section == "leases":
                query.extend([("q", "documentation-client"), ("by", "hostname")])
            origin = f"{plugin_base}/combined/{section}{family}/?{urlencode(query)}"
            page.goto(origin)
            page.get_by_role("link", name=second.name, exact=True).click()
            target_path = {
                "leases": f"leases{family}/",
                "configuration": f"dhcp{family}/option-def/",
                "sync": "sync_status/",
            }[section]
            page.wait_for_url(re.compile(rf"/servers/{second.id}/{target_path}\?"))
            shell = page.locator("#kea-workspace-shell")
            expect(shell.get_by_label("Server Scope")).to_have_text(second.name)
            expect(shell.get_by_role("link", name=f"DHCPv{family}", exact=True)).to_have_attribute(
                "aria-current", "page"
            )
            target_query = parse_qs(urlparse(page.url).query)
            assert target_query["return_url"] == [urlparse(origin).path + "?" + urlparse(origin).query]
            if section == "leases":
                expect(page.locator("#id_q")).to_have_value("documentation-client")
                assert target_query["by"] == ["hostname"]
            destination = page.url
            page.go_back()
            expect(page).to_have_url(origin)
            page.go_forward()
            expect(page).to_have_url(destination)
            shell.get_by_role("link", name="Back to workspace", exact=True).click()
            expect(page).to_have_url(origin)
            _assert_no_http_errors(track_http_errors)
        finally:
            second.delete()

    @pytest.mark.parametrize("family", [4, 6])
    def test_disabled_single_server_uses_canonical_workspace(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
        family: int,
    ) -> None:
        """A disabled family still resolves one selected Server to its own workspace."""
        kea_server.update({f"dhcp{family}": False})
        page.goto(f"{plugin_base}/combined/leases{family}/?server={kea_server.id}")
        expect(page).to_have_url(f"{plugin_base}/servers/{kea_server.id}/leases{family}/")
        expect(page.get_by_text("Protocol not enabled", exact=True)).to_be_visible()
        shell = page.locator("#kea-workspace-shell")
        expect(shell.get_by_label("Server Scope")).to_have_text(kea_server.name)
        other_family = 6 if family == 4 else 4
        shell.get_by_role("link", name=f"DHCPv{other_family}", exact=True).click()
        expect(page).to_have_url(f"{plugin_base}/servers/{kea_server.id}/leases{other_family}/")
        _assert_no_http_errors(track_http_errors)

    @pytest.mark.parametrize("width", [1280, 390], ids=["desktop", "narrow"])
    def test_filtered_reservation_returns_from_owning_server(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        nb_api,
        kea_url: str,
        kea_dhcp6_url: str,
        kea_client: "_DualEndpointKeaClient",
        track_http_errors: list,
        width: int,
    ) -> None:
        """Open an owning Server, edit its Reservation and restore the filtered workspace."""
        identifier = "e2:e2:e2:e2:e2:12"
        second = nb_api.plugins.kea.servers.create(
            name=f"{kea_server.name}-return",
            ca_url=kea_url,
            dhcp6_url=kea_dhcp6_url,
            has_control_agent=False,
        )
        try:
            page.set_viewport_size({"width": width, "height": 720})
            page.goto(f"{plugin_base}/servers/{kea_server.id}/reservations4/add/")
            cidr = _subnet_cidr_for_id(page, 1)
            address = str(ipaddress.ip_network(cidr)[-40])
            kea_client.command(
                "reservation-add",
                4,
                arguments={
                    "reservation": {
                        "subnet-id": 1,
                        "hw-address": identifier,
                        "ip-address": address,
                        "hostname": "workspace-return-client",
                    }
                },
            )
            page.goto(f"{plugin_base}/combined/reservations4/?server={kea_server.id}&server={second.id}")
            page.locator("#id_q").fill("workspace-return")
            page.locator("#id_subnet_id").select_option("1")
            page.locator("#id_scope").select_option("in-subnet")
            page.get_by_role("button", name=re.compile(r"Filter$")).click()
            page.wait_for_load_state("networkidle")
            workspace_url = page.url
            workspace_path = urlparse(workspace_url).path + "?" + urlparse(workspace_url).query
            rows = page.locator("table.object-list > tbody > tr").filter(has_text=identifier)
            expect(rows).to_have_count(2)
            row = rows.filter(has=page.get_by_role("link", name=second.name, exact=True))
            row.get_by_role("link", name=second.name, exact=True).click()
            page.wait_for_load_state("networkidle")
            assert urlparse(page.url).path == f"/plugins/kea/servers/{second.id}/reservations4/"
            assert parse_qs(urlparse(page.url).query)["return_url"] == [workspace_path]
            shell = page.locator("#kea-workspace-shell")
            expect(shell.get_by_label("Server Scope")).to_have_text(second.name)
            back = shell.get_by_role("link", name=re.compile(r"Back to"))
            expect(back).to_have_attribute("href", workspace_path)
            server_url = page.url
            back.click()
            expect(page).to_have_url(workspace_url)
            rows.filter(has=page.get_by_role("link", name=second.name, exact=True)).get_by_role(
                "link", name=second.name, exact=True
            ).click()
            expect(page).to_have_url(server_url)
            page.go_back()
            expect(page).to_have_url(workspace_url)
            page.go_forward()
            expect(page).to_have_url(server_url)
            for label in ("Overview", "Subnets", "Reservations"):
                page.get_by_role("navigation", name="Workspace sections").get_by_role(
                    "link", name=label, exact=True
                ).click()
                expect(shell.get_by_role("link", name=re.compile(r"Back to"))).to_have_attribute("href", workspace_path)
            page.get_by_role("link", name="Journal", exact=True).click()
            expect(shell.get_by_role("link", name=re.compile(r"Back to"))).to_have_attribute("href", workspace_path)
            page.get_by_role("navigation", name="Workspace sections").get_by_role(
                "link", name="Reservations", exact=True
            ).click()
            page.locator("table.object-list > tbody > tr").filter(has_text=identifier).locator(
                'a[href*="/edit/"]'
            ).click()
            page.wait_for_load_state("networkidle")
            expect(page.locator("#kea-workspace-shell").get_by_label("Server Scope")).to_have_text(second.name)
            expect(page.get_by_role("link", name="Cancel", exact=True)).to_have_attribute("href", workspace_path)
            page.locator("#id_hostname").fill("workspace-return-edited")
            _submit_and_wait_nav(page, "document.getElementById('id_hostname').closest('form').submit()")
            expect(page).to_have_url(workspace_url)
            expect(page.locator("#id_q")).to_have_value("workspace-return")
            expect(page.locator("#id_subnet_id")).to_have_value("1")
            expect(page.locator("#id_scope")).to_have_value("in-subnet")
            assert set(parse_qs(urlparse(page.url).query)["server"]) == {str(kea_server.id), str(second.id)}
            expect(page.locator("table.object-list > tbody > tr").filter(has_text=identifier)).to_have_count(2)
            # Both Servers read one daemon, but the edit rotates only the generation of its own Server (ADR 0009).
            expect(page.get_by_text("workspace-return-edited", exact=True)).to_have_count(1)
            page.get_by_role("button", name="Refresh").click()
            expect(page.get_by_text("workspace-return-edited", exact=True)).to_have_count(2)
            expect(page).to_have_url(workspace_url)
            _assert_no_http_errors(track_http_errors)
        finally:
            kea_client.command(
                "reservation-del",
                4,
                arguments={"subnet-id": 1, "identifier-type": "hw-address", "identifier": identifier},
                check=(0, 3),
            )
            second.delete()

    @pytest.mark.parametrize("width", [1280, 390], ids=["desktop", "narrow"])
    @pytest.mark.parametrize("mode", ["light", "dark"])
    def test_shared_workspace_keeps_scope_across_sections_and_families(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        nb_api,
        kea_url: str,
        kea_dhcp6_url: str,
        track_http_errors: list,
        width: int,
        mode: str,
    ) -> None:
        """Two selected Servers keep a usable scope bar throughout workspace navigation."""
        second = nb_api.plugins.kea.servers.create(
            name=f"{kea_server.name}-workspace",
            ca_url=kea_url,
            dhcp6_url=kea_dhcp6_url,
            has_control_agent=False,
        )
        try:
            page.set_viewport_size({"width": width, "height": 360})
            page.add_init_script(f"localStorage.setItem('netbox-color-mode', '{mode}');")
            page.goto(f"{plugin_base}/combined/?server={kea_server.id}&server={second.id}")
            for family in (4, 6):
                page.get_by_role("navigation", name="DHCP family").get_by_role(
                    "link", name=f"DHCPv{family}", exact=True
                ).click()
                for label in ("Overview", "Leases", "Subnets", "Reservations", "Configuration", "Sync"):
                    page.get_by_role("navigation", name="Workspace sections").get_by_role(
                        "link", name=label, exact=True
                    ).click()
                    page.wait_for_load_state("networkidle")
                    expect(page.locator("html")).to_have_attribute("data-bs-theme", mode)
                    shell = page.locator("#kea-workspace-shell")
                    expect(shell.get_by_label("Server Scope")).to_have_text("2 Servers selected")
                    expect(shell.get_by_role("link", name=f"DHCPv{family}", exact=True)).to_have_attribute(
                        "aria-current", "page"
                    )
                    assert set(parse_qs(urlparse(page.url).query)["server"]) == {str(kea_server.id), str(second.id)}
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    page.wait_for_function("window.scrollY > 0")
                    geometry = shell.evaluate("""el => {
                        const rect = el.getBoundingClientRect();
                        const navbar = document.querySelector('header.navbar.sticky-top');
                        const navbarBottom = navbar && getComputedStyle(navbar).display !== 'none'
                            ? navbar.getBoundingClientRect().bottom : 0;
                        return {top: rect.top, bottom: rect.bottom, navbarBottom, height: window.innerHeight};
                    }""")
                    assert geometry["top"] >= geometry["navbarBottom"] - 1
                    assert geometry["bottom"] <= geometry["height"]
                    expect(shell.get_by_label("Server Scope")).to_be_in_viewport()
                    # Keyboard focus remains available after scrolling on narrow layouts.
                    active = shell.get_by_role("link", name=label, exact=True)
                    active.focus()
                    expect(active).to_be_focused()
                    sections = shell.get_by_role("navigation", name="Workspace sections")
                    sections.get_by_role("link", name="Overview", exact=True).focus()
                    page.keyboard.press("Tab")
                    expect(sections.get_by_role("link", name="Leases", exact=True)).to_be_focused()
                    _assert_no_http_errors(track_http_errors)
        finally:
            second.delete()

    def test_server_selector_applies_two_servers_together(
        self,
        page: Page,
        plugin_base: str,
        kea_server,
        nb_api,
        kea_url: str,
        kea_dhcp6_url: str,
        track_http_errors: list,
    ) -> None:
        """Two checked Servers stay on the combined page after Apply."""
        second = nb_api.plugins.kea.servers.create(
            name=f"{kea_server.name}-second",
            ca_url=kea_url,
            dhcp6_url=kea_dhcp6_url,
            has_control_agent=False,
        )
        try:
            url = f"{plugin_base}/combined/"
            page.goto(url)
            page.get_by_role("button", name=re.compile(r"Servers")).click()
            form = page.locator("#server-filter-form")
            form.locator(f"#srv_{kea_server.id}").check()
            expect(page).to_have_url(url)
            form.locator(f"#srv_{second.id}").check()
            expect(page).to_have_url(url)
            form.get_by_role("button", name="Apply", exact=True).click()
            page.wait_for_url(re.compile(r"/combined/\?"))
            selected = {int(value) for value in parse_qs(urlparse(page.url).query)["server"]}
            assert selected == {kea_server.id, second.id}
            cards = page.locator(".card-header")
            expect(cards.get_by_role("link", name=kea_server.name, exact=True)).to_be_visible()
            expect(cards.get_by_role("link", name=second.name, exact=True)).to_be_visible()
            page.get_by_role("button", name=re.compile(r"Servers")).click()
            expect(form.locator(f"#srv_{kea_server.id}")).to_be_checked()
            expect(form.locator(f"#srv_{second.id}")).to_be_checked()
            _assert_no_http_errors(track_http_errors)
        finally:
            second.delete()

    def test_lease_chooser_opens_a_server_for_lease_search(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        reserved_lease4: str,
        track_http_errors: list,
    ) -> None:
        """Choose a named Server and search its seeded lease."""
        page.goto(f"{plugin_base}/combined/leases4/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        page.locator(".list-group").get_by_role("link", name=kea_server.name, exact=True).click()
        page.wait_for_url(re.compile(rf"/servers/{kea_server.id}/leases4/\?"))
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        page.locator("#id_q").fill(reserved_lease4)
        page.locator("#id_by + div.form-select").click()
        with page.expect_response(re.compile(r"value_control=1")):
            page.locator("#id_by-ts-dropdown").get_by_role("option", name="IP Address", exact=True).click()
        with page.expect_response(re.compile(r"/leases4/")) as response:
            page.get_by_role("button", name="Search", exact=True).click()
        assert response.value.ok
        rows = page.locator("table.object-list > tbody > tr")
        expect(rows).to_have_count(1)
        expect(rows.first).to_contain_text(reserved_lease4)
        # A chooser link carries a search; this absent address proves that the Server page filters.
        page.goto(f"{plugin_base}/combined/leases4/?q=203.0.113.250&by=ip")
        page.locator(".list-group").get_by_role("link", name=kea_server.name, exact=True).click()
        page.wait_for_url(re.compile(rf"/servers/{kea_server.id}/leases4/\?"))
        query = parse_qs(urlparse(page.url).query)
        assert query["q"] == ["203.0.113.250"]
        assert query["by"] == ["ip"]
        page.wait_for_load_state("networkidle")
        expect(page.locator("table.object-list")).to_be_visible()
        expect(rows.filter(has_text=reserved_lease4)).to_have_count(0)
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

    def test_combined_reservations4_server_column_present(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Combined reservations4 table must include a 'Server' column header."""
        # Reservations view also renders table on page load (no search required)
        page.goto(f"{plugin_base}/combined/reservations4/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        expect(page.locator("th", has_text="Server").first).to_be_visible()
        _assert_no_http_errors(track_http_errors)

    def test_combined_reservations4_lease_column_present(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Combined reservations4 table must include a 'Lease' column header."""
        page.goto(f"{plugin_base}/combined/reservations4/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        expect(page.locator("th", has_text="Lease").first).to_be_visible()
        _assert_no_http_errors(track_http_errors)

    def test_per_server_leases4_reserved_column_present(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Per-server leases4 table must include the Reserved column."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/leases4/?q=192.0.2.1&by=ip")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        expect(page.locator("th", has_text="Reserved").first).to_be_visible()
        _assert_no_http_errors(track_http_errors)

    def test_per_server_reservations4_lease_column_present(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Per-server reservations4 table must include 'Lease' and 'NetBox IP' columns."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/reservations4/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        expect(page.locator("th", has_text="Lease").first).to_be_visible()
        expect(page.locator("th", has_text="NetBox IP").first).to_be_visible()
        _assert_no_http_errors(track_http_errors)


# ---------------------------------------------------------------------------
# TestBadgeEnrichment — verify badge rendering with live Kea data
# ---------------------------------------------------------------------------


#: A reservation the test Kea already holds in its static config
#: (``tests/docker/kea_configs/kea-dhcp4.conf``): this hardware address reserves this
#: address inside subnet 192.0.2.0/24. Badge assertions need a lease on a *reserved*
#: address, and reusing the configured pair avoids declaring a second reservation.
#: These constants still copy the config, so ``reserved_lease4`` reads the reservation
#: back from Kea and fails there if the two ever drift.
_RESERVED_IP4 = "192.0.2.201"
_RESERVED_MAC4 = "1a:1b:1c:1d:1e:1f"
_RESERVED_SUBNET_ID = 1


@pytest.fixture
def reserved_lease4(kea_client: "_DualEndpointKeaClient", clear_leases: None) -> Iterator[str]:
    """Seed an active lease on a reserved address and yield that address.

    Depends on ``clear_leases`` because that fixture is autouse and wipes every lease;
    without the dependency the seeded lease is not ordered after the wipe.
    """
    # Fail here, not on a badge locator, if the Kea config stops reserving this pair:
    # the lease would still add (the address is in-subnet) and every badge assertion
    # would fail pointing at the badge code instead of at the config.
    reserved = kea_client.command(
        "reservation-get",
        4,
        arguments={"subnet-id": _RESERVED_SUBNET_ID, "identifier-type": "hw-address", "identifier": _RESERVED_MAC4},
        check=(0, 3),
    )[0]
    assert reserved["result"] == 0, (
        f"kea-dhcp4.conf no longer reserves {_RESERVED_MAC4}; update _RESERVED_MAC4/_RESERVED_IP4"
    )
    assert reserved["arguments"]["ip-address"] == _RESERVED_IP4, (
        f"{_RESERVED_MAC4} now reserves {reserved['arguments']['ip-address']}, not {_RESERVED_IP4}"
    )
    kea_client.command(
        "lease4-add",
        4,
        arguments={
            "ip-address": _RESERVED_IP4,
            "hw-address": _RESERVED_MAC4,
            "hostname": "reserved-client",
        },
    )
    try:
        yield _RESERVED_IP4
    finally:
        kea_client.command("lease4-del", 4, arguments={"ip-address": _RESERVED_IP4}, check=(0, 3))


class TestBadgeEnrichment:
    """Badge enrichment rendering against live Kea servers.

    These tests inspect live Reservation and lease data through the plugin UI.
    """

    def test_reserved_badge_appears_on_leases4_for_known_reservation(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        reserved_lease4: str,
        track_http_errors: list,
    ) -> None:
        """A lease with a matching reservation must show the 'Reserved' badge on the leases page."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/leases4/?q={reserved_lease4}&by=ip")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

        expect(page.locator("th", has_text="Reserved").first).to_be_visible()

        # The seeded lease sits on a configured reservation, so the row must exist and
        # carry the badge. The logged-in user may change the server, so the badge is the
        # linked variant (netbox_kea/tables.py gates the link on can_change_reservation).
        row = page.locator("table.object-list > tbody > tr").filter(has_text=reserved_lease4)
        expect(row).to_have_count(1)
        reserved_link = row.locator('a.badge:has-text("Reserved")')
        expect(reserved_link).to_have_count(1)
        href = reserved_link.get_attribute("href")
        assert href and "reservations4" in href, f"Reserved badge link href does not point to reservations: {href}"

    def test_active_lease_badge_is_link_on_reservations4_page(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        reserved_lease4: str,
        track_http_errors: list,
    ) -> None:
        """'Active Lease' badges on the reservations4 page must be clickable links."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/reservations4/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

        expect(page.locator("th", has_text="Lease").first).to_be_visible()

        # 'Active Lease' must be an <a>, never a plain <span>
        active_spans = page.locator('span.badge:has-text("Active Lease")')
        assert active_spans.count() == 0, (
            f"Found {active_spans.count()} non-link 'Active Lease' badge(s); they must all be <a> elements"
        )

        # 'No Lease' must be a plain <span>, never a link
        no_lease_links = page.locator('a.badge:has-text("No Lease")')
        assert no_lease_links.count() == 0, (
            f"Found {no_lease_links.count()} linked 'No Lease' badge(s); they must be plain spans"
        )

        # The seeded lease is on a reserved address, so that reservation's row must
        # report an Active Lease and link to the search that finds it.
        row = page.locator("table.object-list > tbody > tr").filter(has_text=_RESERVED_MAC4)
        expect(row).to_have_count(1)
        active_link = row.locator('a.badge:has-text("Active Lease")')
        expect(active_link).to_have_count(1)
        href = active_link.get_attribute("href")
        assert href and "leases4" in href, f"Active Lease link href does not point to leases4: {href}"
        # Parse rather than match a substring: the view emits `?by=ip&q=...`, so the
        # earlier `"?q=" in href` check was false for every real link it never ran on.
        query = parse_qs(urlparse(href).query)
        assert query.get("q") == [reserved_lease4], f"Active Lease link does not search the leased address: {href}"

    def test_active_lease_link_navigates_to_lease_search(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        reserved_lease4: str,
        track_http_errors: list,
    ) -> None:
        """Clicking an 'Active Lease' badge navigates to the lease search page without errors."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/reservations4/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)

        # Click the badge belonging to the seeded reservation, not whichever renders
        # first: a wrong-but-valid lease URL must not pass.
        row = page.locator("table.object-list > tbody > tr").filter(has_text=_RESERVED_MAC4)
        expect(row).to_have_count(1)
        active_link = row.locator('a.badge:has-text("Active Lease")')
        expect(active_link).to_have_count(1)

        active_link.click()
        page.wait_for_load_state("networkidle")

        _check_no_django_error(page)
        assert "leases4" in page.url, f"Expected leases4 URL after click, got: {page.url}"
        assert parse_qs(urlparse(page.url).query).get("q") == [reserved_lease4], (
            f"Active Lease badge did not navigate to the search for {reserved_lease4}: {page.url}"
        )
        expect(page.locator("table.object-list > tbody > tr").filter(has_text=reserved_lease4)).to_have_count(1)
        _assert_no_http_errors(track_http_errors)

    def test_combined_reservations4_active_lease_badge_is_link(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        reserved_lease4: str,
        track_http_errors: list,
    ) -> None:
        """Combined reservations4 'Active Lease' badges must also be <a> links."""
        page.goto(f"{plugin_base}/combined/reservations4/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)

        active_spans = page.locator('span.badge:has-text("Active Lease")')
        assert active_spans.count() == 0, (
            f"Found {active_spans.count()} non-link 'Active Lease' badge(s) in combined view"
        )

        # Without a seeded lease every reservation reports "No Lease", so the span check
        # above holds with zero badges of either kind. Assert the link positively too.
        #
        # This view aggregates every registered Server, and the suite's servers all
        # address the same Kea daemon, so the reservation renders once per Server and
        # the row count is whatever else the session has registered. Assert exactly one
        # badge per row for this reservation instead of pinning a row count.
        rows = page.locator("table.object-list > tbody > tr").filter(has_text=_RESERVED_MAC4)
        expect(rows.first).to_be_visible()
        for row in rows.all():
            expect(row.locator('a.badge:has-text("Active Lease")')).to_have_count(1)

    def test_netbox_ip_synced_badge_or_sync_button_present_on_leases4(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        reserved_lease4: str,
        track_http_errors: list,
    ) -> None:
        """The Server lease page shows one NetBox IP widget for the seeded lease."""
        page.goto(f"{plugin_base}/servers/{kea_server.id}/leases4/?q={reserved_lease4}&by=ip")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("th", has_text="NetBox IP").first).to_be_visible()
        row = page.locator("table.object-list > tbody > tr").filter(has_text=reserved_lease4)
        expect(row).to_have_count(1)
        widgets = row.locator('a.badge:has-text("Synced"), button.badge:has-text("Sync")')
        expect(widgets).to_have_count(1)


# ---------------------------------------------------------------------------
# Lease search modes (live Kea)
# ---------------------------------------------------------------------------


class TestLeaseSearchModes:
    """Verify each lease search mode renders the table correctly against live Kea."""

    def test_search_by_subnet_shows_table(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Searching leases4 by subnet_id renders headers without a Django error."""
        server_id = kea_server.id
        # Navigate directly with URL params — avoids Tom Select interaction
        page.goto(f"{plugin_base}/servers/{server_id}/leases4/?q=1&by=subnet_id")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("th", has_text="IP Address").first).to_be_visible()

    def test_search_by_ip_shows_result_or_empty(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Searching leases4 by IP produces a valid page (found or not-found, never a 500)."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/leases4/?q=192.0.2.1&by=ip")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("th", has_text="IP Address").first).to_be_visible()

    def test_search_by_hostname_renders_table(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Searching leases4 by hostname renders the table without errors."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/leases4/?q=test&by=hostname")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("th", has_text="IP Address").first).to_be_visible()

    def test_search_by_mac_renders_table(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Searching leases4 by hardware address renders the table without errors.

        Note: BY_HW_ADDRESS constant value is "hw" (not "hw_address").
        """
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/leases4/?q=aa:bb:cc:dd:ee:ff&by=hw")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("th", has_text="IP Address").first).to_be_visible()

    def test_csv_export_returns_csv_content(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
    ) -> None:
        """CSV export for leases4 returns text/csv content.

        Uses the browser session (via page.context.request) so Django's session
        auth is used — regular plugin views don't accept Token auth headers.
        """
        server_id = kea_server.id
        url = f"{plugin_base}/servers/{server_id}/leases4/?q=1&by=subnet_id&export=all"
        # page.context.request shares the browser's cookie jar (including the session
        # cookie set by netbox_login), so it's fully authenticated.
        response = page.context.request.get(url)
        assert response.ok, f"CSV export returned HTTP {response.status}"
        ct = response.headers.get("content-type", "")
        assert "text/csv" in ct or "text/plain" in ct, f"Expected CSV content-type, got: {ct}"


# ---------------------------------------------------------------------------
# Reservation CRUD via UI (live Kea)
# ---------------------------------------------------------------------------


class TestReservationCRUD:
    """End-to-end create → verify → edit → delete reservation cycle via the UI."""

    # Deterministic test data — unlikely to clash with real production entries
    _TEST_MAC = "e2:e2:e2:e2:e2:01"
    _TEST_HOSTNAME = "e2e-crud-test"
    _TEST_HOSTNAME_EDITED = "e2e-crud-edited"
    _SUBNET_ID = 1
    # Host offset inside the selected Subnet. High enough to sit outside the pools a
    # live Kea normally allocates from, so the reservation does not clash with a lease.
    _TEST_HOST_OFFSET = -34
    # A second identifier and address, so the state test never races the CRUD test.
    _STATE_MAC = "e2:e2:e2:e2:e2:02"
    _STATE_HOSTNAME = "e2e-state-test"
    # The pagination fixture fills hosts 1 through 250. Use the last usable address.
    _STATE_HOST_OFFSET = -2

    def _test_ip(self, cidr: str, offset: int | None = None) -> str:
        """Return the reservation address at *offset* inside *cidr*.

        The address must belong to the Subnet the live Kea exposes for ``_SUBNET_ID``, so
        derive it instead of pinning one range.
        """
        host_offset = self._TEST_HOST_OFFSET if offset is None else offset
        network = ipaddress.ip_network(cidr)
        assert network.num_addresses > abs(host_offset), (
            f"Subnet {cidr} is too small for a reservation at host offset {host_offset}"
        )
        return str(network[host_offset])

    def _reservation_add_url(self, plugin_base: str, server_id: int) -> str:
        return f"{plugin_base}/servers/{server_id}/reservations4/add/"

    def _reservation_edit_url(self, plugin_base: str, server_id: int, subnet_id: int, identifier: str) -> str:
        query = urlencode({"identifier_type": "hw-address", "identifier": identifier})
        return f"{plugin_base}/servers/{server_id}/reservations4/{subnet_id}/edit/?{query}"

    def _reservation_delete_url(self, plugin_base: str, server_id: int, subnet_id: int, identifier: str) -> str:
        query = urlencode({"identifier_type": "hw-address", "identifier": identifier})
        return f"{plugin_base}/servers/{server_id}/reservations4/{subnet_id}/delete/?{query}"

    def _reservation_list_url(self, plugin_base: str, server_id: int) -> str:
        return f"{plugin_base}/servers/{server_id}/reservations4/"

    def _reservation_row(
        self,
        page: Page,
        plugin_base: str,
        server_id: int,
        identifier: str,
        address: str,
    ) -> Locator:
        """Return the row with both parts of the test Reservation identity."""
        page.goto(self._reservation_list_url(plugin_base, server_id))
        page.wait_for_load_state("networkidle")
        return (
            page.locator("tr")
            .filter(has=page.get_by_text(identifier, exact=True))
            .filter(has=page.get_by_text(address, exact=True))
        )

    def _submit_form_by_field(self, page: Page, field_id: str) -> None:
        """Submit the form that contains *field_id*, waiting for the resulting navigation."""
        _submit_and_wait_nav(page, f"document.getElementById('{field_id}').closest('form').submit()")

    def _fill_reservation_form(
        self,
        page: Page,
        cidr: str,
        ip: str,
        mac: str,
        hostname: str = "",
        identifier_type: str = "hw-address",
    ) -> None:
        """Fill the Reservation4Form fields.

        The ``identifier_type`` ChoiceField is wrapped by Tom Select.
        We set it via JavaScript on the underlying ``<select>`` then dispatch
        a 'change' event so the Tom Select widget syncs its display.
        """
        page.locator("#id_subnet_cidr").select_option(cidr)
        page.locator("#id_ip_address").fill(ip)
        # Tom Select wraps identifier_type — set via JS
        page.evaluate(
            f"""() => {{
                const sel = document.getElementById('id_identifier_type');
                if (sel) {{
                    sel.value = '{identifier_type}';
                    sel.dispatchEvent(new Event('change'));
                }}
            }}"""
        )
        page.locator("#id_identifier").fill(mac)
        if hostname:
            page.locator("#id_hostname").fill(hostname)

    def _ui_cleanup_reservation(
        self,
        page: Page,
        plugin_base: str,
        server_id: int,
        identifier: str,
        address: str,
        *,
        strict: bool,
    ) -> None:
        """Delete the Reservation matching *identifier* and *address* through the UI.

        Safe to call twice. Strict cleanup raises failures. Lenient cleanup warns so it
        does not replace an exception that is already propagating from the test body.
        """
        try:
            stale_row = self._reservation_row(page, plugin_base, server_id, identifier, address)
            row_count = stale_row.count()
            if not row_count:
                return
            assert row_count == 1, f"Found {row_count} Reservations matching {identifier} and {address}"
            # get_attribute returns the raw root-relative href and this suite sets no base_url.
            delete_url = stale_row.first.locator('a[href*="/delete/"]').evaluate("el => el.href")
            assert delete_url
            page.goto(delete_url)
            page.wait_for_load_state("networkidle")
            _submit_and_wait_nav(
                page,
                "document.querySelectorAll('form[method=\"post\"]')"
                "[ document.querySelectorAll('form[method=\"post\"]').length - 1 ].submit()",
            )
            if self._reservation_row(page, plugin_base, server_id, identifier, address).count():
                message = f"Test Reservation {identifier} at {address} is still present after delete"
                if strict:
                    raise AssertionError(message)
                warnings.warn(message, stacklevel=2)
        except Exception as exc:
            if strict:
                raise
            warnings.warn(f"Could not remove test Reservation {identifier} at {address}: {exc}", stacklevel=2)

    @classmethod
    def _netbox_ip_id(
        cls,
        nb_http: requests.Session,
        netbox_url: str,
        address: str,
        hostname: str,
    ) -> int | None:
        """Return the one NetBox IP ID with the complete state-test identity.

        The sync marker identifies the row, not the whole description: the status, and so the marker kind, can
        change, and an operator note can follow the marker.
        """
        found = nb_http.get(
            f"{netbox_url}/api/ipam/ip-addresses/",
            params={"address": address, "dns_name": hostname, "description__isw": _KEA_SYNC_MARKER_PREFIX},
            timeout=5,
        )
        found.raise_for_status()
        payload = found.json()
        results = payload.get("results", [])
        assert payload.get("count", len(results)) == len(results), "The test IP query returned an incomplete page"

        matches = []
        for entry in results:
            entry_address = str(ipaddress.ip_interface(str(entry.get("address"))).ip)
            # NetBox has no case-sensitive "starts with" filter, so the exact prefix check is here.
            marked = str(entry.get("description", "")).startswith(_KEA_SYNC_MARKER_PREFIX)
            if entry_address != address or entry.get("dns_name") != hostname or not marked:
                raise AssertionError(f"NetBox returned IP {entry.get('id')!r} outside the test identity")
            matches.append(entry)

        assert len(matches) <= 1, f"Found {len(matches)} NetBox IPs with the complete test identity"
        if not matches:
            return None
        ip_id = matches[0].get("id")
        assert isinstance(ip_id, int) and not isinstance(ip_id, bool), f"NetBox returned invalid IP ID {ip_id!r}"
        return ip_id

    @classmethod
    def _cleanup_netbox_ip(
        cls,
        nb_http: requests.Session,
        netbox_url: str,
        address: str,
        hostname: str,
        *,
        ip_id: int | None,
        strict: bool,
    ) -> None:
        """Delete the captured test IP, or discover an exact prior-run residue."""
        try:
            target_id = ip_id
            if target_id is None:
                target_id = cls._netbox_ip_id(nb_http, netbox_url, address, hostname)
            if target_id is None:
                return
            nb_http.delete(f"{netbox_url}/api/ipam/ip-addresses/{target_id}/", timeout=5).raise_for_status()
        except Exception as exc:
            if strict:
                raise
            warnings.warn(f"Could not remove test NetBox IP {address}: {exc}", stacklevel=2)

    def test_full_crud_lifecycle(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Create → verify listed → edit hostname → verify edit → delete → verify gone."""
        server_id = kea_server.id
        add_url = self._reservation_add_url(plugin_base, server_id)

        page.goto(add_url)
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _dismiss_debug_toolbar(page)
        cidr = _subnet_cidr_for_id(page, self._SUBNET_ID)
        test_ip = self._test_ip(cidr)

        # ---- 0. PRE-CLEAN — remove any leftover from a previous interrupted run ----
        self._ui_cleanup_reservation(
            page,
            plugin_base,
            server_id,
            self._TEST_MAC,
            test_ip,
            strict=True,
        )

        try:
            # ---- 1. CREATE ----
            page.goto(self._reservation_add_url(plugin_base, server_id))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            _dismiss_debug_toolbar(page)

            self._fill_reservation_form(
                page,
                cidr,
                test_ip,
                self._TEST_MAC,
                hostname=self._TEST_HOSTNAME,
            )
            self._submit_form_by_field(page, "id_subnet_cidr")
            _check_no_django_error(page)
            _assert_no_http_errors(track_http_errors)

            # ---- 2. VERIFY LISTED ----
            page.goto(self._reservation_list_url(plugin_base, server_id))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            row = page.locator("tr").filter(has=page.get_by_text(self._TEST_MAC, exact=True))
            expect(row.get_by_text(test_ip, exact=True)).to_be_visible()

            # ---- 3. EDIT ----
            page.goto(self._reservation_edit_url(plugin_base, server_id, self._SUBNET_ID, self._TEST_MAC))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            _dismiss_debug_toolbar(page)

            page.locator("#id_hostname").fill(self._TEST_HOSTNAME_EDITED)
            self._submit_form_by_field(page, "id_ip_address")
            _check_no_django_error(page)
            _assert_no_http_errors(track_http_errors)

            # ---- 4. VERIFY EDIT — reload list and confirm hostname changed ----
            page.goto(self._reservation_list_url(plugin_base, server_id))
            page.wait_for_load_state("networkidle")
            row = page.locator("tr").filter(has=page.get_by_text(self._TEST_MAC, exact=True))
            expect(row.get_by_text(test_ip, exact=True)).to_be_visible()
            expect(row.get_by_text(self._TEST_HOSTNAME_EDITED, exact=True)).to_be_visible()

            # ---- 5. DELETE ----
            page.goto(self._reservation_delete_url(plugin_base, server_id, self._SUBNET_ID, self._TEST_MAC))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            # The delete confirmation form has only one unique element — submit it directly
            _submit_and_wait_nav(
                page,
                "document.querySelectorAll('form[method=\"post\"]')"
                "[ document.querySelectorAll('form[method=\"post\"]').length - 1 ].submit()",
            )
            _check_no_django_error(page)
            _assert_no_http_errors(track_http_errors)

            # ---- 6. VERIFY GONE ----
            page.goto(self._reservation_list_url(plugin_base, server_id))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            assert test_ip not in page.content(), f"Reservation {test_ip} still visible after delete"
        finally:
            # A reservation left in live Kea blocks the next run on the same identifier.
            self._ui_cleanup_reservation(
                page,
                plugin_base,
                server_id,
                self._TEST_MAC,
                test_ip,
                strict=sys.exc_info()[0] is None,
            )

    def test_reservation_relationship_and_synchronization_state_are_definite(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        netbox_url: str,
        nb_http: requests.Session,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """One Reservation reports a definite lease relationship and synchronization state.

        The fixture address sits outside the pools live Kea allocates from and uses an
        identifier no client offers, so both answers are deterministic: no lease, and
        not synchronized until this test synchronizes it.
        """
        server_id = kea_server.id
        add_url = self._reservation_add_url(plugin_base, server_id)

        page.goto(add_url)
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _dismiss_debug_toolbar(page)
        cidr = _subnet_cidr_for_id(page, self._SUBNET_ID)
        test_ip = self._test_ip(cidr, self._STATE_HOST_OFFSET)
        self._ui_cleanup_reservation(
            page,
            plugin_base,
            server_id,
            self._STATE_MAC,
            test_ip,
            strict=True,
        )
        # A stopped run can leave this exact state-test IP in NetBox.
        self._cleanup_netbox_ip(
            nb_http,
            netbox_url,
            test_ip,
            self._STATE_HOSTNAME,
            ip_id=None,
            strict=True,
        )
        netbox_ip_id = None
        # The Reservation lives on the live Kea, so cleanup covers every step that can
        # create it, not only the assertions after it.
        try:
            page.goto(self._reservation_add_url(plugin_base, server_id))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            _dismiss_debug_toolbar(page)
            self._fill_reservation_form(page, cidr, test_ip, self._STATE_MAC, hostname=self._STATE_HOSTNAME)
            self._submit_form_by_field(page, "id_subnet_cidr")
            _check_no_django_error(page)

            row = self._reservation_row(page, plugin_base, server_id, self._STATE_MAC, test_ip)
            _check_no_django_error(page)
            _dismiss_debug_toolbar(page)
            assert row.count() == 1, f"Expected one state-test Reservation at {test_ip}"
            row = row.first
            expect(row).to_be_visible()

            # A definite relationship, not a missing badge: this address holds no lease.
            expect(row.locator('.badge:has-text("No Lease")')).to_be_visible()
            assert row.locator('.badge:has-text("Active Lease")').count() == 0, (
                "A Reservation outside every pool must not report an active lease"
            )

            # One address, none of it in NetBox yet.
            expect(row.locator('.badge:has-text("Not Synchronized 0/1")')).to_be_visible()

            row.locator('button:has-text("Sync all")').click()
            expect(row.locator('.badge:has-text("Synchronized 1/1")')).to_be_visible()
            _assert_no_http_errors(track_http_errors)
            netbox_ip_id = self._netbox_ip_id(nb_http, netbox_url, test_ip, self._STATE_HOSTNAME)
            assert netbox_ip_id is not None, f"Sync did not create the state-test NetBox IP {test_ip}"
        finally:
            # Nested, so a failure removing the Reservation still removes the NetBox IP.
            try:
                self._ui_cleanup_reservation(
                    page,
                    plugin_base,
                    server_id,
                    self._STATE_MAC,
                    test_ip,
                    strict=sys.exc_info()[0] is None,
                )
            finally:
                self._cleanup_netbox_ip(
                    nb_http,
                    netbox_url,
                    test_ip,
                    self._STATE_HOSTNAME,
                    ip_id=netbox_ip_id,
                    strict=sys.exc_info()[0] is None,
                )

    def test_add_reservation_form_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Add-reservation form renders without error."""
        server_id = kea_server.id
        page.goto(self._reservation_add_url(plugin_base, server_id))
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("#id_ip_address")).to_be_visible()

    def test_edit_reservation_form_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Edit-reservation form loads for an existing reservation without error."""
        server_id = kea_server.id
        page.goto(self._reservation_list_url(plugin_base, server_id))
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _dismiss_debug_toolbar(page)

        # Collect edit hrefs directly from the DOM to avoid pointer-event interception
        hrefs = page.evaluate(
            """() => Array.from(
                document.querySelectorAll('a[href*="reservations4"][href*="/edit/"]')
            ).map(a => a.href)"""
        )
        assert hrefs, (
            "subnets4 config in tests/docker/kea_configs/kea-dhcp4.conf reserves hosts, so the "
            "reservations4 page must offer an edit link; none rendered"
        )

        page.goto(hrefs[0])
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("#id_ip_address")).to_be_visible()

    def test_delete_confirmation_page_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Delete confirmation page for a known reservation loads without error."""
        server_id = kea_server.id
        page.goto(self._reservation_list_url(plugin_base, server_id))
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _dismiss_debug_toolbar(page)

        # Collect delete hrefs directly from the DOM
        hrefs = page.evaluate(
            """() => Array.from(
                document.querySelectorAll('a[href*="reservations4"][href*="/delete/"]')
            ).map(a => a.href)"""
        )
        assert hrefs, (
            "tests/docker/kea_configs/kea-dhcp4.conf reserves hosts, so the reservations4 page "
            "must offer a delete link; none rendered"
        )

        page.goto(hrefs[0])
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        # The delete form is always the last form[method=post] on the page
        # (NetBox adds bookmark/subscribe forms before the content form)
        expect(page.locator('form[method="post"]').last).to_be_visible()


class TestPoolManagement:
    """E2E tests for pool add/delete against a live Kea server."""

    @staticmethod
    def _subnets4_url(plugin_base: str, server_id: int) -> str:
        return f"{plugin_base}/servers/{server_id}/subnets4/"

    @staticmethod
    def _pool_add_url(plugin_base: str, server_id: int, subnet_id: int) -> str:
        return f"{plugin_base}/servers/{server_id}/subnets4/{subnet_id}/pools/add/"

    @staticmethod
    def _pool_delete_url(plugin_base: str, server_id: int, subnet_id: int, pool: str) -> str:
        return f"{plugin_base}/servers/{server_id}/subnets4/{subnet_id}/pools/{pool}/delete/"

    def _discover_first_subnet(self, page: Page):
        """Extract subnet CIDR and add-pool URL from the first applicable table row."""
        return page.evaluate(
            """() => {
                const rows = document.querySelectorAll('table tbody tr');
                for (const row of rows) {
                    const addLink = row.querySelector('a[href*="pools/add"]');
                    if (!addLink) continue;
                    let subnet = null;
                    for (const cell of row.querySelectorAll('td')) {
                        const text = cell.textContent.trim();
                        if (/^[\\d.]+\\/\\d+$/.test(text)) { subnet = text; break; }
                    }
                    if (!subnet) continue;
                    return { add_url: addLink.href, subnet: subnet };
                }
                return null;
            }"""
        )

    def test_pool_add_form_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Pool add form renders without error."""
        server_id = kea_server.id
        page.goto(self._subnets4_url(plugin_base, server_id))
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _dismiss_debug_toolbar(page)

        hrefs = page.evaluate("() => Array.from(document.querySelectorAll('a[href*=\"pools/add\"]')).map(a => a.href)")
        assert hrefs, (
            "tests/docker/kea_configs/kea-dhcp4.conf defines subnets, so the subnets4 page must "
            "offer an add-pool link; none rendered"
        )

        page.goto(hrefs[0])
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator("#id_pool")).to_be_visible()

    def test_pool_delete_form_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """Pool delete confirmation page renders for an existing pool."""
        server_id = kea_server.id
        page.goto(self._subnets4_url(plugin_base, server_id))
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _dismiss_debug_toolbar(page)

        hrefs = page.evaluate(
            """() => Array.from(
                document.querySelectorAll('a[href*="pools/"][href*="/delete/"]')
            ).map(a => a.href)"""
        )
        assert hrefs, (
            "tests/docker/kea_configs/kea-dhcp4.conf defines a pool in every subnet, so the "
            "subnets4 page must offer a delete-pool link; none rendered"
        )

        page.goto(hrefs[0])
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        expect(page.locator('form[method="post"]').last).to_be_visible()

    def _kea4_cleanup_pool(self, kea_client, subnet_id: int, pool: str, *, strict: bool) -> None:
        """Remove *pool* from *subnet_id* through Kea directly (safe to call twice).

        Strict cleanup raises failures. Lenient cleanup warns so it does not replace
        an exception that is already propagating from the test body.
        """
        try:
            data = kea_client.command("subnet4-get", 4, arguments={"id": subnet_id}, check=(0, 3))[0]
            for subnet in (data.get("arguments") or {}).get("subnet4") or []:
                if not any(entry.get("pool") == pool for entry in subnet.get("pools") or []):
                    continue
                kea_client.command(
                    "subnet4-delta-del",
                    4,
                    arguments={"subnet4": [{"id": subnet_id, "subnet": subnet["subnet"], "pools": [{"pool": pool}]}]},
                    check=(0, 3),
                )
        except Exception as exc:
            if strict:
                raise
            warnings.warn(f"Could not remove test pool {pool} from subnet {subnet_id}: {exc}", stacklevel=2)

    def test_pool_add_and_delete_cycle(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        kea_client,
        track_http_errors: list,
    ) -> None:
        """Full cycle: add a pool → verify present → delete it → verify gone."""
        server_id = kea_server.id
        page.goto(self._subnets4_url(plugin_base, server_id))
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _dismiss_debug_toolbar(page)

        row_data = self._discover_first_subnet(page)
        assert row_data and row_data.get("subnet"), (
            "tests/docker/kea_configs/kea-dhcp4.conf defines subnets, so the subnets4 page must "
            "show a subnet row with an add-pool link; none rendered"
        )

        net = ipaddress.IPv4Network(row_data["subnet"], strict=False)
        host_count = net.num_addresses - 2
        assert host_count >= 15, (
            f"Subnet {row_data['subnet']} has {host_count} hosts; the config's subnets are /24, so "
            "a subnet too small for the test pool means the config changed"
        )

        start_addr = ipaddress.IPv4Address(int(net.broadcast_address) - 10)
        end_addr = ipaddress.IPv4Address(int(net.broadcast_address) - 6)
        test_pool = f"{start_addr}-{end_addr}"

        # Parse subnet_id from the add_url path
        add_url_path = row_data["add_url"].split("//", 1)[-1].split("/", 1)[-1]
        parts = ("/" + add_url_path).rstrip("/").split("/")
        subnet_id = int(parts[parts.index("subnets4") + 1])

        try:
            # ---- ADD ----
            page.goto(self._pool_add_url(plugin_base, server_id, subnet_id))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            page.fill("#id_pool", test_pool)
            _submit_and_wait_nav(page, "document.getElementById('id_pool').closest('form').submit()")
            _check_no_django_error(page)
            _assert_no_http_errors(track_http_errors)

            # ---- VERIFY ADDED ----
            page.goto(self._subnets4_url(plugin_base, server_id))
            page.wait_for_load_state("networkidle")
            assert test_pool in page.content(), f"Test pool {test_pool} not visible in subnets table after add"

            # ---- DELETE ----
            page.goto(self._pool_delete_url(plugin_base, server_id, subnet_id, test_pool))
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            _submit_and_wait_nav(
                page,
                "document.querySelectorAll('form[method=\"post\"]')"
                "[ document.querySelectorAll('form[method=\"post\"]').length - 1 ].submit()",
            )
            _check_no_django_error(page)
            _assert_no_http_errors(track_http_errors)

            # ---- VERIFY DELETED ----
            page.goto(self._subnets4_url(plugin_base, server_id))
            page.wait_for_load_state("networkidle")
            assert test_pool not in page.content(), f"Test pool {test_pool} still visible after delete"
        finally:
            # Kea rejects a duplicate range, so a pool left behind fails every later run.
            self._kea4_cleanup_pool(kea_client, subnet_id, test_pool, strict=sys.exc_info()[0] is None)


class TestSubnetManagement:
    """E2E tests for subnet add/delete against a live Kea server."""

    def _kea4_cleanup_subnet(self, kea_client, cidr: str, *, strict: bool) -> None:
        """Remove every Kea subnet whose CIDR matches *cidr* (direct API call).

        Strict cleanup raises failures. Lenient cleanup warns so it does not replace
        an exception that is already propagating from the test body.
        """
        try:
            data = kea_client.command("subnet4-list", 4, check=(0, 3))[0]
            for s in (data.get("arguments") or {}).get("subnets", []):
                if s.get("subnet") == cidr:
                    kea_client.command("subnet4-del", 4, arguments={"id": s["id"]}, check=(0, 3))
        except Exception as exc:
            if strict:
                raise
            warnings.warn(f"Could not remove test subnet {cidr}: {exc}", stacklevel=2)

    def test_subnet_add_form_loads(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
    ) -> None:
        """The add-subnet form renders without error."""
        server_id = kea_server.id
        page.goto(f"{plugin_base}/servers/{server_id}/subnets4/add/")
        page.wait_for_load_state("networkidle")
        _check_no_django_error(page)
        _assert_no_http_errors(track_http_errors)
        assert page.locator("#id_subnet").is_visible(), "Subnet CIDR input not found"

    def test_subnet_add_and_delete_cycle(
        self,
        page: Page,
        netbox_login: None,
        plugin_base: str,
        kea_server,
        track_http_errors: list,
        kea_client,
    ) -> None:
        """Full add→verify→delete cycle for a DHCPv4 subnet."""
        server_id = kea_server.id
        test_subnet = "10.254.253.0/24"
        test_pool = "10.254.253.10-10.254.253.20"

        # ---- PRE-CLEANUP: remove any leftover test subnets via direct Kea API ----
        self._kea4_cleanup_subnet(kea_client, test_subnet, strict=True)

        try:
            # ---- ADD ----
            page.goto(f"{plugin_base}/servers/{server_id}/subnets4/add/")
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)

            page.fill("#id_subnet", test_subnet)
            page.fill("#id_pools", test_pool)
            page.fill("#id_gateway", "10.254.253.1")

            _submit_and_wait_nav(page, "document.getElementById('id_subnet').closest('form').submit()")
            _check_no_django_error(page)
            _assert_no_http_errors(track_http_errors)

            # ---- VERIFY VISIBLE ----
            page.goto(f"{plugin_base}/servers/{server_id}/subnets4/")
            page.wait_for_load_state("networkidle")
            page.wait_for_selector("table tbody tr", timeout=10000)
            rows_after_add = page.locator("table tbody tr").filter(has_text=test_subnet).all()
            assert rows_after_add, f"Test subnet {test_subnet} not visible in subnets table after add"

            # Find the new subnet's ID from the delete link in the matching row
            all_added_ids = []
            for row in rows_after_add:
                for link in row.locator("a[href*='subnets4/'][href*='/delete/']").all():
                    href = link.get_attribute("href") or ""
                    m = re.search(r"/subnets4/(\d+)/delete/$", urlparse(href).path)
                    if m:
                        all_added_ids.append(int(m.group(1)))
            assert all_added_ids, f"Could not find any subnet delete links for {test_subnet}"
            new_subnet_id = max(all_added_ids)  # highest ID = the one we just added

            # ---- DELETE via UI ----
            page.goto(f"{plugin_base}/servers/{server_id}/subnets4/{new_subnet_id}/delete/")
            page.wait_for_load_state("networkidle")
            _check_no_django_error(page)
            assert test_subnet in page.content(), "Subnet CIDR not shown on delete confirmation page"

            _submit_and_wait_nav(page, "document.querySelector('.card-body form[method=\"post\"]').submit()")
            _check_no_django_error(page)
            _assert_no_http_errors(track_http_errors)

            # ---- VERIFY DELETED via direct Kea API ----
            data = kea_client.command("subnet4-list", 4, check=(0, 3))[0]
            remaining_ids = {s["id"] for s in (data.get("arguments") or {}).get("subnets", [])}
            assert new_subnet_id not in remaining_ids, (
                f"Subnet ID {new_subnet_id} ({test_subnet}) still present in Kea after UI delete"
            )

        finally:
            # Unconditional: the helper matches by CIDR under check=(0, 3), so it is a no-op
            # once the UI delete succeeded, and no flag can be left stale by a failed wait.
            self._kea4_cleanup_subnet(kea_client, test_subnet, strict=sys.exc_info()[0] is None)
