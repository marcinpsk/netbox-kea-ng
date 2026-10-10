# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Demo data and the capture helper of the documentation screenshot suite.

The suite runs only when ``--docs-media-dir`` names the output directory (see tests/conftest.py).
It drives the same Compose harness as tests/ui, and writes each view in the light and the dark
color mode of NetBox.
"""

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import pynetbox
import pytest
from playwright.sync_api import Browser, Locator, Page, expect

from ..conftest import REQUEST_TIMEOUT, NoBranchGuard
from ..kea import KeaClient

# pytest registers each fixture that a conftest imports, for the tests in this directory.
from ..ui.conftest import (
    _DualEndpointKeaClient,
    browser_type_launch_args,  # noqa: F401
    netbox_login,  # noqa: F401
    netbox_user_permissions,  # noqa: F401
    plugin_base,  # noqa: F401
    reset_user_preferences,  # noqa: F401
)

VIEWPORT = {"width": 1440, "height": 900}
DEVICE_SCALE_FACTOR = 1
COLOR_MODES = ("light", "dark")
#: A neutral fill for a masked value in each color mode.
_MASK_COLORS = {"light": "#e9ecef", "dark": "#2c3036"}
#: NetBox keeps the color mode in local storage and on the html element (setmode.js, colorMode.ts).
_SET_COLOR_MODE = """mode => {
    localStorage.setItem("netbox-color-mode", mode);
    document.documentElement.setAttribute("data-bs-theme", mode);
}"""
#: Remove the DEBUG banner of the harness and the sticky top bar, which covers a scrolled element.
#: Hide what differs on each run: the object ID and the timestamps.
_PREPARE_PAGE = """() => {
    for (const alert of document.querySelectorAll(".alert")) {
        if (alert.querySelector(".alert-title")?.textContent.trim() === "Debug mode is enabled") alert.remove();
    }
    const style = document.createElement("style");
    style.textContent = `header.navbar.sticky-top { display: none !important; }
        .breadcrumb + code, li:has(> .mdi-calendar-plus), li:has(> .mdi-calendar-edit)
        { visibility: hidden !important; }`;
    document.head.append(style);
}"""
_BODY_LUMINANCE = """() => {
    const [r, g, b] = getComputedStyle(document.body).backgroundColor.match(/\\d+/g).map(Number);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}"""

#: The harness proxy in front of the DHCPv4 daemon, with its basic-auth credentials (tests/docker/nginx.conf).
_PROXY_URL = "http://nginx"
_PROXY_CREDENTIALS = {"ca_username": "kea", "ca_password": "kea"}

#: Documentation MAC addresses (RFC 7042, 00-00-5E-00-53-00 to 00-00-5E-00-53-FF).
LEASES4 = (
    ("192.0.2.10", "00:00:5e:00:53:0a", "laptop-alice"),
    ("192.0.2.11", "00:00:5e:00:53:0b", "laptop-bob"),
    ("192.0.2.12", "00:00:5e:00:53:0c", "voip-phone-101"),
    ("192.0.2.13", "00:00:5e:00:53:0d", "build-runner-01"),
    ("192.0.2.20", "00:00:5e:00:53:14", "printer-2f"),
    ("198.51.100.20", "00:00:5e:00:53:20", "sensor-lab-01"),
    ("198.51.100.21", "00:00:5e:00:53:21", "camera-lobby"),
)
#: Reservations in subnet 1 (192.0.2.0/24): the printer also holds a lease, the NAS does not.
RESERVATIONS4 = (
    ("192.0.2.20", "00:00:5e:00:53:14", "printer-2f"),
    ("192.0.2.21", "00:00:5e:00:53:15", "nas-backup"),
)
#: DHCPv6 address leases in subnet 1 (2001:db8:1::/64), with DUID-LL client identifiers.
LEASES6 = (
    ("2001:db8:1::a", "00:03:00:01:00:00:5e:00:53:0a", "laptop-alice"),
    ("2001:db8:1::b", "00:03:00:01:00:00:5e:00:53:0b", "laptop-bob"),
)
#: A delegated prefix from the pd-pool 2001:db8:8::/56 of subnet 1.
DELEGATED_PREFIX = ("2001:db8:8::", 64, "00:03:00:01:00:00:5e:00:53:30", "cpe-router-7")
#: The leases that the suite synchronizes to NetBox IPAM, so that the tables show the Synced badge.
SYNCED4 = ("192.0.2.10", "192.0.2.20")


@dataclass(frozen=True)
class DemoData:
    """The objects of the demo data set that the shots open."""

    campus: object
    branch: object
    synced_ip_id: int


@pytest.fixture(scope="session")
def docs_media_dir(pytestconfig: pytest.Config) -> Path:
    """Return the output directory; tests/conftest.py skips the suite when no option names one."""
    directory = pytestconfig.invocation_params.dir / pytestconfig.getoption("docs_media_dir")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args: dict) -> dict:
    """Fix the viewport, the pixel ratio and the locale, so that each run draws the same image."""
    return {
        **browser_context_args,
        "viewport": VIEWPORT,
        "device_scale_factor": DEVICE_SCALE_FACTOR,
        "locale": "en-US",
        "timezone_id": "UTC",
        "reduced_motion": "reduce",
    }


@pytest.fixture(scope="session")
def demo_kea(kea_control_urls: dict[int, str]) -> Iterator[_DualEndpointKeaClient]:
    with (
        KeaClient(kea_control_urls[4], timeout=30, max_unpaged_leases=1000, write_guard=NoBranchGuard()) as dhcp4,
        KeaClient(kea_control_urls[6], timeout=30, max_unpaged_leases=1000, write_guard=NoBranchGuard()) as dhcp6,
    ):
        yield _DualEndpointKeaClient(dhcp4, dhcp6)


def _create_server(nb_api: pynetbox.api, name: str, **fields):
    """Create a demo Server, after removing one that an interrupted run left on the same endpoint."""
    for stale in nb_api.plugins.kea.servers.filter(name=name):
        if stale.ca_url != fields["ca_url"]:
            raise RuntimeError(f"A Server named {name!r} exists on another endpoint; the suite does not delete it.")
        stale.delete()
    return nb_api.plugins.kea.servers.create(name=name, **fields)


def _sync_identity_rows(nb_api: pynetbox.api) -> dict[str, list]:
    """Return the NetBox rows, in any VRF, that a Sync of a lease in SYNCED4 writes or changes."""
    macs = {address: mac for address, mac, _hostname in LEASES4}
    found = {}
    for address in SYNCED4:
        # NetBox refuses a duplicate host address at any prefix length, so look up the host.
        found[f"IP address {address}"] = list(nb_api.ipam.ip_addresses.filter(parent=f"{address}/32"))
        found[f"MAC address {macs[address]}"] = list(nb_api.dcim.mac_addresses.filter(mac_address=macs[address]))
    return {name: rows for name, rows in found.items() if rows}


def _require_no_sync_rows(nb_api: pynetbox.api) -> None:
    """Fail before seeding when a row that the Sync would write exists: the suite deletes only its own rows."""
    if existing := _sync_identity_rows(nb_api):
        raise RuntimeError(
            "NetBox already holds rows that the demo Sync writes, and the suite does not delete rows it did not "
            f"create. Delete them, then run again: {existing}"
        )


def _require_paused_periodic_sync(page: Page, netbox_url: str) -> None:
    """The periodic sync would claim the seeded leases, so the images would not show the Sync buttons."""
    page.goto(f"{netbox_url}/plugins/kea/sync-jobs/")
    toggle = page.locator("#id_sync_enabled")
    toggle.wait_for()
    if toggle.is_checked():
        raise RuntimeError(
            "The periodic Kea IPAM sync is enabled. tests/docker/plugins.py disables it when the migration creates "
            "the SyncConfig row, so this stack reuses an older postgres volume: run 'docker compose down -v' in "
            "tests/docker, then tests/test_setup.sh again."
        )


def _delete_kea_demo_data(kea: _DualEndpointKeaClient) -> None:
    for address, _mac, _hostname in LEASES4:
        kea.command("lease4-del", 4, arguments={"ip-address": address}, check=(0, 3))
    for _address, mac, _hostname in RESERVATIONS4:
        kea.command(
            "reservation-del",
            4,
            arguments={"subnet-id": 1, "identifier-type": "hw-address", "identifier": mac},
            check=(0, 3),
        )
    for address, _duid, _hostname in LEASES6:
        kea.command("lease6-del", 6, arguments={"ip-address": address}, check=(0, 3))
    kea.command("lease6-del", 6, arguments={"ip-address": DELEGATED_PREFIX[0], "type": "IA_PD"}, check=(0, 3))


def _add_kea_demo_data(kea: _DualEndpointKeaClient) -> None:
    # Remove every lease, so that leases from another suite do not show in the images.
    kea.command("lease4-wipe", 4, check=(0, 3))
    kea.command("lease6-wipe", 6, check=(0, 3))
    for address, mac, hostname in RESERVATIONS4:
        kea.command(
            "reservation-add",
            4,
            arguments={"reservation": {"subnet-id": 1, "hw-address": mac, "ip-address": address, "hostname": hostname}},
        )
    for address, mac, hostname in LEASES4:
        kea.command(
            "lease4-add",
            4,
            arguments={"ip-address": address, "hw-address": mac, "hostname": hostname, "valid-lft": 86400},
        )
    for iaid, (address, duid, hostname) in enumerate(LEASES6, start=1):
        kea.command(
            "lease6-add",
            6,
            arguments={
                "ip-address": address,
                "duid": duid,
                "iaid": iaid,
                "hostname": hostname,
                "valid-lft": 86400,
                "preferred-lft": 43200,
            },
        )
    prefix, length, duid, hostname = DELEGATED_PREFIX
    kea.command(
        "lease6-add",
        6,
        arguments={
            "ip-address": prefix,
            "type": "IA_PD",
            "prefix-len": length,
            "subnet-id": 1,
            "duid": duid,
            "iaid": 7,
            "hostname": hostname,
            "valid-lft": 86400,
            "preferred-lft": 43200,
        },
    )


def _sync_leases(page: Page, netbox_url: str, server_id: int) -> None:
    """Press Sync on each lease in SYNCED4, as an operator does, so that the plugin writes the IPAM rows."""
    page.goto(f"{netbox_url}/plugins/kea/servers/{server_id}/leases4/?q=1&by=subnet_id")
    for address in SYNCED4:
        row = page.locator("table.object-list > tbody > tr").filter(has_text=address)
        row.get_by_role("button", name="Sync", exact=True).click()
        # The reply replaces the button with a link to the new IP address.
        expect(row.get_by_role("link", name=f"{address}/")).to_have_count(1, timeout=REQUEST_TIMEOUT * 1000)


@pytest.fixture(scope="session")
def demo_data(
    docs_media_dir: Path,
    nb_api: pynetbox.api,
    demo_kea: _DualEndpointKeaClient,
    browser: Browser,
    browser_context_args: dict,
    netbox_url: str,
    kea_url: str,
    kea_dhcp6_url: str,
) -> Iterator[DemoData]:
    """Load one fixed data set into Kea and NetBox, for every shot of the session.

    Before seeding, no row that the Sync writes may exist, so each such row after the Sync is the
    suite's own: teardown deletes exactly the rows that it records then.
    """
    context = browser.new_context(**browser_context_args)
    try:
        page = context.new_page()
        page.goto(f"{netbox_url}/login/")
        page.get_by_label("Username").fill("admin")
        page.get_by_label("Password").fill("admin")
        page.get_by_role("button", name="Sign In").click()
        _require_paused_periodic_sync(page, netbox_url)
        _require_no_sync_rows(nb_api)
        _delete_kea_demo_data(demo_kea)
        # The periodic sync of these Servers stays off too; only the Sync button writes IPAM rows.
        campus = _create_server(
            nb_api, "kea-campus", ca_url=kea_url, dhcp6_url=kea_dhcp6_url, has_control_agent=False, sync_enabled=False
        )
        branch = _create_server(
            nb_api,
            "kea-branch-office",
            ca_url=_PROXY_URL,
            dhcp6=False,
            has_control_agent=False,
            sync_enabled=False,
            **_PROXY_CREDENTIALS,
        )
        assert not campus.sync_enabled and not branch.sync_enabled, "a demo Server takes part in the periodic sync"
        created: dict[str, list] = {}
        try:
            _add_kea_demo_data(demo_kea)
            try:
                _sync_leases(page, netbox_url, campus.id)
            finally:
                created = _sync_identity_rows(nb_api)
            yield DemoData(campus=campus, branch=branch, synced_ip_id=created[f"IP address {SYNCED4[0]}"][0].id)
        finally:
            for rows in created.values():
                for row in rows:
                    row.delete()
            _delete_kea_demo_data(demo_kea)
    finally:
        context.close()


@pytest.fixture
def capture(page: Page, docs_media_dir: Path) -> Callable[..., None]:
    """Return a function that writes one view as <name>-light.png and <name>-dark.png.

    The image shows the page content without the navigation, unless the caller names another element.
    """

    def _capture(name: str, target: Locator | None = None, mask: Sequence[Locator] = ()) -> None:
        page.wait_for_load_state("networkidle")
        page.evaluate(_PREPARE_PAGE)
        # Keep the pointer off the content, so that no row or button shows its hover state.
        page.mouse.move(0, 0)
        target = target or page.locator("#page-content")
        luminance = {}
        for mode in COLOR_MODES:
            page.emulate_media(color_scheme=mode)
            page.evaluate(_SET_COLOR_MODE, mode)
            expect(page.locator("html")).to_have_attribute("data-bs-theme", mode)
            luminance[mode] = page.evaluate(_BODY_LUMINANCE)
            target.screenshot(
                path=docs_media_dir / f"{name}-{mode}.png",
                animations="disabled",
                caret="hide",
                mask=list(mask),
                mask_color=_MASK_COLORS[mode],
            )
        assert luminance["dark"] < luminance["light"], f"{name}: the dark image is not darker: {luminance}"
        light, dark = (docs_media_dir / f"{name}-{mode}.png" for mode in COLOR_MODES)
        assert light.read_bytes() != dark.read_bytes(), f"{name}: the light and the dark image are the same"

    return _capture
