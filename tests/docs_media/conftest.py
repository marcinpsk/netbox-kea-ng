# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Demo data, the capture helper and the recorder of the documentation media suite.

The suite runs only when ``--docs-media-dir`` names the media root (see tests/conftest.py).
It drives the same Compose harness as tests/ui. It writes each screenshot in the light and the
dark color mode of NetBox to <root>/screenshots/, and each recording to <root>/recordings/.
It assumes that no other writer changes the harness during a run; the prechecks find leftovers of an earlier run.
"""

import re
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path

import pynetbox
import pytest
from playwright.sync_api import Browser, BrowserContext, Locator, Page, expect

from ..conftest import REQUEST_TIMEOUT, NoBranchGuard, no_display_cache
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
from .recording import CURSOR_SCRIPT, END_PAUSE, Clip, encode

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
#: Remove the DEBUG banner of the harness.
_REMOVE_DEBUG_BANNER = """() => {
    for (const alert of document.querySelectorAll(".alert")) {
        if (alert.querySelector(".alert-title")?.textContent.trim() === "Debug mode is enabled") alert.remove();
    }
}"""
#: Remove the sticky top bar, which covers a scrolled element.
#: Hide what differs on each run: the object ID and the timestamps.
_PREPARE_PAGE = """() => {
    const style = document.createElement("style");
    style.textContent = `header.navbar.sticky-top { display: none !important; }
        .breadcrumb + code, li:has(> .mdi-calendar-plus), li:has(> .mdi-calendar-edit)
        { visibility: hidden !important; }`;
    document.head.append(style);
}"""
_NEXT_PAINT = "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
_BODY_LUMINANCE = """() => {
    const [r, g, b] = getComputedStyle(document.body).backgroundColor.match(/\\d+/g).map(Number);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}"""

#: The harness proxy in front of the DHCPv4 daemon, with its basic-auth credentials (tests/docker/nginx.conf).
_PROXY_URL = "http://nginx"
_PROXY_CREDENTIALS = {"ca_username": "kea", "ca_password": "kea"}

#: The names of the demo Servers. Server.name is unique, so a Server with one of them stops the suite.
DEMO_SERVERS = ("kea-campus", "kea-branch-office")
#: Subnet 2 (198.51.100.0/24) of the harness. No screenshot shows it, so each recording changes one lease in it.
RECORDED_SUBNET_ID = 2
#: Documentation MAC addresses (RFC 7042, 00-00-5E-00-53-00 to 00-00-5E-00-53-FF).
RECORDED_SYNC_LEASE = ("198.51.100.20", "00:00:5e:00:53:20", "sensor-lab-01")
RECORDED_RESERVE_LEASE = ("198.51.100.21", "00:00:5e:00:53:21", "camera-lobby")
RECORDED_EDIT_LEASE = ("198.51.100.22", "00:00:5e:00:53:22", "kiosk-entrance")
RECORDED_EDIT_HOSTNAME = "kiosk-lobby"
LEASES4 = (
    ("192.0.2.10", "00:00:5e:00:53:0a", "laptop-alice"),
    ("192.0.2.11", "00:00:5e:00:53:0b", "laptop-bob"),
    ("192.0.2.12", "00:00:5e:00:53:0c", "voip-phone-101"),
    ("192.0.2.13", "00:00:5e:00:53:0d", "build-runner-01"),
    ("192.0.2.20", "00:00:5e:00:53:14", "printer-2f"),
    RECORDED_SYNC_LEASE,
    RECORDED_RESERVE_LEASE,
    RECORDED_EDIT_LEASE,
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
    """Return the media root; tests/conftest.py skips the suite when no option names one."""
    return pytestconfig.invocation_params.dir / pytestconfig.getoption("docs_media_dir")


@pytest.fixture(scope="session")
def screenshots_dir(docs_media_dir: Path) -> Path:
    directory = docs_media_dir / "screenshots"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


@pytest.fixture(scope="session")
def recordings_dir(docs_media_dir: Path) -> Path:
    directory = docs_media_dir / "recordings"
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
def demo_kea(kea_harness_daemons: dict[int, str]) -> Iterator[_DualEndpointKeaClient]:
    with (
        KeaClient(
            kea_harness_daemons[4],
            timeout=30,
            max_unpaged_leases=1000,
            write_guard=NoBranchGuard(),
            on_write=no_display_cache,
        ) as dhcp4,
        KeaClient(
            kea_harness_daemons[6],
            timeout=30,
            max_unpaged_leases=1000,
            write_guard=NoBranchGuard(),
            on_write=no_display_cache,
        ) as dhcp6,
    ):
        yield _DualEndpointKeaClient(dhcp4, dhcp6)


def _require_no_demo_servers(nb_api: pynetbox.api) -> None:
    """Fail before seeding when a Server has a demo name: nb_api deletes only the Servers that this session created."""
    # The name filter of the Server API matches a part of the name, so compare the whole name here.
    candidates = (server for name in DEMO_SERVERS for server in nb_api.plugins.kea.servers.filter(name=name))
    if existing := [server for server in candidates if server.name in DEMO_SERVERS]:
        raise RuntimeError(
            "NetBox already holds a Server with a demo name, and the suite does not delete Servers it did not "
            f"create. Delete or rename it, then run again: {[(server.id, server.name) for server in existing]}"
        )


def _sync_identity_rows(nb_api: pynetbox.api, addresses: Sequence[str]) -> dict[str, list]:
    """Return the NetBox rows, in any VRF, that a Sync of the leases of *addresses* writes or changes."""
    macs = {address: mac for address, mac, _hostname in LEASES4}
    found = {}
    for address in addresses:
        # NetBox refuses a duplicate host address at any prefix length, so look up the host.
        found[f"IP address {address}"] = list(nb_api.ipam.ip_addresses.filter(parent=f"{address}/32"))
        found[f"MAC address {macs[address]}"] = list(nb_api.dcim.mac_addresses.filter(mac_address=macs[address]))
    return {name: rows for name, rows in found.items() if rows}


def _require_no_sync_rows(nb_api: pynetbox.api, addresses: Sequence[str]) -> None:
    """Fail before a Sync when a row that it would write exists: the suite deletes only its own rows."""
    if existing := _sync_identity_rows(nb_api, addresses):
        raise RuntimeError(
            "NetBox already holds rows that the demo Sync writes, and the suite does not delete rows it did not "
            f"create. Delete them, then run again: {existing}"
        )


def _claim_sync_rows(nb_api: pynetbox.api, synced: Locator, address: str) -> list:
    """Return the IP address that a Sync reply links to, then the MAC address rows of its lease.

    Call it right after the reply: the precheck found none of these rows, so each one is the suite's own.
    """
    link = re.search(r"/ipam/ip-addresses/(\d+)/$", synced.get_attribute("href") or "")
    assert link, f"the Sync reply of {address} links to no IP address: {synced.get_attribute('href')!r}"
    ip = nb_api.ipam.ip_addresses.get(int(link[1]))
    assert ip is not None and ip.address.split("/")[0] == address, f"the Sync reply of {address} links to {ip}"
    mac = {lease_address: mac for lease_address, mac, _hostname in LEASES4}[address]
    return [ip, *nb_api.dcim.mac_addresses.filter(mac_address=mac)]


def _delete_rows(rows: list) -> None:
    for row in rows:
        row.delete()


def _require_writable_configuration(kea: _DualEndpointKeaClient) -> None:
    """Fail before any write when a daemon cannot persist its configuration: a clip would show that failure."""
    for family in (4, 6):
        (reply,) = kea.command("config-write", family, check=(0, 1))
        if reply["result"] != 0:
            raise RuntimeError(
                f"The DHCPv{family} daemon cannot write its configuration ({reply.get('text')}). Start the harness "
                "with COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.docs.yml in "
                "tests/docker, so that each daemon runs on a writable copy of its configuration."
            )


def _require_paused_periodic_sync(page: Page, netbox_url: str) -> None:
    """The periodic sync would claim the seeded leases, so the images would not show the Sync buttons."""
    page.goto(f"{netbox_url}/plugins/kea/settings/sync/")
    toggle = page.locator("#id_sync-sync_enabled")
    toggle.wait_for()
    if toggle.is_checked():
        raise RuntimeError(
            "The periodic Kea IPAM sync is enabled. tests/docker/plugins.py disables it when the migration creates "
            "the SyncConfig row, so this stack reuses an older postgres volume: run 'docker compose down -v' in "
            "tests/docker, then tests/test_setup.sh again."
        )


def _delete_reservation4(kea: _DualEndpointKeaClient, subnet_id: int, mac: str) -> None:
    kea.command(
        "reservation-del",
        4,
        arguments={"subnet-id": subnet_id, "identifier-type": "hw-address", "identifier": mac},
        check=(0, 3),
    )


def _add_lease4(kea: _DualEndpointKeaClient, address: str, mac: str, hostname: str) -> None:
    kea.command(
        "lease4-add", 4, arguments={"ip-address": address, "hw-address": mac, "hostname": hostname, "valid-lft": 86400}
    )


def _delete_kea_demo_data(kea: _DualEndpointKeaClient) -> None:
    for address, _mac, _hostname in LEASES4:
        kea.command("lease4-del", 4, arguments={"ip-address": address}, check=(0, 3))
    for _address, mac, _hostname in RESERVATIONS4:
        _delete_reservation4(kea, 1, mac)
    _delete_reservation4(kea, RECORDED_SUBNET_ID, RECORDED_RESERVE_LEASE[1])
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
    for lease in LEASES4:
        _add_lease4(kea, *lease)
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


def _sync_leases(page: Page, netbox_url: str, server_id: int, nb_api: pynetbox.api, created: list) -> None:
    """Press Sync on each lease in SYNCED4, as an operator does, and add the rows of each Sync to *created*."""
    page.goto(f"{netbox_url}/plugins/kea/servers/{server_id}/leases4/?q=1&by=subnet_id")
    for address in SYNCED4:
        row = page.locator("table.object-list > tbody > tr").filter(has_text=address)
        row.get_by_role("button", name="Sync", exact=True).click()
        # The reply replaces the button with a link to the new IP address.
        synced = row.get_by_role("link", name=f"{address}/")
        expect(synced).to_have_count(1, timeout=REQUEST_TIMEOUT * 1000)
        created.extend(_claim_sync_rows(nb_api, synced, address))


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

    Before seeding, no row that the Sync writes may exist. The suite records the rows of each Sync
    right after its reply, and teardown deletes exactly those. A Sync without a reply leaves its rows,
    and the precheck of the next run names them.
    """
    context = browser.new_context(**browser_context_args)
    try:
        page = context.new_page()
        page.goto(f"{netbox_url}/login/")
        page.get_by_label("Username").fill("admin")
        page.get_by_label("Password").fill("admin")
        page.get_by_role("button", name="Sign In").click()
        _require_writable_configuration(demo_kea)
        _require_paused_periodic_sync(page, netbox_url)
        _require_no_demo_servers(nb_api)
        _require_no_sync_rows(nb_api, SYNCED4)
        _delete_kea_demo_data(demo_kea)
        # The periodic sync of these Servers stays off too; only the Sync button writes IPAM rows.
        servers = nb_api.plugins.kea.servers
        campus = servers.create(
            name=DEMO_SERVERS[0], ca_url=kea_url, dhcp6_url=kea_dhcp6_url, has_control_agent=False, sync_enabled=False
        )
        branch = servers.create(
            name=DEMO_SERVERS[1],
            ca_url=_PROXY_URL,
            dhcp6=False,
            has_control_agent=False,
            sync_enabled=False,
            **_PROXY_CREDENTIALS,
        )
        assert not campus.sync_enabled and not branch.sync_enabled, "a demo Server takes part in the periodic sync"
        created: list = []
        try:
            _add_kea_demo_data(demo_kea)
            _sync_leases(page, netbox_url, campus.id, nb_api, created)
            # _claim_sync_rows puts the IP address of each Sync first.
            yield DemoData(campus=campus, branch=branch, synced_ip_id=created[0].id)
        finally:
            _delete_rows(created)
            _delete_kea_demo_data(demo_kea)
    finally:
        context.close()


@pytest.fixture
def capture(page: Page, screenshots_dir: Path) -> Callable[..., None]:
    """Return a function that writes one view as <name>-light.png and <name>-dark.png.

    The image shows the page content without the navigation, unless the caller names another element.
    """

    def _capture(name: str, target: Locator | None = None, mask: Sequence[Locator] = ()) -> None:
        page.wait_for_load_state("networkidle")
        page.evaluate(_REMOVE_DEBUG_BANNER)
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
                path=screenshots_dir / f"{name}-{mode}.png",
                animations="disabled",
                caret="hide",
                mask=list(mask),
                mask_color=_MASK_COLORS[mode],
            )
        assert luminance["dark"] < luminance["light"], f"{name}: the dark image is not darker: {luminance}"
        light, dark = (screenshots_dir / f"{name}-{mode}.png" for mode in COLOR_MODES)
        assert light.read_bytes() != dark.read_bytes(), f"{name}: the light and the dark image are the same"

    return _capture


@pytest.fixture
def record(
    page: Page, new_context: Callable[..., BrowserContext], output_path: str, recordings_dir: Path
) -> Callable[..., AbstractContextManager[Clip]]:
    """Return a context manager that records one workflow from *url* as <name>.mp4 with the poster <name>.png.

    The clip starts on the rendered start page: the recorded context starts signed in, and the
    encoding cuts the time until the start page is ready. A failed step leaves the WebM in test-results.
    """

    @contextmanager
    def _record(name: str, url: str, gif: bool = False) -> Iterator[Clip]:
        context = new_context(
            storage_state=page.context.storage_state(),
            color_scheme="light",
            record_video_dir=Path(output_path) / "video",
            record_video_size=VIEWPORT,
        )
        context.add_init_script(script=CURSOR_SCRIPT)
        context.add_init_script(script=f'addEventListener("DOMContentLoaded", {_REMOVE_DEBUG_BANNER});')
        recorded = context.new_page()
        # The video timeline starts with the screencast of the page.
        started = time.monotonic()
        response = recorded.goto(url)
        assert response is not None and response.ok, f"{url} answered {response and response.status}"
        recorded.wait_for_load_state("networkidle")
        expect(recorded.locator("html")).to_have_attribute("data-bs-theme", "light")
        # Chromium moves the pointer of a new page to the top left corner, so start it in the middle.
        recorded.mouse.move(VIEWPORT["width"] / 2, VIEWPORT["height"] / 2)
        # Wait until the browser paints the ready page, so that the cut does not show a partly drawn page.
        recorded.evaluate(_NEXT_PAINT)
        start = time.monotonic() - started
        clip = Clip(recorded)
        clip.pause()
        yield clip
        clip.pause(END_PAUSE)
        video = recorded.video
        assert video is not None, "the recorded context records no video"
        context.close()
        encode(Path(video.path()), start, recordings_dir / name, gif=gif)

    return _record


@dataclass(frozen=True)
class RecordedSync:
    """The lease that the Sync recording synchronizes, and the rows that its Sync wrote."""

    address: str
    nb_api: pynetbox.api
    created: list

    def claim(self, synced: Locator) -> None:
        """Record the rows of the Sync whose reply shows the link *synced*, for teardown."""
        self.created.extend(_claim_sync_rows(self.nb_api, synced, self.address))


@pytest.fixture
def recorded_sync(demo_data: DemoData, nb_api: pynetbox.api) -> Iterator[RecordedSync]:
    """Return the lease of the Sync recording; afterwards delete the rows that it claimed, and only those."""
    sync = RecordedSync(RECORDED_SYNC_LEASE[0], nb_api, [])
    _require_no_sync_rows(nb_api, (sync.address,))
    try:
        yield sync
    finally:
        _delete_rows(sync.created)


@pytest.fixture
def recorded_reservation(demo_data: DemoData, demo_kea: _DualEndpointKeaClient) -> Iterator[str]:
    """Return the address that the Reserve recording reserves, and delete its Reservation afterwards."""
    address, mac, _hostname = RECORDED_RESERVE_LEASE
    try:
        yield address
    finally:
        _delete_reservation4(demo_kea, RECORDED_SUBNET_ID, mac)


@pytest.fixture
def recorded_edit(demo_data: DemoData, demo_kea: _DualEndpointKeaClient) -> Iterator[str]:
    """Return the address that the edit recording changes, and give the lease its demo values again afterwards."""
    address = RECORDED_EDIT_LEASE[0]
    try:
        yield address
    finally:
        demo_kea.command("lease4-del", 4, arguments={"ip-address": address}, check=(0, 3))
        _add_lease4(demo_kea, *RECORDED_EDIT_LEASE)
