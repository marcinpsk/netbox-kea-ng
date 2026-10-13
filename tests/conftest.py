# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2023-2026 Devon Mar <devon-mar@users.noreply.github.com>
# SPDX-License-Identifier: Apache-2.0
import os
import warnings
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from urllib.parse import urlsplit

import pynetbox
import pytest
import requests

REQUEST_TIMEOUT = 20
#: The documentation media suite. It runs only when --docs-media-dir names the media root.
DOCS_MEDIA_SUITE = Path(__file__).resolve().parent / "docs_media"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--docs-media-dir",
        default=None,
        type=Path,
        help="Run tests/docs_media and write the documentation screenshots and recordings below this directory.",
    )


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """Leave the documentation media suite out of a run that names no media root."""
    if collection_path == DOCS_MEDIA_SUITE and config.getoption("docs_media_dir") is None:
        return True
    return None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip the media tests that a run names explicitly without a media root, before any fixture runs."""
    if config.getoption("docs_media_dir") is not None:
        return
    skip = pytest.mark.skip(reason="pass --docs-media-dir to write the documentation media")
    for item in items:
        if item.path.is_relative_to(DOCS_MEDIA_SUITE):
            item.add_marker(skip)


class TimeoutSession(requests.Session):
    """Apply a default timeout to requests made through the API client."""

    def request(self, method, url, **kwargs):
        """Bound requests that do not specify a timeout."""
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = REQUEST_TIMEOUT
        return super().request(method, url, **kwargs)


class NoBranchGuard:
    """The KeaClient write guard of the host harness: it has no NetBox, so no branch can be active."""

    def refuse(self, operation: str) -> None:
        """Refuse nothing."""


def no_display_cache(family: int | None, *, configuration: bool) -> None:
    """The KeaClient ``on_write`` of the host harness: it has no NetBox, so it has no display cache to rotate."""


def _delete_created_servers(api: pynetbox.api, created_server_ids: set[int]) -> None:
    """Delete every session-owned Server, and report failures without stopping."""
    for server_id in sorted(created_server_ids):
        try:
            server = api.plugins.kea.servers.get(server_id)
            if server is not None and server.delete() is not True:
                raise RuntimeError("the NetBox API did not confirm deletion")
        except Exception as exc:  # noqa: BLE001,PERF203 - cleanup must continue after each failure
            warnings.warn(f"Could not delete test Server {server_id}: {exc}", RuntimeWarning, stacklevel=2)


def _record_created_server_ids(
    response: requests.Response,
    *args,
    created_server_ids: set[int],
    netbox_url: str,
    **kwargs,
) -> requests.Response:
    """Record exact Server IDs from successful Pynetbox create responses."""
    request = response.request
    server_collection_path = urlsplit(f"{netbox_url}/api/plugins/kea/servers").path.rstrip("/")
    if (
        request is None
        or request.method != "POST"
        or urlsplit(response.url).path.rstrip("/") != server_collection_path
        or not 200 <= response.status_code < 300
    ):
        return response

    if "application/json" not in response.headers.get("Content-Type", "").lower():
        return response
    try:
        payload = response.json()
    except ValueError:
        return response
    records = payload if isinstance(payload, list) else [payload]
    created_server_ids.update(
        identifier
        for record in records
        if isinstance(record, dict)
        and isinstance((identifier := record.get("id")), int)
        and not isinstance(identifier, bool)
    )
    return response


@pytest.fixture(scope="session")
def netbox_url() -> str:
    # Overridable so the harness can be published on another port when 8000 is taken.
    # NETBOX_PORT is what Compose publishes on, so fall back to it before assuming 8000.
    # A blank value means "unset", and a trailing slash would double up the / in every
    # f-string that appends a path.
    port = os.environ.get("NETBOX_PORT", "").strip() or "8000"
    url = os.environ.get("NETBOX_URL", "").strip() or f"http://localhost:{port}"
    return url.rstrip("/")


@pytest.fixture(scope="session")
def netbox_token(netbox_url: str) -> str:
    resp = requests.post(
        f"{netbox_url}/api/users/tokens/provision/",
        json={"username": "admin", "password": "admin"},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()

    data = resp.json()
    if data.get("version") == 2:
        return f"nbt_{data['key']}.{data['token']}"
    return data["key"]


@pytest.fixture(scope="session")
def netbox_username() -> str:
    return "admin"


@pytest.fixture(scope="session")
def netbox_password() -> str:
    return "admin"


@pytest.fixture(scope="session")
def kea_url() -> str:
    # Kea 3.0: no Control Agent — the DHCPv4 daemon's own HTTP control socket.
    # Used as ca_url / DHCPv4 endpoint; pair with kea_dhcp6_url for the v6 daemon.
    return os.environ.get("KEA_DHCP4_URL", "").strip() or "http://kea-dhcp4:8000"


@pytest.fixture(scope="session")
def kea_dhcp6_url() -> str:
    return os.environ.get("KEA_DHCP6_URL", "").strip() or "http://kea-dhcp6:8000"


@pytest.fixture(scope="session")
def kea_control_urls() -> dict[int, str]:
    """Return the host-side control socket of each harness daemon, by DHCP family.

    These are the same daemons that KEA_DHCP4_URL and KEA_DHCP6_URL name for NetBox.
    A run that moves one must move the other, or the two drive different daemons.
    """
    return {
        4: os.environ.get("KEA_DHCP4_CONTROL_URL", "").strip() or "http://127.0.0.1:8001",
        6: os.environ.get("KEA_DHCP6_CONTROL_URL", "").strip() or "http://127.0.0.1:8003",
    }


#: The global user-context key that marks a daemon of the Compose harness (tests/docker/kea_configs).
HARNESS_MARKER = "netbox-kea-test-harness"
#: The variable that moves each control URL away from the harness default.
_CONTROL_URL_VARIABLES = {4: "KEA_DHCP4_CONTROL_URL", 6: "KEA_DHCP6_CONTROL_URL"}


@pytest.fixture(scope="session")
def kea_harness_daemons(kea_control_urls: dict[int, str]) -> dict[int, str]:
    """Return the control URLs once each daemon shows the harness marker in its configuration.

    The suites wipe and change the leases of these daemons and cannot restore them, so every
    fixture that writes to Kea takes its URLs from here, never from ``kea_control_urls``.
    """
    # Absolute and late: the unit suite loads this file without its package, where `from .kea` fails.
    from tests.kea import KeaClient, KeaCommand, KeaException

    for family, url in kea_control_urls.items():
        try:
            with KeaClient(
                url,
                timeout=REQUEST_TIMEOUT,
                max_unpaged_leases=None,
                write_guard=NoBranchGuard(),
                on_write=no_display_cache,
            ) as client:
                (reply,) = client.command(KeaCommand.CONFIG_GET, family)
            marker = reply["arguments"][f"Dhcp{family}"].get("user-context", {}).get(HARNESS_MARKER)
        except (requests.RequestException, KeaException, RuntimeError, ValueError, KeyError, TypeError) as exc:
            marker = f"no configuration ({type(exc).__name__})"
        if marker is not True:
            pytest.fail(
                f"The DHCPv{family} daemon at {url} ({_CONTROL_URL_VARIABLES[family]}) is not a test harness daemon: "
                f'its Dhcp{family} "user-context" has no "{HARNESS_MARKER}": true (found {marker!r}). The suites '
                "wipe its leases, so they write only to the daemons of tests/docker/kea_configs.",
                pytrace=False,
            )
    return kea_control_urls


@pytest.fixture(scope="session")
def kea_server_kwargs(kea_url: str, kea_dhcp6_url: str) -> dict:
    """Server-create kwargs for the Kea 3.0 dual-daemon harness (no Control Agent):
    ca_url/DHCPv4 -> kea-dhcp4, DHCPv6 -> kea-dhcp6, and has_control_agent disabled."""
    return {"ca_url": kea_url, "dhcp6_url": kea_dhcp6_url, "has_control_agent": False}


@pytest.fixture(scope="session")
def nb_http(netbox_token: str) -> requests.Session:
    s = TimeoutSession()
    auth_prefix = "Bearer" if netbox_token.startswith("nbt_") else "Token"
    s.headers.update(
        {
            "Authorization": f"{auth_prefix} {netbox_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    return s


@pytest.fixture(scope="session", autouse=True)
def nb_api(netbox_url: str, netbox_token: str) -> Iterator[pynetbox.api]:
    """Return a client and delete only Servers that this test session created."""
    api = pynetbox.api(netbox_url, token=netbox_token)
    api.http_session = TimeoutSession()
    created_server_ids: set[int] = set()
    api.http_session.hooks["response"].append(
        partial(_record_created_server_ids, created_server_ids=created_server_ids, netbox_url=netbox_url)
    )

    yield api

    _delete_created_servers(api, created_server_ids)


@pytest.fixture
def kea_basic_url() -> str:
    return "http://nginx"


@pytest.fixture
def kea_basic_username() -> str:
    return "kea"


@pytest.fixture
def kea_basic_password() -> str:
    return "kea"


@pytest.fixture
def kea_https_url() -> str:
    return "https://nginx"


@pytest.fixture
def kea_cert_url() -> str:
    return "https://nginx:444"


@pytest.fixture
def kea_client_cert() -> str:
    return "/certs/netbox.crt"


@pytest.fixture
def kea_client_key() -> str:
    return "/certs/netbox.key"


@pytest.fixture
def kea_ca() -> str:
    return "/certs/nginx.crt"
