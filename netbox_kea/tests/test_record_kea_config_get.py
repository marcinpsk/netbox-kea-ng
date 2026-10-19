# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""scripts/record_kea_config_get.py reads every key of a Kea source list, and its downloads end when a server stops."""

import importlib.util
import select
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "record_kea_config_get.py"


@pytest.fixture
def script():
    spec = importlib.util.spec_from_file_location("record_kea_config_get", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def stalled_url() -> Iterator[str]:
    """A local HTTP server that accepts each connection and never answers."""
    server = socket.create_server(("127.0.0.1", 0))
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept():
        while not stop.is_set():
            if select.select([server], [], [], 0.1)[0]:
                held.append(server.accept()[0])

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.getsockname()[1]}"
    stop.set()
    thread.join(timeout=5)
    for connection in held:
        connection.close()
    server.close()


def _stalls_until_the_deadline(download) -> None:
    started = time.monotonic()
    with pytest.raises(subprocess.CalledProcessError) as raised:
        download()
    assert raised.value.returncode == 28  # curl: operation timed out
    assert time.monotonic() - started < 10


def test_a_package_download_ends_when_the_server_stops_sending(script, stalled_url, tmp_path):
    with patch.object(script, "DOWNLOAD_SECONDS", 1):
        _stalls_until_the_deadline(lambda: script._curl(f"{stalled_url}/APKINDEX.tar.gz", tmp_path / "index"))


def test_a_keyword_table_download_ends_when_the_server_stops_sending(script, stalled_url):
    with (
        patch.object(script, "DOWNLOAD_SECONDS", 1),
        patch.object(script, "KEA_PARSERS", stalled_url + "/{version}/{source}"),
    ):
        _stalls_until_the_deadline(lambda: script._accepted_keys(4, "3.2.0"))


_TABLE = """const SimpleKeywords SimpleParser4::POOL4_PARAMETERS = {
    { "pool",     Element::string },
    { "array",    Element::boolean, },
    { "metadata", Element::map }
};
"""


def test_a_keyword_table_entry_without_a_trailing_comma_is_read(script):
    assert script._table_keys(_TABLE, "POOL4_PARAMETERS") == ["array", "metadata", "pool"]


def test_a_keyword_table_entry_that_cannot_be_read_stops_the_recording(script):
    source = _TABLE.replace('{ "pool",     Element::string },', "{ POOL_KEY, Element::string },")
    with pytest.raises(SystemExit):
        script._table_keys(source, "POOL4_PARAMETERS")


_HOSTS = """getSupportedParams4(const bool identifiers_only = false) {
    if (params_set.empty()) {
        params_set.insert("hostname");
        params_set.insert( "user-context" );
        params_set.insert ("client-classes");
        params_set.insert(
            "option-data");
    }
}
"""


def test_a_spaced_host_reservation_key_is_read(script):
    assert script._host_keys(_HOSTS, 4) == ["client-classes", "hostname", "option-data", "user-context"]


def test_a_host_reservation_key_that_cannot_be_read_stops_the_recording(script):
    source = _HOSTS.replace('params_set.insert("hostname");', "params_set.insert(HOSTNAME);")
    with pytest.raises(SystemExit):
        script._host_keys(source, 4)


_INTERFACES = """IfacesConfigParser::parse(const CfgIfacePtr& cfg, const ConstElementPtr& ifaces_config) {
    for (auto const& element : ifaces_config->mapValue()) {
        if (element.first == "interfaces") {
            continue;
        }
        if (element.first == "dhcp-socket-type") {
            if (protocol_ == AF_INET) {
                continue;
            } else {
                isc_throw(DhcpConfigError,
                          "dhcp-socket-type is not supported in DHCPv6");
            }
        }
        if (element.first == "user-context") {
            continue;
        }
    }
}
"""


def test_the_interface_keys_leave_out_a_key_that_dhcpv6_refuses(script):
    assert script._interface_keys(_INTERFACES, 4) == ["dhcp-socket-type", "interfaces", "user-context"]
    assert script._interface_keys(_INTERFACES, 6) == ["interfaces", "user-context"]


def test_an_interface_key_that_cannot_be_read_stops_the_recording(script):
    source = _INTERFACES.replace('element.first == "interfaces"', "element.first == INTERFACES")
    with pytest.raises(SystemExit):
        script._interface_keys(source, 4)


def test_an_unspaced_interface_key_is_read(script):
    source = _INTERFACES.replace('element.first == "user-context"', 'element.first=="user-context"')
    assert script._interface_keys(source, 4) == ["dhcp-socket-type", "interfaces", "user-context"]
