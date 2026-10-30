# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for the command-aware Kea HTTP stub itself (``kea_stub``).

The stub is test infrastructure, so these verify its dispatch contract directly:
a plain ``list`` is a verbatim multi-service payload, ``queued()`` sequences
responses, and both request recording and queue dispatch are thread-safe (the
enrichment views POST from cloned clients on worker threads).
"""

import json
import threading
from pathlib import Path

import pytest
import requests
from urllib3.exceptions import SSLError as Urllib3SSLError

from netbox_kea.kea import KeaCommand, KeaException
from netbox_kea.tests.kea_stub import (
    Applied,
    KeaHttpStub,
    SubnetDaemon,
    _http_response,
    _reservation_family,
    _typed_reservation,
    client_failure,
    kea_client,
    queued,
    recorded_host,
    stub_kea,
)


def _call(stub, command="version-get"):
    return stub("https://kea.example.com/api/v1/", json={"command": command}).json()


def test_dict_payload_is_wrapped_in_single_entry_list():
    """A dict value is the single ``.json()`` entry (Kea returns a list)."""
    stub = KeaHttpStub({"version-get": {"result": 0}})
    assert _call(stub) == [{"result": 0}]


def test_http_boundary_returns_concrete_requests_responses():
    """The real KeaClient decodes a stubbed success and raises on a stubbed HTTP error."""
    client = kea_client(url="https://kea.example.invalid/")
    with stub_kea({"version-get": {"result": 0}}) as stub:
        assert client.command(KeaCommand.VERSION_GET, 4) == [{"result": 0}]
    assert stub.urls() == ["https://kea.example.invalid/"]

    failed = _http_response([{"result": 1}], status=503, url="https://kea.example.invalid/")
    with stub_kea({"version-get": failed}), pytest.raises(requests.HTTPError) as error:
        client.command(KeaCommand.VERSION_GET, 4)
    assert error.value.response is failed


def test_plain_multi_entry_list_returned_verbatim():
    """A real multi-service response is a list and must NOT be treated as a queue."""
    multi = [{"result": 0}, {"result": 3}]
    stub = KeaHttpStub({"version-get": multi})
    # Every call returns the full list, unchanged — not truncated to one entry.
    assert _call(stub) == multi
    assert _call(stub) == multi


def test_empty_list_payload_returned_not_indexerror():
    """An empty list is a valid empty payload, not an IndexError."""
    stub = KeaHttpStub({"version-get": []})
    assert _call(stub) == []


def test_queued_dispatches_in_order_then_repeats_last():
    stub = KeaHttpStub({"version-get": queued({"result": 0}, {"result": 3})})
    assert _call(stub) == [{"result": 0}]
    assert _call(stub) == [{"result": 3}]
    assert _call(stub) == [{"result": 3}]  # last response repeats once exhausted


def test_queued_requires_at_least_one_response():
    with pytest.raises(ValueError):
        queued()


def test_unregistered_command_raises_assertion_error():
    stub = KeaHttpStub({})
    with pytest.raises(AssertionError, match="no response registered for command 'status-get'"):
        _call(stub, "status-get")


def test_a_command_kea_does_not_have_cannot_be_registered():
    with pytest.raises(AssertionError, match=r"registers \['subnet4-pool-add'\], which the harness Kea does not have"):
        KeaHttpStub({"subnet4-pool-add": {"result": 0}, "subnet4-delta-add": {"result": 0}})


def test_a_command_kea_does_not_have_cannot_be_sent():
    stub = KeaHttpStub({})
    with pytest.raises(AssertionError, match=r"receives \['subnet6-pool-del'\], which the harness Kea does not have"):
        _call(stub, "subnet6-pool-del")


def test_callable_resolves_against_request_body():
    stub = KeaHttpStub({"version-get": lambda body: {"echo": body["command"]}})
    assert _call(stub) == [{"echo": "version-get"}]


def test_urls_records_endpoints_in_order():
    """``urls()`` records each POST endpoint in call order (for dual-URL routing asserts)."""
    stub = KeaHttpStub({"version-get": {"result": 0}})
    stub("http://v4:1", json={"command": "version-get"})
    stub("http://v6:2", json={"command": "version-get"})
    assert stub.urls() == ["http://v4:1", "http://v6:2"]


def test_shared_response_builders_shape():
    """Lock the shape of the shared reservation builders so callers can't drift."""
    from netbox_kea.tests.kea_stub import _res_get, _res_page, _subnet_list

    host = {"ip-address": "10.0.0.1", "subnet-id": 1}
    # _res_page: hosts snapshot + pagination cursor (both 0 == source exhausted).
    assert _res_page([host]) == {
        "result": 0,
        "arguments": {"hosts": [host], "next": {"from": 0, "source-index": 0}},
    }
    assert _res_page([], next_from=2, next_source=1)["arguments"]["next"] == {"from": 2, "source-index": 1}
    # _res_get: host fields returned directly under arguments.
    assert _res_get(host) == {"result": 0, "arguments": host}
    # _subnet_list: the Subnet catalogue list response.
    subnets = [{"id": 1, "subnet": "10.0.0.0/24"}]
    assert _subnet_list(4, subnets) == {"result": 0, "arguments": {"subnets": subnets}}
    assert _subnet_list(6, []) == {"result": 0, "arguments": {"subnets": []}}


def test_catalogue_responses_shape():
    """Lock the shared catalogue factory that replaced three drifting local copies."""
    from netbox_kea.tests.kea_stub import _catalogue_responses, _catalogue_responses_for_subnets, _subnet_list

    responses = _catalogue_responses(4, 20, "198.18.0.0/24")

    subnet = {"id": 20, "subnet": "198.18.0.0/24"}
    assert set(responses) == {"subnet4-list", "config-get"}
    assert responses["subnet4-list"] == _subnet_list(4, [subnet])
    # Pinned literally: the host_cmds hook gates the Reservation mutation capabilities everywhere.
    assert responses["config-get"] == {
        "result": 0,
        "arguments": {
            "Dhcp4": {
                "subnet4": [subnet],
                "shared-networks": [],
                "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_host_cmds.so"}],
            },
            "hash": "shared-catalogue",
        },
    }
    # The family drives both the identity command and the configuration block.
    v6 = _catalogue_responses(6, 30, "2001:db8::/64", config_hash="other")
    assert "subnet6-list" in v6
    assert v6["config-get"]["arguments"]["Dhcp6"]["subnet6"] == [{"id": 30, "subnet": "2001:db8::/64"}]
    assert v6["config-get"]["arguments"]["hash"] == "other"

    options = ({"name": "routers", "data": "198.18.0.1"},)
    definitions = ({"code": 222, "name": "site-code", "space": "dhcp4", "type": "string"},)
    configured = _catalogue_responses_for_subnets(
        4,
        [],
        global_options=options,
        option_definitions=definitions,
    )["config-get"]["arguments"]["Dhcp4"]
    assert configured["option-data"] == list(options)
    assert configured["option-def"] == list(definitions)

    shared_networks = [{"name": "clients", "subnet4": []}]
    with_networks = _catalogue_responses_for_subnets(4, [], shared_networks=shared_networks)
    assert with_networks["config-get"]["arguments"]["Dhcp4"]["shared-networks"] == shared_networks


def test_a_member_of_an_unknown_shared_network_fails_loudly():
    """Kea refuses such a Subnet, and ``config-get`` would drop it while the Subnet list keeps it."""
    from netbox_kea.tests.kea_stub import SubnetDaemon, _catalogue_responses_for_subnets

    with pytest.raises(AssertionError, match=r"\{7: 'missing'\}"):
        _catalogue_responses_for_subnets(
            4, [{"id": 7, "subnet": "10.0.7.0/24"}], shared_networks=[{"name": "office"}], members={7: "missing"}
        )

    daemon = SubnetDaemon(4, networks=("office",))
    daemon.add({"id": 7, "subnet": "10.0.7.0/24"}, network="missing")
    with pytest.raises(AssertionError, match=r"\{7: 'missing'\}"):
        daemon.responses()["config-get"]({})


@pytest.mark.parametrize(
    ("host", "family"),
    (
        ({"ip-address": "198.18.0.10"}, 4),
        ({"ip-address": "2001:db8::10"}, 6),
        ({"ip-addresses": ["2001:db8::10"]}, 6),
        ({"prefixes": ["2001:db8:1::/64"]}, 6),
    ),
)
def test_reservation_family_covers_each_wire_address_shape(host, family):
    assert _reservation_family(host) == family


@pytest.mark.parametrize(
    "host",
    (
        {"subnet-id": 20, "remote-id": "relay-value"},
        {"subnet-id": 20},
    ),
)
def test_typed_reservation_rejects_a_fixture_without_a_supported_identity(host):
    with pytest.raises(AssertionError, match="no supported identifier"):
        _typed_reservation(host)


@pytest.mark.parametrize(
    "error",
    (
        requests.ConnectionError("down"),
        requests.ConnectionError,
        requests.Timeout("slow"),
        requests.exceptions.SSLError("bad certificate"),
        OSError("Could not find a suitable TLS CA certificate bundle, invalid path: /missing"),
        UnicodeEncodeError("latin-1", "pass\u20ac", 4, 5, "ordinal not in range(256)"),
        Urllib3SSLError("decryption failed"),
    ),
)
def test_a_transport_error_is_raised(error):
    stub = KeaHttpStub({"version-get": error})
    expected = error if isinstance(error, type) else type(error)
    with pytest.raises(expected):
        _call(stub)


def test_callable_returning_a_transport_error_is_raised():
    stub = KeaHttpStub({"version-get": lambda body: requests.Timeout("slow")})
    with pytest.raises(requests.Timeout):
        _call(stub)


@pytest.mark.parametrize(
    ("error", "name"),
    (
        (RuntimeError, "RuntimeError"),
        (ValueError("x"), "ValueError"),
        (KeaException({"result": 1, "text": "refused", "arguments": None}), "KeaException"),
        # Response.json() raises it, never Session.post(); it is a RequestException.
        (requests.JSONDecodeError("bad JSON", "x", 0), "JSONDecodeError"),
    ),
)
def test_an_error_a_real_post_cannot_raise_is_refused(error, name):
    """A malformed reply is a payload that the real KeaClient rejects, not an exception raised at the boundary."""
    for response in (error, lambda body: error, queued(error)):
        stub = KeaHttpStub({"version-get": response})
        with pytest.raises(AssertionError, match=rf"version-get.*{name}.*requests\.RequestException"):
            _call(stub)


def test_a_callable_that_raises_an_error_a_real_post_cannot_raise_is_refused():
    def respond(body):
        raise ValueError("bad json")

    for response in (respond, queued(respond)):
        stub = KeaHttpStub({"version-get": response})
        with pytest.raises(AssertionError, match=r"version-get.*ValueError"):
            _call(stub)


def test_a_callable_that_raises_a_transport_error_or_an_assertion_is_unchanged():
    def respond(error):
        def raise_it(body):
            raise error

        return raise_it

    for error in (requests.Timeout("slow"), AssertionError("the stub saw a wrong request")):
        stub = KeaHttpStub({"version-get": respond(error)})
        with pytest.raises(type(error)) as raised:
            _call(stub)
        assert raised.value is error


def test_a_subnet_daemon_script_refuses_an_error_a_real_post_cannot_raise():
    daemon = SubnetDaemon(4)
    daemon.script("subnet4-list", RuntimeError("boom"))
    daemon.script("config-get", Applied(ValueError("bad json")))
    client = kea_client(url="https://kea.example.invalid/")
    with stub_kea(daemon.responses()):
        for command, name in ((KeaCommand.SUBNET4_LIST, "RuntimeError"), (KeaCommand.CONFIG_GET, "ValueError")):
            with pytest.raises(AssertionError, match=rf"{command.value}.*{name}"):
                client.command(command, 4)


def test_client_failure_raises_for_one_command_and_sends_the_others():
    client = kea_client(url="https://kea.example.invalid/")
    with stub_kea({"version-get": {"result": 0}}) as stub, client_failure(KeaCommand.CONFIG_GET, TypeError("bug")):
        with pytest.raises(TypeError, match="bug"):
            client.command(KeaCommand.CONFIG_GET, 4)
        with pytest.raises(TypeError, match="bug"):
            client.command(command=KeaCommand.CONFIG_GET, target=4)
        assert client.command(KeaCommand.VERSION_GET, 4) == [{"result": 0}]
        assert client.command(command=KeaCommand.VERSION_GET, target=4) == [{"result": 0}]
    assert stub.commands() == ["version-get", "version-get"]


def test_concurrent_requests_are_all_recorded():
    """Request recording under the lock loses no entries across worker threads."""
    stub = KeaHttpStub({"version-get": {"result": 0}})
    threads = [threading.Thread(target=_call, args=(stub,)) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert stub.commands().count("version-get") == 50


def test_queue_dispatch_is_thread_safe():
    """Each queued response is consumed exactly once across concurrent callers.

    Without the dispatch lock, the non-atomic length-check-then-pop would let two
    threads pop the same entry or skip one, so this would flake.
    """
    n = 20
    stub = KeaHttpStub({"version-get": queued(*[{"n": i} for i in range(n)])})
    seen: list[int] = []
    seen_lock = threading.Lock()

    def worker():
        result = _call(stub)
        with seen_lock:
            seen.append(result[0]["n"])

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(seen) == list(range(n))


@pytest.mark.parametrize("family", [4, 6])
def test_config_writes_carry_only_keys_a_real_kea_returns(family):
    recorded = (Path(__file__).with_name("kea_recordings") / f"dhcp{family}.json").read_text()
    arguments = json.loads(recorded)["config-get"]["arguments"]
    stub = KeaHttpStub({"config-test": {"result": 0}})
    assert stub("https://kea.example.invalid/", json={"command": "config-test", "arguments": arguments}).ok

    network = arguments[f"Dhcp{family}"]["shared-networks"][0]
    network["client-classes"] = ["voip"]
    assert stub("https://kea.example.invalid/", json={"command": "config-test", "arguments": arguments}).ok

    member = arguments[f"Dhcp{family}"]["shared-networks"][1][f"subnet{family}"][0]
    for entry in (network, member):
        entry["description"] = "Kea rejects this key"
        with pytest.raises(AssertionError, match=r"sends \['description'\]"):
            stub("https://kea.example.invalid/", json={"command": "config-test", "arguments": arguments})
        del entry["description"]


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("command", ["reservation-add", "reservation-update"])
def test_host_writes_carry_only_keys_and_pairs_a_real_kea_takes(family, command):
    stub = KeaHttpStub({command: {"result": 0}})
    host = recorded_host(family)

    def send(reservation):
        return stub(
            "https://kea.example.invalid/", json={"command": command, "arguments": {"reservation": reservation}}
        )

    assert send(host).ok
    with pytest.raises(AssertionError, match=r"sends \['excluded_prefixes'\] in a host"):
        send({**host, "excluded_prefixes": []})
    with pytest.raises(AssertionError, match="do not pair one to one"):
        send({**recorded_host(6), "prefixes": ["2001:db8:500::/56"], "excluded-prefixes": ["", ""]})
    other = {"next-server": "192.0.2.5"} if family == 6 else {"prefixes": ["2001:db8:500::/56"]}
    # A host that mixes the keys of both families is refused, whichever family the stub takes it for.
    with pytest.raises(AssertionError, match=r"not accept on a DHCPv[46] host"):
        send({**host, **other})


@pytest.mark.parametrize("family", [4, 6])
def test_a_control_agent_service_names_the_family_of_a_host_write(family):
    stub = KeaHttpStub({"reservation-add": {"result": 0}})
    # A DHCPv6 host with only keys that both families take, plus a DHCPv4 boot field, looks like a DHCPv4 host.
    host = {"subnet-id": 21, "hw-address": "aa:bb:cc:00:01:00", "next-server": "192.0.2.5"}
    body = {"command": "reservation-add", "service": [f"dhcp{family}"], "arguments": {"reservation": host}}
    if family == 4:
        assert stub("https://kea.example.invalid/", json=body).ok
    else:
        with pytest.raises(AssertionError, match=r"\['next-server'\]"):
            stub("https://kea.example.invalid/", json=body)
