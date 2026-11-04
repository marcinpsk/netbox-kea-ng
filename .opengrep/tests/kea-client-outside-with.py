# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-client-outside-with. Intentionally contains
# rule-violating code; excluded from ruff (see pyproject [tool.ruff] exclude).
from functools import partial


def bad_chained_call(server, family):
    # ruleid: kea-client-outside-with
    return server.get_client(version=family).command(KeaCommand.VERSION_GET, family)


def bad_assigned_name(server, family):
    # ruleid: kea-client-outside-with
    client = server.get_client(version=family)
    return client.subnet_get(family, 1)


def bad_lambda_in_attempt(server, family):
    return attempt(
        "The read",
        # ruleid: kea-client-outside-with
        lambda: server.get_client(version=family).subnet_get(family, 1),
    )


def bad_second_client_in_the_block(server):
    with server.get_client(version=4) as client:
        # ruleid: kea-client-outside-with
        other = server.get_client(version=6)
        return client.command(KeaCommand.VERSION_GET, 4), other


def bad_client_of_another_server(server, other):
    with server.get_client(version=4) as client:
        # ruleid: kea-client-outside-with
        return client.command(KeaCommand.VERSION_GET, 4), other.get_client(version=4)


def bad_helper_that_returns_a_client(server, family):
    # ruleid: kea-client-outside-with
    return attempt("The client", lambda: server.get_client(version=family))


def good_with_item(server, family):
    # ok: kea-client-outside-with
    with server.get_client(version=family) as client:
        return client.command(KeaCommand.VERSION_GET, family)


def good_with_item_and_another_context(server, family):
    # ok: kea-client-outside-with
    with server.get_client(version=family) as client, _serialized(client, family):
        return client.command(KeaCommand.CONFIG_GET, family)


def good_local_function_in_attempt(server, family):
    def read():
        # ok: kea-client-outside-with
        with server.get_client(version=family) as client:
            return client.subnet_get(family, 1)

    return attempt("The read", read)


def bad_change_client_assigned(server, family):
    # ruleid: kea-client-outside-with
    client = build_client(server, family)
    return client.command(KeaCommand.CONFIG_GET, family)


def bad_change_client_through_the_module(server, family):
    # ruleid: kea-client-outside-with
    return change_outcome.build_client(server, family).command(KeaCommand.CONFIG_GET, family)


def bad_second_change_client_in_the_block(server):
    with build_client(server, 4) as client:
        # ruleid: kea-client-outside-with
        other = build_client(server, 6)
        return client.command(KeaCommand.CONFIG_GET, 4), other


def good_change_client_with_the_lock(server, family):
    # ok: kea-client-outside-with
    with build_client(server, family) as client, _serialized(client, family):
        return client.command(KeaCommand.CONFIG_GET, family)


def good_change_client_through_the_module(server, family):
    # ok: kea-client-outside-with
    with change_outcome.build_client(server, family) as client:
        return client.command(KeaCommand.CONFIG_GET, family)


def build_client(server, family):
    # ok: kea-client-outside-with
    client = attempt("The client", lambda: server.get_client(version=family))
    return client


@contextmanager
def _catalogue_client(server, family):
    # ok: kea-client-outside-with
    client = attempt("The client", lambda: server.get_client(version=family))
    with client:
        yield client


@contextmanager
def _client_or_refusal(server, version):
    # ok: kea-client-outside-with
    client = attempt("The client", lambda: server.get_client(version=version))
    with client:
        yield client


class LazyClient:
    def __call__(self):
        if self._client is None:
            # ok: kea-client-outside-with
            self._client = self.server.get_client(version=self.target)
        return self._client


class WorkerClients:
    def __call__(self):
        # ok: kea-client-outside-with
        client = self._server.get_client(version=self._family)
        self._local.client = client
        return client


def limit_reference_without_a_call(server, family):
    # ok: kea-client-outside-with
    return attempt("The client", partial(server.get_client, version=family))
