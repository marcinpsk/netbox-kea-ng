# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-get-client-missing-version. Intentionally contains
# rule-violating code; excluded from ruff (see pyproject [tool.ruff] exclude).


def fetch(server):
    # ruleid: kea-get-client-missing-version
    with server.get_client() as client:
        return client.command(KeaCommand.VERSION_GET, 4)


def fetch_versioned(server):
    # ok: kea-get-client-missing-version
    with server.get_client(version=4) as client:
        return client.command(KeaCommand.VERSION_GET, 4)


def fetch_versioned_var(server, version):
    # ok: kea-get-client-missing-version
    with server.get_client(version=version) as client:
        return client.command(KeaCommand.VERSION_GET, 4)


def nested(server, helper):
    # ruleid: kea-get-client-missing-version, kea-client-outside-with
    return helper(server.get_client())
