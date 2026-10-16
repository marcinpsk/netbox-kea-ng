# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-runtime-write-outside-runtime-change. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
# The bad cases are the view calls that ADR 0011 moved into runtime_change.
from netbox_kea import runtime_change


def bad_view_enables_dhcp(instance, family):
    client = instance.get_client(version=family)
    # ruleid: kea-runtime-write-outside-runtime-change
    client.dhcp_enable(family)


def bad_view_disables_dhcp_on_a_chained_client(instance):
    # ruleid: kea-runtime-write-outside-runtime-change
    instance.get_client(version=4).dhcp_disable(4, max_period=300)


def bad_view_wipes_the_leases_of_a_subnet(client, subnet_id):
    # ruleid: kea-runtime-write-outside-runtime-change
    client.lease_wipe(version=4, subnet_id=subnet_id)


def bad_import_adds_each_row(client, rows):
    for _line, creation in rows:
        # ruleid: kea-runtime-write-outside-runtime-change
        client.lease_add(creation)


def bad_view_updates_and_deletes_a_lease(client, fresh, body):
    # ruleid: kea-runtime-write-outside-runtime-change
    client.lease_update(4, body)
    # ruleid: kea-runtime-write-outside-runtime-change
    return client.lease_delete(fresh.identity)


def ok_view_runs_the_runtime_change(server, creation, shown):
    # ok: kea-runtime-write-outside-runtime-change
    runtime_change.add_lease(server, 4, creation)
    # ok: kea-runtime-write-outside-runtime-change
    return runtime_change.delete_lease(server, 4, shown)


def ok_view_reads_a_lease(client, identity):
    # ok: kea-runtime-write-outside-runtime-change
    fresh = client.lease_get_fresh(identity)
    # ok: kea-runtime-write-outside-runtime-change
    return client.lease_get(identity), fresh


def ok_view_sends_the_signal_of_an_added_lease(request, server):
    # ok: kea-runtime-write-outside-runtime-change
    lease_added.send_robust(sender=None, request=request, server=server)


def ok_view_reads_the_daemon_status(client):
    # ok: kea-runtime-write-outside-runtime-change
    return client.daemon_status(4)


# A data migration is not exempt. `opengrep test` does not apply path filters, so a directory scan proves the path.
def bad_migration_wipes_the_leases(apps, schema_editor):
    server = apps.get_model("netbox_kea", "Server").objects.first()
    # ruleid: kea-runtime-write-outside-runtime-change
    server.get_client(version=4).lease_wipe(4, 1)
