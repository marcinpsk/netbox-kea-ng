# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-reservation-write-outside-config-write. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
# The bad cases are the view calls that ADR 0012 moved into config_write.
from netbox_kea import config_write


def bad_view_creates_a_reservation(server, reservation):
    client = server.get_client(version=4)
    # ruleid: kea-reservation-write-outside-config-write
    client.reservation_add(reservation)


def bad_import_creates_each_entry_on_a_chained_client(server, reservations):
    for reservation in reservations:
        # ruleid: kea-reservation-write-outside-config-write
        server.get_client(version=4).reservation_add(reservation)


def bad_view_updates_a_reservation(client, fresh, intended):
    # ruleid: kea-reservation-write-outside-config-write
    client.reservation_update(4, fresh.updated(intended))


def bad_view_deletes_a_reservation(client, scope, identity):
    # ruleid: kea-reservation-write-outside-config-write
    return client.reservation_del(4, scope, identity)


def ok_view_runs_the_configuration_change(server, build, identity):
    # ok: kea-reservation-write-outside-config-write
    config_write.add_reservation(server, 4, "198.18.0.0/24", build)
    # ok: kea-reservation-write-outside-config-write
    return config_write.delete_reservation(server, 4, 20, identity)


def ok_view_reads_a_reservation(client, catalogue, scope, identity):
    # ok: kea-reservation-write-outside-config-write
    fresh = client.reservation_get_fresh(4, catalogue, scope, identity)
    # ok: kea-reservation-write-outside-config-write
    return client.reservation_by_identity(4, catalogue, scope, identity), fresh


def ok_view_sends_the_signal_of_a_created_reservation(request, server):
    # ok: kea-reservation-write-outside-config-write
    reservation_created.send_robust(sender=None, request=request, server=server)


# A data migration is not exempt. `opengrep test` does not apply path filters, so a directory scan proves the path.
def bad_migration_deletes_a_reservation(apps, schema_editor, scope, identity):
    server = apps.get_model("netbox_kea", "Server").objects.first()
    # ruleid: kea-reservation-write-outside-config-write
    server.get_client(version=4).reservation_del(4, scope, identity)
