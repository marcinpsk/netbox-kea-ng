# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-snapshot-read-without-notice. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
from netbox_kea import server_configuration, subnet_catalogue
from netbox_kea.views.notices import ServerNotices, load_snapshot, notice, show_notices


class BadSubnetsView:
    def get_children(self, request, parent):
        # ruleid: kea-snapshot-read-without-notice
        snapshot = subnet_catalogue.display(parent, self.dhcp_version)
        if snapshot.unavailable:
            return []
        return list(snapshot.subnets)

    def get(self, request, pk, subnet_id):
        server = self.get_object(pk=pk)
        # ruleid: kea-snapshot-read-without-notice
        configuration = server_configuration.for_verification(server, self.dhcp_version)
        return [subnet for subnet in configuration.subnets if subnet.declared_subnet_id == subnet_id]


def bad_partial_reads_leases_without_the_loader(client, server, by, q):
    # ruleid: kea-view-read-ladder
    try:
        # ruleid: kea-snapshot-read-without-notice
        snapshot = client.lease_search(4, by, q, server_id=server.pk)
    except (KeaException, requests.RequestException, RuntimeError):
        return None
    return snapshot.records


def bad_combined_page_reads_without_notices(executor, servers):
    # ruleid: kea-snapshot-read-without-notice
    futures = {executor.submit(server_configuration.display, server, 4): server for server in servers}
    return [future.result() for future in futures]


class BadLeasesView:
    def get(self, request, client, instance, search):
        # ruleid: kea-snapshot-read-without-notice
        return read_leases(client, 4, search, instance.pk)


class GoodSubnetsView:
    def get_children(self, request, parent):
        # ok: kea-snapshot-read-without-notice
        snapshot = subnet_catalogue.display(parent, self.dhcp_version)
        if snapshot.unavailable:
            show_notices(request, notice(snapshot))
            return []
        return list(snapshot.subnets)

    def get(self, request, client, instance, search):
        loaded = load_snapshot(
            instance,
            "lease",
            # ok: kea-snapshot-read-without-notice
            lambda: read_leases(client, 4, search, instance.pk),
        )
        return loaded


def bad_reservation_tab_reads_without_the_loader(server, query):
    # ruleid: kea-snapshot-read-without-notice
    snapshot = _read_reservations(server, 4, query)
    return snapshot.records


def fetch(server, family, query):
    # ok: kea-snapshot-read-without-notice
    return load_snapshot(server, "reservation", lambda: _read_reservations(server, family, query))


def _read_reservations(server, family, query):
    # ok: kea-snapshot-read-without-notice
    return server.get_client(version=family).reservation_snapshot(family, None)


def good_form_carries_the_notice(server):
    # ok: kea-snapshot-read-without-notice
    snapshot = subnet_catalogue.display(server, 4)
    return {"subnet_notice": notice(snapshot)}


def good_combined_page_fills_its_lists(executor, servers):
    notices = ServerNotices()
    # ok: kea-snapshot-read-without-notice
    futures = {executor.submit(server_configuration.display, server, 4): server for server in servers}
    for future, server in futures.items():
        notices.add(server, notice(future.result()))
    return notices


def good_import_validation_refuses_with_the_failed_load(server):
    # ok: kea-snapshot-read-without-notice
    configuration = server_configuration.for_verification(server, 4)
    if configuration.unavailable:
        return failed_load(configuration).lines
    return ()


def get_export(request, client, server):
    # ruleid: kea-snapshot-read-without-notice
    return client.lease_get_all(4, server_id=server.pk)


def get_export_all(request, client, server):
    # ok: kea-snapshot-read-without-notice
    return load_snapshot(server, "lease", lambda: client.lease_get_all(4, server_id=server.pk))


def good_exact_and_synchronization_reads(client, server, identity):
    # ok: kea-snapshot-read-without-notice
    found = client.lease_get(identity)
    # ok: kea-snapshot-read-without-notice
    catalogue = for_synchronization(server, 4)
    return found, catalogue


def _display_capabilities(server, family):
    # ok: kea-snapshot-read-without-notice
    return server_configuration.reservation_capabilities(server_configuration.display(server, family))


def _live_capabilities(server, family):
    # ok: kea-snapshot-read-without-notice
    return server_configuration.reservation_capabilities(server_configuration.for_verification(server, family))


def _read_reservation_page(server, version, query):
    catalogue = subnet_catalogue.display(server, version)
    # ok: kea-snapshot-read-without-notice
    return _read_reservations(server, version, query, catalogue)
