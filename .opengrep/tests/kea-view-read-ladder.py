# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-view-read-ladder. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
import requests

from netbox_kea.kea import KeaException, kea_error_message
from netbox_kea.views.notices import Notice, load_snapshot, load_target, show_notices


class BadLeaseEditView:
    def get(self, request, client, identity):
        # ruleid: kea-view-read-ladder
        try:
            result = client.lease_get(identity)
        except KeaException as exc:
            messages.error(request, kea_error_message(exc))
            return None
        except (requests.RequestException, RuntimeError, ValueError):
            messages.error(request, "Failed to fetch lease: see server logs for details.")
            return None
        return result


def bad_export_reads_in_a_tuple_ladder(server, version):
    # ruleid: kea-view-read-ladder
    try:
        snapshot = export_snapshot(server, version)
    except (KeaException, requests.RequestException, RuntimeError, ValueError):
        return HttpResponse("The Reservation Snapshot could not be exported.", status=502)
    return snapshot


def bad_transport_only_ladder(request, client, identity):
    # ruleid: kea-view-read-ladder
    try:
        return client.lease_get(identity)
    except (requests.RequestException, RuntimeError):
        return _row_error(request, "Could not fetch live data from Kea.")


def bad_ladder_after_a_value_error_clause(request, server, identity):
    # ruleid: kea-view-read-ladder
    try:
        reservation = _load_target(server, 4, 1, identity)
    except ValueError:
        return None
    except (KeaException, RuntimeError) as exc:
        messages.error(request, "The Reservation could not be loaded. See server logs.")
        return None
    return reservation


class GoodLeaseEditView:
    def get(self, request, server, client, identity):
        # ok: kea-view-read-ladder
        loaded = load_target(server, "lease_target", lambda: client.lease_get(identity))
        if isinstance(loaded, Notice):
            show_notices(request, loaded)
            return None
        return loaded


def good_export_catches_only_its_value_error(request, server, client, search):
    # ok: kea-view-read-ladder
    try:
        loaded = load_snapshot(server, "lease", lambda: read_leases(client, server, 4, search))
    except ValueError:
        messages.error(request, "The lease search is not valid, so it was not exported.")
        return None
    return loaded


def good_client_settings_check(request, server):
    # ok: kea-view-read-ladder
    try:
        server.get_client(version=4).close()
    except ValueError as exc:
        messages.error(request, _client_settings_error(server, exc))


def _enrich_subnet_statistics(rows, server, version):
    # ok: kea-view-read-ladder
    try:
        utilization = _read_utilization(server, version)
    except KeaException:
        logger.warning("Kea refused the Subnet utilization read of server %s", server.pk, exc_info=True)
        return
    except (requests.RequestException, RuntimeError, ValueError):
        logger.warning("Could not read Subnet utilization from server %s", server.pk, exc_info=True)
        return
    rows.extend(utilization)


def _daemon_online(server, version):
    # ok: kea-view-read-ladder
    try:
        daemon_version(server, version)
    except (KeaException, requests.RequestException, OSError, RuntimeError, ValueError) as exc:
        logger.warning("The DHCPv%s daemon of server %s did not answer (%s)", version, server.pk, type(exc).__name__)
        return False
    return True


def good_broad_handler_is_another_rule(request, server):
    # ok: kea-view-read-ladder
    try:
        run_dhcp_plugin_import(server)
    except Exception:
        logger.exception("DHCP-plugin import failed for server %s", server.name)
