# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-view-read-ladder. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
import requests

from netbox_kea.kea import KeaClientSettingsError, KeaException, kea_error_message
from netbox_kea.malformed import MalformedKeaReply
from netbox_kea.read_failure import ReadFailure, attempt
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


def _enrich_subnet_statistics(rows, server, version):
    # ruleid: kea-view-read-ladder
    try:
        utilization = _read_utilization(server, version)
    except KeaException:
        logger.warning("Kea refused the Subnet utilization read of server %s", server.pk, exc_info=True)
        return
    rows.extend(utilization)


def bad_malformed_reply_handler(server, family):
    # ruleid: kea-view-read-ladder
    try:
        return read_configuration(server, family)
    except MalformedKeaReply:
        return unavailable(server, family, "malformed-configuration-response")


def bad_malformed_reply_in_a_tuple(server, family):
    # ruleid: kea-view-read-ladder
    try:
        return observe_leases(server, family)
    except (MalformedKeaReply, OSError) as exc:
        return LeaseObservation(None, exc)


def bad_client_settings_handler(request, server):
    # ruleid: kea-view-read-ladder
    try:
        return server.get_client(version=4)
    except KeaClientSettingsError as exc:
        messages.error(request, "The client settings are not valid.")
        return None


def good_attempt_maps_the_kind(server, family):
    # ok: kea-view-read-ladder
    read = attempt("The configuration read", lambda: read_configuration(server, family))
    if isinstance(read, ReadFailure):
        return unavailable(server, family, read.kind)
    return read


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


def good_a_named_malformed_subclass_of_a_write_step(fresh, change):
    # ok: kea-view-read-ladder
    try:
        return fresh.updated(change)
    except (MalformedReservation, ValueError) as exc:
        raise ChangeRejected("not-sent", ("unusable",)) from exc


def mutate(client, family, send, *, on_failure):
    # ok: kea-view-read-ladder
    try:
        send()
    except KeaException as exc:
        return "unknown", (kea_error_message(exc),)
    except requests.RequestException:
        return "unknown", ()
    except (MalformedKeaReply, ValueError, RuntimeError):
        return "unknown", ()
    return "applied", ()


def _test_before(client, family, candidate):
    def test():
        # ok: kea-view-read-ladder
        try:
            client.config_test(candidate)
        except KeaException as exc:
            if exc.unsupported_command:
                return
            raise

    before_change(test, "unusable")


def good_broad_handler_is_another_rule(request, server):
    # ok: kea-view-read-ladder
    try:
        run_dhcp_plugin_import(server)
    except Exception:
        logger.exception("DHCP-plugin import failed for server %s", server.name)
