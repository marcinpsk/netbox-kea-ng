# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-change-in-broad-except. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
from netbox_kea import config_write, runtime_change


def bad_view_catches_exception(request, server):
    try:
        # ruleid: kea-change-in-broad-except
        config_write.delete_shared_network(server, 4, "net")
    except Exception:
        logger.exception("Could not delete the Shared Network")


def bad_view_catches_exception_by_name(request, server):
    try:
        # ruleid: kea-change-in-broad-except
        outcome = config_write.add_shared_network(server, 4, "net")
    except Exception as exc:
        logger.exception("Could not add the Shared Network: %s", exc)
        return None
    return outcome


def bad_view_catches_base_exception_in_a_tuple(request, server):
    try:
        # ruleid: kea-change-in-broad-except
        config_write.delete_shared_network(server, 4, "net")
    except (ValueError, BaseException):
        logger.exception("Could not delete the Shared Network")


def bad_view_uses_a_bare_except(request, server):
    try:
        # ruleid: kea-change-in-broad-except
        config_write.delete_shared_network(server, 4, "net")
    except:
        logger.exception("Could not delete the Shared Network")


def bad_view_defers_the_change_to_another_helper(request, server):
    try:
        # ruleid: kea-change-in-broad-except
        return run_later(lambda: config_write.delete_shared_network(server, 4, "net"))
    except Exception:
        logger.exception("Could not delete the Shared Network")


def bad_view_evaluates_the_change_before_the_mapper(request, server):
    try:
        # ruleid: kea-change-in-broad-except
        return _run_change(request, "Deleted.", config_write.delete_shared_network(server, 4, "net"))
    except Exception:
        logger.exception("Could not delete the Shared Network")


def ok_view_catches_around_the_mapper(request, server):
    try:
        # ok: kea-change-in-broad-except
        return _run_change(request, "Deleted.", lambda: config_write.delete_shared_network(server, 4, "net"))
    except Exception:
        logger.exception("Could not build the redirect")


def ok_view_catches_a_narrow_error(request, server):
    try:
        # ok: kea-change-in-broad-except
        config_write.delete_shared_network(server, 4, "net")
    except ValueError:
        logger.exception("Could not delete the Shared Network")


def ok_view_calls_without_a_try(request, server):
    # ok: kea-change-in-broad-except
    return config_write.delete_shared_network(server, 4, "net")


def bad_view_wipes_inside_a_broad_except(request, server):
    try:
        # ruleid: kea-change-in-broad-except
        runtime_change.wipe_leases(server, 4, 10)
    except Exception:
        logger.exception("Could not wipe the Leases")


def ok_view_runs_a_runtime_change_through_the_mapper(request, server):
    try:
        # ok: kea-change-in-broad-except
        return _run_change(request, "Wiped.", lambda: runtime_change.wipe_leases(server, 4, 10))
    except Exception:
        logger.exception("Could not build the redirect")


def ok_view_runs_a_loop_through_the_mapper(request, server, selected):
    try:
        # ok: kea-change-in-broad-except
        return _run_change_loop(selected, lambda shown: runtime_change.delete_lease(server, 4, shown))
    except Exception:
        logger.exception("Could not build the report")
