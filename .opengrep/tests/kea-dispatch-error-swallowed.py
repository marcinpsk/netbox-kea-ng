# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from netbox_kea import event_scope


def broad(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except ValueError:
        pass
    except Exception:
        pass


def broad_in_a_loop(rows):
    try:
        for row in rows:
            # ruleid: kea-dispatch-error-swallowed
            with event_scope.atomic():
                row.save()
    except Exception as exc:
        print(type(exc))


def bare(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except:  # noqa: E722
        pass


def base(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except BaseException:
        pass


def reraised(obj):
    try:
        # ok: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:
        print(type(exc))


def narrow(obj):
    try:
        # ok: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except (LookupError, ValueError):
        pass


def broad_with_else(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except Exception as exc:
        print(type(exc))
    else:
        return obj
    return None


def reraised_with_else(obj):
    try:
        # ok: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        raise
    except Exception as exc:
        print(type(exc))
    else:
        return obj
    return None


def broad_in_a_tuple(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except (Exception, OSError):
        pass


def broad_last_in_a_tuple(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except (OSError, Exception) as exc:
        print(type(exc))
    else:
        return obj
    return None


def base_in_a_tuple(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except (KeyboardInterrupt, BaseException) as exc:
        print(type(exc))


def reraised_before_a_tuple(obj):
    try:
        # ok: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        raise
    except (Exception, OSError):
        pass


def runtime_error_around_a_claim(server, leases):
    try:
        # ruleid: kea-dispatch-error-swallowed
        claim(server, 4, leases, force=True)
    except (RuntimeError, ValueError):
        pass


def runtime_error_around_a_reconciliation_reraised(server, phases):
    try:
        # ok: kea-dispatch-error-swallowed
        reconcile(server, 4, phases)
    except event_scope.EventDispatchError:
        raise
    except RuntimeError as exc:
        print(type(exc))


def _run_lease_sync_to_netbox(request, server, leases):
    try:
        # ok: kea-dispatch-error-swallowed
        claim(server, 4, leases, force=False)
    except event_scope.EventDispatchError:
        messages.error(request, "Lease created, but NetBox could not dispatch the events of the sync.")
    except (RuntimeError, ValueError):
        messages.error(request, "Lease created but NetBox IPAM sync failed.")


def dispatch_error_passed(server, leases):
    try:
        # ruleid: kea-dispatch-error-swallowed
        claim(server, 4, leases, force=False)
    except event_scope.EventDispatchError:
        pass
    except (RuntimeError, ValueError):
        messages.error(request, "Lease created but NetBox IPAM sync failed.")


def dispatch_error_only_logged(request, obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        logger.exception("The events of the sync could not be dispatched")
    except (RuntimeError, ValueError):
        messages.error(request, "Lease created but NetBox IPAM sync failed.")


def _sync_to_netbox(request, server, leases):
    try:
        # ruleid: kea-dispatch-error-swallowed
        claim(server, 4, leases, force=False)
    except event_scope.EventDispatchError:
        logger.exception("The events of the sync could not be dispatched")
        messages.error(request, "Lease created, but NetBox could not dispatch the events of the sync.")
    except (RuntimeError, ValueError):
        messages.error(request, "Lease created but NetBox IPAM sync failed.")


def dispatch_error_reported_after_an_ordinary_unit(request, obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        messages.error(request, "Saved, but NetBox could not dispatch the events.")
    except RuntimeError:
        messages.error(request, "The save failed.")


def dispatch_error_reported_after_a_claim_outside_a_runtime_change(request, server, leases):
    try:
        # ruleid: kea-dispatch-error-swallowed
        claim(server, 4, leases, force=False)
    except event_scope.EventDispatchError:
        messages.error(request, "Synced, but NetBox could not dispatch the events of the sync.")
    except (RuntimeError, ValueError):
        messages.error(request, "NetBox IPAM sync failed.")


def claim(*args, **kwargs):
    return args, kwargs


def reconcile(*args, **kwargs):
    return args, kwargs


def journal_events_reported(obj) -> SideEffectStatus:
    try:
        # ok: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        logger.exception("Committed journal events failed")
        return "events-failed"
    except RuntimeError:
        return "failed"


def typed_status_cannot_hide_a_committed_write(obj) -> SideEffectStatus:
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        return "failed"
    except RuntimeError:
        return "failed"


def an_untyped_string_is_not_a_committed_event_fact(obj):
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        return "events-failed"
    except RuntimeError:
        return "failed"


def committed_claim_events_reported(server, records):
    try:
        # ok: kea-dispatch-error-swallowed
        return claim(server, 4, records, force=True)
    except event_scope.EventDispatchError:
        return ClaimFailure("events-failed")
    except RuntimeError:
        return ClaimFailure("failed")


def a_failed_claim_fact_is_not_a_committed_event_fact(server, records):
    try:
        # ruleid: kea-dispatch-error-swallowed
        return claim(server, 4, records, force=True)
    except event_scope.EventDispatchError:
        return ClaimFailure("failed")
    except RuntimeError:
        return ClaimFailure("failed")


def a_valid_handler_does_not_hide_another_failed_unit(obj) -> SideEffectStatus:
    try:
        # ok: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except event_scope.EventDispatchError:
        return "events-failed"
    except RuntimeError:
        return "failed"
    try:
        # ruleid: kea-dispatch-error-swallowed
        with event_scope.atomic():
            obj.save()
    except RuntimeError:
        return "failed"
