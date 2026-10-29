# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-exception-detail-in-response. Intentionally contains
# rule-violating code; excluded from ruff (see pyproject [tool.ruff] exclude).
from django.contrib import messages
from django.http import HttpResponse


def bad_str(request):
    try:
        do()
    except Exception as exc:
        # ruleid: kea-exception-detail-in-response
        messages.error(request, str(exc))


def bad_fstring(request):
    try:
        do()
    except Exception as exc:
        # ruleid: kea-exception-detail-in-response
        messages.warning(request, f"Failed: {exc}")


def bad_http(request):
    try:
        do()
    except ValueError as err:
        # ruleid: kea-exception-detail-in-response
        return HttpResponse(str(err))


def ok_generic(request):
    try:
        do()
    except Exception:
        # ok: kea-exception-detail-in-response
        messages.error(request, "An internal error occurred")


def ok_hint(request):
    try:
        do()
    except Exception as exc:
        logger.exception("kea call failed")
        # ok: kea-exception-detail-in-response
        messages.error(request, kea_error_message(exc))


class JobRunnerFixture:
    def bad_job_log(self):
        try:
            do()
        except Exception as exc:
            # ruleid: kea-exception-detail-in-response
            self.logger.error(f"Import failed: {type(exc).__name__}: {exc}; see the worker log")

    def bad_job_log_concatenated(self, name):
        try:
            do()
        except Exception as exc:
            # ruleid: kea-exception-detail-in-response
            self.logger.error(
                f"Unhandled error syncing server {name}: {type(exc).__name__}: {exc};"
                " the worker log has the traceback"
            )

    def bad_job_log_str(self):
        try:
            do()
        except ValueError as err:
            # ruleid: kea-exception-detail-in-response
            self.logger.warning(str(err))

    def ok_job_log_type_only(self):
        try:
            do()
        except Exception as exc:
            # ok: kea-exception-detail-in-response
            self.logger.error(f"Import failed: {type(exc).__name__}; the worker log has the details")

    def ok_job_log_typed_refusal(self):
        try:
            do()
        except MetadataBusy as error:
            # ok: kea-exception-detail-in-response
            self.logger.error(f"Import failed: {error.message}")
