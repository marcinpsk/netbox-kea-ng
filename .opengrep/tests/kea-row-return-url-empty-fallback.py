# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0


def row_actions(request, row):
    # ruleid: kea-row-return-url-empty-fallback
    row["return_url"] = _safe_return_url(request, "")

    # ok: kea-row-return-url-empty-fallback
    row["return_url"] = _safe_return_url(request, request.get_full_path())

    # ok: kea-row-return-url-empty-fallback
    row["return_url"] = request.get_full_path()

    # Navigation may have no workspace origin to carry.
    # ok: kea-row-return-url-empty-fallback
    return_url = _safe_return_url(request, "")
    return return_url
