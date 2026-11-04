# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ruleid: kea-private-reservation-view-import
from .reservations import _build_reservation_options_formset

# ruleid: kea-private-reservation-view-import
from .reservations import (
    RESERVATIONS_TAB,
    _display_capabilities,
    _live_capabilities,
)

# ok: kea-private-reservation-view-import
from .reservations import MUTATION_UNCONFIRMED, fetch, present

# ok: kea-private-reservation-view-import
from .reservations import present as _present

# ok: kea-private-reservation-view-import
from ..reservations import _exact_reservation

from . import reservations as reservation_views


def uses_a_private_name(request, server):
    # ruleid: kea-private-reservation-view-import
    return reservation_views._reservation_list_context(request, server, 4)


def uses_a_public_name(server, query):
    # ok: kea-private-reservation-view-import
    return reservation_views.fetch(server, 4, query)
