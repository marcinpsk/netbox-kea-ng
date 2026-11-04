# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ruleid: kea-private-reservation-read-import
from netbox_kea.views.reservations import _RESERVATION_PAGE_SIZE

# ruleid: kea-private-reservation-read-import
from ..views.reservations import _reservation_list_context

# ruleid: kea-private-reservation-read-import
from .views.reservations import fetch, _reservation_export_response

# ruleid: kea-private-reservation-read-import
from netbox_kea.reservation_reads import _matches

# ruleid: kea-private-reservation-read-import
from ..reservation_reads import _read_page as read_page

# ruleid: kea-private-reservation-read-import
from .reservation_reads import (
    PAGE_SIZE,
    _search,
)

# ok: kea-private-reservation-read-import
from netbox_kea.views.reservations import RESERVATIONS_TAB, present

# ok: kea-private-reservation-read-import
from ..reservation_reads import ReservationQuery, cached_page

# ok: kea-private-reservation-read-import
from .reservation_reads import (
    ReservationPage,
    read_snapshot as snapshot,
)

# ok: kea-private-reservation-read-import
from ..reservations import _parse_reservation_page

import netbox_kea.reservation_reads
from netbox_kea import reservation_reads
from netbox_kea import reservation_reads as absolute_reads
from netbox_kea.views import reservations as reservation_views

from .. import reservation_reads as relative_reads


def uses_a_private_name(server, query):
    # ruleid: kea-private-reservation-read-import
    reservation_reads._matches(query)
    # ruleid: kea-private-reservation-read-import
    absolute_reads._search(server, 4, query)
    # ruleid: kea-private-reservation-read-import
    relative_reads._read_page(server, 4, query)
    # ruleid: kea-private-reservation-read-import
    reservation_views._reservation_list_context(query, server, 4)
    # ruleid: kea-private-reservation-read-import
    return netbox_kea.reservation_reads._SEARCH_PAGE_LIMIT


def uses_the_public_names(server, query):
    # ok: kea-private-reservation-read-import
    reservation_reads.empty_snapshot(4, query.read_started)
    # ok: kea-private-reservation-read-import
    relative_reads.read_snapshot(server, 4)
    # ok: kea-private-reservation-read-import
    reservation_views.fetch(server, 4, query)
    # ok: kea-private-reservation-read-import
    absolute_reads.ReservationQuery(q="host")
    # ok: kea-private-reservation-read-import
    return netbox_kea.reservation_reads.PAGE_SIZE
