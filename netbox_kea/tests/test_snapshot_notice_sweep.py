# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Every Server page that reads a Snapshot or loads one record shows the error headline of each kind it reads.

The sweep walks the URL resolver, so a new Server page fails until someone names its Snapshot kinds or exempts it.
"""

import re

import requests
from bs4 import BeautifulSoup
from django.contrib import messages as django_messages
from django.contrib.messages import get_messages
from django.urls import URLPattern, URLResolver, get_resolver, reverse

from netbox_kea.views.notices import HEADLINES, NoticeKind

from .kea_stub import stub_kea
from .kea_wire_discipline import WIRE_COMMANDS
from .utils import _ViewTestBase

_NAMESPACE = "plugins:netbox_kea:"

#: Each Server GET route that shows no Snapshot Notice, with the reason.
_EXEMPT = {
    "combined": "The Overview reads no Snapshot; badges have their own route.",
    "combined_overview": "The Overview reads no Snapshot; badges have their own route.",
    "combined_leases": "A Server chooser that reads no Kea data.",
    "combined_configuration": "A Server chooser that reads no Kea data.",
    "combined_sync": "Recorded NetBox jobs, with no live Kea read.",
    "combined_server_status_badge": "An htmx badge that reads version-get, not a Snapshot.",
    "ipaddress_kea_reservations": "Its pk names an IP address, and it reads no Kea data.",
    "reservation_check_ip": "An htmx fragment that reads NetBox IPAM, not Kea.",
    "server": "The NetBox object page reads no Kea data.",
    "server_switch": "A redirect checks target Subnet identities only for Subnet filters; dedicated request tests cover it.",
    "server_status": "The legacy Status entry point redirects without a Snapshot read.",
    "server_changelog": "A NetBox page that reads no Kea data.",
    "server_delete": "A NetBox page that reads no Kea data.",
    "server_edit": "A NetBox page that reads no Kea data.",
    "server_journal": "A NetBox page that reads no Kea data.",
    "server_jobs": "The job list reads no Kea data.",
    "server_sync_status": "The Sync tab reads no Kea data.",
    "server_dhcp_plugin": "The page reads no Kea data; htmx loads its drift card from server_dhcp_plugin_drift.",
    "server_dhcp_plugin_drift": (
        "An htmx card that reads nothing while the integration is off; DriftPartialTest covers its Notice."
    ),
    "server_dhcp_enable": "A confirmation page that reads no Kea data.",
    "server_dhcp_disable": "A confirmation page that reads no Kea data.",
    "server_lease_add": "A form that reads no Snapshot.",
    "server_lease_bulk_import": "An upload form that reads no Kea data.",
    "server_leases_delete": "A GET redirects; the delete is a POST.",
    "server_option_def_add": "A form that reads no Kea data.",
    "server_option_def_delete": "A confirmation page that reads no Kea data.",
    "server_reservation_bulk_import": "An upload form that reads no Kea data.",
    "server_reservation_published_name": "An htmx preview that shows no suffix when the Catalogue cannot.",
    "server_shared_network_add": "A form that reads no Kea data.",
    "server_shared_network_delete": "A confirmation page that reads no Kea data.",
    "server_option_def_tab": "The v4 tab link of server_option_def, which the sweep checks.",
    "server_leases_tab": "The v4 tab link of server_leases, which the sweep checks.",
    "server_reservations_tab": "The v4 tab link of server_reservations, which the sweep checks.",
    "server_subnets_tab": "The v4 tab link of server_subnets, which the sweep checks.",
}

#: The kinds whose error headline each page must show, by route name.
_EXPECTED: dict[str, frozenset[NoticeKind]] = {
    "combined_subnets": frozenset({"catalogue"}),
    "combined_shared_networks": frozenset({"configuration"}),
    "combined_reservations": frozenset({"reservation"}),
    "server_status_data": frozenset({"configuration"}),
    "server_dhcp_options_edit": frozenset({"configuration"}),
    "server_option_def": frozenset({"configuration"}),
    "server_shared_networks": frozenset({"configuration"}),
    "server_shared_network_edit": frozenset({"configuration"}),
    "server_subnet_add": frozenset({"configuration"}),
    "server_subnet_delete": frozenset({"configuration"}),
    "server_subnet_wipe_leases": frozenset({"configuration"}),
    "server_subnet_edit": frozenset({"catalogue", "configuration"}),
    "server_subnets": frozenset({"catalogue"}),
    "server_subnet_options_edit": frozenset({"catalogue"}),
    "server_subnet_pool_add": frozenset({"catalogue"}),
    "server_subnet_pool_delete": frozenset({"catalogue"}),
    "server_leases": frozenset({"catalogue"}),
    "server_reservation_add": frozenset({"catalogue"}),
    "server_reservation_edit": frozenset({"catalogue"}),
    "server_reservation_delete": frozenset({"catalogue"}),
    "server_lease_edit": frozenset({"lease_target"}),
    "server_reservations": frozenset({"reservation"}),
}

#: The query that a page needs before it reads anything.
_QUERIES = {
    ("server_reservation_edit", 4): {"identifier_type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff"},
    ("server_reservation_edit", 6): {"identifier_type": "duid", "identifier": "00:01:02:03"},
    ("server_reservation_delete", 4): {"identifier_type": "hw-address", "identifier": "aa:bb:cc:dd:ee:ff"},
    ("server_reservation_delete", 6): {"identifier_type": "duid", "identifier": "00:01:02:03"},
}

#: The htmx partial request of a page, and the Snapshot kinds whose error headline it must show inline.
_HTMX_SEARCHES: dict[tuple[str, int], tuple[dict[str, str], frozenset[NoticeKind]]] = {
    ("server_leases", 4): ({"by": "hw", "q": "aa:bb:cc:dd:ee:ff"}, frozenset({"catalogue", "lease"})),
    ("server_leases", 6): ({"by": "duid", "q": "00:01:02:03:04:05"}, frozenset({"catalogue", "lease"})),
    ("server_subnets", 4): ({}, frozenset({"catalogue"})),
    ("server_subnets", 6): ({}, frozenset({"catalogue"})),
}

_ARGUMENTS = {
    4: {
        "subnet_id": 1,
        "pool": "198.18.0.10-198.18.0.20",
        "network_name": "net",
        "code": 222,
        "space": "dhcp4",
        "ip_address": "198.18.0.10",
    },
    6: {
        "subnet_id": 1,
        "pool": "2001:db8::10-2001:db8::20",
        "network_name": "net",
        "code": 222,
        "space": "dhcp6",
        "ip_address": "2001:db8::10",
    },
}


def _server_routes(resolver: URLResolver | None = None, namespace: str = "", parameters: tuple = ()):
    """Yield the name and parameters of each plugin GET route whose pk names a Server."""
    for entry in (resolver or get_resolver()).url_patterns:
        found = (*parameters, *entry.pattern.regex.groupindex)
        if isinstance(entry, URLResolver):
            yield from _server_routes(entry, f"{namespace}{entry.namespace}:" if entry.namespace else namespace, found)
        elif (
            isinstance(entry, URLPattern)
            and f"{namespace}{entry.name}".startswith(_NAMESPACE)
            and ("pk" in found or str(entry.name).startswith("combined"))
        ):
            view = getattr(entry.callback, "view_class", None) or getattr(entry.callback, "cls", None)
            if hasattr(view, "get"):
                yield f"{namespace}{entry.name}".removeprefix(_NAMESPACE), found


def _shown_error_kinds(response) -> set[NoticeKind]:
    """Return each Snapshot kind whose headline the page shows at the error level, as a message or an inline alert."""
    shown = {str(m) for m in get_messages(response.wsgi_request) if m.level == django_messages.ERROR}
    page = response.content.decode() if response.status_code == 200 else ""
    alerts = BeautifulSoup(page, "html.parser").select(".alert-danger")
    return {
        kind
        for kind, text in HEADLINES.items()
        if text in shown
        or any(text in alert.get_text() for alert in alerts)
        or re.search(rf'class="alert alert-danger[^"]*"[^>]*>\s*(?:<(?:div|strong)>\s*)*{re.escape(text)}', page)
    }


class TestEveryServerPageShowsAFailedRead(_ViewTestBase):
    def test_every_server_page_shows_an_error_notice_when_kea_fails(self):
        routes = dict(_server_routes())
        self.assertFalse(set(_EXEMPT) - set(routes), "An exemption names a route that no longer exists.")
        stale = set(_EXPECTED) - set(routes)
        self.assertFalse(stale, "An expected entry names a route that no longer exists.")
        failure = requests.ConnectionError("Kea is unreachable")
        checked = []
        with stub_kea(dict.fromkeys(WIRE_COMMANDS, failure)):
            for name, parameters in sorted(routes.items()):
                if name in _EXEMPT:
                    continue
                expected = _EXPECTED.get(name)
                self.assertIsNotNone(expected, f"Add the Snapshot kinds of {name} to _EXPECTED, or exempt it.")
                families = (4, 6) if "family" in parameters else (4,)
                for family in families:
                    arguments = {"pk": self.server.pk, "family": family, **_ARGUMENTS[family]}
                    url = reverse(_NAMESPACE + name, kwargs={key: arguments[key] for key in parameters})
                    requests_ = [(url, _QUERIES.get((name, family), {}), {}, expected)]
                    if (name, family) in _HTMX_SEARCHES:
                        htmx_query, htmx_kinds = _HTMX_SEARCHES[name, family]
                        requests_.append((url, htmx_query, {"HTTP_HX_REQUEST": "true"}, htmx_kinds))
                    for path, query, headers, kinds in requests_:
                        with self.subTest(route=name, family=family, htmx=bool(headers)):
                            self._fresh_client()
                            response = self.client.get(path, query, **headers)
                            self.assertIn(response.status_code, (200, 302))
                            missing = sorted(kinds - _shown_error_kinds(response))
                            self.assertEqual(missing, [], f"{name} shows no error headline of {missing}")
                            checked.append((name, family))
        # The sweep must reach the pages that read each Snapshot kind.
        self.assertTrue(
            {("server_subnets", 4), ("server_status_data", 4), ("server_reservations", 4), ("server_leases", 6)}
            <= set(checked)
        )
