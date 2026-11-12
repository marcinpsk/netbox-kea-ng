# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one Server access gate: its refusal rule on every Server route, and the controls that follow from it."""

from unittest.mock import patch

import requests
from bs4 import BeautifulSoup
from django.conf import settings
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import URLPattern, URLResolver, get_resolver, reverse
from ipam.models import IPAddress
from netaddr import IPNetwork

from netbox_kea import branching
from netbox_kea.models import Server
from netbox_kea.views.server_scope import ServerAccessMixin

from .kea_stub import stub_kea
from .kea_wire_discipline import WIRE_COMMANDS
from .utils import User, _grant, _make_db_server

_KEA_DOWN = dict.fromkeys(WIRE_COMMANDS, requests.ConnectionError("Kea is unreachable"))
_NAMESPACE = "plugins:netbox_kea:"
_CHANGE_REFUSED = "You do not have permission to modify Kea server data."


class _AccessTestCase(TestCase):
    """Two Servers, and a user who may view both but may change and delete only the other one."""

    def setUp(self):
        self.server = _make_db_server(name="gated")
        self.other = _make_db_server(name="other")
        self.user = User.objects.create_user("constrained")
        _grant([Server], ["view"], user=self.user)
        _grant([Server], ["change", "delete"], user=self.user, constraints={"pk": self.other.pk})
        self.client.force_login(self.user)


class RunNowAndToggleRefusalTest(_AccessTestCase):
    """Run Now and the Sync toggle follow the refusal rule: a viewable Server that the user may not change is 403."""

    def test_run_now_is_refused_with_403_and_enqueues_nothing(self):
        url = reverse("plugins:netbox_kea:server_sync_now", args=[self.server.pk])
        with patch("netbox_kea.views.sync_jobs.KeaIpamSyncJob", autospec=True) as job:
            response = self.client.post(url)

        self.assertContains(response, _CHANGE_REFUSED, status_code=403)
        job.enqueue.assert_not_called()

    def test_sync_toggle_is_refused_with_403_and_changes_nothing(self):
        url = reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk])

        response = self.client.post(url)

        self.assertContains(response, _CHANGE_REFUSED, status_code=403)
        self.server.refresh_from_db()
        self.assertTrue(self.server.sync_enabled)


def _header_controls(response, server: Server) -> tuple[list, list]:
    """Return the Edit links and the Delete controls of *server* in the page header."""
    page = BeautifulSoup(response.content, "html.parser")
    edit = reverse("plugins:netbox_kea:server_edit", args=[server.pk])
    delete = reverse("plugins:netbox_kea:server_delete", args=[server.pk])
    controls = page.select(".btn-list")
    return (
        [link for block in controls for link in block.select(f'a[href^="{edit}"]')],
        [link for block in controls for link in block.select(f'[hx-get^="{delete}"]')],
    )


class HeaderControlsTest(_AccessTestCase):
    """The header Edit and Delete controls show only for a Server that the user may change or delete."""

    def _pages(self, server: Server) -> dict[str, str]:
        return {
            "the Overview (a NetBox object view)": reverse("plugins:netbox_kea:server", args=[server.pk]),
            "the Option Definitions (a plain view)": reverse(
                "plugins:netbox_kea:server_option_def", kwargs={"pk": server.pk, "family": 4}
            ),
        }

    def test_a_grant_constrained_to_another_server_shows_no_edit_or_delete(self):
        for name, url in self._pages(self.server).items():
            with self.subTest(page=name), stub_kea(_KEA_DOWN):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(_header_controls(response, self.server), ([], []))

    def test_the_server_that_the_grant_names_shows_edit_and_delete(self):
        for name, url in self._pages(self.other).items():
            with self.subTest(page=name), stub_kea(_KEA_DOWN):
                response = self.client.get(url)
                edit, delete = _header_controls(response, self.other)
                self.assertEqual((len(edit), len(delete)), (1, 1))


class ServerOptionsLinkTest(_AccessTestCase):
    """The Server Options subsection links only a Server that the user may change."""

    def _options_links(self, server: Server) -> list:
        url = reverse("plugins:netbox_kea:server_option_def", kwargs={"pk": server.pk, "family": 4})
        options = reverse("plugins:netbox_kea:server_dhcp_options_edit", kwargs={"pk": server.pk, "family": 4})
        with stub_kea(_KEA_DOWN):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.content, "html.parser").select(f'.kea-tabs a[href^="{options}"]')

    def test_a_viewer_sees_no_server_options_link(self):
        self.assertEqual(self._options_links(self.server), [])

    def test_a_user_who_may_change_the_server_sees_the_link(self):
        self.assertEqual(len(self._options_links(self.other)), 1)


class CreateReservationLinksTest(_AccessTestCase):
    """Both Create Reservation link lists name only the Servers that the user may change."""

    def setUp(self):
        super().setUp()
        _grant([IPAddress], ["view"], user=self.user)
        self.ip = IPAddress.objects.create(address=IPNetwork("192.0.2.10/24"), dns_name="host.example.com")

    def _assert_links_only_the_changeable_server(self, response):
        page = response.content.decode()
        self.assertEqual(response.status_code, 200)
        for server, shown in ((self.other, True), (self.server, False)):
            add = reverse("plugins:netbox_kea:server_reservation_add", kwargs={"pk": server.pk, "family": 4})
            self.assertEqual(add in page, shown, server.name)
            self.assertEqual(server.name in page, shown, server.name)

    def test_the_ip_address_panel_lists_only_servers_the_user_may_change(self):
        self._assert_links_only_the_changeable_server(self.client.get(reverse("ipam:ipaddress", args=[self.ip.pk])))

    def test_the_ip_kea_reservations_page_lists_only_servers_the_user_may_change(self):
        response = self.client.get(reverse("plugins:netbox_kea:ipaddress_kea_reservations", args=[self.ip.pk]))
        self._assert_links_only_the_changeable_server(response)


_ARGUMENTS = {
    "pk": 1,
    "family": 4,
    "subnet_id": 1,
    "pool": "192.0.2.10-192.0.2.20",
    "network_name": "net",
    "code": 222,
    "space": "dhcp4",
    "ip_address": "192.0.2.10",
    "section": "sync",
}


def _plugin_routes(resolver=None, namespace: str = "", parameters: tuple[str, ...] = ()) -> list:
    """Return the name, the parameters and the callback of each UI route of the plugin."""
    routes = []
    for entry in (resolver or get_resolver()).url_patterns:
        found = (*parameters, *entry.pattern.regex.groupindex)
        if isinstance(entry, URLResolver):
            routes += _plugin_routes(entry, f"{namespace}{entry.namespace}:" if entry.namespace else namespace, found)
        elif isinstance(entry, URLPattern) and branching.plugin_owned(entry.callback) and namespace == _NAMESPACE:
            routes.append((f"{namespace}{entry.name}", found, entry.callback))
    return routes


def _view(callback) -> type:
    """Return the view class of a URL callback."""
    return getattr(callback, "view_class", None) or callback.cls


def _url(name: str, parameters: tuple[str, ...], **values) -> str:
    """Reverse the route *name* with a value for each of its *parameters*."""
    arguments = {**_ARGUMENTS, **values}
    return reverse(name, kwargs={key: arguments[key] for key in parameters})


class MutationFormSetTest(TestCase):
    """The branch controls recognize the same change forms as before the gate."""

    def test_mutation_form_recognizes_exactly_the_change_forms(self):
        recognized = sorted(
            {
                _view(callback).__name__
                for _name, _parameters, callback in _plugin_routes()
                if branching.mutation_form(callback)
            }
        )

        self.assertEqual(
            recognized,
            [
                "ServerBulkDeleteView",
                "ServerBulkEditView",
                "ServerBulkImportView",
                "ServerDHCPDisableView",
                "ServerDHCPEnableView",
                "ServerDHCPOptionsEditView",
                "ServerDeleteView",
                "ServerEditView",
                "ServerLeaseAddView",
                "ServerLeaseBulkImportView",
                "ServerLeaseEditView",
                "ServerOptionDefAddView",
                "ServerOptionDefDeleteView",
                "ServerReservationAddView",
                "ServerReservationBulkImportView",
                "ServerReservationDeleteView",
                "ServerReservationEditView",
                "ServerReservationPublishedNameView",
                "ServerSharedNetworkAddView",
                "ServerSharedNetworkDeleteView",
                "ServerSharedNetworkEditView",
                "ServerSubnetAddView",
                "ServerSubnetDeleteView",
                "ServerSubnetEditView",
                "ServerSubnetOptionsEditView",
                "ServerSubnetPoolAddView",
                "ServerSubnetPoolDeleteView",
                "ServerSubnetWipeView",
            ],
        )


#: Routes whose pk names another object.
_NOT_A_SERVER = {"ipaddress_kea_reservations": "Its pk names an IP address."}
#: Routes whose handler calls ``server_access()`` with this action instead of inheriting the gate, with the reason.
_HANDLER_GATE = {
    # A gated change view is a change form to the branch controls, and these POST-only actions are not.
    "server_sync_now": "change",
    "server_sync_toggle": "change",
    # The switch leaves its Server, so the disabled family of that Server does not apply.
    "server_switch": "view",
    # NetBox's views, which also serve the add form and keep NetBox's check there.
    "server_edit": "change",
    "server_delete": "delete",
}
_POST_ONLY = frozenset(("server_sync_now", "server_sync_toggle"))


def _server_routes() -> list[tuple[str, tuple[str, ...], type]]:
    """Return the short name, the parameters and the view class of each plugin route whose pk names a Server."""
    return [
        (name.removeprefix(_NAMESPACE), parameters, _view(callback))
        for name, parameters, callback in _plugin_routes()
        if "pk" in parameters and name.removeprefix(_NAMESPACE) not in _NOT_A_SERVER
    ]


class GateCompletenessTest(TestCase):
    """Every view on a Server route declares the action of its Server, so the gate answers each request."""

    def test_every_server_route_view_declares_its_server_action(self):
        routes = _server_routes()
        names = {name for name, _parameters, _view_class in routes}
        self.assertFalse(set(_HANDLER_GATE) - names, "An exception names a route that no longer exists.")
        missing = sorted(
            f"{name} ({view.__name__})"
            for name, _parameters, view in routes
            if name not in _HANDLER_GATE
            and not (issubclass(view, ServerAccessMixin) and view.server_action in ("view", "change"))
        )
        self.assertEqual(missing, [], "Give each view the gate and a server_action, or list it with its reason.")

    def test_the_handler_gated_routes_declare_no_server_action(self):
        for name, _parameters, view in _server_routes():
            if name in _HANDLER_GATE:
                with self.subTest(route=name):
                    self.assertFalse(hasattr(view, "server_action"))


class RefusalRuleRouteTest(TestCase):
    """Each Server route gives the reply of the refusal rule to each kind of user, through the real permissions."""

    def setUp(self):
        self.server = _make_db_server(name="gated")
        other = _make_db_server(name="other")
        self.users = {"none": User.objects.create_user("no-permission")}
        for kind in ("viewer", "constrained", "changer"):
            self.users[kind] = User.objects.create_user(kind)
            _grant([Server], ["view"], user=self.users[kind])
        _grant([Server], ["change", "delete"], user=self.users["constrained"], constraints={"pk": other.pk})
        _grant([Server], ["change", "delete"], user=self.users["changer"])

    def _request(self, name: str, parameters: tuple[str, ...], view: type):
        url = _url(_NAMESPACE + name, parameters, pk=self.server.pk)
        # A POST-only gated view answers a GET after the gate with 405, so no handler runs.
        if name in _POST_ONLY:
            return self.client.post(url)
        return self.client.get(url)

    def _assert_reply(self, response, expected: str) -> None:
        login = response.status_code == 302 and response.url.startswith(settings.LOGIN_URL)
        refused = response.status_code == 403 and response.content.decode() == _CHANGE_REFUSED
        if expected == "login":
            self.assertTrue(login, f"{response.status_code} is not the login redirect")
        elif expected == "404":
            self.assertEqual(response.status_code, 404)
        elif expected == "403":
            self.assertTrue(refused, f"{response.status_code} is not the change refusal")
        else:
            self.assertFalse(
                login or refused or response.status_code == 404, f"the gate refused: {response.status_code}"
            )

    def test_each_route_gives_the_reply_of_the_refusal_rule(self):
        checked = set()
        with stub_kea(_KEA_DOWN):
            for name, parameters, view in _server_routes():
                action = _HANDLER_GATE.get(name) or view.server_action
                expected = {
                    None: "login",
                    "none": "404",
                    "viewer": "pass" if action == "view" else "403",
                    "constrained": "pass" if action == "view" else "403",
                    "changer": "pass",
                }
                for kind, reply in expected.items():
                    with self.subTest(route=name, user=kind):
                        self.client.logout()
                        if kind is not None:
                            self.client.force_login(self.users[kind])
                        self._assert_reply(self._request(name, parameters, view), reply)
                        checked.add((name, expected["viewer"]))
        self.assertTrue(
            {
                ("server_sync_now", "403"),
                ("server_leases", "pass"),
                ("server_subnet_edit", "403"),
                ("server_edit", "403"),
                ("server_delete", "403"),
                ("server_switch", "pass"),
            }
            <= checked
        )


class ServerLoadCountTest(_AccessTestCase):
    """A change view loads its Server once: the gate's load serves every later read of the request."""

    def test_a_post_to_a_change_view_loads_the_server_once(self):
        _grant([Server], ["change"], user=self.user)
        url = reverse(
            "plugins:netbox_kea:server_option_def_delete",
            kwargs={"pk": self.server.pk, "family": 4, "code": 222, "space": "dhcp4"},
        )
        with stub_kea(_KEA_DOWN), CaptureQueriesContext(connection) as queries:
            response = self.client.post(url)

        self.assertEqual(response.status_code, 302)
        loads = [query["sql"] for query in queries.captured_queries if 'FROM "netbox_kea_server"' in query["sql"]]
        self.assertEqual(len(loads), 1, loads)


class SwitchFromDisabledFamilyTest(TestCase):
    """The Server switch leaves its Server, so the disabled family of that Server does not stop it."""

    def test_a_switch_from_a_disabled_family_page_opens_the_target(self):
        source = _make_db_server(name="six-only", dhcp4=False, dhcp6=True)
        target = _make_db_server(name="four-only", dhcp4=True, dhcp6=False)
        user = User.objects.create_user("switcher")
        _grant([Server], ["view"], user=user)
        self.client.force_login(user)

        with stub_kea({}) as kea:
            response = self.client.get(
                reverse("plugins:netbox_kea:server_switch", args=[source.pk]),
                {"target": target.pk, "section": "leases", "family": "4"},
            )

        self.assertRedirects(
            response,
            reverse("plugins:netbox_kea:server_leases", kwargs={"pk": target.pk, "family": 4}),
            fetch_redirect_response=False,
        )
        self.assertEqual(kea.commands(), [])


class LinksNeedViewAndChangeTest(TestCase):
    """A Create Reservation link names only a Server that the user may view and change, as the gate needs."""

    def setUp(self):
        self.viewed = _make_db_server(name="viewed-only")
        self.changed = _make_db_server(name="changed-only")
        self.user = User.objects.create_user("split-grants")
        _grant([IPAddress], ["view"], user=self.user)
        _grant([Server], ["view"], user=self.user, constraints={"pk": self.viewed.pk})
        _grant([Server], ["change"], user=self.user, constraints={"pk": self.changed.pk})
        self.client.force_login(self.user)
        self.ip = IPAddress.objects.create(address=IPNetwork("192.0.2.10/24"))

    def test_neither_page_links_a_server_that_the_user_may_not_view(self):
        for page in (
            reverse("ipam:ipaddress", args=[self.ip.pk]),
            reverse("plugins:netbox_kea:ipaddress_kea_reservations", args=[self.ip.pk]),
        ):
            with self.subTest(page=page):
                response = self.client.get(page)
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, self.changed.name)
                self.assertNotContains(
                    response,
                    reverse("plugins:netbox_kea:server_reservation_add", kwargs={"pk": self.changed.pk, "family": 4}),
                )


class DhcpPluginSyncRefusalTest(_AccessTestCase):
    """The DHCP plugin page names the one change refusal for a viewer."""

    def test_the_page_names_the_change_refusal(self):
        response = self.client.get(reverse("plugins:netbox_kea:server_dhcp_plugin", args=[self.server.pk]))

        self.assertEqual(response.context["sync_refusal"], _CHANGE_REFUSED)


class ServerEditAndDeleteRefusalTest(_AccessTestCase):
    """NetBox's Server edit and delete views on a pk follow the refusal rule of the gate."""

    def _urls(self, server: Server) -> dict[str, str]:
        return {
            action: reverse(f"plugins:netbox_kea:server_{action}", args=[server.pk]) for action in ("edit", "delete")
        }

    def test_a_viewer_with_grants_constrained_to_another_server_gets_403(self):
        for action, url in self._urls(self.server).items():
            with self.subTest(action=action):
                self.assertContains(self.client.get(url), _CHANGE_REFUSED, status_code=403)
                self.assertContains(self.client.post(url, {"confirm": True}), _CHANGE_REFUSED, status_code=403)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())

    def test_a_server_that_the_user_may_not_view_is_404(self):
        hidden = User.objects.create_user("no-view")
        _grant([Server], ["change", "delete"], user=hidden)
        self.client.force_login(hidden)
        for action, url in self._urls(self.server).items():
            with self.subTest(action=action):
                self.assertEqual(self.client.get(url).status_code, 404)

    def test_the_server_that_the_grants_name_opens_and_the_add_form_keeps_its_rule(self):
        with stub_kea(_KEA_DOWN):
            for action, url in self._urls(self.other).items():
                with self.subTest(action=action):
                    self.assertEqual(self.client.get(url).status_code, 200)
            self.assertEqual(self.client.get(reverse("plugins:netbox_kea:server_add")).status_code, 403)
