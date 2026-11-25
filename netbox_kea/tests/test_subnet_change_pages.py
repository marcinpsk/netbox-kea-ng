# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A Subnet change page opens only when its write can run (#317).

Each page runs the prepare read of its ``config_write`` operation. A refusal sends the operator back to the Subnets
list with the reason that the write gives for the same Kea state.
"""

from dataclasses import dataclass, field
from typing import Any

from bs4 import BeautifulSoup
from django.contrib import messages as django_messages
from django.contrib.messages import get_messages
from django.urls import reverse

from netbox_kea import display_cache, server_configuration, subnet_catalogue
from netbox_kea.read_failure import client_settings_message

from .kea_stub import SubnetDaemon, _catalogue_responses_for_subnets, _res_page, _subnet_list, stub_kea
from .utils import _make_db_server, _page_data, _ViewTestBase, invalid_server_settings

_SEEN = "10.0.0.0/24"
_POOL = "10.0.0.10-10.0.0.20"
_NEW_POOL = "10.0.0.100-10.0.0.110"
_NOT_SENT = "The change was not sent to Kea."
_UNSUPPORTED = {"result": 2, "text": "'subnet4-list' command not supported."}
_NO_SUBNET_CMDS = (
    "NetBox could not confirm Kea's Subnet list, because the subnet_cmds hook library is not loaded, so it did not "
    "send the change."
)
_UNCONFIRMED = "NetBox could not confirm Kea's Subnet list, so it did not send the change. Try again later."
_GONE = "Subnet 1 changed in Kea. Reload the page and try again."


@dataclass(frozen=True)
class _Page:
    """One Subnet change page: its route, the data that its form posts, and the Kea command of its write."""

    name: str
    route: str
    post: dict[str, str]
    write: str
    pool: str | None = None

    def url(self, server_pk: int) -> str:
        kwargs: dict[str, Any] = {"pk": server_pk, "family": 4, "subnet_id": 1}
        if self.pool is not None:
            kwargs["pool"] = self.pool
        return reverse(f"plugins:netbox_kea:{self.route}", kwargs=kwargs)


_EDIT = _Page(
    "edit",
    "server_subnet_edit",
    {"subnet_cidr": _SEEN, "original_network": "", "shared_networks_complete": "True"},
    "subnet4-update",
)
_PAGES = (
    _EDIT,
    _Page("delete", "server_subnet_delete", {"subnet_cidr": _SEEN}, "subnet4-del"),
    _Page("pool add", "server_subnet_pool_add", {"subnet_cidr": _SEEN, "pool": _NEW_POOL}, "subnet4-delta-add"),
    _Page("pool delete", "server_subnet_pool_delete", {"subnet_cidr": _SEEN}, "subnet4-delta-del", pool=_POOL),
    _Page(
        "options",
        "server_subnet_options_edit",
        {
            "subnet_cidr": _SEEN,
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "0",
            "form-MIN_NUM_FORMS": "0",
            "form-MAX_NUM_FORMS": "1000",
            "form-0-name": "routers",
            "form-0-data": "10.0.0.1",
        },
        "config-set",
    ),
)


_OPTIONS = tuple(page for page in _PAGES if page.name == "options")
_UNSAFE = "Kea returned a configuration that NetBox cannot edit safely."
_INVALID_OPTION: dict[str, Any] = {"option-data": [{}]}


def _subnet(cidr: str = _SEEN, pools: tuple[str, ...] = (_POOL,), **keys: Any) -> dict[str, Any]:
    return {"id": 1, "subnet": cidr, "pools": [{"pool": pool} for pool in pools], **keys}


def _kea(subnets: tuple[dict[str, Any], ...] = (_subnet(),), /, **overrides: Any) -> dict[str, Any]:
    """Return the responses of a daemon that holds *subnets*, with *overrides* for single commands."""
    return {**SubnetDaemon(4, subnets).responses(), **overrides}


@dataclass(frozen=True)
class _Refusal:
    """One Kea state, the pages that it refuses, and the reason that the page and the write give."""

    name: str
    responses: dict[str, Any]
    reason: str
    pages: tuple[_Page, ...] = field(default=_PAGES)


_REFUSALS = (
    _Refusal(
        "no subnet_cmds hook",
        _kea(**{"subnet4-list": _UNSUPPORTED, "subnet4-get": {**_UNSUPPORTED, "text": "not supported"}}),
        _NO_SUBNET_CMDS,
    ),
    _Refusal("ID gone", _kea(()), _GONE),
    _Refusal(
        "unconfirmed membership",
        # The list has no shared-network-name and config-get fails, so no source shows the membership.
        _kea(
            **{
                "subnet4-list": _subnet_list(4, [{"id": 1, "subnet": _SEEN}]),
                "config-get": {"result": 1, "text": "configuration unavailable"},
            }
        ),
        _UNCONFIRMED,
        pages=(_EDIT,),
    ),
    _Refusal(
        "invalid Option Definition",
        {
            **_kea(),
            "config-get": _catalogue_responses_for_subnets(4, [_subnet()], option_definitions=({},))["config-get"],
        },
        _UNSAFE,
        pages=_OPTIONS,
    ),
    _Refusal("invalid target DHCP Option", _kea((_subnet(**_INVALID_OPTION),)), _UNSAFE, pages=_OPTIONS),
    _Refusal(
        "missing Pool",
        _kea((_subnet(pools=()),)),
        f"Subnet 1 ({_SEEN}) has no Pool {_POOL}. Reload the page and try again.",
        pages=tuple(page for page in _PAGES if page.name == "pool delete"),
    ),
)


def _posted(form) -> dict[str, str]:
    """Return the data that a browser posts for the unbound *form*: each value that the page shows."""
    data = {}
    for bound in form:
        value = bound.value()
        if value is None or value is False:
            continue
        data[bound.html_name] = "True" if value is True else str(value)
    return data


def _browser_data(response) -> dict[str, str]:
    """Return the data that a browser posts for the form of *response*: a disabled field posts nothing."""
    form = response.context["form"]
    return {name: value for name, value in _page_data(response).items() if not form.fields[name].disabled}


def _selected(response) -> str:
    """Return the Shared Network that the selector of *response* posts: the selected option, else the first one."""
    select = BeautifulSoup(response.content, "html.parser").select_one("select[name=shared_network]")
    option = select.select_one("option[selected]") or select.select_one("option")
    return option["value"]


class _PageClient(_ViewTestBase):
    def _errors(self, response) -> list[str]:
        return [str(m) for m in get_messages(response.wsgi_request) if m.level == django_messages.ERROR]

    def _subnets_url(self) -> str:
        return reverse("plugins:netbox_kea:server_subnets", kwargs={"pk": self.server.pk, "family": 4})

    def _get(self, page: _Page, responses: dict[str, Any]):
        self._fresh_client()
        with stub_kea(responses) as kea:
            response = self.client.get(page.url(self.server.pk))
        return response, kea

    def _post(self, page: _Page, responses: dict[str, Any]):
        self._fresh_client()
        with stub_kea(responses) as kea:
            response = self.client.post(page.url(self.server.pk), page.post)
        return response, kea


class TestChangePagesWithoutTheSubnetCmdsHook(_PageClient):
    def test_the_edit_and_delete_pages_do_not_open(self):
        """Every save of these forms is refused without the hook, so the page does not open."""
        responses = _kea(**{"subnet4-list": _UNSUPPORTED, "subnet4-get": _UNSUPPORTED})
        for page in (page for page in _PAGES if page.name in ("edit", "delete")):
            with self.subTest(page.name):
                response, _kea_stub = self._get(page, responses)
                self.assertRedirects(response, self._subnets_url(), fetch_redirect_response=False)
                self.assertEqual(self._errors(response), [_NO_SUBNET_CMDS])


class TestEditPageWithUnconfirmedMembership(_PageClient):
    def test_the_edit_page_does_not_open(self):
        """The write refuses a membership that it cannot confirm, so the page does not open with a warning."""
        (refusal,) = (refusal for refusal in _REFUSALS if refusal.name == "unconfirmed membership")
        response, kea = self._get(_EDIT, refusal.responses)
        self.assertRedirects(response, self._subnets_url(), fetch_redirect_response=False)
        self.assertEqual(self._errors(response), [_UNCONFIRMED])
        self.assertNotIn("subnet4-get", kea.commands())


class TestPageAndWriteGiveOneReason(_PageClient):
    """For each page and each refusal, the GET refuses and the POST refuses with the same reason."""

    def test_the_get_and_the_post_refuse_with_the_same_reason(self):
        for refusal in _REFUSALS:
            for page in refusal.pages:
                with self.subTest(refusal.name, page=page.name):
                    response, kea = self._get(page, refusal.responses)
                    self.assertRedirects(response, self._subnets_url(), fetch_redirect_response=False)
                    self.assertEqual(self._errors(response), [refusal.reason])
                    response, kea = self._post(page, refusal.responses)
                    # The edit form shows the input again after a refusal; the other pages go back to the list.
                    self.assertEqual(response.status_code, 200 if page is _EDIT else 302)
                    # The edit form shown again adds the Notice of its display configuration.
                    self.assertEqual(self._errors(response)[0], f"{_NOT_SENT} {refusal.reason}")
                    self.assertNotIn(page.write, kea.commands())

    def test_invalid_client_settings_refuse_the_get_and_the_post_with_the_same_reason(self):
        bad = _make_db_server(name="bad-client", client_cert_path="/nonexistent/cert.pem")
        reason = client_settings_message(bad)
        for page in _PAGES:
            with self.subTest(page.name):
                self._fresh_client()
                url = page.url(bad.pk)
                with stub_kea(_kea()) as kea:
                    response = self.client.get(url)
                    self.assertRedirects(
                        response,
                        reverse("plugins:netbox_kea:server_subnets", kwargs={"pk": bad.pk, "family": 4}),
                        fetch_redirect_response=False,
                    )
                    self.assertEqual(self._errors(response), [reason])
                    self._fresh_client()
                    response = self.client.post(url, page.post)
                self.assertEqual(self._errors(response)[0], invalid_server_settings(bad))
                self.assertEqual(kea.commands(), [])

    def test_an_id_that_names_another_cidr_opens_on_that_cidr_and_refuses_the_cidr_that_the_page_showed(self):
        """A page shows the CIDR that Kea holds now. A save from a page that showed another CIDR is refused."""
        responses = _kea((_subnet("10.0.0.0/25"),))
        for page in _PAGES:
            with self.subTest(page.name):
                response, _ = self._get(page, responses)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'name="subnet_cidr" value="10.0.0.0/25"')
                response, kea = self._post(page, responses)
                self.assertEqual(
                    self._errors(response),
                    [f"{_NOT_SENT} Subnet 1 ({_SEEN}) changed in Kea. Reload the page and try again."],
                )
                self.assertNotIn(page.write, kea.commands())


class TestEditPageShowsTheSubnetGetEntry(_PageClient):
    def test_the_form_shows_the_subnet_get_values_and_an_unchanged_save_applies(self):
        """The stale-value check of the write reads subnet4-get, so the form shows the values of that entry."""
        daemon = SubnetDaemon(4, [_subnet(**{"valid-lifetime": 7200})])
        listed = _kea((_subnet(**{"valid-lifetime": 3600}),))
        responses = {**daemon.responses(), "config-get": listed["config-get"]}
        response, _ = self._get(_EDIT, responses)
        self.assertEqual(response.status_code, 200)
        form = response.context["form"]
        self.assertEqual(form.initial["valid_lft"], 7200)
        self._fresh_client()
        with stub_kea(responses) as kea:
            response = self.client.post(_EDIT.url(self.server.pk), _posted(form))
        self.assertEqual(response.status_code, 302)
        self.assertEqual([str(m) for m in get_messages(response.wsgi_request)], [f"Subnet 1 ({_SEEN}) updated."])
        self.assertIn("subnet4-update", kea.commands())


class TestEditPageHintsComeFromTheDisplayConfiguration(_PageClient):
    """The Shared Network choices and the inherited options are display data, on the GET and on the re-render."""

    def _warm(self) -> dict[str, Any]:
        """Fill the display cache from a daemon with Shared Network 'cached-net' and a global DNS server."""
        cached = SubnetDaemon(4, [_subnet()], networks=("cached-net",)).responses()
        config = cached["config-get"]({})
        config["arguments"]["Dhcp4"]["option-data"] = [{"name": "domain-name-servers", "data": "192.0.2.53"}]
        with stub_kea({**cached, "config-get": config}):
            server_configuration.display(self.server, 4)
        return SubnetDaemon(4, [_subnet()], networks=("live-net",)).responses()

    def _assert_display_hints(self, response) -> None:
        options = [
            option["value"]
            for option in BeautifulSoup(response.content, "html.parser").select("select[name=shared_network] option")
        ]
        self.assertIn("cached-net", options)
        self.assertNotIn("live-net", options)
        self.assertEqual(response.context["inherited_options"]["dns_servers"]["value"], "192.0.2.53")

    def test_the_get_reads_the_hints_from_the_display_configuration(self):
        live = self._warm()
        response, _ = self._get(_EDIT, live)
        self.assertEqual(response.status_code, 200)
        self._assert_display_hints(response)

    def test_the_post_re_render_reads_the_hints_from_the_display_configuration(self):
        live = self._warm()
        self._fresh_client()
        with stub_kea(live):
            response = self.client.post(_EDIT.url(self.server.pk), {**_EDIT.post, "gateway": "not-an-address"})
        self.assertEqual(response.status_code, 200)
        self._assert_display_hints(response)


class TestChangePageOpenRotatesNothing(_PageClient):
    def test_the_cached_display_entries_of_the_family_stay(self):
        responses = _kea()
        with stub_kea(responses):
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
        for page in _PAGES:
            with self.subTest(page.name):
                response, _ = self._get(page, responses)
                self.assertEqual(response.status_code, 200)
        with stub_kea(responses) as kea:
            subnet_catalogue.display(self.server, 4)
            server_configuration.display(self.server, 4)
        self.assertEqual(kea.commands(), [])


_NETWORKS_NOT_LOADED = (
    "NetBox could not load the Shared Networks from Kea, so the Subnet form cannot be saved. "
    "Reload the page and try again."
)


class TestEditPageNeedsTheSharedNetworkList(_PageClient):
    """A page without the Shared Network list offers only the held choice, and the edit page does not open without it."""

    _FAILED = {"result": 1, "text": "config-get failed"}

    @staticmethod
    def _daemon() -> SubnetDaemon:
        # The Subnet list names the Shared Network 'alpha' of Subnet 1, so the prepare read confirms the membership.
        return SubnetDaemon(4, [_subnet()], networks=("alpha", "beta"), members={1: "alpha"})

    def test_the_get_does_not_open_when_the_display_configuration_has_no_shared_network_list(self):
        daemon = self._daemon()
        daemon.script("config-get", self._FAILED, self._FAILED)
        response, kea = self._get(_EDIT, daemon.responses())
        self.assertRedirects(response, self._subnets_url(), fetch_redirect_response=False)
        self.assertIn(_NETWORKS_NOT_LOADED, self._errors(response))
        self.assertIn("subnet4-get", kea.commands())

    def _save_through_an_unavailable_list(self, daemon: SubnetDaemon, choice: str):
        """Choose *choice*, then save through two forms shown again without the list and one after it is back."""
        url = _EDIT.url(self.server.pk)
        with stub_kea(daemon.responses()) as kea:
            page = self.client.get(url)
            self.assertEqual(page.status_code, 200)
            # The display configuration is gone for the next two forms shown again.
            display_cache.rotate_configuration(self.server, 4)
            daemon.script("config-get", self._FAILED, self._FAILED)
            shown = self.client.post(
                url, {**_browser_data(page), "shared_network": choice, "gateway": "not-an-address"}
            )
            self.assertEqual(_selected(shown), choice)
            shown = self.client.post(url, {**_browser_data(shown), "gateway": ""})
            self.assertContains(shown, _NETWORKS_NOT_LOADED)
            self.assertEqual(_selected(shown), choice)
            # The display configuration is back. The form posted without the list is refused once more.
            shown = self.client.post(url, _browser_data(shown))
            self.assertContains(shown, _NETWORKS_NOT_LOADED)
            self.assertEqual(_selected(shown), choice)
            self.assertNotIn("subnet4-update", kea.commands())
            saved = self.client.post(url, _browser_data(shown))
        self.assertEqual(saved.status_code, 302)
        return kea.commands()

    def test_a_save_without_the_list_never_takes_the_subnet_out_of_its_shared_network(self):
        """The selector posts the Shared Network that the form holds, so the Subnet stays in it."""
        daemon = self._daemon()
        commands = self._save_through_an_unavailable_list(daemon, "alpha")
        self.assertIn("subnet4-update", commands)
        self.assertNotIn("network4-subnet-del", commands)
        self.assertEqual(daemon.members, {1: "alpha"})

    def test_the_choice_of_the_operator_survives_a_form_shown_again_without_the_list(self):
        """An explicit choice, the global pool included, is what the save sends."""
        for choice, members in (("", {}), ("beta", {1: "beta"})):
            with self.subTest(choice=choice):
                self._fresh_client()
                daemon = self._daemon()
                commands = self._save_through_an_unavailable_list(daemon, choice)
                self.assertIn("network4-subnet-del", commands)
                self.assertEqual(daemon.members, members)


class TestPoolAddWarningReadsTheCatalogueAfterTheWrite(_PageClient):
    def test_a_subnet_that_the_display_did_not_hold_still_gets_its_reservation_warning(self):
        """The write checks the Subnet live, so the warning reads the Catalogue again after the write."""
        subnet = {"id": 1, "subnet": "198.18.0.0/24"}
        with stub_kea(_catalogue_responses_for_subnets(4, [])):
            subnet_catalogue.display(self.server, 4)
        # Another tool added Subnet 1 and its Reservation after the display cache was filled.
        responses = {
            **_catalogue_responses_for_subnets(4, [subnet]),
            "subnet4-delta-add": {"result": 0},
            "config-test": {"result": 0},
            "config-write": {"result": 0},
            "reservation-get-page": _res_page(
                [{"subnet-id": 1, "hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "198.18.0.15"}]
            ),
        }
        url = reverse(
            "plugins:netbox_kea:server_subnet_pool_add", kwargs={"pk": self.server.pk, "family": 4, "subnet_id": 1}
        )
        with stub_kea(responses) as kea:
            response = self.client.post(url, {"subnet_cidr": "198.18.0.0/24", "pool": "198.18.0.10-198.18.0.20"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("subnet4-delta-add", kea.commands())
        warnings = [str(m) for m in get_messages(response.wsgi_request) if m.level == django_messages.WARNING]
        self.assertEqual(
            warnings,
            [
                (
                    "Pool 198.18.0.10-198.18.0.20 overlaps 1 existing reservation(s): 198.18.0.15. "
                    "Kea allows this. Reservations take priority over pool allocation."
                )
            ],
        )


class TestPrepareReadIsLive(_PageClient):
    def test_the_pool_delete_page_reads_kea_live_and_leaves_the_display_cache(self):
        """The display cache still holds the Pool, the live read does not, so the page refuses and the cache stays."""
        (pool_delete,) = (page for page in _PAGES if page.name == "pool delete")
        with stub_kea(_kea()):
            subnet_catalogue.display(self.server, 4)
        response, kea = self._get(pool_delete, _kea((_subnet(pools=()),)))
        self.assertRedirects(response, self._subnets_url(), fetch_redirect_response=False)
        self.assertEqual(
            self._errors(response), [f"Subnet 1 ({_SEEN}) has no Pool {_POOL}. Reload the page and try again."]
        )
        self.assertEqual(kea.commands(), ["subnet4-list", "config-get"])
        with stub_kea(_kea((_subnet(pools=()),))) as kea:
            cached = subnet_catalogue.display(self.server, 4)
        self.assertEqual(kea.commands(), [])
        (subnet,) = cached.subnets
        self.assertEqual([pool.range for pool in subnet.configuration.pools], [_POOL])
