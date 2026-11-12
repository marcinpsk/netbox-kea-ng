# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The one Server access gate of the Server views, the permitted Servers, and a combined page's Server Scope.

Only this module reads the Server permissions of a user (OpenGrep ``kea-server-permission-outside-server-scope``).
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from typing import Any, ClassVar, Literal, cast

from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.db.models import QuerySet
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseForbidden, QueryDict
from django.shortcuts import render

from ..constants import Family, validate_family
from ..decimal_text import parse_decimal
from ..models import Server

#: The Server selector always submits this field, so a selection with no Server checked stays explicit.
SELECTION_FIELD = "server_selection"


class ServerScopeKind(Enum):
    """The four possible results of a Server selection."""

    ALL = "all"
    SELECTION = "selection"
    ONE = "one"
    INVALID = "invalid"


@dataclass(frozen=True)
class ServerScope:
    """The permitted Server choices, resolved selection, and family availability of one request."""

    kind: ServerScopeKind
    all_servers: tuple[Server, ...]
    servers: tuple[Server, ...]
    missing_family: tuple[Server, ...]
    selected_pks: frozenset[int]
    server_qs: str

    @property
    def is_all(self) -> bool:
        """Return whether the request covers all permitted Servers."""
        return self.kind is ServerScopeKind.ALL

    @property
    def is_one(self) -> bool:
        """Return whether the request selects exactly one permitted Server."""
        return self.kind is ServerScopeKind.ONE

    @property
    def is_invalid(self) -> bool:
        """Return whether any selected ID is invalid, unknown, or inaccessible."""
        return self.kind is ServerScopeKind.INVALID

    @property
    def query_servers(self) -> list[Server]:
        """Return the Servers in the Server Scope that serve the requested family."""
        return [server for server in self.servers if server not in self.missing_family]


def resolve(request: HttpRequest, family: Family | None) -> ServerScope:
    """Resolve repeated Server IDs against view permissions; one bad value invalidates the selection."""
    permitted = tuple(permitted_servers(request.user).order_by("name"))
    selection = QueryDict(mutable=True)
    selection.setlist("server", request.GET.getlist("server"))
    selected: set[int] = set()
    kind = ServerScopeKind.ALL
    servers = permitted
    if "server" in request.GET or SELECTION_FIELD in request.GET:
        try:
            selected = {parse_decimal(value) for value in request.GET.getlist("server")}
        except ValueError:
            kind = ServerScopeKind.INVALID
        else:
            permitted_pks = {server.pk for server in permitted}
            kind = (
                ServerScopeKind.INVALID if not selected or not selected <= permitted_pks else ServerScopeKind.SELECTION
            )
        if kind is ServerScopeKind.INVALID:
            servers = ()
            selected = set()
            if SELECTION_FIELD in request.GET:
                selection[SELECTION_FIELD] = "1"
        else:
            servers = tuple(server for server in permitted if server.pk in selected)
            selection.setlist("server", [str(pk) for pk in sorted(selected)])
            if len(servers) == 1:
                kind = ServerScopeKind.ONE
    missing = tuple(
        server for server in servers if family is not None and not (server.dhcp4 if family == 4 else server.dhcp6)
    )
    return ServerScope(kind, permitted, servers, missing, frozenset(selected), selection.urlencode())


def writable_servers(user: Any, servers: Iterable[Server]) -> frozenset[int]:
    """Return the pks of the *servers* that *user* may change, with one query for every Server of a page."""
    pks = [server.pk for server in servers]
    return frozenset(permitted_servers(user, "change").filter(pk__in=pks).values_list("pk", flat=True))


#: The action that a Server view needs on its Server. Each action but view needs view too.
ServerAction = Literal["view", "change", "delete"]

#: The one refusal of a viewable Server that the user may not change.
CHANGE_REFUSED = "You do not have permission to modify Kea server data."

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def permitted_servers(user: Any, action: ServerAction = "view") -> QuerySet[Server]:
    """Return the Servers that *user* may view and, for another *action*, may also take that action on."""
    viewable = Server.objects.restrict(user, "view")
    return viewable if action == "view" else viewable.filter(pk__in=Server.objects.restrict(user, action))


class ServerAccess:
    """The Server of one request and what its user may do with it, each permission read at most once."""

    def __init__(self, user: Any, server: Server, action: ServerAction = "view") -> None:
        self.user = user
        self.server = server
        # The gate loaded the Server with the permission of its action.
        if action == "change":
            self.can_change = True
        if action == "delete":
            self.can_delete = True

    @cached_property
    def can_change(self) -> bool:
        """Return whether the user may change the Server."""
        return permitted_servers(self.user, "change").filter(pk=self.server.pk).exists()

    @cached_property
    def can_delete(self) -> bool:
        """Return whether the user may delete the Server."""
        return permitted_servers(self.user, "delete").filter(pk=self.server.pk).exists()

    def permitted_actions(self, actions: Iterable[Any]) -> list[Any]:
        """Keep the NetBox object *actions* whose change or delete permission the user holds on this Server.

        NetBox checks the model permissions of *actions*; this checks the object. A NetBox 4.3 action is a string.
        """
        held = {"change": lambda: self.can_change, "delete": lambda: self.can_delete}
        return [
            action
            for action in actions
            if all(held[name]() for name in getattr(action, "permissions_required", ()) if name in held)
        ]


class GatedRequest(HttpRequest):
    """The request of a Server view that passed the gate, with the access result of its Server."""

    server_access: ServerAccess


def request_access(request: HttpRequest, server: Server) -> ServerAccess:
    """Return the access result of *server* that the gate stored on *request*, or a new one.

    NetBox's own Server tabs, such as the Journal and the Changelog, do not pass the gate.
    """
    access = getattr(request, "server_access", None)
    if isinstance(access, ServerAccess) and access.server.pk == server.pk:
        return access
    return ServerAccess(request.user, server)


def _login_refusal(request: HttpRequest) -> HttpResponse | None:
    if not request.user.is_authenticated and settings.LOGIN_REQUIRED:
        return redirect_to_login(request.get_full_path())
    return None


def server_access(request: HttpRequest, pk: int, action: ServerAction) -> ServerAccess | HttpResponse:
    """Load the Server *pk* once for *action*, or return the refusal rule's reply (ADR 0016).

    An anonymous user gets the login redirect; a Server that the user may not view is 404; a viewable Server that
    the user may not change or delete is 403 for that action.
    """
    if refusal := _login_refusal(request):
        return refusal
    server = permitted_servers(request.user, action).filter(pk=pk).first()
    if server is not None:
        return ServerAccess(request.user, server, action)
    if not request.user.is_authenticated:
        return redirect_to_login(request.get_full_path())
    if action != "view" and permitted_servers(request.user).filter(pk=pk).exists():
        return HttpResponseForbidden(CHANGE_REFUSED)
    raise Http404


def selected_family(request: HttpRequest, server: Server) -> Family:
    """Read the family route parameter, or the explicit selection on a Server page without one."""
    match = request.resolver_match
    if match is not None and "family" in match.kwargs:
        return validate_family(match.kwargs["family"])
    selected = request.GET.get("family")
    if selected in ("4", "6"):
        return 4 if selected == "4" else 6
    return 4 if server.dhcp4 else 6


class ServerAccessMixin:
    """The gate of a Server view: it loads the Server of the route once, then refuses a disabled family.

    A view names the action of its handlers in ``server_action``. The handlers read ``self.server``, and
    ``self.access.can_change`` when they offer changes.
    """

    server_action: ClassVar[ServerAction]
    workspace_section = "overview"
    server: Server
    access: ServerAccess

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Apply the refusal rule and the disabled-family state before the handler runs."""
        if refusal := _login_refusal(request):
            return refusal
        if request.method not in SAFE_METHODS and (refusal := self.server_scope_access(request)):
            return refusal
        access = server_access(request, kwargs["pk"], self.server_action)
        if isinstance(access, HttpResponse):
            return access
        self.access = cast(GatedRequest, request).server_access = access
        self.server = server = access.server
        if not (server.dhcp4 if selected_family(request, server) == 4 else server.dhcp6):
            if request.method not in SAFE_METHODS and (refusal := self.disabled_family_access(request, server)):
                return refusal
            if request.headers.get("HX-Request") == "true":
                response = HttpResponse()
                response["HX-Refresh"] = "true"
                return response
            return render(request, "netbox_kea/server_protocol_disabled.html", {"object": server})
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]

    def get_object(self, **kwargs: Any) -> Server:
        """Return the Server that the gate loaded, so a NetBox handler does not load it again."""
        return self.server

    def get_permitted_actions(self, user: Any, model: Any = None) -> list[Any]:
        """Keep the NetBox actions that the user may take on this Server, not only on the model."""
        return self.access.permitted_actions(super().get_permitted_actions(user, model=model))  # type: ignore[misc]

    def server_scope_access(self, request: HttpRequest) -> HttpResponse | None:
        """Keep object-independent action refusals before the Server lookup."""
        return None

    def disabled_family_access(self, request: HttpRequest, server: Server) -> HttpResponse | None:
        """Keep an action's extra permission refusal before the disabled state."""
        return None
