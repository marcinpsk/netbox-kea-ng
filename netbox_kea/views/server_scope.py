# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Resolve a combined page's Server Scope without broadening an explicit selection."""

from dataclasses import dataclass
from enum import Enum

from django.http import HttpRequest, QueryDict

from ..constants import Family
from ..decimal_text import parse_decimal
from ..models import Server


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
    all_servers_url: str

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
    permitted = tuple(Server.objects.restrict(request.user, "view").order_by("name"))
    query = request.GET.copy()
    query.pop("server", None)
    all_url = request.path + (f"?{query.urlencode()}" if query else "")
    selection = QueryDict(mutable=True)
    selection.setlist("server", request.GET.getlist("server"))
    selected: set[int] = set()
    kind = ServerScopeKind.ALL
    servers = permitted
    if "server" in request.GET:
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
        else:
            servers = tuple(server for server in permitted if server.pk in selected)
            selection.setlist("server", [str(pk) for pk in sorted(selected)])
            if len(servers) == 1:
                kind = ServerScopeKind.ONE
    missing = tuple(
        server for server in servers if family is not None and not (server.dhcp4 if family == 4 else server.dhcp6)
    )
    return ServerScope(kind, permitted, servers, missing, frozenset(selected), selection.urlencode(), all_url)
