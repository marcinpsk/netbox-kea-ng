# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Resolve a combined page's Server Scope without broadening an explicit selection."""

from dataclasses import dataclass
from typing import Literal

from django.http import HttpRequest, QueryDict

from ..constants import Family
from ..decimal_text import parse_decimal
from ..models import Server


@dataclass(frozen=True)
class ScopeResolution:
    """The permitted Server choices, resolved selection, and family availability of one request."""

    kind: Literal["all", "selection", "one", "invalid"]
    all_servers: tuple[Server, ...]
    servers: tuple[Server, ...]
    missing_family: tuple[Server, ...]
    selected_pks: frozenset[int]
    server_qs: str
    all_servers_url: str

    @property
    def query_servers(self) -> list[Server]:
        """Return only the scoped Servers that serve the requested family."""
        return [server for server in self.servers if server not in self.missing_family]


def resolve(request: HttpRequest, family: Family | None) -> ScopeResolution:
    """Resolve repeated Server IDs against view permissions; one bad value invalidates the selection."""
    permitted = tuple(Server.objects.restrict(request.user, "view").order_by("name"))
    query = request.GET.copy()
    query.pop("server", None)
    all_url = request.path + (f"?{query.urlencode()}" if query else "")
    selection = QueryDict(mutable=True)
    selection.setlist("server", request.GET.getlist("server"))
    selected: set[int] = set()
    kind: Literal["all", "selection", "one", "invalid"] = "all"
    servers = permitted
    if "server" in request.GET:
        try:
            selected = {parse_decimal(value) for value in request.GET.getlist("server")}
        except ValueError:
            kind = "invalid"
        else:
            permitted_pks = {server.pk for server in permitted}
            kind = "invalid" if not selected or not selected <= permitted_pks else "selection"
        if kind == "invalid":
            servers = ()
            selected = set()
        else:
            servers = tuple(server for server in permitted if server.pk in selected)
            if len(servers) == 1:
                kind = "one"
    missing = tuple(
        server for server in servers if family is not None and not (server.dhcp4 if family == 4 else server.dhcp6)
    )
    return ScopeResolution(kind, permitted, servers, missing, frozenset(selected), selection.urlencode(), all_url)
