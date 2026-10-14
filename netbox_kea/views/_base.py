# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar, cast
from urllib.parse import parse_qsl, unquote, urlparse, urlsplit
from urllib.parse import urlencode as _urlencode

import requests
from django.contrib import messages
from django.contrib.auth.models import PermissionsMixin
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.http.request import HttpRequest
from django.urls import Resolver404, get_script_prefix, resolve, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from netbox.tables import BaseTable

from .. import display_cache
from ..config_write import ConfigChangeOutcome, ConfigChangeRejected, RejectionReason
from ..constants import Family
from ..dhcp_options import shown_options
from ..kea import DaemonStatus, DaemonVersion, KeaClient, KeaCommand, KeaException, SubnetUtilization, close_quietly
from ..models import Server
from ..server_configuration import SharedNetwork
from ..subnet_catalogue import ConfiguredSubnet, VerifiedSubnet

try:
    from utilities.views import ConditionalLoginRequiredMixin
except ImportError:
    from django.contrib.auth.mixins import (  # noqa: F401
        LoginRequiredMixin as ConditionalLoginRequiredMixin,  # type: ignore[assignment]
    )

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseTable)
OutcomeT = TypeVar("OutcomeT", bound=ConfigChangeOutcome)

# Allowed characters in a pool range/CIDR string (digits, dots, colons, letters a-f, slash, hyphen).
# Protects the <path:pool> URL parameter from injection before it reaches the Kea API.
_POOL_RE = re.compile(r"^[0-9a-fA-F.:/-]{3,100}$")

_UNCONFIRMED = "Kea did not confirm the change. Check the server configuration before retrying."
_REJECTED: dict[RejectionReason, str] = {
    "kea-rejected": "Kea rejected the change.",
    "config-test-rejected": "Kea's config-test rejected the change, so it was not applied.",
    "not-sent": "The change was not sent to Kea.",
    "invalid-client-configuration": "The change was not sent to Kea, because the Server settings are not valid.",
}


def _safe_return_url(request: HttpRequest, fallback: str) -> str:
    """Return the request's ``return_url`` when it is a local absolute path, else *fallback*."""
    return_url = request.GET.get("return_url", "")
    # redirect() reverses a value without "/" as a view name, so only a path is safe.
    if (
        not return_url.startswith("/")
        or "\\" in return_url
        or any(ord(character) < 32 for character in return_url)
        or not url_has_allowed_host_and_scheme(return_url, allowed_hosts=None)
    ):
        return fallback
    path = unquote(urlsplit(return_url).path)
    prefix = get_script_prefix()
    if not path.startswith(prefix):
        return fallback
    try:
        resolve("/" + path.removeprefix(prefix))
    except Resolver404:
        return fallback
    return return_url


def _strip_empty_params(path: str) -> str:
    """Return *path* with blank query-string parameters removed.

    HTMX 2.x omits empty form values from the browser push URL while still
    sending them in the actual HTTP request.  Using this helper when building
    ``return_url`` ensures the URL we redirect to after bulk-delete matches
    the URL Playwright (and real browsers) see in the address bar.
    A blank ``q`` stays: the lease page runs a search only when ``q`` is present.
    """
    parsed = urlparse(path)
    params = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if value or key == "q"]
    query = _urlencode(params) if params else ""
    return parsed._replace(query=query).geturl()


def _client_settings_error(server: Server, exc: ValueError) -> str:
    """Log the ``ValueError`` of ``server.get_client()`` and return the message that names the Server setting.

    ``get_client()`` sends nothing, so its ``ValueError`` is never a connection failure. The client also refuses an
    invalid ``max_unpaged_leases``, but that value comes from ``lease_query_max_unpaged_leases``, which NetBox
    validates at startup, so the remaining cause is a client key without a certificate, or the reverse.
    """
    logger.error("Kea client settings of server %s are invalid", server.pk, exc_info=exc)
    return f"The Kea client settings of Server {server.name} are invalid. Check the client certificate and key."


class _KeaChangeMixin:
    """Mixin that gates a view behind ``netbox_kea.change_server``.

    Applied to all views that mutate live Kea state (reservation/pool/subnet
    add, edit, delete).  Both GET (form display) and POST (form submit) are
    protected so users without write access never see the form.
    """

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated:
            from django.contrib.auth.views import redirect_to_login

            return redirect_to_login(request.get_full_path())
        pk = kwargs.get("pk")
        if pk is not None:
            if not Server.objects.restrict(request.user, "view").filter(pk=pk).exists():
                raise Http404
            if not Server.objects.restrict(request.user, "change").filter(pk=pk).exists():
                return HttpResponseForbidden("You do not have permission to modify Kea server data.")
        elif not cast(PermissionsMixin, request.user).has_perm("netbox_kea.change_server"):
            return HttpResponseForbidden("You do not have permission to modify Kea server data.")
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]


def _run_config_change(
    request: HttpRequest, confirmed: str | Callable[[OutcomeT], str], change: Callable[[], OutcomeT]
) -> OutcomeT | None:
    """Run one Configuration Change, show one message for its outcome or its rejection, and return the outcome.

    *confirmed* is the message for a change that Kea applied, such as "Shared network 'x' created.", or a function
    that builds it from the outcome. Returns None after a rejection.
    """
    try:
        outcome = change()
    except ConfigChangeRejected as rejection:
        messages.error(request, " ".join((_REJECTED[rejection.reason], *rejection.diagnostics)))
        return None
    if outcome.application == "unknown":
        # Never claim the change is live: the disk warning names the running configuration only.
        not_saved = ("Kea also could not save its running configuration to disk.",)
        parts = (_UNCONFIRMED, *(not_saved if outcome.persistence == "failed" else ()), *outcome.diagnostics)
        messages.warning(request, " ".join(parts))
        return outcome
    text = confirmed if isinstance(confirmed, str) else confirmed(outcome)
    if outcome.persistence == "failed":
        restart = "It is live, but it may not survive a Kea restart, because Kea did not save it to disk."
        messages.warning(request, " ".join((text, restart, *outcome.diagnostics)))
    else:
        messages.success(request, text)
    return outcome


def _catalogue_subnet_row(
    subnet: VerifiedSubnet | ConfiguredSubnet,
    server: Server,
    version: Family,
    can_change: bool,
) -> dict[str, Any]:
    """Build one Subnet table row from typed catalogue facts."""
    identity = subnet.identity if isinstance(subnet, VerifiedSubnet) else subnet.candidate_identity
    configuration = subnet.configuration
    row = {
        "id": identity.subnet_id,
        "subnet": identity.cidr,
        "_subnet_sort_key": int(identity.network.network_address),
        "dhcp_version": version,
        "server_pk": server.pk,
        "server_name": server.name,
        "identity_verified": isinstance(subnet, VerifiedSubnet),
        "configuration_available": configuration is not None,
        "can_change": can_change and isinstance(subnet, VerifiedSubnet),
        "can_edit_options": can_change and isinstance(subnet, VerifiedSubnet) and configuration is not None,
        "ddns_qualifying_suffix": configuration.settings.ddns_qualifying_suffix if configuration else None,
        "options": shown_options(configuration.options, version) if configuration else {},
        "pools": [pool.range for pool in configuration.pools] if configuration else [],
    }
    if subnet.shared_network is not None:
        row["shared_network"] = subnet.shared_network.name
    return row


def _shared_network_row(
    network: SharedNetwork,
    server: Server,
    version: Family,
    can_change: bool,
    *,
    include_server_name: bool = False,
) -> dict[str, Any]:
    """Build one Shared Network table row from typed configuration facts."""
    subnet_links = [
        {
            "cidr": cidr,
            "url": (
                reverse(f"plugins:netbox_kea:server_leases{version}", args=[server.pk])
                + "?"
                + _urlencode({"by": "subnet", "q": cidr})
            ),
        }
        for cidr in network.member_cidrs
    ]
    row = {
        "name": network.name,
        "description": network.description or "",
        "subnet_count": len(network.member_cidrs),
        "subnet_links": subnet_links,
        "server_pk": server.pk,
        "dhcp_version": version,
        "can_change": can_change,
    }
    if include_server_name:
        row["server_name"] = server.name
    return row


@dataclass(frozen=True)
class _Utilization:
    """One display cache entry: the ``stat_cmds`` address counts of each Subnet of one family."""

    counts: Mapping[int, SubnetUtilization]

    @property
    def settled(self) -> bool:
        """Return true: a failed read raises, so the display cache can store each read that returns."""
        return True


class LazyClient:
    """The Kea client of one Server and target, built on first use and closed quietly at the end of the block.

    A display cache hit builds no client. A target of ``None`` is the Control Agent.
    """

    def __init__(self, server: Server, target: Family | None) -> None:
        self.server = server
        self.target = target
        self._client: KeaClient | None = None

    def __call__(self) -> KeaClient:
        """Return the client, built on the first call."""
        if self._client is None:
            self._client = self.server.get_client(version=self.target)
        return self._client

    def __enter__(self) -> "LazyClient":
        return self

    def __exit__(self, *args: object) -> None:
        if self._client is not None:
            close_quietly(self._client)


def _read_utilization(server: Server, version: Family) -> _Utilization:
    with LazyClient(server, version) as client:
        return _Utilization(client().subnet_utilization(version))


def daemon_status(client: LazyClient) -> DaemonStatus:
    """Return the ``status-get`` facts of the target of *client* through the display cache.

    Raises:
        KeaException: If Kea returns a failure result.
        requests.RequestException: If the transport fails.
        RuntimeError: If the reply is malformed.

    """
    return display_cache.cached(
        client.server,
        client.target,
        "status",
        lambda: client().daemon_status(client.target),
        query=(KeaCommand.STATUS_GET.value,),
    )


def daemon_version(client: LazyClient) -> DaemonVersion:
    """Return the ``version-get`` facts of the target of *client* through the display cache.

    Raises:
        KeaException: If Kea returns a failure result.
        requests.RequestException: If the transport fails.
        RuntimeError: If the reply is malformed.

    """
    return display_cache.cached(
        client.server,
        client.target,
        "status",
        lambda: client().daemon_version(client.target),
        query=(KeaCommand.VERSION_GET.value,),
    )


def _enrich_subnet_statistics(rows: list[dict[str, Any]], server: Server, version: Family, *, live: bool) -> None:
    """Add available utilization measurements to Subnet presentation rows, through the display cache.

    With *live*, for an export, it reads Kea live and replaces the entry.
    """
    try:
        utilization = display_cache.cached(
            server, version, "utilization", lambda: _read_utilization(server, version), refresh=live
        ).counts
    except KeaException as exc:
        if exc.unsupported_command:
            logger.debug("stat_cmds hook unavailable", exc_info=True)
        else:
            logger.warning("Kea refused the Subnet utilization read of server %s", server.pk, exc_info=True)
        return
    except (requests.RequestException, RuntimeError, ValueError):
        logger.warning("Could not read Subnet utilization from server %s", server.pk, exc_info=True)
        return
    for row in rows:
        if (counts := utilization.get(row["id"])) is not None:
            pct = round(counts.assigned / counts.total * 100) if counts.total > 0 else 0
            row.update(total=counts.total, assigned=counts.assigned, utilization=f"{pct}%", utilization_pct=pct)
