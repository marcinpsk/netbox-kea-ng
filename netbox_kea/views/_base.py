# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast
from urllib.parse import parse_qsl, unquote, urlparse, urlsplit
from urllib.parse import urlencode as _urlencode

from django.contrib import messages
from django.contrib.auth.models import PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from django.dispatch import Signal
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.http.request import HttpRequest
from django.urls import Resolver404, get_script_prefix, resolve, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from extras.models import JournalEntry
from netbox.tables import BaseTable

from .. import display_cache
from ..change_outcome import ChangeRejected, RejectionReason
from ..config_write import ConfigChangeOutcome, ReservationChangeOutcome
from ..constants import Family
from ..dhcp_options import shown_options
from ..kea import DaemonStatus, DaemonVersion, KeaClient, KeaCommand, SubnetUtilization, close_quietly
from ..models import Server
from ..read_failure import ReadFailure, attempt
from ..runtime_change import RuntimeChangeOutcome
from ..server_configuration import SharedNetwork
from ..subnet_catalogue import ConfiguredSubnet, VerifiedSubnet

if TYPE_CHECKING:
    from ..ipam_reconciliation import OwnershipState

try:
    from utilities.views import ConditionalLoginRequiredMixin
except ImportError:
    from django.contrib.auth.mixins import (  # noqa: F401
        LoginRequiredMixin as ConditionalLoginRequiredMixin,  # type: ignore[assignment]
    )

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseTable)
OutcomeT = TypeVar("OutcomeT", bound=ConfigChangeOutcome | RuntimeChangeOutcome)
RowT = TypeVar("RowT")

# Allowed characters in a pool range/CIDR string (digits, dots, colons, letters a-f, slash, hyphen).
# Protects the <path:pool> URL parameter from injection before it reaches the Kea API.
_POOL_RE = re.compile(r"^[0-9a-fA-F.:/-]{3,100}$")

_UNCONFIRMED = "Kea did not confirm the change. Check the server configuration before retrying."
_RECORDED_NOTHING = "NetBox recorded nothing for this change."
_UNCONFIRMED_RUNTIME = f"Kea did not confirm the change. Check the Server before you try again. {_RECORDED_NOTHING}"
_NOT_SAVED = "It is live, but it may not survive a Kea restart, because Kea did not save it to disk."
_REJECTED: dict[RejectionReason, str] = {
    "kea-rejected": "Kea rejected the change.",
    "config-test-rejected": "Kea's config-test rejected the change, so it was not applied.",
    "not-sent": "The change was not sent to Kea.",
    "invalid-client-configuration": "The change was not sent to Kea, because the Server settings are not valid.",
    "target-changed": "This request changed nothing.",
}


#: The Unknown reason of a Synchronization State when the IPAM Ownership read fails.
IPAM_UNREADABLE = "NetBox IPAM state could not be read."


def sync_title(state: "OwnershipState", noun: str) -> str:
    """Return the title of a Sync button: what a Sync does to a *noun* in *state*, empty for another state."""
    if state == "unmarked":
        return f"The {noun} has no Kea sync marker. Sync takes it over."
    if state == "not-synchronized":
        return f"Sync adds this Server as an owner of the {noun}."
    return ""


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


def _client_or_refusal(server: Server, version: Family) -> KeaClient | str:
    """Return the Kea client of *server*, or the message that names its invalid client settings. It sends nothing.

    The client also refuses an invalid ``max_unpaged_leases``, but NetBox validates that setting when it is saved, so
    the remaining cause is a client key without a certificate, or the reverse.
    """
    client = attempt(f"The DHCPv{version} client of Server {server.pk}", lambda: server.get_client(version=version))
    if isinstance(client, ReadFailure):
        return f"The Kea client settings of Server {server.name} are invalid. Check the client certificate and key."
    return client


def _client_settings_refusal(server: Server, version: Family) -> str:
    """Return the client settings error of *server*, or an empty string when its Kea client can be built.

    It builds the client and closes it again, so it sends nothing.
    """
    client = _client_or_refusal(server, version)
    if isinstance(client, str):
        return client
    client.close()
    return ""


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


def _run_change(
    request: HttpRequest,
    confirmed: str | Callable[[OutcomeT], str],
    change: Callable[[], OutcomeT],
    *,
    subject: str = "",
    applied_warning: bool = False,
) -> OutcomeT | None:
    """Run one change, show one message for its outcome or its rejection, and return the outcome.

    *confirmed* is the message for a change that Kea applied, such as "Shared network 'x' created.", or a function
    that builds it from the outcome. *applied_warning* shows it as a warning, for a change that stops a service.
    *subject*, such as "Lease 192.0.2.10", starts any other message. Returns None after a rejection.
    """
    try:
        outcome = change()
    except ChangeRejected as rejection:
        _rejection_message(rejection).show(request, subject)
        return None
    if outcome.application == "unknown":
        _unconfirmed_message(outcome).show(request, subject)
        return outcome
    text = confirmed if isinstance(confirmed, str) else confirmed(outcome)
    not_saved = _persistence_failure(outcome)
    if not_saved is not None:
        messages.warning(request, f"{text} {not_saved}")
    elif applied_warning:
        messages.warning(request, text)
    else:
        messages.success(request, text)
    return outcome


@dataclass(frozen=True)
class ChangeMessage:
    """The message of a change that Kea did not apply or did not confirm. *warning* False shows it as an error."""

    text: str
    warning: bool

    def show(self, request: HttpRequest, subject: str = "") -> None:
        """Queue the message, after *subject* when one is given."""
        show = messages.warning if self.warning else messages.error
        show(request, _about(subject, self.text))


@dataclass
class ChangeLoop(Generic[RowT, OutcomeT]):
    """The rows of a loop of changes, by what Kea did with them, each with its outcome or its message."""

    applied: list[tuple[RowT, OutcomeT]] = field(default_factory=list)
    rejected: list[tuple[RowT, ChangeMessage]] = field(default_factory=list)
    unknown: tuple[RowT, ChangeMessage] | None = None
    #: The row where the loop stopped: the unknown row, a rejected row that stops the loop, or a row whose client
    #: could not be built.
    stopped_at: RowT | None = None
    #: The rows after *stopped_at*, which the loop did not send.
    not_sent: list[RowT] = field(default_factory=list)


def _run_change_loop(
    rows: Sequence[RowT],
    change: Callable[[RowT], OutcomeT],
    *,
    stop_on_rejection: bool = False,
    after_applied: Callable[[RowT, OutcomeT], None] | None = None,
) -> ChangeLoop[RowT, OutcomeT]:
    """Send one change for each of *rows*. A rejected row does not stop the loop, unless *stop_on_rejection* is true.

    The loop stops at the first unknown row, and at the first row whose client could not be built, because every
    later row would fail the same way. The optional after-applied step runs after classification and before the next row.
    """
    loop: ChangeLoop[RowT, OutcomeT] = ChangeLoop()
    for index, row in enumerate(rows):
        try:
            outcome = change(row)
        except ChangeRejected as rejection:
            loop.rejected.append((row, _rejection_message(rejection)))
            if not stop_on_rejection and rejection.reason != "invalid-client-configuration":
                continue
        else:
            if outcome.application == "applied":
                loop.applied.append((row, outcome))
                if after_applied is not None:
                    after_applied(row, outcome)
                continue
            loop.unknown = (row, _unconfirmed_message(outcome))
        loop.stopped_at = row
        loop.not_sent = list(rows[index + 1 :])
        break
    return loop


def _rejection_message(rejection: ChangeRejected) -> ChangeMessage:
    # Another writer changed the target, so nothing is wrong with the request or the Server.
    text = " ".join((_REJECTED[rejection.reason], *rejection.diagnostics))
    return ChangeMessage(text, warning=rejection.reason == "target-changed")


def _unconfirmed_message(outcome: ConfigChangeOutcome | RuntimeChangeOutcome) -> ChangeMessage:
    if isinstance(outcome, RuntimeChangeOutcome):
        return ChangeMessage(" ".join((_UNCONFIRMED_RUNTIME, *outcome.diagnostics)), warning=True)
    # Never claim the change is live: the disk warning names the running configuration only.
    not_saved = ("Kea also could not save its running configuration to disk.",)
    recorded = (_RECORDED_NOTHING,) if isinstance(outcome, ReservationChangeOutcome) else ()
    parts = (_UNCONFIRMED, *recorded, *(not_saved if outcome.persistence == "failed" else ()), *outcome.diagnostics)
    return ChangeMessage(" ".join(parts), warning=True)


def _persistence_failure(outcome: ConfigChangeOutcome | RuntimeChangeOutcome) -> str | None:
    """Return the warning for an applied change that Kea did not save to disk, or None when nothing failed."""
    if isinstance(outcome, ConfigChangeOutcome) and outcome.persistence == "failed":
        return " ".join((_NOT_SAVED, *outcome.diagnostics))
    return None


def _journal_applied(request: HttpRequest, server: Server, comments: str) -> None:
    """Write the journal entry of an applied change. A failure shows a separate error and keeps the change."""
    try:
        JournalEntry.objects.create(assigned_object=server, created_by=request.user, kind="info", comments=comments)
    except (DatabaseError, ValidationError):
        logger.exception("Could not write the journal entry of an applied change to Server %s", server.pk)
        messages.error(
            request, "Kea applied the change, but NetBox could not write the journal entry; see server logs."
        )


def _signal_applied(request: HttpRequest, signal: Signal, name: str, **kwargs: Any) -> None:
    """Send *signal* after an applied change. A receiver that fails shows a separate error."""
    # send_robust() returns the error of each receiver instead of raising it.
    responses = signal.send_robust(sender=None, request=request, **kwargs)
    errors = [response for _receiver, response in responses if isinstance(response, Exception)]
    for error in errors:
        logger.error("A receiver of the %s signal failed", name, exc_info=error)
    if errors:
        messages.error(request, f"Kea applied the change, but a receiver of the {name} signal failed; see server logs.")


def _about(subject: str, text: str) -> str:
    return f"{subject}: {text}" if subject else text


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
        MalformedReply: If the reply is malformed.

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
        MalformedReply: If the reply is malformed.

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
    read = attempt(
        f"The DHCPv{version} Subnet utilization read of Server {server.pk}",
        lambda: display_cache.cached(
            server, version, "utilization", lambda: _read_utilization(server, version), refresh=live
        ),
    )
    if isinstance(read, ReadFailure):
        return
    utilization = read.counts
    for row in rows:
        if (counts := utilization.get(row["id"])) is not None:
            pct = round(counts.assigned / counts.total * 100) if counts.total > 0 else 0
            row.update(total=counts.total, assigned=counts.assigned, utilization=f"{pct}%", utilization_pct=pct)
