# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Subnet and Shared Network lists of the Server tabs and the combined pages.

Each list has one ``fetch``, which reads Kea and is safe in a worker thread, and one ``present``, which builds the
rows with the one permission rule in the main thread. The page shells (templates, the htmx table refresh, how a Notice
shows) stay with each scope.
"""

from collections.abc import Mapping, Set
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from django.urls import reverse

from .. import display_cache, forms, server_configuration, subnet_catalogue
from ..constants import Family
from ..dhcp_options import shown_options
from ..kea import SubnetUtilization
from ..models import Server
from ..read_failure import ReadFailure, attempt
from ..server_configuration import ServerConfigurationSnapshot, SharedNetwork
from ..subnet_catalogue import CatalogueSnapshot, ConfiguredSubnet, VerifiedSubnet
from ._base import LazyClient
from .notices import Notice, notice


@dataclass(frozen=True)
class SubnetRead:
    """The cached Subnet Catalogue of one Server and family, its Notice, and the utilization of its Subnets."""

    catalogue: CatalogueSnapshot
    notice: Notice | None
    #: The ``stat_cmds`` counts by Subnet ID; empty when the Catalogue is unavailable or the read failed.
    utilization: Mapping[int, SubnetUtilization]


@dataclass(frozen=True)
class SharedNetworkRead:
    """The cached Server Configuration of one Server and family, and its Notice."""

    configuration: ServerConfigurationSnapshot
    notice: Notice | None


@dataclass(frozen=True)
class PresentedRows:
    """The table rows of one Server for one user, and the Notice of their read."""

    rows: list[dict[str, Any]]
    notice: Notice | None


@dataclass(frozen=True)
class _Utilization:
    """One display cache entry: the ``stat_cmds`` address counts of each Subnet of one family."""

    counts: Mapping[int, SubnetUtilization]

    @property
    def settled(self) -> bool:
        """Return true: a failed read raises, so the display cache can store each read that returns."""
        return True


def _read_utilization(server: Server, family: Family) -> _Utilization:
    with LazyClient(server, family) as client:
        return _Utilization(client().subnet_utilization(family))


def fetch_subnets(server: Server, family: Family, *, live: bool) -> SubnetRead:
    """Read the cached Subnet Catalogue and the utilization of *server*. It is safe in a worker thread.

    With *live*, for an export, the utilization is read live and replaces its display cache entry.
    """
    catalogue = subnet_catalogue.display(server, family)
    if catalogue.unavailable:
        return SubnetRead(catalogue, notice(catalogue), {})
    utilization = attempt(
        f"The DHCPv{family} Subnet utilization read of Server {server.pk}",
        lambda: display_cache.cached(
            server, family, "utilization", lambda: _read_utilization(server, family), refresh=live
        ),
    )
    counts = {} if isinstance(utilization, ReadFailure) else utilization.counts
    return SubnetRead(catalogue, notice(catalogue), counts)


def _subnet_row(
    subnet: VerifiedSubnet | ConfiguredSubnet,
    server: Server,
    family: Family,
    *,
    writable: bool,
    utilization: Mapping[int, SubnetUtilization],
    return_url: str,
) -> dict[str, Any]:
    identity = subnet.identity if isinstance(subnet, VerifiedSubnet) else subnet.candidate_identity
    configuration = subnet.configuration
    # A change needs a Verified Subnet; an option edit also needs its configuration facts.
    can_change = writable and isinstance(subnet, VerifiedSubnet)
    row = {
        "id": identity.subnet_id,
        "subnet": identity.cidr,
        "_subnet_sort_key": int(identity.network.network_address),
        "dhcp_version": family,
        "server_pk": server.pk,
        "server_name": server.name,
        "can_change": can_change,
        "can_edit_options": can_change and configuration is not None,
        "ddns_qualifying_suffix": configuration.settings.ddns_qualifying_suffix if configuration else None,
        "options": shown_options(configuration.options, family) if configuration else {},
        "pools": [pool.range for pool in configuration.pools] if configuration else [],
        "return_url": return_url,
    }
    if subnet.shared_network is not None:
        row["shared_network"] = subnet.shared_network.name
    if (counts := utilization.get(identity.subnet_id)) is not None:
        pct = round(counts.assigned / counts.total * 100) if counts.total > 0 else 0
        row.update(total=counts.total, assigned=counts.assigned, utilization=f"{pct}%", utilization_pct=pct)
    return row


def present_subnets(server: Server, read: SubnetRead, *, writable: Set[int], return_url: str) -> PresentedRows:
    """Build the Subnet rows of *server*. *writable* holds the pks of the Servers that the user may change.

    Each row action returns to *return_url*.
    """
    catalogue = read.catalogue
    subnets: tuple[VerifiedSubnet | ConfiguredSubnet, ...] = (*catalogue.subnets, *catalogue.configured_subnets)
    rows = [
        _subnet_row(
            subnet,
            server,
            catalogue.family,
            writable=server.pk in writable,
            utilization=read.utilization,
            return_url=return_url,
        )
        for subnet in subnets
    ]
    return PresentedRows(rows, read.notice)


def filter_subnets(rows: list[dict[str, Any]], search_form: forms.SubnetSearchForm) -> list[dict[str, Any]]:
    """Return the Subnet rows that match a valid search; an invalid search filters nothing.

    Kea has no Subnet search, so the filter runs on the rows of the Subnet Catalogue.
    """
    if not search_form.is_valid():
        return rows
    subnet_id = search_form.cleaned_data.get("subnet_id")
    if subnet_id is not None:
        rows = [row for row in rows if row.get("id") == subnet_id]
    text = (search_form.cleaned_data.get("q") or "").lower()
    if text:
        rows = [row for row in rows if text in row.get("subnet", "").lower()]
    return rows


def fetch_shared_networks(server: Server, family: Family) -> SharedNetworkRead:
    """Read the cached Server Configuration of *server*. It is safe in a worker thread."""
    configuration = server_configuration.display(server, family)
    return SharedNetworkRead(configuration, notice(configuration))


def _shared_network_row(
    network: SharedNetwork, server: Server, family: Family, *, writable: bool, return_url: str
) -> dict[str, Any]:
    leases = reverse(f"plugins:netbox_kea:server_leases{family}", args=[server.pk])
    subnet_links = [
        {"cidr": cidr, "url": f"{leases}?{urlencode({'by': 'subnet', 'q': cidr})}"} for cidr in network.member_cidrs
    ]
    return {
        "name": network.name,
        "description": network.description or "",
        "subnet_count": len(network.member_cidrs),
        "subnet_links": subnet_links,
        "server_pk": server.pk,
        "server_name": server.name,
        "dhcp_version": family,
        "can_change": writable,
        "return_url": return_url,
    }


def present_shared_networks(
    server: Server, read: SharedNetworkRead, *, writable: Set[int], return_url: str
) -> PresentedRows:
    """Build the Shared Network rows of *server*. *writable* holds the pks of the Servers that the user may change.

    Each row action returns to *return_url*.
    """
    configuration = read.configuration
    rows = [
        _shared_network_row(
            network, server, configuration.family, writable=server.pk in writable, return_url=return_url
        )
        for network in configuration.shared_networks
    ]
    return PresentedRows(rows, read.notice)
