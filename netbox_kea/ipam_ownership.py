# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The IPAM Ownership reads (ADR 0006): the Synchronization State of an IP address or a Prefix for one source.

The Lease and Reservation views read the ownership of the objects that their rows show. The module also holds the
canonical text of a NetBox address and network, which the claim code shares as a report key.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any, Literal

from django.db.models import Exists, OuterRef, QuerySet
from ipam.models import IPAddress, Prefix

from .constants import Family
from .ipam_marker import parse_marker
from .models import IPAMOwnershipLink, Server

# The Synchronization State terms of CONTEXT.md; "hidden" is the Unknown of an object the user may not view.
OwnershipState = Literal["synchronized", "not-synchronized", "unmarked", "not-in-netbox", "hidden"]


@dataclass(frozen=True)
class Ownership:
    """The IPAM Ownership of one IP address or Prefix in the sync VRF for one source, as one user may see it.

    ``obj`` is the object the user may view; it is ``None`` when the state is ``not-in-netbox`` or ``hidden``.
    """

    state: OwnershipState
    obj: IPAddress | Prefix | None = None

    def __post_init__(self) -> None:
        if (self.obj is None) != (self.state in ("not-in-netbox", "hidden")):
            raise ValueError(f"An ownership state {self.state!r} with obj={self.obj!r} is not valid.")


def address_ownership(
    server: Server, family: Family, source: str, addresses: Collection[str], user: Any
) -> dict[str, Ownership]:
    """Return the ownership of the IP address of each address by *source* of *server* and *family*.

    The rules are those of :func:`_ownership`. Each key is the canonical text of an address.
    """
    parsed = [ipaddress.ip_address(address) for address in addresses]
    if any(getattr(address, "scope_id", None) for address in parsed):
        raise ValueError("A NetBox IP address has no IPv6 scope zone.")
    hosts = {str(address) for address in parsed}
    rows = IPAddress.objects.filter(vrf_id=server.sync_vrf_id, address__net_in=sorted(hosts))
    return _ownership(server, family, source, user, rows, hosts, lambda ip: host_text(ip.address))


def prefix_ownership(
    server: Server, family: Family, source: str, networks: Collection[str], user: Any
) -> dict[str, Ownership]:
    """Return the ownership of the Prefix of each network by *source* of *server* and *family*.

    Only a Prefix of the same network and length counts. The rules are those of :func:`_ownership`. Each key is the
    canonical text of a network.
    """
    keys = {str(ipaddress.ip_network(network)) for network in networks}
    rows = Prefix.objects.filter(vrf_id=server.sync_vrf_id, prefix__in=sorted(keys))
    return _ownership(server, family, source, user, rows, keys, network_text)


#: The link field of each model that an ownership read takes.
_LINK_FIELDS: dict[type, str] = {IPAddress: "ip_address", Prefix: "prefix"}


def _ownership(
    server: Server,
    family: Family,
    source: str,
    user: Any,
    rows: QuerySet[IPAddress] | QuerySet[Prefix],
    keys: Collection[str],
    key_of: Callable[[Any], str],
) -> dict[str, Ownership]:
    """Return the ownership of the object of each key among *rows* by *source* of *server* and *family*, in two queries.

    An object is ``synchronized`` when it has a marker and a link of this Server, family and source; any link counts,
    adopted and stale-marked included. A marker without such a link is ``not-synchronized``, and no marker is
    ``unmarked``. A key with an object that *user* may not view is ``hidden``, also when it has duplicate rows that the
    user may view. Else the first duplicate row by pk decides, as in a claim.
    """
    if not keys:
        return {}
    own_link = IPAMOwnershipLink.objects.filter(
        **{_LINK_FIELDS[rows.model]: OuterRef("pk")}, server=server, family=family, source=source
    )
    found_rows = list(rows.annotate(linked=Exists(own_link)).order_by("pk"))
    visible = set(
        rows.model.objects.restrict(user, "view")
        .filter(pk__in=[row.pk for row in found_rows])
        .values_list("pk", flat=True)
    )
    found: dict[str, Ownership] = {}
    for row in found_rows:
        key = key_of(row)
        if row.pk not in visible:
            found[key] = Ownership("hidden")
        elif key not in found:
            found[key] = Ownership(_ownership_state(row), row)
    return {key: found.get(key, Ownership("not-in-netbox")) for key in keys}


def _ownership_state(row: IPAddress | Prefix) -> OwnershipState:
    if parse_marker(row.description) is None:
        return "unmarked"
    return "synchronized" if row.linked else "not-synchronized"


def host_text(address: Any) -> str:
    """Return the canonical host text of a NetBox address, the same text as a phase report's address."""
    return str(ipaddress.ip_address(str(address.ip)))


def network_text(prefix: Prefix) -> str:
    """Return the canonical network text of a NetBox Prefix, the same text as a network report's address."""
    return str(ipaddress.ip_network(str(prefix.prefix)))
