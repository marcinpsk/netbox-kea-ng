# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from netbox_kea.ipam_sources import POOL, RESERVATION, SOURCES, SUBNET


def compares_a_literal(source, link, phase):
    # ruleid: kea-ownership-source-literal
    if source == "pool":
        return 1
    # ruleid: kea-ownership-source-literal
    if "subnet" != source:
        return 2
    # ruleid: kea-ownership-source-literal
    if link.source == "reservation":
        return 3
    # ruleid: kea-ownership-source-literal
    if source in ("reservation-prefix", "pd-pool"):
        return 4
    # ruleid: kea-ownership-source-literal
    if phase.source not in ["lease"]:
        return 5
    # ruleid: kea-ownership-source-literal
    if source in {SUBNET, "pool"}:
        return 6
    # ruleid: kea-ownership-source-literal
    return "ip-range" if source == "pool" else "prefix"


def compares_a_constant_or_another_name(source, link, kind, resource, sources):
    # ok: kea-ownership-source-literal
    if source == POOL:
        return 1
    # ok: kea-ownership-source-literal
    if link.source != RESERVATION:
        return 2
    # ok: kea-ownership-source-literal
    if source in (RESERVATION, POOL):
        return 3
    # ok: kea-ownership-source-literal
    if kind == "delegated-prefix":
        return 4
    # ok: kea-ownership-source-literal
    if SOURCES[source].object_field == "ip_range":
        return 5
    # ok: kea-ownership-source-literal
    if resource == "pool":
        return 6
    # ok: kea-ownership-source-literal
    if source in sources:
        return 7
    # ok: kea-ownership-source-literal
    return link.allocation_kind == "address"
