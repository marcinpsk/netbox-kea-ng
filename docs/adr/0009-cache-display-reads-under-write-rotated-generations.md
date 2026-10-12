---
status: accepted
date: 2026-10-12
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Cache display reads under write-rotated generations

## Context

Each tab switch sends every Kea read again: Reservation pages, Lease pages, capability checks, Lease badges,
utilization and daemon status. Only the Server Configuration Snapshot and the Catalogue Snapshot are cached
([ADR 0003](0003-separate-server-configuration-authority.md)), and the Catalogue reaches into a private
generation function of `server_configuration`.
A Server save does not rotate the generation, so a Server with a new URL shows old Snapshots until the TTL ends.
Every plugin write to Kea already passes through `KeaClient.command()`, which knows the command kind.
Every authority read (verification, synchronization, mutation scopes, post-write checks) is already live.

## Decision

- One cache module owns the keys, generations, TTLs, admission rule and invalidation of every display read.
  `server_configuration` and `subnet_catalogue` use it and stop sharing a private function.
- Each Server and address family has a configuration generation (today's) and one records generation.
  `KeaClient.command()` rotates the records generation before and after every write command. A write with
  no family target rotates both families. Configuration changes keep rotating the configuration generation.
- A Server save rotates every generation of that Server. A save that writes only workflow receipt fields or
  `sync_enabled` does not.
- Authority reads never read or fill the cache. A cached entry never authorizes a write.
- The cache admits an incomplete result. It never admits a failed read or a page walk stopped by an error.
  A walk stopped at its configured limit is settled and is admitted.
- An entry belongs to one Server, family and query, never to a user. Permission filtering runs after the read.
  Lease badges on Reservation rows are their own entries with the Lease TTL.
- TTLs come from the display cache settings ([ADR 0010](0010-runtime-plugin-settings-live-in-database-singletons.md)).
  A TTL of 0 turns off caching for that read kind. A settings save makes every existing entry unreachable.
- Each cached table shows the read age and a Refresh control. Refresh reads live and replaces that one entry.

## Considered options

- A generation per read kind. Rejected: each write command needs a list of the kinds it affects, and the
  list drifts (`subnet4-del` also removes Reservations and Leases).
- Clearing other Servers that are HA partners or share a hosts database. Rejected: the plugin does not model
  those links. Changes from outside this NetBox lag by at most one TTL.
- A browser or htmx history cache, or per-request memoization. Rejected: a write cannot invalidate the first,
  and the second does not help a tab switch.

## Consequences

- An operator sees their own writes at once. Changes from kea-shell, another NetBox or an HA partner, and
  Leases that Kea allocates, appear after at most one TTL or a Refresh.
- The ADR 0003 cache rules now apply to every display read.
- The test cache hygiene fixture clears one key prefix.
