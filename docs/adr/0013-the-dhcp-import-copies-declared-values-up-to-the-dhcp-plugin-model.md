---
status: accepted
date: 2026-10-17
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# The DHCP Import copies Declared Values up to the DHCP plugin model

## Context

The DHCP Import copies a Server's Kea configuration and Reservations into netbox-plugin-dhcp (0.2.0). It drops
facts that the plugin can hold:
- DHCPv6 `pd-pools`
- Pool classes, IDs and DDNS settings
- Subnet client classes
- unused Option Definitions
- the Reservation keys outside the typed model of ADR 0002

It also has other faults:
- It compares Subnet values with the global configuration only, so Shared Network values land on member Subnets
  as overrides.
- It lets the plugin number Subnets, and keeps one DHCPServer for both address families.
- It never removes anything.
- In-Subnet Reservations, Pools and client classes have no DHCP Import Mapping.

Some Kea facts need upstream plugin changes (marcinpsk/netbox-kea-ng#88), for example a Shared Network whose Subnets
share no enclosing Prefix. A reverse direction from the plugin to Kea must stay possible.

## Decision

- **Build for the full fact set; the installed plugin decides.** The import plans every in-scope Kea fact as if the
  plugin could hold it. Before it writes a fact, it checks the DHCP Plugin Capability that the fact needs: a field,
  a choice, a value range or a uniqueness scope. A fact without its capability fails alone and is reported as
  unsupported, with the capability, its Kea path and the #88 gap. When a later plugin release gains the capability,
  the fact imports with no change here. For a capability the plugin lacks entirely, the import assumes the shape that
  #88 proposes. Each run's result is stored. We add no custom fields or companion models for plugin gaps.
- **Declared Values only.** The plugin's own inheritance supplies the rest. Kea's `config-get` merges inherited
  values into a Subnet for some keys. There, a value equal to the parent's value counts as inherited. The parent is
  the Shared Network of a member Subnet, else the global configuration.
- **Shared Networks** are imported with their Declared Values, DHCP Options and Subnet membership. A Shared Network
  that the plugin cannot hold, for example one whose Subnets share no enclosing Prefix, fails as unsupported. Its
  member Subnets still import without membership. The values those Subnets inherit from it are reported, never copied
  onto the Subnets.
- **Identity.** Every top-level object has a DHCP Import Mapping, which is the identity a reverse direction will use:
  - the global configuration of each family, one DHCPServer per Server and family
  - Shared Network, by name
  - Subnet, by Kea subnet ID
  - Pool, by Subnet and range
  - delegated-prefix Pool, by Subnet, prefix and delegated length
  - Reservation in either scope, by Reservation Identity
  - client class, by name
  - custom Option Definition, by space and code

  A client class and a Shared Network keep their Kea name. While the plugin requires names to be unique across all
  servers, a second Server's object of the same name fails as unsupported. Subnets, Pools and Reservations have no
  Kea name, so their names are synthesized.
- **Subnet ID.** The import writes Kea's subnet ID to the plugin Subnet. While the plugin requires subnet IDs to be
  unique across all servers, a Subnet whose ID another Server or family holds fails as unsupported, with its Pools and
  In-Subnet Reservations.
- **Fidelity.** The import never rewrites a value in a way that cannot be written back unchanged. It stores no opaque
  copy of a Kea record.
- **Ownership.** Kea owns the managed fields of a mapped row. A managed field that Kea does not declare is cleared
  to inherit. Unmapped rows and unmanaged fields are left alone.
- **Removal.** The import removes a Stale DHCP Import Object only after a Complete observation of its kind. A Pool
  whose range changes is a new Pool.
- **Runs.** An operator runs the import from the Server page. It can also run with the periodic sync job, which is
  off by default.
- **Guard.** A parity ledger test fails when a Kea key that the import can meet is neither mapped (with the DHCP
  Plugin Capability it needs, if any) nor listed as not imported with a reason.

## Considered options

- **Kea as the ceiling, through custom fields or a companion model.** Rejected: we would own schema the plugin
  should own, before the reverse direction is designed.
- **The installed plugin model as the ceiling.** Facts outside it were reported and never written. Rejected: each
  upstream fix would then need a netbox-kea change before it helped anyone.
- **Synthesized client class names, so that every class imports today.** Rejected: the names would need a migration
  once the plugin allows the same name per server.
- **Effective values on every Subnet.** Rejected: the plugin could no longer tell an override from a default, and a
  reverse direction would write defaults back as Subnet overrides.
- **Compare with the global configuration only, as before.** Rejected: Shared Network values become Subnet
  overrides.
- **Plugin-assigned Subnet IDs.** Rejected: a reverse direction would renumber Subnets and orphan their Leases.
- **Store the raw Kea record.** Rejected: an unvalidated second source of truth.
- **Never remove imported rows.** Rejected: drift grows silently. Fill-only updates were rejected because they hide
  Kea changes.

## Consequences

- An explicit Subnet override that equals its parent's value is not imported. The plugin shows the inherited value,
  which is the same.
- While the plugin keeps names and subnet IDs unique across all servers, a dual-stack Server loses its DHCPv6 Subnets
  that reuse a DHCPv4 ID, and a second Server loses its classes that share a name. Each loss is reported, and each
  ends with the upstream change.
- A Shared Network that the plugin cannot hold leaves its member Subnets without membership and without the values
  they inherit from it. The report lists each value.
- A capability that the plugin lacks entirely is checked under the shape #88 proposes. If upstream picks another
  shape, that one check changes.
- Hand edits to managed fields of mapped rows are overwritten at the next run.
- The first run after upgrade adopts the existing DHCPServer as the primary family's. It adds mappings for objects
  that were matched by structure until now.
