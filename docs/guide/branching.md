<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# netbox-branching

In a [netbox-branching](https://github.com/netboxlabs/netbox-branching) branch, live Kea and import operations are read-only. CI tests
NetBox 4.7 with netbox-branching 1.2.1. List `netbox_branching` last in `PLUGINS`.

- Kea Servers, sync settings and IPAM ownership links stay in main. A branch has
  no copy of them, so it shows main's values.
- DHCP Import Mappings follow their imported DHCP Servers, Subnets, Pools, Reservations, client classes
  and custom Option Definitions in a fresh branch. Deleting a target removes its branch mapping
  (a Subnet also removes the mappings of its Pools and Reservations) while main retains both. Discard
  preserves main.
  Squash merge deletes the matching main pair; revert restores both original identities, so reimport
  updates the restored object. This applies to IPv4, IPv6, instance deletion and queryset deletion.
  Mapping recovery adds no manual editor or branch-local import.
- Kea data is live, in main and in every branch.
- In a branch, the plugin refuses every change that comes through its web pages or its REST API,
  before it sends anything to Kea or writes to the database. A page shows HTTP 409 with a link to
  main; the REST API answers 409 with the code `branch_write_refused`. Plugin pages show a banner,
  and plugin and GraphQL responses carry an `X-NetBox-Kea-Sources` header.
- A change request that still selects a branch that you can no longer use changes nothing. A
  `_branch` query that names a merged, archived, or not ready branch, and an `active_branch` cookie
  that names such a branch or a deleted one, get HTTP 409 with the code `branch_selection_unusable`.
  netbox-branching answers HTTP 400 first when a `_branch` query names a deleted branch, and when
  an API `X-NetBox-Branch` header names a deleted or unusable branch. In the web interface, select
  main (`?_branch=`) and try again. An API client sends the request again without the
  `X-NetBox-Branch` header.
- Code that runs outside a web request (a custom script, for example) is also refused in a branch.
  A save or a delete of a Kea Server, sync settings or an IPAM ownership link raises
  `BranchActive`, and so does a Kea command that changes Kea, from a client that
  `Server.get_client()` returns. The periodic IPAM sync job fails when it runs in a branch.
- A merge fails, and changes nothing, when the branch deletes a VRF that a Kea server in main now
  syncs into. Clear or change that server's Sync VRF, then merge again.
- In a branch, a delete of an IP address, Prefix or IP Range that a Kea server owns is refused, and
  so is a delete of a device or virtual machine that holds such an IP address, because the ownership
  data exists in main only. NetBox shows the refusal as an error message; the REST API answers 400.

**DHCP mapping recovery.** Select the squash strategy for affected branches. Recovery refuses the
whole action if main has conflicting changes, history is incomplete, a source Server is missing,
an identity has been reused, or restoration would violate a source or target constraint. A busy
transaction refuses with a retry message. Resolve the reported conflict before retrying; newer main
state is preserved. Older branches keep independent read pages, but their DHCP Plugin page (under Sync) requires
a fresh branch. A mapping, target or required Tag branching exemption also requires a fresh branch after
the exemption is removed. Existing branch schemas and missing history are not retrofitted.
Apply Tag changes separately on main or in a Tag-only branch, then create a fresh branch for DHCP
changes. Recovery refuses mixed Tag changes and mapped DHCP target replay, including unrelated Tag
changes in the same branch. A required missing, renamed or replaced Tag also causes a refusal.

Mappings lost under the previous policy require explicit operator repair. Preserve the existing
target, verify its Server, family and source identity from trusted records, and repair the association
on main through an audited operator procedure. A matching target name does not prove that association.
See [the recovery contract](https://github.com/marcinpsk/netbox-kea-ng/blob/main/docs/design/dhcp-import-mapping-branching.md).

**Upgrade with open branches.** Earlier releases let netbox-branching copy the Kea servers table
into each new branch. Nothing removes that copy: branch sync no longer updates it, and branch
migrate does not drop it. NetBox still reads Kea servers from main, but a VRF delete in the branch
checks the old copy, not main. A merge also applies to main every Kea server change that the branch
recorded before the upgrade. Before you upgrade, merge or delete every branch that is not yet
merged, and create new branches after the upgrade. If a branch changed a Kea server password, delete
it and make the change again in main: the change log holds a placeholder, not the password, so a
merge can write the placeholder to main. A merged branch keeps its schema until you
archive it; archive it when you no longer need to revert it.
