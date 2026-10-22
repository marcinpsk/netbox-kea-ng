<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# IPAM Sync

## What the sync writes

- Sync current address leases → NetBox `IPAddress` (status `dhcp`)
- Sync current DHCPv6 delegated-prefix leases → NetBox `Prefix`, when lease sync and Prefix sync are both on
- Sync reservations → NetBox `IPAddress` (status `reserved`)
- Sync button on individual leases and reservations
- Bulk sync for entire lease tables
- Pending-change detection: badge on leases where a reservation exists at a different IP
- MAC address sync → NetBox `MACAddress`
- Sets `dns_name` on IPAddress for automatic DNS sync via [netbox-dns](https://github.com/peteeckel/netbox-plugin-dns) IPAM DNSsync

![A NetBox IP address that a lease Sync wrote: status DHCP, the DNS name from the lease hostname and the sync marker in the description](assets/screenshots/synced-ip-address-light.png#only-light)
![A NetBox IP address that a lease Sync wrote: status DHCP, the DNS name from the lease hostname and the sync marker in the description](assets/screenshots/synced-ip-address-dark.png#only-dark)

The Sync button of a lease writes the NetBox IP address at once. The button then links to it.

<video controls muted loop playsinline preload="none" width="1440" height="900" poster="../assets/recordings/sync-lease.png" aria-label="Recording: press Sync on a lease, follow the Synced link, and see the sync marker on the NetBox IP address">
  <source src="assets/recordings/sync-lease.mp4" type="video/mp4">
</video>

## Background IPAM Sync

The background sync requires `rqworker`.

- Automatic Kea→NetBox IPAM sync on a configurable interval (default 5 minutes)
- Syncs all current leases and reservations from all configured servers
- Visible in NetBox **System → Background Jobs**

The `Kea IPAM Sync` job runs automatically when `rqworker` is active:

1. Iterates all configured `Server` objects
2. For each server: fetches all leases (v4 + v6) and all reservations. Only a current lease is an owner: an
   assigned address or delegated prefix, or a registered address, whose valid lifetime has not ended
3. Creates or updates NetBox `IPAddress` objects in the server's `sync_vrf`, and links each one to the server
   and its source (lease or reservation):
    - Leases → `status=dhcp`, `dns_name` set from the lease hostname, without a trailing dot
    - In-subnet reservations → `status=reserved`, `dns_name` set from the published name: the reserved hostname
      with the effective `ddns-qualifying-suffix`, as Kea gives it to the client
    - An address with both a lease and a reservation → `status=active`; the reservation hostname wins
    - The MAC address description `dhcp_hostname: <name>` takes the same name from both sources, so a lease and
      its reservation do not change it on each run
    - Global reservations create and change no IP address
    - The description starts with the sync marker `[kea-sync: <kind>]`. Text after the marker is an operator note,
      and the sync keeps it. To release an address from the sync, remove the marker or move it away from the start.
4. Cleans up stale IPs (the **Stale IP Cleanup** setting). A server's lease or reservation that Kea no longer
   reports loses its link. When the last link of every server to an address goes, Stale IP Cleanup applies, but
   only after a complete lease sync and a complete reservation sync. If the server disables reservation sync,
   a complete lease sync is sufficient. An unavailable `host_cmds` hook leaves the reservation source incomplete,
   because config-file reservations can still exist. Failed or truncated lease reads keep their stale links.
5. Links Subnets to Prefixes and Pools to IP Ranges in the server's `sync_vrf`. A complete Subnet or Pool phase
   drops its own stale links. These objects stay unchanged by default and are never deleted. The server that drops
   the last link can opt in to deprecation with `sync_deprecate_prefixes_and_ranges`. A deprecated object's last link
   stays marked stale until an applied report restores its active status, or another owner supersedes the stale link.
   Removing the description marker releases every link without deprecation. DHCP plugin references prevent deprecation.
6. Links each current DHCPv6 delegated-prefix lease to a Prefix in the server's `sync_vrf` (source `lease-prefix`),
   when lease sync and Prefix sync are both on. The DHCP plugin import owns the delegated prefixes of Reservations,
   and the prefixes that they exclude, through its own source, so neither cleans up the other's links. These
   Prefixes follow the rules of step 5. A delegated prefix never creates an IP address. The DHCP plugin import also owns the prefix and the excluded prefix of each DHCPv6
   delegated-prefix Pool (`pd-pools`), through the source `pd-pool` and the marker `[kea-sync: pd pool]`. The job
   reads no delegated-prefix Pool, so it never drops these links. The import drops them after it read every
   delegated-prefix Pool, with the rules of step 5
7. One server failing does not block others
8. Summary logged per server and in total

Each execution groups its native changelog records under one request ID, including MAC address changes.
**Sync now** records the initiating user. Scheduled runs use the reserved user `netbox-kea-sync`.
A job whose initiating user was deleted also uses system attribution.

The job creates this attribution account inactive, with an unusable password and no permissions.
Keep it inactive and without access grants. If an existing account with that name has login access or
permissions, the job fails before synchronization and leaves the account unchanged.

Each server's summary reports `created`, `updated`, `errors`, `prefix_errors`, `conflicts`, `disagreements`,
`skipped`, `waiting` and `unclassified`. The job total also reports `unowned`:

- **skipped**: reservations the sync deliberately did not write: global reservations and
  reservations that reserve no address. They are not errors and do not fail the job.
- **errors**: lease and reservation rows that failed to sync, snapshots that could not
  be read, and reservations that the snapshot could not read. Any error fails the job. A
  failed snapshot and the first 10 failed rows of each server and IP version are logged at
  warning level, with the source (lease or reservation), the address and the exception.
- **conflicts**: IPAM objects that the sync left unchanged: the description of the object does not start with the sync marker (it was created by hand, or an operator
  removed the marker),
  or the new marker and the note after it do not fit in the 200-character description.
  They are deduplicated per server across its phases. Up to 20 of
  them are named in the summary and the log, so the addresses to look at are visible
  without trawling debug output.
- **disagreements**: addresses that two Kea servers report with different facts (the
  hostname or the prefix length), or that one server reports twice with different facts,
  for example from two reservations in overlapping subnets. A lease and a reservation
  disagree only on the prefix length, and an empty hostname makes no claim. The address
  keeps its values until the reports agree, or until one of them goes.
- **unowned**: marker objects with no ownership link, including objects left by a deleted server. Only the job total
  reports this count, because these objects have no owning server. It counts each object once.
- **waiting**: adopted objects whose cleanup this server held during the run while a potential owner had not
  completed its initial observations. The job total counts objects still waiting after all servers finish.
  Counts include each object once across sources and address families.
- **unclassified**: IP addresses that keep a stale DHCPv6 lease link from before the sync recorded the allocation
  kind (see "Delegated-prefix leases from earlier releases" below).

View job history, next scheduled time and logs under **System → Background Jobs → Kea IPAM Sync**.

To change the sync interval, edit it on the **Settings** page. You do not need to restart the worker: the new interval applies after the next scheduled run.

## Manual Sync permissions

A manual Sync makes the writes of the automatic sync, and permission constraints do not limit the automatic sync.
Thus a manual Sync runs only for an active superuser, or for an active user who has an unconstrained grant of each
permission that the Sync can use. An enabled ObjectPermission of the user, or of a group of the user, gives a grant.
`DEFAULT_PERMISSIONS` also gives a grant. A grant is unconstrained when it has no constraint set, or an empty one.

| Control | Required permissions |
| --- | --- |
| Lease **Sync**, lease add with **Sync to NetBox IPAM** | `ipam.add_ipaddress`, `ipam.change_ipaddress`, `dcim.add_macaddress`, `dcim.change_macaddress` |
| Lease **Sync** of a DHCPv6 delegated prefix | `ipam.add_prefix`, `ipam.change_prefix` |
| Reservation **Sync all** and **Sync All to NetBox**, Reservation add or edit with **Sync to NetBox IPAM**, Reservation import with **Sync to NetBox** | The same as for a lease |
| **Sync to DHCP plugin now** | The same as for a lease, `ipam.add_prefix`, `ipam.change_prefix`, `ipam.add_iprange`, `ipam.change_iprange`, change permission on the Server, and the `netbox_dhcp` permissions below |

**Sync All to NetBox** runs only the reservation phase. Its stale cleanup cannot delete an IP address, so it needs no
delete permission. When a user does not have a required grant, the Sync control is disabled. Its tooltip names each
missing or constrained permission, and the server refuses the request with the same text. A grant that only an LDAP
group mapping (`FIND_GROUP_PERMS`) gives does not count.

**Sync to DHCP plugin now** also writes the DHCP plugin objects. It needs add and change on DHCP Server, Option
Definition, Option, Client Class, Subnet, Pool, Prefix Delegation Pool and Host Reservation. It removes Stale DHCP
Import Objects (see [Configuration](configuration.md)), so it also needs delete on Option Definition, Option, Client
Class, Shared Network, Subnet, Pool, Prefix Delegation Pool and Host Reservation.

## Upgrade to ownership links

The first observations adopt marker objects that Kea still reports. No data migration assigns owners.
An object with a blank description stays unchanged unless an operator forces a claim.
When every configured server uses the same non-global `sync_vrf`, an unowned marker IP address in the global
VRF moves into that VRF with its primary key and changelog intact. A row already owned by another server does
not move. A destination address collision keeps the global row unowned and reports a conflict. Servers with
different VRFs keep the global row and create their own scoped rows. A global-VRF server adopts it in place.

Adopted objects keep their last link until every potential owner completes all relevant enabled observations.
Periodic jobs and DHCP imports record completion separately. An incomplete phase or missing family does not
count as complete. Disabled sources and families do not hold the barrier. A Server whose DHCP plugin integration
does not run (see [Configuration](configuration.md)) has no DHCP import to wait for. The read-only
`ipam_first_complete_at` field shows when a server first completed its enabled observations. Newly enabled
sources still require complete observations, even when that timestamp is already set.

Stale IP Cleanup set to Remove now also removes the rows of expired leases, deleted Reservations and hostless
leases after their final ownership link becomes stale. On upgrade, lease removal applies only to leases that
expire after adoption. Rows already stale before the upgrade get no link, stay unchanged and count as
`unowned`. Review these rows before removing them manually.

## Delegated-prefix leases from earlier releases

Earlier releases synced a DHCPv6 delegated-prefix lease as an IP address at the prefix base. The sync now records
the allocation kind on each lease link. DHCPv4 lease links are address links. Existing DHCPv6 lease links start
unclassified, because the stored facts cannot show the original kind:

- An address lease that a complete run reads at that address, current or not, classifies the link as an address
  link.
- A current delegated prefix at that base classifies the link only after a complete run links its Prefix.
  The normal stale cleanup then retires the old IP address under Stale IP Cleanup, and other owners keep it.
- Prefix sync off, a failed Prefix claim (for example an operator Prefix without the marker) or an incomplete
  lease read keeps the old link unclassified.
- An unclassified link that Kea no longer reports stays, and the summary counts it as `unclassified`.
  Remove the sync marker from the IP address to release it.
