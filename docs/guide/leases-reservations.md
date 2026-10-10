<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Leases, Reservations and Subnets

## Lease Add / Edit / Delete / Bulk Import

![A DHCPv4 lease search by Subnet ID: each lease shows its state, a Reserved badge or a Reserve button, and a Synced badge or a Sync button](assets/screenshots/lease-search-light.png#only-light)
![A DHCPv4 lease search by Subnet ID: each lease shows its state, a Reserved badge or a Reserve button, and a Synced badge or a Sync button](assets/screenshots/lease-search-dark.png#only-dark)

- Add and edit individual leases, and bulk import leases from CSV. A DHCPv4 lease needs a hardware
  address (`hw-address`), because Kea refuses one without it. A CSV row that is not a valid lease
  rejects the whole file; the message names the file line and the column, never the value. A line number
  counts every line of the file, also the header, comments and blank lines.
- Edit, Delete and Reserve act on the allocation that the row shows: an address, or a DHCPv6 delegated
  prefix (`address/length`). Reserve on a delegated prefix fills the Reservation prefix field.
- Edit and Delete read the lease again before they change it. They change nothing when the client
  binding (MAC address and client ID, or DUID and IAID), the Subnet, the kind, the prefix length or an
  edited field differs from the page; reload and try again. A renewal alone does not stop the change,
  and an edit keeps the renewed times and Kea's extension values, such as `user-context`. This is a
  check before the change, not an atomic compare-and-write: another writer can still change the lease
  between the check and the change. A lease that is gone is never created again.
- An edit writes only the fields that you change. A blank hostname clears the hostname; a blank
  client identifier or valid lifetime keeps the current value.
- After an add, the plugin reads the new lease back from Kea. *Sync to NetBox IPAM* claims it only
  when that read shows a current lease whose client binding, and Subnet and hostname when the form
  gave them, match the request.
- A Reservation of the client that holds only the other kind (addresses for a delegated prefix, or
  prefixes for an address) shows as *Reservation*, not *Reserved*, and the row offers no *+ Reserve*.
- The `lease_added` and `leases_deleted` signals carry typed values (see `netbox_kea/signals.py`).
  `lease_added` sends `creation`, the request that Kea confirmed, and `lease`, the lease that the read
  back observed, or `None` when that read failed or does not match the request. A CSV import sends
  `lease_added` for each row that Kea created, with `lease` `None`, because it reads nothing back.
  `leases_deleted` sends `leases`, the leases whose deletion Kea confirmed. A refused, changed or
  failed action sends no signal. Wiping the leases of a Subnet sends no signal, because Kea does
  not report which leases it removed.

![The Edit DHCPv4 Lease form with the hostname, the hardware address and the valid lifetime of the lease](assets/screenshots/lease-edit-light.png#only-light)
![The Edit DHCPv4 Lease form with the hostname, the hardware address and the valid lifetime of the lease](assets/screenshots/lease-edit-dark.png#only-dark)

![A DHCPv6 lease search that shows two address leases and one delegated prefix with its prefix length](assets/screenshots/dhcpv6-leases-light.png#only-light)
![A DHCPv6 lease search that shows two address leases and one delegated prefix with its prefix length](assets/screenshots/dhcpv6-leases-dark.png#only-dark)

## Lease observations

- The plugin validates each lease record that Kea returns. A malformed record is left out and the
  page shows a safe reason for it (a code, the Kea field and the record position, never the rejected value).
  The other leases stay visible. A malformed record never counts as "no lease".
- Only a Current Lease is live evidence: an assigned address or delegated prefix, or a registered
  DHCPv6 address, whose valid lifetime has not ended. An infinite lifetime never ends. The
  Reservation **Lease** column shows *No Lease* only when the lease query of that Reservation is
  complete; otherwise it shows *Lease Unknown* with the reason.
- The lease REST actions (`/api/plugins/kea/servers/<pk>/leases4/` and `leases6/`) take one filter:
  `ip_address`, `hw_address` (DHCPv4), `duid` (DHCPv6), `hostname` or `subnet_id`. When a request
  gives more than one, the first in that order is used. `state` keeps only the leases in one Kea state
  code (`0` assigned to `4` registered) for every filter. A `subnet_id` search takes only `0` (assigned)
  or `1` (declined), because Kea counts only those states for the query guard.
  They return one normalized observation: `count`, `results`, `diagnostics`, `complete`, `next_cursor`,
  `query` (`family`, `selector`, `value`, `state`), `coverage` (`exhaustive` or `page`) and `evaluated_at`.
  Each result has `family`, `kind` (`address` or `delegated-prefix`), `address`, `prefix_length`,
  `subnet_id`, `state` (the Kea state name), `current`, `binding` (`hw_address` and `client_id` for
  DHCPv4, `duid` and `iaid` for DHCPv6), `hostname`, `valid_lifetime`, `last_transaction` and
  `expiration` (`infinite`, `expires_at`). Each diagnostic has `code`, `field`,
  `message`, `source_position` and `kinds`. The response contains no Kea extension values, such as
  `user-context`, and no display labels. A search covers its own query scope only, so `complete`
  never means that the daemon has no other leases.
- A DHCPv6 *IP Address* search reads the address and the delegated prefix at that address. It is
  complete only when Kea confirms both. A *Subnet* search for a CIDR that Kea does not configure is
  refused, because Kea can keep leases under a Subnet ID that is no longer configured: search by
  *Subnet ID* instead. When `lease_query_max_unpaged_leases` is set, a Subnet read that returns more
  leases than the limit is refused too, because Kea's statistics do not count every lease state.
- *Export All Leases* and *All Data* are complete exports. They refuse an incomplete observation (a
  malformed record, or more leases than the export limit) and show the reason. Their columns are:
    - DHCPv4: `family`, `kind`, `address`, `prefix_length`, `subnet_id`, `state`, `current`, `hostname`,
      `valid_lifetime`, `last_transaction`, `infinite`, `expires_at`, `hw_address`, `client_id`.
    - DHCPv6: `family`, `kind`, `address`, `prefix_length`, `subnet_id`, `state`, `current`, `hostname`,
      `valid_lifetime`, `last_transaction`, `infinite`, `expires_at`, `duid`, `iaid`, `hw_address`,
      `preferred_lifetime`.

    `kind` is `address` or `delegated-prefix`. `state` is the Kea state name (`assigned`, `declined`,
    `expired-reclaimed`, `released`, `registered`) and `current` is `true` or `false`. Lifetimes are
    in seconds. `last_transaction` and `expires_at` are ISO 8601 times in UTC; `expires_at` is empty
    when `infinite` is `true`. An empty cell is a value that the lease does not have.
- *Current View (limited coverage)* exports the readable leases of the search, in the columns that
  the table shows, as `leases_limited_coverage.csv`. It is not a complete export.

## Upgrading from 1.x: lease contracts that changed

Integrations that read leases from the plugin must change with the typed lease release (2.0 and later):

- The `leases4` and `leases6` REST actions return the observation above. The Kea fields with
  underscores, such as `ip_address`, `valid_lft`, `cltt` and `user_context`, and the display keys
  `state_label`, `expires_in` and `expiry_class` are gone. Check `complete` before you treat a
  missing lease as absent.
- *Export All Leases* and *All Data* use the documented columns and refuse an incomplete observation.
- `lease_added` sends `creation` and `lease` instead of `ip_address`, `hw_address` and `hostname`.
  `leases_deleted` sends `leases` instead of `ip_addresses`. A delegated prefix is a
  `DHCPv6PrefixLease` with its prefix length, not an IP address.
- The DHCPv4 lease CSV import requires the `hw-address` column.
- The IPAM sync records a delegated-prefix lease as a Prefix, not an IP address. The first complete
  runs after the upgrade repair the IP addresses that earlier releases made of delegated prefixes
  (see [Delegated-prefix leases from earlier releases](ipam-sync.md#delegated-prefix-leases-from-earlier-releases)).

## Host Reservations

- Full CRUD for DHCPv4 and DHCPv6 reservations via [`host_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#hooks-host-cmds) and [`subnet_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#hooks-subnet-cmds) hooks
- Identifier types: hw-address (v4), DUID (v6), client-id, flex-id, circuit-id, remote-id
- Reservations that reserve no address — an identifier-only host (hostname, options or
  client classes only) and a DHCPv6 host that only delegates prefixes. Both are listed,
  created, edited and deleted by client identifier instead of by IP, and the IPAM sync
  reports them as *skipped*: there is no address to record in NetBox. Their **Lease**
  column matches the client identifier against the leases of the reservation's own
  subnet, there being no reserved address to match on
- Per-reservation DHCP options
- The hostname field takes the name that clients get. Kea adds the effective `ddns-qualifying-suffix`
  (the Pool that contains the reserved address, then the Subnet, the Shared Network and the global value) to a
  reserved hostname, except to a name that ends in a dot or already ends in the suffix. When a Pool of the
  Subnet sets a suffix, a Reservation without an address has no known published name, and the form refuses a
  hostname for it. The form shows a preview of the published name, and the plugin stores the
  hostname that makes Kea publish the entered name: the labels without the suffix, a single label as entered
  (Kea qualifies it), or any other name with a trailing dot. A saved Reservation keeps its stored hostname
  until you edit the name
- Journal entries on add/edit/delete
- Validated YAML or JSON bulk transfer. Export a Complete Snapshot from one server
  or the combined view, then import it from the matching DHCPv4 or DHCPv6 Reservations page

![The DHCPv4 Reservations of a Server, with the identifier, the reserved address, the DHCP options, the lease state and the NetBox IP state of each Reservation](assets/screenshots/reservations-light.png#only-light)
![The DHCPv4 Reservations of a Server, with the identifier, the reserved address, the DHCP options, the lease state and the NetBox IP state of each Reservation](assets/screenshots/reservations-dark.png#only-dark)

## Subnet Management

- Add, edit and delete subnets (requires [`subnet_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#hooks-subnet-cmds) or `config-set`)
- Pool management (add/delete pools per subnet)
- Shared network management (add/edit/delete)
- Per-subnet and global DHCP option editing

![The DHCPv4 Subnets of a Server, with the pools, the utilization, the options and the shared network of each Subnet](assets/screenshots/subnets-light.png#only-light)
![The DHCPv4 Subnets of a Server, with the pools, the utilization, the options and the shared network of each Subnet](assets/screenshots/subnets-dark.png#only-dark)
