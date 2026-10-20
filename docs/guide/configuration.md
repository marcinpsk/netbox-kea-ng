<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Configuration

All runtime settings are on the **Settings** page (menu **DHCP Kea > Settings**). A change applies without a
restart. The page has one section for each group of settings:

| Section | Setting | Default | Description |
|---|---|---|---|
| Sync | Sync Interval (minutes) | `5` | How often the background sync job runs, from 1 to 1440. A change applies after the next run |
| Sync | Sync Enabled (global) | On | Global switch. Clear it to stop the sync for all Servers |
| Sync | Max Leases per Server | `50000` | The most leases that one sync run reads from one Server. `0` means no limit |
| Sync | Stale IP Cleanup | Remove | What the sync does with an IP address when the last link of every Server to it goes: Remove deletes it, Deprecate sets its status to Deprecated, None keeps it |
| Sync | Sync Leases | On | Sync current DHCP address leases to NetBox IPAM. With Sync Prefixes, also DHCPv6 delegated-prefix leases as Prefixes |
| Sync | Sync Reservations | On | Sync Kea reservations to NetBox IPAM |
| Sync | Sync Prefixes | On | Sync Kea subnets to NetBox IPAM as IP Prefixes. With Sync Leases, also DHCPv6 delegated-prefix leases |
| Sync | Sync IP Ranges | On | Sync Kea pools to NetBox IPAM as IP Ranges |
| Kea Client | Kea Timeout (seconds) | `30` | How long each Kea request can take, at least 1. A change applies to the next request |
| Kea Client | Max Unpaged Leases | `1000` | Refuse an unpaged Subnet lease query when its Kea statistics count exceeds this limit. `0` disables this safety check |
| Display Cache | Configuration TTL (seconds) | `300` | How long a page shows a cached Server configuration and Subnet list. `0` turns off caching for them |
| Display Cache | Reservations TTL (seconds) | `300` | How long a page shows cached Reservations. `0` turns off caching for them |
| Display Cache | Leases TTL (seconds) | `30` | How long a page shows cached Leases, the Lease badges of Reservations and the Reservation badges of Leases. `0` turns off caching for them |
| Display Cache | Utilization and Status TTL (seconds) | `15` | How long a page shows cached Subnet utilization and daemon status. `0` turns off caching for them |
| DHCP Plugin | Integration Enabled (global) | On | Global switch. Clear it to stop the DHCP plugin integration for all Servers. The section shows only when the NetBox DHCP plugin (`netbox_dhcp`) is installed |

A section shows to a user with the view permission of its model (`netbox_kea.view_syncconfig`,
`netbox_kea.view_keaclientconfig`, `netbox_kea.view_displaycacheconfig`, `netbox_kea.view_dhcpintegrationconfig`). A save needs the change permission of the model too. Without it, the section
shows the values read-only. Each save writes a change log record. While a branch is active, the page refuses a save.

A save of the Display Cache section makes every cached entry unused, also when no value changes. A change that the
plugin sends to Kea makes the cached entries that the change affects unused at once. A change from outside this NetBox, such as
kea-shell or an HA partner, shows when the TTL of the entry ends, or after a Refresh. This also applies to a change
through another Server record that points at the same daemon: a change resets only the entries of the Server that sent it. A Reservations table and a
Leases table show the age of their read ("Read 42 s ago") and a **Refresh** button, which reads Kea again for that
table and for the badges of its rows. On a page of all Servers, the age is the age of the oldest read, and Refresh reads
each Server again. A badge is never older than the table that shows it. Subnet utilization and daemon status show no
read age and no Refresh: their TTL is short.

The DHCP plugin integration runs for a Server only when the NetBox DHCP plugin is installed, the Server has
**Sync to DHCP plugin** on, and **Integration Enabled (global)** is on. When one of them is off, the Server has no
**DHCP Plugin** subsection under Sync, **Sync to DHCP plugin now** refuses, and the IPAM sync does not wait for a
DHCP plugin import before it removes an adopted object. Objects that DHCP plugin records refer to stay protected from
stale cleanup while the switch is off.

The DHCP Import needs netbox-plugin-dhcp 0.2.0 or later. With an older release installed, **Sync to DHCP plugin now**
refuses before it reads Kea, names the required version, and changes nothing.

Kea runs DHCPv4 and DHCPv6 as separate daemons, so the import writes one DHCP Server for each enabled family of a
Server, named for example `kea1 DHCPv4` and `kea1 DHCPv6`. Each DHCP Server holds only the global configuration,
global DHCP Options, client classes and Option Definitions of its own daemon, and the Subnets and Reservations of its
family attach to it. A global value that Kea no longer declares is cleared on the next run. The first run after an
upgrade keeps the DHCP Server that an earlier release named after the Server, with its device, tags and comments, for
DHCPv4 (or for DHCPv6 on a DHCPv6-only Server). A new DHCP Server takes the device or virtual machine of the Server's
other DHCP Server when that one is already imported; after that, the device or virtual machine is yours to change.
Rows that the earlier release wrote for the other family move to that family's DHCP Server. The import links the interfaces that
Kea's `interfaces-config` names to the DHCP Server's device or virtual machine interfaces of those names. A name that
matches no interface is reported, and so are `*` and the address part of an entry such as `eth0/192.0.2.1`, which
the DHCP plugin cannot hold.

The import keeps a DHCP Import Mapping from each DHCP Server, Subnet, Pool, Reservation, client class and custom
Option Definition that it writes to its Kea source. A later run finds the object through its mapping and updates it. When you rename an
object, the mapping stays and the import keeps your name. A client class is the exception: it keeps its Kea name,
because Kea refers to a class by name. The first run after an upgrade maps each object that an earlier release
imported, so it makes no duplicate, and renames each client class from `kea1: voip` to `voip`. The DHCP plugin keeps
client class names unique across all DHCP Servers. So when another client class already holds the name, the class is
unsupported: a new class is not created, and an existing class keeps its old name while its other fields still
follow Kea. With netbox-plugin-dhcp 0.2.0, the family of a DHCP Server, the `server-id` parameters other than its
type, a global `user-context`, the `flex-id` Reservation identifier, `allow-address-registration` (DHCPv6) and
`stash-agent-options` (DHCPv4) are unsupported. The rest of the global configuration imports.

Each imported Subnet holds Kea's subnet ID. A Subnet that an earlier release imported takes its Kea subnet ID on the
next run. netbox-plugin-dhcp 0.2.0 keeps Subnet IDs unique across all DHCP Servers, but Kea numbers the Subnets of
each daemon on its own. So when another DHCP Server already holds the ID, for example the DHCPv4 Subnet 1 of a
dual-stack Server, the Subnet is unsupported, together with its Pools and In-Subnet Reservations. The entry names the
Subnet that holds the ID. The import never gives a Subnet another ID.

Each run of **Sync to DHCP plugin now** stores its result. The **DHCP Plugin** page under Sync shows the latest run:
the counts for each family, object kind and outcome, and one entry for each Kea fact that the run created, updated or
did not write. An entry names its fact by a Kea path, for example `Dhcp4/subnet4[id=20]/option-data[code=150]`. A
fact that the run did not write has a reason:

- **Unsupported**: the DHCP plugin cannot hold the fact. A later DHCP plugin release can remove this limit. When
  the installed release lacks a DHCP Plugin Capability that the fact needs, the entry names that capability and its
  row in the [DHCP plugin gap list](https://github.com/marcinpsk/netbox-kea-ng/issues/88). The import checks the
  installed models at each run, so a release that gains the capability imports the fact with no netbox-kea change.
- **Not imported**: the fact is out of scope (for example a Shared Network), the Kea data is not valid, or the DHCP
  plugin has no field for it by design.
- **Skipped**: the parent object was not imported, IPAM ownership kept the IP Range unchanged, a write failed, or
  Kea could not be read in full.

An object that did not change has no entry. A run that stops part way also stores its result, with an entry for the
family that stopped. NetBox keeps the 10 latest runs of each Server and deletes the older runs
when it stores a new one. Runs are not in the change log. A user who can view the Server can see its runs. When
NetBox cannot store a result, it logs the error and the import still completes. In a branch the import refuses and
stores no result.

Turning the switch off does not stop an import that already runs. While the switch is off, the sync can remove an
adopted object that would otherwise wait for an import, and turning the switch on again does not bring it back. An
import receipt that a Server already has stays valid when the switch goes on again, so the Server needs no new import.

Subnet lease searches use `stat-lease4-get` or `stat-lease6-get` before an
unpaged lease command. Kea statistics can reject a query that is already too
large. They cannot prove that an unqualified query is below the limit because
stored expired states are not included in all statistics. Select Active or
Declined to narrow a large query. Other states require an exact IP address or
client identifier search. The guard fails closed when the `stat_cmds` hook is
not available. State-filtered searches also fail closed when Kea does not
support the scoped state commands. Set the limit to `0` only when you accept
unbounded responses.

A Configuration Change holds a PostgreSQL advisory lock in an open transaction
for all of its Kea requests, up to and including the save to disk. A PostgreSQL
`idle_in_transaction_session_timeout` or a connection pooler timeout shorter than
the longest Configuration Change ends that transaction and releases the lock
while the change runs, so set these timeouts longer.

## Settings from `PLUGINS_CONFIG`

Earlier releases read these settings from `PLUGINS_CONFIG["netbox_kea"]`. `./manage.py migrate` copies each value
that is still there into the Settings page once, so an upgrade keeps it. A value of the wrong type or outside its
range stops the migration, and the error names the key, the allowed values, and the given value. After that, the
plugin ignores these keys, and the plugin logs a warning at startup for each key that is still set. Remove them from
the configuration and use the Settings page.
