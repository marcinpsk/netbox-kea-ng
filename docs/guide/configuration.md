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
| Display Cache | Leases TTL (seconds) | `30` | How long a page shows cached Leases. `0` turns off caching for them. The Lease pages do not use the cache yet |
| Display Cache | Utilization and Status TTL (seconds) | `15` | How long a page shows cached utilization and daemon status. `0` turns off caching for them. These pages do not use the cache yet |
| DHCP Plugin | Integration Enabled (global) | On | Global switch. Clear it to stop the DHCP plugin integration for all Servers. The section shows only when the NetBox DHCP plugin (`netbox_dhcp`) is installed |

A section shows to a user with the view permission of its model (`netbox_kea.view_syncconfig`,
`netbox_kea.view_keaclientconfig`, `netbox_kea.view_displaycacheconfig`, `netbox_kea.view_dhcpintegrationconfig`). A save needs the change permission of the model too. Without it, the section
shows the values read-only. Each save writes a change log record. While a branch is active, the page refuses a save.

A save of the Display Cache section makes every cached entry unused, also when no value changes. A change that the
plugin sends to Kea makes the cached entries that the change affects unused at once. A change from outside this NetBox, such as
kea-shell or an HA partner, shows when the TTL of the entry ends, or after a Refresh. This also applies to a change
through another Server record that points at the same daemon: a change resets only the entries of the Server that sent it. A Reservations table shows the
age of its read ("Read 42 s ago") and a **Refresh** button, which reads Kea again for that table. On a page of all
Servers, the age is the age of the oldest read, and Refresh reads each Server again.

The DHCP plugin integration runs for a Server only when the NetBox DHCP plugin is installed, the Server has
**Sync to DHCP plugin** on, and **Integration Enabled (global)** is on. When one of them is off, the Server has no
**DHCP Plugin** subsection under Sync, **Sync to DHCP plugin now** refuses, and the IPAM sync does not wait for a
DHCP plugin import before it removes an adopted object. Objects that DHCP plugin records refer to stay protected from
stale cleanup while the switch is off.

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
