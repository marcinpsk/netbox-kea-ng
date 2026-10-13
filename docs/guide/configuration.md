<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Configuration

All settings are under `PLUGINS_CONFIG["netbox_kea"]`:

| Setting | Default | Description |
|---|---|---|
| `kea_timeout` | `30` | HTTP request timeout in seconds for Kea API calls |
| `lease_query_max_unpaged_leases` | `1000` | Reject an unpaged Subnet lease query when its Kea statistics count exceeds this limit. Set to `0` to disable this safety check |
| `stale_ip_cleanup` | `"remove"` | What to do with stale IPs after sync: `"remove"` (delete), `"deprecate"` (set status=deprecated), `"none"` (skip) |
| `sync_interval_minutes` | `5` | Initial interval of the background sync job (minutes). Edit it later on the **Settings** page |
| `sync_enabled` | `True` | Initial state of the global sync switch. Edit it later on the **Settings** page |
| `sync_leases_enabled` | `True` | Sync current DHCP address leases to NetBox IPAM. With `sync_prefixes_enabled`, also DHCPv6 delegated-prefix leases as Prefixes |
| `sync_reservations_enabled` | `True` | Sync Kea reservations to NetBox IPAM |
| `sync_prefixes_enabled` | `True` | Sync Kea subnets to NetBox IPAM as IP Prefixes. With `sync_leases_enabled`, also DHCPv6 delegated-prefix leases |
| `sync_ip_ranges_enabled` | `True` | Sync Kea pools to NetBox IPAM as IP Ranges |
| `sync_max_leases_per_server` | `50000` | Hard cap on leases fetched per server per sync run. Set to `0` for no limit |

NetBox refuses to start when one of these settings has a value of the wrong type or outside its range.
The error names the setting, the allowed values, and the given value. A number must be an integer, not a string
or a boolean. `kea_timeout` must be at least 1, `sync_interval_minutes` must be from 1 to 1440, and the other
numbers must be at least 0.

`./manage.py migrate` reads `sync_interval_minutes`, `sync_enabled` and the four `sync_*_enabled`
toggles once, when it creates the Sync Configuration. After that, the **Settings** page holds these values,
and a later change to these settings in `PLUGINS_CONFIG` has no effect.

The **Settings** page shows the Sync Configuration to a user with the `netbox_kea.view_syncconfig` permission.
A save needs `netbox_kea.change_syncconfig`. Without it, the page shows the values read-only. Each save writes a
change log record. While a branch is active, the page refuses a save.

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
