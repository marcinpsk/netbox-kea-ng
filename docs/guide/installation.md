<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Installation

## Requirements

- NetBox 4.3 – 4.7
- Kea 3.0+ (recommended) — the plugin connects directly to each daemon's built-in HTTP control socket (`kea-dhcp4` / `kea-dhcp6`). The [Kea Control Agent](https://kea.readthedocs.io/en/latest/arm/agent.html) was deprecated in Kea 3.0 and removed in Kea 3.1.8. Before Kea 3.0, point the server URL at the Control Agent; Kea 3.0 supports both.
- [`lease_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#hooks-lease-cmds) hook library (for lease search and management)
- [`stat_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#hooks-stat-cmds) hook library (for guarded Subnet lease searches unless **Max Unpaged Leases** on the Settings page is `0`)
- Kea 3.1.5+ for state-filtered Subnet lease searches. Earlier releases do not provide the scoped state commands, so these searches fail closed.
- [`host_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#hooks-host-cmds) hook library (optional, for reservation management; it also requires `subnet_cmds` to resolve a reservation's subnet from its CIDR). The plugin finds it in `hooks-libraries`: the library file name must be `libdhcp_host_cmds` followed by an extension, for example `libdhcp_host_cmds.so`.
- [`subnet_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#hooks-subnet-cmds) hook library (optional, for subnet add/edit/delete, reservation management, and the subnet suggestions on the lease search and reservation forms)

The plugin degrades gracefully when optional hooks are absent — tabs for unavailable features are hidden automatically. Two pages offer the server's configured subnets as suggestions and read them through `subnet_cmds`; without that hook each says so in a banner rather than silently offering nothing:

- **Lease search** keeps working: the Search field offers no subnet suggestions, so type an exact configured subnet CIDR or ID.
- **Add reservation** cannot save, because resolving the entered CIDR to a Kea subnet ID needs `subnet_cmds`. Load the hook first.

## Compatibility

| netbox-kea-ng | NetBox | Kea |
|---|---|---|
| 3.x | 4.3 – 4.7 | 3.0+ recommended (2.4+ via Control Agent) |

The plugin talks directly to each DHCP daemon's HTTP control socket (Kea 3.0 and later), or connects through a Control Agent (deprecated in Kea 3.0 and removed in Kea 3.1.8). CI tests against **Kea 3.2.0** using the `memfile` lease database.

For netbox-branching, see [netbox-branching](branching.md).

## Install the plugin

### 1. Install the package

Add `netbox-kea-ng` to your `local_requirements.txt` (or install with pip):

```bash
pip install netbox-kea-ng
```

### 2. Enable the plugin

In `configuration.py`:

```python
PLUGINS = ["netbox_kea"]
```

After the migrations, change the plugin settings on the **Settings** page (see [Configuration](configuration.md)).
The plugin takes no `PLUGINS_CONFIG` settings.

### 3. Run migrations

```bash
./manage.py migrate
```

### 4. Start the background worker (required for periodic sync)

The periodic IPAM sync job runs via NetBox's built-in `rqworker`. If you're not already running it:

```bash
./manage.py rqworker
```

The `Kea IPAM Sync` job will appear under **System → Background Jobs** and runs on the configured interval.
