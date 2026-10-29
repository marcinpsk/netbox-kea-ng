<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# netbox-kea-ng

[![PyPI](https://img.shields.io/pypi/v/netbox-kea-ng)](https://pypi.org/project/netbox-kea-ng/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/netbox-kea-ng)](https://pypi.org/project/netbox-kea-ng/)
[![CI](https://img.shields.io/github/actions/workflow/status/marcinpsk/netbox-kea-ng/ci.yml?branch=main&label=tests)](https://github.com/marcinpsk/netbox-kea-ng/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/marcinpsk/netbox-kea-ng/branch/main/graph/badge.svg)](https://codecov.io/gh/marcinpsk/netbox-kea-ng)
[![CodeQL](https://github.com/marcinpsk/netbox-kea-ng/actions/workflows/codeql.yml/badge.svg)](https://github.com/marcinpsk/netbox-kea-ng/actions/workflows/codeql.yml)
[![REUSE](https://api.reuse.software/badge/github.com/marcinpsk/netbox-kea-ng)](https://api.reuse.software/info/github.com/marcinpsk/netbox-kea-ng)
[![License](https://img.shields.io/github/license/marcinpsk/netbox-kea-ng)](https://github.com/marcinpsk/netbox-kea-ng/blob/main/LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/netbox-kea-ng)](https://pypi.org/project/netbox-kea-ng/)
[![NetBox](https://img.shields.io/badge/NetBox-%E2%89%A54.3.0-blue)](https://github.com/netbox-community/netbox)

> **Origin:** `netbox-kea-ng` started as a fork of
> [netbox-kea](https://github.com/devon-mar/netbox-kea) by
> [Devon Mar](https://github.com/devon-mar) and is now a separate project.
> It is published to PyPI as **`netbox-kea-ng`**.
> Issues and pull requests up to version 3.1.0 are in the archived repository
> [marcinpsk/netbox-kea](https://github.com/marcinpsk/netbox-kea).
> Upstream changes are merged where applicable.

NetBox plugin for the [Kea DHCP](https://www.isc.org/kea/) server. Manage your DHCP infrastructure directly from NetBox — view daemon status, search and manage leases, manage host reservations, configure subnets/pools/options, and keep your NetBox IPAM synchronized with live Kea data via a background job.

The full documentation is at **[marcinpsk.github.io/netbox-kea-ng](https://marcinpsk.github.io/netbox-kea-ng/)**.

![A lease search in NetBox: Sync on a lease writes a NetBox IP address, and the Synced link opens it with the sync marker in the description](https://marcinpsk.github.io/netbox-kea-ng/assets/recordings/sync-lease.gif)

## Features

- Kea DHCPv4 and DHCPv6 daemon status, with enable and disable controls.
- Lease search, add, edit, delete, CSV import and export, with links to NetBox devices and VMs.
- Host Reservation management, with YAML or JSON bulk transfer.
- Subnet, pool, shared network and DHCP option editing.
- IPAM sync of leases, reservations, subnets and pools, by hand or in a periodic background job.
- Combined Overview, Reservation, Subnet and Shared Network views in a Server Scope.
- A Server chooser for lease search.
- Direct connections to each Kea 3.0+ daemon, or a Control Agent (removed in Kea 3.1.8).
- REST API and GraphQL for Server objects. Works with netbox-dns and netbox-branching.

## Compatibility

| netbox-kea-ng | NetBox | Kea |
|---|---|---|
| 3.x | 4.3 – 4.7 | 3.0+ recommended (2.4+ via Control Agent) |

Lease search needs the Kea `lease_cmds` hook. Other hooks are optional. See [Requirements](https://marcinpsk.github.io/netbox-kea-ng/installation/#requirements).

## Quick install

```bash
pip install netbox-kea-ng
```

In `configuration.py`:

```python
PLUGINS = ["netbox_kea"]
```

Then run the migrations, and start `rqworker` for the periodic sync:

```bash
./manage.py migrate
./manage.py rqworker
```

All runtime settings are on the **Settings** page (**DHCP Kea > Settings**), and a change needs no restart. The
plugin takes no `PLUGINS_CONFIG` settings: `migrate` copies the values of an earlier release once, then the plugin logs
a warning for each key that is still set. See [Configuration](https://marcinpsk.github.io/netbox-kea-ng/configuration/).

## Documentation

- [Installation](https://marcinpsk.github.io/netbox-kea-ng/installation/) and [Configuration](https://marcinpsk.github.io/netbox-kea-ng/configuration/)
- [Kea Servers](https://marcinpsk.github.io/netbox-kea-ng/servers/): single URL, dual URL and credentials
- [IPAM Sync](https://marcinpsk.github.io/netbox-kea-ng/ipam-sync/): background sync, permissions and upgrade notes
- [DHCP Import](https://marcinpsk.github.io/netbox-kea-ng/dhcp-import/): copy a Server into the NetBox DHCP plugin
- [Leases, Reservations and Subnets](https://marcinpsk.github.io/netbox-kea-ng/leases-reservations/)
- [Event rules and webhooks](https://marcinpsk.github.io/netbox-kea-ng/event-rules/), [DNS](https://marcinpsk.github.io/netbox-kea-ng/dns/) and [Custom links](https://marcinpsk.github.io/netbox-kea-ng/custom-links/)
- [netbox-branching](https://marcinpsk.github.io/netbox-kea-ng/branching/)
- [Development](https://marcinpsk.github.io/netbox-kea-ng/development/) and the [Changelog](https://marcinpsk.github.io/netbox-kea-ng/changelog/)

## License

[Apache-2.0](https://github.com/marcinpsk/netbox-kea-ng/blob/main/LICENSE). Original code by [Devon Mar](https://github.com/devon-mar), maintained by [Marcin Zieba](https://github.com/marcinpsk).
