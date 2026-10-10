<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# netbox-kea-ng

> **Origin:** `netbox-kea-ng` started as a fork of
> [netbox-kea](https://github.com/devon-mar/netbox-kea) by
> [Devon Mar](https://github.com/devon-mar) and is now a separate project.
> It is published to PyPI as **`netbox-kea-ng`**.
> Issues and pull requests up to version 3.1.0 are in the archived repository
> [marcinpsk/netbox-kea](https://github.com/marcinpsk/netbox-kea).
> Upstream changes are merged where applicable.

NetBox plugin for the [Kea DHCP](https://www.isc.org/kea/) server. Manage your DHCP infrastructure directly from NetBox — view daemon status, search and manage leases, manage host reservations, configure subnets/pools/options, and keep your NetBox IPAM synchronized with live Kea data via a background job.

## Features

### Core (from upstream)

- View Kea daemon status (DHCPv4/DHCPv6 daemons, and the Control Agent before Kea 3.1.8)
- Full DHCPv4 and DHCPv6 support
- Search, view, delete and export DHCP leases
- Search for NetBox devices/VMs directly from DHCP leases
- View DHCP subnets from Kea configuration
- REST API and GraphQL support for Server objects

### Additions in this fork

- [Host Reservations](leases-reservations.md#host-reservations): full DHCPv4 and DHCPv6 reservation management, with
  YAML or JSON bulk transfer
- [Subnet Management](leases-reservations.md#subnet-management): subnets, pools, shared networks and DHCP options
- [Lease add, edit, delete and bulk import](leases-reservations.md#lease-add-edit-delete-bulk-import)
- [IPAM Sync](ipam-sync.md): leases, reservations, subnets and pools to NetBox IPAM, by hand or in a periodic
  background job
- [Server connection validation and dual-URL servers](servers.md)
- [netbox-branching](branching.md) support, [event rules](event-rules.md) and [DNS integration](dns.md)

**DHCP Control**

- Enable/disable DHCPv4 and DHCPv6 daemons from the NetBox UI

**Global / Cross-Server Views**

- Combined Overview, Reservation, Subnet and Shared Network views in a Server Scope
- A Server chooser for lease search, with each search on one named Server

![The combined view lists each Kea Server with its endpoint URLs and the online state of each DHCP daemon](assets/screenshots/combined-dashboard-light.png#only-light)
![The combined view lists each Kea Server with its endpoint URLs and the online state of each DHCP daemon](assets/screenshots/combined-dashboard-dark.png#only-dark)

## License

[Apache-2.0](https://github.com/marcinpsk/netbox-kea-ng/blob/main/LICENSE). Original code by [Devon Mar](https://github.com/devon-mar), maintained by [Marcin Zieba](https://github.com/marcinpsk).
