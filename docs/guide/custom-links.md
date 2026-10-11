<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Custom Links

Add custom links to NetBox models to navigate directly to Kea lease searches.

Replace `<Kea Server ID>` with your server's object ID (visible in the top-right corner of the server detail page as `netbox_kea.server:<ID>`).

## Show DHCP leases for a prefix

**Content type**: `IPAM > Prefix`

**URL**: `https://netbox.example.com/plugins/kea/servers/<Kea Server ID>/leases{{ object.prefix.version }}/?q={{ object.prefix }}&by=subnet`

## Show DHCPv4 leases for a device/VM interface (by MAC)

**Content types**: `DCIM > Interface`, `Virtualization > Interface`

**DHCPv4 URL**: `https://netbox.example.com/plugins/kea/servers/<Kea Server ID>/leases4/?q={{ object.mac_address }}&by=hw`

Kea has no DHCPv6 lease search by MAC address. To find a DHCPv6 lease by client identifier, search by DUID.

## Show DHCP leases for a device/VM (by hostname)

**Content types**: `DCIM > Device`, `Virtualization > Virtual Machine`

**DHCPv4 URL**: `https://netbox.example.com/plugins/kea/servers/<Kea Server ID>/leases4/?q={{ object.name|lower }}&by=hostname`

**DHCPv6 URL**: `https://netbox.example.com/plugins/kea/servers/<Kea Server ID>/leases6/?q={{ object.name|lower }}&by=hostname`

You can substitute `{{ object.name|lower }}` with a custom field: `{{ object.cf.<your_field>|lower }}`.
