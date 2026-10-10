<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# DNS Integration

When [netbox-dns](https://github.com/peteeckel/netbox-plugin-dns) with IPAMDNSsync is installed:

1. The IPAM sync sets `dns_name` on `IPAddress` objects from the name that Kea publishes (see [Background IPAM Sync](ipam-sync.md#background-ipam-sync))
2. IPAMDNSsync picks up `dns_name` changes via Django signals
3. A/AAAA/PTR records are created automatically (provided matching DNS views + zones exist)

No additional configuration is required — the integration is automatic when both plugins are present.
