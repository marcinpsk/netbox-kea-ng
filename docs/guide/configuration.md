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
| DHCP Plugin | Scheduled Import | Off | Each run of the periodic sync job also runs the DHCP Import of each Server that the DHCP plugin integration runs for |

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

With **Scheduled Import** on, each run of the periodic sync job runs the DHCP Import of each Server that the
integration runs for, after the IPAM sync of all Servers. It is the same import as **Sync to DHCP plugin now**, and it
stores its result with the trigger Scheduled. The reserved user `netbox-kea-sync` makes its changes.
**Sync Enabled (global)** and the IPAM sync settings do not stop it. A **Run Now** of one Server on the Sync Jobs page
syncs IPAM only. The job log shows the counts of each family of each Server. The import of a Server fails when Kea
does not give its configuration, when the configuration cannot be parsed, when a read or a write of one object fails,
or when the import stops. The job then records the failure, continues with the next Server, and ends as failed. When
another DHCP Import of a Server is running, the job skips that Server. When NetBox cannot dispatch the events of the
IPAM sync or of an import, the job stops. While a branch is active in the worker, the sync job fails before it reads
anything, so no import runs.

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

The import keeps a DHCP Import Mapping from each DHCP Server, Shared Network, Subnet, Pool, delegated-prefix Pool,
Reservation, client class and custom Option Definition that it writes to its Kea source. A later run finds the object through
its mapping and updates it.
Kea owns the managed fields of a mapped object. Each run sets every managed field from Kea. It clears a managed field
that Kea does not declare, so the DHCP plugin inherits its value. The next run overwrites a hand edit of a managed
field. The import does not change the other fields, such as tags, comments, description, status, weight, cluster and
the device or virtual machine. It also does not change an object without a mapping, such as a Pool or Reservation that
you add, or its DHCP Options. A Kea Subnet without a subnet ID has no mapping, and neither have its Pools and
delegated-prefix Pools. The import creates them, but a later run that finds a row without a mapping in their place
leaves that row, its DHCP Options and its Pools as they are, and reports the Kea object as not imported. A DHCP Option
has no mapping of its own. The import finds it by its object, the option space and code of its
Option Definition and its client classes. When no Option has the same client classes, the import takes an Option of the
same object, space and code that no other Kea option took, for example one that an earlier release wrote without
classes. When the definition of an option moves, for example from the global `option-def` to a client class, the
Option keeps its row and binds to the new definition. So a DHCP
Option that you add with another Option Definition stays. When you rename an object, the mapping stays and the import
keeps your name. A client class and a Shared Network are the exceptions: they keep their Kea name, because Kea refers to
them by name. The first run after an upgrade maps each object that an earlier release imported, so it makes no
duplicate. It also renames each client class from `kea1: voip` to `voip`. The DHCP plugin keeps client class and
Shared Network names unique across all DHCP Servers. So when another client class or Shared Network already holds the
name, the object is unsupported. A new object is not created. An existing object keeps its old name, and its other
fields still follow Kea. With netbox-plugin-dhcp 0.2.0, these
global facts are unsupported: the family of a DHCP Server, the `server-id` parameters other than its type, a global
`user-context`, the `flex-id` Reservation identifier, `allow-address-registration` (DHCPv6) and `stash-agent-options`
(DHCPv4). The rest of the global configuration imports. On a Subnet, the relay address list, `user-context` and the
DHCPv4-over-DHCPv6 keys (`4o6-subnet`, `4o6-interface`, `4o6-interface-id`) are unsupported, and so is the
`user-context` of a Pool or a delegated-prefix Pool. The rest of the Subnet, the Pool and the delegated-prefix Pool
imports. The DHCP plugin 0.2.0 keeps the relay as free text, which the import does not write, so a value that you
enter there stays.

The import writes each Kea Shared Network as a DHCP plugin Shared Network. The Shared Network gets its Kea name, its
Declared Values, its client classes, its additional classes, its interface and its DHCP Options. A Kea Shared Network
has no prefix, so the import never links a Prefix to a Shared Network. A Prefix that you set on an imported Shared
Network stays. Each member Subnet belongs to its Shared Network (`shared_network`), not to the DHCP Server
(`dhcp_server`). A member Subnet does not hold the values that it inherits from its Shared Network: the DHCP plugin
supplies them. When Kea moves a Subnet to another Shared Network, or out of one, the next run moves the Subnet.

netbox-plugin-dhcp 0.2.0 needs a Prefix for each Shared Network. So with that release, every Shared Network is
unsupported, and so are its DHCP Options. The entry names [gap 1](https://github.com/marcinpsk/netbox-kea-ng/issues/88).
The member Subnets then belong to the DHCP Server. The import reports each value that a member Subnet inherits from its
Shared Network. A DHCP plugin release that makes the Prefix optional imports the Shared Networks with no netbox-kea
change.

A Shared Network is also unsupported when another Shared Network holds its name, for example the Shared Network of the
same name in the other family. When a run does not write a Shared Network that the DHCP plugin can hold, for example
after a failed write, each member Subnet keeps its parent. A new member Subnet then belongs to the DHCP Server.

The import writes each DHCPv6 delegated-prefix Pool (`pd-pools`) as a Prefix Delegation Pool in its Subnet, with its
delegated length, `pool-id`, client classes, additional classes and DHCP Options. Its prefix and its excluded prefix
are NetBox Prefixes in the Server's `sync_vrf`. The import creates or links them as it does the Prefix of a Subnet,
under the IPAM source `pd-pool` and the marker `[kea-sync: pd pool]` (see [IPAM sync](ipam-sync.md)). The Subnet ID,
the prefix and the delegated length identify a delegated-prefix Pool, so a changed prefix or delegated length is a
new Pool. The DHCP plugin checks each Pool when the import saves it. When it refuses one, for example a delegated
length shorter than the prefix, the Pool is unsupported with the reason of the plugin, its DHCP Options are skipped,
and the run goes on. A delegated-prefix Pool that you add stays as it is, also when Kea has a Pool with the same
prefix: the import writes its own.

The import writes each Global and In-Subnet Reservation as a Host Reservation. The Host Reservation gets the
identifier (also a `flex-id`), the hostname, the addresses, the client classes and the DHCP Options of the
Reservation. A DHCPv4 Reservation also gives its boot fields `next-server`, `server-hostname` and `boot-file-name`.
A boot field that Kea does not set has no value. The delegated prefixes of
a DHCPv6 Reservation and the prefix that Kea excludes from each of them (`excluded-prefixes`) are NetBox Prefixes in
the Server's `sync_vrf`, linked as `ipv6_prefixes` and `excluded_ipv6_prefixes`. The import creates or links both
under the IPAM source `delegated-prefix` and the marker `[kea-sync: delegated prefix]`. When the claim of one of these
Prefixes fails, the Host Reservation keeps the Prefixes that it had. After the run removes the stale Reservations, it
drops the `delegated-prefix` link of each Prefix that no imported Reservation reports, and deprecates the Prefix when
the Server opts in (see [IPAM sync](ipam-sync.md)). When the run keeps a stale Reservation, it drops no such link.
The `user-context` of a Reservation is
unsupported with netbox-plugin-dhcp 0.2.0, and the rest of the Reservation imports.

The import writes every custom Option Definition that Kea declares, also one that no option uses, before it writes
any DHCP Option. A definition of the global `option-def` belongs to the DHCP Server. A definition of a client class
(`client-classes[].option-def`, DHCPv4 only) belongs to that client class and has its own mapping. The `user-context`
of a definition or a DHCP Option (Kea returns a `comment` as `user-context`) is unsupported with
netbox-plugin-dhcp 0.2.0. So are a definition in an option space other than `dhcp4`, `dhcp6` and
`vendor-specific-options-space` (for example `vendor-encapsulated-options-space` or `vendor-4491`), a DHCPv6 code
above 255, and a DHCP Option without an Option Definition that the DHCP plugin knows. A DHCP Option that needs an
unsupported definition is unsupported for the same reason. A DHCP Option keeps its Kea `client-classes` in its
`client_classes`. Two Kea options with the same code and other client classes are two DHCP Options. When a class of
the list has no client class that the same run imported, the DHCP Option is skipped: without the class, the DHCP
plugin would send the option to more clients.

The table lists the managed fields of each DHCP plugin model. A field behind a DHCP Plugin Capability is managed only
when the installed DHCP plugin has that capability. Without it, the import does not write or clear the field. It
reports the Kea value as unsupported. A Kea value that the DHCP plugin field cannot hold is also unsupported, for
example a percentage with four decimal places. That field keeps its value. The `client_classes` and
`evaluate_additional_classes` of a Shared Network, a Subnet, a Pool or a delegated-prefix Pool, and the
`client_classes` of a Host Reservation, refer to the client classes that the same run imported for the DHCP Server. The import reports a class
name without such a class and leaves it out. A class that Kea defines but that was not imported is skipped. A class that Kea does not define, for example the built-in
class `KNOWN`, is not imported.
The DHCP plugin keeps these relations unordered, so Kea's evaluation order of `evaluate-additional-classes` is lost.
A Subnet's or Shared Network's `interface` links the object to the DHCP Server interface of that name. The DHCP Server has that interface
when Kea's `interfaces-config` names it, or when you link it while Kea serves every interface (`*`). Otherwise the
interface is reported, with the reason: the DHCP Server has no device or virtual machine, it does not list the
interface, or its device or virtual machine has no interface of that name. The object then has no interface link, as
Kea owns the link. The import creates no interface. A Shared Network, Subnet or Pool class list that is not valid is
reported, and its class links stay as they are. A member Subnet of a Shared Network takes the interface of its Shared
Network in Kea. When the Shared Network is not imported, the import reports the interface as inherited.

| Model | Managed fields | Fields behind a capability |
| --- | --- | --- |
| `DHCPServer` | `valid_lifetime`, `min_valid_lifetime`, `max_valid_lifetime`, `preferred_lifetime`, `min_preferred_lifetime`, `max_preferred_lifetime`, `offer_lifetime`, `renew_timer`, `rebind_timer`, `match_client_id`, `authoritative`, `reservations_global`, `reservations_out_of_pool`, `reservations_in_subnet`, `calculate_tee_times`, `t1_percent`, `t2_percent`, `cache_threshold`, `cache_max_age`, `store_extended_info`, `allocator`, `pd_allocator`, `adaptive_lease_time_threshold`, `ddns_send_updates`, `ddns_override_no_update`, `ddns_override_client_update`, `ddns_replace_client_name`, `ddns_generated_prefix`, `ddns_qualifying_suffix`, `ddns_update_on_renew`, `ddns_conflict_resolution_mode`, `ddns_ttl_percent`, `ddns_ttl`, `ddns_ttl_min`, `ddns_ttl_max`, `hostname_char_set`, `hostname_char_replacement`, `next_server`, `server_hostname`, `boot_file_name`, `decline_probation_period`, `echo_client_id`, `relay_supplied_options`, `server_id`, `host_reservation_identifiers`, `device_interfaces`, `virtual_machine_interfaces` | `family` (`server_family`), `user_context` (`user_context`), `server_id_identifier` (`server_id_fields`), `server_id_enterprise_id` (`server_id_fields`), `server_id_htype` (`server_id_fields`), `server_id_time` (`server_id_fields`), `allow_address_registration` (`address_registration`), `stash_agent_options` (`stash_agent_options`) |
| `SharedNetwork` | `name`, `dhcp_server`, `valid_lifetime`, `min_valid_lifetime`, `max_valid_lifetime`, `preferred_lifetime`, `min_preferred_lifetime`, `max_preferred_lifetime`, `offer_lifetime`, `renew_timer`, `rebind_timer`, `match_client_id`, `authoritative`, `reservations_global`, `reservations_out_of_pool`, `reservations_in_subnet`, `calculate_tee_times`, `t1_percent`, `t2_percent`, `cache_threshold`, `cache_max_age`, `store_extended_info`, `allocator`, `pd_allocator`, `adaptive_lease_time_threshold`, `ddns_send_updates`, `ddns_override_no_update`, `ddns_override_client_update`, `ddns_replace_client_name`, `ddns_generated_prefix`, `ddns_qualifying_suffix`, `ddns_update_on_renew`, `ddns_conflict_resolution_mode`, `ddns_ttl_percent`, `ddns_ttl`, `ddns_ttl_min`, `ddns_ttl_max`, `hostname_char_set`, `hostname_char_replacement`, `next_server`, `server_hostname`, `boot_file_name`, `interface_id`, `rapid_commit`, `client_classes`, `evaluate_additional_classes`, `server_interfaces` | `relay` (`relay_address_list`), `user_context` (`user_context`) |
| `Subnet` | `prefix`, `dhcp_server`, `shared_network`, `subnet_id`, `valid_lifetime`, `min_valid_lifetime`, `max_valid_lifetime`, `preferred_lifetime`, `min_preferred_lifetime`, `max_preferred_lifetime`, `offer_lifetime`, `renew_timer`, `rebind_timer`, `match_client_id`, `authoritative`, `reservations_global`, `reservations_out_of_pool`, `reservations_in_subnet`, `calculate_tee_times`, `t1_percent`, `t2_percent`, `cache_threshold`, `cache_max_age`, `store_extended_info`, `allocator`, `pd_allocator`, `adaptive_lease_time_threshold`, `ddns_send_updates`, `ddns_override_no_update`, `ddns_override_client_update`, `ddns_replace_client_name`, `ddns_generated_prefix`, `ddns_qualifying_suffix`, `ddns_update_on_renew`, `ddns_conflict_resolution_mode`, `ddns_ttl_percent`, `ddns_ttl`, `ddns_ttl_min`, `ddns_ttl_max`, `hostname_char_set`, `hostname_char_replacement`, `next_server`, `server_hostname`, `boot_file_name`, `interface_id`, `rapid_commit`, `client_classes`, `evaluate_additional_classes`, `server_interfaces` | `relay` (`relay_address_list`), `dhcp4o6_subnet` (`dhcp4o6_subnet_selection`), `dhcp4o6_interface` (`dhcp4o6_subnet_selection`), `dhcp4o6_interface_id` (`dhcp4o6_subnet_selection`), `user_context` (`user_context`) |
| `Pool` | `subnet`, `ip_range`, `pool_id`, `ddns_send_updates`, `ddns_override_no_update`, `ddns_override_client_update`, `ddns_replace_client_name`, `ddns_generated_prefix`, `ddns_qualifying_suffix`, `ddns_update_on_renew`, `ddns_conflict_resolution_mode`, `ddns_ttl_percent`, `ddns_ttl`, `ddns_ttl_min`, `ddns_ttl_max`, `hostname_char_set`, `hostname_char_replacement`, `client_classes`, `evaluate_additional_classes` | `user_context` (`user_context`) |
| `PDPool` | `subnet`, `prefix`, `delegated_length`, `excluded_prefix`, `pool_id`, `client_classes`, `evaluate_additional_classes` | `user_context` (`user_context`) |
| `HostReservation` | `subnet`, `dhcp_server`, `hostname`, `hw_address`, `duid`, `circuit_id`, `client_id`, `flex_id`, `ipv4_address`, `next_server`, `server_hostname`, `boot_file_name`, `ipv6_addresses`, `ipv6_prefixes`, `excluded_ipv6_prefixes`, `client_classes` | `user_context` (`user_context`) |
| `Option` | `definition`, `data`, `csv_format`, `send_option`, `client_classes` | `space` (`option_without_definition`), `code` (`option_without_definition`), `user_context` (`user_context`) |
| `OptionDefinition` | `space`, `code`, `family`, `type`, `array`, `record_types`, `encapsulate`, `dhcp_server`, `client_class` | `user_context` (`user_context`) |
| `ClientClass` | `name`, `dhcp_server`, `test`, `template_test`, `only_in_additional_list`, `valid_lifetime`, `min_valid_lifetime`, `max_valid_lifetime`, `preferred_lifetime`, `min_preferred_lifetime`, `max_preferred_lifetime`, `next_server`, `server_hostname`, `boot_file_name` | `user_context` (`user_context`) |

Each imported Subnet holds Kea's subnet ID. A Subnet that an earlier release imported takes its Kea subnet ID on the
next run. netbox-plugin-dhcp 0.2.0 keeps Subnet IDs unique across all DHCP Servers, but Kea numbers the Subnets of
each daemon on its own. So when another DHCP Server already holds the ID, for example the DHCPv4 Subnet 1 of a
dual-stack Server, the Subnet is unsupported, together with its Pools, delegated-prefix Pools and In-Subnet
Reservations. The entry names the
Subnet that holds the ID. The import never gives a Subnet another ID.

Each run of **Sync to DHCP plugin now** stores its result. The **DHCP Plugin** page under Sync shows the latest run:
the counts for each family, object kind and outcome, and one entry for each Kea fact that the run created, updated,
removed or did not write. An entry names its fact by a Kea path, for example `Dhcp4/subnet4[id=20]/option-data[code=150]`. A
fact that the run did not write has a reason:

- **Unsupported**: the DHCP plugin cannot hold the fact. A later DHCP plugin release can remove this limit. When
  the installed release lacks a DHCP Plugin Capability that the fact needs, the entry names that capability and its
  row in the [DHCP plugin gap list](https://github.com/marcinpsk/netbox-kea-ng/issues/88). The import checks the
  installed models at each run, so a release that gains the capability imports the fact with no netbox-kea change.
- **Not imported**: the fact is out of scope (for example a value that a Subnet inherits from a Shared Network that
  was not imported), the Kea data is not valid, or the DHCP plugin has no field for it by design.
- **Skipped**: the parent object was not imported, IPAM ownership kept the IP Range unchanged, a write failed,
  Kea could not be read in full, or the run kept a stale object (see below).

A run removes each Stale DHCP Import Object: a mapped Shared Network, Subnet, Pool, delegated-prefix Pool,
Reservation, client class or custom Option Definition whose Kea source Kea no longer reports. A Pool whose range changes in Kea is a new Pool,
and so is a delegated-prefix Pool whose prefix or delegated length changes, so the run removes the old row and creates
a new one. The run removes an object only after it read every Kea object of that kind. When
the Server Configuration or the Reservation Snapshot was not read in full, the run keeps the objects of the kinds that
the read covers, and one skipped entry for each kind tells why and how many objects it kept. The run also keeps an
object when its removal would remove a DHCP plugin row that the run keeps, for example a Pool that an operator added
to a stale Subnet or a Subnet that an operator added to a stale Shared Network, when an Option still uses a stale Option Definition, or when a row that the run keeps names a
stale client class in its `client_classes` or `evaluate_additional_classes` (without the class, that row would reach
more clients). A DHCP Option of an object that the run removes goes with that object and keeps nothing. Before it
writes anything, the run finds the stale objects whose removal removes or changes no object that it keeps, so a kept
object leaves no change behind. Stale objects whose removals rely on each other are removed together or not at all. When a removal fails,
each stale object whose removal relies on it, directly or through other objects, is kept too. A removal deletes
the DHCP plugin row with its DHCP Options. It never deletes an IP address, a Prefix or an IP Range. The change log records each removal, and
the import needs the delete permission of each DHCP plugin model that it can remove.

The **Drift** card of the same page reads Kea after the page opens and compares it with the imported rows of each
mapped kind. It lists each missing object (Kea has it, NetBox has no imported row) and each stale object (the next run
removes it), with a count of the objects that are in step. When Kea was not read in full for a kind, the card shows
why, and it lists the imported rows that it did not see as not seen, never as stale. When Kea cannot be read, the card
shows the error and lists the imported rows as unknown. Its **Latest run** link opens the stored result of the last
run.

One run of a Server runs at a time. A second run of the same Server, while one runs, is refused before it reads Kea
and changes nothing; run it again when the first one has finished. The run holds a PostgreSQL session lock, so connect
NetBox to PostgreSQL directly or through a pooler in session mode. A pooler in transaction mode, such as PgBouncer
with `pool_mode = transaction`, can release the lock on a different server session, and the lock then refuses every
later run of the Server.

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
