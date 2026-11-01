<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# DHCP Import

The DHCP Import copies the Kea configuration and the Reservations of one Server into the NetBox DHCP plugin
([netbox-plugin-dhcp](https://github.com/sys4/netbox-plugin-dhcp)). It is a one-way copy: it reads Kea and never
writes to Kea.

The DHCP Import needs netbox-plugin-dhcp 0.2.0 or later. With an older release installed, **Sync to DHCP plugin now**
refuses before it reads Kea, names the required version, and changes nothing. The scheduled import also refuses before
it reads Kea. The job records the failure, continues with the next Server, and ends as failed.

## When the import runs

The DHCP plugin integration runs for a Server only when the NetBox DHCP plugin is installed, the Server has
**Sync to DHCP plugin** on, and **Integration Enabled (global)** is on (see [Configuration](configuration.md)). When
one of them is off, the Server has no **DHCP Plugin** subsection under Sync, **Sync to DHCP plugin now** refuses, and
the IPAM sync does not wait for a DHCP plugin import before it removes an adopted object. Objects that DHCP plugin
records refer to stay protected from stale cleanup while the switch is off.

Turning the switch off does not stop an import that already runs. While the switch is off, the sync can remove an
adopted object that would otherwise wait for an import, and turning the switch on again does not bring it back. An
import receipt that a Server already has stays valid when the switch goes on again, so the Server needs no new import.

### Manual runs

**Sync to DHCP plugin now** on the **DHCP Plugin** page under Sync runs the import of the Server. The permissions that
it needs are in [IPAM Sync](ipam-sync.md#manual-sync-permissions).

One run of a Server runs at a time. A second run of the same Server, while one runs, is refused before it reads Kea
and changes nothing; run it again when the first one has finished. The run holds a PostgreSQL session lock, so connect
NetBox to PostgreSQL directly or through a pooler in session mode. A pooler in transaction mode, such as PgBouncer
with `pool_mode = transaction`, can release the lock on a different server session, and the lock then refuses every
later run of the Server.

In a branch the import refuses and stores no result.

### Scheduled runs

With **Scheduled Import** on, each run of the periodic sync job runs the DHCP Import of each Server that the
integration runs for, before the IPAM sync of all Servers. It is the same import as **Sync to DHCP plugin now**, and it
stores its result with the trigger Scheduled. The reserved user `netbox-kea-sync` makes its changes.
**Sync Enabled (global)** and the IPAM sync settings do not stop it. A **Run Now** of one Server on the Sync Jobs page
syncs IPAM only. When the IPAM sync runs before the import removes the record of a removed Kea Subnet, Pool or
Reservation, for example in a **Run Now**, or with **Scheduled Import** off and a later **Sync to DHCP plugin now**,
its Prefix, IP Range or IP address stays and has no owner. The import attaches the address of a Global Reservation
only when NetBox already has it, so an address that the lease sync adds is attached in the next run.
The job log shows the counts of each family of each Server. The import of a Server fails when Kea
does not give its configuration, when the configuration cannot be parsed, when a read or a write of one object fails,
or when the import stops. The job then records the failure, continues with the next Server, and ends as failed. When
another DHCP Import of a Server is running, the job skips that Server. When NetBox cannot dispatch the events of the
IPAM sync or of an import, the job stops. While a branch is active in the worker, the sync job fails before it reads
anything, so no import runs.

## What it imports

Kea runs DHCPv4 and DHCPv6 as separate daemons, so the import writes one DHCP Server for each enabled family of a
Server, named for example `kea1 DHCPv4` and `kea1 DHCPv6`. Each DHCP Server holds only the global configuration,
global DHCP Options, client classes and Option Definitions of its own daemon, and the Subnets and Reservations of its
family attach to it. A global value that Kea no longer declares is cleared on the next run. The first run after an
upgrade keeps the DHCP Server that an earlier release named after the Server, with its device, tags and comments, for
DHCPv4 (or for DHCPv6 on a DHCPv6-only Server). A new DHCP Server takes the device or virtual machine of the Server's
other DHCP Server when that one is already imported; after that, the device or virtual machine is yours to change.
Rows that the earlier release wrote for the other family move to that family's DHCP Server. The import links the
interfaces that Kea's `interfaces-config` names to the DHCP Server's device or virtual machine interfaces of those
names. A name that matches no interface is reported, and so are `*` and the address part of an entry such as
`eth0/192.0.2.1`, which the DHCP plugin cannot hold.

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
the Server opts in (see [IPAM sync](ipam-sync.md)). When a Reservation that Kea no longer reports stays in NetBox,
the run drops no such link.

The import writes every custom Option Definition that Kea declares, also one that no option uses, before it writes
any DHCP Option. A definition of the global `option-def` belongs to the DHCP Server. A definition of a client class
(`client-classes[].option-def`, DHCPv4 only) belongs to that client class and has its own mapping. A DHCP Option keeps
its Kea `client-classes` in its `client_classes`. Two Kea options with the same code and other client classes are two
DHCP Options. When a class of the list has no client class that the same run imported, the DHCP Option is skipped:
without the class, the DHCP plugin would send the option to more clients.

The `client_classes` and `evaluate_additional_classes` of a Shared Network, a Subnet, a Pool or a delegated-prefix
Pool, and the `client_classes` of a Host Reservation, refer to the client classes that the same run imported for the
DHCP Server. The import reports a class name without such a class and leaves it out. A class that Kea defines but that
was not imported is skipped. A class that Kea does not define, for example the built-in class `KNOWN`, is not
imported. The DHCP plugin keeps these relations unordered, so Kea's evaluation order of `evaluate-additional-classes`
is lost. A Subnet's or Shared Network's `interface` links the object to the DHCP Server interface of that name. The
DHCP Server has that interface when Kea's `interfaces-config` names it, or when you link it while Kea serves every
interface (`*`). Otherwise the interface is reported, with the reason: the DHCP Server has no device or virtual
machine, it does not list the interface, or its device or virtual machine has no interface of that name. The object
then has no interface link, as Kea owns the link. The import creates no interface. A Shared Network, Subnet or Pool
class list that is not valid is reported, and its class links stay as they are. A member Subnet of a Shared Network
takes the interface of its Shared Network in Kea. When the Shared Network is not imported, the import reports the
interface as inherited.

Some Kea settings have no DHCP plugin field by design, for example `lease-database`, `hooks-libraries`, `loggers` and
the socket settings of `interfaces-config`. The import reports each one that Kea returns as not imported.

### Mappings and managed fields

The import keeps a DHCP Import Mapping from each DHCP Server, Shared Network, Subnet, Pool, delegated-prefix Pool,
Reservation, client class, custom Option Definition and DHCP Option that it writes to its Kea source. A later run
finds the object through its mapping and updates it.
Kea owns the managed fields of a mapped object. Each run sets every managed field from Kea. It clears a managed field
that Kea does not declare, so the DHCP plugin inherits its value. The next run overwrites a hand edit of a managed
field. The import does not change the other fields, such as tags, comments, description, status, weight, cluster and
the device or virtual machine. It also does not change an object without a mapping, such as a Pool or Reservation that
you add, or its DHCP Options. Kea refuses a Subnet without a subnet ID, so the import reports such a Subnet entry as
invalid Kea data. It does not import the Subnet, its Pools, its delegated-prefix Pools or their DHCP Options.

The mapping of a DHCP Option holds the Kea source of its object and the identity of the option in that object: the
option space, the code and the set of client classes. A Kea object can assign one identity more than once. Each one
then has its own mapping, in Kea order. A Kea option whose client classes change has a new identity. So the run
creates a new DHCP Option and removes the old one. When the definition of an option moves, for example from the global
`option-def` to a client class, the Option keeps its row and binds to the new definition.

A DHCP Option that you add to an imported object has no mapping. The run does not change it and does not remove it.
A Kea option without a mapped Option gets a new DHCP Option. Only the upgrade is an exception. Each imported object
takes the Options without a mapping once: on the first run that reaches it after the upgrade. Then a Kea option
without a mapped Option takes an Option without a mapping of the same object. It takes one with the same space, code
and client classes first. Then it takes one with the same space and code, for example one that an earlier release
wrote without classes. The run maps each Option that it takes before it writes it, so a write that fails keeps the
mapping, and the next run updates the same Option. Then the mapping of the object records that its Options are mapped,
whatever the writes do, and the object takes no unmapped Option again. The exception is an Option that waits for a
custom Option Definition that failed to write, or for a client class that Kea defines and this run did not import. Then
the run does not record it, and the next run takes Options without a mapping again. The global configuration, client classes,
Shared Networks, Subnets, Pools, delegated-prefix Pools and Reservations take them this way. A run that cannot read the
Reservations does not reach them, so a later run that reads them maps their Options.
A branch revert keeps the fact that the Options of an object are mapped, as main recorded it. When change log retention
has removed the change log entry of the merge, the revert restores that fact from the branch, so the restored object can
take Options without a mapping again.

A mapping has no length limit. So a DHCP Option with many long client class names also has a mapping, and a run
updates and removes it as any other DHCP Option.

When you rename an object, the mapping stays and the import keeps your name. A client class and a Shared
Network are the exceptions: they keep their Kea name, because Kea refers to them by name. The first run after an
upgrade maps each object that an earlier release imported, so it makes no duplicate. It also renames each client
class from `kea1: voip` to `voip`.

The table lists the managed fields of each DHCP plugin model. A field behind a DHCP Plugin Capability is managed only
when the installed DHCP plugin has that capability. Without it, the import does not write or clear the field. It
reports the Kea value as unsupported. A Kea value that the DHCP plugin field cannot hold is also unsupported, for
example a percentage with four decimal places. That field keeps its value.

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

## Unsupported facts and DHCP Plugin Capabilities

The import plans every Kea fact as if the DHCP plugin could hold it. Before it writes a fact, it checks the DHCP
Plugin Capability that the fact needs. When the installed DHCP plugin does not have that capability, the fact is
unsupported: the run reports it with the capability and its row in the
[DHCP plugin gap list](https://github.com/marcinpsk/netbox-kea-ng/issues/88), and the rest of the object and of the
run imports. With netbox-plugin-dhcp 0.2.0, the plugin has none of these capabilities.

The import reads the models of the installed DHCP plugin at each run: their fields, field types, choices, validators,
nullability and uniqueness constraints. It also lets the plugin check samples of option data that Kea accepts. It does not compare version numbers, so a fork or a backport with the change
also counts. When you upgrade to a DHCP plugin release that gains a capability, the next run imports the facts that
need it. No netbox-kea upgrade is necessary.

| Capability | Name | #88 gap | Kea facts that need it |
| --- | --- | --- | --- |
| `shared_network_optional_prefix` | Shared Network without one enclosing Prefix | 1 | Each Shared Network, its DHCP Options and the membership of its Subnets (see [Shared Networks](#shared-networks)) |
| `subnet_id_per_server` | Subnet ID unique per DHCP server | 2 | A Subnet whose Kea subnet ID another DHCP Server holds, with its Pools, delegated-prefix Pools and In-Subnet Reservations |
| `name_per_server` | Name unique per DHCP server | 3 | A client class or a Shared Network whose name another DHCP Server holds |
| `server_family` | DHCP server address family | 4 | The family of each DHCP Server |
| `flex_id_identifier` | flex-id Reservation identifier | 5 | `flex-id` in `host-reservation-identifiers` |
| `user_context` | User context | 6 | The `user-context` of the global configuration, a Shared Network, a Subnet, a Pool, a delegated-prefix Pool, a Reservation, a client class, an Option Definition and a DHCP Option. Kea returns a `comment` as `user-context` |
| `option_spaces` | Kea option space names | 7 | An Option Definition or a DHCP Option in an option space that the DHCP plugin does not list. netbox-plugin-dhcp 0.2.0 lists `dhcp4`, `dhcp6` and `vendor-specific-options-space`, so for example `vendor-encapsulated-options-space` and `vendor-4491` need it |
| `option_code_16_bit` | DHCPv6 option codes above 255 | 8 | A DHCPv6 Option Definition or DHCP Option with a code above 255 |
| `option_without_definition` | DHCP Option without an Option Definition | 9 | A DHCP Option without an Option Definition that the DHCP plugin knows |
| `server_id_fields` | Full server-id | 10 | The DHCPv6 `server-id` parameters other than its type, when Kea does not generate them |
| `relay_address_list` | Relay address list | 11 | The `relay` of a Subnet or a Shared Network |
| `dhcp4o6_subnet_selection` | DHCPv4-over-DHCPv6 Subnet selection | 12 | `4o6-subnet`, `4o6-interface` and `4o6-interface-id` of a DHCPv4 Subnet |
| `address_registration` | Address registration | 13 | `allow-address-registration` (DHCPv6) |
| `stash_agent_options` | Stashed relay agent options | 14 | `stash-agent-options` (DHCPv4) |
| `kea_option_data` | DHCP Option data in each form that Kea accepts | 17 | A DHCP Option whose data netbox-plugin-dhcp 0.2.0 refuses. The plugin checks each value of the data against the type of the Option Definition by its own rules, and it does not read `csv-format`. So it refuses for example hexadecimal data with `csv-format: false` (except for the binary and string types, and digits that it reads as a value of the type), a boolean `1` or `0`, an integer in hexadecimal (`0x10`), a single-label FQDN, tuple data that is not JSON, and a value with spaces around it, which Kea removes. The import runs the data check of the plugin before it writes the Option. If the data check fails with an error that is not a refusal, the Option is `write_failed`. A write that fails for a different reason, for example a custom validator, is also `write_failed` |

A DHCP Option that needs an unsupported Option Definition is unsupported for the same reason. The DHCP plugin 0.2.0
keeps the relay as free text, which the import does not write, so a value that you enter there stays.

## The run result

Each run, from **Sync to DHCP plugin now** or the scheduled import, stores its result with its trigger. The **DHCP
Plugin** page under Sync shows the latest run of either trigger: the counts for each family, object kind and outcome, and one entry for each Kea fact that the run created, updated, removed or did not write. An
entry names its fact by a Kea path, for example `Dhcp4/subnet4[id=20]/option-data[code=150]`. An object that did not
change has no entry. A run that stops part way also stores its result, with an entry for the family that stopped.
NetBox keeps the 10 latest runs of each Server and deletes the older runs when it stores a new one. Runs are not in
the change log. A user who can view the Server can see its runs. When NetBox cannot store a result, it logs the error
and the import still completes.

A fact that the run did not write has a reason code. The reason gives the outcome:

- **Unsupported**: the installed DHCP plugin cannot hold the fact. A later DHCP plugin release can remove this limit.
- **Not imported**: the import leaves the fact out by design, or the Kea data is not valid.
- **Skipped**: this run did not write the fact because of another object, a failure or an incomplete read.

| Reason code | Outcome | Shown as |
| --- | --- | --- |
| `plugin_gap` | Unsupported | The DHCP plugin cannot hold it |
| `subnet_id_clash` | Unsupported | Another Server or family holds this Subnet ID |
| `not_in_scope` | Not imported | Not in scope |
| `inherited_from_shared_network` | Not imported | Inherited from a Shared Network |
| `no_matching_interface` | Not imported | No matching interface |
| `invalid_kea_data` | Not imported | Invalid Kea data |
| `no_plugin_home` | Not imported | No DHCP plugin field by design |
| `parent_not_imported` | Skipped | Its parent object was not imported |
| `ipam_ownership` | Skipped | IPAM ownership kept the IPAM object unchanged |
| `write_failed` | Skipped | The write failed |
| `read_failed` | Skipped | Kea could not be read in full |
| `incomplete_observation` | Skipped | Kea was not observed in full, so removal was suppressed |
| `removal_blocked` | Skipped | Other rows still depend on it, so it was not removed |

## Declared Values and inheritance

The import writes only the Declared Values of a Shared Network, a Subnet, a Pool, a delegated-prefix Pool and a client
class: the values that the object sets for itself. The DHCP plugin supplies the rest through its own inheritance.

Kea's `config-get` reply also holds values that an object inherits. It copies some keys, for example the lifetimes and
the timers, from the global configuration into a Shared Network, and from the Shared Network (or else the global
configuration) into a Subnet. The import counts such a value as inherited when it is equal to the value of the parent.
So a Subnet value that you set to the same value as its parent is not imported, and the DHCP plugin shows the
inherited value, which is the same. Kea also returns its own default for some keys that no level declares, for example
an empty `relay`. The import counts such a value as inherited when the parent has no value. The DHCP Server holds the
global configuration, so it gets every global value that Kea returns.

A member Subnet does not hold the values that it inherits from its Shared Network. When the DHCP plugin cannot hold
the Shared Network, the import reports each value that a member Subnet inherits from it, with the reason
`inherited_from_shared_network`. It never copies the value onto the Subnet, so a later import of the Shared Network
finds no false override.

## Shared Networks

The import writes each Kea Shared Network as a DHCP plugin Shared Network. The Shared Network gets its Kea name, its
Declared Values, its client classes, its additional classes, its interface and its DHCP Options. A Kea Shared Network
has no prefix, so the import never links a Prefix to a Shared Network. A Prefix that you set on an imported Shared
Network stays. Each member Subnet belongs to its Shared Network (`shared_network`), not to the DHCP Server
(`dhcp_server`). When Kea moves a Subnet to another Shared Network, or out of one, the next run moves the Subnet.

netbox-plugin-dhcp 0.2.0 needs one Prefix for each Shared Network, and that Prefix must enclose every member Subnet.
Kea has no such rule. A Kea Shared Network groups the Subnets of one link or one relay, and their prefixes often have
no common enclosing Prefix, for example `192.0.2.0/24` and `198.51.100.0/24`. A Prefix that enclosed them would be an
aggregate that the network does not have. So with that release, every Shared Network is unsupported, and so are its
DHCP Options. The entry names [gap 1](https://github.com/marcinpsk/netbox-kea-ng/issues/88).
The member Subnets then belong to the DHCP Server. The import reports each value that a member Subnet inherits from its
Shared Network. A DHCP plugin release that makes the Prefix optional imports the Shared Networks with no netbox-kea
change.

When a run does not write a Shared Network that the DHCP plugin can hold, for example after a failed write, each
member Subnet keeps its parent. A new member Subnet then belongs to the DHCP Server.

## Subnet ID and name clashes

Each imported Subnet holds Kea's subnet ID. A Subnet that an earlier release imported takes its Kea subnet ID on the
next run. netbox-plugin-dhcp 0.2.0 keeps Subnet IDs unique across all DHCP Servers, but Kea numbers the Subnets of
each daemon on its own. So when another DHCP Server already holds the ID, for example the DHCPv4 Subnet 1 of a
dual-stack Server, the Subnet is unsupported, together with its Pools, delegated-prefix Pools, In-Subnet
Reservations and the DHCP Options of each. The entry has the reason `subnet_id_clash` and names the Subnet that holds
the ID. The import never gives a Subnet another ID.

The DHCP plugin also keeps client class and Shared Network names unique across all DHCP Servers. So when another client
class or Shared Network already holds the name, for example the client class of the same name in the other family,
the object is unsupported. A new object is not created. An existing object keeps its old name, and its other fields
still follow Kea.

Both limits end with [gaps 2 and 3](https://github.com/marcinpsk/netbox-kea-ng/issues/88): a DHCP plugin release that
makes Subnet IDs and names unique per DHCP Server imports these objects with no netbox-kea change.

## Removal of Stale DHCP Import Objects

A run removes each Stale DHCP Import Object: a mapped Shared Network, Subnet, Pool, delegated-prefix Pool,
Reservation, client class, custom Option Definition or DHCP Option whose Kea source Kea no longer reports. A Pool whose
range changes in Kea is a new Pool, and so is a delegated-prefix Pool whose prefix or delegated length changes, and a
DHCP Option whose client classes change, so the run removes the old row and creates a new one. The run removes an
object only after it read every Kea object of that kind. When the Server Configuration or the Reservation Snapshot was
not read in full, the run keeps the objects of the kinds that the read covers, and one skipped entry for each kind
tells why and how many objects it kept. The run judges a DHCP Option by the kind of its object. It removes the Option
only when it read every object of that kind and every DHCP Option entry of those objects. So an invalid `option-data`
entry of a Pool keeps only the Options of Pools, and an unread Reservation Snapshot keeps only the Options of
Reservations. The Options of Reservations come from the Reservation Snapshot, so a Server Configuration that was not read
in full keeps the global Options and the Options of the configuration objects, but not the Options of Reservations.
The run also keeps an object
when its removal would remove a DHCP plugin row that the run keeps, for example a Pool that an operator added to a
stale Subnet, a Subnet that an operator added to a stale Shared Network, or a mapped DHCP Option that the run cannot
judge. It also keeps an object when an Option that the run keeps still uses a stale Option Definition, or when a row
that the run keeps names a stale client class in its `client_classes` or `evaluate_additional_classes` (without the
class, that row would reach more clients). A stale DHCP Option goes on its own, so a stale Option Definition or client
class that only it used can go after it. A DHCP Option without a mapping goes with the object that the run removes. Before it writes anything, the run finds the stale
objects whose removal removes or changes no object that it keeps, so a kept object leaves no change behind. Stale
objects whose removals rely on each other are removed together or not at all. When a removal fails, each stale object
whose removal relies on it, directly or through other objects, is kept too. A removal deletes the DHCP plugin row with
its DHCP Options. It never deletes an IP address, a Prefix or an IP Range. The change log records each removal, and
the import needs the delete permission of each DHCP plugin model that it can remove.

The **Drift** card of the **DHCP Plugin** page reads Kea after the page opens and compares it with the imported rows
of each mapped kind. It lists each missing object (Kea has it, NetBox has no imported row) and each stale object (the
next run removes it), with a count of the objects that are in step. When Kea was not read in full for a kind, the
card shows why, and it lists the imported rows that it did not see as not seen, never as stale. A DHCP Option is
judged by the read of its own entries and of its object, so its kind can show why the read is not complete and still
list a stale Option of an object that Kea gave in full. When Kea cannot be read, the card shows the error and lists
the imported rows as unknown. Its **Latest run** link opens the stored result of the last run.
