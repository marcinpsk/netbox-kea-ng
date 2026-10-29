<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Kea Network Management

This context manages Kea DHCP configuration and mirrors selected live Kea state into NetBox IPAM.

## Language

**Server**:
A configured Kea server that provides DHCPv4, DHCPv6, or both.
_Avoid_: Kea instance, endpoint

**Server Scope**:
The Servers that a combined page covers: all permitted Servers, an explicit selection of several Servers, or one Server.
An explicit selection is invalid if any selected Server is unknown or inaccessible, or any selected ID is empty or invalid.
_Avoid_: Scope, Server filter

**Subnet**:
A Kea-managed IP network for one address family. Within a Server and address family, its CIDR and Kea subnet ID identify the same Subnet.
_Avoid_: Network

**Subnet Identity**:
The canonical CIDR and Kea subnet ID that identify one Subnet within a Server and address family. Both values must identify the same Subnet.
_Avoid_: Subnet key

**Shared Network**:
A named Kea grouping whose Subnets share configuration. It carries its own settings and DHCP Option values, and
it can exist with no member Subnets.
_Avoid_: Network, subnet group

**DHCP Link**:
A vendor-neutral, family-specific DHCP selection domain for Subnets on one client attachment or relay-selected link. Kea Shared Network, ISC DHCP shared-network, Microsoft Superscope, Cisco Network or Link, and Infoblox Shared Network are vendor implementations. A DHCP Link does not require an aggregate Prefix.
_Avoid_: Aggregate Prefix, Shared Prefix

**DHCP Import**:
The one-way copy of one Server's Kea configuration and Reservations into the NetBox DHCP plugin. It takes only
Declared Values. It writes each fact for which the installed DHCP plugin has the DHCP Plugin Capability, and reports
every other fact as unsupported or not imported.
_Avoid_: DHCP plugin sync, export to the DHCP plugin

**DHCP Plugin Capability**:
Whether the installed DHCP plugin can hold one kind of Kea fact, such as a field, a choice, a value range, or a
uniqueness scope. A fact without its capability is unsupported: the DHCP Import reports it and writes it as soon as
an installed plugin release gains the capability.
_Avoid_: Plugin gap, plugin version check

**DHCP Import Result**:
The stored record of one DHCP Import run: the Server, the start and end times, the trigger, and one entry for each
Kea fact that the run created, updated, removed or did not write. An entry names its fact by a Kea path, such as
`Dhcp4/subnet4[id=20]/option-data[code=150]`. A fact that the run did not write has a reason from a closed set, and
the reason gives its outcome: unsupported, not imported or skipped. An object that did not change has no entry.
_Avoid_: Import log, import summary

**Stale DHCP Import Object**:
A NetBox DHCP object with a DHCP Import Mapping whose Kea source a Complete observation of the same kind no longer
reports. The DHCP Import removes it. An Incomplete observation cannot make an object stale. A Pool whose range
changes in Kea is a different Pool, so the old one becomes stale. So is a delegated-prefix Pool whose prefix or
delegated length changes, and a DHCP Option whose client classes change. A DHCP Option is judged by its own
observation and by the observation of the kind of the object that assigns it.
_Avoid_: Orphan, orphaned Subnet

**Declared Value**:
A value that a Kea object sets for itself, as opposed to one it inherits from its Shared Network or the global
configuration. Subnet Settings are effective values and do not say which values are declared.
_Avoid_: Override, explicit setting

**DHCP Import Mapping**:
An association between a Kea source object and its imported NetBox DHCP object. Each object that a DHCP Import writes
has one: the global configuration of one address family, a Shared Network, a Subnet, a Pool, a delegated-prefix Pool, a
Reservation, a client class, a custom Option Definition, and a DHCP Option. The exception is a Kea Subnet without a
subnet ID: it, its Pools, its delegated-prefix Pools and each DHCP Option of these objects have no mapping. A DHCP
Option whose identity is longer than a mapping holds has no mapping either. The source identity includes the Server,
address family, and the Kea identity of the object: a Shared Network name, a Kea subnet
ID, a Pool within its Subnet, a delegated-prefix Pool's prefix and delegated length within its Subnet, a Reservation
Identity, a client class name, an Option Definition's space and code (with the name of its client class, for a
definition that a client class declares), or a DHCP Option's identity within the source of the object that assigns it.
Apart from these exceptions, a DHCP Option without a mapping, for example one that an operator adds, is not the import's.
_Avoid_: DHCP Link, ownership link

**Aggregate Prefix**:
An optional IPAM aggregate that contains more-specific Prefixes. It does not define DHCP selection, allocation, or configuration inheritance.
_Avoid_: DHCP Link, Shared Prefix

**Pool**:
An inclusive address range within a Subnet from which Kea can allocate leases. Kea can express it as explicit endpoints or as a prefix.
_Avoid_: Range

**DHCP Option**:
A DHCP parameter assignment. Within the object that assigns it, the option space, the code, and the set of client
classes identify one DHCP Option. A missing space is the default space of the address family, and a name identifies
the code that its Option Definition gives it; a name with no known definition identifies the option by name. The same
option can be assigned once for each set of client classes. It includes encoded data and Kea delivery flags. Its
declaration scope determines which clients receive it. The same value semantics apply wherever Kea assigns the option.
_Avoid_: Option, option-data, Subnet option, reservation option

**Lease**:
A Kea record of a DHCP address allocation or an IPv6 delegated-prefix allocation. It describes the allocation's
state and client information within one Server and address family.
_Avoid_: Reservation, static lease

**Lease Identity**:
Within one Server and address family, the allocation kind and canonical allocation address identify one Lease
in Kea. Client binding, Subnet and delegated prefix length describe the observed allocation.
_Avoid_: Lease IP, lease key

**Current Lease**:
A Lease in the assigned state, or an address Lease in the registered state, whose valid lifetime has not ended.
An infinite valid lifetime does not end.
_Avoid_: Active IP address, database lease

**Lease Snapshot**:
A time-bounded observation of Leases for one Server, address family and requested scope. An Incomplete Lease
Snapshot preserves valid Leases with diagnostics and cannot establish the absence of a Lease.
_Avoid_: Lease response, lease collection

**Reservation**:
A Kea host-specific DHCP configuration for exactly one Reservation Identity. It can reserve no address, one IPv4 address, or multiple IPv6 addresses and delegated prefixes.
_Avoid_: Host record, static lease

**Reservation Identity**:
Within a Server and address family, the Reservation Scope together with exactly one Kea identifier type and value. All three parts are necessary. The identifier type and value alone do not identify a Reservation, because the same identifier can name one Global and one In-Subnet Reservation.
_Avoid_: Identifier priority, reservation key

**Reservation Scope**:
The place where Kea applies a Reservation. It is either Global or one specific Subnet. "Scope" alone means Reservation Scope.
_Avoid_: Subnet ID, reservation location

**Published Name**:
The hostname that Kea gives a client for a Reservation: the stored Reservation hostname under the Effective DDNS
Qualifying Suffix, in lower case and without a trailing dot. The Reservation forms take it, and the IPAM
synchronization writes it to NetBox for the Reservation source. The lease source writes the observed Lease hostname,
which Kea stores already qualified, without a trailing dot.
_Avoid_: Stored hostname, qualified name, FQDN

**Effective DDNS Qualifying Suffix**:
The `ddns-qualifying-suffix` that Kea applies to one address: the value of the Pool that contains the address,
else of its Subnet, its Shared Network, or the global configuration, in that order. It is unknown when a Pool of
the Subnet sets a value and the address is not known.
_Avoid_: Subnet suffix, domain suffix

**Reservation Snapshot**:
A time-bounded observation of Reservations for one Server, address family, and requested scope. An Incomplete Reservation Snapshot preserves valid Reservations; failed or bounded page reads can make it incomplete without a record diagnostic, while parsing failures identify records that could not be interpreted.
_Avoid_: Reservation response, host list

**Reservation Synchronization State**:
The relationship between all addresses in one Reservation and their corresponding NetBox IP addresses in the sync VRF of the Server. An address is synchronized only when the Server has IPAM Ownership of its IP address from a Reservation: a marker, or a link of another Server or of another source, is not enough. The state is Unknown when NetBox could not be read or the user may not view an IP address of the Reservation. It is Not Applicable, Not Synchronized, Partially Synchronized, Synchronized, or Unknown.
_Avoid_: Lease status, sync badge

**Lease Synchronization State**:
The relationship between one Current Lease and the NetBox object of its allocation in the sync VRF of the Server: the IP address of an address Lease, or the Prefix of a delegated-prefix Lease. It is Synchronized when the Server has IPAM Ownership of the object from a lease source. It is Not Synchronized when the object has a marker but no such ownership, for example when only another Server or a Reservation owns it. It is Unmarked when the object has no marker, so a Sync takes the object over. It is Not in NetBox when no object exists, and Unknown when NetBox could not be read or the user may not view the object.
_Avoid_: NetBox IP badge, synced

**Reservation Match**:
The relationship between one Lease and the Reservation of its client. Kea applies a Reservation only when the reservation flags of the Lease's Subnet (`reservations-in-subnet`, `reservations-global`, inherited from the Shared Network and the global configuration) enable its Reservation Scope. A Reservation of a disabled scope, found only when no enabled scope holds one, is an Ignored Reservation. Only the reserved allocations that Kea gives for the Lease's Subnet count, for Global and In-Subnet Reservations alike: an address in the Lease's Subnet, and any delegated prefix. With `reservations-out-of-pool`, an In-Subnet reserved allocation in a Pool of the Subnet does not count, but a Lease of a reserved allocation stays Reserved, because Kea renews it. A Reservation whose reserved allocations of the Lease kind are all in a Pool, with no Global allocation that applies, is an Ignored Reservation. When an In-Subnet Reservation holds allocations, but none of the Lease kind that counts, Kea tries the Global Reservation of the client (DHCPv6 also when the In-Subnet Reservation holds only the other kind). An In-Subnet Reservation of no allocation stops this and stays a Host-Only Reservation, and a DHCPv6 Reservation of only prefixes for an address Lease, with no Global allocation, stays an Other-Kind Reservation. When a Global allocation applies, the match is Unknown if the Subnet has other Subnets in its Shared Network or its membership is not shown, because Kea tries their In-Subnet Reservations first. Else DHCPv6 gives the Global allocation, and DHCPv4 gives the In-Subnet address, because the Global address only selects the Subnet. An address in another Subnet of its Shared Network counts when the flags and client classes of that Subnet show that Kea gives it. A fact that the configuration does not show, such as a flag, a Pool or a sibling Subnet, makes the match Unknown when it changes the match. It is Reserved, Stale MAC, Pending Address Change, Host-Only Reservation, Other-Kind Reservation, Ignored Reservation, Unreserved, or Unknown.
_Avoid_: Reserved badge, lease-reservation correlation

**Current Lease Presence**:
Whether the client of one Reservation holds a Current Lease: Present, Absent, or Unknown. Absent requires complete coverage of the query, so an Incomplete Lease Snapshot gives Unknown.
_Avoid_: Lease status, active lease badge

**Reservation Transfer Document**:
A YAML or JSON document that represents one or more Reservations with explicit Reservation Scope. The same structure supports export and proposed creation. The complete document must be valid before any creation starts. It carries the stored Reservation hostname, not the Published Name.
_Avoid_: CSV import, CSV export, Kea payload

**Subnet Settings**:
The typed DHCP behavior that Kea currently applies to a Subnet after inheritance, such as lease timers, allocator selection, relay data, class restrictions, and DDNS settings. It does not state where a value was declared.
_Avoid_: Raw subnet configuration, settings dictionary

**Verified Subnet**:
A Subnet whose canonical CIDR and Kea subnet ID have been confirmed as one unique Subnet by the identity authority.
_Avoid_: Valid subnet

**Configured Subnet**:
A Subnet description derived from validated configuration facts without verified Subnet Identity. It cannot authorize identity-sensitive work.
_Avoid_: Unverified identity, fallback subnet

**New Subnet Identity**:
A proposed canonical CIDR and Kea subnet ID that a complete live identity observation confirms are available for creation.
_Avoid_: Free subnet ID, next subnet ID

**Subnet Catalogue**:
The complete canonical description of configured Subnets for one Server and address family. It includes identity, Shared Network membership, Pools, DHCP Option values, and Subnet Settings.
_Avoid_: Subnet list, subnet choices

**Catalogue Snapshot**:
A time-bounded observation of one Subnet Catalogue. A Complete Catalogue Snapshot has valid and consistent required facts. An Incomplete Catalogue Snapshot preserves safe facts but identifies missing, invalid, or inconsistent facts. One missing or invalid Pool, DHCP Option, or Subnet Settings value makes the Snapshot incomplete, and the configuration facts that did parse are not authoritative for the Subnet.
_Avoid_: Response, raw configuration

**Identity-Only Catalogue Snapshot**:
An Incomplete Catalogue Snapshot that has verified Subnet Identity facts but lacks full configuration facts.
_Avoid_: Partial subnet list

**Configuration-Only Catalogue Snapshot**:
An Incomplete Catalogue Snapshot that has validated configuration facts but lacks verified Subnet Identity facts.
_Avoid_: Identity fallback

**Option Definition**:
A declaration that gives a DHCP Option its code, name, option space, and data type. A standard definition is built
into Kea for the default DHCPv4 or DHCPv6 space. A custom definition comes from `option-def` in the Server
Configuration, or in a DHCPv4 client class, where it defines options for that class only. It defines an option. It
does not assign a value.
_Avoid_: option-def, custom option

**Server Configuration**:
The complete declared DHCP configuration that one Server applies for one address family. It includes Subnets,
Shared Networks, server-global DHCP Option values, Option Definitions, the Reservation identifier types, and the
loaded hook libraries.
_Avoid_: Raw config, config-get response

**Server Configuration Snapshot**:
A time-bounded observation of one Server Configuration. It states whether the observation is available and
whether every fact parsed. Valid facts survive an invalid one.
_Avoid_: Configuration Snapshot, Dhcp4 dict

**Configuration Change**:
One operator-requested change to a Server Configuration or to the Reservations of a Server, such as adding a
Subnet, moving it to another Shared Network, or editing a Reservation. It can need several Kea commands, and it is
applied, rejected, or unknown as a whole.
_Avoid_: Config write, config mutation, config-set

**Configuration Change Outcome**:
The observed result of a Configuration Change that is live or can be live. It states whether the change is
applied or unknown, and whether it is persisted, failed to persist, or had no persistence requested.
_Avoid_: Partial persist, ambiguous config-set

**Runtime Change**:
One operator-requested change to the runtime state of a Server, such as adding, editing or deleting a Lease, wiping
the Leases of a Subnet, or disabling or enabling the DHCP service. It does not change the Server Configuration. It is
applied, rejected, or unknown.
_Avoid_: Kea action, direct action, runtime write

**IPAM Ownership**:
The fact that one Server and address family synchronized a NetBox IP address, Prefix, or IP Range from one Kea
source: an address lease, a delegated-prefix lease, a Reservation, a Subnet, a Pool, a Reservation delegated
prefix, or a delegated-prefix Pool. Only a Current Lease is a lease source. One object can have several owners. An
operator ends every ownership of an object when the description no longer starts with a well-formed marker block
(`[kea-sync: <kind>]`): the block is missing, moved or malformed. A block of another known kind still marks the
object. Text after the block is an operator note, and the synchronization keeps it.
_Avoid_: Kea-managed IP, synced description

**Stale IPAM Object**:
An owned NetBox object that a complete synchronization of its owner no longer reports. The owner drops its
ownership. The object is removed or deprecated only when no owner is left.
_Avoid_: Ghost IP, stale IP, orphan
