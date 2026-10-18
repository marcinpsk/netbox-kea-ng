---
status: accepted
date: 2026-10-18
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# One DHCP Option identity and merge for every scope

## Context

An option edit reads the live `option-data` list, changes the entries the operator edited, and writes the list back.
Four copies of that merge each decide differently which live entry an edit targets:
- The Reservation merge matches the space exactly, then lets a missing space match any space. It matches by code,
  else by name, and ignores client classes.
- The Reservation form matches rows by list position.
- The Subnet and global rows compare the space, the code or name, and the client classes as written. There, a missing
  space is a value of its own, and a name never matches a code.
- The Transfer Document dedup ignores client classes.

So one Kea entry can be the same option in one scope and a different option in another. The copies also disagree on
order and on which values the stale check compares. The DHCP Import (#100) and the widened typed Reservation (#102)
need two options that differ only in their client classes to stay two options.

## Decision

- **Identity.** Within the object that assigns it, the option space, the code and the set of client classes identify
  one DHCP Option. A missing space is the family's default space (`dhcp4` or `dhcp6`), as Kea reads it. A name
  identifies the code that its standard or custom Option Definition gives it. A name with no known definition
  identifies the option by name. The custom definitions come from the configuration that the change already reads
  live, so resolving names costs no extra Kea round trip.
- **One merge for every scope.** The global configuration, Subnets, Shared Networks and Reservations take the same
  typed option edit. No form data crosses the `config_write` seam (ADR 0005). The edit has two parts:
  - **The seen snapshot:** every option the operator was shown, each with its identity and its managed keys (data,
    always-send, never-send and csv-format).
  - **The changes:** each change holds the seen option (none for an add) and the intended option (none for a
    delete). Unchanged options are not changes.
- **Merge rules:**
  - **The snapshot check.** The live entries must equal the seen snapshot, compared as a multiset of identity and
    managed keys. Otherwise the edit is a conflict: an option was added, removed or changed after the operator saw
    the list. Repeated identities count, so duplicates the operator saw pass the check.
  - **Ambiguous changes.** A change whose seen identity occurs more than once in the live entries is a conflict
    that names the option. Duplicates that no change targets are kept as they are.
  - **What is kept.** A live entry keeps its list position and every key that the change does not set, including
    unknown keys such as `user-context`.
  - **New entries** go at the end.
  - **The one exception:** a replaced value drops `csv-format`, because the form writes the data in its own encoding.
- **The fixed form fields** (gateway, DNS and NTP servers) translate into one edit for the entry of the default space
  with no client classes. More than one such entry is still ambiguous and is refused.

## Considered Options

- **Compare entries as written**, as the Subnet rows do today. Rejected: `routers`, `3` and `{space: dhcp4, code: 3}`
  are one option to Kea, so an edit could miss its target, or one live option could count as two.
- **Leave client classes out of identity**, as the Reservation path does today. Rejected: Kea assigns the same option
  once per set of client classes, and the DHCP Import must keep those assignments apart.
- **Drop or keep a live entry the operator did not see.** Rejected: dropping it loses a concurrent addition, and
  keeping it hides the fact that the operator edited a list they had not fully seen.
- **Require one change per shown option, and match each one-to-one.** Rejected: an unchanged duplicate would always
  be ambiguous, so any object holding duplicates could never be edited. The seen snapshot detects concurrent changes
  without matching unchanged options one by one.

## Consequences

- Kea's reading of a missing space and of names is now part of our identity rule. A Kea release that changes either
  changes this ADR.
- Adding a custom Option Definition can change a name-identified option into a code-identified one. Both forms refer
  to the same Kea entry, so no stored state depends on the change.
- Editing the client classes of a Reservation option, and carrying them in the Reservation Transfer Document, belong to
  #102. This ADR fixes only how entries are identified and merged.
