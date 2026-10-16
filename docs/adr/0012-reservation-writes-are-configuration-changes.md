---
status: accepted
date: 2026-10-16
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Reservation writes are Configuration Changes

## Context

A Reservation add, edit or delete changes the Reservations that a Server applies, and it runs the persist step
of [ADR 0005](0005-configuration-changes-return-a-typed-outcome.md). It still sits outside `config_write`:

- It takes no advisory lock. When Kea keeps its Reservations in the configuration, a NetBox `config-set`
  read-modify-write can erase a concurrent NetBox `reservation-add`. ADR 0005 says that two NetBox operations on
  one daemon run one at a time, and for Reservations that is false.
- `ReservationMutationResult` has `application="applied"` only. A lost reply raises, and the view says that the
  Reservation could not be created, updated or deleted.
- One `try` in each view covers the live read, the Kea write and `_confirmed_side_effects`. `claim()` can raise
  `EventDispatchError`, a `RuntimeError`, so the view reports a failure after Kea applied the change and NetBox
  committed it.

## Decision

A Reservation add, edit or delete is a Configuration Change.

- `config_write` gains `add_reservation`, `edit_reservation` and `delete_reservation`. Each takes `(server,
  family)` and typed arguments, holds the advisory lock of ADR 0005 from its first read to the end of its persist
  step, and returns a `ReservationChangeOutcome` or raises `ChangeRejected`.
- `ReservationChangeOutcome` extends `ConfigChangeOutcome` with the previous and intended Reservation and the
  verification state. `ReservationMutationResult` is deleted.
- The live reads before the write (the Subnet Catalogue `MutationScope`, the target read and the fingerprint
  check) run as reads before the change: a failure means that the change was not sent. A changed fingerprint, or
  a target that is gone, gives a rejection with the reason `target-changed`.
- Result 3 on `reservation-del` means that no host data source had the Reservation. It gives a rejection with
  the reason `target-changed`.
- Any other failure result gives `unknown`, with no read after it. `host_cmds` writes each selected host data
  source in turn and does not roll back the earlier sources when a later one fails, and a SQL source can lose
  the commit acknowledgement. A read cannot show which sources changed. The message shows Kea's text, as in
  ADR 0011.
- The verification read runs only after `applied`.
- `KeaClient` keeps the Reservation commands, cursors and raw record handling of ADR 0002 and ADR 0004.
  `config_write` owns sequencing, the lock, the classification and the outcome.
- The views present the outcome through `_run_change` ([ADR 0011](0011-runtime-changes-return-a-typed-outcome.md)).
  The journal entry, the signals and `claim()` run only after `applied`, outside the call that classifies the
  change. When one of them fails, for example `claim()` with `EventDispatchError`, the view still reports the
  Reservation as applied and shows the side-effect failure as a separate error, as ADR 0011 says.
- The bulk Reservation import runs one Configuration Change per entry. An `unknown` entry or a rejected entry
  stops the import, and the report states the applied entries.
- Global Reservations stay read only, as in ADR 0002.

## Consequences

Reservation writes and Subnet changes to one daemon wait for each other.

A lost reply on a Reservation write reads as unconfirmed, and NetBox records no journal entry or IPAM claim for it.

This decision changes the result type of ADR 0002 and the scope of the ADR 0005 lock. Reservation writes do not
use the check read of ADR 0005.

## Rejected alternatives

- Runtime Changes with a persistence field: rejected because a Reservation in the configuration needs the lock,
  and Runtime Changes take none.
- Leave Reservation writes to a later move of the edit protocol out of the views: rejected because the lock gap
  and the false failure report are live now.
- Read the Reservation again after a failure result, as ADR 0005 does for a native command: rejected because
  the read can find the Reservation in a source that the write did not reach yet, and then calls a partial
  write a rejection.
- Classify a failure result as a rejection: rejected because a later host data source can fail after an earlier
  one changed.
