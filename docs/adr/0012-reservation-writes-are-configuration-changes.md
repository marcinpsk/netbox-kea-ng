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
- One `try` in each view covers the live read, the Kea write and the after-apply work. `claim()` can raise
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
- Result 2 (the command is not supported) is a rejection, as in ADR 0011.
- Any other failure result gives `unknown`, with no read after it. `host_cmds` writes each selected host data
  source in turn and does not roll back the earlier sources when a later one fails, and a SQL source can lose
  the commit acknowledgement. A read cannot show which sources changed. The message shows Kea's text, as in
  ADR 0011.
- The verification read runs only after `applied`.
- `KeaClient` keeps the Reservation commands, cursors and raw record handling of ADR 0002 and ADR 0004.
  `config_write` owns sequencing, the lock, the classification and the outcome.
- The views present the outcome through `_run_change` ([ADR 0011](0011-runtime-changes-return-a-typed-outcome.md)).
  `reservation_edit.after_apply()` writes the journal entry, sends the robust Reservation signal and optionally
  calls `claim()`. It runs only after `applied`, outside the call that classifies the change. It returns typed
  facts for each independent step. A journal savepoint rolls back a failed insert or save receiver without
  preventing the signal and claim. A committed journal or claim whose event dispatch fails has a separate fact
  from a write failure. A refused permission check, an unrequested claim and a Reservation with no address each
  have their own skip reason. Views map these facts to messages. A failure still reports the Reservation as
  applied and shows the after-apply error separately, as ADR 0011 says.
  _Amended 2026-11-01 (#214): the claim fact is the outcome of a Manual Sync (`manual_sync.sync_reservation`):
  Refused, Failed, or a run with the claim result and whether NetBox dispatched its events. Only `not-requested`
  and `not-applied` stay after-apply skip reasons, and a delete requests no claim. A Reservation with no address
  runs and gives an empty claim result. One presenter maps the outcome to messages._
- The bulk Reservation import calls the public `reservation_edit.save_import()` for each entry. After each
  applied change returns, `_run_change_loop` invokes `reservation_edit.after_apply()` outside its classification
  callback and before the next entry. An `unknown` entry or a rejected entry stops the import, and the report
  states the applied entries. An earlier entry keeps its journal and signal when a later entry is refused.
- Global Reservations stay read-only, as in ADR 0002.

## Consequences

Reservation writes and Subnet changes to one daemon wait for each other.

A lost reply on a Reservation write gives `unknown`, and NetBox records no journal entry or IPAM claim for it.

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
