---
status: accepted
date: 2026-10-16
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Runtime Changes return a typed outcome

## Context

[ADR 0005](0005-configuration-changes-return-a-typed-outcome.md) gives every Configuration Change one outcome:
applied, unknown, or a rejection. Its Scope section leaves out Lease writes, Lease wipe, and `dhcp-enable` and
`dhcp-disable`, because they change runtime state, not the Server Configuration. These are Runtime Changes.

Seven view sites send a Runtime Change and translate its failures by hand: DHCP enable and disable, Lease add,
update, delete and wipe, and the bulk Lease import. No site tells "not sent" from "reply lost":

- A read timeout or a reset after the send reads "Failed to ...", "An internal error occurred." or "could not reach
  the Kea server", although Kea can have run the command. The journal entry and the signal of an applied change
  are then missing.
- A Control Agent forward failure reads "Kea reported an error", although ADR 0005 shows that the daemon can have
  run the command.
- Lease update and delete read the shown Lease again before the write, inside one client call. A failure of that
  read and a failure of the write give the same message.
- `kea_error_hint` maps result codes to fixed text, so the operator never sees Kea's own answer. Two handlers do
  not log a `KeaException`.

## Decision

Runtime Changes follow the Application rules of ADR 0005, through the same code.

### Interface

A `runtime_change` module owns every Runtime Change. Its purpose-named operations take `(server, family)` and
typed arguments, and build their own `KeaClient`:

```text
add_lease, edit_lease, delete_lease, wipe_leases
enable_dhcp, disable_dhcp
```

An operation returns a Runtime Change Outcome (`application` and `diagnostics`) when the change is live or can be
live. It raises `ChangeRejected` when the change is not live, as far as NetBox can tell.

### Application

- The classifier of ADR 0005 (`_before_change`, `_mutate`, `_never_sent`) moves from `config_write` into one
  shared module. `config_write` and `runtime_change` both use it.
- A failed read before the write, such as the fresh read of the shown Lease, means that the change was not sent.
- A connect-phase failure means that the change was not sent. An HTTP 401 answer and an invalid URL also mean
  that the change was not sent, because Kea did not run the command. NetBox does not follow a redirect for a
  command. A lost or malformed reply, any other HTTP error, a TLS failure, a Control Agent forward failure, or
  result 5 gives `unknown`.
- Result 2 in a well-formed reply is a rejection for every command: the command is not supported, so Kea ran
  no handler for it.
- Any other failure result on `dhcp-enable` or `dhcp-disable` is a rejection, with no read after it. These
  commands change only the state in Kea memory, so a failure result means that nothing changed. A command added
  later that can fail after it applies gives `unknown` on a failure result.
- Any other failure result on a Lease add, update or delete gives `unknown`. A MySQL or PostgreSQL backend can
  lose the commit acknowledgement, and it writes the DHCPv6 extended-info rows after the Lease row. Kea then
  returns result 1 after the Lease changed. A read after the failure cannot prove that nothing changed, because
  the DHCP service, an HA peer or another API client can write the same Lease in the meantime.
- Any other failure result on `lease4-wipe` or `lease6-wipe` gives `unknown`. The memfile backend deletes the
  Leases of the Subnet one at a time, so a failed lease-file write returns result 1 after earlier Leases are gone.
  No read can show which Leases this request deleted, because Kea allocates Leases at the same time.
- These give a rejection with the reason `target-changed`: a fresh read that does not match the shown Lease, a
  Lease that is gone before the send, result 3 on `lease-del` (the Lease is gone), and result 4 on `lease-update`
  (a conflict). This request did not change that Lease. `LeaseChangeResult` and its variants are deleted.
- No operation reads Kea after the send to classify the change. The read after an applied Lease add is a
  display read.

### Shared types and presentation

- `ConfigChangeRejected` becomes `ChangeRejected`. Its reasons gain `target-changed`.
- One `Application` literal serves both kinds of change. `ConfigChangeOutcome` adds persistence to the shared
  fields.
- `_run_config_change` becomes `_run_change` in `views/_base.py`. It maps every outcome and rejection to one
  message. The message for `unknown` says that Kea did not confirm the change and that the operator must check
  the Server before trying again. When Kea returned a failure result, the message also shows Kea's text, so an
  argument error stays visible.
- One formatter replaces `kea_error_hint` everywhere, reads included. It gives fixed guidance for result 2 (the
  required hook library may not be loaded) and result 128 (the daemon cannot be reached), followed by
  `Kea replied: <text>` for every result.
  No Python exception text reaches the operator.

### Side effects

The journal entry, the signals and the IPAM synchronization run only after `applied`, outside the call that
classifies the change. An error in a side effect therefore never reads as a Kea failure. When a side effect fails
after `applied`, the view still reports the change as applied, logs the error, and shows a separate error that
names the side effect that failed. After `unknown`, the message says that NetBox recorded nothing. The next
periodic synchronization brings IPAM up to date.
_Amended 2026-11-01 (#214): the IPAM synchronization of one Lease or one Reservation is a Manual Sync
(`manual_sync.py`). It returns a typed outcome, and one presenter gives the same words to every caller. When NetBox
saves the claim but cannot dispatch its events, the outcome holds the claim result and that fact. A row Sync button
then returns a 200 row reply with the claim result and a separate error. It does not raise `EventDispatchError`.
This holds where `event_scope.atomic()` is a unit (a NetBox release whose `event_tracking` nests). On an older
release the events dispatch at the end of the request, outside the view, so a failed dispatch can still give a
500 there._

### Loops

The multi-Lease delete and the bulk Lease import send one Runtime Change per row. An `unknown` row stops the
loop. The report lists the applied rows, the unknown row and the rows not sent. A rejected row does not stop
the loop.

### Serialization

Runtime Changes take no lock. Lease and service state never pass through `config-get` or `config-set`, so no
NetBox change can erase them.

### Guard

An OpenGrep rule refuses a call to the `KeaClient` runtime write primitives (`lease_add`, `lease_update`,
`lease_delete`, `lease_wipe`, `dhcp_enable`, `dhcp_disable`) outside `runtime_change`. The rule matches the method
name, so it cannot see a call through an alias. The ADR 0005 rules for the rejection and the mapper are renamed to
the shared names.

## Consequences

Views lose seven exception ladders. A new failure mode needs one change in the shared classifier and one row in
the mapper.

An operator who sees `unknown` after a Lease write can find the Lease changed with no journal entry.

User-facing view reads go through `load_snapshot()` or `load_target()`, which use the new formatter. The
OpenGrep rule `kea-view-read-ladder` refuses a hand-written ladder in `views/`; only the named reads that
degrade silently and log the failure keep their own handler.
_Amended 2026-10-30 ([ADR 0015](0015-kea-read-failures-are-classified-outside-keaclient-by-one-module.md)): every
Kea read runs through `read_failure.attempt()`, and the rule covers all of `netbox_kea/`. No read keeps its own
handler._

## Rejected alternatives

- Two states, success or failure: rejected because a lost reply then claims that an applied change failed.
- One view runner that wraps a callable: rejected because it cannot tell the pre-read from the write inside one
  client call.
- Let `KeaClient` raise "not sent" and "lost" errors: rejected for the reason of ADR 0005, domain classification
  does not belong in the wire client.
- Read the target again after a failure result of `dhcp-enable` or `dhcp-disable`: rejected because these
  commands apply as one operation in memory.
- Classify every Lease failure result as a rejection: rejected because a SQL backend can apply the Lease and
  still return result 1.
- Read the Lease again after a failure result, and give a rejection when it is unchanged: rejected because
  another writer can put back the earlier Lease, and the read then calls an applied change a rejection.
- Ask Kea for its lease backend and trust a failure result from memfile: rejected because it adds a configuration
  read on the failure path, and the form validation in NetBox already stops most argument errors.
- Run the side effects after `unknown`: rejected because NetBox can then record a change that never happened.
- Treat an HTTP 403 answer as not sent: rejected because a proxy can block the reply after Kea ran the command.
- Treat a TLS certificate verification failure as not sent: rejected because a TLS 1.2 server can renegotiate
  after it received the command.
- Keep the Lease result variants beside the outcome: rejected because one operation then has two vocabularies.
- Show only fixed messages: rejected because the operator loses Kea's own answer, such as a Lease that already
  exists.
- Take the ADR 0005 lock: rejected because no NetBox change can erase runtime state, and a long wipe would block
  Subnet changes.
