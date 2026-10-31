---
status: accepted
date: 2026-10-30
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Kea read failures are classified outside KeaClient by one module

## Context

`KeaClient` reports a failed read through overloaded built-in exception types:

- `MalformedReply`, `MalformedConfiguration` and `MalformedLeaseResponse` were `RuntimeError`s, and many other
  malformed replies were plain `RuntimeError`s.
- `MalformedReservation` was a `ValueError`.
- `KeaClient()` raised a plain `ValueError` for invalid client settings, for example a key without a certificate.
- Transport, TLS file and credential encoding failures are `requests.RequestException`s.

So each caller derived the same split again. About 45 `except` clauses in about 20 production modules did this,
with at least 6 different catch tuples, and the copies disagreed about a `ValueError`. The Snapshot builders made
the Snapshot unavailable, the notice loader let it raise, the badge lookups made it `INVALID_READ`, the read before a
change made it an unusable reply, and the Reservation page API answered 400 for every `ValueError` after the client
was built. The OpenGrep rule `kea-view-read-ladder` guarded `views/` only.

## Decision

A `read_failure` module classifies every failed Kea read. It is the read-side twin of `change_outcome`
([ADR 0011](0011-runtime-changes-return-a-typed-outcome.md)), and it stays outside `KeaClient` for the same reason:
domain classification does not belong in the wire client.

### Interface

`attempt(label, read)` runs the read and returns its value, or a `ReadFailure`. A `ReadFailure` holds the kind, Kea's
answer (`kea_error_message()`, for `unsupported` and `refused` only) and the label of the read. A caller maps the
kind to its own presentation and writes no `except` for these failures.

| Kind | Cause |
| --- | --- |
| `unsupported` | Kea does not provide the command: result 2, the hook library is not loaded. |
| `refused` | Kea answered with another failure result. |
| `unreachable` | The transport, a TLS file or the credential encoding failed. Nothing usable came back. |
| `malformed` | Kea answered, but NetBox cannot use the reply or a record in it. |
| `misconfigured` | The client settings of the Server cannot build a client. Nothing was sent. |

A refused Lease query (`LeaseQueryGuardError`), a `ValueError` and every other exception still raise. A bare
`ValueError` now means a caller bug.

### Exception types

- `MalformedKeaReply` is the base of every malformed reply. It is neither a `RuntimeError` nor a `ValueError`.
  `MalformedReply`, `MalformedConfiguration`, `MalformedLeaseResponse` and `MalformedReservation` subclass it, and
  each malformed reply that `KeaClient` raised as a plain `RuntimeError` is now a `MalformedReply`. The base lives
  in its own module, because `leases` and `reservations` cannot import `kea`.
- `KeaClient` and `Server.get_client()` raise `KeaClientSettingsError` for invalid client settings.

### Logging

`attempt()` writes the one log line of a failure: `unsupported` at INFO, `misconfigured` at WARNING without a
traceback, and `refused`, `unreachable` and `malformed` at WARNING with a traceback. A caller does not log a read
failure. The badge lookups, which logged at DEBUG, now log as every other read does.

### Callers

Every production read moves in this change:

- The Snapshot builders (`server_configuration`, `subnet_catalogue`) map the kind to the unavailable Snapshot and its
  diagnostic code, as before.
- `views/notices` maps a `ReadFailure` to the unavailable Notice of the loaded kind. The views that built a client
  themselves use `_client_or_refusal()`, which keeps the message that names the client settings.
- `lease_reservation_reads` maps the kind to its badge enums: `unsupported` to the hook reason, `refused` and
  `unreachable` to `KEA_ERROR`, `malformed` to `MALFORMED_REPLY`, and `misconfigured` to `INVALID_READ`.
- The REST API answers from one table: `unreachable` gives 502 "Could not connect to Kea server.", `refused`,
  `unsupported` and `malformed` give 502 "An internal error occurred", and `misconfigured` gives 500 "Server
  configuration error.".
- `server_connection`, the DHCP Import Reservation read, the `ipam_reconciliation` reads, the verification read of a
  Reservation change and the reads of the views that degrade silently (utilization, status, the read back of a
  created Lease, a later page of a Reservation search) use `attempt()`.
- `change_outcome.build_client` and the step before a change use `attempt()`. Kea's answer explains a refusal and
  the given text explains every other kind, as before. A TLS file or credential failure in that step stays the
  `invalid-client-configuration` rejection of ADR 0011.

`change_outcome.mutate` keeps its write classification (ADR 0011), and so does the config-test step of a
Configuration Change (`config_write._test_before`, ADR 0005). Neither is a read.

### Clock step

A Lease Snapshot whose read finishes before it starts, because the wall clock stepped back, is not a failure. The
Snapshot builder uses the later of the start and finish times as the finish time.

### Guard

The OpenGrep rule `kea-view-read-ladder` covers all of `netbox_kea/` except `read_failure.py`, `kea.py` and the tests.
It refuses a handler of `KeaException`, `requests.RequestException`, `MalformedKeaReply` or `KeaClientSettingsError`.
It exempts `change_outcome.mutate` and `config_write._test_before` by name. The rule
`kea-exception-handler-misses-runtime-error` is deleted: a malformed reply is no longer a `RuntimeError`, and the wider
rule refuses every handler that it checked.

## Consequences

A new failure mode needs one change in `attempt()` and one row in each mapping of a kind.

These results change for the operator:

- A settings error on a Reservation API query answers 500 "Server configuration error." instead of "Invalid Kea
  server configuration.".
- A Reservation that Kea returns for a lookup but that does not parse or fit the lookup is malformed. Its Reservation
  API identity or address query answers "An internal error occurred" instead of "Kea returned a malformed
  Reservation target.", and its badge reason is `MALFORMED_REPLY` instead of `INVALID_READ`.
- A Lease read across a backward clock step gives its Snapshot instead of an Unknown badge.

## Rejected alternatives

- Let `KeaClient` return or raise the classified failure: rejected for the reason of ADR 0005 and ADR 0011.
- Keep the built-in exception types and share one catch tuple: rejected because a `RuntimeError` or a `ValueError`
  of a caller bug then still reads as a Kea failure.
- Classify a TLS file or credential failure as `misconfigured`: rejected because the API and the views report these
  as a connection failure today.
- Keep the exception in `ReadFailure`, so a caller can keep a narrower message: rejected because each caller then
  classifies again.
