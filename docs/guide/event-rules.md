<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Event rules and webhooks

NetBox queues an event for each change and sends the queue to event rules and webhooks when the request or
job ends. The plugin writes each sync row, each DHCP-plugin import family and each import receipt in its own
transaction. On NetBox 4.6.9 and later, when such a transaction starts with no other transaction open in a request or in the
IPAM sync job, NetBox dispatches its events right after its COMMIT, and none when it rolls back. A failed row or
family then sends no event for the changes that it reverted. This has these consequences:

- Events dispatch once per transaction, not once per request or job. An object that two transactions change
  sends two events (for example `created`, then `updated`), where one request sends one combined event. This can
  change which event rules match.
- The events of these transactions dispatch before the other events of the same request.
- A sync job that fails still dispatches the events of the rows that it committed before the failure.
- Each dispatch reads the enabled event rules once per event type and object type, about two reads for each
  synchronized address. On a development host, 10,000 such transactions took 151 s, against 127 s for the same
  changes in one transaction.
- When the dispatch fails after a COMMIT (for example, the events pipeline cannot reach Redis), the operation
  stops with an error and the committed rows stay. The IPAM sync job logs the error for that server and counts it.

The sync refuses a Reservation row before its first IP address or MAC address write when a hardware address
is not an EUI-48 or EUI-64 address, or when NetBox has more than one MAC address row for it. A row whose address
is a conflict is reported as a conflict. The exception is a legacy address in the global table: the sync moves it
into its VRF before it finds that its description cannot fit, so a bad hardware address refuses that row.

Known limits. NetBox gives a plugin no public way to remove one event from its queue, so these remain:

- Inside a transaction that something else owns, a plugin transaction is a savepoint. When it rolls back,
  NetBox still dispatches the events of its reverted changes. This applies to the rows of a DHCP-plugin
  import when a database error, another app's signal receiver, or a MAC address row that another writer
  duplicated during the row fails it after a change. It also applies to a DHCP-plugin import that a caller
  runs in its own transaction, and to a deletion that the DHCP mapping guard refuses after NetBox queued the
  delete event.
- On NetBox 4.3 to 4.6.8, `event_tracking` cannot be nested, so every plugin transaction is plain and the events
  of a failed row dispatch with the request. On these releases a failed request also dispatches its events.
- An `on_commit` hook of another app that raises after a COMMIT drops the events of that transaction.
- A netbox-branching merge or revert dispatches the events of each change inside its own transaction. When a
  later change fails, the merge rolls back, but the events of the earlier changes have already dispatched.
