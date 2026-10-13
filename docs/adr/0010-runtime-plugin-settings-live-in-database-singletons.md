---
status: accepted
date: 2026-10-12
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# Runtime plugin settings live in database singletons

## Context

Plugin settings have two homes. `SyncConfig` is a database row that operators edit on the Sync Jobs page,
and migration 0018 seeds it once from `PLUGINS_CONFIG`; after that, the `sync_*` keys in `PLUGINS_CONFIG`
do nothing. `kea_timeout`, `lease_query_max_unpaged_leases`, `stale_ip_cleanup` and
`sync_max_leases_per_server` exist only in `PLUGINS_CONFIG`, so a change needs a restart.
The display cache ([ADR 0009](0009-cache-display-reads-under-write-rotated-generations.md)) adds TTLs that
operators tune while they watch the pages, and the DHCP integration needs a global switch.

## Decision

- Every runtime setting is a field on a singleton model (one row, pk 1), one model for each concern:
  `SyncConfig` (also gains `stale_ip_cleanup` and `sync_max_leases_per_server`), a Kea client config
  (`kea_timeout`, `lease_query_max_unpaged_leases`), a DHCP integration config (the global switch) and the
  display cache config (the TTLs).
- Defaults live on the model fields. A migration copies the values from `PLUGINS_CONFIG` once, so an
  existing install keeps them. After that, the keys leave `plugin_settings.SETTINGS`.
- A removed key that is still in `PLUGINS_CONFIG` causes a startup warning that names the Settings page.
  The value is ignored. An upgrade never fails to start because of it.
- One Settings page shows a section for each singleton. A section shows to a user with the view permission of its
  model. Without the change permission of the model, the section is read-only. A save needs both permissions.
  The Sync Jobs page keeps only the jobs.
- The singletons are change-logged. Like every sync setting, they are main-only
  ([ADR 0007](0007-netbox-kea-rows-stay-in-main-and-a-branch-is-read-only.md)).
- The DHCP integration runs for a Server only when the global switch and the Server's
  `sync_dhcp_plugin_enabled` are both on.

## Considered options

- Keep `PLUGINS_CONFIG` for the remaining keys and show them read-only on the page. Rejected: two
  sources of truth for one kind of fact, and a restart for each change.
- One settings model for all fields. Rejected: one change permission for unrelated concerns, and
  `SyncConfig` would need a merge migration.
- A startup error for a removed key. Rejected: an upgrade could fail to boot.

## Consequences

- No setting needs a restart.
- Deployments that keep these values in configuration files lose that control. They edit the Settings page.
- Code that read a setting through `plugin_setting()` now reads a row. Tests set rows instead of overriding
  Django settings.
