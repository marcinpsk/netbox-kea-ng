<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# opengrep ruleset

Custom [opengrep](https://github.com/opengrep/opengrep) rules that encode this
project's `AGENTS.md` security/correctness invariants as machine-checked gates,
so the same classes of bug stop coming back review after review.

## Why opengrep (and not just ruff / CodeQL)

- **ruff** (incl. the `S` / flake8-bandit rules) covers generic Python lint and
  security smells, but can't express project-specific call-shape rules.
- **CodeQL** (`.github/workflows/codeql.yml`) covers broad dataflow SAST.
- **opengrep** fills the gap: cheap, readable YAML patterns for *our* invariants
  — and it is the same engine **CodeRabbit** runs.

## Relationship to CodeRabbit

CodeRabbit skips its OpenGrep analysis when it detects OpenGrep in CI.
The custom rules run locally through the **pre-commit hook**. Keep OpenGrep
out of CI so CodeRabbit can run its own analysis on pull requests.

## Layout

| Path | Purpose |
| --- | --- |
| `.opengrep/kea-rules.yaml` | The ruleset. **Single source of truth.** Used by the pre-commit hook. |
| `.opengrep/tests/*.py` | Annotated rule-test fixtures (`# ruleid:` must match, `# ok:` must not). |
| `.semgrepignore` | Replaces opengrep's built-in ignore list, which skips every `tests/` directory. A rule that must not apply to tests excludes `**/tests/**` itself. |
| `scripts/opengrep-scan.sh` | Scan the source tree; used by the pre-commit hook. Exits non-zero on any finding. |
| `scripts/opengrep-test.sh` | Run the rule-tests against the ruleset. |

## Rules

| Rule id | Severity | Catches |
| --- | --- | --- |
| `kea-row-return-url-empty-fallback` | error | A row's `return_url` assigned from `_safe_return_url()` with an empty fallback. Row actions must retain the current list query. Limit: the rule checks this direct assignment only; it does not follow aliases or intermediate values. |
| `kea-queryset-model-attribute-discriminator` | error | A `model` attribute check used to distinguish querysets from model instances. Model fields can use the same name. |
| `kea-config-phase-without-reply-validation` | error | Direct config-test, config-set, or config-write calls that bypass `_one_command()` or `_config_mutation_command()` and their single-reply validation. |
| `kea-sync-hostname-unpublished` | error | A `.hostname` of a lease, Reservation or record passed as a call argument or in a `(hardware, hostname)` pair in `ipam_reconciliation.py` or `integrations/dhcp_plugin.py`, except to `lease_published_name()`. The IPAM and MAC sync report the name that Kea publishes (`published_name.py`), so both sources agree. Limits: it matches receiver names that end in `lease`, `reservation` or `record`, and it does not follow a hostname through a local variable. |
| `kea-get-client-missing-version` | warning | `server.get_client()` without `version=` (wrong daemon on dual-URL servers). |
| `kea-exception-detail-in-response` | error | `str(exc)` / f-string of a caught exception leaked into `messages.*` / HTTP / DRF responses or a JobRunner's `self.logger` job log (log `type(exc).__name__` there). |
| `kea-command-result-indexed-without-guard` | error | `client.command(...)[0]` indexed directly, before validating the response shape. |
| `kea-reservation-command-outside-adapter` | error | A `reservation-*` Kea command sent outside `kea.py`, which would put raw Reservation records in front of a consumer that cannot read their keys. |
| `kea-config-read-modify-write-without-reader` | error | A `config-get` read in a function that calls `config_set()`, bypassing `config_candidate()` and its `Dhcp4`/`Dhcp6` shape check. |
| `kea-unsupported-command-inline-check` | error | `exc.response.get("result") == 2` (or `["result"]`) outside `KeaException`; use the `unsupported_command` property. |
| `kea-change-rejection-caught-outside-mapper` | error | An `except` that names `ChangeRejected` in `views/` outside a function named `_run_change()` or `_run_change_loop()`. These functions, in `views/_base.py`, are the one place that turns a Configuration Change or Runtime Change outcome or rejection into a message. |
| `kea-change-mapper-outside-base` | error | A `def _run_change` or `def _run_change_loop` under `views/` in any file but `views/_base.py`. It closes the name exemption of the rule above. |
| `kea-change-in-broad-except` | error | A `config_write` or `runtime_change` call under `views/` inside a `try` whose `except` catches `Exception`, `BaseException`, or everything. That handler would also catch `ChangeRejected`. A call passed to `_run_change()` or `_run_change_loop()` as a lambda is exempt, because the mapper catches the rejection first. |
| `kea-runtime-write-outside-runtime-change` | error | A call of a `KeaClient` runtime write primitive (`lease_add`, `lease_update`, `lease_delete`, `lease_wipe`, `dhcp_enable`, `dhcp_disable`) outside `runtime_change.py` and the tests. `runtime_change` classifies the reply as applied, unknown or a rejection (ADR 0011). Limit: the rule matches the method name, so a call through an alias is not seen. |
| `kea-reservation-write-outside-config-write` | error | A call of a `KeaClient` Reservation write primitive (`reservation_add`, `reservation_update`, `reservation_del`) outside `config_write.py` and the tests. `config_write` holds the advisory lock of the Kea daemon and classifies the reply as applied, unknown or a rejection (ADR 0012). Limit: the rule matches the method name, so a call through an alias is not seen. |
| `kea-http-call-outside-client` | error | `requests.Session()`, `requests.get()`, `post()`, `put()`, `patch()`, `delete()`, `head()` or `request()` in `netbox_kea/` outside `kea.py` and the tests. `KeaClient.command()` is the one seam that applies the Server TLS settings on each request and reports a missing TLS file as a `RequestException`. Limit: it matches the `requests.` module prefix only, so an aliased import (`from requests import post`, `import requests as r`) is not detected. |
| `kea-mac-sync-write-without-savepoint` | error | Direct MAC lookup and save calls in `sync_mac_address()` outside `event_scope.atomic()`. The guard covers this synchronizer's savepoint boundary, not transaction ownership across other callers. |
| `kea-no-event-queue-internals` | error | `events_queue`, `EventContext` or `enqueue_event` in `netbox_kea/` outside the tests. NetBox owns its event queue; `event_scope.atomic()` uses only `event_tracking`. Limit: it matches the names as text, so a comment that names them also matches. |
| `kea-raw-atomic` | error | `django.db.transaction.atomic` (call, `with`, decorator, aliased import) in `netbox_kea/` outside `event_scope.py` and the tests. Every plugin transaction goes through `event_scope.atomic()`, which decides whether the block is a unit. |
| `kea-refusal-after-event-write` | error | A `raise` after `save()`, `delete()`, `create()`, `get_or_create()`, `update_or_create()` or an m2m `set()`, `add()`, `remove()`, `clear()` in an `event_scope.atomic()` block inside a `try`. Inside a transaction the block is a savepoint, and NetBox dispatches the event of the write that it rolled back. Limit: writes and raises inside called helpers and callbacks are not seen. |
| `kea-dispatch-error-swallowed` | error | An `event_scope.atomic()` block in a `try` whose `except Exception`, `except BaseException` (alone or in a tuple) or bare `except` has no `except event_scope.EventDispatchError:` clause in the same `try`. The clause re-raises, or, in the IPAM sync after a Runtime Change that Kea applied (`_run_lease_sync_to_netbox`, `_sync_to_netbox`, exempt by function name), reports the failed dispatch with `messages.error()` (ADR 0011). Limits: the handler order is not checked; a `try` with `finally` and handlers in callers are not seen. The one reviewed broad handler above units is the IPAM job's per-Server catch in `jobs.py`, which logs the error and counts it in the job report. |
| `subprocess-without-timeout` | error | `subprocess.run()`, `call()`, `check_call()`, or `check_output()` without `timeout=`, in the package, the scripts, or the tests. A child process that stops responding would block the caller with no limit. |
| `netbox-ipam-get-or-create-non-unique-key` | error | `get_or_create()` or `update_or_create()` on `Prefix`, `IPRange`, or `IPAddress`, directly or on a queryset chain such as `.filter(...)`. An exact `pk=` or `id=` lookup is exempt. NetBox does not enforce these keys in the database, so a duplicate row makes every call raise `MultipleObjectsReturned`. |
| `netbox-ipam-mutation-outside-reconciliation` | error | Deletes and status writes on `IPAddress`, `Prefix` and `IPRange` outside `netbox_kea/ipam_reconciliation.py`. Covers direct queryset chains, local query bindings and typed helper parameters, including import aliases. Tests and migrations are excluded. |
| `kea-request-number-without-ascii-check` | error | `str.isdigit()`, `isdecimal()` or `isnumeric()`, a `\d` in an `re` pattern, and `int()` of a request value: `request.GET`, `POST`, `query_params` or `data`, a `params` mapping, or form `cleaned_data`, directly or through a local variable. These also accept other Unicode digits, so `?subnet_id=١٢` reads Subnet 12. Use `parse_decimal()` from `netbox_kea/decimal_text.py`. Limit: a value passed to another function as a parameter is not followed. |
| `kea-snapshot-notice-outside-notice-module` | error | A read of `.diagnostics`, or `messages.ERROR` or `messages.WARNING`, in `views/` outside `views/notices.py`. One function there codes the Presentation rule of ADR 0003 for every Snapshot; a view that picks a level by hand codes it again. Exempt: the change outcome in `_run_change()`, `_rejection_message()`, `_unconfirmed_message()` and `_persistence_failure()`, the Reservation search that builds its Snapshot in `_read_reservations()`, the lease export refusal in `_incomplete_export_message()`, and a function that parses a Reservation Transfer Document. Limits: a messages constant imported by name, diagnostics passed to a helper outside `views/`, and templates are not seen. A `messages.error()` or `messages.warning()` call is not seen either, because non-Snapshot messages use these calls correctly. |
| `kea-snapshot-read-without-notice` | error | A function in `views/` that reads a Catalogue, Server Configuration, Reservation or Lease Snapshot (directly, through a named read helper, or through `executor.submit()`) and calls none of `notice()`, `failed_load()` and `load_snapshot()`. The rule names each exempt function and its reason: read helpers whose callers use the loader, and reads that only feed another read, a badge, a check or a preview. Limits: a helper that the rule does not name, another function reference, an aliased import and a Notice made in a called helper are not seen. `test_snapshot_notice_sweep.py` covers the pages at run time. |
| `kea-view-read-ladder` | error | A `try` anywhere in `netbox_kea/` (outside `read_failure.py`, `kea.py` and the tests) with an `except` that names `KeaException`, `requests.RequestException`, `MalformedKeaReply` or `KeaClientSettingsError`, alone or in a tuple. `read_failure.attempt()` is the one classifier of a failed Kea read (ADR 0015): it returns a `ReadFailure` with the kind and logs the failure, and the caller maps the kind. Exempt by function name: the write classification of `change_outcome.mutate` and `config_write._test_before`. Limits: an `except` of `Exception`, of a subclass such as `requests.ConnectionError` or `MalformedReply`, or of an aliased import is not seen. |
| `kea-catalogue-absence-without-consistency` | error | `not <catalogue>.configuration_complete` in `views/` or `subnet_catalogue.py`. A Catalogue with disagreeing sources omits the disputed Subnets, so absence needs `configuration_confirms_absence`. Limits: only the negated attribute read is seen. |
| `kea-cache-outside-display-cache` | error | `django.core.cache` (`cache`, `caches`, `import django.core.cache`, `from django.core import cache`, or an import from it), or a private name of `display_cache` in `netbox_kea/` outside `display_cache.py` and the tests: an absolute or relative import of the name (`from .display_cache import _generation`, also in parentheses), or an attribute of the module (`display_cache._generation`, also through `from . import display_cache as x`). That module owns every key, the configuration and records generations, the TTLs and the admission rule (ADR 0009); a key built in another module has none of the generations. Limits: another cache library, `getattr()`, a re-export, and a cache reached through a helper outside `netbox_kea/` are not seen. |
| `kea-ownership-read-without-database-error` | error | `address_ownership()` or `prefix_ownership()` in `views/` outside a `try` that catches `DatabaseError` (alone or in a tuple). The IPAM Ownership read only feeds a badge or an advisory, so a failed read shows the unknown state or no advisory, not a 500 reply. Limits: a call inside an `except` or `finally` block of such a `try`, an aliased import and a call through a helper are not seen. |
| `kea-option-path-outside-planned-options` | error | `kea_paths.option()` in `netbox_kea/integrations/` outside `PlannedOptions` and the tests. The DHCP Import names a DHCP Option with `PlannedOptions.paths()`: a keyed Option takes the path of its `OptionKey`, which a later run also uses when it removes it, so one Kea option has one path in the run results. Limits: an import of the function by name and a call through a helper are not seen; the parse step in `mappers/` keeps the literal path, because it runs before the definitions are known. |
| `kea-object-path-outside-key` | error | `kea_paths.subnet()`, `pool()`, `pd_pool()`, `reservation()`, `client_class()`, `shared_network()` or `option_definition()` in `netbox_kea/integrations/` outside a `path(self, family)` method and the tests. Each planned object of the DHCP Import has one key, and its `path()` gives the one path of the object when a run creates it and when it removes it. A writer that renders the path again can name the object by a second path. Limits: an import of a function by name and a call through a helper are not seen; the parse step in `mappers/` keeps its literal paths. |
| `kea-dhcp-row-write-outside-protocol` | error | `observe_mapping()`, or a `try` with the pair `except event_scope.EventDispatchError: raise` and `except ManagedFieldsMismatch: raise`, in `netbox_kea/integrations/` outside `dhcp_import_write.py` and the tests. Every imported DHCP plugin row but the DHCPServer goes through `write_row()` and a `RowAdapter` of its kind, which finds or adopts the row, writes it, observes its mapping, reports a failed write in one failure table and skips the planned subtree of an object that it does not write. Exempt by name: `upsert_dhcp_server()` and `_apply_global_settings()`, the writers of the root of a run. Limits: a writer that bypasses the protocol without calling `observe_mapping()` or opening the pair is not caught, and a call through a module attribute or an aliased import is not seen. The pair matches in this handler order only (`EventDispatchError`, then `ManagedFieldsMismatch`), and the exemptions go by function name. A lone `except event_scope.EventDispatchError: raise` is not the pair. |

The adjacent snapshot rule uses the stdlib AST checker
`netbox_kea/tests/snapshot_discipline.py`. It checks that loaded model saves take
a snapshot before their first direct mutation or known mutation-helper call.
It also rejects a later snapshot that overwrites the old values. An explicit
inventory classifies direct save sites; new or changed sites require review.
The checker runs in the native suite and the `snapshot-discipline` pre-commit
hook. Its direct-receiver scope and limits are documented in
[the design record](https://github.com/marcinpsk/netbox-kea-ng/issues/178).
It has no baseline or inline suppression marker.

## Running locally

```bash
# Scan (same as the pre-commit hook):
./scripts/opengrep-scan.sh

# Run the rule-tests:
./scripts/opengrep-test.sh
```

Both scripts find opengrep via `$OPENGREP_BIN`, then `PATH`, then
`~/.local/opt/opengrep/bin`. Install opengrep from
<https://github.com/opengrep/opengrep> (or set `OPENGREP_BIN`).

## How it gates commits

The `opengrep` hook in `.pre-commit-config.yaml` runs at the **pre-commit** stage
when Python files, `.opengrep/`, OpenGrep scripts, or the hook configuration change.
It scans the whole package, `scripts/`, and `tests/`. Install the hook types once:

```bash
uv run --system-certs pre-commit install --install-hooks
```

The custom OpenGrep gate runs locally only. A commit made with `--no-verify`
bypasses it.

## Suppressing a true exception

Add an inline `# nosemgrep: <rule-id>` on the offending line, with a short reason
comment above it — see `views/server.py` (the version-agnostic Control Agent
status call).

## Adding a rule

1. Add the rule to `.opengrep/kea-rules.yaml`.
2. Add a fixture `.opengrep/tests/<rule-id>.py` with `# ruleid:` / `# ok:` lines.
3. `./scripts/opengrep-test.sh` — confirm it passes.
4. `./scripts/opengrep-scan.sh` — confirm the existing tree is clean (or fix it).
