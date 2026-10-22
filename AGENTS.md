<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md — netbox-kea-ng

Guidance for AI coding agents (and humans) working in this repository. This is the
single source of truth for repo conventions; `CLAUDE.md` points here.

A NetBox plugin that integrates [Kea DHCP](https://www.isc.org/kea/) server
management. Published to PyPI as **`netbox-kea-ng`** — a fork of
[netbox-kea](https://github.com/devon-mar/netbox-kea) by Devon Mar. The Django
app/module name remains `netbox_kea` (unchanged from upstream). It exposes a
`Server` model representing a Kea endpoint, with views for live daemon status,
lease search/add/edit/delete, host-reservation CRUD, subnet/pool/shared-network
management, DHCP option editing, and automatic Kea→NetBox IPAM sync via a
background job.

**Kea connection model.** Kea 3.0 deprecated the Control Agent and Kea 3.1.8 removed it: each DHCP daemon
exposes its own HTTP control socket, so the plugin connects **directly** to each
daemon (`has_control_agent=False`, the modern default for Kea 3.0+). A legacy
Control Agent (before Kea 3.1.8, or a per-protocol CA) is still supported via
`has_control_agent=True`. This flag is the single source of truth for request
routing — see "Protocol-aware / direct-daemon client" below.

## Build, Test & Lint

```bash
uv sync                                    # install dev dependencies (activates .venv via .envrc)
uv build                                   # build wheel (required before integration tests)
uv run ruff check .                        # lint
uv run ruff format --check .               # check formatting
uv run ruff format .                       # auto-format
uv run reuse lint                          # SPDX/REUSE compliance
uv run --group docs zensical build --strict  # documentation site (Python 3.11+): mkdocs.yml, pages in docs/guide/
uv run --native-tls pre-commit install --install-hooks  # install configured hook types
./scripts/opengrep-scan.sh                 # custom opengrep ruleset gate (pre-commit only)
./scripts/opengrep-test.sh                 # opengrep rule tests
uv run ./scripts/mypy-gate.sh              # type check, new errors only (pre-push + CI)
uv run ./scripts/mypy-gate.sh --sync       # rewrite mypy-baseline.txt after fixing errors
```

### Unit tests (`netbox_kea/tests/`)

`testpaths` in `pyproject.toml` defaults to `netbox_kea/tests`. Unit tests run
against a **real NetBox install and a PostgreSQL test database** — NetBox requires
PostgreSQL (array/JSON fields, etc.); SQLite is not used. They do **not** need the
Kea/integration Docker stack: every Kea HTTP call is stubbed at the transport
boundary (see "Testing philosophy" below).

Use a task-specific PostgreSQL database and a dedicated Redis host. Each xdist
worker gets a private PostgreSQL database and private Redis task and cache
databases. Eight workers is the supported maximum. `-n auto` is capped there by
`pytest_xdist_auto_num_workers` in `netbox_kea/tests/conftest.py`, so it is safe on
any machine. Always use xdist, including for focused tests. A serial run can clear
Redis database 1, which the shared manual verification environment uses as its
default cache.

`TEST_DB_NAME` must start with `test_`; `TEST_REDIS_HOST` names a Redis reachable
from the run. Both are required. The values below are recommended local defaults. CI
sets its own database name for each job. Change them to something only this task holds
when another project shares the host: a shared database is rebuilt by whichever suite
runs `--create-db` next, and a shared Redis is written to by every worker.

```bash
TEST_DB_NAME=test_netbox_kea_local TEST_REDIS_HOST=localhost \
  uv run --native-tls pytest --reuse-db -n auto --maxschedchunk=1
TEST_DB_NAME=test_netbox_kea_local TEST_REDIS_HOST=localhost \
  uv run --native-tls pytest --reuse-db -n auto --maxschedchunk=1 netbox_kea/tests/test_views_leases.py -v
```

`pythonpath` is set to `/opt/netbox/netbox` and
`DJANGO_SETTINGS_MODULE=netbox_kea.tests.isolated_settings`
— unit tests require a NetBox installation at that path (present in the devcontainer).

### Integration tests (`tests/`, Docker required)

```bash
./tests/test_setup.sh   # generates TLS certs, builds a wheel, starts the compose stack
uv run --native-tls pytest -p no:django tests/ --tracing=retain-on-failure -v --cov=netbox_kea --cov-report=xml
```

`test_setup.sh` copies the CA bundle to `tests/docker/host_ca.crt` for the `host_ca` build
secret, because buildx refuses a secret file outside the project. The source defaults to
`/etc/ssl/certs/ca-certificates.crt`. Set `SSL_CERT_FILE` to the local CA bundle on any host
that keeps it elsewhere (for example `/etc/pki/tls/certs/ca-bundle.crt`).

The compose stack runs: NetBox, netbox-worker, postgres, redis, nginx (basic-auth
+ TLS), and **kea-dhcp4 / kea-dhcp6 as direct daemons** (no Control Agent). The
daemons run with `-X` because Kea 3.2.0 refuses to start with an unsecured HTTP
control socket; the sockets are loopback-bound with nginx terminating auth in front.
The suites wipe the leases of these daemons. The `kea_harness_daemons` fixture in `tests/conftest.py` reads each
daemon's configuration first and refuses one whose global `user-context` lacks `"netbox-kea-test-harness": true`
(set in `tests/docker/kea_configs/`). Every fixture that writes to Kea takes its URLs from that fixture.

### Browser tests (`tests/ui/`, Docker required)

Playwright tests are part of the integration suite: one run over `tests/` covers both,
against the same compose stack. `tests/ui/conftest.py` holds the one browser harness
both modules share: login, the Server object, a real `KeaClient` on each daemon's
loopback socket, and HTTP-error tracking. `test_ui.py` covers tables,
search, and permissions; `test_workflows.py` covers navigation, badge enrichment, and
CRUD lifecycles.

They used to live in a top-level `e2e/` directory that no workflow named, so they never
ran anywhere. `test_pytest_configuration.py` now asserts the suite stays inside the path
the integration job executes.

`test_branching_refusal.py` needs the netbox-branching variant of the harness: set
`COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.branching.yml` and
`NETBOX_BRANCHING_VERSION` (the value in the `env` of `.github/workflows/ci.yml`) before
`test_setup.sh`, with a NetBox 4.7 image. Elsewhere it skips; `NETBOX_KEA_REQUIRE_BRANCHING=1`
makes it fail instead.

### Documentation media (`tests/docs_media/`, Docker required)

The site pages show screenshots and short recordings that CI makes from the commit it builds. Git never holds them:
`docs/guide/assets/screenshots/` and `docs/guide/assets/recordings/` are in `.gitignore`, and the pre-commit hook
`no-committed-media` refuses any image or video. The suite runs only when
`--docs-media-dir` names the media root, so the integration run over `tests/` leaves it out. It drives the `tests/ui`
harness and loads one demo data set. `test_screenshots.py` writes each view as `screenshots/<name>-light.png` and
`<name>-dark.png`. `test_recordings.py` records each workflow in the light color mode as `recordings/<name>.mp4`
(H.264) with the poster `<name>.png`, and the Sync clip also as the README GIF. `tests/docs_media/recording.py` draws
the pointer, paces the steps and encodes with the ffmpeg of `imageio-ffmpeg` (dev group). Each recording changes one
lease of subnet 2, which no screenshot shows, and its fixture removes the change. `zensical build --strict` does not
check media, so `scripts/check_docs_media.py` reads the `<img src>`, `<video src>`, `<video poster>` and `<source src>`
of each built page. It fails on a page that shows a file that the site does not hold, on a captured screenshot or
recording that no page shows, and on a README image under the `site_url` that the site does not hold. Each page builds
to `<page>/index.html`. Zensical rewrites a `<source src>` like a Markdown link, but not a `<video poster>`, so a page
names `<source src="assets/recordings/<name>.mp4">` and `poster="../assets/recordings/<name>.png"`.
`docs/guide/assets/js/autoplay-videos.js` plays each `muted` video while half of it is on the screen, and pauses it
when it goes away. It does nothing when the reader prefers reduced motion.

Start the harness with `docker-compose.docs.yml` on top of the two base files. It runs each Kea daemon on a writable
copy of its configuration, so `config-write` succeeds and the clips show no persistence failure. The suite refuses a
daemon that cannot write its configuration. Set `COMPOSE_FILE` for the setup command only: the other suites keep
the read-only configuration.

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.docs.yml ./tests/test_setup.sh
uv run --native-tls pytest -p no:django tests/docs_media --docs-media-dir docs/guide/assets
uv run --group docs zensical build --strict
uv run python scripts/check_docs_media.py site docs/guide/assets
```

### CI

- **Unit-test job**: pinned to the exact NetBox patch release named by
  `QUERY_COUNT_NETBOX_VERSION` in `netbox_kea/tests/conftest.py`, because
  `netbox_kea/tests/query_counts.json` describes that release only (see "Query-count
  baselines"). Bump the constant, `NETBOX_RELEASE` in the workflow `env`, and the baselines in one
  change.
- **Event-rollback job (NetBox 4.3)**: runs `test_event_scope.py` on the supported floor, where
  `event_scope.atomic()` is always a plain transaction. Keep that module free of netbox-branching fixtures.
- **DHCP plugin job**: runs with netbox-plugin-dhcp 0.2.0. A test module that skips without `netbox_dhcp`
  must be in its file list (or the branching job's). `test_pytest_configuration.py` fails when one is missing.
- **Branching job**: the unit-test NetBox release with netbox-branching 1.2.1 and netbox-plugin-dhcp 0.2.0.
  It runs `test_branching.py` and `test_dhcp_mapping_recovery.py` with
  `NETBOX_KEA_REQUIRE_BRANCHING=1`, so these modules fail
  instead of skipping when netbox-branching is absent. `netbox_kea/branching.py` is the only
  module that imports `netbox_branching` (ADR 0007, `docs/design/netbox-branching.md`).
  Every migration sets `fake_on_branch`; guard 4 in `test_branching.py` checks the value.
  `BranchRefusalMiddleware` in `branching.py` refuses every unsafe request to a netbox_kea URL
  callback in a branch, or with an unusable branch selection. Below the middleware, `KeaClient.command()`
  refuses a `write` member of `KeaCommand` with `BranchActive` (`Server.get_client()` binds the client
  to the active branch, also in a worker thread), `pre_save` and `pre_delete` receivers in
  `branching.py` refuse a save or a delete of every netbox_kea row except `KeaDhcpLink`, and `KeaIpamSyncJob` fails before
  any read. Guard 1 in `test_branching.py`
  sends GET, HEAD, OPTIONS, POST, PUT, PATCH and DELETE to every netbox_kea URL in a provisioned
  branch, API action routes included; a new route with a parameter the guard cannot build fails
  by name, so teach `_route_arguments` the object.
  DHCP Import Mappings follow their imported target (one netbox_dhcp model for each kind in
  `MAPPING_KINDS`, `models.py`) through native squash merge and revert. `dhcp_mapping_lifecycle.py` owns their history and writer boundaries.
  Before changing mapping writes, target deletion or branch replay, read ADR 0008 and
  `docs/design/dhcp-import-mapping-transactions.md` for the recovery contract and lock order.
  Read `docs/design/dhcp-import-mapping-lock-scope.md` before changing which writes, deletions or
  imports take the mapping lock, or how a lock error maps to a refusal.
- **Compatibility matrix**: runs the integration suite (`test_setup.sh`) against
  NetBox v4.3 (floor), v4.7 (ceiling), and the dev snapshot (allowed to fail).
- **Branching browser job**: the integration steps on the netbox-branching variant of the
  harness (a NetBox 4.7 image), running only `tests/ui/test_branching_refusal.py`.
- **Documentation job**: the reusable workflow `docs-build.yml` starts the docs variant of the harness with NetBox 4.7, runs the
  media suite and the media check, and builds the site with `--strict`. `ci.yml` calls it on pull requests to
  `main` and in the scheduled run, and uploads the site as an artifact. `docs.yml` calls it for one release tag and
  deploys the site to GitHub Pages, so the site shows the latest release only. `release.yml` calls `docs.yml` after
  a release, in a separate job, so a failed deployment leaves the PyPI release in place. The deploy job refuses a tag
  that is not the latest GitHub release. To deploy the latest release again, dispatch `docs.yml` from `main` with its tag. The lint job has no screenshots or recordings, so its link check
  excludes them.
- Playwright traces on failure are uploaded as artifacts.

Ruff is configured in `pyproject.toml`: line length 120, max complexity 15,
migrations excluded, E501 ignored (handled by the formatter). Docstrings required
except in tests, migrations, and `__init__.py`.

## Architecture

```text
URL request
  → urls.py             (routes to view classes)
  → views/              (view modules; each calls server.get_client() → KeaClient)
      _base.py          (ConditionalLoginRequiredMixin, _KeaChangeMixin, shared helpers)
      notices.py        (the one notice rule of a read: notice(), load_snapshot(), load_target() and the channels; ADR 0003)
      read_age.py       (the read age line and Refresh control of a cached table; ADR 0009)
      server.py         (Server CRUD, status tab)
      leases.py         (DHCPv4/v6 lease search, add, edit, delete, badge enrichment)
      reservations.py   (DHCPv4/v6 reservation CRUD)
      subnets.py        (subnet/pool management)
      shared_networks.py (shared network CRUD)
      options.py        (global and per-subnet DHCP option editing)
      dhcp_control.py   (enable/disable DHCP daemons)
      combined.py       (cross-server dashboard, reservations, subnets; the lease Server chooser)
      server_scope.py   (Server selection, view permissions, and family availability)
      fan_out.py        (the per-Server read pool of combined Subnets, Shared Networks, Reservations)
      sync_views.py     (per-server IPAM sync UI)
      sync_jobs.py      (jobs tab, periodic sync management)
      settings_page.py  (Settings page: one section per settings singleton; ADR 0010)
  → reservation_edit.py (Reservation add/edit/import, signed form state, Published Name rules and after-apply facts)
  → config_write.py     (Configuration Changes, Reservation writes included: typed outcome, advisory lock, persist step)
  → change_outcome.py   (ChangeRejected and the Application classifier that every change shares; ADR 0011)
  → runtime_change.py   (Runtime Changes: Lease add/edit/delete/wipe, DHCP enable/disable; ADR 0011)
  → kea.py              (HTTP POST to each daemon's / control socket)
  → display_cache.py    (the display cache: keys, generations, TTLs, admission; ADR 0009)
  → lease_reads.py      (the cached Lease Snapshot reads of the Leases tab and of the Lease badges; ADR 0009)
  → lease_reservation_reads.py (Current Lease Presence of Reservation rows and Reservation Match of Lease rows:
                        cached lookups in one worker pool)
  → sync.py             (the aggregate Reservation Synchronization State and DCIM MAC synchronization)
  → ipam_reconciliation.py (IPAM Ownership links, stale cleanup, per-row savepoints; ADR 0006)
  → ipam_marker.py     (the `[kea-sync: <kind>]` description marker: parse, rewrite, legacy text; ADR 0006)
  → jobs.py             (KeaIpamSyncJob — periodic background sync)
  → tables.py           (non-model GenericTable renders enriched dicts)
  → template            (django-tables2 + HTMX for pagination)
```

### Core components

- **`Server` model** (`models.py`): stores connection
  config: `ca_url` (default/fallback endpoint), optional per-protocol `dhcp4_url` /
  `dhcp6_url` (dual-URL mode), CA and per-protocol credentials, TLS fields
  (`ssl_verify`, `ca_file_path`, `client_cert_path`, `client_key_path`),
  `has_control_agent`, per-server IPAM sync toggles, `sync_vrf` (`PROTECT` FK to `ipam.VRF`;
  blank = global table), and `persist_config`. `clean()` validates local settings only.
  `server_connection.py` checks enabled services on UI, REST, CSV and bulk submissions
  that create a Server or change connection values. Metadata and unchanged connection values send no HTTP.
  `get_client(version=4|6|None)` returns a protocol-aware `KeaClient`.
- **Settings singletons** (`models.py`, ADR 0010): every runtime setting is a field of a `SettingsSingleton`
  row (pk=1). `SyncConfig` holds the sync settings (`interval_minutes`, `sync_enabled`, the type toggles,
  `sync_max_leases_per_server`, `stale_ip_cleanup`); `KeaClientConfig` holds `kea_timeout` and
  `lease_query_max_unpaged_leases`, and `Server.get_client()` reads it on each call. `DhcpIntegrationConfig` holds
  `enabled`, the global switch of the DHCP plugin integration, and `scheduled_import_enabled`.
  `DisplayCacheConfig` holds the TTL of each read kind of the display cache. `dhcp_plugin.integration_refusal(server)` is the one
  rule that combines `is_available()`, `Server.sync_dhcp_plugin_enabled` and that switch; no other code combines
  them. Guards that keep DHCP plugin references safe from cleanup check `is_available()` only. Defaults live on the
  model fields. Migrations 0018, 0025, 0026 and 0027 create the rows, and 0018 and 0025 copy the values of
  `PLUGINS_CONFIG` once, so `get()` only reads. After that the plugin reads no `PLUGINS_CONFIG` key:
  `NetBoxKeaConfig.ready()` logs a warning for each key of `REMOVED_SETTINGS` that is still set. A TransactionTestCase flush deletes the rows, and a
  `post_migrate` receiver in `netbox_kea/tests/conftest.py` creates each of them again: SyncConfig and
  KeaClientConfig with the migrations' values, every other row with its model defaults. They
  inherit `ChangeLoggingMixin` (not a `NetBoxModel`), so a save in a request writes an ObjectChange;
  `api/serializers.py` has a brief serializer for each because NetBox's change log API serializes each changed
  object. The Settings page (`views/settings_page.py`) has one section for each row (`SECTIONS`): a section shows
  with the view permission of its model, a save needs the change permission too, and the view calls `snapshot()`
  before the form changes the row. A section whose `available()` is false (the DHCP Plugin section without
  `netbox_dhcp`) does not show, and a save of it is refused. `navigation.py` builds one menu item for each available
  section. The adoption cleanup locks the `Server`, `SyncConfig` and `DhcpIntegrationConfig` tables to freeze policy.
  A new settings row needs a model, a migration that creates the row, a brief serializer and a `SECTIONS` line. The
  page builds the form from the model fields (`modelform_factory`) and renders them with `inc/settings_fields.html`
  unless the section names its own include; a test fails while a singleton has no section. A section can give a
  one-sentence `description` that the page shows under its heading, for a fact about the whole section. A worker
  thread opens no database connection: `PinnedSettings.read(*models)` reads rows on the request thread, and in each
  `PinnedSettings.context()` (one for each worker task) `SettingsSingleton.get()` returns the pinned row and raises
  `RuntimeError` for a model that is not pinned. `fan_out` pins `KeaClientConfig` and `DisplayCacheConfig`.
- **`KeaClient`** (`kea.py`): wraps a `requests.Session`. All API calls go through
  `.command(command, target, arguments, check)`, the only HTTP send of the plugin, which POSTs
  JSON to the **configured endpoint URL** (`self.url`: the daemon's `/` control socket, or a
  Control Agent URL). `command` is a `KeaCommand` member, never a string (a string is a
  `TypeError`); each member has a `read` or `write` kind. `target` is the `Family` (4 or 6), or
  `None` for the Control Agent itself. A family-specific command comes from a per-family mapping
  in `kea.py`, such as `SUBNET_LIST[family]`; never format a command name. A new member needs an
  entry in the pinned read or write set of `test_kea_command.py`. `write_guard` and `on_write` are
  required keyword arguments: `Server.get_client()` passes the branch binding and the generation rotation
  of the display cache, and unit tests build clients through `kea_stub.kea_client()`, which passes both (its
  `on_write` does nothing). Responses are `list[KeaResponse]`; `check_response()` raises `KeaException`
  if any result code is not in `check`. `command()` passes the TLS settings (`verify`, `cert`) on each request, so the
  `REQUESTS_CA_BUNDLE` environment variable cannot replace a CA file or `ssl_verify=False`. A TLS file
  that requests cannot find raises `KeaTLSFileError`, a `requests.RequestException`, so each
  handler of request errors also handles it. Basic Auth credentials that are not Latin-1 text raise
  `KeaRequestEncodingError`, also a `requests.RequestException`, when `command()` prepares the request before the
  send. In both cases nothing was sent, and `change_outcome` rejects a change as `invalid-client-configuration`.
  requests can also fail to encode credentials after the send: it prepares the next request of a redirect reply
  (from `.netrc`) also when it does not follow it. That failure is a plain `RequestException`, so a change is
  `unknown`. A client is not thread-safe, so each worker
  thread builds its own.
  **`send_service`**: `command()` sends the target as the `service`
  argument only when the server is fronted by a Control Agent
  (`send_service = has_control_agent`); a direct daemon drops it, because Kea 3.2.0+
  rejects a `service` that does not match the daemon the request lands on.
- **Display cache** (`display_cache.py`, ADR 0009): the only module that touches the Django cache. The OpenGrep
  rule `kea-cache-outside-display-cache` refuses `django.core.cache` and the private names of the module in other
  modules. `cached(server, family, kind, read, query=, refresh=)` serves the `display()` reads of
  `server_configuration` (kind `configuration`) and `subnet_catalogue` (kind `catalogue`), each Reservation page
  of the Server tab and the combined page (kind `reservations`, in `views/reservations.fetch()`), each Lease Snapshot
  of the Leases tab and of the Lease badges of Reservation rows (kind `leases`, in `lease_reads.cached_read()`), each
  Reservation lookup of a Lease row (kind `reservation_lookups`, in `lease_reservation_reads._ReservationLookups`), Subnet
  utilization (kind `utilization`, in `views/_base._enrich_subnet_statistics()`) and the `status-get` and
  `version-get` reads of the Overview and the combined status badge (kind `status`, in `views/_base.daemon_status()`
  and `daemon_version()`). It stores only a value whose `settled` property is true (the `Cacheable` protocol). A
  failed read raises, so it is never stored. A Reservation entry (`_ReservationPage`) holds the page Snapshot and the
  Subnet Catalogue it was parsed against, so a hit sends no Catalogue read; it is settled only when both are. A
  Reservation walk that an error stopped (`page-fetch-failed`, `pagination-stalled`) is not settled; a walk stopped at
  its limit is. A Lease entry (`LeaseRead`) holds the Snapshot, or the Catalogue that could not resolve a
  Subnet search; the view shows its Notice. A Subnet search resolves its CIDR inside the cached read through a live Catalogue read, keyed by the
  unresolved search, so a hit sends no Kea command; a result of a Catalogue that did not settle is not stored. A Lease
  search key holds the Attribute, the value and the state; a read of every Lease also holds the cursor and the page
  size. `LeaseSnapshot.settled` is always true: a failed Lease read raises, and each diagnostic excludes one record.
  A Lease badge of a Reservation row is an ordinary Lease search, so it shares the entry of the same Leases tab
  search. A lookup that finds no Reservation is stored. `_KINDS` names the TTL field of `DisplayCacheConfig` and the
  generations of each kind; a TTL of 0 sends every read to Kea. A key holds the Server, the family, the kind,
  `netbox_kea.__version__` (an upgrade makes entries of the old class shapes unreachable), its generations, a keyed
  digest of `Server.kea_connection()`, `last_updated` of the settings row (a settings save makes every entry
  unreachable), and a digest of the query parts. The configuration kinds hold the configuration generation;
  `reservations`, `leases`, `reservation_lookups` and `utilization` also hold the records generation, because a write
  changes them. `status` holds no generation, because a daemon changes its status without a plugin write; it alone
  takes the family `None` of the Control Agent. `refresh=True` removes the entry and reads live, so a refresh that
  fails or is not settled leaves no entry; a Reservation Refresh also reads the Catalogue live
  (`subnet_catalogue.display(refresh=True)`), and so does a Leases Refresh, before its search form. The Refresh control
  (`views/read_age.py`, `inc/read_age.html`) sends an htmx GET of the same URL with the `X-Kea-Refresh` header and
  swaps the Reservation section (`#kea-reservations`), which holds the warnings, the search card and the table, or the
  Lease section (`#lease-search`). An error of a Refresh shows inside the section: the Leases view passes the section
  id to `exception_htmx.html`. The page shows "Read N s ago" from `read_started` of the Snapshot (the oldest one on a
  combined page). A badge entry holds its read time, and the badge passes the read time of its table to the `fresh`
  predicate of `cached()`: an entry read before the table is read again. So a badge is never older than its table, and
  a Refresh, which reads the table live, also reads the badges of the shown rows live. No refresh flag reaches a badge. Utilization and status have no read age and no Refresh. The
  badge lookups run in worker threads that pin `DisplayCacheConfig` and `KeaClientConfig`, and a failed badge lookup
  is a typed Unknown that logs no traceback (`lease_reservation_reads`).
  Each cached Lease, utilization and status read builds its client on a miss only and closes it
  (`views/_base.LazyClient`; the badge pool of Reservation and Lease rows builds one per worker thread, in
  `lease_reservation_reads.WorkerClients`); a close that fails is logged. Exports
  (`ReservationQuery(full=True)`, the Lease `get_export` through `read_leases()` and `get_export_all`, the utilization
  of a Subnet export), the API, `ipam_reconciliation`, the edit and delete target loads, `_checked_lease`, the read
  back of a created Lease and the `version-get` connectivity check of `server_connection` read live. `KeaClient.command()` calls
  `on_write(family, configuration=False)` before and after each write command, also when the send fails, and
  `_config_mutation_command` calls `on_write(family, configuration=True)` around a live configuration mutation,
  a Reservation write included.
  `Server.get_client()` binds it to `rotate_after_write`, which rotates the records generation (both families for
  `None`) and, for a configuration change, the configuration generation. `MutationScope` calls
  `rotate_configuration`. A rotation failure is logged, and the write continues. The callers validate the family;
  the module takes a `Family`, or `None` for the Control Agent in `cached()`. Authority reads (`for_verification`, `for_synchronization`, `for_import`,
  `read_identity`, mutation scopes) never read or fill the cache. `fan_out` pins the settings row for its workers
  (see "Settings singletons"). The test fixture `_plugin_cache_hygiene` clears `display_cache.KEY_PREFIX`
  around each test.
- **`sync.py`**: builds the aggregate Reservation Synchronization State and synchronizes DCIM MAC addresses.
  IPAM ownership reads, creation, status changes and cleanup belong to `ipam_reconciliation.py`.
- **`ipam_reconciliation.py`**: `reconcile(server, family, phases) -> SyncReport` (ADR 0006). The job's
  lease, Reservation, Subnet and Pool phases run through it: it links each reported IPAM object in `Server.sync_vrf` under
  an advisory lock on the identity and a row lock, the status comes from the live links, and a complete
  phase removes its own stale links. The last link of a Server to an IP address needs a complete lease phase and a complete
  Reservation phase, unless that Server disables Reservation sync. The last link of an IP address follows `stale_ip_cleanup`. A complete Subnet or Pool phase
  drops its own stale links; `Server.sync_deprecate_prefixes_and_ranges` opts in to deprecation, never deletion.
  `read_catalogue` pairs the shared snapshot with a cutoff taken before its request. Per-row actions use
  `claim`, which never cleans up. Adoption preserves legacy object identities and marks their links.
  Complete whole-workflow job and DHCP import receipts protect each adopted object's last link until all
  relevant enabled owners have observed their sources. `Server.ipam_first_complete_at` records the initial
  completion time. Internal scoped receipts protect newly enabled sources after that time.
  Read `docs/design/ipam-upgrade-adoption.md` when changing adoption, completion receipts or upgrade cleanup.
  The job reads one `LeaseObservation` per family for its address `LeasePhase` and its DHCPv6 `LeasePrefixPhase`
  (source `lease-prefix`, enabled by the lease and the Prefix flags together). Both own objects only through Current Leases.
  A lease link records its `allocation_kind`; an unclassified DHCPv6 lease link is never cleaned up (ADR 0006).
- **`jobs.py`**: `KeaIpamSyncJob` (`@system_job`). Iterates all `Server` objects,
  runs subnet/lease/reservation/prefix/range sync phases, writes a per-server
  summary to the job log. Then, with `DhcpIntegrationConfig.scheduled_import_enabled` on, a separate pass calls
  `run_dhcp_plugin_import(server, DhcpImportTrigger.SCHEDULED)` for each Server that `integration_refusal` accepts.
  A Run Now of one Server (`server_pk`) skips that pass. A Server fails when a family has a `READ_FAILED` or
  `WRITE_FAILED` entry of any kind or IPAM ownership errors (`_failed_facts`; `ImportSummary.errors` counts less),
  or when the import raises. A failed Server fails the job and the pass continues. Only `ImportRunning` (another run
  holds the import lock) skips a Server. An `EventDispatchError` of either pass stops the job.
- **DHCP Import** (`integrations/`): `dhcp_import.run_dhcp_plugin_import(server, trigger)` reads Kea for every
  enabled family, plans each family (`dhcp_import_plan.py`) and applies each plan (`dhcp_plugin.apply_plan`). Each
  DHCP Server, Shared Network, Subnet, Pool, delegated-prefix Pool, Reservation, client class, custom Option
  Definition and DHCP Option that the apply writes has a DHCP Import Mapping (`KeaDhcpLink`: a kind of `MAPPING_KINDS` and the source columns of `dhcp_import_plan.MappingSource`). The source of a DHCP Option is an `OptionKey`: the source of its parent plus its ADR 0014 identity. `planned_options` keys the options of a planned object for both the plan and the apply. `KindObservation.gap` judges a stale Option by its own gaps and by the observation of its parent's kind. `KeaDhcpLink.options_mapped` records on the mapping of a parent that its Options are mapped; until then, its Options adopt unmapped rows. `mapped_target` and `observe_mapping` in `dhcp_mapping_lifecycle.py` read and
  write it through that source; an unmapped row that matches by structure is adopted once. Each Kea
  fact of a run is an `ImportEntry` (`dhcp_import_report.py`): a kind, a Kea path from `kea_paths.py`, an outcome and,
  for a fact that was not written, a reason from a closed set. The reason gives the outcome (`REASON_OUTCOME`).
  `ImportSummary` counts only its entries, and an unchanged row has no entry. `store_run` stores a `DhcpImportRun`
  with its `DhcpImportEntry` rows, keeps the `RETAINED_RUNS` latest runs of the Server, and logs a database failure
  instead of raising it. The rows are main-only (ADR 0007) and not change-logged.
- **Before you change the DHCP Import**, read ADR 0013, the capability probe reference (`CHECKS` in
  `integrations/dhcp_plugin_capabilities.py`, one check for each #88 gap, and #88 itself) and the parity ledger below.
  The user guide page `docs/guide/dhcp-import.md` lists each capability and reason code, and
  `test_dhcp_import_fields.py` compares both tables with `CAPABILITY_LABELS`, `REASON_LABELS` and `REASON_OUTCOME`.
- **Parity ledger** (`integrations/dhcp_import_ledger.py`, ADR 0013): every key that Kea accepts on an object the
  DHCP Import can meet is listed once, as mapped (with the DHCP Plugin Capability its write needs), not imported
  (with a reason) or deprecated (with the key Kea returns instead). The parse gives each not-imported key of every
  Kea object an entry of the run (`_ParseLog.leave_out` in `mappers/kea_to_dhcp.py`).
  `MERGED_KEYS` lists the keys Kea merges into `config-get` from the parent object, and `KEA_DEFAULTS` the values
  Kea returns when no level declares a key. `test_dhcp_import_ledger.py` compares them with the recordings, and in
  the DHCP plugin job with the import's field maps and the plugin models. `CoverageImportTest` in
  `test_dhcp_import.py` runs the coverage configuration through `run_dhcp_plugin_import` and compares the stored
  unsupported and not-imported entries with the ledger and the probe.
  When a change maps a key, change its entry in the same change.
  - **After a Kea upgrade:** set the new `KEA_VERSION`, run `scripts/record_kea_config_get.py`, and list each key the
    ledger test reports as missing. Remove each key that Kea no longer has. When Kea deprecates a key, set it on its
    object in `kea-dhcp{4,6}.conf`, record again, and list it as deprecated. When a merged-key or Kea-default
    assertion fails, update `MERGED_KEYS` or `KEA_DEFAULTS` (the Declared Value inference reads both).
  - **After a netbox-plugin-dhcp upgrade:** run the DHCP plugin job. A "no plugin home" key whose name is now a plugin
    field fails; map it. A mapped target that the plugin removed fails. When the upgrade ships
    a #88 change, check that the capability check matches the shipped shape, as #88 says. The entries that name the
    capability stay: the capability probe (#106) finds it present at run time.
- **Sync interval**: `SyncConfig.interval_minutes` is the only runtime source.
  `KeaIpamSyncJob.enqueue_once()` (rqworker startup) and each periodic `run()` read it.
  Ghost-job healing also runs inside `enqueue_once()`, not `ready()`.
- **REST API** (`api/`): `NetBoxModelViewSet` + `NetBoxModelSerializer` — only the
  `Server` model is exposed. All password fields are write-only.
- **GraphQL** (`graphql.py`): a strawberry-django `ServerType` + `Query`
  (`server` / `server_list` fields), auto-discovered by NetBox. Note the **legacy
  single-module layout** (`graphql.py`, not a `graphql/` package with `types.py`),
  so NetBox's standard `APIViewTestCases.GraphQLTestCase` cannot resolve
  `netbox_kea.graphql.types.ServerType`; the Server API tests compose the REST CRUD
  mixins and leave GraphQL out until the schema moves to the package layout.

### Exception hierarchy

```text
Exception
 ├── KeaException                  # base: any non-ok result from Kea
 └── ChangeRejected                # change_outcome: the change is not live, with a reason
```

**`views/notices.py` owns every Snapshot notice and every notice of a failed Kea read** (ADR 0003, Presentation).
- A view passes a Catalogue or Server Configuration Snapshot to `notice()`. It runs a Reservation or Lease read
  through `load_snapshot()`.
- An exact load of one Lease or one Reservation (an edit, a delete, a row Sync) goes through `load_target()`, with
  the kind `lease_target` or `reservation_target`.
- When a load needs facts that a Catalogue or Server Configuration Snapshot cannot give, the view shows
  `failed_load(snapshot)`: the error Notice of that Snapshot. For example, a Reservation load whose `subnet{v}-list`
  read failed shows the Catalogue Notice, not a Reservation headline.
- Both loaders share one classifier. A Kea refusal, a transport failure and a malformed reply become an unavailable
  Notice, and the failure is logged. A malformed reply is a `MalformedReply`, a `MalformedLeaseResponse`, a
  `MalformedReservation`, or a `LeaseLookupFailed` result of `load_target()`.
- A Kea refusal adds `kea_error_message(exc)` as a line under the headline (`Notice.reply`). So every channel shows
  Kea's answer.
- The channels are `show_notices()`, a template (`inc/notice_alert.html`), `ServerNotices` on a combined page, and
  `Notice.text` in a row badge or a plain-text reply. A view never chooses the level. It never writes its own
  read-failure text. All headlines live in `HEADLINES`.
- When the `host_cmds` hook is missing, the Reservations tab shows its hook panel. It shows no Notice and no
  mutation warning for the same cause, so the guidance shows once.
- A refused Lease query (`LeaseQueryGuardError`) still raises. Every `ValueError` except `MalformedReservation` still
  raises. A site catches only a `ValueError` that it can raise (a bad selection, the client settings) and shows an
  accurate message for it. `_client_settings_refusal()` in `views/_base.py` checks the client settings. A combined
  page adds these errors to the `ServerNotices` lists itself.
- Three OpenGrep rules (`kea-snapshot-notice-outside-notice-module`, `kea-snapshot-read-without-notice`,
  `kea-view-read-ladder`) and `test_snapshot_notice_sweep.py` guard the rule. `kea-view-read-ladder` refuses an
  `except` of `KeaException` or `requests.RequestException` in `views/`. The reads that degrade silently and log
  the failure are exempt by function name: utilization, status, the read back of a created Lease, a later page of a
  Reservation search, and the Reservation read of the DHCP plugin import.
- A new Server page that reads no Snapshot needs an entry with a reason in the sweep's exempt list.

**`config_write` owns every Configuration Change** (ADR 0005). An
operation returns a `ConfigChangeOutcome` (`applied`/`unknown` and
`persisted`/`failed`/`not-requested`) or raises `ChangeRejected` with a reason.
A view runs it through `_run_change` in `views/_base.py`, which owns the
messages, and catches nothing itself. Shared Network add, edit and delete, Subnet add, edit and
delete, Pool add and delete, Subnet and server DHCP Options, and Option Definition add and
delete use it. An OpenGrep rule refuses an `except` of `ChangeRejected` in `views/`
outside `_run_change` and `_run_change_loop`. A second rule keeps those functions in `views/_base.py`, and a third
refuses a broad `except` around a direct `config_write` or `runtime_change` call in a view. Only `config_write` operations take the per-daemon advisory
lock. A Subnet, Pool
or Subnet DHCP Options operation takes the Subnet ID and the CIDR that the page showed, and
sends nothing unless its `MutationScope` returns a Verified Subnet with both.

Reservation add, edit and delete are Configuration Changes too (ADR 0012): `add_reservation`, `edit_reservation`
and `delete_reservation` hold the lock from the `MutationScope` read to the end of the persist step and return a
`ReservationChangeOutcome` (the previous and intended Reservation, the verification state and the Catalogue of the
scope read, which `claim()` takes). The add and edit views call `reservation_edit`, which owns the form state,
token checks, Published Name rules and typed builders. It checks the token before any Kea read; `config_write`
checks the non-option managed-fact fingerprint under the lock. The signed token carries the complete shown option
snapshot. Reservation option edits use the shared identity and merge in `dhcp_options`, with the Option Definitions
from the same live Catalogue read (ADR 0014). The builders use the live facts and Catalogue that `config_write`
supplies. A Reservation conflict becomes a form error. An unknown suffix becomes a hostname error.
A `ValueError` becomes a page error. The view presents the pool-overlap warning facts.
After an applied outcome, `reservation_edit.after_apply` returns the journal, signal and IPAM claim facts.
The views present those facts separately from the Kea change result.
A Subnet or a Reservation that is gone, a changed fingerprint and result 3 on `reservation-del` are
`target-changed`; result 2 is a rejection; any other failure result, result 5, a forward failure or a lost reply is
`unknown`, with no read after it. The persist step runs after `applied` and `unknown`, and the verification read only
after `applied`. `KeaClient` keeps the single commands (`reservation_add`, `reservation_update`, `reservation_del`,
sent through `_config_mutation_command`, so a display read during the write is not kept), the reads and the raw
record handling (`FreshReservation.updated` keeps each Kea field that NetBox does not manage: since #102 only
`user-context`). The typed Reservation carries client classes, the DHCPv4 boot fields, the DHCPv6 excluded prefixes
(`ExcludedPrefix` pairs each with its delegated prefix; the serializer builds Kea's positional list) and the read-only
`user_context`. The managed-fact fingerprint covers every field except the options and `user_context`.
`reservation_edit.excluded_prefix_pairs` pairs the excluded prefixes of the form under the lock: a live pair stays
while its delegated prefix stays, and another excluded prefix pairs with the one delegated prefix that holds it. A
Transfer Document import does not send `user_context`. The OpenGrep rule
`kea-reservation-write-outside-config-write` refuses a call to these write primitives outside `config_write`. The
bulk Reservation import calls `reservation_edit.save_import` for each entry through
`_run_change_loop(..., stop_on_rejection=True)`, so an unknown or a rejected entry stops it. The import checks the
optional IPAM claim permission once before its first write. It calls `after_apply` after each change returns,
outside the change callback. The shared import report (`_import_report` in `views/sync_views.py`,
`inc/import_report.html`) keeps claim failures with their entry, and later entries continue. Pool overlap facts
produce one capped warning by Reservation Identity. Transfer document hostnames are stored values and stay unchanged.

**`runtime_change` owns every Runtime Change** (ADR 0011): Lease add, edit, delete and wipe, and DHCP enable and
disable. An operation returns a `RuntimeChangeOutcome` (`applied`/`unknown` and diagnostics) or raises
`ChangeRejected`. Both modules classify through `change_outcome` (`before_change`, `mutate`, `never_sent`): a failed
read before the write, a connect-phase failure, an invalid URL or an HTTP 401 answer is `not-sent`; a lost or
malformed reply, any other HTTP error, every TLS failure (its diagnostic names the TLS connection), a redirect, a
Control Agent forward failure or result 5 is `unknown`. Result 2 in a well-formed reply is a rejection for every command. Any other failure result on a Lease
write or a wipe is `unknown`, and on `dhcp-enable` or `dhcp-disable` a rejection; no operation reads Kea after the
send. A fresh read that does not match the shown Lease,
a Lease that is gone before the send, result 3 on `lease{v}-del` and result 4 on `lease{v}-update` are
`target-changed`. A view runs one change through `_run_change` and a loop of changes (multi-Lease delete, Lease CSV
import) through `_run_change_loop`, which stops at the first `unknown` row. The journal entry, the signals and the
IPAM synchronization run in the view only after `applied`; a failure there shows a separate error. `_journal_applied`
and `_signal_applied` in `views/_base.py` write the journal entry and send a signal for Lease changes;
`send_robust()` returns a receiver error, so `_signal_applied` reads its responses. The OpenGrep rule
`kea-runtime-write-outside-runtime-change` refuses a call to a `KeaClient` runtime write primitive outside
`runtime_change`.

Subnet add is the first multi-step change: `add_subnet` adds the Subnet and then assigns it to
a Shared Network. When the assignment does not apply, it deletes the Subnet again, but only
while a fresh `subnet{v}-list` read shows the Subnet with the sent ID and CIDR and no Shared Network. The
persist step runs once, at the end. In tests, `SubnetDaemon` in `kea_stub.py` holds Subnets
and Shared Networks, so a test can script a Kea failure or a change by another writer.

Subnet edit (`edit_subnet`) removes the Subnet from its Shared Network, adds it to the new one,
and then updates the fields, because Kea refuses to add a Subnet that is already in a Shared
Network. It also takes the Shared Network that the page showed, and sends nothing while the
scope shows another one; a page that could not confirm the membership cannot save. When a step
does not apply, the operation undoes the applied membership steps, newest first, each only while
a fresh `subnet{v}-list` read shows the membership that the step set. The field update is the last step, so a
rollback never undoes it. Both operations run their steps through `_run_steps` in `config_write`.

A check after a step reads only what it compares, while the operation holds the lock: identity and
membership come from one `subnet{v}-list` read (`subnet_catalogue.read_identity`), not from a full scope with
`config-get`. A Pool check still reads a fresh scope. The target Shared Network of a move or an assignment comes
from the `ServerConfigurationSnapshot` that the operation's own scope read (`MutationScope.has_shared_network`).
When that read cannot show the Shared Network, the operation sends `network{v}-get` as before.

Subnet edit and Shared Network edit also take the values that the page showed (`shown`, the type of the edit),
and send nothing while a live value differs, because a save writes back every field that the form shows. One
function maps the live facts to those values for the GET and for the check under the lock:
`server_configuration.shown_subnet` and `shown_shared_network`. `_ShownValuesForm` builds each hidden `shown_`
field as a copy of its visible field, so a value that Kea writes in another text form is not a change.

A read-modify-write operation holds the lock from its `config-get` to the end of the
persist step. `KeaClient` sends each command (`config_candidate`, `config_test`,
`config_set`); `CandidateConfiguration` in `kea.py` edits the raw configuration in place,
because the wire-discipline gate keeps wire literals out of `config_write`. An edit
raises `MalformedConfiguration` for a configuration that it cannot edit safely, and
`config_write` catches only that type, so a bug still fails loudly. Any failure result on
`config-set` is `unknown`, because Kea commits the configuration before the hook
initialization can fail.
A stale or renamed DHCP Option row (`DHCPOptionConflict`, `DHCPOptionNameChange`) is not
a Configuration Change result: it leaves the operation before any command that changes
the configuration, and the options views show it as a form error.

## Security & Code Quality Rules

Several of these are machine-enforced by the custom opengrep ruleset in
`.opengrep/kea-rules.yaml` (see `.opengrep/README.md`). The pre-commit hook runs
these rules locally. Keep OpenGrep out of CI so CodeRabbit can run its own analysis.
When a rule below has a matching opengrep rule, a violation fails the local hook.

- **Never leak exception details to HTTP responses.** Use `logger.exception()`
  server-side and return a generic message like `"An internal error occurred"`.
  Raw `str(exc)` can expose internal URLs, TLS details, or Kea config.
- **Always pass `version=` to `server.get_client()`** when the DHCP version is known
  (`server.get_client(version=self.dhcp_version)`). Omitting it falls back to
  `ca_url` even when a protocol-specific URL is configured.
- **Always call `server.get_client()` inside a try block** — client creation raises
  `ValueError` on bad config and sends no request. A try block around `get_client()` alone
  catches `ValueError` only, and a view reports it with `_client_settings_error()` in
  `views/_base.py`, never as a connection failure. Request errors come from the Kea calls, so the "Catch" rule
  below covers those calls. Never call it at module/class level or before error handling
  is in scope.
- **Validate Kea response shape before indexing.** After `client.command()`, check
  `resp` is a non-empty list and `resp[0]` is a dict before reading
  `resp[0]["arguments"]`; check nested keys (`"leases"`, `"subnet4"`, …) are lists
  before indexing. Malformed payloads should raise `RuntimeError` to hit existing
  handlers.
- **Run a user-facing Kea read through `load_snapshot()` or `load_target()`** in `views/notices.py`; a view
  catches no `KeaException` or `requests.RequestException` itself (OpenGrep `kea-view-read-ladder`). A read
  that degrades silently (a badge, a status) catches
  `(KeaException, requests.RequestException, RuntimeError, ValueError)` and logs the failure.
  `check_response()` raises `RuntimeError` for a malformed reply entry. A Configuration Change or a Runtime Change
  goes through `_run_change` instead (see "Exception hierarchy").
- **Use `kea.kea_error_message(exc)` for user-facing Kea error messages**, also in change diagnostics: fixed guidance for result 2 (hook
  library not loaded) and result 128 (daemon not reachable), followed by `Kea replied: <text>` for every result. Show Kea's text, never
  the text of a Python exception.
- **Guard action URLs/buttons by permission AND lookup state.** Don't offer
  Sync/Reserve for a Lease whose Reservation Match is Unknown; don't offer add/edit to
  users without `change` permission.
- **Django form querysets must be evaluated at instantiation, not at class-definition
  time.** Set `self.fields["field"].queryset` in `__init__` — class-level querysets
  go stale in long-running processes.
- **django-tables2 Column instances must not be shared across table classes.** Use a
  factory function, not a module-level instance.
- **Catch `DatabaseError` (not just `ProgrammingError`/`OperationalError`)** around
  non-critical DB writes (e.g. `JournalEntry.objects.create`) so a successful Kea
  operation never turns into a 500.
- **DHCPv6 reservations use `ip-addresses` (list), not `ip-address` (string).** Check
  both fields when inspecting reservation data.
- **Pass `timeout=` to every `subprocess` call**, in the package, `scripts/`, and the tests.
  A child process that stops responding must fail the caller, not hang it.

## Testing philosophy

Value tests by how much real behaviour they exercise: **end-to-end → integration
against real deps (real DB/ORM/serializers/forms) → narrow unit**. Mocks are a last
resort, reserved for true external boundaries you cannot run locally.

- **Stub the HTTP boundary, drive the real `KeaClient`.** Unit tests do **not** mock
  `KeaClient` or patch `netbox_kea.models.KeaClient`. They construct a real client and
  stub only the transport by patching `netbox_kea.kea.requests.Session.post` — the
  `stub_kea()` context manager in `netbox_kea/tests/kea_stub.py`. This exercises the
  real `command()` payload building, response parsing, and error handling, so a broken
  parser can't hide behind a `MagicMock`. Register responses by command name (dict /
  list / `queued(...)` / a `(body) -> payload` callable / an exception instance raised
  at the boundary). Patching is at the class level so it also covers the client of each worker thread.
- **Recorded Kea replies check the parser.** A hand-written stub shows what we expect
  Kea to return. `netbox_kea/tests/kea_recordings/` holds `config-get` and
  `subnet{4,6}-list` replies recorded from a real Kea (the harness `KEA_VERSION`), with
  coverage configurations that use every field `server_configuration` reads. The `leases`
  section of each recording holds lease replies for every state, an infinite lifetime and
  DHCPv6 delegated prefixes, and the lease changes that Kea refuses.
  `test_kea_recordings.py` requires zero diagnostics. The script also writes
  `accepted-keys.json` from the key lists that Kea's `config-test` and `config-set` check in the
  same release: the keyword tables of `simple_parser{4,6}.cc`, and the host reservation and client
  class key sets. The wire-discipline gate and the parity ledger read it. `stub_kea()`
  fails a `config-test` or `config-set` whose Shared Network or Subnet carries a key
  outside that file, because Kea rejects unknown keys. When you bump `KEA_VERSION` or
  make the parser read a new field, add the field to `kea-dhcp{4,6}.conf` and run
  `scripts/record_kea_config_get.py` (Docker and curl required).
- **Kea command names come from a real Kea.** The script also records the
  `list-commands` reply of each daemon. The coverage configurations load the same hook
  libraries as `tests/docker/kea_configs/`. `WIRE_COMMANDS` in `kea_wire_discipline.py`
  is that recorded set, and `stub_kea()` fails a command outside it, registered or sent.
  Never add a command name by hand. The black-box test `tests/test_kea_commands.py` compares the live harness daemons with the
  recording in CI. When you change `KEA_VERSION` or the harness hook libraries, run the
  script again.
- **Type-check gate.** `scripts/mypy-gate.sh` (+ `test_mypy_gate.py`, a pre-push hook,
  the CI `lint` job) type-checks `netbox_kea/` and fails only on errors that are absent
  from `mypy-baseline.txt`. It exists to catch annotation drift between a producer and
  its consumer: a `list[dict | Reservation]` passed to a `list[Reservation]` parameter is
  an error because `list` is invariant, and that reached review once already. NetBox is
  deliberately **not** installed for this gate, so NetBox objects are `Any`; every
  first-party signature and call site is still checked, and no upstream NetBox release
  can break the gate. Unlike the mock-discipline baseline, `mypy-baseline.txt` is **not**
  empty: it records the errors that already existed when the gate was added. Fix one and
  run `--sync` to shrink it; never `--sync` to silence a new error. The baseline matches
  on error text, not line number, so edits above an error do not force a resync.
  **Always run the gate through `uv run`**, so the locked dev group is active. `django-stubs`
  is a dev dependency, and mypy resolves Django imports through its stubs only when it is
  installed; a baseline generated without it misses ~95 findings and CI then fails on a
  clean checkout. A resolved baseline error does not fail the gate (`--allow-unsynced`),
  so fixing types never breaks the build, and a mypy exit status above 1 fails loudly
  rather than filtering an empty report into a false pass.

- **Mock-discipline gate.** `netbox_kea/tests/mock_discipline.py` (+
  `test_mock_discipline.py`, a pre-commit hook) flags new spec-less
  `MagicMock`/`Mock`, and new `patch("netbox_kea…")` / `patch.object(<our class>, …)`
  without `autospec=` — `patch` returns the same fabricating `MagicMock`, and an
  unspecced one also survives a signature change in the function it replaces.
  Patching a real boundary (`requests.Session.post`, `django_rq`) is not flagged.
  Use `spec=`/`autospec=True` or a `# mock-ok` justification for the rare legitimate
  boundary (job-runner stand-in, error injection the real transport can't produce, an
  unreachable defensive guard). `mock_discipline_baseline.txt` is **empty** and must stay
  that way: it grandfathers accepted violations per (file, function), so regenerating it
  to silence a failure defeats the gate. Fix the call site instead.
- **Kea wire-discipline gate.** `netbox_kea/tests/kea_wire_discipline.py` checks
  production code for Kea command names, hyphenated payload keys, and family-suffixed
  configuration keys or service names. String templates (f-strings, `.format`, `%`, `+`)
  count when they can build a wire literal. Wire owners are `kea.py`, `kea_paths.py`,
  `integrations/dhcp_import_ledger.py`, `integrations/dhcp_import_fields.py`, `server_configuration.py`, `subnet_catalogue.py`, `reservations.py`,
  `dhcp_options.py`, `leases.py`, and `subnet_settings.py`, relative to `netbox_kea/`. The vocabulary of hyphenated
  keys includes every key in `accepted-keys.json`.
  The checker excludes these exact modules, tests, and migrations. The transport stub
  `tests/kea_stub.py` may also use wire literals to model Kea responses.
  It also checks `arguments` when code uses it as a raw payload key. Prefer typed domain
  interfaces when the gate fails. The baseline is the follow-up brief and only shrinks.
  Use `--update-baseline` to record decreases. It refuses new sites and higher counts
  without changing the baseline. A test prevents the baseline from adding files.
  A real-tree test fails while a budget is above the count in the tree. Record a decrease in
  the change that makes it.
  The pre-commit hook and the real-tree suite test enforce the budgets.
- **Standard NetBox model coverage via mixins.** For the `Server` model (a
  `NetBoxModel` with standard generic views + `NetBoxModelViewSet`), use NetBox's
  `ViewTestCases` / `APIViewTestCases` (see `test_server_generic.py`). Wire plugin
  namespaces: UI `_get_base_url` → `plugins:netbox_kea:server_{}`; API
  `view_namespace = "plugins-api:netbox_kea"`. Submission connectivity checks are
  answered by `stub_kea({"version-get": ...})` in `setUp`. Model validation is local;
  build fixtures with `bulk_create`. These mixins
  don't fit the Kea-proxy views (leases/subnets/reservations over live daemon data) —
  those stay `stub_kea`-driven.
- **Query-count baselines.** The list-view mixins assert an exact SQL query count
  against `netbox_kea/tests/query_counts.json` to catch N+1 drift. Record/update with
  `TEST_DB_NAME=test_netbox_kea_local TEST_REDIS_HOST=localhost \
  UPDATE_QUERY_COUNTS=1 uv run --native-tls pytest -n 1 ...`, then commit the file. One xdist
  worker prevents concurrent writes and keeps Redis isolated. A count is a fact about
  one NetBox release, not about the plugin alone: NetBox re-records its own baselines on
  patch releases. `QUERY_COUNT_NETBOX_VERSION` in `netbox_kea/tests/conftest.py` names
  the release the file describes, the unit-test CI job pins that same release, and the
  assertions are skipped with a warning on any other release. To move to a new NetBox,
  bump the constant, bump `NETBOX_RELEASE` in the workflow `env`, and re-record in one change.
- **When fixing a bug, write the failing (red) test first**, confirm it fails against
  the unfixed code, then fix until green.
- **No source line numbers in comments or docstrings**: name the function or the
  behaviour. `test_no_source_line_references.py` fails on each "Lines 731-736" or "(line 910)".

### Unit test seams & patterns

- **User model**: use `get_user_model()`, never `from django.contrib.auth.models import User`.
- **API auth in tests**: `api_client.force_authenticate(user=self.user)` (NetBox v4
  tokens use the `nbt_` format).
- **BulkImportView POST**: requires `data=`, `format='csv'`, `csv_delimiter=','`.
- **Settings in tests**: `get_client()` reads the `KeaClientConfig` row, so a test that calls it needs the
  database (`TestCase`, not `SimpleTestCase`). Set a row value with `with_kea_client_config(...)`,
  `with_sync_config(...)`, `with_dhcp_integration_config(...)` or `with_display_cache_config(...)` from
  `tests/utils.py`: a class, method or `with`
  decorator that restores the value.
  `_ViewTestBase` turns the lease-query guard off (`lease_query_max_unpaged_leases=0`).

## Key Patterns

- **Non-model tables**: lease/subnet/reservation/shared-network tables use
  `GenericTable(BaseTable)` (no Django model). They accept `list[dict]` and define
  `objects_count` = `len(self.data)` for NetBox pagination.
- **HTMX pagination**: lease views serve a full page or an HTMX partial from the same
  `get()` via `htmx_partial(request, ...)`. The hidden `page` field uses
  `VeryHiddenInput` (renders empty) to avoid form conflicts.
- **View registration**: standard CRUD uses `@register_model_view(Server)` /
  `@register_model_view(Server, "edit")`; `get_model_urls("netbox_kea", "server")`
  auto-generates detail/edit/delete/changelog/journal. Custom routes (leases,
  reservations, subnets, shared-networks, options, DHCP control) are declared
  explicitly before the `include()`. Custom tabs use `OptionalViewTab` (a `ViewTab`
  accepting `is_enabled: Callable[[Server], bool]`).
- **Generic views with TypeVar**: `BaseServerLeasesView` is `generic.ObjectView,
  Generic[T]` (T bound to `BaseTable`); concrete subclasses declare `table_class`,
  `form_class`, `dhcp_version`, `lease_service`. The base handles pagination, HTMX,
  search, export, delete routing.
- **FakeLeaseModel**: leases aren't a real model, so `FakeLeaseModel` /
  `FakeLeaseModelMeta` provide `app_label`/`model_name` so `GetReturnURLMixin`
  resolves in delete views.
- **Lease badge enrichment**: `_enrich_leases_with_badges()` gets one typed Reservation
  Match per row from `lease_reservation_reads.reservation_matches()`. The lookups try the
  Reservation Scopes that the reservation flags of the Lease's Subnet enable first, then the
  disabled ones. The In-Subnet scope looks up the address or delegated prefix of the Lease,
  then each carried identity; the Global scope looks up each identity. When
  `reservations.tries_global_reservation()` is true (an In-Subnet Reservation that can give
  no allocation of the Lease kind, for example under `reservations-out-of-pool`), the Global
  Reservation is read too. One call reads each lookup once. `reservations.reservation_match()`
  is the rule, and the view maps each outcome to its badge, links and Sync with `match` and
  `assert_never`. The NetBox IP column shows the Lease Synchronization State of each Current Lease from one
  ownership read per page: `ipam_reconciliation.address_ownership()` (source `lease`) and `prefix_ownership()`
  (source `lease-prefix`), limited to the objects that the user may view.
- **Sync lifecycle**: IP status is `dhcp` (dynamic lease only), `reserved`
  (reservation only), or `active` (both). `reconcile()` claims all phase reports
  before it removes stale ownership links for complete phases. An incomplete phase
  keeps its links. `claim()` handles selected records without stale cleanup.
- **Transactions**: open every transaction with `event_scope.atomic()`, never `transaction.atomic`
  (opengrep `kea-raw-atomic`). At the top level of a tracked request, on a NetBox release whose `event_tracking` nests (`event_scope._nested_tracking`), it is a unit, whose events
  dispatch after its COMMIT or not at all. Put `except event_scope.EventDispatchError: raise` before a broad
  `except`. The one exception is a side effect after a change that Kea applied: the Lease add view reports failed
  IPAM event dispatch separately; `reservation_edit.after_apply` returns it as a fact for Reservation views.
  The request must report the applied change. Read `docs/design/savepoint-event-queue.md` (sections 22 and 24) before you change it.
- **Kea option names per family**: DNS is `domain-name-servers` (v4) or `dns-servers` (v6), and NTP is
  `ntp-servers` (v4) or `sntp-servers` (v6). `dhcp_options._FORM_MANAGED_OPTIONS` maps each form field to them.
- **Forms**: lease search forms inherit `BaseLeasesSarchForm` (the typo is
  intentional/existing); inner `Meta.ip_version` drives validation. The Subnet and
  Shared Network forms clean in the field class (`_AddressListField` for `dns_servers`,
  `ntp_servers` and relay addresses gives canonical addresses), so a copy of a field
  cleans the same way. A change form that refuses stale values inherits
  `_ShownValuesForm` and names its managed fields once, in `shown_names`.
  `dhcp_options.form_managed_entry` picks the one DHCP Option entry that a form field
  manages, for the display and for the save. Two fitting entries refuse the form.
  The Subnet table column uses the same rule (`dhcp_options.shown_options`) and shows a badge for two fitting
  entries. Option codes come from the Kea standard option table in `dhcp_options`, and the Subnet Settings keys
  from `subnet_settings.SETTING_KEYS`.
- **API URL naming**: the serializer's `HyperlinkedIdentityField` uses
  `view_name="plugins-api:netbox_kea-api:server-detail"` — `plugins-api:` prefix and
  `-api:` namespace suffix are NetBox conventions.

## Kea API Reference

- **Primary**: `kea.readthedocs.io/en/latest/api.html` — full JSON command schemas.
- **Hook discovery**: the Server Configuration Snapshot holds the `hooks-libraries` paths.
  `server_configuration.reservation_capabilities()` reads `host_cmds` and `flex_id` from them; the plugin sends no
  `list-commands`. A page render uses `display()`, and a write uses `for_verification()`. A read of another hook's
  command treats result code 2 as "hook not loaded" (`KeaException.unsupported_command`).
- **Key hooks** and the commands they gate:
  - `host_cmds` — all `reservation-*` commands (open source since Kea 2.7.7 / MPL 2.0)
  - `lease_cmds` — `lease4/6-get-by-hostname/hw-address/state`, `lease4/6-update/add`
  - `subnet_cmds` — `subnet4/6-list/get/add/update` (alternative to `config-get`)
  - `stat_cmds` — `stat-lease4/6-get` for per-subnet utilization
- **Pool operations** use `subnet4/6-delta-add` and `subnet4/6-delta-del` (Kea 2.2+). `subnet_cmds` has no `subnet4/6-pool-add` or `-pool-del` command.

## Conventions

- **Commit messages**: Conventional Commits (feat, fix, docs, style, refactor, perf,
  test, build, ci, chore, revert) — enforced by a pre-commit hook.
- **REUSE/SPDX**: every file needs licensing; `uv run reuse lint` must pass. Each file
  carries an inline SPDX header, and a new file without one fails the lint. Templates use
  `{# ... #}` (an HTML comment renders into the page). `REUSE.toml` lists only files that
  cannot take a comment or are generated (license text, binary, JSON, lock file, changelog).
  Name one `SPDX-FileCopyrightText` line per author whose lines are in the file. Never
  remove a holder whose code is still in the file (Apache-2.0 section 4(c)).
- **User documentation**: the site pages in `docs/guide/` hold it, and `mkdocs.yml` lists them in `nav`.
  Keep `README.md` short. PyPI renders it too, so each of its links must be absolute.
- **Ruff**: line length 120, max complexity 15, migrations excluded, E501 ignored,
  docstrings required except in tests/migrations/`__init__.py`.
