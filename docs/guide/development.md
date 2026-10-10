<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Development

```bash
# Install dev dependencies
uv sync

# Lint
uv run ruff check .
uv run ruff format --check .

# REUSE compliance check
uv run reuse lint

# Format
uv run ruff format .

# Install pre-commit hooks
uv run pre-commit install

# Build wheel (required before integration tests)
uv build

# Run unit tests; both variables are required (see AGENTS.md for picking values)
TEST_DB_NAME=test_netbox_kea_local TEST_REDIS_HOST=localhost \
  uv run --native-tls pytest --reuse-db -n auto --maxschedchunk=1 -q

# Run integration tests (requires Docker — see tests/test_setup.sh)
./tests/test_setup.sh
uv run --native-tls pytest -p no:django tests/ --tracing=retain-on-failure -v --cov=netbox_kea --cov-report=xml
```

[AGENTS.md](https://github.com/marcinpsk/netbox-kea-ng/blob/main/AGENTS.md) explains how to pick the test database and Redis values, and holds the
repository conventions.

Build the documentation site from `docs/guide/`. The `--strict` flag fails the build on a broken link:

```bash
uv run --group docs zensical build --strict
```

See the [Changelog](changelog.md) for version history.
