<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
SPDX-License-Identifier: Apache-2.0
-->

# Development

Development needs uv 0.11.0 or later. `pyproject.toml` declares it, so an older uv stops with an error.

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
  uv run --system-certs pytest --reuse-db -n auto --maxschedchunk=1 -q

# Run integration tests (requires Docker — see tests/test_setup.sh)
./tests/test_setup.sh
uv run --system-certs pytest -p no:django tests/ --tracing=retain-on-failure -v --cov=netbox_kea --cov-report=xml
```

[AGENTS.md](https://github.com/marcinpsk/netbox-kea-ng/blob/main/AGENTS.md) explains how to pick the test database and Redis values, and holds the
repository conventions.

Build the documentation site from `docs/guide/`. The `--strict` flag fails the build on a broken link. Zensical needs Python 3.11 or later in the project environment:

```bash
uv run --group docs zensical build --strict
```

The pages show screenshots and short recordings that CI makes. To make them locally, start the integration harness
with the documentation variant `docker-compose.docs.yml`, which lets Kea write its configuration. The suite writes the
screenshots to `docs/guide/assets/screenshots/`, and the recordings (MP4, a PNG poster and the README GIF) to
`docs/guide/assets/recordings/`:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.docs.yml ./tests/test_setup.sh
uv run --system-certs pytest -p no:django tests/docs_media --docs-media-dir docs/guide/assets
uv run --group docs zensical build --strict
uv run python scripts/check_docs_media.py site docs/guide/assets
```

The site shows the latest release. After a release, the release workflow builds the site from the release tag and
deploys it to GitHub Pages. A release pull request and the scheduled CI run build the site and upload it as an
artifact. To deploy the site of the latest release again, run the Docs workflow from `main` with its tag. The
workflow refuses any other tag:

```bash
gh workflow run docs.yml --ref main -f tag=v3.2.0
```

See the [Changelog](changelog.md) for version history.
