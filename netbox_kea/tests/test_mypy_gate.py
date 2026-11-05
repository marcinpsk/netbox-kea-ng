# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for the mypy gate (plain ``mypy`` over ``[tool.mypy]``, in CI and the pre-push hook).

The gate exists to catch annotation drift between a producer and its consumer, the class
of defect that reached review as ``list[dict | Reservation]`` passed to a
``list[Reservation]`` parameter. These tests prove the configuration still reports that
class, so weakening it (for example by disabling ``arg-type``) fails here rather than
silently retiring the gate.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
#: The one gate command. A clean tree is the only accepted state: there is no baseline of known errors.
GATE_COMMAND = "uv run mypy"

DRIFTING_MODULE = '''
class Reservation:
    """One reservation."""


def consume(*, records: list[Reservation]) -> None:
    """Accept only reservations."""


def produce() -> None:
    """Fill one mixed list and hand it to a narrower parameter."""
    records: list[dict | Reservation] = []
    consume(records=records)
'''


def test_the_project_configuration_reports_annotation_drift(tmp_path):
    """`list` is invariant, so the mixed list must not satisfy `list[Reservation]`."""
    api = pytest.importorskip("mypy.api", reason="mypy is a dev dependency")
    module = tmp_path / "drift.py"
    module.write_text(DRIFTING_MODULE)

    stdout, _stderr, status = api.run(["--config-file", str(REPOSITORY_ROOT / "pyproject.toml"), str(module)])

    assert status != 0, f"mypy accepted the invariant-list call:\n{stdout}"
    assert "[arg-type]" in stdout, f"the arg-type check is disabled:\n{stdout}"


def test_a_matching_annotation_passes(tmp_path):
    """The same call is clean once the parameter names both record types."""
    api = pytest.importorskip("mypy.api", reason="mypy is a dev dependency")
    module = tmp_path / "aligned.py"
    module.write_text(DRIFTING_MODULE.replace("records: list[Reservation]", "records: list[dict | Reservation]"))

    stdout, _stderr, status = api.run(["--config-file", str(REPOSITORY_ROOT / "pyproject.toml"), str(module)])

    assert status == 0, f"mypy rejected an aligned call:\n{stdout}"


NETADDR_MIXUP_MODULE = '''
import ipaddress

import netaddr

IPAddressValue = ipaddress.IPv4Address | ipaddress.IPv6Address


def consume(addresses: tuple[IPAddressValue, ...]) -> int:
    """Accept only stdlib address values."""
    return len(addresses)


def produce() -> None:
    """Hand it netaddr's same-named class instead."""
    consume((netaddr.IPAddress("198.18.0.5"),))
'''


#: Stub-only packages the gate needs to see third-party values as anything but Any.
#: `ignore_missing_imports` is on for NetBox, so a missing stub is silent, not an error.
REQUIRED_STUB_PACKAGES = ("types-netaddr", "types-PyYAML", "djangorestframework-stubs")


def _stub_package_installed(name: str) -> bool:
    from importlib.metadata import PackageNotFoundError, distribution

    try:
        distribution(name)
    except PackageNotFoundError:
        return False
    return True


def _dev_group_requirements(pyproject: Path) -> list[str]:
    """Return the ``dependency-groups.dev`` requirement strings of *pyproject*."""
    data = tomllib.loads(pyproject.read_text())
    return data.get("dependency-groups", {}).get("dev", [])


def _declares_package(requirements: list[str], package: str) -> bool:
    """Report whether *requirements* pins *package*, ignoring its version specifier."""
    normalized_package = re.sub(r"[-_.]+", "-", package).lower()
    return any(
        re.sub(r"[-_.]+", "-", re.split(r"[<>=!~\[;\s]", requirement, maxsplit=1)[0]).lower() == normalized_package
        for requirement in requirements
    )


@pytest.mark.parametrize("declared_name", ["types.PyYAML", "types_PyYAML", "types-pyyaml"])
def test_declared_package_names_use_pep_503_normalization(declared_name):
    assert _declares_package([f"{declared_name}>=6.0"], "types-PyYAML")


@pytest.mark.parametrize("package", REQUIRED_STUB_PACKAGES)
def test_the_dev_group_declares_the_stub_packages_the_gate_needs(package):
    """A dropped stub package silently turns that library's values back into Any.

    `ignore_missing_imports = true` means mypy reports nothing when a stub goes
    missing, so only this check would notice.
    """
    requirements = _dev_group_requirements(REPOSITORY_ROOT / "pyproject.toml")
    assert requirements, "The dev dependency group is empty; this guard would read nothing."
    assert _declares_package(requirements, package), f"{package} is no longer in the dev dependency group."


def test_the_stub_package_check_reads_only_the_dev_group(tmp_path):
    """A text scan of everything after ``[dependency-groups]`` also reads later tables.

    A package named anywhere below that marker satisfied the assertion, so moving a
    stub out of ``dev`` and mentioning it in any later table read as still declared.
    """
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[dependency-groups]\ndev = ["pytest>=8.0.0"]\n\n[tool.example]\nnote = "types-netaddr lives elsewhere now"\n'
    )

    assert '"types-netaddr' in pyproject.read_text().split("[dependency-groups]", 1)[-1]
    assert not _declares_package(_dev_group_requirements(pyproject), "types-netaddr")


def test_a_netaddr_value_cannot_pass_as_a_stdlib_address(tmp_path):
    """netaddr exports IPAddress and IPNetwork too, and they are not interchangeable.

    The same address built by each library compares unequal, so a mix-up makes a
    duplicate check silently miss. Without the netaddr stubs its objects are Any and
    mypy accepts them anywhere, which is why types-netaddr is a dev dependency.
    """
    api = pytest.importorskip("mypy.api", reason="mypy is a dev dependency")
    if not _stub_package_installed("types-netaddr"):
        pytest.skip("types-netaddr is not installed here; the dev group declares it.")
    module = tmp_path / "netaddr_mixup.py"
    module.write_text(NETADDR_MIXUP_MODULE)

    stdout, _stderr, status = api.run(["--config-file", str(REPOSITORY_ROOT / "pyproject.toml"), str(module)])

    assert status != 0, f"mypy accepted a netaddr value where a stdlib address was declared:\n{stdout}"
    assert "[arg-type]" in stdout, stdout


def test_no_baseline_can_mute_an_error():
    """The tree is clean, so the gate fails on every error; a baseline file would let one stay."""
    assert not (REPOSITORY_ROOT / "mypy-baseline.txt").exists()
    assert not _declares_package(_dev_group_requirements(REPOSITORY_ROOT / "pyproject.toml"), "mypy-baseline")


def test_the_contributor_docs_describe_no_baseline_gate():
    """A guide that still names the removed gate sends a contributor to a script and flags that do not exist."""
    removed = ("mypy-gate.sh", "mypy-baseline", "--allow-unsynced", "baseline error")
    for name in ("AGENTS.md", "README.md", "CONTRIBUTING.md"):
        path = REPOSITORY_ROOT / name
        if not path.exists():
            continue
        text = path.read_text()
        assert not [term for term in removed if term in text], f"{name} still describes the removed baseline gate."


def _gate_hooks() -> list[dict]:
    """Return each pre-commit hook that runs mypy."""
    import yaml

    hooks = yaml.safe_load((REPOSITORY_ROOT / ".pre-commit-config.yaml").read_text())
    return [hook for repository in hooks["repos"] for hook in repository["hooks"] if "mypy" in hook.get("entry", "")]


def test_the_lint_job_and_the_pre_push_hook_share_the_gate():
    """CI and the local hook must run one command, or the two gates drift apart.

    The hook must use ``uv run``: a bare ``mypy`` type-checks against whatever interpreter
    the push shell exposes, and without ``django-stubs`` from the locked dev group that
    report differs from CI.
    """
    workflow = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text()
    ci_commands = [
        line.split("run:", 1)[1].strip() for line in workflow.splitlines() if re.search(r"run:.*\bmypy\b", line)
    ]
    # A host behind a TLS-intercepting proxy needs --system-certs; the CI runners do not.
    hook_entries = [hook["entry"].replace(" --system-certs", "") for hook in _gate_hooks()]

    assert ci_commands == [GATE_COMMAND], f"The lint job runs {ci_commands}, not {GATE_COMMAND}."
    assert hook_entries == [GATE_COMMAND], f"The pre-push hook runs {hook_entries}, not {GATE_COMMAND}."


def test_the_pre_push_gate_cannot_be_skipped_by_file_type():
    """The gate reads the whole package, so no changed-file filter may gate it.

    A push that touches only pyproject.toml changes what the gate reports while matching no Python file.
    """
    gate = _gate_hooks()

    assert len(gate) == 1, f"Expected one mypy gate hook, found {len(gate)}."
    hook = gate[0]
    filters = {key: hook[key] for key in ("types", "types_or", "files") if key in hook}
    assert hook.get("always_run") or not filters, (
        f"The gate hook is filtered by {filters} and is not always_run, so a push that "
        "changes only the mypy config skips it."
    )
    assert hook.get("pass_filenames") is False, "mypy must read [tool.mypy] files, not the pushed file list."
