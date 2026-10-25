# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for the repository's domain-language documentation."""

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_context_defines_the_dhcp_option_term_consistently():
    """Keep the Catalogue glossary on its canonical singular domain term."""
    context = (REPOSITORY_ROOT / "CONTEXT.md").read_text()

    assert context.count("**DHCP Option**:") == 1
    assert "DHCP Options" not in context


def test_context_distinguishes_server_scope_from_reservation_scope():
    """Keep Server selection separate from the place where Kea applies a Reservation."""
    context = (REPOSITORY_ROOT / "CONTEXT.md").read_text()
    assert context.count("**Server Scope**:") == 1
    server_scope = context.split("**Server Scope**:\n", 1)[1].split("\n_Avoid_:", 1)[0]
    for kind in ("all permitted Servers", "an explicit selection of several Servers", "one Server"):
        assert kind in server_scope
    reservation_scope = context.split("**Reservation Scope**:\n", 1)[1].split("\n_Avoid_:", 1)[0]
    assert '"Scope" alone means Reservation Scope.' in reservation_scope


def test_agent_architecture_lists_server_scope():
    """Document the owner of combined Server selection and family availability."""
    agents = (REPOSITORY_ROOT / "AGENTS.md").read_text()
    architecture = agents.split("## Architecture", 1)[1].split("### Core components", 1)[0]
    assert "server_scope.py   (Server selection, view permissions, and family availability)" in architecture


def test_agent_sync_lifecycle_uses_the_current_ownership_interfaces():
    """Direct agents to the phase reconciler and the claim-only entry point."""
    instructions = (REPOSITORY_ROOT / "AGENTS.md").read_text()
    lifecycle = instructions.split("**Sync lifecycle**:", 1)[1].split("\n- **", 1)[0]

    assert "reconcile()" in lifecycle
    assert "claim()" in lifecycle
    for retired in ("cleanup_stale_ips_batch()", "_sync()", "cleanup=False"):
        assert retired not in lifecycle


def test_agent_reconciler_scopes_the_two_phase_last_link_rule_to_ip_addresses():
    """Prefix and IP Range links follow their own phase, so the two-phase rule names IP addresses."""
    instructions = (REPOSITORY_ROOT / "AGENTS.md").read_text()
    reconciler = " ".join(instructions.split("- **`ipam_reconciliation.py`**:", 1)[1].split("\n- **", 1)[0].split())

    assert "The last link of a Server to an IP address needs a complete lease phase" in reconciler
    assert "The last link of a Server needs" not in reconciler


def test_the_dhcp_import_guide_states_the_scheduled_import_version_refusal():
    """Document the scheduled job's failure when the DHCP plugin is too old."""
    guide = " ".join((REPOSITORY_ROOT / "docs/guide/dhcp-import.md").read_text().split())
    requirement = "The DHCP Import needs netbox-plugin-dhcp 0.2.0 or later."
    passage = guide.split(requirement, 1)[1].split("## When the import runs", 1)[0]

    assert "The scheduled import also refuses before it reads Kea." in passage
    assert "The job records the failure, continues with the next Server, and ends as failed." in passage


def test_the_mapping_kind_lists_name_every_kind_of_mapping_kinds():
    """Every prose list of the DHCP Import Mapping kinds must follow ``MAPPING_KINDS``."""
    from netbox_kea.integrations.dhcp_import_report import Kind
    from netbox_kea.models import MAPPING_KINDS

    terms = {
        Kind.SERVER: "dhcp server",
        Kind.SHARED_NETWORK: "shared network",
        Kind.SUBNET: "subnet",
        Kind.POOL: "pool",
        Kind.PD_POOL: "delegated-prefix pool",
        Kind.RESERVATION: "reservation",
        Kind.CLIENT_CLASS: "client class",
        Kind.OPTION_DEFINITION: "option definition",
        Kind.OPTION: "dhcp option",
    }
    assert set(terms) == set(MAPPING_KINDS)

    passages = (
        (
            "docs/adr/0008-dhcp-import-mappings-follow-target-branch-history.md",
            "follow their targets",
            ")",
            terms.values(),
        ),
        ("docs/guide/branching.md", "- dhcp import mappings follow", " - ", terms.values()),
        ("docs/guide/dhcp-import.md", "keeps a dhcp import mapping from", ".", terms.values()),
        ("AGENTS.md", "applies each plan (`dhcp_plugin.apply_plan`).", "that the apply writes", terms.values()),
    )
    missing = {}
    for path, start, end, expected in passages:
        text = " ".join((REPOSITORY_ROOT / path).read_text().split()).lower()
        passage = text.split(start, 1)[1].split(end, 1)[0]
        missing[path] = []
        for term in expected:
            plural = "(?:es)?" if term == "client class" else "s?"
            if not re.search(rf"(?<![a-z-])(?<!delegated-prefix ){re.escape(term)}{plural}(?![a-z])", passage):
                missing[path].append(term)
    assert missing == {path: [] for path, *_ in passages}


def test_context_qualifies_mapping_ownership_for_a_subnet_without_an_id():
    """Objects created without a Kea subnet ID can have no mapping."""
    context = (REPOSITORY_ROOT / "CONTEXT.md").read_text()
    mapping = " ".join(context.split("**DHCP Import Mapping**:\n", 1)[1].split("\n_Avoid_:", 1)[0].split())

    assert (
        "The exception is a Kea Subnet without a subnet ID: it, its Pools, its delegated-prefix Pools and each DHCP "
        "Option of these objects have no mapping." in mapping
    )
    assert "Apart from that exception, a DHCP Option without a mapping" in mapping
