# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for the repository's domain-language documentation."""

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


def test_branching_decisions_keep_ownership_links_in_main():
    """The decisions must agree with the ownership link's main-only routing."""
    design = (REPOSITORY_ROOT / "docs/design/netbox-branching.md").read_text()
    decisions = design.split("## Decisions\n", 1)[1].split("## Design\n", 1)[0]
    opening, table = decisions.split("| # |", 1)
    assert "ADR 0006 link model main-only" in " ".join(opening.split())
    exemption_decision = next(row for row in table.splitlines() if row.startswith("| D14 |"))
    assert "first branchable plugin model" not in exemption_decision
    assert "ADR 0006" in exemption_decision
    assert "main-only" in exemption_decision


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


def test_the_mapping_kind_lists_name_every_kind_of_mapping_kinds():
    """Every prose list of the DHCP Import Mapping kinds must follow ``MAPPING_KINDS``."""
    from netbox_kea.integrations.dhcp_import_report import Kind
    from netbox_kea.models import MAPPING_KINDS

    terms = {
        Kind.SERVER: "dhcp server",
        Kind.SHARED_NETWORK: "shared network",
        Kind.SUBNET: "subnet",
        Kind.POOL: "pool",
        Kind.RESERVATION: "reservation",
        Kind.CLIENT_CLASS: "client class",
        Kind.OPTION_DEFINITION: "option definition",
    }
    assert set(terms) == set(MAPPING_KINDS)

    # The guides list what the import writes, and it does not write a Shared Network yet.
    imported = [term for kind, term in terms.items() if kind != Kind.SHARED_NETWORK]
    passages = (
        ("docs/design/dhcp-import-mapping-branching.md", "## contract", "| operation |", terms.values()),
        (
            "docs/adr/0008-dhcp-import-mappings-follow-target-branch-history.md",
            "follow their targets",
            ")",
            terms.values(),
        ),
        ("docs/guide/branching.md", "- dhcp import mappings follow", " - ", imported),
        ("docs/guide/configuration.md", "keeps a dhcp import mapping from", ".", imported),
        ("AGENTS.md", "applies each plan (`dhcp_plugin.apply_plan`).", "that the apply writes", imported),
    )
    missing = {}
    for path, start, end, expected in passages:
        text = " ".join((REPOSITORY_ROOT / path).read_text().split()).lower()
        passage = text.split(start, 1)[1].split(end, 1)[0]
        missing[path] = [term for term in expected if term not in passage]
    assert missing == {path: [] for path, *_ in passages}
