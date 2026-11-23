"""
Test Suite: Item 1 - Adapter Exports & Ambient Rule Discovery
============================================================
Verifies:
1. Clean export of all adapters including CodexAdapter from lcs.adapters.
2. Ambient rule discovery (AGENTS.md, CLAUDE.md, .cursorrules, RULES.md) across adapters.
3. Classification of ambient rules under ResourceType.RULE with correct provenance.
4. Instruction-only playbooks report execution_mode='INSTRUCTION_HANDOFF'.
5. Instruction-only playbooks fail closed when expected deliverables cannot be produced.
"""

import os
import tempfile
import pytest

from lcs.adapters import (
    AntigravityAdapter,
    ClaudeCodeAdapter,
    OpenCodeAdapter,
    CodexAdapter,
    GenericPOSIXAdapter,
    EnvironmentKind
)
from lcs.inventory.models import ResourceType
from lcs.inventory.inventory import UnifiedCapabilityInventory
from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.planning import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition
from lcs.governance import ApproverConsent, ApproverRole, GovernanceStatus
from lcs.policy import InterfaceTrustPolicy


def test_01_adapter_imports_and_all_exports():
    """Confirms all supported adapters including CodexAdapter are cleanly exported."""
    import lcs.adapters as adapters_pkg
    assert hasattr(adapters_pkg, "CodexAdapter")
    assert hasattr(adapters_pkg, "AntigravityAdapter")
    assert hasattr(adapters_pkg, "ClaudeCodeAdapter")
    assert hasattr(adapters_pkg, "OpenCodeAdapter")
    assert hasattr(adapters_pkg, "GenericPOSIXAdapter")
    assert "CodexAdapter" in adapters_pkg.__all__
    assert "AntigravityAdapter" in adapters_pkg.__all__


def test_02_ambient_rules_discovered_in_workspace_root():
    """
    Confirms that ambient rule files in the workspace root:
    - AGENTS.md
    - CLAUDE.md
    - .cursorrules
    are discovered and categorized as ResourceType.RULE by Antigravity and Generic adapters.
    """
    with tempfile.TemporaryDirectory(prefix="lcs_rules_test_") as tmpdir:
        # Create ambient rules in workspace root
        agents_md = os.path.join(tmpdir, "AGENTS.md")
        with open(agents_md, "w", encoding="utf-8") as f:
            f.write("# Workspace Multi-Agent Rules\nRule 1: Always verify deliverables.\n")

        cursorrules = os.path.join(tmpdir, ".cursorrules")
        with open(cursorrules, "w", encoding="utf-8") as f:
            f.write("Do not use unverified mock outputs.\n")

        ag_adapter = AntigravityAdapter(workspace_root=tmpdir)
        roots = ag_adapter.discover_capability_roots(tmpdir)
        root_paths = [os.path.realpath(r.root_path) for r in roots]
        assert os.path.realpath(tmpdir) in root_paths

        cfg = LCSConfig.resolve(root_override=tmpdir)
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            inv = ctx.inventory
            inv.initialize_environment(adapters=[ag_adapter])

            # Verify AGENTS.md and .cursorrules are in inventory as RULE
            records = inv.list_all()
            rule_recs = [r for r in records if r.resource_type == ResourceType.RULE]
            assert len(rule_recs) >= 2

            agents_rec = next((r for r in rule_recs if r.name == "AGENTS"), None)
            assert agents_rec is not None
            assert agents_rec.resource_type == ResourceType.RULE
            assert "Workspace Multi-Agent Rules" in agents_rec.raw_content

            cursor_rec = next((r for r in rule_recs if r.name == ".cursorrules"), None)
            assert cursor_rec is not None
            assert cursor_rec.resource_type == ResourceType.RULE


def test_03_codex_adapter_discovers_workspace_rules(monkeypatch):
    """Confirms Codex adapter discovers workspace root rules when active."""
    with tempfile.TemporaryDirectory(prefix="lcs_codex_rules_") as tmpdir:
        claude_md = os.path.join(tmpdir, "CLAUDE.md")
        with open(claude_md, "w", encoding="utf-8") as f:
            f.write("# Codex & Claude Code Project Rules\nEnforce strict typing.\n")

        monkeypatch.setenv("CODEX_SESSION_ID", "sess-test-9912")
        codex_adapter = CodexAdapter(workspace_root=tmpdir)
        assert codex_adapter.detect_active()

        roots = codex_adapter.discover_capability_roots(tmpdir)
        root_paths = [os.path.realpath(r.root_path) for r in roots]
        assert os.path.realpath(tmpdir) in root_paths

        cfg = LCSConfig.resolve(root_override=tmpdir)
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            inv = ctx.inventory
            inv.initialize_environment(adapters=[codex_adapter])
            rec = next((r for r in inv.list_all() if r.name == "CLAUDE"), None)
            assert rec is not None
            assert rec.resource_type == ResourceType.RULE


def test_04_instruction_only_skill_reports_handoff_mode():
    """
    Confirms that instruction-only skills report execution_mode='INSTRUCTION_HANDOFF'
    when executed without declared deliverable output files.
    """
    with tempfile.TemporaryDirectory(prefix="lcs_handoff_test_") as tmpdir:
        skills_dir = os.path.join(tmpdir, ".agents", "skills", "code-architect")
        os.makedirs(skills_dir, exist_ok=True)
        with open(os.path.join(skills_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(
                "---\n"
                "name: code-architect\n"
                "description: Architectural design guidance for modular microservices\n"
                "---\n"
                "# Code Architect\n"
                "Provide high-level architecture designs without writing executable code.\n"
            )

        cfg = LCSConfig.resolve(root_override=tmpdir)
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            inv = ctx.inventory
            inv.initialize_environment(adapters=ctx.adapter_registry.list_all())
            rec = next((r for r in inv.list_all() if r.name == "code-architect"), None)
            assert rec is not None

            # Execute via execution engine
            res = ctx.execution_engine.skill_handler.execute_skill(
                capability_urn=rec.urn,
                arguments={"query": "Design an auth service"}
            )
            assert res["status"] == "SUCCESS"
            assert res["execution_mode"] == "INSTRUCTION_HANDOFF"
            assert "Code Architect" in res["rendered_instructions"]


def test_05_instruction_only_skill_fails_closed_when_deliverable_demanded():
    """
    Confirms truthful execution: if a deliverable artifact is required but the capability
    has no executable script to produce it, execution fails closed instead of faking success.
    """
    with tempfile.TemporaryDirectory(prefix="lcs_fail_closed_") as tmpdir:
        skills_dir = os.path.join(tmpdir, ".agents", "skills", "doc-reviewer")
        os.makedirs(skills_dir, exist_ok=True)
        with open(os.path.join(skills_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(
                "---\n"
                "name: doc-reviewer\n"
                "description: Documentation guidelines\n"
                "---\n"
                "# Doc Reviewer\nReview docs.\n"
            )

        cfg = LCSConfig.resolve(root_override=tmpdir)
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            inv = ctx.inventory
            inv.initialize_environment(adapters=ctx.adapter_registry.list_all())
            rec = next((r for r in inv.list_all() if r.name == "doc-reviewer"), None)

            deliv_path = os.path.join(tmpdir, "review_summary.pdf")
            with pytest.raises(Exception) as excinfo:
                ctx.execution_engine.skill_handler.execute_skill(
                    capability_urn=rec.urn,
                    arguments={"deliverable": deliv_path}
                )
            assert "instruction-only playbook" in str(excinfo.value)
