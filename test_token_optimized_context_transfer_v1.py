"""
LCS Token-Optimized Context Transfer & Deep Retrieval Test Suite
===============================================================
Verifies Item 3:
1. Complete delivery of selected instructions and transitive dependencies without summarization.
2. Long dependency chain (A -> B -> C -> D) with required instructions preserved at the tail.
3. Diamond / shared dependencies deduplicated in the context transfer payload.
4. Dependency cycle detection (A -> B -> A) without infinite recursion.
5. Inaccessible or missing mandatory files block execution (ready=False, missing_required reported).
6. Same-name resources from different locations resolved by deterministic precedence.
7. Budget gating: if mandatory instructions exceed budget, handoff blocks with clear deficit reporting.
8. Catalog isolation invariant: adding 100 irrelevant skills to the catalog does not inflate payload size.
"""

import os
import json
import sqlite3
import pytest

from lcs.inventory.models import (
    ResourceType,
    UnifiedResourceRecord,
    ProvenanceRecord,
    OperationalLifecycleState,
    ExecutionRequirement,
)
from lcs.inventory.inventory import UnifiedCapabilityInventory
from lcs.inventory.retrieval import DeepCapabilityRetriever


@pytest.fixture
def retriever_setup():
    conn = sqlite3.connect(":memory:")
    inv = UnifiedCapabilityInventory(conn=conn)
    retriever = DeepCapabilityRetriever(inv)
    return inv, retriever, conn


def test_01_complete_instruction_and_transitive_dependency_delivery(retriever_setup):
    """Case 1: Deep retrieval delivers verbatim instructions and transitive dependencies."""
    inv, retriever, conn = retriever_setup

    # Child dependency
    child_content = "# Child Tool\nExecute low-level database socket query."
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:tool:posix:db-socket",
        name="db-socket",
        resource_type=ResourceType.TOOL,
        display_name="DB Socket Tool",
        description="Low level DB socket",
        raw_content=child_content,
        raw_content_digest="child_digest_123",
        provenance=ProvenanceRecord("generic_posix", "HOST", "/bin/sock", "/bin/sock", "child_digest_123"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
    ))

    # Primary capability declaring dependency on db-socket
    primary_content = "# Master Data Query\nRun high level customer query using db-socket."
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:antigravity.workspace:data-query",
        name="data-query",
        resource_type=ResourceType.SKILL,
        display_name="Data Query Skill",
        description="Query data records",
        raw_content=primary_content,
        raw_content_digest="primary_digest_456",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/dq", "/ws/dq", "primary_digest_456"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        declared_dependencies=[{"name": "db-socket", "mandatory": True, "type": "TOOL"}]
    ))

    res = retriever.retrieve_deep("urn:lcs:skill:antigravity.workspace:data-query")
    assert res.is_executable is True
    assert len(res.resolved_dependencies) == 1
    assert res.resolved_dependencies[0].name == "db-socket"

    payload = retriever.optimize_context_transfer("query customer accounts", res)
    assert payload.instructions_text == primary_content
    assert "db-socket" in payload.dependency_snippets
    assert child_content in payload.dependency_snippets["db-socket"]
    assert payload.provenance_hashes["urn:lcs:skill:antigravity.workspace:data-query"] == "primary_digest_456"
    assert payload.provenance_hashes["urn:lcs:tool:posix:db-socket"] == "child_digest_123"


def test_02_long_chain_dependency_resolution(retriever_setup):
    """Case 2: Long dependency chain (A -> B -> C -> D) preserves instructions at the end of the chain."""
    inv, retriever, conn = retriever_setup

    nodes = ["step-d", "step-c", "step-b", "step-a"]
    for idx, name in enumerate(nodes):
        child_dep = [{"name": nodes[idx - 1], "mandatory": True}] if idx > 0 else []
        content = f"# Instruction for {name}\nRun step logic for {name}."
        inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
            urn=f"urn:lcs:skill:workspace:{name}",
            name=name,
            resource_type=ResourceType.SKILL,
            display_name=f"Skill {name}",
            description=f"Performs {name}",
            raw_content=content,
            raw_content_digest=f"hash_{name}",
            provenance=ProvenanceRecord("antigravity", "WORKSPACE", f"/ws/{name}", f"/ws/{name}", f"hash_{name}"),
            lifecycle_state=OperationalLifecycleState.EXECUTABLE,
            declared_dependencies=child_dep
        ))

    res = retriever.retrieve_deep("urn:lcs:skill:workspace:step-a")
    assert res.is_executable is True
    assert len(res.resolved_dependencies) == 3
    resolved_names = [d.name for d in res.resolved_dependencies]
    assert resolved_names == ["step-b", "step-c", "step-d"]

    payload = retriever.optimize_context_transfer("execute pipeline", res)
    assert "step-d" in payload.dependency_snippets
    assert "Run step logic for step-d" in payload.dependency_snippets["step-d"]


def test_03_shared_diamond_dependency_deduplication(retriever_setup):
    """Case 3: Diamond dependency (A -> B, A -> C, B -> D, C -> D) is deduplicated without duplicates in payload."""
    inv, retriever, conn = retriever_setup

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:tool:common:base-util",
        name="base-util",
        resource_type=ResourceType.TOOL,
        display_name="Base Utility",
        description="Shared base utility",
        raw_content="BASE_UTIL_INSTRUCTION_V1",
        raw_content_digest="base_util_hash",
        provenance=ProvenanceRecord("generic_posix", "BUILTIN", "/b/u", "/b/u", "base_util_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
    ))

    for branch in ("branch-left", "branch-right"):
        inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
            urn=f"urn:lcs:skill:ws:{branch}",
            name=branch,
            resource_type=ResourceType.SKILL,
            display_name=branch,
            description=f"Branch {branch}",
            raw_content=f"INSTRUCTION_{branch.upper()}",
            raw_content_digest=f"hash_{branch}",
            provenance=ProvenanceRecord("antigravity", "WORKSPACE", f"/b/{branch}", f"/b/{branch}", f"hash_{branch}"),
            lifecycle_state=OperationalLifecycleState.EXECUTABLE,
            declared_dependencies=[{"name": "base-util", "mandatory": True}]
        ))

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:diamond-root",
        name="diamond-root",
        resource_type=ResourceType.SKILL,
        display_name="Diamond Root",
        description="Root of diamond dependency",
        raw_content="INSTRUCTION_DIAMOND_ROOT",
        raw_content_digest="hash_root",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/b/root", "/b/root", "hash_root"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        declared_dependencies=[
            {"name": "branch-left", "mandatory": True},
            {"name": "branch-right", "mandatory": True}
        ]
    ))

    res = retriever.retrieve_deep("urn:lcs:skill:ws:diamond-root")
    assert res.is_executable is True
    # Distinct resolved dependencies should be exactly 3: branch-left, branch-right, base-util
    assert len(res.resolved_dependencies) == 3
    payload = retriever.optimize_context_transfer("diamond task", res)
    # base-util must only appear once in snippets
    assert list(payload.dependency_snippets.keys()).count("base-util") == 1


def test_04_dependency_cycle_detection(retriever_setup):
    """Case 4: Cyclic dependency (A -> B -> A) terminates safely without recursion loops."""
    inv, retriever, conn = retriever_setup

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:cycle-a",
        name="cycle-a",
        resource_type=ResourceType.SKILL,
        display_name="Cycle A",
        description="Cycle A node",
        raw_content="A",
        raw_content_digest="hash_ca",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/a", "/a", "hash_ca"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        declared_dependencies=[{"name": "cycle-b", "mandatory": True}]
    ))

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:cycle-b",
        name="cycle-b",
        resource_type=ResourceType.SKILL,
        display_name="Cycle B",
        description="Cycle B node",
        raw_content="B",
        raw_content_digest="hash_cb",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/b", "/b", "hash_cb"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        declared_dependencies=[{"name": "cycle-a", "mandatory": True}]
    ))

    res = retriever.retrieve_deep("urn:lcs:skill:ws:cycle-a")
    assert res.is_executable is True
    # Visited tracking prevents infinite expansion
    assert len(res.resolved_dependencies) == 1
    assert res.resolved_dependencies[0].name == "cycle-b"


def test_05_missing_mandatory_dependency_blocks_execution(retriever_setup):
    """Case 5: Missing mandatory dependency sets is_executable=False and reports missing items."""
    inv, retriever, conn = retriever_setup

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:broken-root",
        name="broken-root",
        resource_type=ResourceType.SKILL,
        display_name="Broken Root",
        description="Depends on nonexistent tool",
        raw_content="BROKEN",
        raw_content_digest="hash_br",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/br", "/br", "hash_br"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        declared_dependencies=[{"name": "nonexistent-database-driver", "mandatory": True}]
    ))

    res = retriever.retrieve_deep("urn:lcs:skill:ws:broken-root")
    assert res.is_executable is False
    assert "nonexistent-database-driver" in res.missing_dependencies


def test_06_token_budget_gating_blocks_over_budget(retriever_setup):
    """Case 6: If mandatory instructions exceed token budget, budget_exceeded is set."""
    inv, retriever, conn = retriever_setup

    huge_content = "# Big Skill\n" + ("x" * 20000)
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:huge-skill",
        name="huge-skill",
        resource_type=ResourceType.SKILL,
        display_name="Huge Skill",
        description="Huge capability exceeding small token budgets",
        raw_content=huge_content,
        raw_content_digest="hash_huge",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/huge", "/huge", "hash_huge"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
    ))

    res = retriever.retrieve_deep("urn:lcs:skill:ws:huge-skill")
    # Low budget of 500 tokens
    payload = retriever.optimize_context_transfer("run huge task", res, token_budget=500)
    assert payload.budget_exceeded is True
    assert payload.estimated_tokens > 500


def test_07_catalog_isolation_invariant(retriever_setup):
    """Case 7: Adding 100 irrelevant capabilities to the catalog does NOT inflate the context transfer payload."""
    inv, retriever, conn = retriever_setup

    # Register target capability
    target_content = "# Target Analyzer\nRun targeted lint analysis."
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:target-analyzer",
        name="target-analyzer",
        resource_type=ResourceType.SKILL,
        display_name="Target Analyzer",
        description="Targeted analyzer",
        raw_content=target_content,
        raw_content_digest="target_hash",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/target", "/target", "target_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
    ))

    # Baseline payload size
    res_base = retriever.retrieve_deep("urn:lcs:skill:ws:target-analyzer")
    payload_base = retriever.optimize_context_transfer("analyze code", res_base)
    baseline_tokens = payload_base.estimated_tokens

    # Inject 100 completely irrelevant capabilities into the inventory
    for i in range(100):
        inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
            urn=f"urn:lcs:skill:irrelevant:skill-{i}",
            name=f"skill-{i}",
            resource_type=ResourceType.SKILL,
            display_name=f"Irrelevant Skill {i}",
            description=f"Irrelevant description {i}",
            raw_content=f"IRRELEVANT_CONTENT_{i}" * 50,
            raw_content_digest=f"irr_hash_{i}",
            provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", f"/irr/{i}", f"/irr/{i}", f"irr_hash_{i}"),
            lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        ))

    assert inv.total_count == 101

    # Re-retrieve target capability
    res_after = retriever.retrieve_deep("urn:lcs:skill:ws:target-analyzer")
    payload_after = retriever.optimize_context_transfer("analyze code", res_after)

    # Invariant: context transfer payload size is identical (0 token bloat from 100 irrelevant catalog items)
    assert payload_after.estimated_tokens == baseline_tokens
    assert len(payload_after.dependency_snippets) == 0
    assert "IRRELEVANT_CONTENT" not in payload_after.instructions_text
    assert "IRRELEVANT_CONTENT" not in payload_after.execution_guidance


def test_08_missing_referenced_asset_file_blocks_handoff(retriever_setup):
    """Case 8: Missing referenced asset file declared in auxiliary_files blocks execution with specific reason."""
    inv, retriever, conn = retriever_setup

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:missing-ref-skill",
        name="missing-ref-skill",
        resource_type=ResourceType.SKILL,
        display_name="Missing Ref Skill",
        description="Requires missing compliance rulebook",
        raw_content="# Missing Ref\nRequires rulebook.",
        raw_content_digest="miss_hash",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/m", "/ws/m", "miss_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        auxiliary_files={
            "references/nonexistent_rulebook.txt": {
                "path": "/tmp/definitely_nonexistent_rulebook_9921.txt",
                "kind": "REFERENCE"
            }
        }
    ))

    res = retriever.retrieve_deep("urn:lcs:skill:ws:missing-ref-skill")
    assert res.is_executable is False
    assert "references/nonexistent_rulebook.txt" in res.missing_dependencies
    assert len(res.inaccessible_resources) >= 1
    assert "missing on disk" in res.inaccessible_resources[0]["reason"].lower()


def test_09_token_metric_clearly_labeled_estimate(retriever_setup):
    """Case 9: Token counts are clearly labeled as estimates."""
    inv, retriever, conn = retriever_setup

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:ws:labeled-token-skill",
        name="labeled-token-skill",
        resource_type=ResourceType.SKILL,
        display_name="Labeled Token Skill",
        description="Verifies token labeling",
        raw_content="# Labeled Token\nVerify token metric labeling.",
        raw_content_digest="label_hash",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/l", "/ws/l", "label_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
    ))

    res = retriever.retrieve_deep("urn:lcs:skill:ws:labeled-token-skill")
    payload = retriever.optimize_context_transfer("test query", res)
    assert payload.token_metric == "ESTIMATE"
    assert payload.estimated_tokens > 0


def test_10_deterministic_same_name_skill_precedence(retriever_setup):
    """Case 10: Deterministic resolution of same-name skills across WORKSPACE and USER_GLOBAL tiers."""
    inv, retriever, conn = retriever_setup

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:global:cloud-deployer",
        name="cloud-deployer",
        resource_type=ResourceType.SKILL,
        display_name="Global Cloud Deployer",
        description="Generic cloud deployer",
        raw_content="# Global Deployer\nGeneric instructions.",
        raw_content_digest="hash_g_dep",
        provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", "/g/dep", "/g/dep", "hash_g_dep"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
    ))

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:workspace:cloud-deployer",
        name="cloud-deployer",
        resource_type=ResourceType.SKILL,
        display_name="Workspace Cloud Deployer",
        description="Project-specific cloud deployer",
        raw_content="# Workspace Deployer\nProject-specific deployment.",
        raw_content_digest="hash_ws_dep",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/dep", "/ws/dep", "hash_ws_dep"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
    ))

    # Retrieve by name
    res = retriever.retrieve_deep("cloud-deployer")
    assert res.primary_resource.urn == "urn:lcs:skill:workspace:cloud-deployer"
    assert res.primary_resource.provenance.precedence_tier == "WORKSPACE"
    assert "Project-specific" in res.primary_resource.raw_content
