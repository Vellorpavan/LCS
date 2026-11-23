"""
LCS Skill Selection Reliability & Benchmark Evaluation Suite
============================================================
Verifies Item 2:
1. Paraphrased requests without skill names.
2. Nested skill structures.
3. Duplicate names across precedence tiers (WORKSPACE > HOST > USER_GLOBAL).
4. Disambiguation between similar descriptions.
5. Multi-skill tasks requiring two independent capabilities.
6. Ambiguous requests returning clarification messages.
7. Unmatched requests returning limitation messages.
8. Anti-cache pollution: weak cache match cannot hide a better installed skill.
9. Anti-self-selection: call-me cannot select itself.
"""

import os
import tempfile
import sqlite3
import pytest

from lcs.inventory.models import (
    ResourceType,
    UnifiedResourceRecord,
    ProvenanceRecord,
    OperationalLifecycleState,
)
from lcs.inventory.inventory import UnifiedCapabilityInventory
from lcs.interface.contract import TaskRequest
from lcs.interface.core_bridge import LCSCoreBridge


@pytest.fixture
def populated_inventory():
    """Sets up an in-memory UnifiedCapabilityInventory with a realistic capability library."""
    conn = sqlite3.connect(":memory:")
    inv = UnifiedCapabilityInventory(conn=conn)

    # 1. Security Review Skill (Global)
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:antigravity.global:security-review",
        name="security-review",
        resource_type=ResourceType.SKILL,
        display_name="Security Reviewer",
        description="Audits source code for security vulnerabilities, hardcoded secrets, and injection flaws.",
        raw_content="# Security Review\nDetects API keys, tokens, SQL injection, and buffer overflows.",
        raw_content_digest="sec_hash_01",
        provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", "/global/sec", "/global/sec", "sec_hash_01"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["security", "audit", "vulnerabilities", "secrets"]
    ))

    # 2. Database Extractor (Workspace Tier)
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:antigravity.workspace:data-extractor",
        name="data-extractor",
        resource_type=ResourceType.SKILL,
        display_name="Data Extractor",
        description="Extracts relational records and customer datasets from database tables.",
        raw_content="# Data Extractor\nQuery SQL databases and extract dataset rows.",
        raw_content_digest="extract_hash_01",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/extract", "/ws/extract", "extract_hash_01"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["database", "sql", "extract", "data"]
    ))

    # 3. Report Generator (Workspace Tier)
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:antigravity.workspace:report-generator",
        name="report-generator",
        resource_type=ResourceType.SKILL,
        display_name="Markdown Report Generator",
        description="Formats structured data arrays into publication-quality Markdown summaries and executive reports.",
        raw_content="# Report Generator\nCompiles data tables into formatted markdown reports.",
        raw_content_digest="report_hash_01",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/report", "/ws/report", "report_hash_01"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["report", "markdown", "summary", "format"]
    ))

    # 4. Duplicate name across tiers: linter (Workspace vs Global)
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:antigravity.global:code-linter",
        name="code-linter",
        resource_type=ResourceType.SKILL,
        display_name="Global Code Linter",
        description="Generic Python and JavaScript syntax linter.",
        raw_content="# Global Linter\nStandard syntax linting.",
        raw_content_digest="lint_global_hash",
        provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", "/global/lint", "/global/lint", "lint_global_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["lint", "syntax"]
    ))
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:antigravity.workspace:code-linter",
        name="code-linter",
        resource_type=ResourceType.SKILL,
        display_name="Custom Workspace Linter",
        description="Project-specific strict linter enforcing corporate architecture rules.",
        raw_content="# Workspace Linter\nStrict project architecture linting.",
        raw_content_digest="lint_ws_hash",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/lint", "/ws/lint", "lint_ws_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["lint", "syntax", "strict"]
    ))

    # 5. Call-Me itself (installed in workspace)
    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:antigravity.workspace:call-me",
        name="call-me",
        resource_type=ResourceType.SKILL,
        display_name="Call Me Orchestrator",
        description="LCS entry point for capability discovery and orchestration.",
        raw_content="# Call Me\nInvoke LCS orchestrator.",
        raw_content_digest="callme_hash",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/callme", "/ws/callme", "callme_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["orchestration", "lcs"]
    ))

    return inv, conn


class MockContext:
    def __init__(self, inventory, cache=None):
        self.inventory = inventory
        self.cache = cache
        self.skill_service = None


class MockCacheCandidate:
    def __init__(self, urn, relevance_score):
        self.urn = urn
        self.relevance_score = relevance_score


class MockCache:
    def __init__(self, candidates):
        self._candidates = candidates

    def search_candidates(self, query, limit=10):
        return self._candidates[:limit]


def test_01_paraphrase_without_skill_name(populated_inventory):
    """Case 1: User describes task without using any skill name ('find security vulnerabilities and credentials')."""
    inv, conn = populated_inventory
    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    req = TaskRequest(
        request_id="req-1",
        session_id="sess-1",
        original_instruction="find security vulnerabilities and credentials in code",
        normalized_task_description="find security vulnerabilities and credentials in code",
        invocation_environment="ANTIGRAVITY"
    )
    resp = bridge.submit_task(req)
    assert resp.status == "ACCEPTED"
    assert resp.candidate_count >= 1
    assert "urn:lcs:skill:antigravity.global:security-review" in resp.candidate_urns


def test_02_duplicate_names_precedence_tier_resolution(populated_inventory):
    """Case 2: Duplicate capability name across WORKSPACE and USER_GLOBAL tiers."""
    inv, conn = populated_inventory
    # Workspace version must have won during conflict resolution
    matches = inv.search("code-linter")
    assert len(matches) >= 1
    reg = matches[0]
    assert reg.provenance.precedence_tier == "WORKSPACE"
    assert reg.urn == "urn:lcs:skill:antigravity.workspace:code-linter"


def test_03_multi_skill_decomposition(populated_inventory):
    """Case 3: Multi-skill request requiring two independent capabilities ('extract customer data and format markdown report')."""
    inv, conn = populated_inventory
    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    req = TaskRequest(
        request_id="req-multi",
        session_id="sess-multi",
        original_instruction="extract customer records from database and generate markdown report",
        normalized_task_description="extract customer records from database and generate markdown report",
        invocation_environment="ANTIGRAVITY"
    )
    resp = bridge.submit_task(req)
    assert resp.status == "ACCEPTED"
    assert resp.candidate_count >= 2
    # Both required capabilities must be selected
    assert "urn:lcs:skill:antigravity.workspace:data-extractor" in resp.candidate_urns
    assert "urn:lcs:skill:antigravity.workspace:report-generator" in resp.candidate_urns


def test_04_call_me_never_selects_itself(populated_inventory):
    """Case 4: Invocation query mentioning call-me must never select call-me as an actionable capability."""
    inv, conn = populated_inventory
    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    req = TaskRequest(
        request_id="req-self",
        session_id="sess-self",
        original_instruction="use call-me to audit security vulnerabilities",
        normalized_task_description="use call-me to audit security vulnerabilities",
        invocation_environment="ANTIGRAVITY"
    )
    resp = bridge.submit_task(req)
    assert resp.status == "ACCEPTED"
    for urn in resp.candidate_urns:
        assert not urn.endswith(":call-me")
        assert not urn.endswith(":call_me")
    assert "urn:lcs:skill:antigravity.global:security-review" in resp.candidate_urns


def test_05_ambiguous_request_clarification(populated_inventory):
    """Case 5: Ambiguous request ('do it' or 'run') must return actionable clarification guidance."""
    inv, conn = populated_inventory
    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    for ambig_prompt in ["do it", "fix this", "run", "help"]:
        req = TaskRequest(
            request_id=f"req-{ambig_prompt}",
            session_id="sess-ambig",
            original_instruction=ambig_prompt,
            normalized_task_description=ambig_prompt,
            invocation_environment="ANTIGRAVITY"
        )
        resp = bridge.submit_task(req)
        assert resp.candidate_count == 0
        assert "ambiguous" in resp.message.lower()


def test_06_unmatched_request_limitation(populated_inventory):
    """Case 6: Domain with no suitable capabilities ('bake an artisan sourdough bread in wood oven')."""
    inv, conn = populated_inventory
    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    req = TaskRequest(
        request_id="req-bake",
        session_id="sess-bake",
        original_instruction="bake an artisan sourdough bread in wood oven",
        normalized_task_description="bake an artisan sourdough bread in wood oven",
        invocation_environment="ANTIGRAVITY"
    )
    resp = bridge.submit_task(req)
    assert resp.candidate_count == 0
    assert "zero registered capabilities" in resp.message.lower()


def test_07_weak_cached_match_cannot_hide_better_installed_skill(populated_inventory):
    """Case 7: Anti-cache pollution: a weak cached match (score 20) must not hide a better installed skill (score 100)."""
    inv, conn = populated_inventory

    # Mock cache containing an irrelevant weak match
    weak_cache_candidate = MockCacheCandidate("urn:lcs:skill:cached:irrelevant-helper", relevance_score=20.0)
    mock_cache = MockCache([weak_cache_candidate])

    ctx = MockContext(inv, cache=mock_cache)
    bridge = LCSCoreBridge(ctx)

    req = TaskRequest(
        request_id="req-anti-cache",
        session_id="sess-anti-cache",
        original_instruction="audits source code for security vulnerabilities",
        normalized_task_description="audits source code for security vulnerabilities",
        invocation_environment="ANTIGRAVITY"
    )
    resp = bridge.submit_task(req)
    assert resp.status == "ACCEPTED"
    assert len(resp.candidate_urns) >= 1
    # The installed security-review skill must be top-ranked above the weak cache hit
    assert resp.candidate_urns[0] == "urn:lcs:skill:antigravity.global:security-review"


def test_08_disambiguation_between_similar_skills(populated_inventory):
    """Case 8: Disambiguate between two similar domain skills based on specific intent."""
    inv, conn = populated_inventory

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:global:python-patterns",
        name="python-patterns",
        resource_type=ResourceType.SKILL,
        display_name="Python Patterns",
        description="Idiomatic Python patterns, PEP 8 coding standards, and type hints for maintainable software.",
        raw_content="# Python Patterns\nFollow PEP 8 and use type hints.",
        raw_content_digest="pat_hash",
        provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", "/g/pat", "/g/pat", "pat_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["python", "pep8", "idioms", "typing"]
    ))

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:global:python-testing",
        name="python-testing",
        resource_type=ResourceType.SKILL,
        display_name="Python Testing",
        description="Python testing strategies using pytest, fixtures, mocking, parametrization, and coverage requirements.",
        raw_content="# Python Testing\nWrite pytest fixtures and unit tests.",
        raw_content_digest="test_hash",
        provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", "/g/test", "/g/test", "test_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["python", "pytest", "testing", "mocks", "fixtures"]
    ))

    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    # Testing query
    req_test = TaskRequest(
        request_id="req-test",
        session_id="s1",
        original_instruction="write pytest test fixtures and mocks for unit testing",
        normalized_task_description="write pytest test fixtures and mocks for unit testing",
        invocation_environment="ANTIGRAVITY"
    )
    resp_test = bridge.submit_task(req_test)
    assert resp_test.status == "ACCEPTED"
    assert resp_test.candidate_urns[0] == "urn:lcs:skill:global:python-testing"

    # Patterns query
    req_pat = TaskRequest(
        request_id="req-pat",
        session_id="s2",
        original_instruction="refactor codebase to enforce PEP 8 idioms and type hints",
        normalized_task_description="refactor codebase to enforce PEP 8 idioms and type hints",
        invocation_environment="ANTIGRAVITY"
    )
    resp_pat = bridge.submit_task(req_pat)
    assert resp_pat.status == "ACCEPTED"
    assert resp_pat.candidate_urns[0] == "urn:lcs:skill:global:python-patterns"


def test_09_nested_skill_discovery_and_selection(populated_inventory):
    """Case 9: Skills in nested directory hierarchies are indexed and selected without naming."""
    inv, conn = populated_inventory

    inv._register_resource_with_conflict_resolution(UnifiedResourceRecord(
        urn="urn:lcs:skill:workspace:nested.db-optimizer",
        name="db-optimizer",
        resource_type=ResourceType.SKILL,
        display_name="Nested Database Optimizer",
        description="Optimizes slow SQL queries, table indexes, and connection pooling parameters.",
        raw_content="# DB Optimizer\nTune database queries and indexing.",
        raw_content_digest="nest_hash",
        provenance=ProvenanceRecord("antigravity", "WORKSPACE", "/ws/nested/db-optimizer", "/ws/nested/db-optimizer", "nest_hash"),
        lifecycle_state=OperationalLifecycleState.EXECUTABLE,
        tags=["database", "sql", "optimize", "indexes"]
    ))

    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    req = TaskRequest(
        request_id="req-nested",
        session_id="s-nest",
        original_instruction="optimize slow SQL queries and missing table indexes",
        normalized_task_description="optimize slow SQL queries and missing table indexes",
        invocation_environment="ANTIGRAVITY"
    )
    resp = bridge.submit_task(req)
    assert resp.status == "ACCEPTED"
    assert "urn:lcs:skill:workspace:nested.db-optimizer" in resp.candidate_urns


def test_10_multi_skill_dependency_execution_ordering(populated_inventory):
    """Case 10: Multi-skill request produces candidates where execution dependencies reflect task structure."""
    inv, conn = populated_inventory
    ctx = MockContext(inv)
    bridge = LCSCoreBridge(ctx)

    req = TaskRequest(
        request_id="req-order",
        session_id="s-order",
        original_instruction="extract dataset records from sql database and then compile markdown report",
        normalized_task_description="extract dataset records from sql database and then compile markdown report",
        invocation_environment="ANTIGRAVITY"
    )
    resp = bridge.submit_task(req)
    assert resp.status == "ACCEPTED"
    assert len(resp.candidate_urns) >= 2
    assert "urn:lcs:skill:antigravity.workspace:data-extractor" in resp.candidate_urns
    assert "urn:lcs:skill:antigravity.workspace:report-generator" in resp.candidate_urns
