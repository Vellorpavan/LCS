"""
LCS Phase 1C Real Pipeline Integration Test Suite
=================================================
Verifies real production-path integration across LCSContext, LocalCapabilityCache,
FilesystemWatcher, SkillIntelligenceServiceV1, ActivationIntegrityVerifier,
and ExecutionGovernanceEngineV1 without mocks.
"""

import os
import time
import shutil
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.cache import ChangeKind
from lcs.adapters import ContentIntegrityMismatchError
from lcs.governance import GovernanceError


@pytest.fixture
def real_lcs_context():
    """Sets up a real LCSContext in an isolated real temporary directory."""
    raw_dir = tempfile.mkdtemp(prefix="lcs_real_pipe_")
    real_dir = os.path.realpath(raw_dir)

    cfg = LCSConfig.resolve(root_override=real_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)

    # Strictly isolate discovery roots to test directory
    ctx.skill_service.resolver.user_home = real_dir
    ctx.skill_service.resolver.workspace_root = real_dir
    ctx.skill_service.set_resolver(ctx.skill_service.resolver)
    ctx.cache.resolver = ctx.skill_service.resolver
    ctx.cache.delta_engine.resolver = ctx.skill_service.resolver
    ctx.fs_watcher.resolver = ctx.skill_service.resolver

    yield ctx, real_dir

    ctx.close()
    shutil.rmtree(real_dir, ignore_errors=True)


def test_01_real_pipeline_initial_and_repeated_discovery(real_lcs_context):
    """
    Verifies that initial discovery populates cache into memory and SQLite,
    and repeated discovery executes via Level 1 stat pass with 0ms I/O.
    """
    ctx, ws = real_lcs_context
    skills_dir = os.path.join(ws, ".agents", "skills", "alpha")
    os.makedirs(skills_dir, exist_ok=True)
    skill_file = os.path.join(skills_dir, "SKILL.md")

    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# Alpha Skill\nDescription: Automated alpha worker\n")

    # 1. Initial discovery
    records = ctx.skill_service.run_full_pipeline()
    assert len(records) >= 1
    ctx.cache.warm_cache()

    alpha_urn = "urn:lcs:skill:antigravity.workspace:alpha"
    summary = ctx.cache.get_by_urn(alpha_urn)
    assert summary is not None
    assert summary.name == "alpha"
    assert summary.lifecycle_state == "AVAILABLE"
    initial_digest = summary.raw_content_digest

    # 2. Repeated discovery (0 changes)
    t0 = time.perf_counter_ns()
    ctx.cache.sync_incremental(ctx.skill_service)
    t1 = time.perf_counter_ns()
    duration_ms = (t1 - t0) / 1e6

    # Verify state unchanged and fast
    updated = ctx.cache.get_by_urn(alpha_urn)
    assert updated.raw_content_digest == initial_digest
    assert duration_ms < 50.0  # Level 1 fast pass


def test_02_real_pipeline_modification_invalidation(real_lcs_context):
    """
    Verifies that modifying file content triggers Level 2 SHA-256 calculation,
    updates CAS storage, and invalidates old digests in cache and catalog.
    """
    ctx, ws = real_lcs_context
    skills_dir = os.path.join(ws, ".agents", "skills", "alpha")
    os.makedirs(skills_dir, exist_ok=True)
    skill_file = os.path.join(skills_dir, "SKILL.md")

    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# Alpha Skill V1\n")

    ctx.skill_service.run_full_pipeline()
    ctx.cache.warm_cache()
    alpha_urn = "urn:lcs:skill:antigravity.workspace:alpha"
    v1_digest = ctx.cache.get_by_urn(alpha_urn).raw_content_digest

    # Modify file content on disk
    time.sleep(0.01)
    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# Alpha Skill V2 with New Capabilities\n")

    # Incremental sync detects modification
    ctx.cache.sync_incremental(ctx.skill_service)
    v2_summary = ctx.cache.get_by_urn(alpha_urn)
    assert v2_summary.raw_content_digest != v1_digest

    # Verify new CAS blob exists
    assert ctx.cas_engine.blob_exists(v2_summary.raw_content_digest) is True


def test_03_real_pipeline_addition_and_deletion(real_lcs_context):
    """
    Verifies that additions become discoverable and deletions remove stale
    capabilities from both in-memory cache and FTS5 search index.
    """
    ctx, ws = real_lcs_context
    beta_dir = os.path.join(ws, ".agents", "skills", "beta")
    os.makedirs(beta_dir, exist_ok=True)
    beta_file = os.path.join(beta_dir, "SKILL.md")

    # 1. Addition
    with open(beta_file, "w", encoding="utf-8") as f:
        f.write("# Beta Skill\nDescription: Beta worker\n")

    ctx.cache.sync_incremental(ctx.skill_service)
    beta_urn = "urn:lcs:skill:antigravity.workspace:beta"
    assert ctx.cache.get_by_urn(beta_urn) is not None

    # Search finds beta
    hits = ctx.cache.search_candidates("beta")
    assert any(h.urn == beta_urn for h in hits)

    # 2. Deletion
    os.remove(beta_file)
    os.rmdir(beta_dir)
    ctx.cache.sync_incremental(ctx.skill_service)

    # Beta evicted from memory cache
    assert ctx.cache.get_by_urn(beta_urn) is None
    hits_after = ctx.cache.search_candidates("beta")
    assert not any(h.urn == beta_urn for h in hits_after)


def test_04_real_pipeline_missed_watcher_event_and_reconciliation(real_lcs_context):
    """
    Verifies that events missed while watcher is offline are recovered
    cleanly by reconciliation without permanently desynchronizing cache.
    """
    ctx, ws = real_lcs_context
    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)

    watcher = ctx.fs_watcher
    watcher.add_root(skills_dir)
    watcher.start()
    time.sleep(0.05)
    watcher.drain_events()
    watcher.stop()

    # Add file while watcher is offline
    gamma_dir = os.path.join(skills_dir, "gamma")
    os.makedirs(gamma_dir, exist_ok=True)
    gamma_file = os.path.join(gamma_dir, "SKILL.md")
    with open(gamma_file, "w", encoding="utf-8") as f:
        f.write("# Gamma Offline Skill\n")

    # Reconcile heals the state
    reconciled = watcher.reconcile_now()
    reconciled_paths = [r.path for r in reconciled]
    assert gamma_file in reconciled_paths

    # Restart watcher and sync cache
    watcher.start()
    ctx.cache.sync_incremental(ctx.skill_service, watcher=watcher)
    gamma_urn = "urn:lcs:skill:antigravity.workspace:gamma"
    assert ctx.cache.get_by_urn(gamma_urn) is not None
    watcher.stop()


def test_05_real_pipeline_hash_on_activation_and_governance(real_lcs_context):
    """
    Verifies that:
    1. A cache hit CANNOT bypass Hash-On-Activation if disk content is tampered.
    2. ExecutionEngine enforces governance authorization before execution.
    """
    ctx, ws = real_lcs_context
    skills_dir = os.path.join(ws, ".agents", "skills", "alpha")
    os.makedirs(skills_dir, exist_ok=True)
    skill_file = os.path.join(skills_dir, "SKILL.md")

    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# Alpha Secure Skill\n")

    ctx.skill_service.run_full_pipeline()
    ctx.cache.warm_cache()
    alpha_urn = "urn:lcs:skill:antigravity.workspace:alpha"

    # Verify intact activation
    rec = ctx.cache.verify_before_activation(alpha_urn)
    assert rec.capability_urn == alpha_urn

    # Tamper with file on disk
    time.sleep(0.01)
    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# MALICIOUS TAMPERING OCCURRED\n")

    # Hash-On-Activation MUST reject execution fail-closed
    with pytest.raises(ContentIntegrityMismatchError):
        ctx.cache.verify_before_activation(alpha_urn)

    # Governance check: dispatch without authorized permit fails fail-closed
    with pytest.raises(Exception):
        ctx.execution_engine.execute_plan(
            plan={"plan_urn": "urn:lcs:plan:unauthorized"},
            permit_token=None
        )
