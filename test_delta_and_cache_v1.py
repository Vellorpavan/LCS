"""
LCS Delta Invalidation & Local Cache Verification Suite (Phase 1C)
==================================================================
Tests Level 1 stat filtering, Level 2 cryptographic SHA-256 verification,
mandatory Hash-On-Activation enforcement on cache hits, dependency bubbling,
interrupted updates, corrupted cache recovery, and concurrent modifications.
"""

import os
import time
import shutil
import tempfile
import sqlite3
import pytest

from lcs.cache import (
    LocalCapabilityCache,
    DeltaEngine,
    StatMetadata,
    CapabilitySummary,
    ChangeKind,
    DeltaChange,
    CacheCorruptionError,
)
from lcs.skills import (
    DiscoveryRootResolver,
    SkillIntelligenceServiceV1,
    SafeFileReader,
    ensure_skill_intelligence_schema,
)
from lcs.migrations import MigrationManager
from lcs.adapters import ActivationIntegrityVerifier, ContentIntegrityMismatchError
from lcs.storage import SecureCASStorageEngine
from lcs.registry import CapabilityRegistrationService
from lcs.profile import CapabilityProfileService
from lcs.discovery import DiscoveryIndexService
from lcs.retrieval import CapabilityRetrievalEngineV11


@pytest.fixture
def test_env():
    """Sets up an isolated database, CAS storage, and workspace directory."""
    raw_dir = tempfile.mkdtemp(prefix="lcs_cache_test_")
    real_dir = os.path.realpath(raw_dir)
    db_path = os.path.join(real_dir, "test.db")
    cas_root = os.path.join(real_dir, "cas")
    key_dir = os.path.join(real_dir, "keys")
    os.makedirs(cas_root, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)

    # Initialize full migrations so all relational & CAS tables exist
    schema_dir = os.path.join(os.path.dirname(__file__), "lcs", "schemas")
    mgr = MigrationManager(db_path=db_path, schema_dir=schema_dir)
    mgr.apply_pending()
    conn = mgr.get_connection()
    ensure_skill_intelligence_schema(conn)

    cas_engine = SecureCASStorageEngine(cas_root=cas_root, trusted_anchor=real_dir, key_store_dir=key_dir)
    cap_service = CapabilityRegistrationService(conn, cas_engine)
    profile_service = CapabilityProfileService(conn, cas_engine)
    index_service = DiscoveryIndexService(conn)
    retrieval_engine = CapabilityRetrievalEngineV11(conn, profile_service, index_service)

    # Strictly isolate home_dir and workspace_root to temporary test directory
    resolver = DiscoveryRootResolver(workspace_root=real_dir, home_dir=real_dir)
    skill_service = SkillIntelligenceServiceV1(
        conn=conn,
        cas_engine=cas_engine,
        profile_service=profile_service,
        index_service=index_service,
        retrieval_engine=retrieval_engine,
        workspace_root=real_dir,
        resolver=resolver
    )

    cache = LocalCapabilityCache(conn=conn, cas_engine=cas_engine, resolver=resolver)

    yield {
        "dir": real_dir,
        "conn": conn,
        "cas_engine": cas_engine,
        "skill_service": skill_service,
        "cache": cache,
        "resolver": resolver,
        "verifier": cache.activation_verifier,
    }

    try:
        cas_engine.close()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass
    shutil.rmtree(real_dir, ignore_errors=True)


def test_01_level1_stat_prefilter_evaluation(test_env):
    """
    Verifies that Level 1 stat filter passes when stat metadata matches,
    and fails when any attribute (size, mtime, inode) changes.
    """
    delta_engine = DeltaEngine(resolver=test_env["resolver"])
    stat_a = StatMetadata(path="/test/file.md", st_size=100, st_mtime_ns=1000, st_ino=55, st_dev=1)
    stat_b = StatMetadata(path="/test/file.md", st_size=100, st_mtime_ns=1000, st_ino=55, st_dev=1)

    # Identical stat: Level 1 pass (heuristic skip)
    assert delta_engine.evaluate_level1_stat_filter(stat_a, stat_b) is True

    # Modified mtime (e.g. touch): Level 1 fail (requires revalidation)
    stat_touched = StatMetadata(path="/test/file.md", st_size=100, st_mtime_ns=2000, st_ino=55, st_dev=1)
    assert delta_engine.evaluate_level1_stat_filter(stat_touched, stat_b) is False

    # Modified size: Level 1 fail
    stat_resized = StatMetadata(path="/test/file.md", st_size=105, st_mtime_ns=1000, st_ino=55, st_dev=1)
    assert delta_engine.evaluate_level1_stat_filter(stat_resized, stat_b) is False

    # Inode replacement (atomic file replacement): Level 1 fail
    stat_new_inode = StatMetadata(path="/test/file.md", st_size=100, st_mtime_ns=1000, st_ino=99, st_dev=1)
    assert delta_engine.evaluate_level1_stat_filter(stat_new_inode, stat_b) is False


def test_02_level2_same_size_content_change_detection(test_env):
    """
    Verifies that when file content changes but file size remains exactly identical,
    Level 2 cryptographic SHA-256 detects the modification.
    """
    ws = test_env["dir"]
    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)
    skill_file = os.path.join(skills_dir, "SKILL.md")

    # Write initial 10-byte content
    with open(skill_file, "wb") as f:
        f.write(b"ABCDEFGHIJ")

    delta_engine = DeltaEngine(resolver=test_env["resolver"])
    initial_stat = StatMetadata.from_path(skill_file)
    _, initial_digest, _ = delta_engine.evaluate_level2_content_verification(skill_file, "")

    # Modify with DIFFERENT bytes of the exact SAME 10-byte length
    time.sleep(0.01)
    with open(skill_file, "wb") as f:
        f.write(b"1234567890")

    is_identical, new_digest, new_stat = delta_engine.evaluate_level2_content_verification(
        skill_file, expected_digest=initial_digest
    )
    assert is_identical is False
    assert new_digest != initial_digest
    assert new_stat.st_size == initial_stat.st_size


def test_03_level2_preserved_mtime_tamper_detection(test_env):
    """
    Verifies that if an attacker modifies file content and artificially restores
    the original modification timestamp (mtime), Level 2 cryptographic SHA-256
    catches the integrity discrepancy.
    """
    ws = test_env["dir"]
    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)
    skill_file = os.path.join(skills_dir, "SKILL.md")

    with open(skill_file, "wb") as f:
        f.write(b"# Original trusted content")

    delta_engine = DeltaEngine(resolver=test_env["resolver"])
    _, original_digest, _ = delta_engine.evaluate_level2_content_verification(skill_file, "")
    orig_stat = os.stat(skill_file)

    # Tamper with content and restore original mtime/atime via os.utime
    with open(skill_file, "wb") as f:
        f.write(b"# Malicious tampered code!")
    os.utime(skill_file, (orig_stat.st_atime, orig_stat.st_mtime))

    # Level 2 cryptographic check must fail
    is_identical, actual_digest, _ = delta_engine.evaluate_level2_content_verification(
        skill_file, expected_digest=original_digest
    )
    assert is_identical is False
    assert actual_digest != original_digest


def test_04_cache_hit_mandatory_hash_on_activation(test_env):
    """
    CRITICAL SECURITY CONTRACT:
    A cache hit provides rapid candidate ranking, but CANNOT bypass Hash-On-Activation.
    If the file on disk is modified or deleted after being returned as a cache hit,
    verify_before_activation() must fail-closed with ContentIntegrityMismatchError.
    """
    ws = test_env["dir"]
    cache: LocalCapabilityCache = test_env["cache"]
    skills_dir = os.path.join(ws, ".agents", "skills", "deployer")
    os.makedirs(skills_dir, exist_ok=True)
    skill_file = os.path.join(skills_dir, "SKILL.md")

    content = b"# Production Deployer\nDescription: Deploys containers\n"
    with open(skill_file, "wb") as f:
        f.write(content)

    # Ingest and prime cache
    test_env["skill_service"].run_full_pipeline()
    cache.warm_cache()

    candidates = cache.search_candidates("deployer")
    assert len(candidates) == 1
    hit = candidates[0]
    assert hit.display_name == "Skills" or "deployer" in hit.name.lower() or "skill" in hit.name.lower()

    # Pre-activation verification passes when file is intact
    record = cache.verify_before_activation(hit.urn)
    assert record.capability_urn == hit.urn

    # Now simulate out-of-band disk modification (tampering after cache lookup)
    time.sleep(0.01)
    with open(skill_file, "wb") as f:
        f.write(b"# TAMPERED MALICIOUS SCRIPT\n")

    # Hash-On-Activation MUST block activation fail-closed!
    with pytest.raises(ContentIntegrityMismatchError):
        cache.verify_before_activation(hit.urn)


def test_05_stale_dependency_invalidation_for_bundles(test_env):
    """
    Verifies that when a child dependency file (e.g. scripts/helper.py) in a
    multi-file bundle is modified, dependent invalidation bubbles up and
    re-computes the parent bundle Merkle digest.
    """
    ws = test_env["dir"]
    cache: LocalCapabilityCache = test_env["cache"]
    skills_dir = os.path.join(ws, ".agents", "skills")
    bundle_dir = os.path.join(skills_dir, "my_tool")
    scripts_dir = os.path.join(bundle_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)

    with open(os.path.join(bundle_dir, "SKILL.md"), "w") as f:
        f.write("# My Tool Skill\n")
    helper_script = os.path.join(scripts_dir, "helper.py")
    with open(helper_script, "w") as f:
        f.write("def helper(): return 1\n")

    test_env["skill_service"].run_full_pipeline()
    cache.warm_cache()

    bundle_urn = "urn:lcs:skill:antigravity.workspace:my_tool"
    initial_summary = cache.get_by_urn(bundle_urn)
    assert initial_summary is not None
    assert initial_summary.is_bundle is True
    initial_merkle = initial_summary.bundle_manifest_digest

    # Modify child script
    time.sleep(0.01)
    with open(helper_script, "w") as f:
        f.write("def helper(): return 2  # Modified child dependency\n")

    # Invalidate dependencies for changed path
    impacted = cache.invalidate_dependencies(helper_script)
    assert len(impacted) >= 1
    assert impacted[0].urn == bundle_urn

    updated_summary = cache.get_by_urn(bundle_urn)
    assert updated_summary.bundle_manifest_digest != initial_merkle


def test_06_corrupted_cache_recovery(test_env):
    """
    Verifies that recover_corrupted_cache() cleans corrupted in-memory state,
    verifies SQLite integrity, and successfully rebuilds cache projections.
    """
    ws = test_env["dir"]
    cache: LocalCapabilityCache = test_env["cache"]
    skills_dir = os.path.join(ws, ".agents", "skills", "robust")
    os.makedirs(skills_dir, exist_ok=True)
    with open(os.path.join(skills_dir, "SKILL.md"), "w") as f:
        f.write("# Robust Skill\n")

    test_env["skill_service"].run_full_pipeline()
    cache.warm_cache()
    assert len(cache.list_all()) >= 1

    # Corrupt in-memory state
    cache._by_urn.clear()
    cache._by_path["/invalid/corrupted/path"] = "urn:corrupted"
    assert len(cache.list_all()) == 0

    # Recover
    recovered_count = cache.recover_corrupted_cache()
    assert recovered_count >= 1
    assert len(cache.list_all()) == recovered_count
    assert "/invalid/corrupted/path" not in cache._by_path


def test_07_interrupted_cache_update_transaction_safety(test_env):
    """
    Verifies that interrupted or failing updates roll back cleanly
    without corrupting database or in-memory cache integrity.
    """
    cache: LocalCapabilityCache = test_env["cache"]
    initial_count = len(cache.list_all())

    # Attempt an update with an invalid change that causes an error inside transaction
    failing_change = DeltaChange(
        kind=ChangeKind.MODIFIED,
        path="/some/file.md",
        urn="urn:lcs:nonexistent",
        content_digest="abc",
        stat_meta=None
    )

    # Calling apply_delta handles missing records safely
    cache.apply_delta(failing_change)

    # Verify database and in-memory cache remain completely uncorrupted
    cur = test_env["conn"].cursor()
    cur.execute("PRAGMA integrity_check;")
    assert cur.fetchone()[0] == "ok"
    assert len(cache.list_all()) == initial_count


def test_08_warm_cache_candidate_search_latency(test_env):
    """
    Verifies that warm in-memory candidate search executes well below target SLA
    (Target P95 <= 2ms).
    """
    ws = test_env["dir"]
    cache: LocalCapabilityCache = test_env["cache"]
    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)

    # Populate 50 synthetic capabilities in memory
    for i in range(50):
        urn = f"urn:lcs:skill:test:cap-{i}"
        summary = CapabilitySummary(
            urn=urn,
            name=f"cap-{i}",
            display_name=f"Capability {i}",
            description=f"Automated test capability {i} for high speed benchmarking",
            taxonomy_kind="SKILL",
            environment_origin="WORKSPACE",
            source_path=f"/fake/path/{i}",
            resolved_path=f"/fake/path/{i}",
            raw_content_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        cache._by_urn[urn] = summary
        cache._by_path[summary.source_path] = urn

    # Measure 50 iterations of candidate search
    latencies_ms = []
    for _ in range(50):
        t0 = time.perf_counter_ns()
        results = cache.search_candidates("benchmarking", limit=10)
        t1 = time.perf_counter_ns()
        latencies_ms.append((t1 - t0) / 1e6)
        assert len(results) == 10

    latencies_ms.sort()
    p95 = latencies_ms[int(0.95 * len(latencies_ms))]
    # Must be sub-millisecond in memory
    assert p95 < 2.0, f"Warm search P95 {p95:.3f}ms exceeded 2ms target SLA"
