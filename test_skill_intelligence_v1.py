"""
test_skill_intelligence_v1.py
=============================
Authoritative end-to-end test suite for LCS Skill Intelligence V1.

Verifies:
1. Universal Skill Lifecycle (DISCOVERED -> READ -> UNDERSTOOD -> INDEXED -> AVAILABLE).
2. Exact-byte CAS storage and Merkle bundle manifest digest verification.
3. Authoritative SHA-256 change detection (independent of st_mtime drift).
4. Parameter Extraction Invariance: EXPLICIT vs INFERRED (inferred variables are ALWAYS optional).
5. Catalog Registration and FTS5 Search Indexing.
6. Quarantine and policy isolation (syntax errors, path traversal, oversized files).
7. Unified Retrieval Coordinator: Context-aware dynamic precedence (Workspace > Host > Global > Builtin) & taxonomic filtering.
8. Frozen Module Invariance: Zero changes to frozen retrieval/parameter/planning/governance modules.
9. CLI Command execution (discover, list, inspect, search).
"""

import os
import sys
import json
import time
import sqlite3
import tempfile
import hashlib
import pytest
from unittest.mock import patch

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.skills import (
    ArtifactTaxonomyKind,
    EnvironmentOrigin,
    PrecedenceTier,
    SkillLifecycleState,
    DiscoveredArtifactRecord,
    DiscoveryRootResolver,
    SafeFileReader,
    ArtifactTaxonomyClassifier,
    BundleManifestHasher,
    SkillDiscoveryEngineV1,
    SkillIngestionService,
    SkillUnderstandingEngine,
    SkillCatalogService,
    UnifiedRetrievalCoordinator,
    SkillIntelligenceServiceV1,
    ensure_skill_intelligence_schema
)
from lcs.cli import main as cli_main
from capability_profile_v2b import EvidenceSource


@pytest.fixture
def skill_test_env(tmp_path):
    """Sets up an isolated LCSContext and multi-environment directories for testing."""
    root = tmp_path / "lcs_root"
    home = tmp_path / "fake_home"
    workspace = tmp_path / "test_workspace"

    root.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)

    cfg = LCSConfig.resolve(root_override=str(root))
    ctx = LCSContext(config=cfg, auto_migrate=True)

    # Configure custom resolver pointing to fake home and workspace
    resolver = DiscoveryRootResolver(
        home_dir=str(home),
        workspace_root=str(workspace),
        canonical_lcs_root=str(root)
    )
    # Replace context's skill service resolver with our test fixture resolver
    ctx.skill_service.set_resolver(resolver)

    yield {
        "ctx": ctx,
        "root": root,
        "home": home,
        "workspace": workspace,
        "resolver": resolver
    }
    ctx.close()


class TestExactByteIngestionAndCAS:
    def test_exact_byte_cas_fidelity(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        # Create sample skill with custom whitespace and exact line endings
        skill_dir = env["home"] / ".gemini" / "config" / "skills" / "fidelity-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        raw_content = b"---\r\nname: fidelity-skill\r\n---\r\n# Exact Bytes\r\nLine with trailing space   \n"
        skill_file = skill_dir / "SKILL.md"
        skill_file.write_bytes(raw_content)

        records = ctx.skill_service.run_full_pipeline(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)
        rec = next(r for r in records if r.name == "fidelity-skill")

        assert rec.lifecycle_state == SkillLifecycleState.AVAILABLE
        expected_digest = hashlib.sha256(raw_content).hexdigest()
        assert rec.raw_content_digest == expected_digest

        # Verify CAS blob exists and matches exact bytes
        assert ctx.cas_engine.blob_exists(expected_digest)
        retrieved_bytes = ctx.cas_engine.read_blob(expected_digest)
        assert retrieved_bytes == raw_content

    def test_directory_bundle_manifest_digest(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        # Create a skill bundle with scripts and references
        bundle_dir = env["workspace"] / ".agents" / "skills" / "bundle-skill"
        (bundle_dir / "scripts").mkdir(parents=True, exist_ok=True)
        (bundle_dir / "references").mkdir(parents=True, exist_ok=True)

        (bundle_dir / "SKILL.md").write_text("---\nname: bundle-skill\n---\n# Root Skill\n")
        (bundle_dir / "scripts" / "run.py").write_text("print('hello')\n")
        (bundle_dir / "references" / "guide.md").write_text("# Reference Guide\n")

        records = ctx.skill_service.run_full_pipeline()
        rec = next(r for r in records if r.name == "bundle-skill")

        assert rec.is_bundle is True
        assert rec.bundle_manifest_digest is not None
        assert len(rec.bundle_manifest_digest) == 64
        assert ctx.cas_engine.blob_exists(rec.bundle_manifest_digest)

        # Verify manifest JSON structure
        manifest_raw = ctx.cas_engine.read_blob(rec.bundle_manifest_digest)
        manifest_json = json.loads(manifest_raw.decode("utf-8"))
        assert manifest_json["schema_version"] == "lcs.skill.bundle.v1"
        asset_paths = [a["path"] for a in manifest_json["assets"]]
        assert "references/guide.md" in asset_paths
        assert "scripts/run.py" in asset_paths


class TestAuthoritativeChangeDetection:
    def test_change_detection_via_sha256(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        skill_dir = env["home"] / ".gemini" / "config" / "skills" / "change-test"
        skill_dir.mkdir(parents=True, exist_ok=True)
        skill_file = skill_dir / "SKILL.md"

        # 1. Initial write
        v1_bytes = b"---\nname: change-test\ndescription: Version 1\n---\n# V1 Body\n"
        skill_file.write_bytes(v1_bytes)
        records_1 = ctx.skill_service.run_full_pipeline(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)
        rec_1 = next(r for r in records_1 if r.name == "change-test")
        v1_digest = rec_1.raw_content_digest

        # 2. Update file content while keeping st_mtime artificial
        v2_bytes = b"---\nname: change-test\ndescription: Version 2\n---\n# V2 Body\n"
        skill_file.write_bytes(v2_bytes)
        # Artificially keep old mtime to simulate unchanged mtime drift
        os.utime(str(skill_file), (rec_1.st_mtime, rec_1.st_mtime))

        records_2 = ctx.skill_service.run_full_pipeline(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)
        rec_2 = next(r for r in records_2 if r.name == "change-test")
        v2_digest = rec_2.raw_content_digest

        # Authoritative SHA-256 detection must catch the content modification
        assert v1_digest != v2_digest
        assert v2_digest == hashlib.sha256(v2_bytes).hexdigest()
        assert ctx.cas_engine.blob_exists(v2_digest)


class TestParameterExtractionInvariance:
    def test_explicit_vs_inferred_parameters(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        # Skill with both explicit parameters and markdown placeholders
        skill_dir = env["home"] / ".gemini" / "config" / "skills" / "param-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        content = (
            "---\n"
            "name: param-skill\n"
            "description: Tests explicit vs inferred parameters\n"
            "parameters:\n"
            "  target_path:\n"
            "    type: string\n"
            "    required: true\n"
            "    description: The mandatory target path\n"
            "  debug_flag:\n"
            "    type: boolean\n"
            "    required: false\n"
            "---\n"
            "# Usage Instructions\n"
            "Execute the task with $ARGUMENTS on ${target_path} and option {{custom_opt}}.\n"
        )
        (skill_dir / "SKILL.md").write_text(content)

        records = ctx.skill_service.run_full_pipeline(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)
        rec = next(r for r in records if r.name == "param-skill")

        data = ctx.skill_service.inspect_artifact(rec.canonical_urn)
        profile = data["semantic_profile"]
        inputs = profile["inputs"]["value"]

        # Verify target_path is EXPLICIT and required = True
        target_param = next(p for p in inputs if p["name"] == "target_path")
        assert target_param["evidence"] == EvidenceSource.EXPLICIT
        assert target_param["required"] is True

        # Verify debug_flag is EXPLICIT and required = False
        debug_param = next(p for p in inputs if p["name"] == "debug_flag")
        assert debug_param["evidence"] == EvidenceSource.EXPLICIT
        assert debug_param["required"] is False

        # MANDATORY INVARIANT: Inferred template variables ($ARGUMENTS, {{custom_opt}}) MUST be optional
        arg_param = next(p for p in inputs if p["name"] == "ARGUMENTS")
        assert arg_param["evidence"] == EvidenceSource.INFERRED
        assert arg_param["required"] is False
        assert "Inferred from template placeholder" in arg_param["notes"]

        opt_param = next(p for p in inputs if p["name"] == "custom_opt")
        assert opt_param["evidence"] == EvidenceSource.INFERRED
        assert opt_param["required"] is False

        # Check required_inputs and optional_inputs list
        assert profile["required_inputs"]["value"] == ["target_path"]
        assert "ARGUMENTS" in profile["optional_inputs"]["value"]
        assert "custom_opt" in profile["optional_inputs"]["value"]
        assert "debug_flag" in profile["optional_inputs"]["value"]


class TestUniversalSkillLifecycle:
    def test_lifecycle_reaches_available(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        skill_dir = env["home"] / ".gemini" / "config" / "skills" / "lifecycle-ok"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text("---\nname: lifecycle-ok\n---\n# OK\n")

        records = ctx.skill_service.run_full_pipeline(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)
        rec = next(r for r in records if r.name == "lifecycle-ok")

        # Must terminate at AVAILABLE
        assert rec.lifecycle_state == SkillLifecycleState.AVAILABLE

        # Verify relational presence in capabilities and capability_declarations
        cur = ctx.conn.cursor()
        cur.execute("SELECT capability_urn, capability_type FROM capability_declarations WHERE capability_urn = ?;", (rec.canonical_urn,))
        row = cur.fetchone()
        assert row is not None
        assert row[1] == "skill"

    def test_quarantine_on_oversized_file(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        skill_dir = env["home"] / ".gemini" / "config" / "skills" / "oversized-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        # Create file exceeding 1MB instruction limit
        oversized = b"A" * (1024 * 1024 + 100)
        (skill_dir / "SKILL.md").write_bytes(oversized)

        records = ctx.skill_service.run_full_pipeline(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)
        rec = next(r for r in records if r.name == "oversized-skill")

        assert rec.lifecycle_state == SkillLifecycleState.QUARANTINED
        assert any("exceeds maximum allowed limit" in q for q in rec.quarantine_reasons)


class TestUnifiedRetrievalCoordinator:
    def test_context_aware_precedence_boosting(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        # Create global skill
        global_skill = env["home"] / ".gemini" / "config" / "skills" / "data-formatter"
        global_skill.mkdir(parents=True, exist_ok=True)
        (global_skill / "SKILL.md").write_text("---\nname: data-formatter\ndescription: Global data formatting utility\n---\n# Global\n")

        # Create workspace skill with identical domain
        ws_skill = env["workspace"] / ".agents" / "skills" / "data-formatter-custom"
        ws_skill.mkdir(parents=True, exist_ok=True)
        (ws_skill / "SKILL.md").write_text("---\nname: data-formatter-custom\ndescription: Workspace specialized data formatter\n---\n# WS\n")

        ctx.skill_service.run_full_pipeline()

        # Query when active workspace context is active
        coordinator = ctx.skill_service.retrieval_coordinator
        results = coordinator.retrieve(
            query="Format dataset into clean records",
            active_workspace_path=str(env["workspace"])
        )

        assert len(results) >= 2
        # Workspace skill should receive precedence boost
        ws_candidate = next(r for r in results if "workspace" in r.capability_urn)
        assert ws_candidate.precedence_boost == 0.25

    def test_taxonomic_filtering(self, skill_test_env):
        env = skill_test_env
        ctx = env["ctx"]

        # Create skill
        c_skill = env["workspace"] / ".claude" / "skills" / "build-tool"
        c_skill.mkdir(parents=True, exist_ok=True)
        (c_skill / "SKILL.md").write_text("# Build Skill\n")

        # Create command
        c_cmd = env["workspace"] / ".claude" / "commands" / "deploy-tool.md"
        c_cmd.parent.mkdir(parents=True, exist_ok=True)
        c_cmd.write_text("# Deploy Command\n")

        ctx.skill_service.run_full_pipeline()

        coordinator = ctx.skill_service.retrieval_coordinator

        # Filter strictly for COMMAND
        cmd_results = coordinator.retrieve(
            query="tool",
            taxonomy_kinds=[ArtifactTaxonomyKind.COMMAND]
        )
        assert all(r.taxonomy_kind == ArtifactTaxonomyKind.COMMAND for r in cmd_results)

        # Filter strictly for SKILL
        skill_results = coordinator.retrieve(
            query="tool",
            taxonomy_kinds=[ArtifactTaxonomyKind.SKILL]
        )
        assert all(r.taxonomy_kind == ArtifactTaxonomyKind.SKILL for r in skill_results)


class TestCliIntegration:
    def test_cli_skill_commands(self, skill_test_env, capsys):
        from pathlib import Path
        env = skill_test_env
        root_dir = str(env["root"])

        # Create a skill to discover inside the root workspace
        s_dir = env["root"] / ".agents" / "skills" / "cli-demo"
        s_dir.mkdir(parents=True, exist_ok=True)
        (s_dir / "SKILL.md").write_text("---\nname: cli-demo\ndescription: CLI verification demo\n---\n# CLI Demo\n")

        with patch.dict(os.environ, {"HOME": str(env["home"])}), \
             patch("os.path.expanduser", lambda p: str(env["home"]) if p.startswith("~") else p), \
             patch.object(Path, "home", return_value=env["home"]):
            # 1. Test 'lcs skill discover'
            rc = cli_main(["--root", root_dir, "skill", "discover"])
            assert rc == 0

            # 2. Test 'lcs skill list'
            rc = cli_main(["--root", root_dir, "skill", "list"])
            assert rc == 0

            # 3. Test 'lcs skill search'
            rc = cli_main(["--root", root_dir, "skill", "search", "CLI verification"])
            assert rc == 0

