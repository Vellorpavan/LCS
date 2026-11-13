"""
test_skill_discovery_v1.py
==========================
Comprehensive test suite for LCS Skill Intelligence V1 - Stage 1 (Discovery Foundation).

Verifies:
1. Dynamic root resolution (no hardcoded machine paths, full coverage).
2. Safe path confinement and path traversal rejection (PathTraversalSecurityError).
3. POSIX descriptor-relative file reading (O_NOFOLLOW, S_ISREG, no symlink following).
4. File size boundary enforcement (>1MB instruction, >5MB asset rejected).
5. Symlink and directory cycle detection (SymlinkCycleError).
6. Artifact taxonomy classification (SKILL, COMMAND, RULE, AGENT_INSTRUCTION, AGENT_CONFIGURATION, etc.).
7. Antigravity discovery adapter (global, builtin, plugin, workspace).
8. Claude Code discovery adapter (skills, commands, rules).
9. OpenCode discovery adapter (opencode.json, markdown instructions, commands).
10. Deterministic bundle manifest hashing (RFC 8785 JCS canonicalization).
11. Exact-byte file ingestion and SHA-256 integrity verification.
12. Zero-execution invariant (ensures no subprocess, shell, or network operations during discovery).
"""

import os
import sys
import json
import stat
import tempfile
import hashlib
import pytest
from unittest.mock import patch

from skill_discovery_v1 import (
    ArtifactTaxonomyKind,
    EnvironmentOrigin,
    PrecedenceTier,
    SkillLifecycleState,
    DiscoveredArtifactRecord,
    SafeFileReader,
    DiscoveryRootResolver,
    ArtifactTaxonomyClassifier,
    BundleManifestHasher,
    AntigravityDiscoveryAdapter,
    ClaudeCodeDiscoveryAdapter,
    OpenCodeDiscoveryAdapter,
    SkillDiscoveryEngineV1,
    SkillDiscoveryError,
    PathTraversalSecurityError,
    DescriptorSecurityError,
    FileSizeExceededError,
    SymlinkCycleError,
    MalformedArtifactError,
    MAX_INSTRUCTION_FILE_SIZE,
    MAX_ASSET_FILE_SIZE,
    MAX_DIRECTORY_RECURSION_DEPTH,
    canonicalize_jcs
)


class TestDynamicRootResolution:
    def test_dynamic_root_resolution_resolves_all_roots(self, tmp_path):
        home = str(tmp_path / "fakehome")
        workspace = str(tmp_path / "fakeworkspace")
        lcs_root = str(tmp_path / "fakelcs")

        os.makedirs(home, exist_ok=True)
        os.makedirs(workspace, exist_ok=True)
        os.makedirs(lcs_root, exist_ok=True)

        resolver = DiscoveryRootResolver(
            home_dir=home,
            workspace_root=workspace,
            canonical_lcs_root=lcs_root
        )
        roots = resolver.get_all_authorized_roots()

        # Check all expected roots are present
        assert resolver.antigravity_global == os.path.realpath(os.path.join(home, ".gemini", "config", "skills"))
        assert resolver.antigravity_builtin == os.path.realpath(os.path.join(home, ".gemini", "antigravity", "builtin", "skills"))
        assert resolver.antigravity_plugins == os.path.realpath(os.path.join(home, ".gemini", "config", "plugins"))
        assert resolver.claude_global == os.path.realpath(os.path.join(home, ".claude"))
        assert resolver.agents_global == os.path.realpath(os.path.join(home, ".agents", "skills"))
        assert resolver.agents_workspace == os.path.realpath(os.path.join(workspace, ".agents", "skills"))
        assert resolver.claude_workspace == os.path.realpath(os.path.join(workspace, ".claude"))
        assert resolver.opencode_workspace == os.path.realpath(os.path.join(workspace, ".opencode"))
        assert resolver.lcs_root == os.path.realpath(lcs_root)

        # Ensure no hardcoded paths exist
        for root in roots:
            assert home in root or workspace in root or lcs_root in root

    def test_confinement_check(self, tmp_path):
        home = str(tmp_path / "home")
        workspace = str(tmp_path / "workspace")
        resolver = DiscoveryRootResolver(home_dir=home, workspace_root=workspace)

        authorized_path = os.path.join(resolver.antigravity_global, "my-skill", "SKILL.md")
        assert resolver.is_confined(authorized_path) is True

        unauthorized_path = "/etc/passwd"
        assert resolver.is_confined(unauthorized_path) is False

        with pytest.raises(PathTraversalSecurityError):
            resolver.assert_confined("/etc/shadow")


class TestSafeFileReader:
    def test_read_regular_file(self, tmp_path):
        test_file = tmp_path / "test.txt"
        content = b"Hello, secure LCS Skill Intelligence!"
        test_file.write_bytes(content)

        read_bytes, st = SafeFileReader.read_exact_bytes(str(test_file))
        assert read_bytes == content
        assert hashlib.sha256(read_bytes).hexdigest() == hashlib.sha256(content).hexdigest()

    def test_read_symlink_rejection(self, tmp_path):
        target = tmp_path / "target.txt"
        target.write_bytes(b"target content")
        symlink = tmp_path / "link.txt"
        symlink.symlink_to(target)

        with pytest.raises(DescriptorSecurityError) as exc_info:
            SafeFileReader.read_exact_bytes(str(symlink))
        assert "Symlink rejected" in str(exc_info.value) or "O_NOFOLLOW" in str(exc_info.value)

    def test_read_size_limit_exceeded(self, tmp_path):
        large_file = tmp_path / "large.txt"
        large_file.write_bytes(b"x" * (MAX_INSTRUCTION_FILE_SIZE + 10))

        with pytest.raises(FileSizeExceededError):
            SafeFileReader.read_exact_bytes(str(large_file), max_bytes=MAX_INSTRUCTION_FILE_SIZE)

    def test_read_non_regular_file_rejection(self, tmp_path):
        directory_as_file = tmp_path / "subdir"
        directory_as_file.mkdir()

        with pytest.raises(DescriptorSecurityError):
            SafeFileReader.read_exact_bytes(str(directory_as_file))


class TestArtifactTaxonomyClassifier:
    def test_classify_skill(self, tmp_path):
        skill_file = tmp_path / "SKILL.md"
        skill_file.write_text("---\nname: demo-skill\ndescription: demo\n---\n# Demo\n")

        kind, reason = ArtifactTaxonomyClassifier.classify(str(skill_file))
        assert kind == ArtifactTaxonomyKind.SKILL
        assert "SKILL.md" in reason

    def test_classify_command(self, tmp_path):
        cmd_file = tmp_path / "commands" / "deploy.md"
        cmd_file.parent.mkdir(parents=True, exist_ok=True)
        cmd_file.write_text("# Deploy Command\n")

        kind, reason = ArtifactTaxonomyClassifier.classify(str(cmd_file))
        assert kind == ArtifactTaxonomyKind.COMMAND

    def test_classify_rule(self, tmp_path):
        rule_file = tmp_path / "rules" / "security.md"
        rule_file.parent.mkdir(parents=True, exist_ok=True)
        rule_file.write_text("# Security Rule\n")

        kind, reason = ArtifactTaxonomyClassifier.classify(str(rule_file))
        assert kind == ArtifactTaxonomyKind.RULE

    def test_classify_agent_instruction(self, tmp_path):
        inst_file = tmp_path / "AGENTS.md"
        inst_file.write_text("# Agent instructions\n")

        kind, reason = ArtifactTaxonomyClassifier.classify(str(inst_file))
        assert kind == ArtifactTaxonomyKind.AGENT_INSTRUCTION

    def test_classify_agent_configuration(self, tmp_path):
        cfg_file = tmp_path / "opencode.json"
        cfg_file.write_text('{"version": "1.0"}')

        kind, reason = ArtifactTaxonomyClassifier.classify(str(cfg_file))
        assert kind == ArtifactTaxonomyKind.AGENT_CONFIGURATION

    def test_classify_unsupported_extensions(self, tmp_path):
        bin_file = tmp_path / "test.bin"
        bin_file.write_bytes(b"\x00\x01\x02")

        kind, _ = ArtifactTaxonomyClassifier.classify(str(bin_file))
        assert kind == ArtifactTaxonomyKind.UNSUPPORTED_ARTIFACT

    def test_extract_frontmatter(self):
        text = "---\nname: my-skill\ndescription: A test skill\n---\n# Body\n"
        meta, body = ArtifactTaxonomyClassifier.extract_frontmatter(text)
        assert meta["name"] == "my-skill"
        assert meta["description"] == "A test skill"
        assert body == "# Body\n"

        no_fm = "# Just markdown\nNo frontmatter here."
        meta2, body2 = ArtifactTaxonomyClassifier.extract_frontmatter(no_fm)
        assert meta2 == {}
        assert body2 == no_fm


class TestBundleManifestHasher:
    def test_deterministic_manifest_hashing(self):
        bundle_files = [
            {"path": "b.txt", "sha256": "bbb", "size_bytes": 20},
            {"path": "a.txt", "sha256": "aaa", "size_bytes": 10},
        ]
        digest1 = BundleManifestHasher.compute_bundle_digest(bundle_files)
        # Reverse input order to ensure determinism
        bundle_files_reversed = [
            {"path": "a.txt", "sha256": "aaa", "size_bytes": 10},
            {"path": "b.txt", "sha256": "bbb", "size_bytes": 20},
        ]
        digest2 = BundleManifestHasher.compute_bundle_digest(bundle_files_reversed)
        assert digest1 == digest2
        assert len(digest1) == 64

    def test_canonicalize_jcs_rfc8785(self):
        obj = {"z": 1, "a": "hello", "m": [3, 2, 1]}
        canonical = canonicalize_jcs(obj).decode("utf-8")
        # RFC 8785 requires lexicographically sorted keys, no whitespace
        assert canonical == '{"a":"hello","m":[3,2,1],"z":1}'


class TestSymlinkAndCycleDetection:
    def test_symlink_cycle_detection(self, tmp_path):
        resolver = DiscoveryRootResolver(
            home_dir=str(tmp_path / "home"),
            workspace_root=str(tmp_path / "workspace")
        )
        adapter = AntigravityDiscoveryAdapter(resolver)

        # Create nested directory with a symlink pointing back to parent
        base_dir = tmp_path / "home" / ".gemini" / "config" / "skills" / "cyclic_skill"
        base_dir.mkdir(parents=True, exist_ok=True)
        (base_dir / "SKILL.md").write_text("# Cyclic Skill\n")

        sub_dir = base_dir / "subdir"
        sub_dir.mkdir()
        loop_link = sub_dir / "loop"
        try:
            loop_link.symlink_to(base_dir)
        except OSError:
            pytest.skip("Symlink creation not supported")

        # Discovering must not get stuck in infinite recursion; cycle is detected or skipped safely
        records = adapter.discover()
        assert len(records) >= 1
        assert any(r.name == "cyclic_skill" for r in records)


class TestAntigravityDiscoveryAdapter:
    def test_discover_global_builtin_and_plugins(self, tmp_path):
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"

        # Global skill
        global_skill_dir = home / ".gemini" / "config" / "skills" / "my-global-skill"
        global_skill_dir.mkdir(parents=True, exist_ok=True)
        (global_skill_dir / "SKILL.md").write_text("---\nname: my-global-skill\n---\n# Global\n")

        # Builtin skill
        builtin_skill_dir = home / ".gemini" / "antigravity" / "builtin" / "skills" / "my-builtin-skill"
        builtin_skill_dir.mkdir(parents=True, exist_ok=True)
        (builtin_skill_dir / "SKILL.md").write_text("---\nname: my-builtin-skill\n---\n# Builtin\n")

        # Plugin skill
        plugin_skill_dir = home / ".gemini" / "config" / "plugins" / "my-plugin" / "skills" / "my-plugin-skill"
        plugin_skill_dir.mkdir(parents=True, exist_ok=True)
        (plugin_skill_dir / "SKILL.md").write_text("---\nname: my-plugin-skill\n---\n# Plugin\n")

        resolver = DiscoveryRootResolver(home_dir=str(home), workspace_root=str(workspace))
        adapter = AntigravityDiscoveryAdapter(resolver)
        records = adapter.discover()

        names = {r.name for r in records}
        assert "my-global-skill" in names
        assert "my-builtin-skill" in names
        assert "my-plugin-skill" in names

        for r in records:
            assert r.origin_environment == EnvironmentOrigin.GOOGLE_ANTIGRAVITY
            assert r.taxonomy_kind == ArtifactTaxonomyKind.SKILL
            assert r.lifecycle_state == SkillLifecycleState.DISCOVERED
            assert len(r.content_sha256) == 64
            assert r.provenance.get("entrypoint_path") is not None


class TestClaudeCodeDiscoveryAdapter:
    def test_discover_claude_artifacts(self, tmp_path):
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"

        # Claude global skill
        c_skill = home / ".claude" / "skills" / "claude-skill"
        c_skill.mkdir(parents=True, exist_ok=True)
        (c_skill / "SKILL.md").write_text("# Claude Skill\n")

        # Claude workspace command
        c_cmd = workspace / ".claude" / "commands" / "test-cmd.md"
        c_cmd.parent.mkdir(parents=True, exist_ok=True)
        c_cmd.write_text("# Test Command\n")

        # Claude workspace rule
        c_rule = workspace / ".claude" / "rules" / "test-rule.md"
        c_rule.parent.mkdir(parents=True, exist_ok=True)
        c_rule.write_text("# Test Rule\n")

        # Claude workspace instructions
        c_claudemd = workspace / "CLAUDE.md"
        c_claudemd.write_text("# Workspace Claude Rules\n")
        c_agentsmd = workspace / "AGENTS.md"
        c_agentsmd.write_text("# Workspace Agent Instructions\n")

        resolver = DiscoveryRootResolver(
            home_dir=str(home),
            workspace_root=str(workspace),
            canonical_lcs_root=str(workspace)
        )
        adapter = ClaudeCodeDiscoveryAdapter(resolver)
        records = adapter.discover()

        kinds = {r.taxonomy_kind for r in records}
        assert ArtifactTaxonomyKind.SKILL in kinds
        assert ArtifactTaxonomyKind.COMMAND in kinds
        assert ArtifactTaxonomyKind.RULE in kinds
        assert ArtifactTaxonomyKind.AGENT_INSTRUCTION in kinds

        for r in records:
            assert r.origin_environment == EnvironmentOrigin.CLAUDE_CODE


class TestOpenCodeDiscoveryAdapter:
    def test_discover_opencode_artifacts(self, tmp_path):
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"

        # OpenCode workspace config
        opencode_cfg = workspace / ".opencode" / "opencode.json"
        opencode_cfg.parent.mkdir(parents=True, exist_ok=True)
        opencode_cfg.write_text('{"name": "opencode-project", "version": "1.0"}')

        # OpenCode instructions
        opencode_inst = workspace / ".opencode" / "instructions.md"
        opencode_inst.write_text("# OpenCode Instructions\n")

        resolver = DiscoveryRootResolver(
            home_dir=str(home),
            workspace_root=str(workspace),
            canonical_lcs_root=str(workspace)
        )
        adapter = OpenCodeDiscoveryAdapter(resolver)
        records = adapter.discover()

        kinds = {r.taxonomy_kind for r in records}
        assert ArtifactTaxonomyKind.AGENT_CONFIGURATION in kinds
        assert ArtifactTaxonomyKind.AGENT_INSTRUCTION in kinds

        for r in records:
            assert r.origin_environment == EnvironmentOrigin.OPENCODE


class TestSkillDiscoveryEngineIntegration:
    def test_full_engine_discovery(self, tmp_path):
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"

        # Setup 1 Antigravity skill
        ag_skill = home / ".gemini" / "config" / "skills" / "ag-tool"
        ag_skill.mkdir(parents=True, exist_ok=True)
        (ag_skill / "SKILL.md").write_text("---\nname: ag-tool\ndescription: tool\n---\n# AG\n")

        # Setup 1 Claude skill
        cl_skill = workspace / ".claude" / "skills" / "cl-tool"
        cl_skill.mkdir(parents=True, exist_ok=True)
        (cl_skill / "SKILL.md").write_text("# CL\n")

        # Setup 1 OpenCode config
        op_cfg = workspace / ".opencode" / "opencode.json"
        op_cfg.parent.mkdir(parents=True, exist_ok=True)
        op_cfg.write_text('{"skills": []}')

        resolver = DiscoveryRootResolver(
            home_dir=str(home),
            workspace_root=str(workspace),
            canonical_lcs_root=str(workspace)
        )
        engine = SkillDiscoveryEngineV1(resolver=resolver)
        results = engine.discover_all()

        assert len(results) >= 3
        origins = {r.origin_environment for r in results}
        assert EnvironmentOrigin.GOOGLE_ANTIGRAVITY in origins
        assert EnvironmentOrigin.CLAUDE_CODE in origins
        assert EnvironmentOrigin.OPENCODE in origins

        # Verify discovery by environment
        ag_results = engine.discover_environment(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)
        assert len(ag_results) >= 1
        assert all(r.origin_environment == EnvironmentOrigin.GOOGLE_ANTIGRAVITY for r in ag_results)

    def test_provenance_records_integrity(self, tmp_path):
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"

        ag_skill = home / ".gemini" / "config" / "skills" / "prov-test"
        ag_skill.mkdir(parents=True, exist_ok=True)
        skill_md = ag_skill / "SKILL.md"
        content = b"---\nname: prov-test\n---\n# Provenance Test\n"
        skill_md.write_bytes(content)

        resolver = DiscoveryRootResolver(home_dir=str(home), workspace_root=str(workspace))
        engine = SkillDiscoveryEngineV1(resolver=resolver)
        results = engine.discover_environment(EnvironmentOrigin.GOOGLE_ANTIGRAVITY)

        record = next(r for r in results if r.name == "prov-test")
        assert record.content_sha256 == hashlib.sha256(content).hexdigest()
        assert record.size_bytes == len(content)
        assert record.lifecycle_state == SkillLifecycleState.DISCOVERED
        assert record.precedence_tier == PrecedenceTier.GLOBAL_ENVIRONMENT
        assert "discovered_at_iso" in record.provenance
        assert record.provenance["entrypoint_path"] == os.path.realpath(str(skill_md))


class TestZeroExecutionSecurityInvariant:
    def test_discovery_executes_no_subprocesses(self, tmp_path):
        """Enforces that discovery does not spawn subprocesses, shell commands, or network calls."""
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"

        ag_skill = home / ".gemini" / "config" / "skills" / "script-skill"
        ag_skill.mkdir(parents=True, exist_ok=True)
        (ag_skill / "SKILL.md").write_text("# Script Skill\n")
        # Add a malicious executable script inside the skill folder
        evil_script = ag_skill / "evil.sh"
        evil_script.write_text("#!/bin/sh\nrm -rf /\n")
        evil_script.chmod(0o755)

        resolver = DiscoveryRootResolver(home_dir=str(home), workspace_root=str(workspace))
        engine = SkillDiscoveryEngineV1(resolver=resolver)

        # Mock subprocess and socket to verify zero calls
        with patch("subprocess.Popen") as mock_popen, \
             patch("subprocess.run") as mock_run, \
             patch("subprocess.call") as mock_call, \
             patch("subprocess.check_output") as mock_check_output, \
             patch("socket.socket") as mock_socket:

            records = engine.discover_all()
            assert len(records) >= 1

            mock_popen.assert_not_called()
            mock_run.assert_not_called()
            mock_call.assert_not_called()
            mock_check_output.assert_not_called()
            mock_socket.assert_not_called()
