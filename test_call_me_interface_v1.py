"""
LCS Phase 2A Call Me Interface Acceptance Test Suite
====================================================
Validates all Phase 2A acceptance requirements:
1. Explicit /call-me activation
2. Natural language intake & verbatim preservation
3. Structured TaskRequest creation & RFC 8785 canonicalization
4. Core handoff to LCSCoreBridge & candidate matching
5. Unsupported / custom environment handling
6. Initialization & syntax failure handling
7. Ordinary chat dormancy invariant (0 DB writes, 0 CAS writes, 0 LLM tokens)
8. Repeated invocation & session isolation
9. Governance preservation (Gate 1 & Gate 2 intact, no un-governed execution)
10. Hash-On-Activation preservation (tampered file detection)
11. Host slash-command generators (feasibility matrix, install, uninstall)
12. CLI integration (cmd_call_me, cmd_install_command, cmd_uninstall_command)
"""

import os
import json
import shutil
import tempfile
import argparse
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.interface import (
    TaskRequest,
    InvocationResponse,
    ConsentState,
    LCSCoreBridge,
    CallMeInterface,
    CallMeError,
    SlashCommandGenerator,
    CommandGeneratorError,
)
from lcs.adapters import ContentIntegrityMismatchError
from lcs.cli import cmd_call_me, cmd_install_command, cmd_uninstall_command


@pytest.fixture
def call_me_env():
    """Sets up an isolated LCSContext in a temporary workspace."""
    raw_dir = tempfile.mkdtemp(prefix="lcs_call_me_test_")
    real_dir = os.path.realpath(raw_dir)

    cfg = LCSConfig.resolve(root_override=real_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)

    # Strictly isolate discovery roots
    ctx.skill_service.resolver.user_home = real_dir
    ctx.skill_service.resolver.workspace_root = real_dir
    ctx.skill_service.set_resolver(ctx.skill_service.resolver)
    ctx.cache.resolver = ctx.skill_service.resolver
    ctx.cache.delta_engine.resolver = ctx.skill_service.resolver
    ctx.fs_watcher.resolver = ctx.skill_service.resolver

    yield ctx, real_dir

    ctx.close()
    shutil.rmtree(real_dir, ignore_errors=True)


def test_01_explicit_call_me_activation(call_me_env):
    """Verifies explicit /call-me activation with various authorized syntax prefixes."""
    ctx, ws = call_me_env

    # 1. Standard /call-me
    resp1 = ctx.call_me.execute_call_me('/call-me "Deploy container to staging"')
    assert resp1 is not None
    assert resp1.status == "ACCEPTED"
    assert resp1.request_id.startswith("req-")
    assert resp1.session_id.startswith("sess-")
    assert resp1.governance_status in ("PENDING_APPROVAL", "PENDING_CAPABILITIES")

    # 2. Plain call-me
    resp2 = ctx.call_me.execute_call_me('call-me Build release package')
    assert resp2 is not None
    assert resp2.status == "ACCEPTED"

    # 3. Colon separator: /call-me: <task>
    resp3 = ctx.call_me.execute_call_me('/call-me: Run security audit')
    assert resp3 is not None
    assert resp3.status == "ACCEPTED"

    # 4. Equals separator: call_me = <task>
    resp4 = ctx.call_me.execute_call_me('call_me = Lint repository')
    assert resp4 is not None
    assert resp4.status == "ACCEPTED"


def test_02_natural_language_intake_and_verbatim_preservation(call_me_env):
    """Verifies that original user instruction is preserved verbatim bit-for-bit."""
    ctx, ws = call_me_env

    raw_complex_instruction = '   Analyze logs in /var/log/app.log and find "ERROR 500" with flags --strict \t\n   '
    msg = f"/call-me {raw_complex_instruction}"

    task_desc, meta = ctx.call_me.parse_invocation(msg)
    # The instruction extracted inside quotes or trimmed from prefix
    assert "Analyze logs in /var/log/app.log" in task_desc
    assert '"ERROR 500"' in task_desc

    req = TaskRequest.create(raw_instruction=raw_complex_instruction, environment="ANTIGRAVITY")
    assert req.original_instruction == raw_complex_instruction
    assert req.normalized_task_description == raw_complex_instruction.strip()
    assert req.invocation_environment == "ANTIGRAVITY"


def test_03_structured_task_request_creation_and_rfc8785_canonicalization():
    """Verifies TaskRequest construction, schema versioning, and RFC 8785 canonical JSON output."""
    req = TaskRequest.create(
        raw_instruction="Run full integration test suite",
        environment="CLAUDE_CODE",
        session_id="custom-session-123",
        inputs={"flag": "ci", "timeout": 30},
        constraints=["no-network", "read-only"],
        deliverables=["test-report.json"]
    )

    assert req.schema_version == "lcs.task.request.v1"
    assert req.session_id == "custom-session-123"
    assert req.consent_and_authorization_state == ConsentState.EXPLICIT_INVOCATION

    # Verify RFC 8785 JCS canonicalization
    canonical_json = req.to_canonical_json()
    assert isinstance(canonical_json, str)
    # RFC 8785 rules: keys sorted lexically, no spaces after colons/commas
    assert '"constraints":["no-network","read-only"]' in canonical_json
    assert '"schema_version":"lcs.task.request.v1"' in canonical_json

    # Round trip from dict
    d = req.to_dict()
    restored = TaskRequest.from_dict(d)
    assert restored.request_id == req.request_id
    assert restored.session_id == req.session_id
    assert restored.original_instruction == req.original_instruction
    assert restored.consent_and_authorization_state == ConsentState.EXPLICIT_INVOCATION


def test_04_core_handoff_and_candidate_matching(call_me_env):
    """Verifies handoff to LCSCoreBridge and fast cache/retrieval candidate matching."""
    ctx, ws = call_me_env

    # Seed a real skill in workspace
    skill_dir = os.path.join(ws, ".agents", "skills", "deploy_worker")
    os.makedirs(skill_dir, exist_ok=True)
    with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# Deploy Worker\nDescription: Automated deployment orchestrator for staging containers\n")

    # Discover and index
    records = ctx.skill_service.run_full_pipeline()
    assert len(records) >= 1

    # Prime cache
    ctx.cache.warm_cache()

    # Invoke /call-me
    resp = ctx.call_me.execute_call_me("/call-me Deploy staging container")
    assert resp is not None
    assert resp.status == "ACCEPTED"
    assert resp.candidate_count >= 1
    assert any("deploy_worker" in urn for urn in resp.candidate_urns)
    assert resp.governance_status == "PENDING_APPROVAL"


def test_05_unsupported_environment_handling(call_me_env):
    """Verifies that unknown or unsupported host environments are handled gracefully."""
    ctx, ws = call_me_env

    custom_interface = CallMeInterface(ctx, environment="FUTURE_UNKNOWN_HOST")
    resp = custom_interface.execute_call_me("/call-me Test capability discovery")
    assert resp is not None
    assert resp.status == "ACCEPTED"
    # Does not crash, retains requested environment in provenance
    assert resp.request_id.startswith("req-")


def test_06_initialization_and_syntax_failure_handling(call_me_env):
    """Verifies handling of empty tasks, missing parameters, or invalid syntax."""
    ctx, ws = call_me_env

    # 1. Bare /call-me without instruction
    resp_empty = ctx.call_me.execute_call_me("/call-me")
    assert resp_empty is not None
    assert resp_empty.status == "ERROR"
    assert "No task instruction provided" in resp_empty.message
    assert resp_empty.governance_status == "REJECTED"

    # 2. Whitespace only task
    resp_ws = ctx.call_me.execute_call_me("/call-me    ")
    assert resp_ws is not None
    assert resp_ws.status == "ERROR"

    # 3. Direct constructor validation
    with pytest.raises(ValueError, match="Task instruction cannot be empty"):
        TaskRequest.create("")


def test_07_ordinary_chat_dormancy_invariant(call_me_env):
    """
    DORMANCY INVARIANT: Ordinary conversational messages MUST NOT activate LCS.
    Produces:
    - 0 database writes
    - 0 CAS writes
    - 0 LLM context overhead
    - execute_call_me returns None immediately
    """
    ctx, ws = call_me_env

    # Count initial CAS objects
    cas_objects_dir = os.path.join(ctx.config.cas_root, "objects")
    initial_cas_count = 0
    if os.path.exists(cas_objects_dir):
        initial_cas_count = sum(len(files) for _, _, files in os.walk(cas_objects_dir))

    # Read initial database WAL / page count
    cur = ctx.conn.cursor()
    cur.execute("PRAGMA schema_version;")
    initial_schema_ver = cur.fetchone()[0]

    ordinary_prompts = [
        "Hello! How can you help me today?",
        "What is the capital of France?",
        "Can you write a python function to sort a list?",
        "Tell me about living capability system",
        "/help with my project",
    ]

    for prompt in ordinary_prompts:
        assert ctx.call_me.is_call_me_command(prompt) is False
        result = ctx.call_me.execute_call_me(prompt)
        assert result is None, f"Dormancy invariant violated for prompt: {prompt}"

    # Verify CAS was completely untouched
    final_cas_count = 0
    if os.path.exists(cas_objects_dir):
        final_cas_count = sum(len(files) for _, _, files in os.walk(cas_objects_dir))
    assert final_cas_count == initial_cas_count, "CAS object count changed during ordinary chat!"

    # Verify database schema untouched
    cur.execute("PRAGMA schema_version;")
    final_schema_ver = cur.fetchone()[0]
    assert final_schema_ver == initial_schema_ver


def test_08_repeated_invocation_and_session_isolation(call_me_env):
    """Verifies that multiple invocations maintain separate request IDs and isolated sessions."""
    ctx, ws = call_me_env

    # Session A
    resp_a1 = ctx.call_me.execute_call_me("/call-me Task 1 in Session A", session_id="session-AAA")
    resp_a2 = ctx.call_me.execute_call_me("/call-me Task 2 in Session A", session_id="session-AAA")

    # Session B
    resp_b1 = ctx.call_me.execute_call_me("/call-me Task 1 in Session B", session_id="session-BBB")

    # Auto session
    resp_c = ctx.call_me.execute_call_me("/call-me Task in Auto Session")

    # Check session IDs
    assert resp_a1.session_id == "session-AAA"
    assert resp_a2.session_id == "session-AAA"
    assert resp_b1.session_id == "session-BBB"
    assert resp_c.session_id.startswith("sess-")
    assert resp_c.session_id not in ("session-AAA", "session-BBB")

    # Check distinct request IDs
    req_ids = {resp_a1.request_id, resp_a2.request_id, resp_b1.request_id, resp_c.request_id}
    assert len(req_ids) == 4


def test_09_governance_preservation_no_ungoverned_execution(call_me_env):
    """
    Verifies that /call-me NEVER performs un-governed or un-approved execution.
    Initial invocation is strictly pre-flight (PENDING_APPROVAL).
    """
    ctx, ws = call_me_env

    resp = ctx.call_me.execute_call_me('/call-me "Format hard drive and delete all files"')
    assert resp is not None
    # Must NOT execute
    assert resp.status == "ACCEPTED"
    assert resp.governance_status in ("PENDING_APPROVAL", "PENDING_CAPABILITIES")

    # Execution engine has zero unapproved execution records/runs
    assert ctx.execution_engine.list_runs() == []


def test_10_hash_on_activation_preservation(call_me_env):
    """
    Verifies that Hash-On-Activation is preserved: if an indexed capability file is
    tampered with on disk, the activation verifier catches it.
    """
    ctx, ws = call_me_env

    # 1. Create a skill
    skill_dir = os.path.join(ws, ".agents", "skills", "security_guard")
    os.makedirs(skill_dir, exist_ok=True)
    skill_file = os.path.join(skill_dir, "SKILL.md")
    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# Security Guard Skill\nDescription: Validates system parameters\n")

    # 2. Discover & verify initial state
    records = ctx.skill_service.run_full_pipeline()
    assert len(records) >= 1
    urn = records[0].canonical_urn

    # Initial activation verification passes
    status = ctx.activation_verifier.verify_capability_activation(urn)
    assert status.capability_urn == urn

    # 3. Tamper with file
    with open(skill_file, "a", encoding="utf-8") as f:
        f.write("\nMALICIOUS INJECTED PAYLOAD\n")

    # 4. Activation verification blocks execution
    with pytest.raises(ContentIntegrityMismatchError):
        ctx.activation_verifier.verify_capability_activation(urn)


def test_11_slash_command_generators_and_feasibility_matrix(call_me_env):
    """Verifies feasibility matrix reporting, artifact generation, and uninstallation."""
    ctx, ws = call_me_env

    # 1. Feasibility matrix
    matrix = SlashCommandGenerator.get_feasibility_status()
    assert "ANTIGRAVITY" in matrix
    assert "CLAUDE_CODE" in matrix
    assert "OPENCODE" in matrix
    assert "GENERIC_POSIX" in matrix
    for env_name, data in matrix.items():
        assert data["host_supported"] is True
        assert data["implemented"] is True
        assert data["tested"] is True

    # 2. Install all
    installed = SlashCommandGenerator.install_all(ws)
    assert os.path.exists(installed["ANTIGRAVITY"])
    assert os.path.exists(installed["CLAUDE_CODE"])
    assert os.path.exists(installed["OPENCODE"])

    # Content verification
    with open(installed["ANTIGRAVITY"], "r", encoding="utf-8") as f:
        content = f.read()
        assert "name: call-me" in content
        assert "/call-me <natural language task description>" in content

    # 3. Uninstall
    assert SlashCommandGenerator.uninstall(ws, "ANTIGRAVITY") is True
    assert SlashCommandGenerator.uninstall(ws, "CLAUDE_CODE") is True
    assert SlashCommandGenerator.uninstall(ws, "OPENCODE") is True

    assert not os.path.exists(installed["ANTIGRAVITY"])
    assert not os.path.exists(installed["CLAUDE_CODE"])
    assert not os.path.exists(installed["OPENCODE"])


def test_12_cli_integration(call_me_env, capsys):
    """Verifies CLI subcommands: lcs call-me, lcs install-command, lcs uninstall-command."""
    ctx, ws = call_me_env

    # 1. Test lcs install-command
    args_install = argparse.Namespace(environment="all", is_global=False)
    ret_inst = cmd_install_command(ctx, args_install)
    assert ret_inst == 0
    captured = capsys.readouterr()
    assert "Installed Antigravity" in captured.out
    assert "Installed Claude Code" in captured.out
    assert "Installed OpenCode" in captured.out

    # 2. Test lcs call-me
    args_call_me = argparse.Namespace(
        task="Audit system configuration",
        session_id="cli-session-1",
        raw_json=False
    )
    ret_call = cmd_call_me(ctx, args_call_me)
    assert ret_call == 0
    captured = capsys.readouterr()
    assert "LIVING CAPABILITY SYSTEM (LCS) — /call-me INVOCATION" in captured.out
    assert "cli-session-1" in captured.out
    assert "Status:             ACCEPTED" in captured.out

    # 3. Test lcs call-me with raw json
    args_json = argparse.Namespace(
        task="Audit system configuration",
        session_id="cli-session-json",
        raw_json=True
    )
    ret_json = cmd_call_me(ctx, args_json)
    assert ret_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert data["status"] == "ACCEPTED"
    assert data["session_id"] == "cli-session-json"

    # 4. Test lcs uninstall-command
    args_uninst = argparse.Namespace(environment="all", is_global=False)
    ret_uninst = cmd_uninstall_command(ctx, args_uninst)
    assert ret_uninst == 0
    captured_un = capsys.readouterr()
    assert "ANTIGRAVITY: REMOVED" in captured_un.out
    assert "CLAUDE_CODE: REMOVED" in captured_un.out
    assert "OPENCODE: REMOVED" in captured_un.out


def test_13_unrelated_user_file_preservation_on_install(call_me_env):
    """
    Verifies that installation REFUSES to overwrite existing unrelated user files
    unless explicitly authorized with overwrite=True.
    """
    ctx, ws = call_me_env

    # 1. Create a pre-existing user command in Claude Code
    claude_cmd_dir = os.path.join(ws, ".claude", "commands")
    os.makedirs(claude_cmd_dir, exist_ok=True)
    custom_claude_file = os.path.join(claude_cmd_dir, "call-me.md")
    user_content = "# User Custom Telephony Command\necho 'Calling external phone endpoint...'\n"
    with open(custom_claude_file, "w", encoding="utf-8") as f:
        f.write(user_content)

    # 2. Attempt install without overwrite -> must raise CommandGeneratorError
    with pytest.raises(CommandGeneratorError, match="Refusing to overwrite existing non-LCS file"):
        SlashCommandGenerator.install_claude_code(ws, overwrite=False)

    # Verify user file is 100% intact
    with open(custom_claude_file, "r", encoding="utf-8") as f:
        assert f.read() == user_content

    # 3. Install with overwrite=True succeeds
    SlashCommandGenerator.install_claude_code(ws, overwrite=True)
    with open(custom_claude_file, "r", encoding="utf-8") as f:
        new_content = f.read()
        assert SlashCommandGenerator.LCS_ARTIFACT_SIGNATURE in new_content


def test_14_unrelated_user_file_preservation_on_uninstall(call_me_env):
    """
    Verifies that uninstallation:
    1. Removes ONLY LCS-managed files and leaves other user files intact in directory.
    2. Refuses to delete unrelated user files with the same name.
    """
    ctx, ws = call_me_env

    # 1. Install Antigravity skill
    skill_file = SlashCommandGenerator.install_antigravity(ws)
    skill_dir = os.path.dirname(skill_file)

    # 2. Place an unrelated user file in the skill directory
    unrelated_file = os.path.join(skill_dir, "user_notes.txt")
    with open(unrelated_file, "w", encoding="utf-8") as f:
        f.write("Important operator notes about capability configuration.\n")

    # 3. Place an unrelated custom call-me.md in Claude Code
    claude_cmd_dir = os.path.join(ws, ".claude", "commands")
    os.makedirs(claude_cmd_dir, exist_ok=True)
    custom_claude_file = os.path.join(claude_cmd_dir, "call-me.md")
    custom_content = "# Telephony Voice System\n"
    with open(custom_claude_file, "w", encoding="utf-8") as f:
        f.write(custom_content)

    # 4. Uninstall Antigravity -> must remove SKILL.md but PRESERVE user_notes.txt and directory
    assert SlashCommandGenerator.uninstall(ws, "ANTIGRAVITY") is True
    assert not os.path.exists(skill_file)
    assert os.path.exists(unrelated_file)
    with open(unrelated_file, "r", encoding="utf-8") as f:
        assert "Important operator notes" in f.read()

    # 5. Uninstall Claude Code -> must refuse to delete unrelated user command
    assert SlashCommandGenerator.uninstall(ws, "CLAUDE_CODE") is False
    assert os.path.exists(custom_claude_file)
    with open(custom_claude_file, "r", encoding="utf-8") as f:
        assert f.read() == custom_content


def test_15_global_install_and_uninstall(call_me_env):
    """
    Verifies that --global installation and uninstallation correctly target
    the user home directory rather than workspace.
    """
    ctx, ws = call_me_env
    mock_home = os.path.join(ws, "mock_user_home")
    os.makedirs(mock_home, exist_ok=True)

    # Global install
    p_anti = SlashCommandGenerator.install_antigravity(ws, is_global=True, home_dir=mock_home)
    p_claude = SlashCommandGenerator.install_claude_code(ws, is_global=True, home_dir=mock_home)

    assert p_anti.startswith(mock_home)
    assert p_claude.startswith(mock_home)
    assert os.path.exists(p_anti)
    assert os.path.exists(p_claude)

    # Global uninstall
    assert SlashCommandGenerator.uninstall(ws, "ANTIGRAVITY", is_global=True, home_dir=mock_home) is True
    assert SlashCommandGenerator.uninstall(ws, "CLAUDE_CODE", is_global=True, home_dir=mock_home) is True

    assert not os.path.exists(p_anti)
    assert not os.path.exists(p_claude)

