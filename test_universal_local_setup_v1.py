"""
LCS Universal Local Setup & Diagnostics Test Suite (Stage 1)
============================================================
Verifies:
1. Persistent user-level LCS state directory resolution & precedence across platforms.
2. Configuration hierarchy (root_override > is_global > LCS_ROOT > cwd .lcs > global fallback).
3. Host agent detection (Antigravity, Claude Code, OpenCode, Codex, Generic POSIX).
4. Idempotent global and project-local setup.
5. Conflict preservation for existing user files and --force overwrite.
6. Setup diagnostics & doctor checks without side-effects.
7. Safe repair behavior healing corrupted or missing directories, keys, and migrations.
8. Portable command invocation syntax across terminal restarts.
9. Cross-project persistence and isolation.
10. End-to-end CLI execution of 'lcs setup'.
"""

import os
import sys
import json
import shutil
import sqlite3
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.cli import main
from lcs.setup import HostDetector, SetupDiagnostics, SetupEngine, DiagnosticCheck
from lcs.interface.generators import SlashCommandGenerator


@pytest.fixture
def test_env(tmp_path):
    """Provides isolated home directory and workspace paths."""
    mock_home = str(tmp_path / "mock_home")
    mock_workspace = str(tmp_path / "mock_workspace")
    os.makedirs(mock_home, exist_ok=True)
    os.makedirs(mock_workspace, exist_ok=True)
    return {
        "home": mock_home,
        "workspace": mock_workspace,
        "tmp_path": tmp_path
    }


def test_user_state_dir_resolution_and_precedence(test_env, monkeypatch):
    """Verifies precedence of state directory resolution across env vars and platforms."""
    mock_home = test_env["home"]

    # 1. LCS_USER_STATE_DIR takes highest precedence
    custom_state = os.path.join(test_env["tmp_path"], "custom_lcs_state")
    monkeypatch.setenv("LCS_USER_STATE_DIR", custom_state)
    assert LCSConfig.get_user_state_dir(home_override=mock_home) == os.path.realpath(custom_state)
    monkeypatch.delenv("LCS_USER_STATE_DIR", raising=False)

    # 2. home_override takes precedence next
    assert LCSConfig.get_user_state_dir(home_override=mock_home) == os.path.realpath(os.path.join(mock_home, ".lcs"))

    # 3. LCS_USER_HOME env var takes precedence if home_override not passed
    monkeypatch.setenv("LCS_USER_HOME", mock_home)
    assert LCSConfig.get_user_state_dir() == os.path.realpath(os.path.join(mock_home, ".lcs"))
    monkeypatch.delenv("LCS_USER_HOME", raising=False)


def test_lcs_config_resolution_hierarchy(test_env, monkeypatch):
    """Verifies configuration precedence hierarchy and is_user_global / is_project_local properties."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]
    monkeypatch.setenv("LCS_USER_HOME", mock_home)

    # Case 1: root_override takes absolute priority
    override_path = os.path.join(test_env["tmp_path"], "override_dir")
    cfg1 = LCSConfig.resolve(root_override=override_path, home_override=mock_home)
    assert cfg1.root_dir == os.path.realpath(override_path)
    assert cfg1.is_project_local is True

    # Case 2: is_global=True forces user state directory
    cfg2 = LCSConfig.resolve(is_global=True, home_override=mock_home)
    expected_global = os.path.realpath(os.path.join(mock_home, ".lcs"))
    assert cfg2.root_dir == expected_global
    assert cfg2.is_user_global is True
    assert cfg2.is_project_local is False

    # Case 3: LCS_ROOT environment variable takes priority over cwd/global fallback
    env_root = os.path.join(test_env["tmp_path"], "env_lcs_root")
    monkeypatch.setenv("LCS_ROOT", env_root)
    cfg3 = LCSConfig.resolve(home_override=mock_home)
    assert cfg3.root_dir == os.path.realpath(env_root)
    monkeypatch.delenv("LCS_ROOT", raising=False)

    # Case 4: Project-local .lcs in cwd takes priority when it exists
    local_lcs = os.path.join(mock_ws, ".lcs")
    os.makedirs(local_lcs, exist_ok=True)
    monkeypatch.chdir(mock_ws)

    # Initialize global state too
    global_lcs = os.path.join(mock_home, ".lcs")
    os.makedirs(global_lcs, exist_ok=True)
    with open(os.path.join(global_lcs, "lcs.db"), "w") as f:
        f.write("")

    cfg4 = LCSConfig.resolve(home_override=mock_home)
    assert cfg4.root_dir == os.path.realpath(local_lcs)
    assert cfg4.is_project_local is True

    # Case 5: When cwd has no .lcs, falls back to initialized global state directory
    empty_ws = os.path.join(test_env["tmp_path"], "empty_ws")
    os.makedirs(empty_ws, exist_ok=True)
    monkeypatch.chdir(empty_ws)

    cfg5 = LCSConfig.resolve(home_override=mock_home)
    assert cfg5.root_dir == os.path.realpath(global_lcs)
    assert cfg5.is_user_global is True


def test_host_detection_engine(test_env):
    """Verifies that installed agents are accurately detected and classified."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]

    # Pre-create config directories for Antigravity, Claude Code, and OpenCode
    ag_cfg = os.path.join(mock_home, ".gemini", "config")
    cc_cfg = os.path.join(mock_home, ".claude")
    oc_cfg = os.path.join(mock_home, ".opencode")
    os.makedirs(ag_cfg, exist_ok=True)
    os.makedirs(cc_cfg, exist_ok=True)
    os.makedirs(oc_cfg, exist_ok=True)

    hosts = HostDetector.detect_all(
        workspace_root=mock_ws,
        home_override=mock_home,
        is_global=True
    )

    assert "ANTIGRAVITY" in hosts
    assert hosts["ANTIGRAVITY"].is_detected is True
    assert hosts["ANTIGRAVITY"].command_status == "MISSING"

    assert "CLAUDE_CODE" in hosts
    assert hosts["CLAUDE_CODE"].is_detected is True
    assert hosts["CLAUDE_CODE"].command_status == "MISSING"

    assert "OPENCODE" in hosts
    assert hosts["OPENCODE"].is_detected is True
    assert hosts["OPENCODE"].command_status == "MISSING"

    assert "GENERIC_POSIX" in hosts
    assert hosts["GENERIC_POSIX"].is_detected is True


def test_lcs_setup_global_idempotency(test_env):
    """Verifies global setup initialization, idempotency, and secure permissions."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]

    # First setup execution
    res1 = SetupEngine.run_setup(
        is_global=True,
        workspace_root=mock_ws,
        home_override=mock_home,
        environments=["all"]
    )

    assert res1["status"] in ("SUCCESS", "WARNING")
    assert res1["overall_health"] in ("HEALTHY", "DEGRADED")
    global_dir = os.path.join(mock_home, ".lcs")
    assert os.path.isdir(global_dir)
    assert os.path.isfile(os.path.join(global_dir, "lcs.db"))
    assert os.path.isdir(os.path.join(global_dir, "cas", "objects"))
    assert os.path.isfile(os.path.join(global_dir, "keys", "key_ring.json"))

    # Permission check on POSIX
    if sys.platform != "win32":
        mode = os.stat(global_dir).st_mode & 0o777
        assert mode & 0o077 == 0

    # Second setup execution (idempotency verification)
    res2 = SetupEngine.run_setup(
        is_global=True,
        workspace_root=mock_ws,
        home_override=mock_home,
        environments=["all"]
    )
    assert res2["status"] in ("SUCCESS", "WARNING")
    assert res2["root_dir"] == res1["root_dir"]


def test_lcs_setup_project_local_isolation(test_env):
    """Verifies that project-local setup remains completely isolated from global state."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]

    # Run global setup
    SetupEngine.run_setup(is_global=True, workspace_root=mock_ws, home_override=mock_home)

    # Run project-local setup
    res_proj = SetupEngine.run_setup(is_global=False, workspace_root=mock_ws, home_override=mock_home)
    assert res_proj["status"] in ("SUCCESS", "WARNING")

    local_lcs = os.path.join(mock_ws, ".lcs")
    global_lcs = os.path.join(mock_home, ".lcs")

    assert os.path.isdir(local_lcs)
    assert os.path.isdir(global_lcs)
    assert os.path.realpath(local_lcs) != os.path.realpath(global_lcs)

    # Verify both databases are separate and functional
    conn_local = sqlite3.connect(os.path.join(local_lcs, "lcs.db"))
    conn_global = sqlite3.connect(os.path.join(global_lcs, "lcs.db"))
    assert conn_local.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
    assert conn_global.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
    conn_local.close()
    conn_global.close()


def test_conflict_preservation_and_force_overwrite(test_env):
    """Verifies that unrelated user command files are protected unless --force is specified."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]

    target_cmd = os.path.join(mock_home, ".claude", "commands", "call-me.md")
    os.makedirs(os.path.dirname(target_cmd), exist_ok=True)
    with open(target_cmd, "w", encoding="utf-8") as f:
        f.write("# Custom User Macro\nDo not overwrite this file!\n")

    # Setup without overwrite (must preserve file and report conflict)
    res_safe = SetupEngine.run_setup(
        is_global=True,
        workspace_root=mock_ws,
        home_override=mock_home,
        environments=["claude_code"],
        overwrite=False
    )

    with open(target_cmd, "r", encoding="utf-8") as f:
        content_after = f.read()
    assert "Custom User Macro" in content_after
    assert res_safe["installed_integrations"]["claude_code"]["status"] == "CONFLICT_SKIPPED"

    # Setup with overwrite=True (--force) must overwrite
    res_forced = SetupEngine.run_setup(
        is_global=True,
        workspace_root=mock_ws,
        home_override=mock_home,
        environments=["claude_code"],
        overwrite=True
    )
    with open(target_cmd, "r", encoding="utf-8") as f:
        content_forced = f.read()
    assert SlashCommandGenerator.LCS_ARTIFACT_SIGNATURE in content_forced
    assert res_forced["installed_integrations"]["claude_code"]["status"] == "INSTALLED"


def test_setup_diagnostics_and_doctor_no_side_effects(test_env):
    """Verifies that running 'lcs setup --check' is read-only and does not mutate files."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]
    target_lcs = os.path.join(mock_home, ".lcs")

    # Ensure target_lcs does not exist
    assert not os.path.exists(target_lcs)

    # Run check
    check_res = SetupEngine.run_check(
        is_global=True,
        workspace_root=mock_ws,
        home_override=mock_home
    )

    # Should report UNHEALTHY because directories don't exist yet
    assert check_res["overall_health"] == "UNHEALTHY"
    # And must NOT create the directories!
    assert not os.path.exists(target_lcs)


def test_setup_repair_heals_corrupted_state(test_env):
    """Verifies that 'lcs setup --repair' restores damaged directories and missing keys."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]

    # Initial setup
    SetupEngine.run_setup(is_global=True, workspace_root=mock_ws, home_override=mock_home)

    # Intentionally corrupt state: delete key file and CAS staging directory
    key_file = os.path.join(mock_home, ".lcs", "keys", "key_ring.json")
    staging_dir = os.path.join(mock_home, ".lcs", "cas", "staging")
    os.remove(key_file)
    shutil.rmtree(staging_dir)

    assert not os.path.exists(key_file)
    assert not os.path.exists(staging_dir)

    # Run repair
    repair_res = SetupEngine.run_repair(
        is_global=True,
        workspace_root=mock_ws,
        home_override=mock_home
    )

    assert repair_res["overall_health"] in ("HEALTHY", "DEGRADED")
    assert os.path.isfile(key_file)
    assert os.path.getsize(key_file) > 0
    assert os.path.isdir(staging_dir)


def test_command_invocation_resilience_and_terminal_restarts():
    """Verifies generated slash command templates contain reliable fallback invocations."""
    # Check templates
    assert "command -v lcs" in SlashCommandGenerator.ANTIGRAVITY_SKILL_TEMPLATE
    assert "command -v lcs" in SlashCommandGenerator.CLAUDE_CODE_COMMAND_TEMPLATE
    assert "command -v lcs" in SlashCommandGenerator.OPENCODE_COMMAND_TEMPLATE
    assert "lcs call-me --handoff" in SlashCommandGenerator.ANTIGRAVITY_SKILL_TEMPLATE
    assert "python3 -m lcs.cli" in SlashCommandGenerator.CLAUDE_CODE_COMMAND_TEMPLATE


def test_cross_project_persistence_and_isolation(test_env, monkeypatch):
    """Verifies that an unconfigured project accesses user-global state without collision."""
    mock_home = test_env["home"]
    monkeypatch.setenv("LCS_USER_HOME", mock_home)

    # Set up global environment
    SetupEngine.run_setup(is_global=True, home_override=mock_home)

    proj_a = os.path.join(test_env["tmp_path"], "project_a")
    proj_b = os.path.join(test_env["tmp_path"], "project_b")
    os.makedirs(proj_a, exist_ok=True)
    os.makedirs(proj_b, exist_ok=True)

    # Set up project B locally
    SetupEngine.run_setup(is_global=False, workspace_root=proj_b, home_override=mock_home)

    # Navigate to Project A (unconfigured) -> resolves to global
    monkeypatch.chdir(proj_a)
    cfg_a = LCSConfig.resolve(home_override=mock_home)
    assert cfg_a.is_user_global is True
    assert cfg_a.root_dir == os.path.realpath(os.path.join(mock_home, ".lcs"))

    # Navigate to Project B (local) -> resolves to local .lcs
    monkeypatch.chdir(proj_b)
    cfg_b = LCSConfig.resolve(home_override=mock_home)
    assert cfg_b.is_project_local is True
    assert cfg_b.root_dir == os.path.realpath(os.path.join(proj_b, ".lcs"))


def test_cli_setup_subcommand_e2e(test_env, monkeypatch, capsys):
    """Verifies end-to-end execution of 'lcs setup' CLI with flags."""
    mock_home = test_env["home"]
    mock_ws = test_env["workspace"]
    monkeypatch.setenv("LCS_USER_HOME", mock_home)
    monkeypatch.chdir(mock_ws)

    # Test 1: lcs setup --check (returns 1 before setup)
    exit_code_check = main(["setup", "--check"])
    captured = capsys.readouterr()
    assert exit_code_check == 1
    assert "SETUP DIAGNOSTICS & DOCTOR" in captured.out

    # Test 2: lcs setup --global
    exit_code_setup = main(["setup", "--global"])
    captured = capsys.readouterr()
    assert exit_code_setup == 0
    assert "LOCAL INSTALLATION & SETUP" in captured.out

    # Test 3: lcs setup --check (returns 0 after setup)
    exit_code_check_post = main(["setup", "--check"])
    captured = capsys.readouterr()
    assert exit_code_check_post == 0
    assert "PRAGMA integrity_check = ok" in captured.out

    # Test 4: lcs setup --json
    exit_code_json = main(["setup", "--json"])
    captured = capsys.readouterr()
    assert exit_code_json == 0
    data = json.loads(captured.out)
    assert data["status"] in ("SUCCESS", "WARNING")
    assert "overall_health" in data
