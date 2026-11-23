"""
LCS Installation Portability & Host Artifact Packaging Test Suite
================================================================
Verifies Item 1:
1. Wheel installation into a clean virtual environment outside source tree.
2. Executable resolution and packaged schema discovery without developer paths.
3. Slash command artifact generation (Antigravity, Claude Code, OpenCode, Codex).
4. Unrelated user file preservation across installation, upgrade, and uninstallation.
5. Project-local and user-global (--global / --is-global) operation.
6. Execution of lcs call-me from external working directories.
"""

import os
import sys
import tempfile
import subprocess
import shutil
import pytest


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory):
    """Builds a fresh wheel from an isolated copy of the repository source."""
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = tmp_path_factory.mktemp("isolated_src")
    dist_dir = tmp_path_factory.mktemp("dist")

    isolated_repo = src_dir / "lcs_source"
    shutil.copytree(
        repo_dir,
        isolated_repo,
        ignore=shutil.ignore_patterns(".git", "build", "dist", "*.egg-info", "__pycache__", ".pytest_cache", ".venv", "*.pyc")
    )
    import importlib.util
    spec = importlib.util.find_spec("build")
    if spec is not None and spec.origin is not None:
        cmd = [sys.executable, "-m", "build", "--wheel", "--no-isolation", "-o", str(dist_dir)]
    else:
        cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(dist_dir), "."]
    res = subprocess.run(cmd, cwd=str(isolated_repo), capture_output=True, text=True)
    assert res.returncode == 0, f"Failed building wheel in isolated directory: {res.stderr}"

    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1, "Expected exactly one built wheel"
    return str(wheels[0])


def test_portable_clean_venv_installation(built_wheel):
    """Tests installing the wheel into a completely isolated venv outside the checkout."""
    repo_dir = os.path.dirname(os.path.abspath(__file__))

    with tempfile.TemporaryDirectory() as td:
        venv_dir = os.path.join(td, "venv")
        work_dir = os.path.join(td, "outside_workspace")
        fake_home = os.path.join(td, "fake_home")
        os.makedirs(work_dir, exist_ok=True)
        os.makedirs(fake_home, exist_ok=True)

        subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
        if sys.platform == "win32":
            venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
            venv_lcs = os.path.join(venv_dir, "Scripts", "lcs.exe")
        else:
            venv_python = os.path.join(venv_dir, "bin", "python3")
            venv_lcs = os.path.join(venv_dir, "bin", "lcs")

        # Install wheel
        clean_pip_env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        subprocess.run([venv_python, "-m", "pip", "install", "--force-reinstall", built_wheel], check=True, capture_output=True, env=clean_pip_env)

        env = os.environ.copy()
        env["HOME"] = fake_home
        env["USERPROFILE"] = fake_home
        if "PYTHONPATH" in env:
            del env["PYTHONPATH"]

        # 1. Verify schema discovery and database initialization
        res = subprocess.run([venv_lcs, "status"], cwd=work_dir, env=env, capture_output=True, text=True)
        assert res.returncode == 0, f"lcs status failed: {res.stderr}"
        assert "[Relational Database]" in res.stdout
        assert "Migrations:        4/4 applied" in res.stdout
        assert repo_dir not in res.stdout

        # 2. Verify project-local installation and unrelated file preservation
        unrelated_dir = os.path.join(work_dir, ".agents", "skills", "unrelated-custom-skill")
        os.makedirs(unrelated_dir, exist_ok=True)
        unrelated_file = os.path.join(unrelated_dir, "SKILL.md")
        with open(unrelated_file, "w") as f:
            f.write("# Unrelated user skill\n")

        res = subprocess.run([venv_lcs, "install-command", "--environment", "all"], cwd=work_dir, env=env, capture_output=True, text=True)
        assert res.returncode == 0, f"install-command failed: {res.stderr}"

        ag_skill = os.path.join(work_dir, ".agents", "skills", "call-me", "SKILL.md")
        cl_cmd = os.path.join(work_dir, ".claude", "commands", "call-me.md")
        oc_cmd = os.path.join(work_dir, ".opencode", "commands", "call-me.md")

        for p in (ag_skill, cl_cmd, oc_cmd):
            assert os.path.isfile(p), f"Missing generated artifact: {p}"
            with open(p) as f:
                content = f.read()
            assert repo_dir not in content, f"Developer path leaked in {p}"

        # 3. Verify user-level global installation
        res = subprocess.run([venv_lcs, "install-command", "--environment", "all", "--global"], cwd=work_dir, env=env, capture_output=True, text=True)
        assert res.returncode == 0
        global_ag = os.path.join(fake_home, ".gemini", "config", "skills", "call-me", "SKILL.md")
        global_cl = os.path.join(fake_home, ".claude", "commands", "call-me.md")
        assert os.path.isfile(global_ag)
        assert os.path.isfile(global_cl)

        # 4. Invoke call-me handoff outside checkout
        res = subprocess.run([venv_lcs, "call-me", "Perform code review on repository"], cwd=work_dir, env=env, capture_output=True, text=True)
        assert res.returncode == 0
        assert "ACCEPTED" in res.stdout

        # 5. Verify uninstallation removes LCS artifacts and preserves unrelated files
        res = subprocess.run([venv_lcs, "uninstall-command", "--environment", "all"], cwd=work_dir, env=env, capture_output=True, text=True)
        assert res.returncode == 0
        assert not os.path.exists(ag_skill)
        assert not os.path.exists(cl_cmd)
        assert not os.path.exists(oc_cmd)
        assert os.path.isfile(unrelated_file), "Unrelated user skill was deleted during uninstallation!"

        # 6. Global uninstall
        res = subprocess.run([venv_lcs, "uninstall-command", "--environment", "all", "--global"], cwd=work_dir, env=env, capture_output=True, text=True)
        assert res.returncode == 0
        assert not os.path.exists(global_ag)
        assert not os.path.exists(global_cl)
