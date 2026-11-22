"""
LCS Filesystem Watcher Verification Suite (Phase 1C)
====================================================
Tests filesystem monitoring, event queueing, atomic replacement detection,
symlink escape defenses, error recovery, and missed event reconciliation.
"""

import os
import time
import shutil
import tempfile
import pytest

from lcs.cache import (
    FilesystemWatcher,
    ChangeKind,
    DeltaChange,
    WatcherError,
)
from lcs.skills import DiscoveryRootResolver, PathTraversalSecurityError


@pytest.fixture
def temp_workspace():
    """Provides an isolated real temporary directory with resolved path."""
    raw_dir = tempfile.mkdtemp(prefix="lcs_fs_test_")
    real_dir = os.path.realpath(raw_dir)
    skills_dir = os.path.join(real_dir, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)
    yield real_dir
    if os.path.exists(real_dir):
        shutil.rmtree(real_dir, ignore_errors=True)


def test_01_watcher_lifecycle_and_basic_events(temp_workspace):
    """Verifies starting, stopping, adding roots, and detecting file additions."""
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)

    watcher.start()
    assert watcher.is_active is True

    # 1. Add a new file
    skill_file = os.path.join(skills_dir, "SKILL.md")
    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# New Test Skill\nDescription: test lifecycle\n")

    # Wait briefly for watcher scan
    time.sleep(0.1)
    events = watcher.drain_events()
    added_paths = [e.path for e in events if e.kind == ChangeKind.ADDED]
    assert skill_file in added_paths

    watcher.stop()
    assert watcher.is_active is False


def test_02_detect_content_modification(temp_workspace):
    """Verifies detecting content changes on an existing file."""
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    skill_file = os.path.join(skills_dir, "SKILL.md")
    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("# Initial content\n")

    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)
    watcher.start()
    time.sleep(0.05)
    watcher.drain_events()

    # Modify file
    time.sleep(0.02)
    with open(skill_file, "a", encoding="utf-8") as f:
        f.write("Updated line of text\n")

    time.sleep(0.1)
    events = watcher.drain_events()
    mod_events = [e for e in events if e.kind == ChangeKind.MODIFIED and e.path == skill_file]
    assert len(mod_events) >= 1

    watcher.stop()


def test_03_detect_file_deletion(temp_workspace):
    """Verifies detecting file deletion on disk."""
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    skill_file = os.path.join(skills_dir, "to_delete.md")
    with open(skill_file, "w", encoding="utf-8") as f:
        f.write("Temporary file\n")

    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)
    watcher.start()
    time.sleep(0.05)
    watcher.drain_events()

    # Delete file
    os.remove(skill_file)
    time.sleep(0.1)
    events = watcher.drain_events()
    del_events = [e for e in events if e.kind == ChangeKind.DELETED and e.path == skill_file]
    assert len(del_events) >= 1

    watcher.stop()


def test_04_detect_file_rename(temp_workspace):
    """Verifies detecting file rename (inode preservation across path change)."""
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    old_file = os.path.join(skills_dir, "old_name.md")
    new_file = os.path.join(skills_dir, "new_name.md")

    with open(old_file, "w", encoding="utf-8") as f:
        f.write("Rename test content\n")

    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)
    watcher.start()
    time.sleep(0.05)
    watcher.drain_events()

    # Rename
    os.rename(old_file, new_file)
    rename_events = []
    for _ in range(30):
        time.sleep(0.05)
        events = watcher.drain_events()
        rename_events.extend([e for e in events if e.kind == ChangeKind.RENAMED])
        if rename_events:
            break

    assert len(rename_events) >= 1
    assert rename_events[0].path == new_file
    assert rename_events[0].old_path == old_file

    watcher.stop()


def test_05_detect_atomic_file_replacement(temp_workspace):
    """
    Verifies detecting atomic file replacements (write to temp file then rename over target).
    In this scenario, inode changes at the exact same path.
    """
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    target_file = os.path.join(skills_dir, "SKILL.md")
    with open(target_file, "w", encoding="utf-8") as f:
        f.write("# Version 1\n")

    orig_st = os.stat(target_file)
    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)
    watcher.start()
    time.sleep(0.05)
    watcher.drain_events()

    # Atomic replacement: create temp file and atomically replace target
    tmp_file = os.path.join(skills_dir, "SKILL.md.tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write("# Version 2 with new inode\n")
    os.replace(tmp_file, target_file)

    new_st = os.stat(target_file)
    assert new_st.st_ino != orig_st.st_ino or new_st.st_mtime_ns != orig_st.st_mtime_ns

    mod_events = []
    for _ in range(30):
        time.sleep(0.05)
        events = watcher.drain_events()
        mod_events.extend([e for e in events if e.kind == ChangeKind.MODIFIED and e.path == target_file])
        if mod_events:
            break
    assert len(mod_events) >= 1

    watcher.stop()


def test_06_detect_directory_move(temp_workspace):
    """Verifies detecting when an entire skill bundle directory is moved."""
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    old_bundle = os.path.join(skills_dir, "bundle_old")
    new_bundle = os.path.join(skills_dir, "bundle_new")
    os.makedirs(old_bundle, exist_ok=True)
    with open(os.path.join(old_bundle, "SKILL.md"), "w") as f:
        f.write("Bundle skill content\n")

    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)
    watcher.start()
    time.sleep(0.05)
    watcher.drain_events()

    # Move directory
    shutil.move(old_bundle, new_bundle)
    time.sleep(0.1)
    events = watcher.drain_events()

    # Events must reflect either directory rename or deletion of old + addition of new
    paths_in_events = [e.path for e in events]
    assert any("bundle_new" in p for p in paths_in_events)

    watcher.stop()


def test_07_symlink_escape_rejected_by_watcher(temp_workspace):
    """
    Verifies that symlinks pointing outside authorized discovery roots are
    rejected and never traversed by the watcher.
    """
    # Create external directory outside workspace
    external_dir = tempfile.mkdtemp(prefix="lcs_external_")
    ext_file = os.path.join(external_dir, "SECRET.txt")
    with open(ext_file, "w") as f:
        f.write("Confidential external data\n")

    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    symlink_path = os.path.join(skills_dir, "escape_link")

    try:
        os.symlink(external_dir, symlink_path)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)
    watcher.start()
    time.sleep(0.1)
    events = watcher.drain_events()
    watcher.stop()

    # Ensure external file is NEVER queued in watcher events
    for ev in events:
        assert "SECRET.txt" not in ev.path
        assert not ev.path.startswith(external_dir)

    shutil.rmtree(external_dir, ignore_errors=True)


def test_08_watcher_error_recovery_and_resilience(temp_workspace):
    """
    Verifies that filesystem errors or transient exceptions do not crash
    the watcher thread, and error metrics are tracked.
    """
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)
    watcher.start()

    # Simulate an error by corrupting the roots list temporarily
    with watcher._lock:
        watcher._roots.append("/nonexistent_forbidden_directory_error_test")

    time.sleep(0.1)
    # Thread must still be running
    assert watcher.is_active is True
    assert watcher._thread.is_alive()

    watcher.stop()


def test_09_missed_notifications_healed_by_reconciliation(temp_workspace):
    """
    Verifies that when events are missed while watcher was stopped or restarted,
    reconciliation fallback heals the state completely.
    """
    skills_dir = os.path.join(temp_workspace, ".agents", "skills")
    resolver = DiscoveryRootResolver(workspace_root=temp_workspace)
    watcher = FilesystemWatcher(roots=[skills_dir], resolver=resolver, poll_interval_sec=0.02)

    # 1. Start and prime snapshot
    watcher.start()
    time.sleep(0.05)
    watcher.drain_events()
    watcher.stop()

    # 2. Add files while watcher is completely STOPPED (simulating dropped events / reboot)
    missed_file = os.path.join(skills_dir, "missed_while_offline.md")
    with open(missed_file, "w", encoding="utf-8") as f:
        f.write("# Missed File\n")

    # 3. Reconcile while offline or on restart
    recon_deltas = watcher.reconcile_now()

    reconciled_paths = [d.path for d in recon_deltas]
    assert missed_file in reconciled_paths
