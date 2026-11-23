"""
LCS Filesystem Watcher
======================
Implements resilient in-process capability root monitoring with:
- Multi-root tracking without external daemons
- Event detection: ADDED, MODIFIED, DELETED, RENAMED, and atomic file replacements
- Symlink confinement enforcement (O_NOFOLLOW / assert_path_confined)
- Automatic error recovery and restart on filesystem errors
- Periodic / on-demand reconciliation fallback (os.scandir)

Governed by: lcs_incremental_discovery_design.md & lcs_filesystem_regression_test_spec.md
"""

import os
import stat
import time
import queue
import logging
import threading
from typing import Dict, Any, List, Optional, Set, Tuple

from .models import ChangeKind, StatMetadata, DeltaChange
from ..skills import DiscoveryRootResolver, PathTraversalSecurityError

logger = logging.getLogger("lcs.cache.watcher")


class WatcherError(Exception):
    """Base exception for LCS Filesystem Watcher."""
    pass


class FilesystemWatcher:
    """
    In-process, low-overhead filesystem watcher for capability directories.
    Provides non-blocking event consumption with robust error recovery.
    """

    def __init__(
        self,
        roots: Optional[List[str]] = None,
        resolver: Optional[DiscoveryRootResolver] = None,
        poll_interval_sec: float = 0.05,
        reconciliation_interval_sec: float = 300.0,
        event_queue_maxsize: int = 10000
    ):
        self.resolver = resolver or DiscoveryRootResolver()
        self._roots: List[str] = [os.path.abspath(r) for r in (roots or [])]
        self._poll_interval = poll_interval_sec
        self._reconciliation_interval = reconciliation_interval_sec

        # Snapshot state: path -> StatMetadata
        self._snapshot: Dict[str, StatMetadata] = {}
        # Inode lookup for rename tracking: (st_ino, st_dev) -> path
        self._inode_map: Dict[Tuple[int, int], str] = {}

        # Concurrency & control
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._event_queue: queue.Queue = queue.Queue(maxsize=event_queue_maxsize)

        # Health & Telemetry
        self.is_active: bool = False
        self.error_count: int = 0
        self.last_error: Optional[str] = None
        self.last_scan_time: float = 0.0
        self.last_reconciliation_time: float = 0.0
        self.scans_completed: int = 0

    # ------------------------------------------------------------------------
    # Lifecycle Management
    # ------------------------------------------------------------------------

    def add_root(self, path: str) -> None:
        """Adds a directory root to the watched set after confinement check."""
        abs_path = os.path.abspath(path)
        self.resolver.assert_path_confined(abs_path)
        with self._lock:
            if abs_path not in self._roots:
                self._roots.append(abs_path)

    def remove_root(self, path: str) -> None:
        """Removes a directory root from the watched set."""
        abs_path = os.path.abspath(path)
        with self._lock:
            if abs_path in self._roots:
                self._roots.remove(abs_path)
                # Purge paths under this root from snapshot
                to_remove = [p for p in self._snapshot if p.startswith(abs_path)]
                for p in to_remove:
                    stat_meta = self._snapshot.pop(p, None)
                    if stat_meta:
                        self._inode_map.pop((stat_meta.st_ino, stat_meta.st_dev), None)

    def start(self) -> None:
        """Starts the background monitoring thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            # Initial snapshot prime
            self._scan_all_roots()
            self._thread = threading.Thread(target=self._run_loop, name="LCS-FS-Watcher", daemon=True)
            self._thread.start()
            self.is_active = True

    def stop(self, timeout_sec: float = 2.0) -> None:
        """Signals the background monitoring thread to stop and waits for join."""
        self._stop_event.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout_sec)
        with self._lock:
            self.is_active = False
            self._thread = None

    def drain_events(self, max_events: int = 1000) -> List[DeltaChange]:
        """Drains pending change events from the event queue non-blockingly."""
        events: List[DeltaChange] = []
        while len(events) < max_events:
            try:
                ev = self._event_queue.get_nowait()
                events.append(ev)
                self._event_queue.task_done()
            except queue.Empty:
                break
        return events

    # ------------------------------------------------------------------------
    # Scanning & Event Generation
    # ------------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Main worker loop with resilient error recovery."""
        while not self._stop_event.is_set():
            try:
                now = time.monotonic()
                # Check if periodic reconciliation is due
                if (now - self.last_reconciliation_time) >= self._reconciliation_interval:
                    self._reconcile_full_scan()
                    self.last_reconciliation_time = now
                else:
                    self._scan_all_roots()

                self.scans_completed += 1
                self.last_scan_time = now
            except Exception as e:
                # Catch-all error recovery: do not let unexpected exceptions crash the thread
                self.error_count += 1
                self.last_error = str(e)
                logger.warning(f"LCS FilesystemWatcher error: {e}. Recovering...")
                # Short pause to prevent spin loops on persistent error
                time.sleep(0.2)

            # Sleep poll interval with interrupt awareness
            self._stop_event.wait(timeout=self._poll_interval)

    def _scan_all_roots(self) -> List[DeltaChange]:
        """
        Walks watched directory roots, compares against current snapshot,
        and generates DeltaChange events.
        """
        current_stats: Dict[str, StatMetadata] = {}
        new_inode_map: Dict[Tuple[int, int], str] = {}
        deltas: List[DeltaChange] = []

        with self._lock:
            active_roots = list(self._roots)

        for root in active_roots:
            if not os.path.exists(root):
                continue
            try:
                self._walk_directory(root, current_stats, new_inode_map)
            except Exception as e:
                logger.debug(f"Scan error in root {root}: {e}")

        with self._lock:
            prev_snapshot = self._snapshot
            prev_inodes = self._inode_map

            # 1. Detect Deleted or Renamed resources
            for old_path, old_stat in prev_snapshot.items():
                if old_path not in current_stats:
                    # Check if inode still exists at another path (Rename detection)
                    new_path = None
                    if old_stat.st_ino != 0:
                        key = (old_stat.st_ino, old_stat.st_dev)
                        new_path = new_inode_map.get(key)
                    if new_path and new_path != old_path:
                        deltas.append(DeltaChange(
                            kind=ChangeKind.RENAMED,
                            path=new_path,
                            old_path=old_path,
                            stat_meta=current_stats.get(new_path)
                        ))
                    else:
                        deltas.append(DeltaChange(
                            kind=ChangeKind.DELETED,
                            path=old_path,
                            stat_meta=None
                        ))

            # 2. Detect Added or Modified resources
            for curr_path, curr_stat in current_stats.items():
                if curr_path not in prev_snapshot:
                    # If this was already emitted as RENAMED in step 1, skip duplicate ADDED
                    if curr_stat.st_ino != 0:
                        key = (curr_stat.st_ino, curr_stat.st_dev)
                        if key in prev_inodes and prev_inodes[key] != curr_path:
                            continue
                    deltas.append(DeltaChange(
                        kind=ChangeKind.ADDED,
                        path=curr_path,
                        stat_meta=curr_stat
                    ))
                else:
                    old_stat = prev_snapshot[curr_path]
                    # Check Level 1 Stat divergence (size, mtime_ns, inode)
                    # Notice: inode change at the same path indicates an ATOMIC REPLACEMENT
                    if not curr_stat.matches(old_stat):
                        deltas.append(DeltaChange(
                            kind=ChangeKind.MODIFIED,
                            path=curr_path,
                            stat_meta=curr_stat
                        ))

            # Commit new snapshot
            self._snapshot = current_stats
            self._inode_map = new_inode_map

        # Enqueue events
        for d in deltas:
            try:
                self._event_queue.put_nowait(d)
            except queue.Full:
                logger.warning("LCS FilesystemWatcher event queue full; dropping event.")

        return deltas

    def _walk_directory(
        self,
        dir_path: str,
        out_stats: Dict[str, StatMetadata],
        out_inodes: Dict[Tuple[int, int], str],
        depth: int = 0,
        max_depth: int = 5
    ) -> None:
        """
        Fast recursive directory traversal using os.scandir with symlink containment.
        """
        if depth > max_depth:
            return

        try:
            with os.scandir(dir_path) as it:
                for entry in it:
                    # Symlink security check: assert path remains confined
                    try:
                        # follow_symlinks=False prevents symlink traversal escaping root
                        st = entry.stat(follow_symlinks=False)
                    except (FileNotFoundError, OSError):
                        continue

                    # If symlink, verify target is confined
                    if entry.is_symlink():
                        try:
                            resolved = self.resolver.assert_path_confined(entry.path)
                            # If resolved is a directory, do NOT follow symlink directory into deep recursion
                            continue
                        except PathTraversalSecurityError:
                            # Skip unconfined symlinks
                            continue

                    norm_path = os.path.abspath(entry.path)
                    stat_meta = StatMetadata.from_stat(norm_path, st, is_dir=entry.is_dir(follow_symlinks=False))
                    out_stats[norm_path] = stat_meta
                    if stat_meta.st_ino != 0:
                        out_inodes[(stat_meta.st_ino, stat_meta.st_dev)] = norm_path

                    if entry.is_dir(follow_symlinks=False):
                        self._walk_directory(entry.path, out_stats, out_inodes, depth + 1, max_depth)
        except (PermissionError, NotADirectoryError, FileNotFoundError, OSError):
            return

    # ------------------------------------------------------------------------
    # Fallback Reconciliation
    # ------------------------------------------------------------------------

    def reconcile_now(self) -> List[DeltaChange]:
        """
        Forces an immediate synchronous scan across all watched roots
        and returns all detected delta changes (reconciliation fallback).
        """
        return self._scan_all_roots()

    def _reconcile_full_scan(self) -> List[DeltaChange]:
        """Internal handler for scheduled periodic reconciliation."""
        logger.debug("Running periodic scheduled reconciliation scan...")
        return self._scan_all_roots()
