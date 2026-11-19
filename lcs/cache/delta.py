"""
LCS Delta Invalidation Engine
=============================
Implements the formal two-level invalidation architecture:
- Level 1: Heuristic POSIX stat metadata pre-filter (st_size, st_mtime_ns, st_ino)
- Level 2: Cryptographic SHA-256 content verification (SafeFileReader descriptor-relative O_NOFOLLOW)

Governed by: lcs_incremental_discovery_design.md
Invariants:
- Metadata checks NEVER establish cryptographic integrity.
- Hash-On-Activation remains mandatory prior to capability dispatch.
"""

import os
import hashlib
from typing import Dict, Any, List, Optional, Set, Tuple, Union

from .models import ChangeKind, StatMetadata, CapabilitySummary, DeltaChange
from ..skills import (
    SafeFileReader,
    BundleManifestHasher,
    DiscoveryRootResolver,
    MAX_INSTRUCTION_FILE_SIZE,
    DescriptorSecurityError,
    PathTraversalSecurityError,
)


class DeltaEngine:
    """
    Coordinates two-level change detection, dependency graph bubbling,
    and cache invalidation across discovered capabilities.
    """

    def __init__(self, resolver: Optional[DiscoveryRootResolver] = None):
        self.resolver = resolver or DiscoveryRootResolver()

    # ------------------------------------------------------------------------
    # Level 1: Stat Pre-Check (Heuristic Filter)
    # ------------------------------------------------------------------------

    def evaluate_level1_stat_filter(
        self,
        current_stat: Optional[StatMetadata],
        cached_stat: Optional[StatMetadata]
    ) -> bool:
        """
        Level 1 Check: Evaluates POSIX filesystem metadata.
        Returns True if metadata indicates file is PROBABLY UNCHANGED (Level 1 Pass).
        Returns False if metadata changed or missing, indicating Level 2 revalidation is REQUIRED.

        Security Invariant: A True result is an opportunistic optimization for discovery search
        and NEVER guarantees cryptographic content integrity.
        """
        if current_stat is None or cached_stat is None:
            return False
        return current_stat.matches(cached_stat)

    # ------------------------------------------------------------------------
    # Level 2: Cryptographic Content Verification
    # ------------------------------------------------------------------------

    def evaluate_level2_content_verification(
        self,
        path: str,
        expected_digest: str,
        is_bundle: bool = False,
        bundle_root: Optional[str] = None
    ) -> Tuple[bool, str, Optional[StatMetadata]]:
        """
        Level 2 Check: Streams raw file bytes via descriptor-relative O_NOFOLLOW
        and computes SHA-256 (or computes Merkle bundle digest for directory bundles).

        Returns:
            (is_identical: bool, actual_digest: str, new_stat: Optional[StatMetadata])
        """
        # 1. Confinement check
        self.resolver.assert_path_confined(path)

        # 2. Case A: Directory bundle
        if is_bundle:
            root = bundle_root or path
            self.resolver.assert_path_confined(root)
            actual_digest, _, _ = BundleManifestHasher.compute_bundle_manifest(root, resolver=self.resolver)
            current_stat = StatMetadata.from_path(root)
            return (actual_digest == expected_digest, actual_digest, current_stat)

        # 3. Case B: Single-file artifact
        raw_bytes, st = SafeFileReader.read_exact_bytes(path, MAX_INSTRUCTION_FILE_SIZE)
        actual_digest = hashlib.sha256(raw_bytes).hexdigest()
        current_stat = StatMetadata.from_stat(path, st)

        return (actual_digest == expected_digest, actual_digest, current_stat)

    # ------------------------------------------------------------------------
    # Delta Evaluation Pipeline
    # ------------------------------------------------------------------------

    def detect_file_delta(
        self,
        path: str,
        cached_summary: Optional[CapabilitySummary]
    ) -> DeltaChange:
        """
        Evaluates a single path against cached state through Level 1 and Level 2.
        """
        current_stat = StatMetadata.from_path(path)

        # 1. File does not exist on disk
        if current_stat is None:
            if cached_summary is not None:
                return DeltaChange(
                    kind=ChangeKind.DELETED,
                    path=path,
                    urn=cached_summary.urn,
                    stat_meta=None,
                    old_content_digest=cached_summary.raw_content_digest,
                    is_bundle=cached_summary.is_bundle,
                    bundle_root=cached_summary.bundle_root_path
                )
            return DeltaChange(kind=ChangeKind.UNMODIFIED, path=path)

        # 2. File is brand new (not in cache)
        if cached_summary is None:
            # We don't hash eagerly for Level 1; Level 2 can be computed when needed
            return DeltaChange(
                kind=ChangeKind.ADDED,
                path=path,
                stat_meta=current_stat
            )

        # 3. Level 1 Evaluation: Compare stat
        cached_stat = cached_summary.stat_meta
        if self.evaluate_level1_stat_filter(current_stat, cached_stat):
            # Stat matches: fast skip for discovery/search
            return DeltaChange(
                kind=ChangeKind.UNMODIFIED,
                path=path,
                urn=cached_summary.urn,
                stat_meta=current_stat,
                content_digest=cached_summary.raw_content_digest,
                is_bundle=cached_summary.is_bundle,
                bundle_root=cached_summary.bundle_root_path
            )

        # 4. Stat differs: Level 2 Cryptographic SHA-256 Verification
        try:
            is_identical, actual_digest, updated_stat = self.evaluate_level2_content_verification(
                path=cached_summary.resolved_path or path,
                expected_digest=cached_summary.bundle_manifest_digest if cached_summary.is_bundle else cached_summary.raw_content_digest,
                is_bundle=cached_summary.is_bundle,
                bundle_root=cached_summary.bundle_root_path
            )
        except Exception:
            # If reading fails (e.g. permission or descriptor error), mark as modified/tampered
            is_identical = False
            actual_digest = "ERR_READ_FAILED"
            updated_stat = current_stat

        if is_identical:
            # Content is bit-for-bit identical, but stat changed (e.g. touch or git checkout)
            # Return UNMODIFIED with the refreshed stat_meta so cache can touch its stat
            return DeltaChange(
                kind=ChangeKind.UNMODIFIED,
                path=path,
                urn=cached_summary.urn,
                stat_meta=updated_stat or current_stat,
                content_digest=actual_digest,
                is_bundle=cached_summary.is_bundle,
                bundle_root=cached_summary.bundle_root_path
            )

        # Content changed!
        return DeltaChange(
            kind=ChangeKind.MODIFIED,
            path=path,
            urn=cached_summary.urn,
            stat_meta=updated_stat or current_stat,
            content_digest=actual_digest,
            old_content_digest=cached_summary.raw_content_digest,
            is_bundle=cached_summary.is_bundle,
            bundle_root=cached_summary.bundle_root_path
        )

    # ------------------------------------------------------------------------
    # Dependency Graph Invalidation
    # ------------------------------------------------------------------------

    def resolve_bundle_dependency_impact(
        self,
        changed_path: str,
        active_summaries: List[CapabilitySummary]
    ) -> List[DeltaChange]:
        """
        When a nested asset (e.g. scripts/run.py or references/schema.json) is modified,
        finds all parent bundles that depend on or enclose this path, and produces
        invalidation delta events for the parent bundles.
        """
        norm_changed = os.path.abspath(changed_path)
        impacted_deltas: List[DeltaChange] = []

        for summary in active_summaries:
            if not summary.is_bundle or not summary.bundle_root_path:
                continue

            bundle_root = os.path.abspath(summary.bundle_root_path)
            # Check if changed_path is within bundle_root or declared in summary.dependencies
            is_enclosed = (
                norm_changed == bundle_root
                or norm_changed.startswith(bundle_root + os.sep)
            )
            is_explicit_dep = any(
                os.path.abspath(dep) == norm_changed for dep in summary.dependencies
            )

            if is_enclosed or is_explicit_dep:
                # Re-compute bundle digest
                try:
                    new_digest, _, _ = BundleManifestHasher.compute_bundle_manifest(
                        bundle_root, resolver=self.resolver
                    )
                except Exception:
                    new_digest = "ERR_BUNDLE_HASH_FAILED"

                impacted_deltas.append(DeltaChange(
                    kind=ChangeKind.MODIFIED,
                    path=summary.source_path,
                    urn=summary.urn,
                    stat_meta=StatMetadata.from_path(bundle_root),
                    content_digest=new_digest,
                    old_content_digest=summary.bundle_manifest_digest or summary.raw_content_digest,
                    is_bundle=True,
                    bundle_root=bundle_root,
                    affected_dependencies=[changed_path]
                ))

        return impacted_deltas
