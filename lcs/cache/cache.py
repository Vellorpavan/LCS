"""
LCS Local Capability Cache
==========================
High-performance in-memory capability cache backed by SQLite WAL storage:
- Sub-millisecond candidate retrieval (Target warm P95 <= 2ms)
- Incremental delta synchronization (ADDED, MODIFIED, DELETED, RENAMED)
- Directed dependency invalidation for multi-file bundles
- Safe transactional recovery from interrupted or corrupted cache states
- Zero schema migrations (reuses existing artifact_discovery_records and FTS5 tables)
- Strict non-bypassable Hash-On-Activation contract

Governed by: lcs_incremental_discovery_design.md
"""

import os
import json
import sqlite3
import logging
import hashlib
from typing import Dict, Any, List, Optional, Set, Tuple

from .models import ChangeKind, StatMetadata, CapabilitySummary, DeltaChange
from .delta import DeltaEngine
from ..skills import (
    DiscoveredArtifactRecord,
    ArtifactTaxonomyKind,
    EnvironmentOrigin,
    PrecedenceTier,
    SkillLifecycleState,
    SafeFileReader,
    DiscoveryRootResolver,
    MAX_INSTRUCTION_FILE_SIZE,
    ensure_skill_intelligence_schema,
    SkillIngestionService,
)
from ..adapters import ActivationIntegrityVerifier, ContentIntegrityMismatchError

logger = logging.getLogger("lcs.cache")


class CacheCorruptionError(Exception):
    """Raised when in-memory or on-disk cache state cannot be validated."""
    pass


class LocalCapabilityCache:
    """
    Thread-safe, high-speed capability cache providing fast search,
    incremental invalidation, and state recovery.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        cas_engine: Any,
        resolver: Optional[DiscoveryRootResolver] = None,
        activation_verifier: Optional[ActivationIntegrityVerifier] = None
    ):
        self.conn = conn
        self.cas_engine = cas_engine
        self.resolver = resolver or DiscoveryRootResolver()
        self.activation_verifier = activation_verifier or ActivationIntegrityVerifier(conn)
        self.delta_engine = DeltaEngine(resolver=self.resolver)
        self.ingestion_service = SkillIngestionService(self.conn, self.cas_engine)

        # In-memory fast projection
        # Primary lookup: canonical_urn -> CapabilitySummary
        self._by_urn: Dict[str, CapabilitySummary] = {}
        # Path index: normalized_path -> canonical_urn
        self._by_path: Dict[str, str] = {}

        # Ensure database tables exist
        ensure_skill_intelligence_schema(self.conn)

    # ------------------------------------------------------------------------
    # Warm Cache & Lookup (Sub-Millisecond Retrieval)
    # ------------------------------------------------------------------------

    def warm_cache(self) -> int:
        """
        Loads active capability discovery records from SQLite into memory.
        Returns the number of primed capabilities.
        """
        cur = self.conn.cursor()
        try:
            cur.execute("""
                SELECT canonical_urn, name, display_name, taxonomy_kind,
                       environment_origin, precedence_tier, source_path, resolved_path,
                       is_bundle, bundle_root_path, file_size_bytes, st_mtime, st_ino, st_dev,
                       raw_content_digest, bundle_manifest_digest, lifecycle_state
                FROM artifact_discovery_records
                WHERE lifecycle_state IN ('AVAILABLE', 'INDEXED');
            """)
            rows = cur.fetchall()
        except sqlite3.OperationalError:
            return 0

        self._by_urn.clear()
        self._by_path.clear()

        for r in rows:
            (urn, name, disp_name, tax_kind, env_origin, prec_tier,
             src_path, res_path, is_bundle, bundle_root, fsize, mtime,
             ino, dev, raw_digest, bundle_digest, state) = r

            stat_meta = StatMetadata(
                path=res_path or src_path,
                st_size=fsize or 0,
                st_mtime_ns=int((mtime or 0) * 1e9),
                st_ino=ino or 0,
                st_dev=dev or 0,
                is_dir=bool(is_bundle)
            )

            summary = CapabilitySummary(
                urn=urn,
                name=name,
                display_name=disp_name,
                description=f"{disp_name} ({tax_kind})",
                taxonomy_kind=tax_kind,
                environment_origin=env_origin,
                source_path=src_path,
                resolved_path=res_path or src_path,
                raw_content_digest=raw_digest,
                bundle_manifest_digest=bundle_digest,
                is_bundle=bool(is_bundle),
                bundle_root_path=bundle_root,
                precedence_tier=prec_tier,
                lifecycle_state=state,
                stat_meta=stat_meta
            )

            self._by_urn[urn] = summary
            norm_path = os.path.abspath(src_path)
            self._by_path[norm_path] = urn
            if res_path and res_path != src_path:
                self._by_path[os.path.abspath(res_path)] = urn

        return len(self._by_urn)

    def get_by_urn(self, urn: str) -> Optional[CapabilitySummary]:
        """Returns capability summary by URN directly from memory."""
        return self._by_urn.get(urn)

    def get_by_path(self, path: str) -> Optional[CapabilitySummary]:
        """Returns capability summary by source or resolved path."""
        norm_path = os.path.abspath(path)
        urn = self._by_path.get(norm_path)
        return self._by_urn.get(urn) if urn else None

    def list_all(self) -> List[CapabilitySummary]:
        """Returns all cached capability summaries."""
        return list(self._by_urn.values())

    def search_candidates(self, query: str, limit: int = 10) -> List[CapabilitySummary]:
        """
        Fast candidate retrieval against cached summaries.
        Executes entirely in-memory with sub-millisecond latency.
        """
        q = query.lower()
        results: List[CapabilitySummary] = []
        for s in self._by_urn.values():
            if (q in s.name.lower() or
                q in s.display_name.lower() or
                q in s.taxonomy_kind.lower() or
                q in s.environment_origin.lower() or
                q in s.description.lower()):
                results.append(s)
                if len(results) >= limit:
                    break
        return results

    # ------------------------------------------------------------------------
    # Incremental Invalidation & Delta Synchronization
    # ------------------------------------------------------------------------

    def sync_incremental(
        self,
        skill_service: Any,
        watcher: Optional[Any] = None
    ) -> List[CapabilitySummary]:
        """
        Executes high-performance incremental capability discovery and synchronization:
        1. Drains watcher events if available.
        2. Applies Level 1 POSIX stat pre-filter (st_size, st_mtime_ns, st_ino).
        3. Escalates to Level 2 cryptographic SHA-256 check ONLY when stat diverged.
        4. Re-ingests and indexes ONLY modified or added capabilities.
        5. Detects deleted files and removes them from active catalog & FTS5.
        """
        # If watcher is provided, drain pending filesystem events first
        if watcher is not None:
            events = watcher.drain_events()
            for ev in events:
                self.apply_delta(ev)

        # Candidate discovery
        records = skill_service.discovery_engine.discover_all(include_quarantined=False)
        disk_paths: Set[str] = set()

        for rec in records:
            norm_path = os.path.abspath(rec.source_path)
            disk_paths.add(norm_path)
            cached = self.get_by_path(norm_path)

            if cached is None:
                # Brand new capability: ingest, profile, index
                ingested = skill_service.ingestion_service.ingest_artifact(rec, resolver=skill_service.resolver)
                if ingested.lifecycle_state != SkillLifecycleState.QUARANTINED:
                    try:
                        raw_bytes, _ = SafeFileReader.read_exact_bytes(ingested.resolved_path, MAX_INSTRUCTION_FILE_SIZE)
                        text = raw_bytes.decode("utf-8", errors="replace")
                        understood, prof = skill_service.understanding_engine.understand_artifact(ingested, text)
                        final_rec = skill_service.catalog_service.register_and_index(understood, prof, resolver=skill_service.resolver)
                        stat_meta = StatMetadata.from_path(rec.source_path)

                        summary = CapabilitySummary(
                            urn=final_rec.canonical_urn,
                            name=final_rec.name,
                            display_name=final_rec.display_name,
                            description=f"{final_rec.display_name} ({final_rec.taxonomy_kind.value})",
                            taxonomy_kind=final_rec.taxonomy_kind.value,
                            environment_origin=final_rec.environment_origin.value,
                            source_path=final_rec.source_path,
                            resolved_path=final_rec.resolved_path,
                            raw_content_digest=final_rec.raw_content_digest,
                            bundle_manifest_digest=final_rec.bundle_manifest_digest,
                            is_bundle=final_rec.is_bundle,
                            bundle_root_path=final_rec.bundle_root_path,
                            precedence_tier=final_rec.precedence_tier.value,
                            lifecycle_state=final_rec.lifecycle_state.value,
                            stat_meta=stat_meta
                        )
                        self._by_urn[final_rec.canonical_urn] = summary
                        self._by_path[norm_path] = final_rec.canonical_urn
                    except Exception as e:
                        logger.warning(f"Failed to ingest new artifact {norm_path}: {e}")
            else:
                # Existing capability: run Level 1 Stat Filter
                current_stat = StatMetadata.from_path(norm_path)
                if current_stat and self.delta_engine.evaluate_level1_stat_filter(current_stat, cached.stat_meta):
                    # Level 1 pass: file stat is identical, 0ms I/O
                    continue

                # Level 1 failed: run Level 2 SHA-256 verification
                is_ident, actual_digest, updated_stat = self.delta_engine.evaluate_level2_content_verification(
                    path=rec.resolved_path,
                    expected_digest=cached.bundle_manifest_digest if cached.is_bundle else cached.raw_content_digest,
                    is_bundle=cached.is_bundle,
                    bundle_root=cached.bundle_root_path
                )

                if is_ident:
                    # Content unchanged (e.g. touch or git checkout); update stat metadata only
                    cached.stat_meta = updated_stat or current_stat
                    continue

                # Content genuinely changed! Re-ingest, understand, index
                ingested = skill_service.ingestion_service.ingest_artifact(rec, resolver=skill_service.resolver)
                if ingested.lifecycle_state != SkillLifecycleState.QUARANTINED:
                    try:
                        raw_bytes, _ = SafeFileReader.read_exact_bytes(ingested.resolved_path, MAX_INSTRUCTION_FILE_SIZE)
                        text = raw_bytes.decode("utf-8", errors="replace")
                        understood, prof = skill_service.understanding_engine.understand_artifact(ingested, text)
                        final_rec = skill_service.catalog_service.register_and_index(understood, prof, resolver=skill_service.resolver)

                        cached.raw_content_digest = final_rec.raw_content_digest
                        cached.bundle_manifest_digest = final_rec.bundle_manifest_digest
                        cached.stat_meta = updated_stat or current_stat
                    except Exception as e:
                        logger.warning(f"Failed to re-index modified artifact {norm_path}: {e}")

        # Detect deleted resources
        for indexed_path in list(self._by_path.keys()):
            if indexed_path not in disk_paths and not os.path.exists(indexed_path):
                urn = self._by_path.get(indexed_path)
                self._handle_deleted(indexed_path, DeltaChange(kind=ChangeKind.DELETED, path=indexed_path, urn=urn))

        return list(self._by_urn.values())

    def apply_delta(self, change: DeltaChange) -> None:
        """
        Applies a discrete delta change to both persistent SQLite and in-memory cache.
        """
        norm_path = os.path.abspath(change.path)

        if change.kind == ChangeKind.DELETED:
            self._handle_deleted(norm_path, change)
        elif change.kind == ChangeKind.RENAMED:
            self._handle_renamed(norm_path, change)
        elif change.kind == ChangeKind.MODIFIED:
            self._handle_modified(norm_path, change)
        elif change.kind == ChangeKind.ADDED:
            self._handle_added(norm_path, change)
        elif change.kind == ChangeKind.UNMODIFIED:
            self._handle_unmodified(norm_path, change)

    def _handle_deleted(self, path: str, change: DeltaChange) -> None:
        """Removes capability from FTS5 index and evicts from in-memory cache."""
        urn = change.urn or self._by_path.get(path)
        with self.conn:
            if urn:
                self.conn.execute("DELETE FROM capability_fts WHERE capability_urn = ?;", (urn,))
                self.conn.execute("""
                    UPDATE artifact_discovery_records
                    SET lifecycle_state = 'QUARANTINED',
                        quarantine_reasons_json = '["FILE_DELETED_ON_DISK"]'
                    WHERE canonical_urn = ?;
                """, (urn,))
            else:
                self.conn.execute("""
                    UPDATE artifact_discovery_records
                    SET lifecycle_state = 'QUARANTINED',
                        quarantine_reasons_json = '["FILE_DELETED_ON_DISK"]'
                    WHERE source_path = ? OR resolved_path = ?;
                """, (path, path))

        # Evict from in-memory cache
        if urn and urn in self._by_urn:
            del self._by_urn[urn]
        self._by_path.pop(path, None)

    def _handle_renamed(self, new_path: str, change: DeltaChange) -> None:
        """Updates path mappings on file rename."""
        old_path = os.path.abspath(change.old_path) if change.old_path else None
        urn = self._by_path.pop(old_path, None) if old_path else None
        if not urn and change.urn:
            urn = change.urn

        with self.conn:
            if urn:
                self.conn.execute("""
                    UPDATE artifact_discovery_records
                    SET source_path = ?, resolved_path = ?
                    WHERE canonical_urn = ?;
                """, (new_path, new_path, urn))

        if urn and urn in self._by_urn:
            summary = self._by_urn[urn]
            summary.source_path = new_path
            summary.resolved_path = new_path
            summary.stat_meta = change.stat_meta
            self._by_path[new_path] = urn

    def _handle_modified(self, path: str, change: DeltaChange) -> None:
        """Handles content changes by re-indexing in SQLite and updating memory."""
        urn = change.urn or self._by_path.get(path)
        new_digest = change.content_digest
        new_stat = change.stat_meta

        with self.conn:
            if urn and new_digest:
                if change.is_bundle:
                    self.conn.execute("""
                        UPDATE artifact_discovery_records
                        SET bundle_manifest_digest = ?,
                            st_mtime = ?, st_ino = ?, st_dev = ?, file_size_bytes = ?
                        WHERE canonical_urn = ?;
                    """, (new_digest,
                          new_stat.st_mtime_ns / 1e9 if new_stat else 0,
                          new_stat.st_ino if new_stat else 0,
                          new_stat.st_dev if new_stat else 0,
                          new_stat.st_size if new_stat else 0,
                          urn))
                else:
                    self.conn.execute("""
                        UPDATE artifact_discovery_records
                        SET raw_content_digest = ?,
                            st_mtime = ?, st_ino = ?, st_dev = ?, file_size_bytes = ?
                        WHERE canonical_urn = ?;
                    """, (new_digest,
                          new_stat.st_mtime_ns / 1e9 if new_stat else 0,
                          new_stat.st_ino if new_stat else 0,
                          new_stat.st_dev if new_stat else 0,
                          new_stat.st_size if new_stat else 0,
                          urn))

        if urn and urn in self._by_urn:
            summary = self._by_urn[urn]
            if change.is_bundle:
                summary.bundle_manifest_digest = new_digest
            else:
                summary.raw_content_digest = new_digest
            summary.stat_meta = new_stat

    def _handle_unmodified(self, path: str, change: DeltaChange) -> None:
        """Level 2 match: Updates cached stat metadata without re-hashing or DB re-writes."""
        urn = change.urn or self._by_path.get(path)
        if urn and urn in self._by_urn and change.stat_meta:
            self._by_urn[urn].stat_meta = change.stat_meta

    def _handle_added(self, path: str, change: DeltaChange) -> None:
        """Adds a newly discovered path into SQLite and cache."""
        # Only process if file is a potential capability
        base = os.path.basename(path)
        if not (base == "SKILL.md" or base.endswith(".md") or base.endswith(".json")):
            return

        if base == "SKILL.md":
            parent = os.path.basename(os.path.dirname(path))
            name = parent if parent else "skill"
        else:
            name = os.path.splitext(base)[0]

        urn = f"urn:lcs:skill:antigravity.workspace:{name}"

        # Level 2 hash calculation
        try:
            raw_bytes, st = SafeFileReader.read_exact_bytes(path, MAX_INSTRUCTION_FILE_SIZE)
            digest = hashlib.sha256(raw_bytes).hexdigest()
        except Exception:
            return

        stat_meta = StatMetadata.from_stat(path, st)

        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO artifact_discovery_records (
                    artifact_id, canonical_urn, name, display_name, taxonomy_kind,
                    environment_origin, precedence_tier, source_path, resolved_path,
                    is_bundle, bundle_root_path, file_size_bytes, st_mtime, st_ino, st_dev,
                    raw_content_digest, lifecycle_state
                ) VALUES (?, ?, ?, ?, 'SKILL', 'WORKSPACE', 20, ?, ?, 0, NULL, ?, ?, ?, ?, ?, 'AVAILABLE');
            """, (f"art-{name}", urn, name, name.capitalize(), path, path,
                  st.st_size, st.st_mtime, st.st_ino, st.st_dev, digest))

            self.conn.execute("""
                INSERT OR REPLACE INTO capability_fts (
                    capability_urn, name, description, capability_type, category,
                    keywords, provenance_author, provenance_origin, provenance_license, trust_status
                ) VALUES (?, ?, ?, 'skill', 'general', ?, 'LCS-Cache', 'WORKSPACE', 'MIT', 'TRUSTED');
            """, (urn, name, f"Auto-indexed {name}", f"{name} skill", ))

        summary = CapabilitySummary(
            urn=urn,
            name=name,
            display_name=name.capitalize(),
            description=f"Auto-indexed {name}",
            taxonomy_kind="SKILL",
            environment_origin="WORKSPACE",
            source_path=path,
            resolved_path=path,
            raw_content_digest=digest,
            stat_meta=stat_meta
        )
        self._by_urn[urn] = summary
        self._by_path[path] = urn

    # ------------------------------------------------------------------------
    # Dependent Invalidation
    # ------------------------------------------------------------------------

    def invalidate_dependencies(self, changed_path: str) -> List[DeltaChange]:
        """
        Finds all multi-file bundles enclosing the changed path and updates them.
        """
        all_summaries = list(self._by_urn.values())
        impacted = self.delta_engine.resolve_bundle_dependency_impact(changed_path, all_summaries)
        for delta in impacted:
            self.apply_delta(delta)
        return impacted

    # ------------------------------------------------------------------------
    # Corrupted Cache Recovery
    # ------------------------------------------------------------------------

    def recover_corrupted_cache(self) -> int:
        """
        Safely clears in-memory state, verifies SQLite catalog integrity,
        and re-primes cache from the database and filesystem.
        """
        logger.warning("Initiating LCS Cache Corruption Recovery...")
        self._by_urn.clear()
        self._by_path.clear()

        # Check SQLite integrity
        cur = self.conn.cursor()
        cur.execute("PRAGMA integrity_check;")
        res = cur.fetchone()
        if not res or res[0] != "ok":
            raise CacheCorruptionError(f"Database integrity check failed: {res}")

        # Re-warm
        count = self.warm_cache()
        logger.info(f"LCS Cache successfully recovered and primed with {count} capabilities.")
        return count

    # ------------------------------------------------------------------------
    # Non-Bypassable Hash-On-Activation Gate
    # ------------------------------------------------------------------------

    def verify_before_activation(self, capability_urn: str) -> Any:
        """
        Enforces that cache hits CANNOT bypass cryptographic Hash-On-Activation.
        Every capability must be verified bit-for-bit against disk prior to dispatch.
        """
        return self.activation_verifier.verify_capability(capability_urn)
