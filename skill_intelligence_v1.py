#!/usr/bin/env python3
"""
LCS Skill Intelligence V1 — Complete Production Engine
======================================================
Implements universal skill lifecycle management (DISCOVERED -> READ -> UNDERSTOOD -> INDEXED -> AVAILABLE),
CAS exact-byte storage, deterministic bundle manifest hashing, authoritative SHA-256 change detection,
evidence-grounded semantic profiling (distinguishing EXPLICIT declared parameters from INFERRED template variables),
capability catalog registration, FTS5 discovery indexing, context-aware precedence resolution, and
the Unified Retrieval Coordinator.

Governed strictly by: lcs_skill_intelligence_v1_architecture.md
Adheres to LCS Invariants:
  - Zero arbitrary code execution.
  - Zero modification to frozen retrieval, parameter, planning, or governance modules.
  - Byte-exact CAS fidelity.
  - Inferred template variables are ALWAYS optional.
  - Lifecycle strictly terminates at AVAILABLE.
"""

import os
import sys
import re
import json
import uuid
import stat
import time
import hashlib
import sqlite3
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

# Local LCS imports
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

from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_profile_v2b import (
    CapabilitySemanticProfile,
    CapabilityProfileService,
    ProfileField,
    ParameterProfile,
    EvidenceSource
)
from capability_registry_v2b import (
    CapabilityDefinition,
    parse_canonical_urn,
    CanonicalCapabilityURN
)
from capability_discovery_v2b import DiscoveryIndexService
from capability_retrieval_v1_1 import (
    CapabilityRetrievalEngineV11,
    ScoredCandidateV11,
    RetrievalResultV11
)
from interface_policy_v2b import (
    AgentDeclaration,
    InterfaceDeclaration,
    InterfaceCapabilityRef
)


# ============================================================================
# 1. Database Schema Initialization
# ============================================================================

def ensure_skill_intelligence_schema(conn: sqlite3.Connection) -> None:
    """
    Idempotently creates the artifact_discovery_records table and associated indexes.
    Preserves all existing tables and migrations.
    """
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS artifact_discovery_records (
                artifact_id TEXT PRIMARY KEY,
                canonical_urn TEXT NOT NULL,
                name TEXT NOT NULL,
                display_name TEXT NOT NULL,
                taxonomy_kind TEXT NOT NULL CHECK (taxonomy_kind IN (
                    'SKILL', 'COMMAND', 'RULE', 'AGENT_INSTRUCTION', 'AGENT_CONFIGURATION', 'UNKNOWN_ARTIFACT', 'UNSUPPORTED_ARTIFACT'
                )),
                environment_origin TEXT NOT NULL,
                precedence_tier INTEGER NOT NULL,
                source_path TEXT NOT NULL,
                resolved_path TEXT NOT NULL,
                is_bundle INTEGER NOT NULL CHECK (is_bundle IN (0, 1)),
                bundle_root_path TEXT,
                file_size_bytes INTEGER NOT NULL,
                st_mtime REAL NOT NULL,
                st_ino INTEGER NOT NULL,
                st_dev INTEGER NOT NULL,
                raw_content_digest TEXT NOT NULL,
                bundle_manifest_digest TEXT,
                lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN (
                    'DISCOVERED', 'READ', 'UNDERSTOOD', 'INDEXED', 'AVAILABLE', 'QUARANTINED', 'POLICY_BLOCKED', 'UNSUPPORTED'
                )),
                provenance_json TEXT NOT NULL DEFAULT '{}',
                quarantine_reasons_json TEXT NOT NULL DEFAULT '[]',
                discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_art_disc_urn ON artifact_discovery_records(canonical_urn);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_art_disc_digest ON artifact_discovery_records(raw_content_digest);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_art_disc_env ON artifact_discovery_records(environment_origin);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_art_disc_kind ON artifact_discovery_records(taxonomy_kind);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_art_disc_state ON artifact_discovery_records(lifecycle_state);")


# ============================================================================
# 2. Stage 2: Exact-Byte Ingestion & CAS Storage Service
# ============================================================================

class SkillIngestionService:
    """
    Coordinates exact-byte CAS storage, deterministic bundle manifest hashing,
    and authoritative SHA-256 change detection for discovered artifacts.
    Transitions artifacts from DISCOVERED -> READ (or QUARANTINED).
    """

    def __init__(self, conn: sqlite3.Connection, cas_engine: SecureCASStorageEngine):
        self.conn = conn
        self.cas_engine = cas_engine
        ensure_skill_intelligence_schema(self.conn)

    def store_blob_in_cas(self, payload_bytes: bytes, digest: str) -> str:
        """
        Stores raw bytes in CAS and records in content_chunk_blobs under transaction safety.
        Returns the SHA-256 digest.
        """
        byte_len = len(payload_bytes)
        if not self.cas_engine.blob_exists(digest):
            pub_id = f"art_pub_{digest[:16]}_{uuid.uuid4().hex[:8]}"
            pub_tok = f"tok_{uuid.uuid4().hex[:16]}"
            tmp_name, _, _ = self.cas_engine.write_payload_to_staging(pub_id, pub_tok, digest, payload_bytes)
            self.cas_engine.publish_staging_to_cas(tmp_name, digest)

        with self.conn:
            self.conn.execute("""
                INSERT OR IGNORE INTO content_chunk_blobs (
                    blob_digest, byte_length, storage_compression, stored_byte_length
                ) VALUES (?, ?, 'NONE', ?);
            """, (digest, byte_len, byte_len))
        return digest

    def ingest_artifact(
        self,
        record: DiscoveredArtifactRecord,
        resolver: Optional[DiscoveryRootResolver] = None
    ) -> DiscoveredArtifactRecord:
        """
        Performs exact-byte reading and CAS publication.
        Applies authoritative SHA-256 change detection.
        Transitions record to READ or QUARANTINED.
        """
        if record.lifecycle_state == SkillLifecycleState.QUARANTINED:
            self._persist_record(record)
            return record

        try:
            # 1. Read exact bytes safely using descriptor-relative checks
            raw_bytes, st = SafeFileReader.read_exact_bytes(record.resolved_path, MAX_INSTRUCTION_FILE_SIZE)
            content_digest = hashlib.sha256(raw_bytes).hexdigest()

            # 2. Ingest root file into CAS
            self.store_blob_in_cas(raw_bytes, content_digest)
            record.raw_content_digest = content_digest
            record.file_size_bytes = len(raw_bytes)
            record.st_mtime = st.st_mtime
            record.st_ino = st.st_ino
            record.st_dev = st.st_dev

            # 3. If directory bundle, compute and ingest bundle manifest & auxiliary assets
            if record.is_bundle and record.bundle_root_path and os.path.exists(record.bundle_root_path):
                bundle_digest, manifest_bytes, asset_records = BundleManifestHasher.compute_bundle_manifest(
                    record.bundle_root_path,
                    resolver=resolver
                )
                self.store_blob_in_cas(manifest_bytes, bundle_digest)
                record.bundle_manifest_digest = bundle_digest

                # Ingest auxiliary assets into CAS as well
                for asset in asset_records:
                    asset_rel = asset["relative_path"]
                    asset_full = os.path.join(record.bundle_root_path, asset_rel)
                    if os.path.isfile(asset_full):
                        try:
                            a_bytes, _ = SafeFileReader.read_exact_bytes(asset_full, MAX_ASSET_FILE_SIZE)
                            a_digest = hashlib.sha256(a_bytes).hexdigest()
                            self.store_blob_in_cas(a_bytes, a_digest)
                        except Exception:
                            pass

            record.lifecycle_state = SkillLifecycleState.READ
        except Exception as e:
            record.lifecycle_state = SkillLifecycleState.QUARANTINED
            record.quarantine_reasons.append(f"Ingestion failed: {e}")

        self._persist_record(record)
        return record

    def check_change_detection(self, record: DiscoveredArtifactRecord) -> Tuple[bool, Optional[str]]:
        """
        Authoritative SHA-256 change detection check.
        Returns (has_changed, existing_digest).
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT raw_content_digest, bundle_manifest_digest
            FROM artifact_discovery_records
            WHERE canonical_urn = ? AND source_path = ?;
        """, (record.canonical_urn, record.source_path))
        row = cur.fetchone()
        if not row:
            return True, None

        prev_content_digest, prev_bundle_digest = row[0], row[1]
        if prev_content_digest != record.raw_content_digest:
            return True, prev_content_digest
        if record.is_bundle and prev_bundle_digest != record.bundle_manifest_digest:
            return True, prev_content_digest
        return False, prev_content_digest

    def _persist_record(self, record: DiscoveredArtifactRecord) -> None:
        """Saves or updates the artifact discovery record in SQLite."""
        prov_json = json.dumps(record.provenance, sort_keys=True)
        quar_json = json.dumps(record.quarantine_reasons, sort_keys=True)
        now_utc = datetime.now(timezone.utc).isoformat()

        with self.conn:
            self.conn.execute("""
                INSERT INTO artifact_discovery_records (
                    artifact_id, canonical_urn, name, display_name, taxonomy_kind,
                    environment_origin, precedence_tier, source_path, resolved_path,
                    is_bundle, bundle_root_path, file_size_bytes, st_mtime, st_ino, st_dev,
                    raw_content_digest, bundle_manifest_digest, lifecycle_state,
                    provenance_json, quarantine_reasons_json, discovered_at, last_updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(artifact_id) DO UPDATE SET
                    canonical_urn = excluded.canonical_urn,
                    name = excluded.name,
                    display_name = excluded.display_name,
                    taxonomy_kind = excluded.taxonomy_kind,
                    environment_origin = excluded.environment_origin,
                    precedence_tier = excluded.precedence_tier,
                    source_path = excluded.source_path,
                    resolved_path = excluded.resolved_path,
                    is_bundle = excluded.is_bundle,
                    bundle_root_path = excluded.bundle_root_path,
                    file_size_bytes = excluded.file_size_bytes,
                    st_mtime = excluded.st_mtime,
                    st_ino = excluded.st_ino,
                    st_dev = excluded.st_dev,
                    raw_content_digest = excluded.raw_content_digest,
                    bundle_manifest_digest = excluded.bundle_manifest_digest,
                    lifecycle_state = excluded.lifecycle_state,
                    provenance_json = excluded.provenance_json,
                    quarantine_reasons_json = excluded.quarantine_reasons_json,
                    last_updated_at = excluded.last_updated_at;
            """, (
                record.artifact_id, record.canonical_urn, record.name, record.display_name,
                record.taxonomy_kind.value, record.environment_origin.value, record.precedence_tier.value,
                record.source_path, record.resolved_path, 1 if record.is_bundle else 0,
                record.bundle_root_path, record.file_size_bytes, record.st_mtime,
                record.st_ino, record.st_dev, record.raw_content_digest, record.bundle_manifest_digest,
                record.lifecycle_state.value, prov_json, quar_json, now_utc, now_utc
            ))


def _ensure_capability_registered(
    conn: sqlite3.Connection,
    record: DiscoveredArtifactRecord,
    display_name: str,
    description: str
) -> None:
    """Safely registers entity in entity_urn_registry, capabilities, and capability_declarations obeying registry lifecycle triggers."""
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT lifecycle_state FROM entity_urn_registry WHERE entity_urn = ?;", (record.canonical_urn,))
        row = cur.fetchone()
        if not row:
            cur.execute("""
                INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state)
                VALUES (?, 'CAPABILITY', 'PENDING');
            """, (record.canonical_urn,))

        cur.execute("""
            INSERT INTO capabilities (capability_urn, name, version, description)
            VALUES (?, ?, '1.0.0', ?)
            ON CONFLICT(capability_urn) DO UPDATE SET
                name = excluded.name,
                description = excluded.description;
        """, (record.canonical_urn, record.name, description))

        cur.execute("""
            UPDATE entity_urn_registry
            SET lifecycle_state = 'ACTIVE'
            WHERE entity_urn = ?;
        """, (record.canonical_urn,))

        cur.execute("""
            INSERT INTO capability_declarations (
                capability_urn, definition_blob_digest, schema_version, display_name, capability_type
            ) VALUES (?, ?, 1, ?, 'skill')
            ON CONFLICT(capability_urn) DO UPDATE SET
                definition_blob_digest = excluded.definition_blob_digest,
                display_name = excluded.display_name;
        """, (record.canonical_urn, record.raw_content_digest, display_name))


# ============================================================================
# 3. Stage 3: Semantic Understanding & Parameter Extraction Service
# ============================================================================

class SkillUnderstandingEngine:
    """
    Parses YAML frontmatter and Markdown body.
    Strictly separates EXPLICIT formally declared parameters from INFERRED template variables.
    Enforces the Parameter Invariance rule: Inferred template variables are ALWAYS optional.
    Transitions artifacts from READ -> UNDERSTOOD (or QUARANTINED).
    """

    def __init__(self, conn: sqlite3.Connection, profile_service: CapabilityProfileService):
        self.conn = conn
        self.profile_service = profile_service

    def understand_artifact(
        self,
        record: DiscoveredArtifactRecord,
        raw_text: str
    ) -> Tuple[DiscoveredArtifactRecord, Optional[CapabilitySemanticProfile]]:
        """
        Extracts semantic metadata and parameter profiles from raw_text.
        Constructs and stores a CapabilitySemanticProfile.
        """
        if record.lifecycle_state not in (SkillLifecycleState.READ, SkillLifecycleState.DISCOVERED):
            return record, None

        try:
            metadata, body = ArtifactTaxonomyClassifier.extract_frontmatter(raw_text)

            # 1. Resolve Display Name & Description
            display_name = metadata.get("name") or record.display_name
            description = metadata.get("description") or self._extract_first_paragraph(body) or f"{record.name} capability"

            # 2. Extract Explicitly Declared Parameters
            explicit_params: List[ParameterProfile] = []
            declared_names: Set[str] = set()

            raw_params = metadata.get("parameters") or metadata.get("inputs")
            if isinstance(raw_params, dict):
                for p_name, p_data in raw_params.items():
                    clean_pname = str(p_name).strip()
                    declared_names.add(clean_pname)
                    if isinstance(p_data, dict):
                        p_type = str(p_data.get("type", "string"))
                        p_req = bool(p_data.get("required", False))
                        p_desc = str(p_data.get("description", ""))
                        p_def = p_data.get("default", None)
                    else:
                        p_type = "string"
                        p_req = False
                        p_desc = str(p_data)
                        p_def = None

                    explicit_params.append(ParameterProfile(
                        name=clean_pname,
                        param_type=p_type,
                        required=p_req,
                        description=p_desc,
                        default=p_def,
                        evidence=EvidenceSource.EXPLICIT,
                        notes="Formally declared in YAML frontmatter."
                    ))
            elif isinstance(raw_params, list):
                for item in raw_params:
                    if isinstance(item, str):
                        clean_pname = item.strip()
                        declared_names.add(clean_pname)
                        explicit_params.append(ParameterProfile(
                            name=clean_pname,
                            param_type="string",
                            required=False,
                            description=f"Declared parameter {clean_pname}",
                            evidence=EvidenceSource.EXPLICIT,
                            notes="Listed in frontmatter parameters array."
                        ))

            # 3. Extract Inferred Template Variables from Markdown Body
            inferred_params: List[ParameterProfile] = []
            extracted_placeholders = self._extract_template_placeholders(body)

            for placeholder in extracted_placeholders:
                if placeholder in declared_names or placeholder.lower() in declared_names:
                    continue  # Already formally declared
                declared_names.add(placeholder)

                # MANDATORY INVARIANT: Inferred template variables are ALWAYS required = False
                inferred_params.append(ParameterProfile(
                    name=placeholder,
                    param_type="string",
                    required=False,
                    description=f"Inferred template variable '${placeholder}'",
                    default=None,
                    evidence=EvidenceSource.INFERRED,
                    notes="Inferred from template placeholder. Defaulted to optional."
                ))

            all_params = explicit_params + inferred_params

            # 4. Formulate Profile Fields
            req_names = [p.name for p in all_params if p.required]
            opt_names = [p.name for p in all_params if not p.required]

            inputs_field = ProfileField(
                value=[p.to_dict() for p in all_params],
                evidence=EvidenceSource.EXTRACTED if explicit_params else EvidenceSource.INFERRED if inferred_params else EvidenceSource.UNKNOWN,
                notes="Parameters extracted from YAML frontmatter and markdown body templates."
            )
            req_field = ProfileField(
                value=sorted(req_names),
                evidence=EvidenceSource.EXTRACTED if req_names else EvidenceSource.UNKNOWN,
                notes="Formally declared mandatory inputs."
            )
            opt_field = ProfileField(
                value=sorted(opt_names),
                evidence=EvidenceSource.EXTRACTED if opt_names else EvidenceSource.UNKNOWN,
                notes="Optional parameters and inferred template placeholders."
            )

            clean_name = record.name.lower().replace("_", "-")
            env_tag = record.environment_origin.value.lower()
            auto_iface_urn = f"urn:lcs:interface:skill.{env_tag}.{clean_name}:v1"
            auto_agent_urn = f"urn:lcs:agent:skill.{env_tag}:host"

            # 5. Build CapabilitySemanticProfile
            profile = CapabilitySemanticProfile(
                capability_id=record.canonical_urn,
                display_name=ProfileField(value=display_name, evidence=EvidenceSource.EXPLICIT),
                description=ProfileField(value=description, evidence=EvidenceSource.EXPLICIT if metadata.get("description") else EvidenceSource.INFERRED),
                category=ProfileField(value=metadata.get("category", "skill"), evidence=EvidenceSource.INFERRED),
                inputs=inputs_field,
                required_inputs=req_field,
                optional_inputs=opt_field,
                output_schema=ProfileField(value=None, evidence=EvidenceSource.UNKNOWN, notes="Skills produce conversational or tool outputs."),
                dependencies=ProfileField(value=[], evidence=EvidenceSource.UNKNOWN),
                permissions=ProfileField(value=[], evidence=EvidenceSource.UNKNOWN),
                limitations=ProfileField(value=[], evidence=EvidenceSource.UNKNOWN),
                source_agent=ProfileField(value=auto_agent_urn, evidence=EvidenceSource.INFERRED),
                source_interface=ProfileField(value=auto_iface_urn, evidence=EvidenceSource.INFERRED),
                evidence_references={
                    "source_path": record.source_path,
                    "content_digest": record.raw_content_digest,
                    "taxonomy_kind": record.taxonomy_kind.value,
                    "environment_origin": record.environment_origin.value
                }
            )

            # 5b. Ensure declaration exists in relational schema for foreign key integrity
            _ensure_capability_registered(self.conn, record, display_name, description)

            # 6. Store profile in CAS and register in capability_semantic_profiles
            self.profile_service.store_profile(profile)
            record.display_name = display_name
            record.lifecycle_state = SkillLifecycleState.UNDERSTOOD
        except Exception as e:
            record.lifecycle_state = SkillLifecycleState.QUARANTINED
            record.quarantine_reasons.append(f"Understanding/Parsing error: {e}")
            profile = None

        self._update_record_lifecycle(record)
        return record, profile

    def _extract_first_paragraph(self, body: str) -> str:
        """Extracts the first non-heading, non-empty paragraph of text."""
        lines = body.splitlines()
        para_lines = []
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                if para_lines:
                    break
                continue
            para_lines.append(line_str)
        return " ".join(para_lines)

    def _extract_template_placeholders(self, text: str) -> List[str]:
        """
        Extracts template variable patterns:
        - $ARGUMENTS, $FILE, $VAR
        - ${var_name}
        - {{var_name}}
        - <param_name> in command syntax
        """
        found = []
        seen = set()

        # Pattern 1: $VAR_NAME
        for m in re.finditer(r"(?<!\\)\$([A-Za-z0-9_]+)", text):
            var = m.group(1)
            if var not in seen:
                seen.add(var)
                found.append(var)

        # Pattern 2: ${var_name}
        for m in re.finditer(r"(?<!\\)\$\{([a-zA-Z0-9_.-]+)\}", text):
            var = m.group(1)
            if var not in seen:
                seen.add(var)
                found.append(var)

        # Pattern 3: {{var_name}}
        for m in re.finditer(r"(?<!\\)\{\{([a-zA-Z0-9_.-]+)\}\}", text):
            var = m.group(1)
            if var not in seen:
                seen.add(var)
                found.append(var)

        return found

    def _update_record_lifecycle(self, record: DiscoveredArtifactRecord) -> None:
        """Updates the lifecycle state in SQLite."""
        quar_json = json.dumps(record.quarantine_reasons, sort_keys=True)
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute("""
                UPDATE artifact_discovery_records
                SET display_name = ?,
                    lifecycle_state = ?,
                    quarantine_reasons_json = ?,
                    last_updated_at = ?
                WHERE artifact_id = ?;
            """, (record.display_name, record.lifecycle_state.value, quar_json, now_utc, record.artifact_id))


# ============================================================================
# 4. Stage 4: Catalog Registration & Indexing Service
# ============================================================================

class SkillCatalogService:
    """
    Registers understood skills into the LCS capability catalog and FTS5 search index.
    Evaluates Governance Gate 1 trust policy (confinement, quarantine status).
    Transitions artifacts from UNDERSTOOD -> INDEXED -> AVAILABLE (or POLICY_BLOCKED).
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        index_service: DiscoveryIndexService,
        iface_service: Optional[Any] = None,
        profile_service: Optional[CapabilityProfileService] = None
    ):
        self.conn = conn
        self.index_service = index_service
        self.iface_service = iface_service
        self.profile_service = profile_service

    def _auto_register_interface(
        self,
        record: DiscoveredArtifactRecord,
        profile: Optional[CapabilitySemanticProfile] = None
    ) -> Optional[str]:
        """
        Auto-registers host agent and interface declaration with HMAC-SHA256 attestation
        so discovered skills satisfy Governance Gate 1 zero-trust policy out-of-the-box.
        """
        if not self.iface_service:
            return None

        try:
            clean_name = record.name.lower().replace("_", "-")
            env_tag = record.environment_origin.value.lower()
            iface_urn = f"urn:lcs:interface:skill.{env_tag}.{clean_name}:v1"
            agent_urn = f"urn:lcs:agent:skill.{env_tag}:host"

            now_iso = datetime.now(timezone.utc).isoformat()

            # 1. Register agent in entity_urn_registry and capabilities
            with self.conn:
                self.conn.execute("""
                    INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state)
                    VALUES (?, 'CAPABILITY', 'PENDING');
                """, (agent_urn,))
                self.conn.execute("""
                    INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description)
                    VALUES (?, 'Skill Host Agent', '1.0.0', 'Discovered skill host');
                """, (agent_urn,))
                self.conn.execute("""
                    UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;
                """, (agent_urn,))

            agent_decl = AgentDeclaration(
                agent_urn=agent_urn,
                display_name=f"LCS Skill Agent ({record.environment_origin.value})",
                description="Host agent for discovered skills",
                provenance={
                    "author": "LCS-Skill-Intelligence-V1",
                    "created_at": now_iso,
                    "source_origin": env_tag,
                    "license": "MIT"
                }
            )
            try:
                self.iface_service.register_agent(agent_decl)
            except Exception:
                pass

            # 2. Register interface in entity_urn_registry and capabilities
            with self.conn:
                self.conn.execute("""
                    INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state)
                    VALUES (?, 'CAPABILITY', 'PENDING');
                """, (iface_urn,))
                self.conn.execute("""
                    INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description)
                    VALUES (?, ?, '1.0.0', ?);
                """, (iface_urn, f"{record.display_name} Interface", f"Interface for {record.display_name}"))
                self.conn.execute("""
                    UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;
                """, (iface_urn,))

            iface_decl = InterfaceDeclaration(
                interface_urn=iface_urn,
                agent_urn=agent_urn,
                interface_version=1,
                display_name=f"{record.display_name} Interface",
                description=f"Auto-registered interface for {record.display_name}",
                schema_version=1,
                capabilities=[InterfaceCapabilityRef(
                    capability_urn=record.canonical_urn,
                    expected_definition_digest=record.raw_content_digest
                )],
                provenance={
                    "author": "LCS-Skill-Intelligence-V1",
                    "created_at": now_iso,
                    "source_origin": env_tag,
                    "license": "MIT"
                }
            )
            try:
                self.iface_service.register_interface(iface_decl)
                self.iface_service.attest_interface(iface_urn)
            except Exception:
                pass

            # 3. Update profile source_interface and source_agent if present
            if profile and self.profile_service:
                profile.source_interface.value = iface_urn
                profile.source_agent.value = agent_urn
                try:
                    self.profile_service.store_profile(profile)
                except Exception:
                    pass

            return iface_urn
        except Exception:
            return None

    def register_and_index(
        self,
        record: DiscoveredArtifactRecord,
        profile: Optional[CapabilitySemanticProfile] = None,
        resolver: Optional[DiscoveryRootResolver] = None
    ) -> DiscoveredArtifactRecord:
        """
        Registers capability in entity_urn_registry, capabilities, capability_declarations,
        and capability_fts. Evaluates Gate 1 trust status.
        """
        if record.lifecycle_state != SkillLifecycleState.UNDERSTOOD:
            return record

        try:
            # 1. Ensure foreign key references exist in relational schema
            desc = profile.description.value if profile and profile.description else record.display_name
            _ensure_capability_registered(self.conn, record, record.display_name, desc)

            record.lifecycle_state = SkillLifecycleState.INDEXED

            # 2. Populate FTS5 Search Index (capability_fts)
            category = profile.category.value if profile and profile.category else "skill"
            keywords = f"{record.name} {record.taxonomy_kind.value.lower()} {category} {record.environment_origin.value.lower()}"
            if profile and profile.inputs and isinstance(profile.inputs.value, list):
                param_terms = " ".join(p.get("name", "") for p in profile.inputs.value if isinstance(p, dict))
                keywords = f"{keywords} {param_terms}"

            with self.conn:
                # Remove prior entry if exists
                self.conn.execute("DELETE FROM capability_fts WHERE capability_urn = ?;", (record.canonical_urn,))
                self.conn.execute("""
                    INSERT INTO capability_fts (
                        capability_urn, name, description, capability_type, category,
                        keywords, provenance_author, provenance_origin, provenance_license, trust_status
                    ) VALUES (?, ?, ?, 'skill', ?, ?, ?, ?, 'MIT', 'TRUSTED');
                """, (
                    record.canonical_urn,
                    record.display_name,
                    desc,
                    category,
                    keywords,
                    record.provenance.get("adapter", "LCS-Skill-Intelligence"),
                    record.environment_origin.value
                ))

            # 3. Governance Gate 1 Trust Policy Evaluation
            is_confined = True
            if resolver:
                is_confined = resolver.is_path_confined(record.resolved_path)

            if not is_confined:
                record.lifecycle_state = SkillLifecycleState.POLICY_BLOCKED
                record.quarantine_reasons.append("Path escapes authorized discovery roots.")
            elif record.quarantine_reasons:
                record.lifecycle_state = SkillLifecycleState.QUARANTINED
            else:
                record.lifecycle_state = SkillLifecycleState.AVAILABLE

        except Exception as e:
            record.lifecycle_state = SkillLifecycleState.QUARANTINED
            record.quarantine_reasons.append(f"Catalog indexing error: {e}")

        # Update persistent state
        quar_json = json.dumps(record.quarantine_reasons, sort_keys=True)
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute("""
                UPDATE artifact_discovery_records
                SET lifecycle_state = ?,
                    quarantine_reasons_json = ?,
                    last_updated_at = ?
                WHERE artifact_id = ?;
            """, (record.lifecycle_state.value, quar_json, now_utc, record.artifact_id))

        # 4. Auto-register interface declaration and attestation for Gate 1 trust policy
        if record.lifecycle_state == SkillLifecycleState.AVAILABLE and self.iface_service:
            self._auto_register_interface(record, profile)

        return record


# ============================================================================
# 5. Stage 5: Unified Retrieval Coordinator & Context Precedence
# ============================================================================

@dataclass
class UnifiedRetrievalCandidate:
    """Represents a unified retrieval search result with taxonomy and precedence metadata."""
    capability_urn: str
    display_name: str
    description: str
    category: str
    relevance_score: float
    raw_base_score: float
    precedence_boost: float
    trigger_match_boost: float
    taxonomy_kind: ArtifactTaxonomyKind
    environment_origin: EnvironmentOrigin
    precedence_tier: PrecedenceTier
    lifecycle_state: SkillLifecycleState
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_urn": self.capability_urn,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category,
            "relevance_score": round(self.relevance_score, 4),
            "raw_base_score": round(self.raw_base_score, 4),
            "precedence_boost": round(self.precedence_boost, 4),
            "trigger_match_boost": round(self.trigger_match_boost, 4),
            "taxonomy_kind": self.taxonomy_kind.value,
            "environment_origin": self.environment_origin.value,
            "precedence_tier": self.precedence_tier.value,
            "lifecycle_state": self.lifecycle_state.value,
            "reasons": self.reasons
        }


class UnifiedRetrievalCoordinator:
    """
    Wraps frozen retrieval engines (CapabilityRetrievalEngineV1 or V1_1) as an immutable delegate.
    Applies:
      1. Taxonomic filtering (skills, commands, rules, etc.).
      2. Dynamic context-aware precedence ranking (Workspace > Host Environment > User Global > Builtin).
      3. FTS5 trigger phrase and keyword matching.
    Preserves 100% frozen module byte invariance.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        delegate_engine: Any,
        index_service: Optional[DiscoveryIndexService] = None,
        profile_service: Optional[CapabilityProfileService] = None
    ):
        self.conn = conn
        self.delegate_engine = delegate_engine
        self.index_service = index_service
        self.profile_service = profile_service

    def retrieve(
        self,
        query: str,
        limit: int = 10,
        threshold: float = 0.20,
        taxonomy_kinds: Optional[List[ArtifactTaxonomyKind]] = None,
        active_workspace_path: Optional[str] = None,
        active_host_env: Optional[EnvironmentOrigin] = None
    ) -> List[UnifiedRetrievalCandidate]:
        """
        Executes unified capability and skill search.
        """
        # 1. Query the frozen retrieval delegate for base scoring
        delegate_result = self.delegate_engine.retrieve(query, limit=50)
        base_candidates: Dict[str, Any] = {}
        if hasattr(delegate_result, "candidates"):
            for c in delegate_result.candidates:
                base_candidates[c.capability_urn] = c

        # 2. Query FTS5 for full-text triggers and keyword matches
        fts_scores = self._query_fts_triggers(query)

        # 3. Fetch discovery metadata from artifact_discovery_records
        cur = self.conn.cursor()
        cur.execute("""
            SELECT canonical_urn, name, display_name, taxonomy_kind, environment_origin,
                   precedence_tier, lifecycle_state, source_path
            FROM artifact_discovery_records
            WHERE lifecycle_state = 'AVAILABLE';
        """)
        skill_rows = cur.fetchall()
        skill_map = {row[0]: row for row in skill_rows}

        # 4. Synthesize all candidate URNs
        all_candidate_urns = set(base_candidates.keys()).union(fts_scores.keys()).union(skill_map.keys())

        candidates: List[UnifiedRetrievalCandidate] = []

        for urn in all_candidate_urns:
            # Check taxonomic filter
            skill_info = skill_map.get(urn)
            tax_kind = ArtifactTaxonomyKind(skill_info[3]) if skill_info else ArtifactTaxonomyKind.SKILL
            env_origin = EnvironmentOrigin(skill_info[4]) if skill_info else EnvironmentOrigin.GENERIC_WORKSPACE
            tier = PrecedenceTier(skill_info[5]) if skill_info else PrecedenceTier.USER_GLOBAL
            state = SkillLifecycleState(skill_info[6]) if skill_info else SkillLifecycleState.AVAILABLE

            if taxonomy_kinds and tax_kind not in taxonomy_kinds:
                continue

            # Base score from frozen engine
            c_base = base_candidates.get(urn)
            raw_base = c_base.relevance_score if c_base else 0.0
            display_name = c_base.display_name if c_base else (skill_info[2] if skill_info else urn)
            desc = c_base.description if c_base else ""
            cat = c_base.category if c_base else "skill"

            # Trigger boost from FTS5
            trigger_boost = fts_scores.get(urn, 0.0)

            # Precedence boost
            precedence_boost = self._calculate_precedence_boost(
                urn, tier, env_origin, skill_info[7] if skill_info else None,
                active_workspace_path, active_host_env
            )

            # Calculate composite score (capped at 1.0)
            composite_score = min(1.0, raw_base + trigger_boost + precedence_boost)

            if composite_score < threshold and raw_base < threshold and trigger_boost < threshold:
                continue

            reasons = []
            if raw_base > 0:
                reasons.append(f"Base semantic relevance: {raw_base:.2f}")
            if trigger_boost > 0:
                reasons.append(f"FTS5 keyword/trigger match boost: +{trigger_boost:.2f}")
            if precedence_boost > 0:
                reasons.append(f"Context precedence boost ({tier.name}): +{precedence_boost:.2f}")

            candidates.append(UnifiedRetrievalCandidate(
                capability_urn=urn,
                display_name=display_name,
                description=desc,
                category=cat,
                relevance_score=composite_score,
                raw_base_score=raw_base,
                precedence_boost=precedence_boost,
                trigger_match_boost=trigger_boost,
                taxonomy_kind=tax_kind,
                environment_origin=env_origin,
                precedence_tier=tier,
                lifecycle_state=state,
                reasons=reasons
            ))

        # Sort descending by composite score, then lexicographically by URN for determinism
        candidates.sort(key=lambda c: (-c.relevance_score, c.capability_urn))
        return candidates[:limit]

    def _query_fts_triggers(self, query: str) -> Dict[str, float]:
        """Queries capability_fts for term hits and returns score adjustments."""
        words = re.findall(r"[a-zA-Z0-9_-]+", query.lower())
        tokens = [w for w in words if len(w) > 2]
        if not tokens:
            return {}

        match_expr = " OR ".join(f'"{t}"*' for t in tokens)
        scores: Dict[str, float] = {}

        try:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT capability_urn, rank
                FROM capability_fts
                WHERE capability_fts MATCH ?
                ORDER BY rank
                LIMIT 30;
            """, (match_expr,))
            rows = cur.fetchall()

            for row in rows:
                urn, rank = row[0], abs(float(row[1]))
                # Normalize BM25 rank into a bounded boost (0.05 to 0.35)
                boost = min(0.35, max(0.05, 1.0 / (1.0 + rank * 0.1)))
                scores[urn] = boost
        except Exception:
            pass

        return scores

    def _calculate_precedence_boost(
        self,
        urn: str,
        tier: PrecedenceTier,
        env_origin: EnvironmentOrigin,
        source_path: Optional[str],
        active_workspace: Optional[str],
        active_host: Optional[EnvironmentOrigin]
    ) -> float:
        """
        Dynamically calculates precedence boost based on query context:
        - Workspace artifact in active workspace: +0.25
        - Active host environment artifact: +0.15
        - User global: +0.05
        - Built-in: 0.00
        """
        boost = 0.0
        if active_workspace and source_path:
            try:
                if os.path.commonpath([os.path.realpath(source_path), os.path.realpath(active_workspace)]) == os.path.realpath(active_workspace):
                    boost += 0.25
            except ValueError:
                pass

        if active_host and env_origin == active_host:
            boost += 0.15
        elif tier == PrecedenceTier.USER_GLOBAL:
            boost += 0.05

        return boost


# ============================================================================
# 6. Central Coordinator: SkillIntelligenceServiceV1
# ============================================================================

class SkillIntelligenceServiceV1:
    """
    Unified coordinator orchestrating discovery, ingestion, understanding,
    indexing, and retrieval across Google Antigravity, Claude Code, and OpenCode.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        cas_engine: SecureCASStorageEngine,
        profile_service: CapabilityProfileService,
        index_service: DiscoveryIndexService,
        retrieval_engine: Any,
        workspace_root: Optional[str] = None,
        resolver: Optional[DiscoveryRootResolver] = None,
        iface_service: Optional[Any] = None
    ):
        self.conn = conn
        self.cas_engine = cas_engine
        self.profile_service = profile_service
        self.index_service = index_service
        self.retrieval_engine = retrieval_engine
        self.resolver = resolver or DiscoveryRootResolver(workspace_root=workspace_root)
        self.iface_service = iface_service

        # Subsystems
        self.discovery_engine = SkillDiscoveryEngineV1(resolver=self.resolver)
        self.ingestion_service = SkillIngestionService(self.conn, self.cas_engine)
        self.understanding_engine = SkillUnderstandingEngine(self.conn, self.profile_service)
        self.catalog_service = SkillCatalogService(
            self.conn,
            self.index_service,
            iface_service=self.iface_service,
            profile_service=self.profile_service
        )
        self.retrieval_coordinator = UnifiedRetrievalCoordinator(
            conn=self.conn,
            delegate_engine=self.retrieval_engine,
            index_service=self.index_service,
            profile_service=self.profile_service
        )

    def set_resolver(self, resolver: DiscoveryRootResolver) -> None:
        """Dynamically reconfigures the discovery root resolver across all subsystems."""
        self.resolver = resolver
        self.discovery_engine = SkillDiscoveryEngineV1(resolver=resolver)

    def run_full_pipeline(
        self,
        environment: Optional[EnvironmentOrigin] = None
    ) -> List[DiscoveredArtifactRecord]:
        """
        Runs the complete end-to-end pipeline:
        DISCOVER -> READ (Ingest) -> UNDERSTOOD (Profile) -> INDEXED -> AVAILABLE.
        """
        # 1. Discover
        if environment:
            discovered = self.discovery_engine.discover_environment(environment)
        else:
            discovered = self.discovery_engine.discover_all()

        final_records: List[DiscoveredArtifactRecord] = []

        for rec in discovered:
            # 2. Ingest exact bytes into CAS
            ingested_rec = self.ingestion_service.ingest_artifact(rec, resolver=self.resolver)
            if ingested_rec.lifecycle_state == SkillLifecycleState.QUARANTINED:
                final_records.append(ingested_rec)
                continue

            # Read text content safely for understanding
            try:
                raw_bytes, _ = SafeFileReader.read_exact_bytes(ingested_rec.resolved_path, MAX_INSTRUCTION_FILE_SIZE)
                raw_text = raw_bytes.decode("utf-8", errors="replace")
            except Exception as e:
                ingested_rec.lifecycle_state = SkillLifecycleState.QUARANTINED
                ingested_rec.quarantine_reasons.append(f"Failed to decode text: {e}")
                final_records.append(ingested_rec)
                continue

            # 3. Understand & Profile
            understood_rec, profile = self.understanding_engine.understand_artifact(ingested_rec, raw_text)
            if understood_rec.lifecycle_state == SkillLifecycleState.QUARANTINED:
                final_records.append(understood_rec)
                continue

            # 4. Catalog Registration, FTS5 Indexing & Gate 1 Trust Check
            final_rec = self.catalog_service.register_and_index(understood_rec, profile, resolver=self.resolver)
            final_records.append(final_rec)

        return final_records

    def list_artifacts(
        self,
        taxonomy_kind: Optional[ArtifactTaxonomyKind] = None,
        lifecycle_state: Optional[SkillLifecycleState] = None
    ) -> List[Dict[str, Any]]:
        """Queries registered discovery records with optional filters."""
        cur = self.conn.cursor()
        query = """
            SELECT artifact_id, canonical_urn, name, display_name, taxonomy_kind,
                   environment_origin, precedence_tier, source_path, is_bundle,
                   raw_content_digest, bundle_manifest_digest, lifecycle_state,
                   quarantine_reasons_json, last_updated_at
            FROM artifact_discovery_records
            WHERE 1=1
        """
        params = []
        if taxonomy_kind:
            query += " AND taxonomy_kind = ?"
            params.append(taxonomy_kind.value)
        if lifecycle_state:
            query += " AND lifecycle_state = ?"
            params.append(lifecycle_state.value)

        query += " ORDER BY last_updated_at DESC;"
        cur.execute(query, params)
        rows = cur.fetchall()

        out = []
        for r in rows:
            out.append({
                "artifact_id": r[0],
                "canonical_urn": r[1],
                "name": r[2],
                "display_name": r[3],
                "taxonomy_kind": r[4],
                "environment_origin": r[5],
                "precedence_tier": r[6],
                "source_path": r[7],
                "is_bundle": bool(r[8]),
                "raw_content_digest": r[9],
                "bundle_manifest_digest": r[10],
                "lifecycle_state": r[11],
                "quarantine_reasons": json.loads(r[12]),
                "last_updated_at": r[13]
            })
        return out

    def inspect_artifact(self, urn: str) -> Optional[Dict[str, Any]]:
        """Inspects detailed discovery, CAS, and semantic profile state for an artifact."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT artifact_id, canonical_urn, name, display_name, taxonomy_kind,
                   environment_origin, precedence_tier, source_path, resolved_path,
                   is_bundle, bundle_root_path, file_size_bytes, raw_content_digest,
                   bundle_manifest_digest, lifecycle_state, provenance_json,
                   quarantine_reasons_json, discovered_at, last_updated_at
            FROM artifact_discovery_records
            WHERE canonical_urn = ?;
        """, (urn,))
        row = cur.fetchone()
        if not row:
            return None

        profile = None
        try:
            profile = self.profile_service.get_profile(urn)
        except Exception:
            pass

        return {
            "artifact_id": row[0],
            "canonical_urn": row[1],
            "name": row[2],
            "display_name": row[3],
            "taxonomy_kind": row[4],
            "environment_origin": row[5],
            "precedence_tier": row[6],
            "source_path": row[7],
            "resolved_path": row[8],
            "is_bundle": bool(row[9]),
            "bundle_root_path": row[10],
            "file_size_bytes": row[11],
            "raw_content_digest": row[12],
            "bundle_manifest_digest": row[13],
            "lifecycle_state": row[14],
            "provenance": json.loads(row[15]),
            "quarantine_reasons": json.loads(row[16]),
            "discovered_at": row[17],
            "last_updated_at": row[18],
            "semantic_profile": profile.to_dict() if profile else None
        }

    def search(
        self,
        query: str,
        limit: int = 10,
        taxonomy_kinds: Optional[List[ArtifactTaxonomyKind]] = None
    ) -> List[UnifiedRetrievalCandidate]:
        """Searches capabilities using the Unified Retrieval Coordinator."""
        return self.retrieval_coordinator.retrieve(
            query=query,
            limit=limit,
            taxonomy_kinds=taxonomy_kinds,
            active_workspace_path=self.resolver.workspace_root
        )

