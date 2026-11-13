#!/usr/bin/env python3
"""
LCS Stage 2B — Capability Semantic Profile (Capability Intelligence Layer - Phase 1)
=====================================================================================
Transforms registered capability declarations into structured, evidence-grounded
semantic profiles. Distinguishes explicitly declared information, deterministically
extracted schema structures, inferred heuristics, and unknown attributes.

Evidence Levels:
  - EXPLICIT:   Declared directly in authoritative manifest, URN, or server metadata.
  - EXTRACTED:  Deterministically parsed from formal JSON/Pydantic schemas.
  - INFERRED:   Derived via heuristic analysis (e.g. keyword classification).
  - UNKNOWN:    Undeclared or unavailable in evidence records.
"""

import os
import re
import sys
import json
import time
import uuid
import hashlib
import sqlite3
from typing import Dict, Any, List, Optional, Tuple, Set

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    CASError,
    CASValidationError
)
from capability_registry_v2b import (
    parse_canonical_urn,
    CanonicalCapabilityURN,
    CapabilityDefinition,
    CapabilityNotFoundError,
    SQLiteForeignKeyEnforcementError
)


# ----------------------------------------------------------------------------
# Evidence & Confidence Levels
# ----------------------------------------------------------------------------

class EvidenceSource:
    EXPLICIT = "EXPLICIT"       # Declared directly by author/manifest/serverInfo
    EXTRACTED = "EXTRACTED"     # Deterministically parsed from formal schema
    INFERRED = "INFERRED"       # Derived via heuristic analysis (e.g. category classification)
    UNKNOWN = "UNKNOWN"         # Undeclared or unavailable in evidence records


VALID_EVIDENCE_SOURCES = frozenset({
    EvidenceSource.EXPLICIT,
    EvidenceSource.EXTRACTED,
    EvidenceSource.INFERRED,
    EvidenceSource.UNKNOWN
})


# ----------------------------------------------------------------------------
# Data Models: ProfileField & ParameterProfile
# ----------------------------------------------------------------------------

class ProfileField:
    """
    A single evidence-annotated attribute within a CapabilitySemanticProfile.
    Guarantees strict provenance tracking and auditability.
    """
    def __init__(self, value: Any, evidence: str, notes: str = ""):
        if evidence not in VALID_EVIDENCE_SOURCES:
            raise ValueError(f"Invalid evidence source '{evidence}'. Must be one of {sorted(VALID_EVIDENCE_SOURCES)}")
        self.value = value
        self.evidence = evidence
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "evidence": self.evidence,
            "notes": self.notes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProfileField":
        return cls(
            value=data.get("value"),
            evidence=data.get("evidence", EvidenceSource.UNKNOWN),
            notes=data.get("notes", "")
        )


class ParameterProfile:
    """
    Describes an individual input parameter deterministically extracted from a JSON/Pydantic schema.
    """
    def __init__(
        self,
        name: str,
        param_type: str,
        required: bool,
        description: Optional[str] = None,
        default: Any = None,
        evidence: str = EvidenceSource.EXTRACTED,
        notes: str = ""
    ):
        self.name = name
        self.param_type = param_type
        self.required = required
        self.description = description
        self.default = default
        self.evidence = evidence
        self.notes = notes or (
            "Deterministically extracted from input schema properties."
            if evidence == EvidenceSource.EXTRACTED else ""
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.param_type,
            "required": self.required,
            "description": self.description,
            "default": self.default,
            "evidence": self.evidence,
            "notes": self.notes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ParameterProfile":
        return cls(
            name=data["name"],
            param_type=data.get("type", "any"),
            required=data.get("required", False),
            description=data.get("description"),
            default=data.get("default"),
            evidence=data.get("evidence", EvidenceSource.EXTRACTED),
            notes=data.get("notes", "")
        )


# ----------------------------------------------------------------------------
# Core Model: CapabilitySemanticProfile
# ----------------------------------------------------------------------------

class CapabilitySemanticProfile:
    """
    Structured, evidence-grounded semantic profile representing a registered capability.
    Deterministic JSON serialization ensures reproducible SHA-256 CAS storage.
    """
    def __init__(
        self,
        capability_id: str,
        display_name: ProfileField,
        description: ProfileField,
        category: ProfileField,
        inputs: ProfileField,            # value: List[Dict[str, Any]] (ParameterProfile dicts) or None
        required_inputs: ProfileField,   # value: List[str]
        optional_inputs: ProfileField,   # value: List[str]
        output_schema: ProfileField,     # value: Dict[str, Any] or None
        dependencies: ProfileField,      # value: List[str] (evidence=UNKNOWN)
        permissions: ProfileField,       # value: List[str] (evidence=UNKNOWN)
        limitations: ProfileField,       # value: List[str] (evidence=UNKNOWN)
        source_agent: ProfileField,      # value: str or None
        source_interface: ProfileField,  # value: str or None
        evidence_references: Dict[str, Any],
        profile_version: int = 1,
        created_at: Optional[str] = None
    ):
        self.capability_id = capability_id
        self.display_name = display_name
        self.description = description
        self.category = category
        self.inputs = inputs
        self.required_inputs = required_inputs
        self.optional_inputs = optional_inputs
        self.output_schema = output_schema
        self.dependencies = dependencies
        self.permissions = permissions
        self.limitations = limitations
        self.source_agent = source_agent
        self.source_interface = source_interface
        self.evidence_references = dict(evidence_references)
        self.profile_version = profile_version
        self.created_at = created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @property
    def unknown_fields(self) -> List[str]:
        """Lists all semantic fields classified with UNKNOWN evidence."""
        unknowns = []
        field_map = {
            "inputs": self.inputs,
            "required_inputs": self.required_inputs,
            "optional_inputs": self.optional_inputs,
            "output_schema": self.output_schema,
            "dependencies": self.dependencies,
            "permissions": self.permissions,
            "limitations": self.limitations,
            "description": self.description,
            "source_agent": self.source_agent,
            "source_interface": self.source_interface
        }
        for name, field in field_map.items():
            if field.evidence == EvidenceSource.UNKNOWN:
                unknowns.append(name)
        return sorted(unknowns)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "semantic_profile_v1",
            "profile_version": self.profile_version,
            "capability_id": self.capability_id,
            "created_at": self.created_at,
            "display_name": self.display_name.to_dict(),
            "description": self.description.to_dict(),
            "category": self.category.to_dict(),
            "inputs": self.inputs.to_dict(),
            "required_inputs": self.required_inputs.to_dict(),
            "optional_inputs": self.optional_inputs.to_dict(),
            "output_schema": self.output_schema.to_dict(),
            "dependencies": self.dependencies.to_dict(),
            "permissions": self.permissions.to_dict(),
            "limitations": self.limitations.to_dict(),
            "source_agent": self.source_agent.to_dict(),
            "source_interface": self.source_interface.to_dict(),
            "evidence_references": self.evidence_references,
            "unknown_fields": self.unknown_fields
        }

    def to_canonical_json(self) -> str:
        """Serializes the profile to deterministic, bit-for-bit reproducible JSON."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'), ensure_ascii=True)

    def compute_digest(self) -> str:
        """Computes the SHA-256 digest of the canonical JSON serialization."""
        return hashlib.sha256(self.to_canonical_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilitySemanticProfile":
        return cls(
            capability_id=data["capability_id"],
            display_name=ProfileField.from_dict(data["display_name"]),
            description=ProfileField.from_dict(data["description"]),
            category=ProfileField.from_dict(data["category"]),
            inputs=ProfileField.from_dict(data["inputs"]),
            required_inputs=ProfileField.from_dict(data["required_inputs"]),
            optional_inputs=ProfileField.from_dict(data["optional_inputs"]),
            output_schema=ProfileField.from_dict(data["output_schema"]),
            dependencies=ProfileField.from_dict(data["dependencies"]),
            permissions=ProfileField.from_dict(data["permissions"]),
            limitations=ProfileField.from_dict(data["limitations"]),
            source_agent=ProfileField.from_dict(data["source_agent"]),
            source_interface=ProfileField.from_dict(data["source_interface"]),
            evidence_references=data.get("evidence_references", {}),
            profile_version=data.get("profile_version", 1),
            created_at=data.get("created_at")
        )


# ----------------------------------------------------------------------------
# Service: CapabilityProfileService
# ----------------------------------------------------------------------------

class CapabilityProfileService:
    """
    Manages semantic profile generation, schema parameter extraction, evidence
    classification, and bit-for-bit reproducible CAS storage.
    """
    def __init__(self, conn: sqlite3.Connection, cas_engine: SecureCASStorageEngine):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("conn must be a sqlite3.Connection")
        if not isinstance(cas_engine, SecureCASStorageEngine):
            raise TypeError("cas_engine must be a SecureCASStorageEngine")

        self.conn = conn
        self.cas_engine = cas_engine
        self._ensure_foreign_keys()
        self.ensure_schema()

    def _ensure_foreign_keys(self) -> None:
        """Enforces that SQLite foreign keys are active."""
        if self.conn.in_transaction:
            raise SQLiteForeignKeyEnforcementError(
                "Cannot enable SQLite foreign-key enforcement during an active uncommitted transaction."
            )
        cur = self.conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        row = cur.fetchone()
        if not row or row[0] != 1:
            self.conn.execute("PRAGMA foreign_keys = ON;")
            cur.execute("PRAGMA foreign_keys;")
            check_row = cur.fetchone()
            if not check_row or check_row[0] != 1:
                raise SQLiteForeignKeyEnforcementError("Failed to enable SQLite foreign-key enforcement")

    def ensure_schema(self) -> None:
        """Idempotently ensures the capability_semantic_profiles table exists."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS capability_semantic_profiles (
                capability_urn TEXT PRIMARY KEY,
                profile_version INTEGER NOT NULL DEFAULT 1,
                profile_blob_digest TEXT NOT NULL,
                generated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (capability_urn) REFERENCES capability_declarations(capability_urn) ON DELETE RESTRICT,
                FOREIGN KEY (profile_blob_digest) REFERENCES content_chunk_blobs(blob_digest) ON DELETE RESTRICT
            );
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_semantic_profile_digest
            ON capability_semantic_profiles(profile_blob_digest);
        """)
        self.conn.commit()

    @staticmethod
    def extract_parameters_from_schema(input_schema: Optional[Dict[str, Any]]) -> Tuple[
        ProfileField, ProfileField, ProfileField
    ]:
        """
        Deterministically extracts input parameters, types, required, and optional sets
        from a JSON Schema or Pydantic-generated schema.
        """
        if not input_schema or not isinstance(input_schema, dict):
            return (
                ProfileField(value=None, evidence=EvidenceSource.UNKNOWN, notes="No input schema declared or attached."),
                ProfileField(value=[], evidence=EvidenceSource.UNKNOWN, notes="No required inputs declared."),
                ProfileField(value=[], evidence=EvidenceSource.UNKNOWN, notes="No optional inputs declared.")
            )

        properties = input_schema.get("properties")
        if properties is None:
            # Check if schema specifies type object with no properties (0 parameters)
            if input_schema.get("type") == "object":
                return (
                    ProfileField(value=[], evidence=EvidenceSource.EXTRACTED, notes="Schema explicitly specifies zero input parameters."),
                    ProfileField(value=[], evidence=EvidenceSource.EXTRACTED, notes="Zero required inputs."),
                    ProfileField(value=[], evidence=EvidenceSource.EXTRACTED, notes="Zero optional inputs.")
                )
            return (
                ProfileField(value=None, evidence=EvidenceSource.UNKNOWN, notes="Schema missing 'properties' dictionary."),
                ProfileField(value=[], evidence=EvidenceSource.UNKNOWN, notes="No required inputs declared."),
                ProfileField(value=[], evidence=EvidenceSource.UNKNOWN, notes="No optional inputs declared.")
            )

        required_keys = set(input_schema.get("required", []))
        param_profiles: List[Dict[str, Any]] = []
        required_names: List[str] = []
        optional_names: List[str] = []

        for prop_name, prop_def in sorted(properties.items()):
            if not isinstance(prop_def, dict):
                prop_def = {}

            # Type extraction (handles arrays, anyOf, oneOf)
            param_type = prop_def.get("type")
            if param_type == "array":
                item_type = prop_def.get("items", {}).get("type", "any")
                param_type = f"array of {item_type}"
            elif not param_type:
                union_types = prop_def.get("anyOf", prop_def.get("oneOf", []))
                if union_types:
                    param_type = " | ".join(t.get("type", "any") for t in union_types if isinstance(t, dict))
                else:
                    param_type = "any"

            desc = prop_def.get("description") or prop_def.get("title")
            default_val = prop_def.get("default")
            is_req = prop_name in required_keys

            if is_req:
                required_names.append(prop_name)
            else:
                optional_names.append(prop_name)

            p = ParameterProfile(
                name=prop_name,
                param_type=param_type,
                required=is_req,
                description=desc,
                default=default_val,
                evidence=EvidenceSource.EXTRACTED
            )
            param_profiles.append(p.to_dict())

        return (
            ProfileField(
                value=param_profiles,
                evidence=EvidenceSource.EXTRACTED,
                notes="Deterministically extracted from input schema properties."
            ),
            ProfileField(
                value=sorted(required_names),
                evidence=EvidenceSource.EXTRACTED,
                notes="Deterministically extracted from schema 'required' constraint."
            ),
            ProfileField(
                value=sorted(optional_names),
                evidence=EvidenceSource.EXTRACTED,
                notes="Deterministically identified as non-required schema properties."
            )
        )

    def generate_profile_from_declaration(self, capability_urn: str) -> CapabilitySemanticProfile:
        """
        Generates an authoritative semantic profile from existing database & CAS declarations.
        Correctly flags missing schema properties as UNKNOWN.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT definition_blob_digest, display_name, capability_type, registered_at
            FROM capability_declarations
            WHERE capability_urn = ?;
        """, (capability_urn,))
        row = cur.fetchone()
        if not row:
            raise CapabilityNotFoundError(f"Capability '{capability_urn}' is not registered.")

        def_digest, db_display_name, cap_type, registered_at = row

        # Read canonical CapabilityDefinition from CAS
        raw_bytes = self.cas_engine.read_blob(def_digest)
        cap_data = json.loads(raw_bytes.decode("utf-8"))

        prov = cap_data.get("provenance", {})
        description = cap_data.get("description", "")
        display_name = cap_data.get("display_name", db_display_name)

        # Check bound interface and agent
        cur.execute("""
            SELECT b.interface_urn, i.agent_urn, i.declaration_blob_digest
            FROM interface_capability_bindings b
            JOIN interface_declarations i ON b.interface_urn = i.interface_urn
            WHERE b.capability_urn = ?
            LIMIT 1;
        """, (capability_urn,))
        binding_row = cur.fetchone()
        if binding_row:
            iface_urn, agent_urn, iface_digest = binding_row
        else:
            iface_urn, agent_urn, iface_digest = None, None, None

        # Check attestation
        attestation_id = None
        if iface_urn:
            cur.execute("""
                SELECT attestation_id FROM interface_attestations
                WHERE interface_urn = ? ORDER BY created_at DESC LIMIT 1;
            """, (iface_urn,))
            att_row = cur.fetchone()
            if att_row:
                attestation_id = att_row[0]

        # Check category from FTS5 if available
        category = "utility"
        try:
            cur.execute("SELECT category FROM capability_fts WHERE capability_urn = ?;", (capability_urn,))
            fts_row = cur.fetchone()
            if fts_row and fts_row[0]:
                category = fts_row[0]
        except sqlite3.OperationalError:
            pass

        # Check policy status
        policy_status = "UNVERIFIED"
        if iface_urn:
            cur.execute("""
                SELECT status FROM interface_policy_decisions
                WHERE interface_urn = ? ORDER BY evaluated_at DESC LIMIT 1;
            """, (iface_urn,))
            dec_row = cur.fetchone()
            if dec_row:
                policy_status = dec_row[0]

        # Extract embedded schema if present in provenance or definition, otherwise UNKNOWN
        raw_input_schema = prov.get("input_schema") or cap_data.get("input_schema")
        raw_output_schema = prov.get("output_schema") or cap_data.get("output_schema")

        return self.generate_profile_from_schema(
            capability_urn=capability_urn,
            display_name=display_name,
            description=description,
            input_schema=raw_input_schema,
            output_schema=raw_output_schema,
            category=category,
            agent_urn=agent_urn,
            interface_urn=iface_urn,
            attestation_id=attestation_id,
            policy_status=policy_status,
            source_origin=prov.get("source_origin"),
            source_author=prov.get("author"),
            definition_digest=def_digest
        )

    def generate_profile_from_schema(
        self,
        capability_urn: str,
        display_name: str,
        description: Optional[str] = None,
        input_schema: Optional[Dict[str, Any]] = None,
        output_schema: Optional[Dict[str, Any]] = None,
        category: Optional[str] = None,
        agent_urn: Optional[str] = None,
        interface_urn: Optional[str] = None,
        attestation_id: Optional[str] = None,
        policy_status: Optional[str] = None,
        source_origin: Optional[str] = None,
        source_author: Optional[str] = None,
        definition_digest: Optional[str] = None,
        created_at: Optional[str] = None
    ) -> CapabilitySemanticProfile:
        """
        Constructs a complete semantic profile with evidence classification across all fields.
        Preserves original creation timestamp if profile was already recorded for this capability URN.
        """
        if created_at is None and hasattr(self, "conn") and self.conn:
            try:
                cur = self.conn.cursor()
                cur.execute("""
                    SELECT profile_blob_digest, generated_at
                    FROM capability_semantic_profiles
                    WHERE capability_urn = ?;
                """, (capability_urn,))
                row = cur.fetchone()
                if row and row[0]:
                    if hasattr(self, "cas_engine") and self.cas_engine and self.cas_engine.blob_exists(row[0]):
                        pdata = json.loads(self.cas_engine.read_blob(row[0]).decode("utf-8"))
                        created_at = pdata.get("created_at") or row[1]
                    else:
                        created_at = row[1]
            except Exception:
                pass
        # 1. Display name
        if display_name and display_name.strip():
            display_field = ProfileField(
                value=display_name.strip(),
                evidence=EvidenceSource.EXPLICIT,
                notes="Explicitly declared title/name."
            )
        else:
            parsed = parse_canonical_urn(capability_urn)
            fallback_name = " ".join(w.capitalize() for w in parsed.identifier.split("-"))
            display_field = ProfileField(
                value=fallback_name,
                evidence=EvidenceSource.EXTRACTED,
                notes="Deterministically extracted from canonical identifier."
            )

        # 2. Description
        if description and description.strip():
            if description.startswith("Tool '") and "discovered from MCP server" in description:
                desc_field = ProfileField(
                    value=description.strip(),
                    evidence=EvidenceSource.INFERRED,
                    notes="Generated default description fallback."
                )
            else:
                desc_field = ProfileField(
                    value=description.strip(),
                    evidence=EvidenceSource.EXPLICIT,
                    notes="Explicitly declared in author specification."
                )
        else:
            desc_field = ProfileField(
                value="",
                evidence=EvidenceSource.UNKNOWN,
                notes="No description declared or provided."
            )

        # 3. Category
        cat_val = (category or "utility").strip()
        cat_field = ProfileField(
            value=cat_val,
            evidence=EvidenceSource.INFERRED,
            notes="Inferred via keyword analysis heuristics."
        )

        # 4. Inputs, required, optional
        inputs_field, req_field, opt_field = self.extract_parameters_from_schema(input_schema)

        # 5. Output schema
        if output_schema and isinstance(output_schema, dict) and output_schema:
            out_field = ProfileField(
                value=output_schema,
                evidence=EvidenceSource.EXTRACTED,
                notes="Deterministically extracted from tool outputSchema."
            )
        else:
            out_field = ProfileField(
                value=None,
                evidence=EvidenceSource.UNKNOWN,
                notes="Output schema not declared or provided by tool."
            )

        # 6. Operational boundaries (Dependencies, Permissions, Limitations)
        # In MCP standard protocol, these are not declared.
        dep_field = ProfileField(
            value=[],
            evidence=EvidenceSource.UNKNOWN,
            notes="No external dependencies declared in capability metadata."
        )
        perm_field = ProfileField(
            value=[],
            evidence=EvidenceSource.UNKNOWN,
            notes="No runtime permissions declared in capability metadata."
        )
        lim_field = ProfileField(
            value=[],
            evidence=EvidenceSource.UNKNOWN,
            notes="No operational limitations declared by provider."
        )

        # 7. Source agent & interface
        if agent_urn:
            agent_field = ProfileField(
                value=agent_urn,
                evidence=EvidenceSource.EXPLICIT,
                notes="Resolved from authoritative agent declaration."
            )
        else:
            agent_field = ProfileField(
                value=None,
                evidence=EvidenceSource.UNKNOWN,
                notes="No source agent declaration resolved."
            )

        if interface_urn:
            iface_field = ProfileField(
                value=interface_urn,
                evidence=EvidenceSource.EXPLICIT,
                notes="Resolved from authoritative interface binding."
            )
        else:
            iface_field = ProfileField(
                value=None,
                evidence=EvidenceSource.UNKNOWN,
                notes="No source interface binding resolved."
            )

        # 8. Evidence references
        ev_refs: Dict[str, Any] = {}
        if definition_digest:
            ev_refs["definition_blob_digest"] = definition_digest
        if interface_urn:
            ev_refs["interface_urn"] = interface_urn
        if attestation_id:
            ev_refs["attestation_id"] = attestation_id
        if policy_status:
            ev_refs["policy_status"] = policy_status
        if source_origin:
            ev_refs["source_origin"] = source_origin
        if source_author:
            ev_refs["source_author"] = source_author

        return CapabilitySemanticProfile(
            capability_id=capability_urn,
            display_name=display_field,
            description=desc_field,
            category=cat_field,
            inputs=inputs_field,
            required_inputs=req_field,
            optional_inputs=opt_field,
            output_schema=out_field,
            dependencies=dep_field,
            permissions=perm_field,
            limitations=lim_field,
            source_agent=agent_field,
            source_interface=iface_field,
            evidence_references=ev_refs,
            profile_version=1,
            created_at=created_at
        )

    def store_profile(self, profile: CapabilitySemanticProfile) -> str:
        """
        Stores the canonical semantic profile into CAS and records the binding
        in capability_semantic_profiles under transaction safety.
        Returns the SHA-256 digest of the stored CAS blob.
        """
        canonical_json = profile.to_canonical_json()
        payload_bytes = canonical_json.encode("utf-8")
        digest = hashlib.sha256(payload_bytes).hexdigest()
        byte_len = len(payload_bytes)

        # 1. Write to CAS staging and publish only if not already published
        if not self.cas_engine.blob_exists(digest):
            pub_id = f"prof_pub_{digest[:16]}_{uuid.uuid4().hex[:8]}"
            pub_tok = f"tok_{uuid.uuid4().hex[:16]}"
            tmp_name, _, _ = self.cas_engine.write_payload_to_staging(pub_id, pub_tok, digest, payload_bytes)
            self.cas_engine.publish_staging_to_cas(tmp_name, digest)

        # 2. Persist in database
        in_tx = self.conn.in_transaction
        if not in_tx:
            self.conn.execute("BEGIN IMMEDIATE;")
        try:
            self.conn.execute("""
                INSERT OR IGNORE INTO content_chunk_blobs (
                    blob_digest, byte_length, storage_compression, stored_byte_length
                ) VALUES (?, ?, 'NONE', ?);
            """, (digest, byte_len, byte_len))

            self.conn.execute("""
                INSERT OR REPLACE INTO capability_semantic_profiles (
                    capability_urn, profile_version, profile_blob_digest, generated_at
                ) VALUES (?, ?, ?, ?);
            """, (profile.capability_id, profile.profile_version, digest, profile.created_at))

            if not in_tx:
                self.conn.commit()
            return digest
        except Exception:
            if not in_tx:
                self.conn.rollback()
            raise

    def get_profile(self, capability_urn: str) -> CapabilitySemanticProfile:
        """
        Retrieves the semantic profile for a capability from CAS storage.
        If not yet stored, generates it on-demand from authoritative declarations,
        persists it into CAS, and returns the verified profile.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT profile_blob_digest FROM capability_semantic_profiles
            WHERE capability_urn = ?;
        """, (capability_urn,))
        row = cur.fetchone()

        if row and row[0]:
            digest = row[0]
            if self.cas_engine.blob_exists(digest):
                raw_bytes = self.cas_engine.read_blob(digest)
                profile_data = json.loads(raw_bytes.decode("utf-8"))
                return CapabilitySemanticProfile.from_dict(profile_data)

        # Generate on-demand from existing declaration
        profile = self.generate_profile_from_declaration(capability_urn)
        self.store_profile(profile)
        return profile

    @staticmethod
    def format_profile_text(profile: CapabilitySemanticProfile) -> str:
        """Formats the profile for user-facing terminal inspection."""
        lines = []
        lines.append("=" * 74)
        lines.append(" LIVING CAPABILITY SYSTEM (LCS) — CAPABILITY SEMANTIC PROFILE")
        lines.append("=" * 74)
        lines.append(f"  Capability URN:      {profile.capability_id}")
        lines.append(f"  Display Name:        {profile.display_name.value} [{profile.display_name.evidence}]")
        lines.append(f"  Profile Version:     {profile.profile_version}")
        lines.append(f"  Generated At:        {profile.created_at}")

        lines.append("\n[Intended Purpose & Classification]")
        lines.append(f"  Description:         {profile.description.value or '(none)'}")
        lines.append(f"  Evidence Level:      {profile.description.evidence} ({profile.description.notes})")
        lines.append(f"  Category:            {profile.category.value}")
        lines.append(f"  Evidence Level:      {profile.category.evidence} ({profile.category.notes})")

        lines.append("\n[Input Parameters]")
        lines.append(f"  Evidence Level:      {profile.inputs.evidence} ({profile.inputs.notes})")
        if profile.inputs.value:
            for p in profile.inputs.value:
                req_str = "REQUIRED" if p.get("required") else "OPTIONAL"
                default_str = f", default={p.get('default')}" if p.get("default") is not None else ""
                desc_str = f" - {p.get('description')}" if p.get("description") else ""
                lines.append(f"  * {p.get('name')} ({p.get('type')}{default_str}) [{req_str}]{desc_str}")
        elif profile.inputs.evidence == EvidenceSource.EXTRACTED and profile.inputs.value == []:
            lines.append("  * (Zero input parameters required by schema)")
        else:
            lines.append("  * (Input parameter structure unknown or undeclared)")

        lines.append("\n[Output Schema]")
        lines.append(f"  Evidence Level:      {profile.output_schema.evidence} ({profile.output_schema.notes})")
        if profile.output_schema.value:
            props = profile.output_schema.value.get("properties", {})
            if props:
                for k, v in sorted(props.items()):
                    lines.append(f"  * {k} ({v.get('type', 'any')})")
            else:
                lines.append(f"  * {json.dumps(profile.output_schema.value)}")
        else:
            lines.append("  * (No output schema provided by tool declaration)")

        lines.append("\n[Operational Boundaries & Unknown Attributes]")
        lines.append(f"  * Dependencies:      {profile.dependencies.evidence} ({profile.dependencies.notes})")
        lines.append(f"  * Permissions:       {profile.permissions.evidence} ({profile.permissions.notes})")
        lines.append(f"  * Limitations:       {profile.limitations.evidence} ({profile.limitations.notes})")

        lines.append("\n[Source & Trust Verification]")
        lines.append(f"  Source Agent:        {profile.source_agent.value or '(unknown)'} [{profile.source_agent.evidence}]")
        lines.append(f"  Source Interface:    {profile.source_interface.value or '(unknown)'} [{profile.source_interface.evidence}]")
        lines.append(f"  Attestation ID:      {profile.evidence_references.get('attestation_id') or '(none)'}")
        lines.append(f"  Policy Decision:     {profile.evidence_references.get('policy_status') or 'UNKNOWN'}")
        lines.append(f"  Definition Digest:   {profile.evidence_references.get('definition_blob_digest') or '(none)'}")
        lines.append(f"  Origin URI:          {profile.evidence_references.get('source_origin') or '(none)'}")
        lines.append("=" * 74)
        return "\n".join(lines)
