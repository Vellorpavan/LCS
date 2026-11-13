#!/usr/bin/env python3
"""
LCS — Capability Semantic Profile Test Suite
============================================
Verifies:
1. Profile generation from existing declarations.
2. Pydantic-generated MCP schemas handling.
3. Required and optional input detection.
4. Missing descriptions handling (INFERRED fallback vs UNKNOWN).
5. Missing output schemas handling (UNKNOWN).
6. Unknown dependencies and permissions handling.
7. Deterministic profile generation and bit-for-bit canonical serialization.
8. Profile versioning and schema validation.
9. CAS integrity (stored profile blobs, hash verification, retrieval).
10. Existing regression test continuity.
"""

import os
import sys
import json
import hashlib
import sqlite3
import tempfile
import shutil
import pytest

_DIR = os.path.dirname(os.path.abspath(__file__))

from capability_profile_v2b import (
    EvidenceSource,
    ProfileField,
    ParameterProfile,
    CapabilitySemanticProfile,
    CapabilityProfileService
)
from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_registry_v2b import (
    CapabilityRegistrationService,
    CapabilityDefinition
)
from interface_policy_v2b import (
    InterfacePolicyService,
    InterfaceDeclaration,
    InterfaceCapabilityRef,
    AgentDeclaration,
    InterfaceTrustPolicy
)


@pytest.fixture
def profile_test_env():
    """Sets up an isolated LCS environment with dedicated CAS, SQLite DB, and keys."""
    temp_dir = tempfile.mkdtemp(prefix="lcs_profile_test_")
    real_temp = os.path.realpath(temp_dir)
    db_path = os.path.join(real_temp, "lcs.db")
    cas_dir = os.path.join(real_temp, "cas")
    key_dir = os.path.join(real_temp, "keys")
    os.makedirs(key_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    schema_path = os.path.join(_DIR, "lcs_schema_v2b.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.commit()

    cas_engine = SecureCASStorageEngine(
        cas_root=cas_dir,
        trusted_anchor=real_temp,
        key_store_dir=key_dir
    )
    cap_service = CapabilityRegistrationService(conn, cas_engine)
    iface_service = InterfacePolicyService(conn, cas_engine, cap_service)
    profile_service = CapabilityProfileService(conn, cas_engine)

    yield {
        "conn": conn,
        "cas_engine": cas_engine,
        "cap_service": cap_service,
        "iface_service": iface_service,
        "profile_service": profile_service,
        "temp_dir": real_temp
    }

    conn.close()
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_01_profile_generation_from_existing_declarations(profile_test_env):
    """Test 1: Generates profile from existing registered declaration without MCP schema."""
    cap_service = profile_test_env["cap_service"]
    profile_service = profile_test_env["profile_service"]

    # Register capability directly in M2
    cap_def = CapabilityDefinition(
        capability_id="urn:lcs:tool:system.math:vector-dot-product",
        display_name="Vector Dot Product",
        description="Calculates inner product of two Euclidean vectors.",
        capability_type="tool",
        schema_version=1,
        input_interface_ref="urn:lcs:interface:schema:dot-input",
        output_interface_ref="urn:lcs:interface:schema:dot-output",
        provenance={
            "author": "math-subsystem",
            "created_at": "2026-11-11 00:00:00Z",
            "license": "MIT",
            "source_origin": "system://math/dot"
        }
    )
    reg_res = cap_service.register_capability(cap_def)

    # Generate profile from declaration
    prof = profile_service.generate_profile_from_declaration(cap_def.capability_id)

    assert prof.capability_id == cap_def.capability_id
    assert prof.display_name.value == "Vector Dot Product"
    assert prof.display_name.evidence == EvidenceSource.EXPLICIT
    assert prof.description.value == "Calculates inner product of two Euclidean vectors."
    assert prof.description.evidence == EvidenceSource.EXPLICIT
    assert prof.category.evidence == EvidenceSource.INFERRED

    # Since no raw schema was stored in M2 declaration, inputs and outputs are UNKNOWN
    assert prof.inputs.evidence == EvidenceSource.UNKNOWN
    assert prof.output_schema.evidence == EvidenceSource.UNKNOWN
    assert prof.dependencies.evidence == EvidenceSource.UNKNOWN
    assert prof.permissions.evidence == EvidenceSource.UNKNOWN
    assert prof.limitations.evidence == EvidenceSource.UNKNOWN

    assert "inputs" in prof.unknown_fields
    assert "output_schema" in prof.unknown_fields
    assert "dependencies" in prof.unknown_fields


def test_02_pydantic_generated_mcp_schemas(profile_test_env):
    """Test 2: Schema parameter extraction handles Pydantic/FastMCP schema structures."""
    profile_service = profile_test_env["profile_service"]

    pydantic_schema = {
        "properties": {
            "samples": {
                "items": {"type": "number"},
                "title": "Samples",
                "type": "array",
                "description": "List of numeric observation data points."
            },
            "ddof": {
                "default": 1,
                "title": "Ddof",
                "type": "integer",
                "description": "Delta degrees of freedom."
            },
            "metadata_filter": {
                "anyOf": [{"type": "string"}, {"type": "null"}],
                "title": "Metadata Filter",
                "default": None
            }
        },
        "required": ["samples"],
        "title": "calculate_statistical_varianceArguments",
        "type": "object"
    }

    inputs, req, opt = profile_service.extract_parameters_from_schema(pydantic_schema)

    assert inputs.evidence == EvidenceSource.EXTRACTED
    assert req.evidence == EvidenceSource.EXTRACTED
    assert opt.evidence == EvidenceSource.EXTRACTED

    param_dict = {p["name"]: p for p in inputs.value}
    assert "samples" in param_dict
    assert param_dict["samples"]["type"] == "array of number"
    assert param_dict["samples"]["required"] is True
    assert param_dict["samples"]["description"] == "List of numeric observation data points."

    assert "ddof" in param_dict
    assert param_dict["ddof"]["type"] == "integer"
    assert param_dict["ddof"]["required"] is False
    assert param_dict["ddof"]["default"] == 1

    assert "metadata_filter" in param_dict
    assert "string" in param_dict["metadata_filter"]["type"]

    assert req.value == ["samples"]
    assert sorted(opt.value) == ["ddof", "metadata_filter"]


def test_03_required_and_optional_input_detection(profile_test_env):
    """Test 3: Correctly partitions required vs optional inputs across different schema styles."""
    profile_service = profile_test_env["profile_service"]

    # Schema with 2 required and 2 optional
    schema = {
        "type": "object",
        "properties": {
            "file_a": {"type": "string"},
            "file_b": {"type": "string"},
            "threshold": {"type": "number", "default": 0.5},
            "verbose": {"type": "boolean", "default": False}
        },
        "required": ["file_a", "file_b"]
    }

    inputs, req, opt = profile_service.extract_parameters_from_schema(schema)
    assert set(req.value) == {"file_a", "file_b"}
    assert set(opt.value) == {"threshold", "verbose"}

    # Schema with all optional (no 'required' key)
    schema_no_req = {
        "type": "object",
        "properties": {
            "opt1": {"type": "string"},
            "opt2": {"type": "integer"}
        }
    }
    inputs2, req2, opt2 = profile_service.extract_parameters_from_schema(schema_no_req)
    assert req2.value == []
    assert set(opt2.value) == {"opt1", "opt2"}

    # Schema specifying type object with zero properties
    schema_empty_obj = {"type": "object"}
    inputs3, req3, opt3 = profile_service.extract_parameters_from_schema(schema_empty_obj)
    assert inputs3.value == []
    assert req3.value == []
    assert opt3.value == []


def test_04_missing_descriptions_classification(profile_test_env):
    """Test 4: Missing descriptions are classified as UNKNOWN or INFERRED (never false EXPLICIT)."""
    profile_service = profile_test_env["profile_service"]

    # Explicit author description
    prof_explicit = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:explicit-tool",
        display_name="Explicit Tool",
        description="Explicitly authored summary of tool operation."
    )
    assert prof_explicit.description.evidence == EvidenceSource.EXPLICIT

    # Fallback generated description
    prof_fallback = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:fallback-tool",
        display_name="Fallback Tool",
        description="Tool 'fallback_tool' discovered from MCP server 'test-server'."
    )
    assert prof_fallback.description.evidence == EvidenceSource.INFERRED

    # Completely missing description
    prof_missing = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:missing-tool",
        display_name="Missing Tool",
        description=""
    )
    assert prof_missing.description.evidence == EvidenceSource.UNKNOWN
    assert "description" in prof_missing.unknown_fields


def test_05_missing_output_schemas(profile_test_env):
    """Test 5: Missing output schemas are marked UNKNOWN, while present ones are EXTRACTED."""
    profile_service = profile_test_env["profile_service"]

    # Output schema provided
    prof_with_out = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:tool-with-output",
        display_name="Tool Output",
        output_schema={"type": "object", "properties": {"status": {"type": "string"}}}
    )
    assert prof_with_out.output_schema.evidence == EvidenceSource.EXTRACTED
    assert prof_with_out.output_schema.value["properties"]["status"]["type"] == "string"

    # Output schema missing
    prof_no_out = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:tool-no-output",
        display_name="Tool No Output",
        output_schema=None
    )
    assert prof_no_out.output_schema.evidence == EvidenceSource.UNKNOWN
    assert prof_no_out.output_schema.value is None
    assert "output_schema" in prof_no_out.unknown_fields


def test_06_unknown_dependencies_and_permissions(profile_test_env):
    """Test 6: Undeclared dependencies, permissions, and limitations are strictly UNKNOWN."""
    profile_service = profile_test_env["profile_service"]

    prof = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:boundary-check",
        display_name="Boundary Check"
    )

    # Must never invent fake permissions or dependencies
    assert prof.dependencies.evidence == EvidenceSource.UNKNOWN
    assert prof.dependencies.value == []

    assert prof.permissions.evidence == EvidenceSource.UNKNOWN
    assert prof.permissions.value == []

    assert prof.limitations.evidence == EvidenceSource.UNKNOWN
    assert prof.limitations.value == []

    assert "dependencies" in prof.unknown_fields
    assert "permissions" in prof.unknown_fields
    assert "limitations" in prof.unknown_fields


def test_07_deterministic_profile_generation(profile_test_env):
    """Test 7: Profile produces deterministic, bit-for-bit identical JSON and digests."""
    profile_service = profile_test_env["profile_service"]

    schema = {
        "type": "object",
        "properties": {
            "z_param": {"type": "string"},
            "a_param": {"type": "integer"}
        },
        "required": ["a_param"]
    }

    fixed_timestamp = "2026-11-11T12:00:00Z"

    prof1 = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:deterministic-tool",
        display_name="Deterministic Tool",
        description="A deterministic test capability.",
        input_schema=schema,
        created_at=fixed_timestamp
    )

    prof2 = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:deterministic-tool",
        display_name="Deterministic Tool",
        description="A deterministic test capability.",
        input_schema=schema,
        created_at=fixed_timestamp
    )

    json1 = prof1.to_canonical_json()
    json2 = prof2.to_canonical_json()
    assert json1 == json2

    digest1 = prof1.compute_digest()
    digest2 = prof2.compute_digest()
    assert digest1 == digest2


def test_08_profile_versioning_and_schema_validation(profile_test_env):
    """Test 8: Validates profile version number and rejects invalid evidence sources."""
    profile_service = profile_test_env["profile_service"]

    prof = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:test.pkg:versioned-tool",
        display_name="Versioned Tool"
    )
    assert prof.profile_version == 1

    d = prof.to_dict()
    assert d["schema_version"] == "semantic_profile_v1"
    assert d["profile_version"] == 1

    # Deserialization round-trip
    restored = CapabilitySemanticProfile.from_dict(d)
    assert restored.capability_id == prof.capability_id
    assert restored.profile_version == prof.profile_version

    # Invalid evidence source rejection
    with pytest.raises(ValueError) as exc:
        ProfileField(value="val", evidence="FABRICATED")
    assert "Invalid evidence source" in str(exc.value)


def test_09_cas_integrity_and_persistence(profile_test_env):
    """Test 9: Verified CAS storage, bit-for-bit retrieval, and tamper resistance."""
    cap_service = profile_test_env["cap_service"]
    cas_engine = profile_test_env["cas_engine"]
    profile_service = profile_test_env["profile_service"]
    conn = profile_test_env["conn"]

    # Register capability in M2
    cap_def = CapabilityDefinition(
        capability_id="urn:lcs:tool:test.pkg:cas-verified-tool",
        display_name="CAS Verified Tool",
        description="Stored in CAS with verified SHA-256.",
        capability_type="tool",
        schema_version=1,
        input_interface_ref="urn:lcs:interface:schema:verified-input",
        output_interface_ref="urn:lcs:interface:schema:verified-output",
        provenance={
            "author": "security-team",
            "created_at": "2026-11-11 00:00:00Z",
            "license": "Apache-2.0",
            "source_origin": "test://cas/tool"
        }
    )
    cap_service.register_capability(cap_def)

    # Generate and store profile
    prof = profile_service.generate_profile_from_declaration(cap_def.capability_id)
    blob_digest = profile_service.store_profile(prof)

    # 1. Verify blob exists in CAS
    assert cas_engine.blob_exists(blob_digest)

    # 2. Read blob directly and verify SHA-256
    raw_bytes = cas_engine.read_blob(blob_digest)
    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    assert actual_sha == blob_digest

    # 3. Retrieve through service
    retrieved = profile_service.get_profile(cap_def.capability_id)
    assert retrieved.capability_id == cap_def.capability_id
    assert retrieved.display_name.value == "CAS Verified Tool"

    # 4. Verify SQLite registration record
    cur = conn.cursor()
    cur.execute("""
        SELECT profile_version, profile_blob_digest FROM capability_semantic_profiles
        WHERE capability_urn = ?;
    """, (cap_def.capability_id,))
    row = cur.fetchone()
    assert row is not None
    assert row[0] == 1
    assert row[1] == blob_digest


def test_10_cli_formatting_and_terminal_output(profile_test_env):
    """Test 10: Validates terminal formatted output conventions."""
    profile_service = profile_test_env["profile_service"]

    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query text"},
            "limit": {"type": "integer", "default": 10}
        },
        "required": ["query"]
    }

    prof = profile_service.generate_profile_from_schema(
        capability_urn="urn:lcs:tool:cli.test:query-runner",
        display_name="Query Runner",
        description="Executes search queries.",
        input_schema=schema,
        output_schema={"type": "object", "properties": {"hits": {"type": "integer"}}},
        agent_urn="urn:lcs:agent:cli.test:host",
        interface_urn="urn:lcs:interface:cli.test:tools-v1",
        attestation_id="att_test_12345",
        policy_status="VERIFIED"
    )

    text = profile_service.format_profile_text(prof)

    assert "LIVING CAPABILITY SYSTEM (LCS) — CAPABILITY SEMANTIC PROFILE" in text
    assert "urn:lcs:tool:cli.test:query-runner" in text
    assert "Display Name:        Query Runner [EXPLICIT]" in text
    assert "Category:            utility" in text
    assert "Evidence Level:      INFERRED" in text
    assert "Evidence Level:      EXTRACTED" in text
    assert "* query (string) [REQUIRED] - Search query text" in text
    assert "* limit (integer, default=10) [OPTIONAL]" in text
    assert "* hits (integer)" in text
    assert "* Dependencies:      UNKNOWN" in text
    assert "* Permissions:       UNKNOWN" in text
    assert "* Limitations:       UNKNOWN" in text
    assert "Source Agent:        urn:lcs:agent:cli.test:host [EXPLICIT]" in text
    assert "Source Interface:    urn:lcs:interface:cli.test:tools-v1 [EXPLICIT]" in text
    assert "Attestation ID:      att_test_12345" in text
    assert "Policy Decision:     VERIFIED" in text
