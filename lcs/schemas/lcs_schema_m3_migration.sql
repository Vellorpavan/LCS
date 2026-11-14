-- ============================================================================
-- LCS STAGE 2B — MILESTONE 3 SCHEMA MIGRATION: INTERFACE ATTESTATION & POLICY
-- ============================================================================
-- Extends the LCS relational storage baseline with:
-- 1. Agent Declarations: Canonical agent entity identities with provenance.
-- 2. Interface Declarations: Canonical interface identities bound to agents and CAS blobs.
-- 3. Interface Capability Bindings: Referential mapping between interfaces and capability definitions.
-- 4. Interface Attestations: Cryptographic HMAC attestations binding interfaces to capability digests.
-- 5. Interface Policy Decisions: Persistent, explainable audit records of policy evaluations.
--
-- Strict Foreign-Key & Referential Integrity:
-- - All references use ON DELETE RESTRICT to prevent dangling references.
-- - Interfaces and agents are registered in entity_urn_registry.
-- - Blob digests reference content_chunk_blobs.
-- ============================================================================

-- 1. Agent Declarations
CREATE TABLE IF NOT EXISTS agent_declarations (
    agent_urn TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT,
    provenance_json TEXT NOT NULL,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (agent_urn) REFERENCES entity_urn_registry(entity_urn) ON DELETE RESTRICT
);

-- 2. Interface Declarations
CREATE TABLE IF NOT EXISTS interface_declarations (
    interface_urn TEXT PRIMARY KEY,
    agent_urn TEXT NOT NULL,
    interface_version INTEGER NOT NULL DEFAULT 1 CHECK (interface_version >= 1),
    display_name TEXT NOT NULL,
    description TEXT,
    declaration_blob_digest TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (interface_urn) REFERENCES entity_urn_registry(entity_urn) ON DELETE RESTRICT,
    FOREIGN KEY (agent_urn) REFERENCES agent_declarations(agent_urn) ON DELETE RESTRICT,
    FOREIGN KEY (declaration_blob_digest) REFERENCES content_chunk_blobs(blob_digest) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_interface_agent ON interface_declarations(agent_urn);
CREATE INDEX IF NOT EXISTS idx_interface_blob ON interface_declarations(declaration_blob_digest);

-- 3. Interface Capability Bindings (Maps an interface to its constituent capabilities)
CREATE TABLE IF NOT EXISTS interface_capability_bindings (
    binding_id TEXT PRIMARY KEY,
    interface_urn TEXT NOT NULL,
    capability_urn TEXT NOT NULL,
    expected_definition_digest TEXT NOT NULL,
    bound_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (interface_urn) REFERENCES interface_declarations(interface_urn) ON DELETE RESTRICT,
    FOREIGN KEY (capability_urn) REFERENCES capability_declarations(capability_urn) ON DELETE RESTRICT,
    FOREIGN KEY (expected_definition_digest) REFERENCES content_chunk_blobs(blob_digest) ON DELETE RESTRICT,
    UNIQUE (interface_urn, capability_urn)
);

CREATE INDEX IF NOT EXISTS idx_binding_interface ON interface_capability_bindings(interface_urn);
CREATE INDEX IF NOT EXISTS idx_binding_capability ON interface_capability_bindings(capability_urn);

-- 4. Cryptographic Interface Attestations
CREATE TABLE IF NOT EXISTS interface_attestations (
    attestation_id TEXT PRIMARY KEY,
    interface_urn TEXT NOT NULL,
    agent_urn TEXT NOT NULL,
    interface_version INTEGER NOT NULL,
    interface_digest TEXT NOT NULL,
    attester_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    attestation_blob_digest TEXT NOT NULL,
    attested_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (interface_urn) REFERENCES interface_declarations(interface_urn) ON DELETE RESTRICT,
    FOREIGN KEY (agent_urn) REFERENCES agent_declarations(agent_urn) ON DELETE RESTRICT,
    FOREIGN KEY (attestation_blob_digest) REFERENCES content_chunk_blobs(blob_digest) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_attestation_interface ON interface_attestations(interface_urn);
CREATE INDEX IF NOT EXISTS idx_attestation_key ON interface_attestations(key_id);

-- 5. Persistent Policy Evaluation Decisions (Audit Trail)
CREATE TABLE IF NOT EXISTS interface_policy_decisions (
    decision_id TEXT PRIMARY KEY,
    interface_urn TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    status TEXT NOT NULL CHECK (status IN ('VERIFIED', 'UNVERIFIED', 'REJECTED', 'UNAVAILABLE')),
    reasons_json TEXT NOT NULL,
    attestation_id TEXT,
    evaluated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (interface_urn) REFERENCES interface_declarations(interface_urn) ON DELETE RESTRICT,
    FOREIGN KEY (attestation_id) REFERENCES interface_attestations(attestation_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_policy_decision_interface ON interface_policy_decisions(interface_urn, policy_name);
