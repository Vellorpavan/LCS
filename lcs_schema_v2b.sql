-- ============================================================================
-- Living Capability System (LCS) Authoritative Relational DDL
-- Specification Revision: Stage 2A.28
-- Authoritative Schema Definition, Publication Coordination & Wire-Bound Closure
-- ============================================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- 1. ENTITY URN REGISTRY & TYPED CORE IDENTITIES
-- ----------------------------------------------------------------------------

CREATE TABLE entity_urn_registry (
    entity_urn TEXT PRIMARY KEY,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN (
        'CAPABILITY', 'CONTENT_VARIANT', 'PHYSICAL_INSTANCE',
        'CONTENT_SNAPSHOT', 'VERIFICATION_RECEIPT', 'AUTHORITY_DECISION'
    )),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN (
        'PENDING', 'ACTIVE', 'DEPRECATED', 'REVOKED', 'ARCHIVED'
    )),
    registered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE capabilities (
    capability_urn TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (capability_urn) REFERENCES entity_urn_registry(entity_urn) ON DELETE RESTRICT
);

CREATE TABLE content_variants (
    variant_id TEXT PRIMARY KEY,
    capability_urn TEXT NOT NULL,
    variant_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (capability_urn) REFERENCES capabilities(capability_urn) ON DELETE RESTRICT
);

CREATE TABLE host_environments (
    host_urn TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os_type TEXT NOT NULL,
    arch TEXT NOT NULL,
    registered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE physical_source_instances (
    instance_id TEXT PRIMARY KEY,
    capability_urn TEXT NOT NULL,
    host_urn TEXT NOT NULL,
    root_path TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (capability_urn) REFERENCES capabilities(capability_urn) ON DELETE RESTRICT,
    FOREIGN KEY (host_urn) REFERENCES host_environments(host_urn) ON DELETE RESTRICT
);

-- ----------------------------------------------------------------------------
-- 2. SNAPSHOTS, CAS CHUNK BLOBS, ACTIVE PUBLICATIONS & MANIFESTS
-- ----------------------------------------------------------------------------

CREATE TABLE content_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    variant_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    is_finalized INTEGER NOT NULL DEFAULT 0 CHECK (is_finalized IN (0, 1)),
    capture_status TEXT NOT NULL CHECK (capture_status IN (
        'IN_PROGRESS', 'USERSPACE_AUDITED_STABLE', 'OS_SNAPSHOT_FROZEN', 'ABORTED'
    )),
    canonical_eligibility TEXT NOT NULL DEFAULT 'PENDING' CHECK (canonical_eligibility IN (
        'PENDING', 'ELIGIBLE', 'INELIGIBLE_COLLISION', 'INELIGIBLE_NON_UTF8'
    )),
    canonical_manifest_digest TEXT,
    source_fidelity_digest TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    finalized_at TEXT,
    FOREIGN KEY (variant_id) REFERENCES content_variants(variant_id) ON DELETE RESTRICT,
    FOREIGN KEY (instance_id) REFERENCES physical_source_instances(instance_id) ON DELETE RESTRICT,
    CHECK (
        (is_finalized = 0 AND capture_status = 'IN_PROGRESS' AND canonical_manifest_digest IS NULL AND source_fidelity_digest IS NULL AND finalized_at IS NULL)
        OR
        (is_finalized = 1 AND capture_status IN ('USERSPACE_AUDITED_STABLE', 'OS_SNAPSHOT_FROZEN') AND source_fidelity_digest IS NOT NULL AND finalized_at IS NOT NULL)
        OR
        (is_finalized = 0 AND capture_status = 'ABORTED')
    )
);

CREATE TABLE content_chunk_blobs (
    blob_digest TEXT PRIMARY KEY, -- 64-character lowercase hex SHA-256
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    storage_compression TEXT NOT NULL CHECK (storage_compression IN ('NONE', 'ZSTD')),
    stored_byte_length INTEGER NOT NULL CHECK (stored_byte_length >= 0),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (
        (storage_compression = 'NONE' AND stored_byte_length = byte_length)
        OR
        (storage_compression = 'ZSTD' AND stored_byte_length >= 0)
    ),
    CHECK (blob_digest GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]')
);

-- Active CAS Publications Table with Formal Lease State Machine & Heartbeat Tracking
CREATE TABLE active_cas_publications (
    publication_id TEXT PRIMARY KEY,
    blob_digest TEXT NOT NULL,
    worker_id TEXT NOT NULL DEFAULT 'worker_default',
    lease_token TEXT NOT NULL DEFAULT 'token_default',
    lease_state TEXT NOT NULL DEFAULT 'ACQUIRED' CHECK (lease_state IN (
        'ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED', 'COMMITTED', 'ABORTED'
    )),
    heartbeat_at TEXT NOT NULL DEFAULT (datetime('now')),
    lease_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (blob_digest GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]')
);

CREATE INDEX idx_active_pub_digest ON active_cas_publications(blob_digest, lease_state, lease_expires_at);
CREATE INDEX idx_active_pub_worker ON active_cas_publications(worker_id, lease_token);

-- ----------------------------------------------------------------------------
-- 2b. GC DELETION RESERVATION & ORPHAN AUDIT REGISTRY (Stage 2A.23)
-- ----------------------------------------------------------------------------

-- Coordinated GC Deletion Reservations Table
-- Coordinates SQLite transactional commit and descriptor-relative filesystem unlink.
CREATE TABLE cas_gc_deletion_reservations (
    blob_digest TEXT PRIMARY KEY,
    reservation_state TEXT NOT NULL CHECK (reservation_state IN (
        'RESERVED',                -- Candidate verified; deletion intent reserved
        'COMMITTED_FOR_UNLINK',    -- Database record committed; waiting for physical filesystem unlink
        'PHYSICALLY_DELETED',      -- Physical unlinkat completed & shard directory fsynced
        'REVERTED'                 -- Aborted/recovered
    )),
    gc_worker_id TEXT NOT NULL,
    reservation_token TEXT NOT NULL,
    reserved_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    CHECK (blob_digest GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]')
);

CREATE INDEX idx_gc_res_state_exp ON cas_gc_deletion_reservations(reservation_state, expires_at);

-- Verifiable Physical Deletion Evidence Receipts (Stage 2A.28)
-- Records cryptographic and operational proof of physical unlink and directory synchronization.
-- Transition to PHYSICALLY_DELETED strictly requires a corresponding verified receipt.
CREATE TABLE cas_physical_deletion_receipts (
    receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    blob_digest TEXT NOT NULL,
    reservation_token TEXT NOT NULL,
    key_id TEXT NOT NULL DEFAULT 'k1',
    unlinked_inode INTEGER NOT NULL,
    shard_inode INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    sync_method TEXT NOT NULL CHECK (sync_method IN ('F_FULLFSYNC', 'FSYNC')),
    sync_timestamp_ns INTEGER NOT NULL,
    receipt_signature TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (blob_digest) REFERENCES cas_gc_deletion_reservations(blob_digest)
);

CREATE INDEX idx_deletion_receipt_lookup ON cas_physical_deletion_receipts(blob_digest, reservation_token);

-- Verifiable GC Cancellation Evidence Receipts (Stage 2A.28)
-- Records cryptographic and operational proof of positive physical existence verification prior to cancellation.
-- Transition from COMMITTED_FOR_UNLINK to REVERTED strictly requires a verified cancellation receipt.
CREATE TABLE cas_gc_cancellation_receipts (
    cancellation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    blob_digest TEXT NOT NULL,
    reservation_token TEXT NOT NULL,
    key_id TEXT NOT NULL DEFAULT 'k1',
    verified_inode INTEGER NOT NULL,
    verified_bytes INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    verified_timestamp_ns INTEGER NOT NULL,
    receipt_signature TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (blob_digest) REFERENCES cas_gc_deletion_reservations(blob_digest)
);

CREATE INDEX idx_cancellation_receipt_lookup ON cas_gc_cancellation_receipts(blob_digest, reservation_token);


-- Quarantined Orphan Staging Records
-- Explicitly records staging files that failed descriptor-relative unlink during partial-write error cleanup.
CREATE TABLE cas_orphan_staging_records (
    orphan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tmp_filename TEXT NOT NULL UNIQUE,
    publication_id TEXT NOT NULL,
    lease_token TEXT NOT NULL,
    expected_digest TEXT NOT NULL,
    bytes_written INTEGER NOT NULL,
    error_message TEXT NOT NULL,
    quarantined_at TEXT NOT NULL DEFAULT (datetime('now')),
    recovered_at TEXT
);


CREATE TABLE snapshot_file_manifest (
    manifest_entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL,
    raw_path_bytes BLOB NOT NULL,
    escaped_path TEXT NOT NULL,
    canonical_logical_path TEXT,
    entry_type TEXT NOT NULL CHECK (entry_type IN ('F', 'D', 'L')),
    file_mode INTEGER NOT NULL CHECK (file_mode >= 0 AND file_mode <= 4294967295), -- Full u32 wire range
    uid INTEGER NOT NULL CHECK (uid >= 0 AND uid <= 4294967295),
    gid INTEGER NOT NULL CHECK (gid >= 0 AND gid <= 4294967295),
    mtime_sec INTEGER NOT NULL,
    mtime_nsec INTEGER NOT NULL CHECK (mtime_nsec >= 0 AND mtime_nsec <= 999999999),
    file_size INTEGER NOT NULL CHECK (file_size >= 0), -- Signed i64 non-negative up to 2^63-1
    content_blob_digest TEXT,
    symlink_target_bytes BLOB,
    path_encoding_status TEXT NOT NULL CHECK (path_encoding_status IN ('CLEAN_UTF8', 'ESCAPED_NON_UTF8')),
    canonical_collision_status TEXT NOT NULL DEFAULT 'UNIQUE' CHECK (canonical_collision_status IN ('UNIQUE', 'COLLISION', 'NON_CANONICAL')),
    FOREIGN KEY (snapshot_id) REFERENCES content_snapshots(snapshot_id) ON DELETE RESTRICT,
    FOREIGN KEY (content_blob_digest) REFERENCES content_chunk_blobs(blob_digest) ON DELETE RESTRICT,
    UNIQUE (snapshot_id, raw_path_bytes),
    UNIQUE (snapshot_id, escaped_path),
    -- Wire protocol 16-bit length limits (65,535 bytes maximum) strictly enforced in UTF-8 bytes
    CHECK (length(raw_path_bytes) > 0 AND length(raw_path_bytes) <= 65535),
    CHECK (canonical_logical_path IS NULL OR (length(CAST(canonical_logical_path AS BLOB)) > 0 AND length(CAST(canonical_logical_path AS BLOB)) <= 65535)),
    CHECK (canonical_logical_path IS NULL OR instr(canonical_logical_path, char(0)) = 0),
    CHECK (symlink_target_bytes IS NULL OR (length(symlink_target_bytes) > 0 AND length(symlink_target_bytes) <= 65535)),
    CHECK (symlink_target_bytes IS NULL OR instr(CAST(symlink_target_bytes AS TEXT), char(0)) = 0),
    -- Native DDL pure-SQL check: reject common decomposed NFD combining diacritical marks in UTF-8
    CHECK (canonical_logical_path IS NULL OR (
        hex(CAST(canonical_logical_path AS BLOB)) NOT GLOB '*CC[89AB]*' AND 
        hex(CAST(canonical_logical_path AS BLOB)) NOT GLOB '*CD[89AB]*'
    )),
    -- Canonical path separator and relative segment constraints
    CHECK (canonical_logical_path IS NULL OR substr(canonical_logical_path, 1, 1) != '/'),
    CHECK (canonical_logical_path IS NULL OR substr(canonical_logical_path, -1, 1) != '/'),
    CHECK (canonical_logical_path IS NULL OR instr(canonical_logical_path, '//') = 0),
    CHECK (canonical_logical_path IS NULL OR (
        canonical_logical_path != '.' AND 
        canonical_logical_path != '..' AND 
        instr(canonical_logical_path, '/./') = 0 AND 
        instr(canonical_logical_path, '/../') = 0 AND 
        substr(canonical_logical_path, 1, 2) != './' AND 
        substr(canonical_logical_path, 1, 3) != '../' AND 
        substr(canonical_logical_path, -2, 2) != '/.' AND 
        substr(canonical_logical_path, -3, 3) != '/..'
    )),
    CHECK (
        (entry_type = 'F' AND content_blob_digest IS NOT NULL AND symlink_target_bytes IS NULL)
        OR
        (entry_type = 'D' AND content_blob_digest IS NULL AND symlink_target_bytes IS NULL AND file_size = 0)
        OR
        (entry_type = 'L' AND content_blob_digest IS NULL AND symlink_target_bytes IS NOT NULL)
    ),
    CHECK (
        (path_encoding_status = 'CLEAN_UTF8' AND canonical_logical_path IS NOT NULL)
        OR
        (path_encoding_status = 'ESCAPED_NON_UTF8' AND canonical_logical_path IS NULL AND canonical_collision_status = 'NON_CANONICAL')
    )
);

CREATE INDEX idx_manifest_snapshot_raw ON snapshot_file_manifest(snapshot_id, raw_path_bytes);
CREATE INDEX idx_manifest_snapshot_escaped ON snapshot_file_manifest(snapshot_id, escaped_path);
CREATE INDEX idx_manifest_snapshot_canon ON snapshot_file_manifest(snapshot_id, canonical_logical_path);

-- ----------------------------------------------------------------------------
-- 3. VERIFICATION RECEIPTS & MUTUALLY EXCLUSIVE CONCRETE FK TARGETING
-- ----------------------------------------------------------------------------

CREATE TABLE verification_receipts (
    receipt_id TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('CAPABILITY', 'VARIANT', 'INSTANCE', 'SNAPSHOT')),
    target_capability_urn TEXT,
    target_variant_id TEXT,
    target_instance_id TEXT,
    target_snapshot_id TEXT,
    receipt_type TEXT NOT NULL CHECK (receipt_type IN (
        'STRUCTURAL_CHECKSUM', 'SEMANTIC_INTERFACE', 'POLICY_ATTESTATION',
        'DYNAMIC_TEST_PASS', 'SOURCE_INTEGRITY_PROVENANCE'
    )),
    verifier_identity TEXT NOT NULL,
    verified_at TEXT NOT NULL DEFAULT (datetime('now')),
    receipt_payload TEXT NOT NULL,
    FOREIGN KEY (target_capability_urn) REFERENCES capabilities(capability_urn) ON DELETE RESTRICT,
    FOREIGN KEY (target_variant_id) REFERENCES content_variants(variant_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_instance_id) REFERENCES physical_source_instances(instance_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_snapshot_id) REFERENCES content_snapshots(snapshot_id) ON DELETE RESTRICT,
    CHECK (
        (target_kind = 'CAPABILITY' AND target_capability_urn IS NOT NULL AND target_variant_id IS NULL AND target_instance_id IS NULL AND target_snapshot_id IS NULL)
        OR
        (target_kind = 'VARIANT'    AND target_capability_urn IS NULL AND target_variant_id IS NOT NULL AND target_instance_id IS NULL AND target_snapshot_id IS NULL)
        OR
        (target_kind = 'INSTANCE'   AND target_capability_urn IS NULL AND target_variant_id IS NULL AND target_instance_id IS NOT NULL AND target_snapshot_id IS NULL)
        OR
        (target_kind = 'SNAPSHOT'   AND target_capability_urn IS NULL AND target_variant_id IS NULL AND target_instance_id IS NULL AND target_snapshot_id IS NOT NULL)
    )
);

CREATE INDEX idx_receipt_target ON verification_receipts(target_kind, target_capability_urn, target_variant_id, target_instance_id, target_snapshot_id);

-- ----------------------------------------------------------------------------
-- 4. SCOPE HIERARCHY & RECURSIVE AUTHORITY DECISION MODEL
-- ----------------------------------------------------------------------------

CREATE TABLE authority_scopes (
    scope_urn TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('GLOBAL', 'HOST', 'PROJECT', 'SESSION')),
    description TEXT NOT NULL
);

CREATE TABLE registered_projects (
    project_urn TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE active_sessions (
    session_urn TEXT PRIMARY KEY,
    host_urn TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (host_urn) REFERENCES host_environments(host_urn) ON DELETE RESTRICT
);

CREATE TABLE authority_decisions (
    decision_id TEXT PRIMARY KEY,
    capability_urn TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('GLOBAL', 'HOST', 'PROJECT', 'SESSION')),
    scope_global_urn TEXT,
    scope_host_urn TEXT,
    scope_project_urn TEXT,
    scope_session_urn TEXT,
    scope_target_urn TEXT GENERATED ALWAYS AS (
        CASE scope_type
            WHEN 'GLOBAL'  THEN scope_global_urn
            WHEN 'HOST'    THEN scope_host_urn
            WHEN 'PROJECT' THEN scope_project_urn
            WHEN 'SESSION' THEN scope_session_urn
        END
    ) STORED,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'RESTRICTED')),
    policy_hash TEXT NOT NULL,
    granted_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (capability_urn) REFERENCES capabilities(capability_urn) ON DELETE RESTRICT,
    FOREIGN KEY (scope_global_urn) REFERENCES authority_scopes(scope_urn) ON DELETE RESTRICT,
    FOREIGN KEY (scope_host_urn) REFERENCES host_environments(host_urn) ON DELETE RESTRICT,
    FOREIGN KEY (scope_project_urn) REFERENCES registered_projects(project_urn) ON DELETE RESTRICT,
    FOREIGN KEY (scope_session_urn) REFERENCES active_sessions(session_urn) ON DELETE RESTRICT,
    CHECK (
        (scope_type = 'GLOBAL'  AND scope_global_urn IS NOT NULL  AND scope_host_urn IS NULL AND scope_project_urn IS NULL AND scope_session_urn IS NULL)
        OR
        (scope_type = 'HOST'    AND scope_global_urn IS NULL AND scope_host_urn IS NOT NULL  AND scope_project_urn IS NULL AND scope_session_urn IS NULL)
        OR
        (scope_type = 'PROJECT' AND scope_global_urn IS NULL AND scope_host_urn IS NULL AND scope_project_urn IS NOT NULL  AND scope_session_urn IS NULL)
        OR
        (scope_type = 'SESSION' AND scope_global_urn IS NULL AND scope_host_urn IS NULL AND scope_project_urn IS NULL AND scope_session_urn IS NOT NULL)
    )
);

CREATE INDEX idx_authority_cap_scope ON authority_decisions(capability_urn, scope_target_urn);

-- ----------------------------------------------------------------------------
-- 5. RECONSTRUCTION VIEWS
-- ----------------------------------------------------------------------------

-- Canonical Manifest Reconstruction View (filtered to eligible unique paths, ordered by canonical_logical_path)
CREATE VIEW v_canonical_manifest_reconstruction AS
SELECT 
    snapshot_id,
    canonical_logical_path,
    entry_type,
    content_blob_digest,
    symlink_target_bytes
FROM snapshot_file_manifest
WHERE canonical_collision_status = 'UNIQUE' AND canonical_logical_path IS NOT NULL
ORDER BY snapshot_id ASC, canonical_logical_path ASC;

-- Source Fidelity Manifest Reconstruction View (all entries, ordered by raw_path_bytes)
CREATE VIEW v_source_manifest_reconstruction AS
SELECT 
    snapshot_id,
    raw_path_bytes,
    entry_type,
    file_mode,
    uid,
    gid,
    mtime_sec,
    mtime_nsec,
    file_size,
    content_blob_digest,
    symlink_target_bytes
FROM snapshot_file_manifest
ORDER BY snapshot_id ASC, raw_path_bytes ASC;

-- ----------------------------------------------------------------------------
-- 6. IMMUTABILITY, TRANSITION & INTEGRITY TRIGGERS
-- ----------------------------------------------------------------------------

-- Registry Guard 1: Direct insert of ACTIVE registry entry is forbidden
CREATE TRIGGER trg_no_direct_active_registry_insert
BEFORE INSERT ON entity_urn_registry
FOR EACH ROW
WHEN NEW.lifecycle_state = 'ACTIVE'
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Direct insert of ACTIVE entity is forbidden; must register as PENDING first');
END;

-- Registry Guard 2: entity_urn is strictly immutable once inserted
CREATE TRIGGER trg_no_update_entity_urn
BEFORE UPDATE OF entity_urn ON entity_urn_registry
FOR EACH ROW
WHEN NEW.entity_urn IS NOT OLD.entity_urn
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: entity_urn is immutable');
END;

-- Registry Guard 3: entity_kind is strictly immutable once inserted
CREATE TRIGGER trg_no_update_entity_kind
BEFORE UPDATE OF entity_kind ON entity_urn_registry
FOR EACH ROW
WHEN NEW.entity_kind IS NOT OLD.entity_kind
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: entity_kind is immutable');
END;

-- Registry Guard 4: Enforce concrete typed entity row exists before activating
CREATE TRIGGER trg_verify_active_has_typed_record
BEFORE UPDATE ON entity_urn_registry
FOR EACH ROW
WHEN NEW.lifecycle_state = 'ACTIVE' AND OLD.lifecycle_state IS NOT 'ACTIVE'
BEGIN
    SELECT CASE
        WHEN NEW.entity_kind = 'CAPABILITY' AND NOT EXISTS (
            SELECT 1 FROM capabilities WHERE capability_urn = NEW.entity_urn
        ) THEN RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot activate CAPABILITY without concrete record in capabilities')
        
        WHEN NEW.entity_kind = 'CONTENT_VARIANT' AND NOT EXISTS (
            SELECT 1 FROM content_variants WHERE 'urn:lcs:variant:' || variant_id = NEW.entity_urn
        ) THEN RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot activate CONTENT_VARIANT without concrete record in content_variants')
        
        WHEN NEW.entity_kind = 'PHYSICAL_INSTANCE' AND NOT EXISTS (
            SELECT 1 FROM physical_source_instances WHERE 'urn:lcs:instance:' || instance_id = NEW.entity_urn
        ) THEN RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot activate PHYSICAL_INSTANCE without concrete record in physical_source_instances')
        
        WHEN NEW.entity_kind = 'CONTENT_SNAPSHOT' AND NOT EXISTS (
            SELECT 1 FROM content_snapshots WHERE 'urn:lcs:snapshot:' || snapshot_id = NEW.entity_urn
        ) THEN RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot activate CONTENT_SNAPSHOT without concrete record in content_snapshots')
        
        WHEN NEW.entity_kind = 'VERIFICATION_RECEIPT' AND NOT EXISTS (
            SELECT 1 FROM verification_receipts WHERE 'urn:lcs:receipt:' || receipt_id = NEW.entity_urn
        ) THEN RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot activate VERIFICATION_RECEIPT without concrete record in verification_receipts')
        
        WHEN NEW.entity_kind = 'AUTHORITY_DECISION' AND NOT EXISTS (
            SELECT 1 FROM authority_decisions WHERE 'urn:lcs:decision:' || decision_id = NEW.entity_urn
        ) THEN RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot activate AUTHORITY_DECISION without concrete record in authority_decisions')
    END;
END;

-- Registry Guard 5: Forbid deleting ACTIVE registry entry
CREATE TRIGGER trg_no_delete_active_registry_entry
BEFORE DELETE ON entity_urn_registry
FOR EACH ROW
WHEN OLD.lifecycle_state = 'ACTIVE'
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot delete ACTIVE registry entry');
END;

-- Capability Guard 1: capability_urn identity is immutable
CREATE TRIGGER trg_no_update_capability_urn
BEFORE UPDATE OF capability_urn ON capabilities
FOR EACH ROW
WHEN NEW.capability_urn IS NOT OLD.capability_urn
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: capability_urn is immutable');
END;

-- Capability Guard 2: Forbid deleting concrete capability while registry entry is ACTIVE
CREATE TRIGGER trg_no_delete_active_capability
BEFORE DELETE ON capabilities
FOR EACH ROW
WHEN (SELECT lifecycle_state FROM entity_urn_registry WHERE entity_urn = OLD.capability_urn) = 'ACTIVE'
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot delete concrete capability while registry entry is ACTIVE');
END;

-- Variant Guard 1: variant_id identity is immutable
CREATE TRIGGER trg_no_update_variant_id
BEFORE UPDATE OF variant_id ON content_variants
FOR EACH ROW
WHEN NEW.variant_id IS NOT OLD.variant_id
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: variant_id is immutable');
END;

-- Variant Guard 2: capability_urn parent binding is immutable
CREATE TRIGGER trg_no_update_variant_capability_urn
BEFORE UPDATE OF capability_urn ON content_variants
FOR EACH ROW
WHEN NEW.capability_urn IS NOT OLD.capability_urn
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: capability_urn of variant is immutable');
END;

-- Variant Guard 3: Forbid deleting concrete variant while registry entry is ACTIVE
CREATE TRIGGER trg_no_delete_active_variant
BEFORE DELETE ON content_variants
FOR EACH ROW
WHEN (SELECT lifecycle_state FROM entity_urn_registry WHERE entity_urn = 'urn:lcs:variant:' || OLD.variant_id) = 'ACTIVE'
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot delete concrete variant while registry entry is ACTIVE');
END;

-- Physical Instance Guard 1: instance_id identity is immutable
CREATE TRIGGER trg_no_update_instance_id
BEFORE UPDATE OF instance_id ON physical_source_instances
FOR EACH ROW
WHEN NEW.instance_id IS NOT OLD.instance_id
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: instance_id is immutable');
END;

-- Physical Instance Guard 2: capability_urn and host_urn bindings are immutable
CREATE TRIGGER trg_no_update_instance_bindings
BEFORE UPDATE OF capability_urn, host_urn ON physical_source_instances
FOR EACH ROW
WHEN NEW.capability_urn IS NOT OLD.capability_urn OR NEW.host_urn IS NOT OLD.host_urn
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: capability_urn and host_urn of physical instance are immutable');
END;

-- Physical Instance Guard 3: Forbid deleting concrete instance while registry entry is ACTIVE
CREATE TRIGGER trg_no_delete_active_instance
BEFORE DELETE ON physical_source_instances
FOR EACH ROW
WHEN (SELECT lifecycle_state FROM entity_urn_registry WHERE entity_urn = 'urn:lcs:instance:' || OLD.instance_id) = 'ACTIVE'
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot delete concrete instance while registry entry is ACTIVE');
END;

-- Snapshot Guard 1: snapshot_id identity is immutable
CREATE TRIGGER trg_no_update_snapshot_id
BEFORE UPDATE OF snapshot_id ON content_snapshots
FOR EACH ROW
WHEN NEW.snapshot_id IS NOT OLD.snapshot_id
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: snapshot_id is immutable');
END;

-- Snapshot Guard 2: variant_id and instance_id bindings are immutable
CREATE TRIGGER trg_no_update_snapshot_bindings
BEFORE UPDATE OF variant_id, instance_id ON content_snapshots
FOR EACH ROW
WHEN NEW.variant_id IS NOT OLD.variant_id OR NEW.instance_id IS NOT OLD.instance_id
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: variant_id and instance_id of snapshot are immutable');
END;

-- Snapshot Guard 3: Prevent direct insertion of finalized snapshots
CREATE TRIGGER trg_no_direct_finalized_snapshot_insert
BEFORE INSERT ON content_snapshots
FOR EACH ROW
WHEN NEW.is_finalized != 0
BEGIN
    SELECT RAISE(ABORT, 'FINALIZATION_INTEGRITY_ERROR: Snapshots cannot be inserted as finalized directly');
END;

-- Snapshot Guard 4: Enforce valid transition to finalized state with NULL-SAFE INDEPENDENT INTEGRITY CHECKS
CREATE TRIGGER trg_validate_finalization_transition
BEFORE UPDATE ON content_snapshots
FOR EACH ROW
WHEN OLD.is_finalized = 0 AND NEW.is_finalized = 1
BEGIN
    -- 1. Valid status check
    SELECT CASE
        WHEN NEW.capture_status NOT IN ('USERSPACE_AUDITED_STABLE', 'OS_SNAPSHOT_FROZEN')
        THEN RAISE(ABORT, 'FINALIZATION_INTEGRITY_ERROR: Finalized snapshot must have status USERSPACE_AUDITED_STABLE or OS_SNAPSHOT_FROZEN')
    END;

    -- 2. Source fidelity digest is strictly mandatory
    SELECT CASE
        WHEN NEW.source_fidelity_digest IS NULL
        THEN RAISE(ABORT, 'FINALIZATION_INTEGRITY_ERROR: source_fidelity_digest cannot be null on finalization')
    END;

    -- 3. Validate source_fidelity_digest format (64-char lowercase hex)
    SELECT CASE
        WHEN LENGTH(NEW.source_fidelity_digest) != 64 
             OR NEW.source_fidelity_digest NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
        THEN RAISE(ABORT, 'FINALIZATION_INTEGRITY_ERROR: source_fidelity_digest must be 64-char lowercase hex')
    END;

    -- 4. Require non-empty manifest
    SELECT CASE
        WHEN (SELECT COUNT(*) FROM snapshot_file_manifest WHERE snapshot_id = NEW.snapshot_id) = 0
        THEN RAISE(ABORT, 'FINALIZATION_INTEGRITY_ERROR: Cannot finalize snapshot with empty manifest')
    END;

    -- 5. BIDIRECTIONAL BLOB CHECK: Verify EVERY regular file entry references an existing blob with identical byte length (null-safe)
    SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM snapshot_file_manifest m
            LEFT JOIN content_chunk_blobs b ON m.content_blob_digest = b.blob_digest
            WHERE m.snapshot_id = NEW.snapshot_id
              AND m.entry_type = 'F'
              AND (b.blob_digest IS NULL OR m.file_size IS NOT b.byte_length)
        )
        THEN RAISE(ABORT, 'FINALIZATION_INTEGRITY_ERROR: Manifest contains file entries referencing missing or size-mismatched chunk blobs')
    END;

    -- 6. CANONICAL ELIGIBILITY INDEPENDENT VALIDATION (When canonical_manifest_digest IS PROVIDED)
    -- Check 6a: snapshot canonical_eligibility column must explicitly state ELIGIBLE (null-safe)
    SELECT CASE
        WHEN NEW.canonical_manifest_digest IS NOT NULL AND NEW.canonical_eligibility IS NOT 'ELIGIBLE'
        THEN RAISE(ABORT, 'CANONICAL_INTEGRITY_ERROR: Cannot finalize canonical manifest for snapshot whose canonical_eligibility is not ELIGIBLE')
    END;

    -- Check 6b: Independent check - Manifest must NOT contain any non-UTF8 paths (null-safe)
    SELECT CASE
        WHEN NEW.canonical_manifest_digest IS NOT NULL AND EXISTS (
            SELECT 1 FROM snapshot_file_manifest
            WHERE snapshot_id = NEW.snapshot_id AND (path_encoding_status IS NOT 'CLEAN_UTF8')
        )
        THEN RAISE(ABORT, 'CANONICAL_INTEGRITY_ERROR: Independent DB check failed: manifest contains non-UTF8 paths')
    END;

    -- Check 6c: Independent check - Manifest must NOT contain non-UNIQUE collision status rows (null-safe)
    SELECT CASE
        WHEN NEW.canonical_manifest_digest IS NOT NULL AND EXISTS (
            SELECT 1 FROM snapshot_file_manifest
            WHERE snapshot_id = NEW.snapshot_id AND (canonical_collision_status IS NOT 'UNIQUE')
        )
        THEN RAISE(ABORT, 'CANONICAL_INTEGRITY_ERROR: Independent DB check failed: manifest contains rows marked COLLISION or NON_CANONICAL')
    END;

    -- Check 6d: Independent check - Manifest must NOT contain NULL canonical_logical_path
    SELECT CASE
        WHEN NEW.canonical_manifest_digest IS NOT NULL AND EXISTS (
            SELECT 1 FROM snapshot_file_manifest
            WHERE snapshot_id = NEW.snapshot_id AND canonical_logical_path IS NULL
        )
        THEN RAISE(ABORT, 'CANONICAL_INTEGRITY_ERROR: Independent DB check failed: manifest contains NULL canonical_logical_path')
    END;

    -- Check 6e: Independent check - Manifest must NOT contain duplicate canonical_logical_path entries (NFC collisions)
    SELECT CASE
        WHEN NEW.canonical_manifest_digest IS NOT NULL AND EXISTS (
            SELECT canonical_logical_path FROM snapshot_file_manifest
            WHERE snapshot_id = NEW.snapshot_id
            GROUP BY canonical_logical_path
            HAVING COUNT(*) > 1
        )
        THEN RAISE(ABORT, 'CANONICAL_INTEGRITY_ERROR: Independent DB check failed: duplicate canonical_logical_path entries detected in manifest')
    END;

    -- Check 6f: Format check for canonical_manifest_digest (64-char lowercase hex)
    SELECT CASE
        WHEN NEW.canonical_manifest_digest IS NOT NULL AND (
             LENGTH(NEW.canonical_manifest_digest) != 64 
             OR NEW.canonical_manifest_digest NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
        )
        THEN RAISE(ABORT, 'FINALIZATION_INTEGRITY_ERROR: canonical_manifest_digest must be 64-char lowercase hex')
    END;
END;

-- Snapshot Guard 5: Block ANY update to finalized snapshots (Strict Immutability)
CREATE TRIGGER trg_no_update_finalized_snapshot
BEFORE UPDATE ON content_snapshots
FOR EACH ROW
WHEN OLD.is_finalized = 1
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_SNAPSHOT_ERROR: Finalized snapshots cannot be modified');
END;

-- Snapshot Guard 6: Block deletion of finalized snapshots
CREATE TRIGGER trg_no_delete_finalized_snapshot
BEFORE DELETE ON content_snapshots
FOR EACH ROW
WHEN OLD.is_finalized = 1
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_SNAPSHOT_ERROR: Finalized snapshots cannot be deleted');
END;

-- Snapshot Guard 7: Forbid deleting concrete snapshot while registry entry is ACTIVE
CREATE TRIGGER trg_no_delete_active_snapshot
BEFORE DELETE ON content_snapshots
FOR EACH ROW
WHEN (SELECT lifecycle_state FROM entity_urn_registry WHERE entity_urn = 'urn:lcs:snapshot:' || OLD.snapshot_id) = 'ACTIVE'
BEGIN
    SELECT RAISE(ABORT, 'REGISTRY_INTEGRITY_ERROR: Cannot delete concrete snapshot while registry entry is ACTIVE');
END;

-- Blob Guard 1: blob_digest in content_chunk_blobs is strictly immutable
CREATE TRIGGER trg_no_update_blob_digest
BEFORE UPDATE OF blob_digest ON content_chunk_blobs
FOR EACH ROW
WHEN NEW.blob_digest IS NOT OLD.blob_digest
BEGIN
    SELECT RAISE(ABORT, 'BLOB_INTEGRITY_ERROR: content_chunk_blobs blob_digest is immutable');
END;

-- Blob Guard 2: byte_length in content_chunk_blobs is strictly immutable
CREATE TRIGGER trg_no_update_blob_byte_length
BEFORE UPDATE OF byte_length ON content_chunk_blobs
FOR EACH ROW
WHEN NEW.byte_length IS NOT OLD.byte_length
BEGIN
    SELECT RAISE(ABORT, 'BLOB_INTEGRITY_ERROR: content_chunk_blobs byte_length is immutable');
END;

-- Manifest Guard 1: Enforce file_size == content_chunk_blobs.byte_length on INSERT (null-safe)
CREATE TRIGGER trg_verify_manifest_blob_size
BEFORE INSERT ON snapshot_file_manifest
FOR EACH ROW
WHEN NEW.entry_type = 'F'
BEGIN
    SELECT CASE
        WHEN NEW.file_size IS NOT (SELECT byte_length FROM content_chunk_blobs WHERE blob_digest = NEW.content_blob_digest)
        THEN RAISE(ABORT, 'BLOB_INTEGRITY_ERROR: manifest file_size does not match content_chunk_blobs byte_length')
    END;
END;

-- Manifest Guard 2: Enforce file_size == content_chunk_blobs.byte_length on UPDATE (null-safe)
CREATE TRIGGER trg_verify_manifest_blob_size_update
BEFORE UPDATE OF file_size, content_blob_digest ON snapshot_file_manifest
FOR EACH ROW
WHEN NEW.entry_type = 'F'
BEGIN
    SELECT CASE
        WHEN NEW.file_size IS NOT (SELECT byte_length FROM content_chunk_blobs WHERE blob_digest = NEW.content_blob_digest)
        THEN RAISE(ABORT, 'BLOB_INTEGRITY_ERROR: manifest file_size does not match content_chunk_blobs byte_length')
    END;
END;

-- Manifest Guard 3: snapshot_id and raw_path_bytes in manifest are immutable
CREATE TRIGGER trg_no_update_manifest_identity
BEFORE UPDATE OF snapshot_id, raw_path_bytes ON snapshot_file_manifest
FOR EACH ROW
WHEN NEW.snapshot_id IS NOT OLD.snapshot_id OR NEW.raw_path_bytes IS NOT OLD.raw_path_bytes
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: snapshot_id and raw_path_bytes in manifest are immutable');
END;

-- Manifest Guard 4: Block inserts into manifest of finalized snapshot
CREATE TRIGGER trg_no_insert_manifest_finalized
BEFORE INSERT ON snapshot_file_manifest
FOR EACH ROW
WHEN (SELECT is_finalized FROM content_snapshots WHERE snapshot_id = NEW.snapshot_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_MANIFEST_ERROR: Cannot insert into finalized manifest');
END;

-- Manifest Guard 5: Block updates to manifest of finalized snapshot
CREATE TRIGGER trg_no_update_manifest_finalized
BEFORE UPDATE ON snapshot_file_manifest
FOR EACH ROW
WHEN (SELECT is_finalized FROM content_snapshots WHERE snapshot_id = OLD.snapshot_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_MANIFEST_ERROR: Cannot update finalized manifest');
END;

-- Manifest Guard 6: Block deletion from manifest of finalized snapshot
CREATE TRIGGER trg_no_delete_manifest_finalized
BEFORE DELETE ON snapshot_file_manifest
FOR EACH ROW
WHEN (SELECT is_finalized FROM content_snapshots WHERE snapshot_id = OLD.snapshot_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_MANIFEST_ERROR: Cannot delete from finalized manifest');
END;

-- Receipt Guard 1: receipt_id identity is immutable
CREATE TRIGGER trg_no_update_receipt_id
BEFORE UPDATE OF receipt_id ON verification_receipts
FOR EACH ROW
WHEN NEW.receipt_id IS NOT OLD.receipt_id
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: receipt_id is immutable');
END;

-- Receipt Guard 2: target bindings of verification receipt are immutable
CREATE TRIGGER trg_no_update_receipt_targets
BEFORE UPDATE OF target_kind, target_capability_urn, target_variant_id, target_instance_id, target_snapshot_id ON verification_receipts
FOR EACH ROW
WHEN NEW.target_kind IS NOT OLD.target_kind
     OR NEW.target_capability_urn IS NOT OLD.target_capability_urn
     OR NEW.target_variant_id IS NOT OLD.target_variant_id
     OR NEW.target_instance_id IS NOT OLD.target_instance_id
     OR NEW.target_snapshot_id IS NOT OLD.target_snapshot_id
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: target bindings of verification receipt are immutable');
END;

-- Receipt Guard 3: Append-only verification receipts (no updates)
CREATE TRIGGER trg_no_update_receipts
BEFORE UPDATE ON verification_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_RECEIPT_ERROR: Verification receipts are append-only');
END;

-- Receipt Guard 4: Append-only verification receipts (no deletions)
CREATE TRIGGER trg_no_delete_receipts
BEFORE DELETE ON verification_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_RECEIPT_ERROR: Verification receipts cannot be deleted');
END;

-- Decision Guard 1: decision_id identity is immutable
CREATE TRIGGER trg_no_update_decision_id
BEFORE UPDATE OF decision_id ON authority_decisions
FOR EACH ROW
WHEN NEW.decision_id IS NOT OLD.decision_id
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: decision_id is immutable');
END;

-- Decision Guard 2: capability and scope bindings of authority decision are immutable
CREATE TRIGGER trg_no_update_decision_targets
BEFORE UPDATE OF capability_urn, scope_type, scope_global_urn, scope_host_urn, scope_project_urn, scope_session_urn ON authority_decisions
FOR EACH ROW
WHEN NEW.capability_urn IS NOT OLD.capability_urn
     OR NEW.scope_type IS NOT OLD.scope_type
     OR NEW.scope_global_urn IS NOT OLD.scope_global_urn
     OR NEW.scope_host_urn IS NOT OLD.scope_host_urn
     OR NEW.scope_project_urn IS NOT OLD.scope_project_urn
     OR NEW.scope_session_urn IS NOT OLD.scope_session_urn
BEGIN
    SELECT RAISE(ABORT, 'IDENTITY_INTEGRITY_ERROR: capability and scope bindings of authority decision are immutable');
END;

-- Decision Guard 3: Append-only authority decisions (no updates)
CREATE TRIGGER trg_no_update_decisions
BEFORE UPDATE ON authority_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_DECISION_ERROR: Authority decisions are append-only');
END;

-- Decision Guard 4: Append-only authority decisions (no deletions)
CREATE TRIGGER trg_no_delete_decisions
BEFORE DELETE ON authority_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE_DECISION_ERROR: Authority decisions cannot be deleted');
END;

-- Manifest Guard: Native DDL Canonical Path Integrity Enforcement (Resistant to function replacement)
CREATE TRIGGER trg_manifest_validate_canonical_path_insert
BEFORE INSERT ON snapshot_file_manifest
FOR EACH ROW
WHEN NEW.canonical_logical_path IS NOT NULL
BEGIN
    SELECT CASE
        WHEN NEW.path_encoding_status != 'CLEAN_UTF8'
        THEN RAISE(ABORT, 'CANONICAL_PATH_INTEGRITY_ERROR: canonical_logical_path requires path_encoding_status CLEAN_UTF8')
        WHEN NEW.canonical_collision_status != 'UNIQUE'
        THEN RAISE(ABORT, 'CANONICAL_PATH_INTEGRITY_ERROR: canonical_logical_path requires canonical_collision_status UNIQUE')
        WHEN hex(CAST(NEW.canonical_logical_path AS BLOB)) GLOB '*CC[89AB]*' OR hex(CAST(NEW.canonical_logical_path AS BLOB)) GLOB '*CD[89AB]*'
        THEN RAISE(ABORT, 'CANONICAL_PATH_INTEGRITY_ERROR: Direct database write of decomposed NFD path rejected by native DDL guard; non-canonical paths must set canonical_collision_status to NON_CANONICAL and canonical_logical_path to NULL')
    END;
END;

CREATE TRIGGER trg_manifest_validate_canonical_path_update
BEFORE UPDATE OF canonical_logical_path, canonical_collision_status, path_encoding_status ON snapshot_file_manifest
FOR EACH ROW
WHEN NEW.canonical_logical_path IS NOT NULL
BEGIN
    SELECT CASE
        WHEN NEW.path_encoding_status != 'CLEAN_UTF8'
        THEN RAISE(ABORT, 'CANONICAL_PATH_INTEGRITY_ERROR: canonical_logical_path requires path_encoding_status CLEAN_UTF8')
        WHEN NEW.canonical_collision_status != 'UNIQUE'
        THEN RAISE(ABORT, 'CANONICAL_PATH_INTEGRITY_ERROR: canonical_logical_path requires canonical_collision_status UNIQUE')
        WHEN hex(CAST(NEW.canonical_logical_path AS BLOB)) GLOB '*CC[89AB]*' OR hex(CAST(NEW.canonical_logical_path AS BLOB)) GLOB '*CD[89AB]*'
        THEN RAISE(ABORT, 'CANONICAL_PATH_INTEGRITY_ERROR: Direct database update with decomposed NFD path rejected by native DDL guard; non-canonical paths must set canonical_collision_status to NON_CANONICAL and canonical_logical_path to NULL')
    END;
END;


-- ----------------------------------------------------------------------------
-- GC / PUBLISHER COORDINATION TRIGGERS (Stage 2A.23)
-- ----------------------------------------------------------------------------

-- Trigger 1: Prevent acquiring or activating publication lease for blob reserved for GC deletion
CREATE TRIGGER trg_pub_check_gc_reservation_insert
BEFORE INSERT ON active_cas_publications
FOR EACH ROW
WHEN NEW.lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED', 'COMMITTED')
BEGIN
    SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM cas_gc_deletion_reservations
            WHERE blob_digest = NEW.blob_digest
              AND (
                  reservation_state = 'COMMITTED_FOR_UNLINK'
                  OR (reservation_state = 'RESERVED' AND datetime('now') <= expires_at)
              )
        )
        THEN RAISE(ABORT, 'CAS_GC_CONFLICT: Cannot acquire or activate publication lease for blob currently reserved for GC deletion')
    END;
END;

-- Trigger 2: Prevent committing publication lease for blob reserved for GC deletion
CREATE TRIGGER trg_pub_check_gc_reservation_update
BEFORE UPDATE OF lease_state ON active_cas_publications
FOR EACH ROW
WHEN NEW.lease_state = 'COMMITTED'
BEGIN
    SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM cas_gc_deletion_reservations
            WHERE blob_digest = NEW.blob_digest
              AND (
                  reservation_state = 'COMMITTED_FOR_UNLINK'
                  OR (reservation_state = 'RESERVED' AND datetime('now') <= expires_at)
              )
        )
        THEN RAISE(ABORT, 'CAS_GC_CONFLICT: Cannot commit publication lease for blob currently reserved for GC deletion')
    END;
END;

-- Trigger 3: Prevent inserting blob into content_chunk_blobs while reserved for GC deletion
CREATE TRIGGER trg_blob_check_gc_reservation_insert
BEFORE INSERT ON content_chunk_blobs
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM cas_gc_deletion_reservations
            WHERE blob_digest = NEW.blob_digest
              AND (
                  reservation_state = 'COMMITTED_FOR_UNLINK'
                  OR (reservation_state = 'RESERVED' AND datetime('now') <= expires_at)
              )
        )
        THEN RAISE(ABORT, 'CAS_GC_CONFLICT: Cannot register blob into content_chunk_blobs while reserved for GC deletion')
    END;
END;

-- Trigger 4: Prevent referencing blob in snapshot manifest while reserved for GC deletion
CREATE TRIGGER trg_manifest_check_gc_reservation
BEFORE INSERT ON snapshot_file_manifest
FOR EACH ROW
WHEN NEW.content_blob_digest IS NOT NULL
BEGIN
    SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM cas_gc_deletion_reservations
            WHERE blob_digest = NEW.content_blob_digest
              AND (
                  reservation_state = 'COMMITTED_FOR_UNLINK'
                  OR (reservation_state = 'RESERVED' AND datetime('now') <= expires_at)
              )
        )
        THEN RAISE(ABORT, 'CAS_GC_CONFLICT: Cannot reference blob in manifest while reserved for GC deletion')
    END;
END;

-- Trigger 5: Prevent GC from reserving a blob that is actively referenced or leased
CREATE TRIGGER trg_gc_reservation_check_eligibility
BEFORE INSERT ON cas_gc_deletion_reservations
FOR EACH ROW
WHEN NEW.reservation_state IN ('RESERVED', 'COMMITTED_FOR_UNLINK')
BEGIN
    SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM snapshot_file_manifest
            WHERE content_blob_digest = NEW.blob_digest
        )
        THEN RAISE(ABORT, 'CAS_GC_ELIGIBILITY_ERROR: Cannot reserve blob that is referenced in snapshot_file_manifest')
        WHEN EXISTS (
            SELECT 1 FROM active_cas_publications
            WHERE blob_digest = NEW.blob_digest
              AND lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED', 'COMMITTED')
              AND datetime('now') <= lease_expires_at
        )
        THEN RAISE(ABORT, 'CAS_GC_ELIGIBILITY_ERROR: Cannot reserve blob that has an active unexpired publication lease')
    END;
END;


-- Trigger 6: Enforce legal initial reservation state on insert
CREATE TRIGGER trg_gc_reservation_validate_insert
BEFORE INSERT ON cas_gc_deletion_reservations
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN NEW.reservation_state NOT IN ('RESERVED', 'COMMITTED_FOR_UNLINK')
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Initial reservation state must be RESERVED or COMMITTED_FOR_UNLINK; cannot insert directly into terminal states')
    END;
END;

-- Trigger 7: Enforce legal state transitions, ownership token validation, and prevent skipping COMMITTED_FOR_UNLINK
CREATE TRIGGER trg_gc_reservation_validate_update
BEFORE UPDATE ON cas_gc_deletion_reservations
FOR EACH ROW
BEGIN
    -- Token validation: reservation_token cannot be mutated during update
    SELECT CASE
        WHEN NEW.reservation_token != OLD.reservation_token
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot alter reservation_token during state transition')
    END;
    
    -- State machine transitions validation
    SELECT CASE
        -- Terminal states cannot be altered
        WHEN OLD.reservation_state IN ('PHYSICALLY_DELETED', 'REVERTED')
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot alter terminal reservation state ' || OLD.reservation_state)
        
        -- Transitions from RESERVED:
        -- Must be COMMITTED_FOR_UNLINK or REVERTED (cannot jump to PHYSICALLY_DELETED)
        WHEN OLD.reservation_state = 'RESERVED' AND NEW.reservation_state NOT IN ('RESERVED', 'COMMITTED_FOR_UNLINK', 'REVERTED')
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Illegal state transition from RESERVED to ' || NEW.reservation_state || '; cannot bypass COMMITTED_FOR_UNLINK')
        
        -- Transitions from COMMITTED_FOR_UNLINK:
        -- Must be PHYSICALLY_DELETED, or REVERTED strictly with an authenticated cancellation receipt
        WHEN OLD.reservation_state = 'COMMITTED_FOR_UNLINK' AND NEW.reservation_state NOT IN ('COMMITTED_FOR_UNLINK', 'PHYSICALLY_DELETED', 'REVERTED')
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Illegal state transition from COMMITTED_FOR_UNLINK to ' || NEW.reservation_state)

        -- Transition from COMMITTED_FOR_UNLINK to REVERTED strictly requires verified physical existence cancellation receipt
        WHEN OLD.reservation_state = 'COMMITTED_FOR_UNLINK' AND NEW.reservation_state = 'REVERTED' AND NOT EXISTS (
            SELECT 1 FROM cas_gc_cancellation_receipts c
            WHERE c.blob_digest = NEW.blob_digest
              AND c.reservation_token = NEW.reservation_token
              AND length(c.receipt_signature) >= 16
        )
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot revert COMMITTED_FOR_UNLINK reservation without verified physical existence cancellation receipt')

        -- Transition to PHYSICALLY_DELETED strictly requires verified physical deletion receipt
        WHEN NEW.reservation_state = 'PHYSICALLY_DELETED' AND NOT EXISTS (
            SELECT 1 FROM cas_physical_deletion_receipts r
            WHERE r.blob_digest = NEW.blob_digest
              AND r.reservation_token = NEW.reservation_token
              AND r.sync_method IN ('F_FULLFSYNC', 'FSYNC')
              AND length(r.receipt_signature) >= 16
        )
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot transition to PHYSICALLY_DELETED without verified physical deletion receipt linking blob_digest and reservation_token')
    END;
END;

-- Trigger 8b: Validate physical deletion receipt insertion
-- Prevents direct SQL from forging deletion receipts without an active COMMITTED_FOR_UNLINK reservation
CREATE TRIGGER trg_validate_physical_deletion_receipt_insert
BEFORE INSERT ON cas_physical_deletion_receipts
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM cas_gc_deletion_reservations res
            WHERE res.blob_digest = NEW.blob_digest
              AND res.reservation_token = NEW.reservation_token
              AND res.reservation_state = 'COMMITTED_FOR_UNLINK'
        )
        THEN RAISE(ABORT, 'GC_RECEIPT_ERROR: Cannot record physical deletion receipt without an active reservation in COMMITTED_FOR_UNLINK state with matching token')
    END;
END;

-- Trigger 8c: Deletion receipts immutability (no UPDATE)
CREATE TRIGGER trg_no_update_physical_deletion_receipt
BEFORE UPDATE ON cas_physical_deletion_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'GC_RECEIPT_ERROR: Physical deletion receipts are immutable');
END;

-- Trigger 8d: Deletion receipts immutability (no DELETE)
CREATE TRIGGER trg_no_delete_physical_deletion_receipt
BEFORE DELETE ON cas_physical_deletion_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'GC_RECEIPT_ERROR: Physical deletion receipts are permanent audit records and cannot be deleted');
END;

-- Trigger 8e: Validate cancellation receipt insertion
-- Prevents direct SQL from forging cancellation receipts without an active reservation
CREATE TRIGGER trg_validate_cancellation_receipt_insert
BEFORE INSERT ON cas_gc_cancellation_receipts
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1 FROM cas_gc_deletion_reservations res
            WHERE res.blob_digest = NEW.blob_digest
              AND res.reservation_token = NEW.reservation_token
              AND res.reservation_state IN ('RESERVED', 'COMMITTED_FOR_UNLINK')
        )
        THEN RAISE(ABORT, 'GC_RECEIPT_ERROR: Cannot record cancellation receipt without an active reservation in RESERVED or COMMITTED_FOR_UNLINK state with matching token')
    END;
END;

-- Trigger 8f: Cancellation receipts immutability (no UPDATE)
CREATE TRIGGER trg_no_update_cancellation_receipt
BEFORE UPDATE ON cas_gc_cancellation_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'GC_RECEIPT_ERROR: Cancellation receipts are immutable');
END;

-- Trigger 8g: Cancellation receipts immutability (no DELETE)
CREATE TRIGGER trg_no_delete_cancellation_receipt
BEFORE DELETE ON cas_gc_cancellation_receipts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'GC_RECEIPT_ERROR: Cancellation receipts are permanent audit records and cannot be deleted');
END;

-- Trigger 8: Prevent premature deletion of active GC reservations
CREATE TRIGGER trg_gc_reservation_prevent_premature_delete
BEFORE DELETE ON cas_gc_deletion_reservations
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN OLD.reservation_state NOT IN ('PHYSICALLY_DELETED', 'REVERTED')
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot delete active reservation row before physical deletion is complete')
    END;
END;
