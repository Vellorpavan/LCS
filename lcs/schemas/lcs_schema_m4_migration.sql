-- ============================================================================
-- LCS STAGE 2B — MILESTONE 4 SCHEMA MIGRATION: CAPABILITY DISCOVERY & FTS5
-- ============================================================================
-- Extends the LCS relational storage baseline with:
-- 1. FTS5 Capability Discovery Index: Full-text search over capability metadata.
-- 2. MCP Server Registry: Audit records for connected local MCP servers.
-- ============================================================================

-- 1. MCP Server Registry Table
CREATE TABLE IF NOT EXISTS mcp_server_registrations (
    server_id TEXT PRIMARY KEY,
    server_name TEXT NOT NULL,
    transport_type TEXT NOT NULL CHECK (transport_type IN ('STDIO', 'LOCAL')),
    command_line TEXT,
    protocol_version TEXT NOT NULL DEFAULT '2024-11-05',
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_sync_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 2. FTS5 Virtual Table for Capability Discovery
-- Indexes name, description, capability_type, category, keywords, provenance.
CREATE VIRTUAL TABLE IF NOT EXISTS capability_fts USING fts5(
    capability_urn UNINDEXED,
    name,
    description,
    capability_type,
    category,
    keywords,
    provenance_author,
    provenance_origin,
    provenance_license,
    trust_status,
    tokenize = 'porter unicode61'
);
