#!/usr/bin/env python3
"""
Living Capability System (LCS) — Unified Database Migration Manager
===================================================================
Applies and tracks sequential SQLite database migrations for LCS.

Migrations:
  1. 001_v2b_baseline       -> lcs_schema_v2b.sql
  2. 002_m3_interface_policy -> lcs_schema_m3_migration.sql
  3. 003_m4_discovery       -> lcs_schema_m4_migration.sql

Ensures:
  - Foreign key enforcement (PRAGMA foreign_keys = ON)
  - Write-Ahead Logging (PRAGMA journal_mode = WAL)
  - Busy timeout (30 seconds)
  - Cryptographic verification of migration script SHA-256
  - Idempotent tracking in lcs_schema_migrations table
"""

import os
import sys
import hashlib
import sqlite3
import datetime
from typing import List, Dict, Any, Tuple, Optional

MIGRATIONS_REGISTRY = [
    {
        "migration_id": "001_v2b_baseline",
        "filename": "lcs_schema_v2b.sql",
        "description": "Baseline LCS Stage 2B Schema (CAS, URN registry, Capabilities, Content chunks, GC receipts)"
    },
    {
        "migration_id": "002_m3_interface_policy",
        "filename": "lcs_schema_m3_migration.sql",
        "description": "Milestone 3 Interface Attestation, Agent Declarations, and Policy Evaluation Tables"
    },
    {
        "migration_id": "003_m4_discovery",
        "filename": "lcs_schema_m4_migration.sql",
        "description": "Milestone 4 FTS5 Full-Text Search Discovery Index, Triggers, and MCP Server Registrations"
    }
]


class MigrationError(Exception):
    """Raised when migration fails or integrity is compromised."""
    pass


class MigrationManager:
    """
    Manages database migrations for the Living Capability System.
    """

    def __init__(self, db_path: str, schema_dir: Optional[str] = None):
        self.db_path = db_path
        self.schema_dir = schema_dir or os.path.dirname(os.path.abspath(__file__))
        self._ensure_migrations_table()

    def get_connection(self) -> sqlite3.Connection:
        """Creates a properly configured SQLite connection."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 30000;")
        # Verify foreign keys are enabled
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        row = cur.fetchone()
        if not row or row[0] != 1:
            conn.close()
            raise MigrationError("Failed to enable foreign_keys pragma on SQLite connection.")
        return conn

    def _ensure_migrations_table(self) -> None:
        """Ensures the migrations tracking table exists."""
        conn = self.get_connection()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS lcs_schema_migrations (
                        migration_id TEXT PRIMARY KEY,
                        filename TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        description TEXT NOT NULL,
                        applied_at TEXT NOT NULL
                    );
                """)
        finally:
            conn.close()

    def get_applied_migrations(self) -> List[Dict[str, Any]]:
        """Returns records of all applied migrations."""
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT migration_id, filename, sha256, description, applied_at
                FROM lcs_schema_migrations
                ORDER BY migration_id ASC;
            """)
            rows = cur.fetchall()
            return [
                {
                    "migration_id": r[0],
                    "filename": r[1],
                    "sha256": r[2],
                    "description": r[3],
                    "applied_at": r[4]
                }
                for r in rows
            ]
        finally:
            conn.close()

    def get_status(self) -> List[Dict[str, Any]]:
        """Returns complete migration status across all known migrations."""
        applied_map = {m["migration_id"]: m for m in self.get_applied_migrations()}
        status_list = []

        for m_info in MIGRATIONS_REGISTRY:
            m_id = m_info["migration_id"]
            fn = m_info["filename"]
            file_path = os.path.join(self.schema_dir, fn)

            if not os.path.exists(file_path):
                raise MigrationError(f"Migration file missing from schema directory: {file_path}")

            with open(file_path, "rb") as f:
                content = f.read()
            actual_sha = hashlib.sha256(content).hexdigest()

            is_applied = m_id in applied_map
            applied_info = applied_map.get(m_id)

            status_list.append({
                "migration_id": m_id,
                "filename": fn,
                "description": m_info["description"],
                "file_sha256": actual_sha,
                "applied": is_applied,
                "applied_at": applied_info["applied_at"] if applied_info else None,
                "recorded_sha256": applied_info["sha256"] if applied_info else None
            })

        return status_list

    def apply_pending(self) -> List[str]:
        """Applies all pending migrations in strict registry order."""
        status = self.get_status()
        applied_now = []

        conn = self.get_connection()
        try:
            for item in status:
                if item["applied"]:
                    continue

                m_id = item["migration_id"]
                fn = item["filename"]
                file_path = os.path.join(self.schema_dir, fn)
                with open(file_path, "r", encoding="utf-8") as f:
                    sql_script = f.read()

                with open(file_path, "rb") as f:
                    file_sha = hashlib.sha256(f.read()).hexdigest()

                # Execute migration
                with conn:
                    conn.executescript(sql_script)
                    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    conn.execute("""
                        INSERT INTO lcs_schema_migrations (migration_id, filename, sha256, description, applied_at)
                        VALUES (?, ?, ?, ?, ?);
                    """, (m_id, fn, file_sha, item["description"], now_utc))

                applied_now.append(m_id)
        finally:
            conn.close()

        return applied_now

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verifies that all recorded migrations match on-disk file checksums."""
        status = self.get_status()
        issues = []
        for item in status:
            if item["applied"]:
                if item["file_sha256"] != item["recorded_sha256"]:
                    issues.append(
                        f"Checksum mismatch for {item['migration_id']}: "
                        f"recorded={item['recorded_sha256']}, disk={item['file_sha256']}"
                    )
        return len(issues) == 0, issues


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 migration_manager.py <db_path> [status|apply|verify]")
        sys.exit(1)

    db_path = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "status"
    mgr = MigrationManager(db_path)

    if action == "status":
        print(f"Migration Status for: {db_path}")
        for s in mgr.get_status():
            st = "APPLIED" if s["applied"] else "PENDING"
            print(f"  [{st}] {s['migration_id']} ({s['filename']}) - {s['applied_at'] or 'not applied'}")
    elif action == "apply":
        applied = mgr.apply_pending()
        print(f"Applied {len(applied)} migrations: {applied}")
    elif action == "verify":
        ok, issues = mgr.verify_integrity()
        if ok:
            print("Integrity verification passed: All migrations match recorded checksums.")
        else:
            print(f"Integrity issues found: {issues}")
            sys.exit(1)

