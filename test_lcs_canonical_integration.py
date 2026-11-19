#!/usr/bin/env python3
"""
LCS Canonical Integration & CLI Verification Suite
=================================================
Verifies that the integrated LCS package and CLI tool operate end-to-end
in the canonical project workspace (/Users/pavan/Desktop/LCS).

Tests:
  1. Package Imports & API Surface Check
  2. Isolated LCSContext Lifecycle & Auto-Migration
  3. MigrationManager Idempotency & Checksum Integrity
  4. CLI 'status' Command Execution
  5. CLI 'discover' Command Execution against MCP Fixture
  6. CLI 'search' Command with Grounded FTS5 Results & Filtering
  7. CLI 'inspect' Command with CAS Definition Retrieval
  8. CLI 'explain' Command with Grounded Trust Policy Audit
  9. CLI Malformed & Unknown URN Fail-Closed Rejection
 10. CLI Empty & Zero-Match Query Safety
"""

import os
import sys
import json
import tempfile
import io
import contextlib

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import lcs
from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.migrations import MigrationManager
from lcs.cli import main


def run_cli_capture(argv: list, root_dir: str) -> tuple:
    """Runs CLI main() capturing stdout, stderr, and exit code."""
    full_argv = ["--root", root_dir] + argv
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        try:
            code = main(full_argv)
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


def test_01_package_imports_and_api():
    print("--- Test 01: Package Imports & API Surface Check ---")
    assert hasattr(lcs, "LCSConfig")
    assert hasattr(lcs, "LCSContext")
    assert hasattr(lcs, "SecureCASStorageEngine")
    assert hasattr(lcs, "PersistentReceiptKeyStore")
    assert hasattr(lcs, "CapabilityRegistrationService")
    assert hasattr(lcs, "CapabilityDefinition")
    assert hasattr(lcs, "InterfacePolicyService")
    assert hasattr(lcs, "InterfaceTrustPolicy")
    assert hasattr(lcs, "CapabilityDiscoveryPipeline")
    assert hasattr(lcs, "DiscoveryIndexService")
    assert hasattr(lcs, "MigrationManager")
    print("  Verified: All top-level symbols exported correctly in 'lcs' package.")


def test_02_context_lifecycle_and_migration():
    print("--- Test 02: Isolated LCSContext Lifecycle & Auto-Migration ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = LCSConfig.resolve(root_override=tmp_dir, schema_override=CURRENT_DIR)
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            assert os.path.exists(cfg.db_path)
            assert os.path.exists(cfg.cas_root)
            assert os.path.exists(cfg.key_store_dir)
            cur = ctx.conn.cursor()
            cur.execute("PRAGMA foreign_keys;")
            assert cur.fetchone()[0] == 1
            cur.execute("PRAGMA journal_mode;")
            assert cur.fetchone()[0].lower() == "wal"
    print("  Verified: LCSContext initialized with active WAL, FK=1, and applied migrations.")


def test_03_migration_manager_idempotency_and_integrity():
    print("--- Test 03: MigrationManager Idempotency & Checksum Integrity ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_p = os.path.join(tmp_dir, "mig_test.db")
        mgr = MigrationManager(db_p, schema_dir=CURRENT_DIR)
        applied1 = mgr.apply_pending()
        assert len(applied1) == 4
        # Idempotent re-run
        applied2 = mgr.apply_pending()
        assert len(applied2) == 0
        # Integrity check
        ok, issues = mgr.verify_integrity()
        assert ok, f"Integrity issues: {issues}"
    print("  Verified: All 4 migrations applied idempotently with verified checksums.")


def test_04_cli_status_command():
    print("--- Test 04: CLI 'status' Command Execution ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        code, out, err = run_cli_capture(["status"], tmp_dir)
        assert code == 0, f"Expected 0, got {code}. err: {err}"
        assert "LIVING CAPABILITY SYSTEM (LCS) — SYSTEM STATUS" in out
        assert "4/4 applied" in out
        assert "Foreign Keys:      ENABLED (1)" in out
    print("  Verified: 'lcs status' returns clean status across all subsystems.")


def test_05_cli_discover_command():
    print("--- Test 05: CLI 'discover' Command Execution against MCP Fixture ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        fixture_path = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        code, out, err = run_cli_capture([
            "discover",
            "--server-command", f"{sys.executable} {fixture_path}",
            "--server-name", "local-document-tools"
        ], tmp_dir)
        assert code == 0, f"Expected 0, got {code}. err: {err}"
        assert "Discovered Tools:        3" in out
        assert "read-pdf-document" in out
        assert "convert-document-format" in out
        assert "query-local-database" in out
        assert "Policy Decision:         ALLOW (VERIFIED)" in out
    print("  Verified: 'lcs discover' successfully ingested, attested, and verified 3 tools.")


def test_06_cli_search_command():
    print("--- Test 06: CLI 'search' Command with Grounded FTS5 Results & Filtering ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        fixture_path = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        run_cli_capture(["discover", "--server-command", f"{sys.executable} {fixture_path}"], tmp_dir)

        # Search for PDF
        code, out, err = run_cli_capture(["search", "PDF"], tmp_dir)
        assert code == 0
        assert "Read Pdf Document" in out
        assert "VERIFIED" in out

        # Search with status filter
        code, out, err = run_cli_capture(["search", "PDF", "--status", "VERIFIED"], tmp_dir)
        assert code == 0
        assert "Read Pdf Document" in out

        code, out, err = run_cli_capture(["search", "PDF", "--status", "REJECTED"], tmp_dir)
        assert code == 0
        assert "No matching capabilities found." in out
    print("  Verified: 'lcs search' matches keyword queries with verified policy status filtering.")


def test_07_cli_inspect_command():
    print("--- Test 07: CLI 'inspect' Command with CAS Definition Retrieval ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        fixture_path = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        run_cli_capture(["discover", "--server-command", f"{sys.executable} {fixture_path}"], tmp_dir)

        urn = "urn:lcs:tool:mcp.local-document-tools:read-pdf-document"
        code, out, err = run_cli_capture(["inspect", urn], tmp_dir)
        assert code == 0, f"Expected 0, got {code}. err: {err}"
        assert "LCS CAPABILITY INSPECTION: Read Pdf Document" in out
        assert "Canonical URN:      urn:lcs:tool:mcp.local-document-tools:read-pdf-document" in out
        assert "Lifecycle State:    ACTIVE" in out
        assert "Definition Digest:" in out
        assert "CAS Stored Canonical Definition" in out
        assert '"capability_id": "urn:lcs:tool:mcp.local-document-tools:read-pdf-document"' in out
    print("  Verified: 'lcs inspect' outputs complete verified capability definition from CAS.")


def test_08_cli_explain_command():
    print("--- Test 08: CLI 'explain' Command with Grounded Trust Policy Audit ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        fixture_path = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        run_cli_capture(["discover", "--server-command", f"{sys.executable} {fixture_path}"], tmp_dir)

        urn = "urn:lcs:tool:mcp.local-document-tools:read-pdf-document"
        code, out, err = run_cli_capture(["explain", urn], tmp_dir)
        assert code == 0, f"Expected 0, got {code}. err: {err}"
        assert "LIVING CAPABILITY SYSTEM (LCS) — POLICY DECISION EXPLANATION" in out
        assert "Policy Enforcement:      ALLOW" in out
        assert "Verified Trust Status:   VERIFIED" in out
        assert "HMAC signature verified against persistent key store" in out
        assert "All 3 bound capabilities verified intact on disk" in out
    print("  Verified: 'lcs explain' provides grounded audit trail for ALLOW/VERIFIED decision.")


def test_09_cli_malformed_and_unknown_urn_rejection():
    print("--- Test 09: CLI Malformed & Unknown URN Fail-Closed Rejection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Malformed URN
        code, out, err = run_cli_capture(["inspect", "NOT_A_URN"], tmp_dir)
        assert code == 1
        assert "Invalid capability URN" in err

        # Nonexistent URN
        code, out, err = run_cli_capture(["inspect", "urn:lcs:tool:system.math:nonexistent"], tmp_dir)
        assert code == 1
        assert "Failed to retrieve capability" in err or "not registered" in err

        # Explain unknown interface
        code, out, err = run_cli_capture(["explain", "urn:lcs:interface:system.math:nonexistent"], tmp_dir)
        assert code == 1
        assert "not registered in LCS" in err
    print("  Verified: Malformed and unregistered URNs are rejected fail-closed with code 1.")


def test_10_cli_empty_and_zero_match_query_safety():
    print("--- Test 10: CLI Empty & Zero-Match Query Safety ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Empty query
        code, out, err = run_cli_capture(["search", "   "], tmp_dir)
        assert code == 1
        assert "cannot be empty" in err

        # Zero match query
        code, out, err = run_cli_capture(["search", "nonexistentquerythatmatchesnothing12345"], tmp_dir)
        assert code == 0
        assert "No matching capabilities found." in out
    print("  Verified: Empty search query rejected with code 1; zero-match queries handled safely.")


if __name__ == "__main__":
    tests = [
        test_01_package_imports_and_api,
        test_02_context_lifecycle_and_migration,
        test_03_migration_manager_idempotency_and_integrity,
        test_04_cli_status_command,
        test_05_cli_discover_command,
        test_06_cli_search_command,
        test_07_cli_inspect_command,
        test_08_cli_explain_command,
        test_09_cli_malformed_and_unknown_urn_rejection,
        test_10_cli_empty_and_zero_match_query_safety,
    ]
    print("=" * 76)
    print("LCS CANONICAL INTEGRATION & CLI TEST SUITE")
    print("=" * 76)
    for t in tests:
        t()
    print("=" * 76)
    print(f"ALL {len(tests)} INTEGRATION TESTS PASSED (100% GREEN)")
    print("=" * 76)

