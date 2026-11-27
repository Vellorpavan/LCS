"""
Call Me — Verification Persistence and Audit Infrastructure
===========================================================
Durable SQLite and CAS storage for Call Me plans and verification receipts:
- Tracks planned runs to prevent fabricated run IDs.
- Records verification receipts in SQLite (call_me_verification_records).
- Persists exact receipt payloads into Content-Addressable Storage (CAS).
- Appends tamper-evident events into GovernanceAuditLedger.
- Retrieves verification receipts by run ID across process restarts.

Invariants:
- Zero modifications to frozen core SQL schemas (uses idempotent tables).
- Fails closed on fabricated, missing, or unauthorized run IDs.
- Cryptographically binds artifact SHA-256 digests to the originating run.
"""

import os
import sys
import json
import uuid
import hashlib
import datetime
import sqlite3
from typing import Dict, Any, List, Optional, Tuple


class VerificationAuditStore:
    """Manages persistent audit storage for Call Me plans and verification receipts."""

    @classmethod
    def ensure_schema(cls, conn: sqlite3.Connection) -> None:
        """Idempotently ensures Call Me audit tables exist."""
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS call_me_planned_runs (
                    run_id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    workspace_root TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS call_me_verification_records (
                    verification_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    is_verified INTEGER NOT NULL,
                    verification_state TEXT NOT NULL,
                    workspace_root TEXT NOT NULL,
                    expected_files_json TEXT NOT NULL,
                    file_digests_json TEXT NOT NULL,
                    verification_commands_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    cas_receipt_digest TEXT,
                    verified_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_call_me_verification_run_id 
                ON call_me_verification_records (run_id);
            """)

    @classmethod
    def record_planned_run(
        cls,
        conn: sqlite3.Connection,
        run_id: str,
        objective: str,
        workspace_root: str,
        plan_dict: Dict[str, Any]
    ) -> None:
        """Records an authentic planned run to prevent fabricated run IDs."""
        cls.ensure_schema(conn)
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO call_me_planned_runs (run_id, objective, workspace_root, plan_json, created_at)
                VALUES (?, ?, ?, ?, ?);
            """, (
                run_id,
                objective,
                os.path.abspath(workspace_root),
                json.dumps(plan_dict, sort_keys=True),
                datetime.datetime.now(datetime.timezone.utc).isoformat()
            ))

    @classmethod
    def is_run_registered(cls, conn: sqlite3.Connection, run_id: str) -> bool:
        """
        Checks whether run_id was legitimately planned or executed.
        Prevents fabricated or unrelated run IDs from recording verification.
        """
        cls.ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM call_me_planned_runs WHERE run_id = ? LIMIT 1;", (run_id,))
        if cur.fetchone():
            return True
        # Also check execution_runs if table exists
        try:
            cur.execute("SELECT 1 FROM execution_runs WHERE run_id = ? LIMIT 1;", (run_id,))
            if cur.fetchone():
                return True
        except sqlite3.OperationalError:
            pass

        # Fallback check against user-level global LCS DB if running against local project DB
        try:
            from ..config import LCSConfig
            user_db = os.path.join(LCSConfig.get_user_state_dir(), "lcs.db")
            if os.path.exists(user_db):
                with sqlite3.connect(user_db) as u_conn:
                    cls.ensure_schema(u_conn)
                    u_cur = u_conn.cursor()
                    u_cur.execute("SELECT 1 FROM call_me_planned_runs WHERE run_id = ? LIMIT 1;", (run_id,))
                    if u_cur.fetchone():
                        return True
        except Exception:
            pass

        return False

    @classmethod
    def get_planned_run(cls, conn: sqlite3.Connection, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an authentic planned run record by run_id."""
        cls.ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT run_id, objective, workspace_root, plan_json, created_at FROM call_me_planned_runs WHERE run_id = ? LIMIT 1;", (run_id,))
        row = cur.fetchone()
        if row:
            try:
                plan_dict = json.loads(row[3])
            except Exception:
                plan_dict = {}
            return {
                "run_id": row[0],
                "objective": row[1],
                "workspace_root": row[2],
                "plan": plan_dict,
                "created_at": row[4]
            }

        # Fallback check against user-level global LCS DB
        try:
            from ..config import LCSConfig
            user_db = os.path.join(LCSConfig.get_user_state_dir(), "lcs.db")
            if os.path.exists(user_db):
                with sqlite3.connect(user_db) as u_conn:
                    cls.ensure_schema(u_conn)
                    u_cur = u_conn.cursor()
                    u_cur.execute("SELECT run_id, objective, workspace_root, plan_json, created_at FROM call_me_planned_runs WHERE run_id = ? LIMIT 1;", (run_id,))
                    u_row = u_cur.fetchone()
                    if u_row:
                        try:
                            u_plan_dict = json.loads(u_row[3])
                        except Exception:
                            u_plan_dict = {}
                        return {
                            "run_id": u_row[0],
                            "objective": u_row[1],
                            "workspace_root": u_row[2],
                            "plan": u_plan_dict,
                            "created_at": u_row[4]
                        }
        except Exception:
            pass

        return None

    @classmethod
    def persist_verification_receipt(
        cls,
        conn: sqlite3.Connection,
        cas_engine: Optional[Any],
        audit_ledger: Optional[Any],
        run_id: str,
        is_verified: bool,
        verification_state: str,
        workspace_root: str,
        expected_files: List[Any],
        file_digests: Dict[str, str],
        verification_commands: List[Any],
        evidence: List[Dict[str, Any]],
        objective_fulfilled: Optional[bool] = None,
        fulfillment_status: Optional[str] = None,
        substitute_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Durably persists verification results into SQLite, CAS, and Audit Ledger.
        """
        cls.ensure_schema(conn)
        verification_id = f"ver-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        resolved_fulfilled = bool(is_verified) if objective_fulfilled is None else bool(objective_fulfilled)
        resolved_status = fulfillment_status or ("FULFILLED" if resolved_fulfilled else "UNFULFILLED")

        persisted_evidence = list(evidence or [])
        if not any(isinstance(ev, dict) and ev.get("criterion") == "Objective fulfillment status" for ev in persisted_evidence):
            detail_parts = [f"status={resolved_status}", f"objective_fulfilled={resolved_fulfilled}"]
            if substitute_reason:
                detail_parts.append(f"reason={substitute_reason}")
            persisted_evidence.append({
                "tier": 4,
                "criterion": "Objective fulfillment status",
                "passed": resolved_fulfilled,
                "details": "; ".join(detail_parts),
            })

        receipt_payload = {
            "verification_id": verification_id,
            "run_id": run_id,
            "is_verified": is_verified,
            "verification_state": verification_state,
            "objective_fulfilled": resolved_fulfilled,
            "fulfillment_status": resolved_status,
            "substitute_reason": substitute_reason,
            "workspace_root": os.path.abspath(workspace_root),
            "expected_files": expected_files,
            "file_digests": file_digests,
            "verification_commands": verification_commands,
            "evidence": persisted_evidence,
            "verified_at": now_iso
        }

        # 1. Store in CAS
        cas_digest = None
        if cas_engine:
            try:
                raw_bytes = json.dumps(receipt_payload, sort_keys=True).encode("utf-8")
                calc_digest = hashlib.sha256(raw_bytes).hexdigest()
                if not cas_engine.blob_exists(calc_digest):
                    pub_id = f"pub_{calc_digest[:8]}"
                    tmp_name, _, _ = cas_engine.write_payload_to_staging(pub_id, "tok_lcs", calc_digest, raw_bytes)
                    cas_engine.publish_staging_to_cas(tmp_name, calc_digest)
                cas_digest = calc_digest
                receipt_payload["cas_receipt_digest"] = cas_digest
            except Exception:
                pass

        # 2. Store in SQLite
        with conn:
            conn.execute("""
                INSERT INTO call_me_verification_records (
                    verification_id, run_id, is_verified, verification_state,
                    workspace_root, expected_files_json, file_digests_json,
                    verification_commands_json, evidence_json, cas_receipt_digest, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                verification_id,
                run_id,
                1 if is_verified else 0,
                verification_state,
                os.path.abspath(workspace_root),
                json.dumps(expected_files, sort_keys=True),
                json.dumps(file_digests, sort_keys=True),
                json.dumps(verification_commands, sort_keys=True),
                json.dumps(persisted_evidence, sort_keys=True),
                cas_digest,
                now_iso
            ))

        # 3. Append to Governance Audit Ledger
        if audit_ledger and hasattr(audit_ledger, "append_event"):
            try:
                audit_ledger.append_event(
                    event_type="CALL_ME_DELIVERABLE_VERIFIED" if is_verified else "CALL_ME_DELIVERABLE_FAILED",
                    plan_id=run_id,
                    plan_integrity_hash=cas_digest or hashlib.sha256(run_id.encode("utf-8")).hexdigest(),
                    token_id="CALL_ME_VERIFIER",
                    event_payload={
                        "run_id": run_id,
                        "verification_id": verification_id,
                        "is_verified": is_verified,
                        "verification_state": verification_state,
                        "file_digests": file_digests,
                        "cas_receipt_digest": cas_digest
                    }
                )
            except Exception:
                pass

        return receipt_payload

    @classmethod
    def get_verification_receipt(
        cls,
        conn: sqlite3.Connection,
        run_id: str,
        cas_engine: Optional[Any] = None,
        workspace_root: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves the latest verification receipt for run_id from SQLite (primary conn,
        workspace .lcs/lcs.db, or user global .lcs/lcs.db).
        """
        cls.ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("""
            SELECT verification_id, run_id, is_verified, verification_state,
                   workspace_root, expected_files_json, file_digests_json,
                   verification_commands_json, evidence_json, cas_receipt_digest, verified_at
            FROM call_me_verification_records
            WHERE run_id = ?
            ORDER BY verified_at DESC, rowid DESC
            LIMIT 1;
        """, (run_id,))
        row = cur.fetchone()
        if not row:
            candidate_dbs: List[str] = []
            if workspace_root:
                candidate_dbs.append(os.path.join(os.path.abspath(workspace_root), ".lcs", "lcs.db"))
            try:
                from ..config import LCSConfig
                candidate_dbs.append(os.path.join(LCSConfig.get_user_state_dir(), "lcs.db"))
            except Exception:
                pass
            for db_path in candidate_dbs:
                if not os.path.exists(db_path):
                    continue
                try:
                    with sqlite3.connect(db_path) as u_conn:
                        cls.ensure_schema(u_conn)
                        u_cur = u_conn.cursor()
                        u_cur.execute("""
                            SELECT verification_id, run_id, is_verified, verification_state,
                                   workspace_root, expected_files_json, file_digests_json,
                                   verification_commands_json, evidence_json, cas_receipt_digest, verified_at
                            FROM call_me_verification_records
                            WHERE run_id = ?
                            ORDER BY verified_at DESC, rowid DESC
                            LIMIT 1;
                        """, (run_id,))
                        row = u_cur.fetchone()
                        if row:
                            break
                except Exception:
                    continue

        if not row:
            return None

        (v_id, r_id, is_ver, v_state, ws_root, exp_f_json, f_dig_json, v_cmds_json, ev_json, cas_dig, v_at) = row
        ev_list = json.loads(ev_json)
        obj_fulfilled = bool(is_ver)
        fulfill_status = "FULFILLED" if obj_fulfilled else "UNFULFILLED"
        sub_reason = None
        for ev in ev_list:
            if isinstance(ev, dict) and ev.get("criterion") == "Objective fulfillment status":
                obj_fulfilled = bool(ev.get("passed"))
                details = str(ev.get("details") or "")
                for part in details.split("; "):
                    if part.startswith("status="):
                        fulfill_status = part[len("status="):].strip()
                    elif part.startswith("reason="):
                        sub_reason = part[len("reason="):].strip()
                break

        return {
            "verification_id": v_id,
            "run_id": r_id,
            "is_verified": bool(is_ver),
            "verification_state": v_state,
            "objective_fulfilled": obj_fulfilled,
            "fulfillment_status": fulfill_status,
            "substitute_reason": sub_reason,
            "workspace_root": ws_root,
            "expected_files": json.loads(exp_f_json),
            "file_digests": json.loads(f_dig_json),
            "verification_commands": json.loads(v_cmds_json),
            "evidence": ev_list,
            "cas_receipt_digest": cas_dig,
            "verified_at": v_at
        }
