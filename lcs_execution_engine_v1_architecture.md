# Living Capability System (LCS) — Execution Engine V1: Runtime Architecture Specification

**Milestone:** Stage 2B — Execution Engine V1  
**Author:** LCS Architecture & Systems Engineering Team  
**Date:** 2026-11-13  
**Status:** PROPOSED ARCHITECTURE FOR REVIEW & APPROVAL  
**Prerequisites:** Execution Governance V1 (Frozen), Skill Intelligence V1 (Frozen), Multi-Capability Planning V1 (Frozen)  

---

## Executive Summary

The Living Capability System (LCS) has achieved end-to-end milestone stability across discovery, storage, semantic profiling, parameter reasoning, multi-capability planning, execution governance, and multi-environment skill intelligence.

Under **Execution Governance V1**, plans are strictly governed:
- Dual-gated trust and approver authorization are evaluated.
- Plans are canonicalized via RFC 8785 JCS, and integrity is bound to an immutable `PlanIntegrityHash`.
- Cryptographically signed Execution Authorization Tokens (`EAT`) and single-use `DispatchPermit` records are minted.

However, Governance V1 deliberately established a strict boundary: **it does not execute capabilities, invoke MCP tools, spawn processes, or access networks.**

**LCS Execution Engine V1** is the operational runtime execution layer that consumes governance-authorized tokens, supervises live capability dispatch, enforces resource constraints and process sandboxing, handles step-by-step parameter propagation, manages fault recovery/compensation, and records immutable runtime execution receipts in the append-only cryptographic audit ledger.

---

## 1. Goals, Non-Goals, and Safety Invariants

### 1.1 Goals
1. **Cryptographic Token & Permit Consumption**:
   - Validate and atomically consume the `ExecutionAuthorizationToken` (`EAT`) within a single SQLite transaction.
   - Enforce single-use consumption (`eat_tokens.consumed_at IS NULL`), signature validity, expiry bounds, and policy revision generation match.
2. **Strict Plan Integrity Re-Verification**:
   - Re-canonicalize the runtime plan using RFC 8785 JCS and ensure its SHA-256 matches `token.plan_integrity_hash` bit-for-bit before starting step 1.
3. **Dual Execution Modality**:
   - **MCP Tool Invocation**: Manage client connections to MCP servers, dispatch JSON-RPC `tools/call`, capture outputs, and handle error responses.
   - **Skill Instruction Activation**: Provide safe environment contextualization for discovered skills (`SKILL`, `COMMAND`), loading exact bytes from CAS and binding resolved parameters.
4. **Isolated Process Supervision & Sandboxing**:
   - Enforce hard step timeouts and total plan execution timeouts.
   - Graceful termination protocol: `SIGTERM` ➔ wait grace window (default 2s) ➔ `SIGKILL`.
   - Prevent zombie processes and descriptor leaks using POSIX `O_CLOEXEC`.
5. **Runtime Output Validation & Downstream Data Flow**:
   - Validate live tool outputs against declared semantic output schemas.
   - Propagate validated outputs into dependent downstream step input arguments via topological data flow.
6. **Fault Tolerance & Compensation Engine**:
   - Enforce execution classification: `IDEMPOTENT`, `REVERSIBLE`, `IRREVERSIBLE`.
   - Execute registered compensation capabilities in reverse order if a downstream reversible step fails.
7. **CAS-Backed Execution Receipts & Hash-Chained Audit**:
   - Store all raw tool outputs, error dumps, and execution logs into CAS.
   - Append `EXECUTION_STARTED`, `STEP_DISPATCHED`, `STEP_COMPLETED`, `STEP_FAILED`, `COMPENSATION_EXECUTED`, and `PLAN_FINALIZED` events to the append-only audit ledger.

### 1.2 Non-Goals
1. **No Plan Synthesis or Re-Planning**: The Execution Engine executes only plans pre-authorized by Governance V1. It does not synthesize new plans or dynamically rewrite plan step graphs on the fly.
2. **No Policy Relaxation**: If runtime conditions violate policy boundaries, the engine fails closed (`EXECUTION_ABORTED`).
3. **No Unauthenticated Execution**: Capabilities cannot be executed without a valid, unconsumed EAT token and matching dispatch permit.

### 1.3 Safety Invariants & Boundary Protections
- **Invariant 1 (Dual-Gate Verification)**: The engine will reject any execution attempt if `EAT` verification fails Gate 1 (Policy Trust) or Gate 2 (Approver Consent).
- **Invariant 2 (Single-Use Token)**: Tokens cannot be re-executed or replayed. Atomic check-and-consume in SQLite prevents concurrent double-spend.
- **Invariant 3 (Descriptor Pinning & Path Confinement)**: File operations are pinned to authorized roots via `openat`/`O_NOFOLLOW` descriptors. Symlinks escaping root directories trigger immediate execution termination.
- **Invariant 4 (Frozen Core Protection)**: Zero modifications to frozen modules (`capability_retrieval_v1.py`, `capability_retrieval_v1_1.py`, `capability_parameter_v1.py`, `capability_planning_v1.py`, `governance_policy_v1.py`).

---

## 2. Runtime Execution Architecture

```
                                  +---------------------------------------+
                                  |   Governance Engine V1 (Authorized)  |
                                  |    - Signed EAT Token                |
                                  |    - DispatchPermit Inserted          |
                                  +-------------------+-------------------+
                                                      |
                                                      | Dispatch Request (Plan + EAT)
                                                      v
+---------------------------------------------------------------------------------------------------+
|                                 LCS EXECUTION ENGINE V1                                           |
|                                                                                                   |
|  +---------------------------------------------------------------------------------------------+  |
|  | Phase 1: Pre-Flight Token & Plan Validation                                                 |  |
|  |   1. Verify Token Signature with PersistentReceiptKeyStore                                   |  |
|  |   2. Atomic SQLite Consume: BEGIN IMMEDIATE; UPDATE eat_tokens SET consumed_at = NOW...    |  |
|  |   3. Verify Policy Generation Freshness (token.policy_rev == current_policy_rev)           |  |
|  |   4. RFC 8785 Plan Re-Canonicalization: SHA-256(JCS(Plan)) == token.plan_integrity_hash     |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                                      |                                            |
|                                                      v                                            |
|  +---------------------------------------------------------------------------------------------+  |
|  | Phase 2: Topological Step Supervisor                                                        |  |
|  |   1. Iterate steps in topological order [step-1, step-2, ...]                                |  |
|  |   2. Dynamic Argument Binding: Substitute upstream step outputs into downstream parameters  |  |
|  |   3. Resource Confinement: Validate and pin path parameters via O_NOFOLLOW                   |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                                      |                                            |
|                        +-----------------------------+-----------------------------+              |
|                        |                                                           |              |
|                        v                                                           v              |
|       +---------------------------------+                         +-----------------------------+ |
|       | Mode A: MCP Tool Invocation     |                         | Mode B: Skill Execution     | |
|       |  - JSON-RPC 2.0 tools/call      |                         |  - Read exact bytes from CAS| |
|       |  - Stdio Pipe Sandboxing        |                         |  - Inject contextual prompts| |
|       |  - Timeout & SIGTERM/SIGKILL    |                         |  - Bind resolved parameters | |
|       +---------------------------------+                         +-----------------------------+ |
|                        |                                                           |              |
|                        +-----------------------------+-----------------------------+              |
|                                                      |                                            |
|                                                      v                                            |
|  +---------------------------------------------------------------------------------------------+  |
|  | Phase 3: Output Contract Validation & Error Recovery                                        |  |
|  |   1. Validate returned output against capability schema & type constraints                   |  |
|  |   2. If Success: Store outputs in CAS, bind to dependent steps, append audit event           |  |
|  |   3. If Failure:                                                                             |  |
|  |      - IDEMPOTENT: Retry with exponential backoff up to max_retries                          |  |
|  |      - REVERSIBLE: Halt downstream, invoke compensation handlers in reverse order             |  |
|  |      - IRREVERSIBLE: Immediately halt, fail plan, log security audit event                  |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                                      |                                            |
|                                                      v                                            |
|  +---------------------------------------------------------------------------------------------+  |
|  | Phase 4: Finalization & Audit Receipts                                                      |  |
|  |   1. Store full execution trace & stdout/stderr in CAS                                      |  |
|  |   2. Commit final EXECUTION_COMPLETED / EXECUTION_FAILED to Append-Only Audit Ledger         |  |
|  |   3. Update DispatchPermit status to 'EXECUTED' or 'FAILED'                                 |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Detailed Subsystem Specifications

### 3.1 Token Consumption Protocol (Atomic Verification)
The Execution Engine interacts with the shared SQLite database using serialized isolation:
```python
def consume_authorization_token(conn: sqlite3.Connection, token: ExecutionAuthorizationToken, plan: ExecutionPlan) -> DispatchPermit:
    cur = conn.cursor()
    cur.execute("BEGIN IMMEDIATE")
    try:
        # 1. Fetch token record
        cur.execute("SELECT consumed_at, plan_integrity_hash, policy_revision_id, expires_at FROM eat_tokens WHERE token_id = ?", (token.token_id,))
        row = cur.fetchone()
        if not row:
            raise TokenConsumptionError("Token does not exist in registry.")
        if row[0] is not None:
            raise TokenReplayError(f"Token '{token.token_id}' was already consumed at {row[0]}.")
        
        # 2. Check expiration
        now = time.time()
        if now > row[3]:
            raise TokenExpiredError(f"Token expired at {row[3]}, current time is {now}.")
            
        # 3. Verify plan integrity hash
        canonical_plan_bytes = canonicalize_jcs(plan.to_dict())
        plan_hash = hashlib.sha256(canonical_plan_bytes).hexdigest()
        if plan_hash != row[1]:
            raise PlanTamperingError(f"Plan integrity hash mismatch: expected {row[1]}, got {plan_hash}.")
            
        # 4. Verify policy revision freshness
        cur.execute("SELECT MAX(revision_id) FROM policy_revisions")
        latest_rev = cur.fetchone()[0]
        if latest_rev != row[2]:
            raise PolicyStaleError(f"Policy revision changed: token authorized under {row[2]}, active is {latest_rev}.")
            
        # 5. Mark consumed and fetch dispatch permit
        cur.execute("UPDATE eat_tokens SET consumed_at = ? WHERE token_id = ?", (now, token.token_id))
        cur.execute("UPDATE dispatch_permits SET status = 'DISPATCHING' WHERE token_id = ?", (token.token_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
```

### 3.2 Process Isolation & Timeout Supervisor
For MCP tool invocations and local process execution:
1. **Subprocess Sandboxing**:
   - Processes are spawned with isolated process groups (`preexec_fn=os.setsid` on POSIX).
   - Stdio descriptors (`stdin`, `stdout`, `stderr`) are piped with non-blocking polling (`select`/`selectors`).
   - Environment variables are strictly filtered: only whitelisted system variables and capability-declared environment variables are passed.
2. **Timeout Enforcement**:
   - Step timeout ceiling ($T_{\text{step}}$, default: 30s).
   - Total plan timeout ceiling ($T_{\text{plan}}$, default: 120s).
   - If $T_{\text{step}}$ expires:
     1. Send `SIGTERM` to the process group (`os.killpg(p.pid, signal.SIGTERM)`).
     2. Wait grace window (2.0s).
     3. If process has not terminated, send `SIGKILL` (`os.killpg(p.pid, signal.SIGKILL)`).
     4. Log `STEP_TIMEOUT_TERMINATED` in audit ledger.

### 3.3 Dynamic Parameter Propagation & Argument Binding
Plans specify data dependencies where output attributes of Step $A$ serve as inputs to Step $B$:
```json
{
  "step_id": "step-2",
  "capability_urn": "urn:lcs:tool:format-report",
  "input_bindings": {
    "data": {
      "source_step": "step-1",
      "output_field": "result"
    }
  }
}
```
1. Before Step $k$ executes, the engine inspects its input bindings.
2. If an input is bound to `source_step`, the engine retrieves the verified output value stored in the execution context of `source_step`.
3. If an input is unresolved or missing and marked `required=True`, the engine halts with `UNRESOLVED_PARAMETER_ERROR`.
4. If the parameter is a filesystem path, path confinement is validated via `O_NOFOLLOW` descriptor checks before passing to the tool.

### 3.4 Compensation & Rollback Mechanics
1. **Step Failure Classification**:
   - `IDEMPOTENT`: The step can be safely retried up to `max_retries` (default: 2) with exponential backoff.
   - `REVERSIBLE`: The step declares a compensation capability (e.g., `create_file` has compensation `delete_file`).
   - `IRREVERSIBLE`: State mutations cannot be automatically undone.
2. **Compensation Unwinding**:
   - If Step $K$ fails and cannot be recovered, the engine enters `COMPENSATION_UNWINDING`.
   - The engine iterates through completed steps in reverse order ($K-1, K-2, \dots, 1$).
   - For each completed step that has an associated compensation capability, the engine dispatches the compensation tool using the stored execution parameters.
   - Each compensation action is recorded in the audit ledger with `COMPENSATION_EXECUTED`.

---

## 4. Lifecycle & State Machine

```
                   [ SUBMITTED ]
                         |
                         v (Verify EAT + Plan Hash + Policy Rev)
                 [ PREFLIGHT_VALID ]
                         |
                         v (Atomic SQLite BEGIN IMMEDIATE)
                  [ TOKEN_CONSUMED ]
                         |
                         v (Initialize Runtime Context)
                   [ EXECUTING ] <--------------------+
                         |                            | (Next Step)
           +-------------+-------------+              |
           |                           |              |
           v (Success)                 v (Failure)    |
   [ STEP_COMPLETED ]           [ STEP_FAILED ]       |
           |                           |              |
           | (More steps)        +-----+-----+        |
           +-------------------->|           |        |
           |                     v           v        |
           |               (Idempotent)  (Reversible/Irreversible)
           |                [ RETRY ]    [ COMPENSATION_UNWIND ]
           |                     |           |
           v (All done)          +-----------+
   [ EXECUTION_SUCCEEDED ]                   v
                                    [ EXECUTION_FAILED ]
```

---

## 5. Storage & Audit Ledger Schemas

### 5.1 Runtime Tables (Migration `004_execution_engine.sql`)
```sql
CREATE TABLE IF NOT EXISTS execution_runs (
    run_id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_integrity_hash TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN (
        'SUBMITTED', 'TOKEN_CONSUMED', 'EXECUTING', 
        'COMPENSATION_UNWIND', 'SUCCEEDED', 'FAILED', 'ABORTED'
    )),
    start_time REAL NOT NULL,
    end_time REAL,
    total_steps INTEGER NOT NULL,
    completed_steps INTEGER DEFAULT 0,
    trace_cas_digest TEXT,
    error_message TEXT,
    FOREIGN KEY(token_id) REFERENCES eat_tokens(token_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS execution_step_records (
    step_record_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    capability_urn TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'COMPENSATED', 'SKIPPED')),
    start_time REAL NOT NULL,
    end_time REAL,
    duration_ms REAL,
    input_arguments_cas_digest TEXT NOT NULL,
    output_result_cas_digest TEXT,
    error_details TEXT,
    retry_count INTEGER DEFAULT 0,
    FOREIGN KEY(run_id) REFERENCES execution_runs(run_id) ON DELETE CASCADE
);
```

### 5.2 Append-Only Audit Ledger Integration
The Execution Engine appends structured event records to the established `AuditLedgerService`:
- `EXECUTION_RUN_STARTED`: Records `run_id`, `token_id`, `plan_integrity_hash`.
- `EXECUTION_STEP_DISPATCH`: Records `step_id`, `capability_urn`, `input_cas_digest`.
- `EXECUTION_STEP_COMPLETED`: Records `step_id`, `duration_ms`, `output_cas_digest`.
- `EXECUTION_STEP_FAILED`: Records `step_id`, `error_code`, `retry_count`.
- `COMPENSATION_ACTION_DISPATCHED`: Records `original_step_id`, `compensation_urn`.
- `EXECUTION_RUN_FINALIZED`: Records `run_id`, `final_status`, `total_duration_ms`.

---

## 6. Implementation Stages & Verification Plan

### Stage 1 — Core Execution Infrastructure & Token Consumption
- Token verification & single-use atomic consumption.
- Schema migration `004_execution_engine.sql`.
- Pre-flight plan re-canonicalization and integrity verification.

### Stage 2 — Process Supervisor & Sandbox
- Subprocess manager with `O_CLOEXEC`, process groups, and pipes.
- Step and plan timeout handling (`SIGTERM` ➔ `SIGKILL`).
- Path descriptor pinning and security validation.

### Stage 3 — Modality Handlers (MCP & Skills)
- MCP JSON-RPC 2.0 `tools/call` client protocol.
- Skill instruction executor (exact bytes from CAS + contextual prompt assembly).

### Stage 4 — Topological Runner & Parameter Propagation
- Step output capturing and semantic contract verification.
- Upstream to downstream input parameter binding.

### Stage 5 — Compensation Engine & Audit Ledger Logging
- Idempotent retry logic with exponential backoff.
- Reverse-order compensation unwinding.
- Full CAS execution trace generation & hash-chained audit ledger events.

### Stage 6 — CLI Surface & Verification
- `lcs execute --token <token_id> --plan <plan.json>`
- `lcs run inspect <run_id>`
- Comprehensive end-to-end integration tests & frozen module verification.

