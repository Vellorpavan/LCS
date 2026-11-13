# Living Capability System (LCS) — Production Release v3.0.0

The **Living Capability System (LCS)** is an autonomous, cryptographic, zero-trust infrastructure for discovering, understanding, planning, governing, and executing agentic tools, MCP servers, and agent skills.

LCS guarantees complete integrity and safety across the entire agent action lifecycle:
- **Zero-Trust Verification**: Tools and interfaces must be attested with HMAC-SHA256 signatures before plan authorization.
- **Fail-Closed Governance**: Strict dual-gated enforcement (Policy Gate 1 & Approver Consent Gate 2).
- **Cryptographic Authorization**: Monotonic, single-use Execution Authorization Tokens (EAT) and Dispatch Permits tied to RFC 8785 Plan Integrity Hashes.
- **Sandboxed Execution**: Process supervisor with process groups (`os.setsid`), graceful `SIGTERM` $\to$ `SIGKILL` timeout management, and strict descriptor-relative path security (`O_NOFOLLOW`).
- **Audit Traceability**: Immutable append-only audit ledgers and exact-byte CAS execution traces for all operations.

---

## Architecture & Integrated Milestones

```
  [ DISCOVERY LAYER ]
  ├── MCP Stdio Servers (JSON-RPC 2.0 tools/list pagination)
  └── Multi-Environment Skill Intelligence (Antigravity, Claude Code, OpenCode)
            │
            ▼
  [ STORAGE & IDENTITY LAYER ]
  ├── Content-Addressed Storage (CAS) Engine (Exact-byte fidelity, O_NOFOLLOW, F_FULLFSYNC)
  ├── SQLite Relational Catalog & URN Registry (urn:lcs:<entity_kind>:<namespace>:<identifier>)
  └── Cryptographic Key Store & Attestation Engine (HMAC-SHA256, atomic key rotation)
            │
            ▼
  [ INTELLIGENCE & PLANNING LAYER ]
  ├── Semantic Profiling & Parameter Extraction (Explicit vs. Inferred Template Variables)
  ├── Dual-Engine Natural Language Retrieval (BM25 + FTS5 + Context Precedence Ranking)
  └── Multi-Capability Planning Engine (Acyclic DAG synthesis, output-to-input parameter binding)
            │
            ▼
  [ GOVERNANCE & POLICY LAYER ]
  ├── Gate 1: Capability Policy & Interface Attestation Verification
  ├── Gate 2: Two-Person-Rule / Role-Based Approver Consent
  ├── RFC 8785 JSON Canonicalization (JCS) & PlanIntegrityHash binding
  └── Monotonic Compare-and-Consume Single-Use Execution Authorization Tokens (EAT)
            │
            ▼
  [ RUNTIME EXECUTION ENGINE ]
  ├── Modality Handlers: MCP Tools, Exact-Byte Skills, Native Capabilities
  ├── Process Supervisor (Process groups, filtered envs, timeout enforcement)
  ├── Reverse-Order Compensation Unwinding on mid-plan failures
  └── Append-Only Audit Ledger & CAS Execution Trace Receipts
```

### Verified Milestone Capabilities:
1. **Milestones 1–4**: CAS engine, canonical registration, interface policy & attestations, MCP discovery, SQLite FTS5 search.
2. **Capability Retrieval V1 & V1.1 (Frozen)**: Natural language semantic retrieval, BM25 scoring, trust status filtering, blind validation.
3. **Capability Parameter Understanding V1 (Frozen)**: Schema validation, parameter readiness analysis, type inference, evidence-grounded parameter mapping.
4. **Multi-Capability Planning V1 (Frozen)**: DAG plan generation, topological sorting, dependency validation, input-output data binding.
5. **Execution Governance V1 (Frozen)**: Dual-gate enforcement, approver consent, single-use EAT tokens, hash-chained audit ledger, RFC 8785 JCS canonicalization.
6. **Skill Intelligence V1**: Taxonomy classification (Skill, Command, Rule, Instruction, Config), safe descriptor reading, Merkle bundle hashing, context precedence boosting.
7. **Execution Engine V1 & E2E Integration**: Sandboxed process supervision, MCP/Skill/Native execution handlers, compensation unwinding, and end-to-end integration suite.

---

## Project Structure

```
/Users/pavan/Desktop/LCS/
├── bin/
│   └── lcs                           # Executable CLI launcher
├── lcs/                              # Canonical Python package
│   ├── __init__.py                   # Package exports (v3.0.0)
│   ├── config.py                     # LCSConfig path resolver & directory setup
│   ├── context.py                    # LCSContext lifecycle & unified service manager
│   ├── storage.py                    # SecureCASStorageEngine & PersistentReceiptKeyStore
│   ├── registry.py                   # CapabilityRegistrationService & CapabilityDefinition
│   ├── policy.py                     # InterfacePolicyService & InterfaceTrustPolicy
│   ├── discovery.py                  # CapabilityDiscoveryPipeline & DiscoveryIndexService
│   ├── profile.py                    # CapabilityProfileService & Semantic Profiling
│   ├── retrieval.py                  # CapabilityRetrievalEngine V1 & V1.1
│   ├── parameter.py                  # ParameterUnderstandingEngine V1
│   ├── planning.py                   # CapabilityPlanningEngine V1
│   ├── governance.py                 # ExecutionGovernanceEngine V1
│   ├── skills.py                     # SkillDiscoveryEngine & SkillIntelligenceService V1
│   ├── execution.py                  # ExecutionEngine V1 runtime layer
│   ├── migrations.py                 # MigrationManager wrapper
│   └── cli.py                        # Comprehensive operator CLI
├── capability_retrieval_v1.py        # [FROZEN] Retrieval V1 Engine
├── capability_retrieval_v1_1.py      # [FROZEN] Retrieval V1.1 Engine
├── capability_parameter_v1.py        # [FROZEN] Parameter Understanding V1 Engine
├── capability_planning_v1.py         # [FROZEN] Multi-Capability Planning V1 Engine
├── governance_policy_v1.py           # [FROZEN] Execution Governance V1 Engine
├── skill_discovery_v1.py             # Skill Discovery Engine & Taxonomy Classifier
├── skill_intelligence_v1.py          # Skill Intelligence V1 & Unified Retrieval Coordinator
├── execution_engine_v1.py            # Execution Engine V1 Runtime Orchestrator
├── evaluation_fixtures/              # Test fixtures & executable MCP stdio servers
├── test_*.py                         # Complete verification suite (278 authoritative tests)
└── lcs_project_final_report.md       # Comprehensive milestone completion report
```

---

## Quick Start & Operator CLI

Make sure the CLI binary is executable:
```bash
chmod +x ./bin/lcs
```

### 1. System Health & Status
```bash
./bin/lcs status
```

### 2. Discover MCP Servers & Capabilities
```bash
# Discover tools from an MCP server over stdio:
./bin/lcs discover --server-command "python3 evaluation_fixtures/executable_test_server.py" --server-name "demo-server"
```

### 3. Discover Skills across Environments
```bash
# Discover skills from Google Antigravity, Claude Code, and OpenCode workspaces:
./bin/lcs skill discover
./bin/lcs skill list
./bin/lcs skill search "data formatter"
```

### 4. Create and Govern Multi-Capability Plans
```bash
# Generate a DAG execution plan from plain English intent:
./bin/lcs plan "format input text then calculate checksum"

# Request Gate 1 evaluation and Gate 2 approver consent:
./bin/lcs approve --plan plan.json --role SECURITY_OFFICER
```

### 5. Execute Governed Plans
```bash
# Execute plan with signed Execution Authorization Token (EAT):
./bin/lcs execute --token eat-abc12345 --plan plan.json

# Inspect completed execution run receipts:
./bin/lcs run list
./bin/lcs run inspect <run_id>
```

---

## Python API Usage

```python
from lcs import LCSConfig, LCSContext, ApproverConsent, ApproverRole

# 1. Initialize LCS Context with automatic migrations and secure permissions
config = LCSConfig.resolve(root_override="./.lcs")
with LCSContext(config=config, auto_migrate=True) as ctx:
    # 2. Discover skills across authorized roots
    records = ctx.skill_service.run_full_pipeline()
    print(f"Discovered {len(records)} skills.")

    # 3. Create Multi-Capability DAG Execution Plan
    plan = ctx.planning_engine.create_plan("format input text")

    # 4. Evaluate Governance Gate 1 (Capability Trust Policy)
    eval_res = ctx.governance_engine.evaluate_plan(plan)
    print(f"Gate 1 Status: {eval_res.gate_1_status}")

    # 5. Grant Gate 2 Approver Consent & Issue EAT Token
    consent = ApproverConsent(principal="security-officer", role=ApproverRole.SECURITY_OFFICER)
    token, approval = ctx.governance_engine.approve_plan(plan, consent)
    print(f"Issued Authorization Token: {token.token_id}")

    # 6. Execute Plan in Sandboxed Runtime
    run_result = ctx.execution_engine.execute_plan(plan, token)
    print(f"Execution State: {run_result.lifecycle_state.value}")
    print(f"Execution Trace CAS Digest: {run_result.trace_cas_digest}")
```

---

## Verification & Test Results

The Living Capability System contains **278 unit, integration, and regression tests** across 23 test suites.

```bash
# Run full authoritative test suite:
python3 -m pytest -q
# 278 passed in 48.18s (100% PASS RATE)
```

### Cryptographically Sealed Frozen Modules:
All five baseline modules remain 100% bit-for-bit identical to their approved cryptographic digests:

| File Name | SHA-256 Digest | Status |
| :--- | :--- | :---: |
| `capability_retrieval_v1.py` | `b7d476236d2f5addd6619f619a6f1145bf407a6917d20493e4d85afd0ca843b4` | ✅ VERIFIED |
| `capability_retrieval_v1_1.py` | `2a29c3dcec1e792021a63707fec9a92c3a6505080b0c05a63e377c69ce272e12` | ✅ VERIFIED |
| `capability_parameter_v1.py` | `469b743cf6af1f6807544f2182dee12a4708ceb5512dd32185c4e5986a524c00` | ✅ VERIFIED |
| `capability_planning_v1.py` | `eb81b3255d58958d73689b99cb8506647f8c781d30d93cea1c90dfd435d070e4` | ✅ VERIFIED |
| `governance_policy_v1.py` | `5273f17e83d1c90cd5f935b815841db711a3523a08d1d180f2a4d67bcad44252` | ✅ VERIFIED |

---

## Security Invariants

1. **Zero Unsigned Execution**: No plan or step can execute without a cryptographically valid, unconsumed EAT token signed by the LCS Key Store.
2. **Replay & Double-Spend Defense**: EAT tokens and Dispatch Permits are atomically consumed under SQLite `BEGIN IMMEDIATE` transactions.
3. **Plan Tampering Immunity**: Tokens are bound to the SHA-256 hash of the RFC 8785 canonicalized plan (`PlanIntegrityHash`). Any mid-flight modification halts execution immediately.
4. **Path Confinement Security**: All file operations enforce `openat` and `O_NOFOLLOW` pinned to authorized discovery roots. Path traversal attempts (`../`) and symlink cycles fail closed.
5. **Exact-Byte Preservation**: Artifact contents are hashed and preserved bit-for-bit in CAS storage without alteration.
