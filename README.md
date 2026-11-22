# Living Capability System (LCS) — Release v3.1.0

The **Living Capability System (LCS)** is an autonomous, cryptographic, zero-trust infrastructure for discovering, understanding, planning, governing, and executing agentic tools, MCP servers, and agent skills.

LCS v3.1.0 introduces the **Call Me Invocation Architecture** (`/call-me`): universal multi-agent capability intelligence and execution orchestration across Google Antigravity, Codex, Claude Code, OpenCode, and Generic POSIX environments without conversational interference, context token inflation, or ungoverned tool execution.

---

## Core Security & Operational Invariants

- **Cryptographic Zero-Trust Governance**: Capabilities and interfaces must be attested with HMAC-SHA256 signatures before plan authorization.
- **Fail-Closed Dual-Gate Control**: Strict verification requires Policy Gate 1 (attestation & version invariants) and Approver Consent Gate 2 (role-based confirmation).
- **Plan Tampering Immunity**: Tokens are bound to the SHA-256 hash of the RFC 8785 JSON Canonicalization (JCS) representation (`PlanIntegrityHash`). Any mid-flight parameter or step alteration fails closed.
- **Single-Use Replay Protection**: Monotonic Compare-and-Consume protocol consumes Execution Authorization Tokens (EAT) and Dispatch Permits atomically under SQLite exclusive transaction locks (`BEGIN IMMEDIATE`).
- **Conversational Dormancy**: Non-`/call-me` developer messages completely bypass LCS Core (0 Core invocations, 0 catalog queries, 0 SQLite mutations, 0 CAS writes, 0 injected context tokens).
- **Exact-Byte Provenance & Sandboxing**: Artifacts are hashed and preserved bit-for-bit in CAS storage (`O_NOFOLLOW`, descriptor-relative path pinning). Process groups (`os.setsid`) manage graceful `SIGTERM` $\to$ `SIGKILL` termination, child reaping, and reverse-order compensation unwinding.

---

## Installation & Clean Initialization

### 1. Installation

LCS is packaged as a standard Python package (`lcs-core`).

**From Local Source (Editable):**
```bash
python3 -m pip install -e .
```

**From Standalone Wheel Package:**
```bash
python3 -m pip install dist/lcs_core-3.1.0-py3-none-any.whl
```

*Requirements:* Python $\ge 3.10$, `pyyaml >= 6.0`.

### 2. Initialization & System Status

Initialize a clean workspace or verify system health:
```bash
lcs status
```
*Note:* Running `lcs status` in a new workspace automatically creates the SQLite relational database (`lcs.db`), applies baseline schemas and migrations, provisions Content-Addressable Storage (CAS) directories, and initializes the persistent cryptographic key store.

To run against a custom directory root:
```bash
lcs --root /path/to/custom_dir status
```

---

## Supported Host Environments & Slash Commands

LCS adapts dynamically to the host environment using dedicated environment adapters:

| Host Environment | Active Adapter | Slash Command Target | Subagent Delegation | Live MCP Stdio |
| :--- | :--- | :--- | :---: | :---: |
| **Google Antigravity** | `AntigravityAdapter` | `.agents/skills/call-me/SKILL.md` | In-Memory (Simulated) | Supported |
| **Codex** | `CodexAdapter` | `.agents/skills/call-me/SKILL.md` | *Unsupported (fails closed)* | Supported |
| **Claude Code** | `ClaudeCodeAdapter` | `.claude/commands/call-me.md` | *Unsupported (fails closed)* | Supported |
| **OpenCode** | `OpenCodeAdapter` | `.opencode/commands/call-me.md` | *Unsupported (fails closed)* | Supported |
| **Generic POSIX** | `GenericPOSIXAdapter` | CLI Subcommand: `lcs call-me` | *Unsupported (fails closed)* | Supported |

### Installing `/call-me` Slash Commands

Install slash command definition files into your workspace or user home:
```bash
# Install into all detected environments in workspace:
lcs install-command --environment all

# Install globally to user home:
lcs install-command --environment all --global

# Safely uninstall command artifacts:
lcs uninstall-command --environment all
```
*Safety Invariant:* `install-command` will refuse to overwrite existing non-LCS files unless `--overwrite` is explicitly provided. `uninstall-command` only deletes verified LCS-managed files and only removes directories if completely empty.

---

## Invocation & Usage

### 1. Host Slash Command Invocation
In supported host conversational interfaces (Antigravity, Claude Code, OpenCode):
```text
/call-me "Inspect release version, run compliance security scan, and deploy to staging"
```

### 2. CLI Invocation
In generic POSIX shells or automation pipelines:
```bash
lcs call-me "Inspect release version, run compliance security scan, and deploy to staging"
```

### 3. Python API Usage
```python
from lcs import LCSConfig, LCSContext, ApproverConsent, ApproverRole, InterfaceTrustPolicy

config = LCSConfig.resolve()
with LCSContext(config=config, auto_migrate=True) as ctx:
    # 1. User explicit /call-me intake
    resp = ctx.call_me.execute_call_me('/call-me "Format data and compute checksum"')
    print(f"Call Me Intake Status: {resp.status}, Matched: {resp.candidate_count}")

    # 2. Planning and Governance
    plan = ctx.planning_engine.create_plan("format data and compute checksum")
    policy = InterfaceTrustPolicy(policy_name="default", min_interface_version=1)
    consent = ApproverConsent(principal="security-officer@local", role=ApproverRole.SECURITY_OFFICER, method="API")
    
    token, eval_res = ctx.governance_engine.approve_plan(plan, consent, active_policy=policy)
    
    # 3. Execution & Audit Ledger
    result = ctx.execution_engine.execute_plan(plan, token)
    print(f"Execution State: {result.lifecycle_state.value}")
```

---

## Known Operational Boundaries & Documented Limitations

1. **Subagent Delegation Boundary:**
   - Host-level subagent coordination is validated for structured task creation, parameter handoff, and output deliverable verification under in-memory executor callbacks (**SIMULATED**).
   - In standalone CPython execution without host-provided IPC callbacks, live interactive Antigravity child agent execution is **NOT VERIFIED**. Non-supporting environments (Claude Code, OpenCode) fail closed honestly.
2. **Governance Duplicate Attestation Invariant:**
   - In frozen core module `governance_policy_v1.py`, `evaluate_plan()` preserves attestation duplicates while `approve_plan()` deduplicates attestation IDs via `set()`.
   - Multi-step plans under strict `require_attestation=True` where multiple steps share an identical attestation ID fail closed at dispatch with `PlanIntegrityTamperedError`.
   - **Mitigation / Safe Compatibility Pattern:** Multi-tool single-server plans must register capabilities under qualified interface URNs (`urn:lcs:interface:mcp.{server}.{tool}:v1`), assigning distinct attestation IDs per capability.
3. **Pending SQLite Version Migration:**
   - `lcs_schema_m5_sqlite_compat.sql` provides backward-compatible static error literals for SQLite `< 3.44`. Production database migration remains deferred pending explicit operator migration authorization.

---

## Cryptographically Sealed Frozen Core

The five foundational baseline modules remain 100% bit-for-bit invariant against their authoritative SHA-256 digests:

| File Name | Authoritative SHA-256 Digest | Status |
| :--- | :--- | :---: |
| `capability_retrieval_v1.py` | `b7d476236d2f5addd6619f619a6f1145bf407a6917d20493e4d85afd0ca843b4` | ✅ VERIFIED |
| `capability_retrieval_v1_1.py` | `2a29c3dcec1e792021a63707fec9a92c3a6505080b0c05a63e377c69ce272e12` | ✅ VERIFIED |
| `capability_parameter_v1.py` | `469b743cf6af1f6807544f2182dee12a4708ceb5512dd32185c4e5986a524c00` | ✅ VERIFIED |
| `capability_planning_v1.py` | `eb81b3255d58958d73689b99cb8506647f8c781d30d93cea1c90dfd435d070e4` | ✅ VERIFIED |
| `governance_policy_v1.py` | `5273f17e83d1c90cd5f935b815841db711a3523a08d1d180f2a4d67bcad44252` | ✅ VERIFIED |
