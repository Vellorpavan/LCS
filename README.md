# Call Me — Universal Multi-Agent Capability Orchestrator

[![CI Matrix](https://img.shields.io/badge/CI-12%2F12%20Passing-brightgreen.svg)](#cross-platform-ci-matrix)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](#system-requirements)
[![Supported OS](https://img.shields.io/badge/OS-macOS%20%7C%20Ubuntu%20Linux%20%7C%20Windows-blueviolet.svg)](#cross-platform-architecture)
[![Governance](https://img.shields.io/badge/Governance-Zero--Trust%20Dual--Gate-orange.svg)](#zero-trust-governance--security-invariants)

**Call Me** is the universal multi-agent capability orchestrator powered by the **Living Capability System (LCS)** cryptographic zero-trust substrate. It enables developers and AI agents to discover, retrieve, plan, govern, and execute capabilities across supported AI hosts (Google Antigravity, Claude Code, OpenCode, Codex) and the command line.

Install once. Then invoke in your AI coding host:
```text
/call-me <any natural-language objective>
```

Or from your terminal:
```bash
call-me "<objective>"
call-me plan "<objective>"
call-me verify <run-id> --workspace <dir> --files <files...>
call-me setup
```

Full backward compatibility is preserved for canonical `lcs` commands (`lcs call-me`, `lcs call-me-plan`, `lcs call-me-verify`, `lcs setup`).

---

## Architecture Overview

```text
  Developer / Coding Agent Interface
       │  (Invokes exact command: /call-me <task>)
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    LCS UNIVERSAL HOST ADAPTER LAYER                     │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐│
│  │  Antigravity  │ │   OpenCode    │ │  Claude Code  │ │ Custom Agents ││
│  │   (Skills)    │ │  (Commands)   │ │  (Commands)   │ │ (Declarative) ││
│  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └───────┬───────┘│
└──────────┼─────────────────┼─────────────────┼─────────────────┼────────┘
           ▼                 ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    CAPABILITY INTELLIGENCE & PLANNING                   │
│  • Fast FTS5 Lexical & Semantic Profile Matcher                        │
│  • Parameter Understanding & Schema Compatibility Engine                │
│  • Directed Acyclic Graph (DAG) Multi-Capability Planner               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   DUAL-GATE GOVERNANCE ENGINE (V1)                      │
│  Gate 1: Interface Trust Policy (Attestation & Boundary Confinement)    │
│  Gate 2: Human Operator Approval (Cryptographic Consent Verification)   │
│  Token:  Single-Use RFC 8785 PlanIntegrityHash Signed Token (EAT)       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                 CONCURRENT EXECUTION & AUDIT SUBSTRATE                  │
│  • Topological Wave Concurrent Execution Engine                        │
│  • Fail-Closed Reverse-Order Step Compensation & Cleanup                │
│  • Exact-Byte Content-Addressable Storage (CAS) Sandboxing              │
│  • Immutable Append-Only Cryptographic Audit Ledger (HMAC-SHA256)      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features (`v3.2.0rc3` Published + `v3.2.0rc4` Candidate)

1. **Universal Local-First Setup (`lcs setup`)**:
   - Install once globally (`~/.lcs`) with automatic project-local state fallback (`./.lcs`).
   - Idempotent configuration management, health diagnostics (`lcs setup --check`), and self-healing repair (`lcs setup --repair`).
2. **Official Vercel Find Skills Integration (`v3.2.0rc4` Candidate)**:
   - Detects uncovered requirement clauses during planning (`call-me-plan` / `plan_call_me`) and queries `vercel-labs/skills` (`skills@1.4.4`) on demand.
   - Applies pre-ranking semantic eligibility filtering (`assess_semantic_eligibility`) across both local and external candidates.
   - Enforces `CALL_ME_ACQUISITION_POLICY=ASK` by default (`APPROVAL_REQUIRED` with `0` unapproved installs); supports `TRUSTED_AUTO` (`DEFAULT_TRUSTED_OWNERS`: `vercel-labs`, `anthropics`, `github`, `microsoft`, `openai` — note: trusted ownership is an allowlist for auto-approval, not a guarantee of safety) and `OFFLINE`.
   - Refreshes the local capability inventory and replans into the active DAG within the same invocation once authorized.
3. **Pluggable Host Adapter Contract & Cross-Agent Context Hydration**:
   - Declarative JSON/YAML adapter specifications with path-traversal and shell-injection guards, plus seamless context transfer across hosts.
4. **Universal Model Context Protocol (MCP) Interface (`lcs serve-mcp`)**:
   - Standard stdio JSON-RPC 2.0 server exposing `lcs_call_me`, with fail-closed governance token enforcement.
5. **Native Cross-Platform Concurrency Parity**:
   - Cross-process file locking on POSIX (`fcntl.flock`) and Windows (`kernel32.LockFileEx`).
6. **Local & Acquired Multi-Skill Composition + Bidirectional Sync**:
   - Topological wave scheduling (`Phase 0` components -> `Phase 1` assembly -> `Phase 2` verification) across local and acquired skills, with `ProjectContractManager` interface mutation invalidation (`NEEDS_UPDATE`) and evidence-backed adaptation (`mark_component_adapted`).
7. **Objective Fulfillment Verification & Persistent Receipt Inspection (`v3.2.0rc4` Candidate)**:
   - Distinguishes raw artifact/test exit codes from genuine objective fulfillment (`FULFILLED`, `PARTIAL_SUBSTITUTE`, `UNFULFILLED`), blocking weaker fallback substitutes and skipped mandatory tests.
   - Persists cryptographic SHA-256 receipts in SQLite and CAS, inspectable from a separate process via `lcs --root <dir> call-me-verify <run-id> --workspace <dir> --inspect --format-json`.

---

## Zero-Trust Governance & Security Invariants

LCS enforces strict mathematical and architectural constraints to guarantee zero-trust execution:

- **Dual-Gate Fail-Closed Control**: Every execution plan must pass Gate 1 (interface policy attestation) and Gate 2 (human approver consent). Plans cannot self-authorize.
- **Plan Integrity Binding**: Authorization tokens are cryptographically bound to the RFC 8785 JSON Canonicalization (JCS) hash of the execution plan (`PlanIntegrityHash`). Any modification to steps or parameters invalidates the token.
- **Single-Use Replay Immunity**: Monotonic compare-and-consume protocol consumes tokens atomically under database exclusive locks (`BEGIN IMMEDIATE`). Token reuse raises `TokenAlreadyConsumedError`.
- **Conversational Dormancy**: Regular conversational messages bypass LCS completely. LCS activates strictly upon explicit `/call-me` invocation.
- **Content-Addressable Storage (CAS)**: Deliverables and execution artifacts are stored under their exact SHA-256 digests with descriptor-pinned, traversal-resistant filesystem operations.
- **Tamper-Evident Audit Ledger**: Every governance evaluation, approval, execution step, and compensation event is written to an append-only, SHA-256 hash-chained ledger.

---

## System Requirements & Supported Platforms

### System Requirements
- **Python**: `3.10–3.13` (established cross-platform CI matrix; `pyproject.toml` specifies `requires-python = ">=3.10"` with classifiers `3.10`–`3.14`)
- **Core Dependencies**: `pyyaml >= 6.0` (core); `pytest`, `mcp`, `build` (development/MCP tools)
- **External Find Skills Acquisition (Optional)**: **Node.js `>= 22.20`** (`node` and `npx` on `PATH`), **Git**, and outbound HTTPS access to `skills.sh` / GitHub. Local-only workflows do **not** require Node.js or network access.
- **Disk**: Minimal footprint (< 50MB for core and runtime database)

### Cross-Platform Architecture
| Platform | Process Concurrency & Locking | Filesystem Sandboxing | Status |
| :--- | :--- | :--- | :---: |
| **macOS (Darwin)** | Kernel `flock` / `F_FULLFSYNC` | Descriptor-relative (`openat`, `O_NOFOLLOW`) | ✅ Full Parity |
| **Ubuntu Linux** | Kernel POSIX `flock` / `fsync` | Descriptor-relative (`openat`, `O_NOFOLLOW`) | ✅ Full Parity |
| **Native Windows** | Win32 `kernel32.LockFileEx` | Realpath boundary confinement & Win32 handles | ✅ Full Parity |

---

## Coding Agent Integration Matrix

LCS standardizes on the **exact invocation command**: `/call-me <task>`.

To prevent ambiguity between simulated adapters and real-world execution, LCS maintains a truthful categorization of supported host agents:

| Host Agent | Target Command Artifact | Invocation Syntax | Verification Classification | Capabilities & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** | `~/.gemini/config/skills/call-me/SKILL.md` | `/call-me` | **LIVE_VERIFIED** | Active runtime; multi-capability intake, DAG planning, subagent dispatch, and contract sync verified. |
| **OpenCode** | `~/.opencode/commands/call-me.md` | `/call-me` | **PROTOCOL_VERIFIED** | Standalone binary (`opencode v2.3.2`) verified; remote execution requires valid provider key. |
| **Claude Code** | `~/.claude/commands/call-me.md` | `/call-me` | **PROTOCOL_VERIFIED** | Markdown command contract verified; CLI binary uninstalled locally. |
| **OpenAI Codex** | `.agents/skills/call-me/SKILL.md` (or `~/.agents/skills/call-me/SKILL.md`) | `$call-me` / skill discovery | **PROTOCOL_VERIFIED** | Installed via `lcs setup --environment codex` or `lcs install-command --environment codex`; ambient skill discovery verified. |
| **Custom Agents** | `.nexus/commands/call-me.md` (or custom) | `/call-me` | **CONTRACT_LIVE_VERIFIED** | Declarative spec schema validated, dynamic loader instantiated, security checks active. |

---

## Installation & Setup

> [!NOTE]
> Call Me is **not** published on PyPI or npm. Install from GitHub Releases (`v3.2.0rc3` is the latest published experimental release) or a source checkout.

### 1. Installation (macOS, Linux & Windows)

**macOS & Linux (`install.sh`):**
```bash
git clone --branch v3.2.0rc3 --depth 1 https://github.com/Vellorpavan/LCS.git
cd LCS
chmod +x install.sh && ./install.sh
export PATH="$HOME/.local/bin:$PATH"
call-me --version && lcs --version
```

**Windows (`install.ps1` in PowerShell):**
```powershell
git clone --branch v3.2.0rc3 --depth 1 https://github.com/Vellorpavan/LCS.git
Set-Location LCS
powershell -ExecutionPolicy Bypass -File .\install.ps1
$env:Path = "$HOME\.local\bin;" + $env:Path
call-me --version; lcs --version
```

**From Release Wheel or Editable Source:**
```bash
pip install lcs_core-<version>-py3-none-any.whl
# or from source checkout:
pip install -e ".[dev]"
```

### 2. Local-First Setup

Run the idempotent setup command to configure LCS and register command artifacts for all detected agents:

```bash
# Setup user-global environment (~/.lcs)
lcs setup --global

# Setup project-local environment (./.lcs)
lcs setup --project
```

### 3. Diagnostics & Health Verification

Inspect system health, database migrations, and agent command integrations:
```bash
# Run non-destructive diagnostic check
lcs setup --check

# Run automatic self-healing repair
lcs setup --repair

# View active status summary
lcs status
```

---

## Usage Examples

### 1. Natural Language Capability Intake via `/call-me`
In supported agent interfaces (Antigravity, OpenCode, Claude Code):
```text
/call-me "Ingest telemetry logs, compute anomaly distribution, and export report"
```

### 2. Standalone CLI Execution
Execute an explicit handoff from the terminal:
```bash
# Hand off matched skill instructions to coding host
lcs call-me --handoff -- "Ingest telemetry logs and export report"

# Direct multi-capability DAG execution in clean terminal environment
lcs call-me --execute "Scaffold SQLite telemetry service, build health check service, and run verification tests" --format-json

# Slash command syntax supported directly from CLI
lcs call-me "/call-me Scaffold SQLite telemetry service and run verification tests" --execute

# Plan with default ASK policy and resume after approving external skill specs
lcs --root . call-me-plan "Build a Python telemetry CLI service, and create a clear GitHub README.md" --workspace . --format-json
CALL_ME_ACQUISITION_APPROVED_SPECS="owner/repo@skill" lcs --root . call-me-plan "Build a Python telemetry CLI service, and create a clear GitHub README.md" --workspace . --format-json

# Verify deliverables and inspect persisted receipt from a separate process
lcs --root . call-me-verify <run-id> --workspace . --files README.md app.py --commands "python3 -m unittest -v" --format-json
lcs --root . call-me-verify <run-id> --workspace . --inspect --format-json
```

### 3. Python API Integration
```python
import os
from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.governance import ApproverConsent, ApproverRole
from lcs.policy import InterfaceTrustPolicy

# Initialize isolated or project context
config = LCSConfig.resolve()
with LCSContext(config=config, auto_migrate=True) as ctx:
    # 1. Synthesize multi-step execution plan from natural language query
    plan = ctx.planning_engine.create_plan("Process report and generate digest")
    print(f"Plan ID: {plan.plan_id}, Steps: {len(plan.steps)}")

    # 2. Authorize plan under Governance Gate 1 & Gate 2
    consent = ApproverConsent("lead@company.com", ApproverRole.HUMAN_OPERATOR, "CLI_APPROVAL")
    policy = InterfaceTrustPolicy("production-policy", min_interface_version=1)
    
    token, eval_result = ctx.governance_engine.approve_plan(plan, approver=consent, active_policy=policy)
    print(f"Authorization Token: {token.token_id}")

    # 3. Execute plan with atomic token consumption
    result = ctx.execution_engine.execute_plan(plan, token)
    print(f"Execution State: {result.lifecycle_state.value}")

    # 4. Verify cryptographic audit chain integrity
    is_valid, count, msg = ctx.execution_engine.audit_ledger.verify_ledger()
    assert is_valid is True
    print(f"Audit ledger verified across {count} events.")
```

### 4. Running the Model Context Protocol (MCP) Server
Launch LCS as a standard stdio MCP server for agent configurations:
```bash
lcs serve-mcp
```
Configure in Claude Desktop, OpenCode, or Cursor:
```json
{
  "mcpServers": {
    "lcs": {
      "command": "lcs",
      "args": ["serve-mcp"]
    }
  }
}
```

---

## Declarative Custom Agent Specification

To integrate a custom or future coding agent, define a declarative specification file (`agent_spec.json`):

```json
{
  "schema_version": "1.0",
  "agent_id": "adapter.custom.v1",
  "name": "custom_agent",
  "display_name": "Custom Coding Agent",
  "precedence": 70,
  "environment_markers": {
    "env_vars": ["CUSTOM_AGENT_ACTIVE"],
    "workspace_files": ["custom_agent.config.json"],
    "workspace_dirs": [".custom_agent"]
  },
  "command_integration": {
    "target_path": ".custom_agent/commands/call-me.md",
    "execution_command": "lcs call-me --handoff -- \"$*\""
  },
  "capabilities": {
    "slash_commands": true,
    "skills": true,
    "mcp": true,
    "subagent_delegation": false
  }
}
```
LCS dynamically detects markers, generates safe `/call-me` command templates, and rejects untrusted command injection or directory traversal patterns.

---

## Cryptographically Sealed Frozen Core

The five foundational Python core modules and four database migration schemas remain 100% invariant against their authoritative SHA-256 digests:

| Component / Module | Authoritative SHA-256 Digest | Status | Invariance Guarantee |
| :--- | :--- | :---: | :---: |
| `capability_retrieval_v1.py` | `b7d476236d2f5addd6619f619a6f1145bf407a6917d20493e4d85afd0ca843b4` | ✅ VERIFIED | Invariant since v3.0.0 |
| `capability_retrieval_v1_1.py` | `2a29c3dcec1e792021a63707fec9a92c3a6505080b0c05a63e377c69ce272e12` | ✅ VERIFIED | Invariant since v3.0.0 |
| `capability_parameter_v1.py` | `469b743cf6af1f6807544f2182dee12a4708ceb5512dd32185c4e5986a524c00` | ✅ VERIFIED | Invariant since v3.0.0 |
| `capability_planning_v1.py` | `eb81b3255d58958d73689b99cb8506647f8c781d30d93cea1c90dfd435d070e4` | ✅ VERIFIED | Invariant since v3.0.0 |
| `governance_policy_v1.py` | `5273f17e83d1c90cd5f935b815841db711a3523a08d1d180f2a4d67bcad44252` | ✅ VERIFIED | Invariant since v3.0.0 |
| `lcs/schemas/lcs_schema_v2b.sql` | `49ee7ff523e6740f01d52ba279da77055047f1ea0325a7042614befb7401e421` | ✅ VERIFIED | Approved Portable Baseline |
| `lcs/schemas/lcs_schema_m3_migration.sql` | `65652fa722ddb4fe1334071cd01369cb13e11923a3dd55d313008f73bdefb652` | ✅ VERIFIED | Invariant since v3.0.0 |
| `lcs/schemas/lcs_schema_m4_migration.sql` | `6644e0ead9752ba2c136c5414a6dde72a8ad5eed126ceebe246e7f84ab1817dc` | ✅ VERIFIED | Invariant since v3.0.0 |
| `lcs/schemas/lcs_schema_m5_sqlite_compat.sql` | `88d13292f7888fe7148785c935f4854d8acfca700f0777e1334190f8f750b620` | ✅ VERIFIED | Invariant since v3.0.1 |

Verify checksums at any time:
```bash
python3 scripts/verify_frozen_hashes.py
```

---

## Cross-Platform CI Matrix

LCS runs automated CI testing across all supported operating systems and Python versions:

| Target Runner OS | Python Versions | Total Jobs | Passed | Status |
| :--- | :--- | :---: | :---: | :---: |
| **Ubuntu Linux 24.04 LTS** | 3.10, 3.11, 3.12, 3.13 | 4 | 4 | ✅ 100% Green |
| **macOS 15 (Apple Silicon)** | 3.10, 3.11, 3.12, 3.13 | 4 | 4 | ✅ 100% Green |
| **Native Windows Server 2022** | 3.10, 3.11, 3.12, 3.13 | 4 | 4 | ✅ 100% Green |

---

## Release Status, Security Boundaries & Known Limitations (`v3.2.0rc3` Published / `v3.2.0rc4` Candidate)

> [!NOTE]
> **`v3.2.0rc3` is the latest published experimental release candidate**; `v3.2.0rc4` is a release-candidate preparation on `feat/find-skills-acquisition` (cross-platform CI pending). All 9 cryptographically sealed frozen core modules and schemas remain unchanged.

### What Is Tested vs. Pending
- **Cross-Platform Automated Test Suite**: `v3.2.0rc3` passed the 15-job CI matrix across Ubuntu, macOS, and Windows (Python 3.10–3.13) + 3 platform installer jobs. `v3.2.0rc4` CI execution is pending branch push/PR verification.
- **Native Host Subagent Execution vs. Fresh-Session Slash-Command Trace**: Multi-agent dispatch (`invoke_subagent`), multi-skill pairing, and synchronized contract adaptation have been **demonstrated on Google Antigravity**, while a genuine fresh-session Antigravity UI `/call-me` end-to-end trace remains a manual acceptance item. Adapters for Claude Code, OpenCode, Codex, and custom hosts are **protocol/template-verified** and do not share identical native subagent APIs.
- **External Acquisition Integrity & Confinement Limitations**:
  - `npx skills@1.4.4 add` resolves from upstream repository HEAD unless pinned (commit/hash is recorded post-install in `skills-lock.json`); `SKILL.md` is digest-checked against the evaluated upstream `SKILL.md`, while supporting scripts outside `SKILL.md` are pattern/symlink-scanned post-install rather than pre-hashed before download.
  - `DEFAULT_TRUSTED_OWNERS` (`vercel-labs`, `anthropics`, `github`, `microsoft`, `openai`) governs `TRUSTED_AUTO` auto-approval only and is **not** a guarantee of safety. `ASK` remains the default policy.
  - Call Me enforces **application-level** security controls (canonical path confinement via `os.path.commonpath`, `os.path.islink` / `O_NOFOLLOW`, environment allowlisting) and does **not** provide OS/kernel-level sandboxing (containers, seccomp, or Seatbelt).
- **Selection Intelligence & Benchmark Limitations**:
  - **Local Fallback Retrieval** achieves **68.57% P@1 / 71.11% R@3** on `dataset_100_objectives.json` (77.50% P@1 / 84.17% R@3 held-out) and **44.00% P@1 / 70.00% R@3** on `dataset_fresh_eval.json` (37.78% P@1 / 66.67% R@3 held-out, 100.00% adversarial abstention).
  - **Host-Assisted Semantic Reasoning** (`SemanticReasoner`) and **Semantic Eligibility Filtering** (`assess_semantic_eligibility`) remain bounded by the Stage A candidate window and heuristic domain matching when host reasoning is unavailable.
- **Contract Synchronization**: Interface mutation detection, stale (`NEEDS_UPDATE`) propagation, verification blocking, and evidence-backed adaptation (`mark_component_adapted`) are enforced by `ProjectContractManager`; specialist redispatch is coordinated by the host orchestrator rather than an autonomous background daemon.

---

## Community & Security Guidelines

- **Contributing**: Please review [CONTRIBUTING.md](CONTRIBUTING.md) for architectural invariants, development setup, and PR requirements.
- **Code of Conduct**: Community interaction guidelines are detailed in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Security Policy**: For vulnerability reporting and security invariants, see [SECURITY.md](SECURITY.md).
- **License**: MIT License (see [LICENSE](LICENSE)). Copyright (c) 2026 Vellor Pavan.
