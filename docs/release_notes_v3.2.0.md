# Release Notes — Living Capability System (LCS) v3.2.0

**Release Tag:** `v3.2.0` (Pending Approval)  
**Release Date:** November 23, 2026  
**Commit Target:** `ff336d2` on `verify/v3.2.0rc1-ci`  

---

## Overview

The **Living Capability System (LCS) v3.2.0** delivers a universal, local-first capability intelligence, planning, governance, and execution engine for coding agents. With v3.2.0, developers can install LCS **once** on their workstation and invoke capabilities seamlessly from any compatible agent—including Google Antigravity, OpenCode, Claude Code, OpenAI Codex, and custom declarative coding agents—using the exact preferred command `/call-me <task>`.

LCS bridges the gap between natural language developer intent and zero-trust tool execution without conversational pollution, token bloat, or unreviewed system actions.

---

## Highlights in v3.2.0

### 1. Universal Local-First Setup (`lcs setup`)
- **Single-Command Setup:** `lcs setup --global` configures a persistent user-level environment (`~/.lcs`), provisions the SQLite database (`lcs.db`), applies all database migrations, and generates command artifacts for all detected agents.
- **Project-Local Isolation:** `lcs setup --project` creates an isolated `./.lcs` state directory, ensuring multi-project isolation with zero database or cache leakage.
- **Diagnostics & Self-Repair:** Run `lcs setup --check` for non-destructive system health inspection and `lcs setup --repair` to fix damaged directories, missing permissions, or stale command files.

### 2. Pluggable Host Adapter Contract
- **Custom Coding Agent Support:** Integrate any third-party or internal coding agent via a declarative JSON/YAML specification (`DeclarativeCustomAdapterSpec`).
- **Security-First Validation:** Built-in validation strictly rejects path traversal attempts and arbitrary shell injection in command templates.
- **Dynamic Discovery & Negotiation:** Automatically detects active agent sessions, workspace instruction files, and capability boundaries.

### 3. Native Cross-Platform Parity
- **Genuine Win32 File Locking:** Replaced compatibility shims with genuine kernel-level cross-process locking (`kernel32.LockFileEx` / `UnlockFileEx`), achieving full concurrency parity between Windows, macOS, and Linux.
- **Descriptor Confinement & Safe Subprocesses:** Descriptor-relative storage emulation and process tree supervision (`taskkill /F /T` on Windows) prevent resource leakage and orphaned child processes.
- **12/12 Green CI Matrix:** Fully verified across Ubuntu Linux 24.04, macOS 15, and native Windows Server 2022 on Python 3.10–3.13.

### 4. Dual-Gate Zero-Trust Governance & Auditability
- **Fail-Closed Execution:** Dual-gate authorization requires Policy Gate 1 (attestation & versioning) and Approver Gate 2 (human consent).
- **Plan Integrity Binding:** Authorization tokens are mathematically bound to the RFC 8785 JSON Canonicalization (JCS) representation of the plan (`PlanIntegrityHash`).
- **Single-Use Replay Protection:** Monotonic Compare-and-Consume atomic protocol under SQLite exclusive transaction locks prevents token replay attacks.
- **Immutable Audit Trail:** Append-only cryptographic ledger chained with HMAC-SHA256 digests.

---

## Coding Agent Support Matrix

| Host Environment | Command Artifact | Syntax | Status |
| :--- | :--- | :--- | :--- |
| **Google Antigravity** | `~/.gemini/config/skills/call-me/SKILL.md` | `/call-me` | **LIVE_VERIFIED** |
| **OpenCode** | `~/.opencode/commands/call-me.md` | `/call-me` | **PROTOCOL_VERIFIED** |
| **Claude Code** | `~/.claude/commands/call-me.md` | `/call-me` | **PROTOCOL_VERIFIED** |
| **OpenAI Codex** | `.agents/skills/call-me/SKILL.md` | `/call-me` | **PROTOCOL_VERIFIED** |
| **Custom Agents** | Declarative spec target | `/call-me` | **CONTRACT_LIVE_VERIFIED** |

---

## Checksum Invariance Verification

| Module / Schema | Expected SHA-256 Digest | Status |
| :--- | :--- | :---: |
| `capability_retrieval_v1.py` | `b7d476236d2f5addd6619f619a6f1145bf407a6917d20493e4d85afd0ca843b4` | Invariant |
| `capability_retrieval_v1_1.py` | `2a29c3dcec1e792021a63707fec9a92c3a6505080b0c05a63e377c69ce272e12` | Invariant |
| `capability_parameter_v1.py` | `469b743cf6af1f6807544f2182dee12a4708ceb5512dd32185c4e5986a524c00` | Invariant |
| `capability_planning_v1.py` | `eb81b3255d58958d73689b99cb8506647f8c781d30d93cea1c90dfd435d070e4` | Invariant |
| `governance_policy_v1.py` | `5273f17e83d1c90cd5f935b815841db711a3523a08d1d180f2a4d67bcad44252` | Invariant |
| `lcs/schemas/lcs_schema_v2b.sql` | `49ee7ff523e6740f01d52ba279da77055047f1ea0325a7042614befb7401e421` | Invariant |
| `lcs/schemas/lcs_schema_m3_migration.sql` | `65652fa722ddb4fe1334071cd01369cb13e11923a3dd55d313008f73bdefb652` | Invariant |
| `lcs/schemas/lcs_schema_m4_migration.sql` | `6644e0ead9752ba2c136c5414a6dde72a8ad5eed126ceebe246e7f84ab1817dc` | Invariant |
| `lcs/schemas/lcs_schema_m5_sqlite_compat.sql` | `88d13292f7888fe7148785c935f4854d8acfca700f0777e1334190f8f750b620` | Invariant |

---

## Installation & Getting Started

```bash
# Install via wheel or editable source
pip install lcs_core-3.2.0rc1-py3-none-any.whl

# Initialize local-first LCS environment
lcs setup --global

# Verify installation health
lcs setup --check
```
