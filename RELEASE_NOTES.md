# LCS v3.2.0rc1 — Release Notes

> **Status:** Release Candidate — not yet merged to `main` or published to PyPI.
> **Branch:** `verify/v3.2.0rc1-ci` · **Verified commit:** `e7d98483e7894ba97116ec62fb2a4fabf0d2dbc1`
> **CI matrix:** 12/12 jobs passing — Ubuntu / macOS / Windows × Python 3.10–3.13

---

## What is LCS?

The **Living Capability System** (LCS) is an open-source Python framework for building capability-driven orchestration pipelines. A developer describes what they want in natural language using `/call-me`, and LCS automatically discovers installed capabilities, constructs a dependency-aware execution DAG, governs every step with cryptographic audit trails, and returns a structured result — with or without an attached LLM host.

---

## New in v3.2.0rc1

### 1. `/call-me` natural-language orchestration

Invoke LCS with a plain English objective:

```bash
lcs call-me "scaffold a Python microservice, add telemetry, write tests, and assemble the application" --execute
```

LCS decomposes the request into discrete capabilities, resolves inter-step dependencies, and executes the pipeline. No manual capability IDs, skill names, or execution graphs required.

### 2. Automatic capability discovery and semantic selection

At startup, `lcs setup` indexes every installed skill and adapter using an FTS5 full-text index with semantic profile scoring. The best-matching capabilities are selected automatically and explained in the execution trace. Discovery works without adapter registration when only the built-in starter catalog is present.

### 3. Five packaged starter capabilities

LCS now ships a minimal, useful starter catalog inside the wheel and source distribution, automatically discovered on first `initialize_environment()` call:

| Capability | URN slug | Purpose |
|---|---|---|
| Python Scaffold | `python-scaffold` | Generate Python project skeletons with packaging metadata |
| Telemetry Service | `telemetry-service` | Add structured logging, metrics, and health endpoints |
| Health Monitor | `health-monitor` | Service health-check and liveness probe scaffolding |
| Application Assembly | `app-assembly` | Compose component outputs into a deployable application bundle |
| Test Runner | `test-runner` | Generate and execute test suites for assembled components |

No adapter registration is needed — the starter skills ship inside the package and are found automatically via path resolution.

### 4. Dependency-aware DAG execution and safe concurrency

The topological wave executor (`execution_engine_v1.py`) schedules capabilities in dependency order: independent capabilities execute concurrently within the same wave; a fan-in step does not begin until every upstream branch has finished. The scheduler validates all DAG edges before execution begins — both compact 2-tuples `(src, dst)` and canonical 4-tuples `(src, dst, type, weight)` are accepted; malformed edges are rejected with an explicit error.

### 5. Semantic component → assembly → verification phase ordering

A new `_semantic_phase_rank` function in `core_bridge.py` enforces that:

- **Phase 1 (rank 0):** scaffold / generation capabilities run first
- **Phase 2 (rank 1):** testing / runner capabilities follow component generation
- **Phase 3 (rank 2):** assembly capabilities run only after components are ready
- **Phase 4 (rank 3):** verification / health / monitor capabilities run last

Cross-capability dependencies (e.g. assembly waiting on scaffold output) are enforced as DAG gate constraints, not just ordering hints. A regression test validates that the assembly step does not start before its declared upstream phases complete.

### 6. Governance: dual-gate policy with cryptographic EAT tokens

Every execution step passes through two gates before dispatch:

- **InterfaceTrustPolicy** — validates that the capability call conforms to its declared schema
- **ApproverConsent** — requires an in-process approval token before execution proceeds

Approval tokens are **single-use** (replay immunity enforced) and are signed as CBOR-encoded EAT (Entity Attestation Token) claims. A consumed token cannot be re-used, even within the same process lifetime.

### 7. SQLite and CAS audit trails

All execution events are recorded in two append-only stores:

- **SQLite ledger** — human-readable event log with HMAC-SHA256 chain integrity. Each row's digest covers all prior rows; tampering with any entry breaks the chain.
- **CAS (Content-Addressable Store)** — artifact digests keyed by SHA-256 content hash, used as step output references in the execution trace.

### 8. Antigravity native-agent integration

LCS provides a first-class integration protocol for Antigravity specialist subagents (`lcs/subagents/bridge.py`). When the host coordinator (e.g., Antigravity) invokes `invoke_subagent`, LCS creates the task record, tracks state transitions, and gates result acceptance through the verification layer.

> **Accurate limitation:** The standalone `lcs call-me --execute` CLI does **not** automatically spawn LLM subagents. It runs the internal concurrent execution engine using registered executor callbacks. Native LLM agent delegation requires the host coordinator to invoke `invoke_subagent`; LCS provides the protocol, task creation, state tracking, and verification gate on the returned result.

---

## Cross-platform support

| Platform | Python versions | CI status |
|---|---|---|
| Ubuntu 22.04 | 3.10, 3.11, 3.12, 3.13 | ✅ 4/4 |
| macOS 13 | 3.10, 3.11, 3.12, 3.13 | ✅ 4/4 |
| Windows Server 2022 | 3.10, 3.11, 3.12, 3.13 | ✅ 4/4 |

---

## Security notes

- **Path validation** (`PathSecurityValidator`) guards against directory traversal, Windows NTFS alternate data stream injection (`:` in filenames), null bytes, and reserved Win32 names (`CON`, `NUL`, `AUX`, etc.) across all platforms.
- **Subprocess execution** is not OS-level sandboxed; the path validator guards inputs but does not restrict the subprocess environment.
- The `secondary_input_data` binding name was chosen to avoid false-positive rejection by the ADS name-token scanner.

---

## Installation

```bash
# From the release wheel
pip install lcs_core-3.2.0rc1-py3-none-any.whl

# Initialize the environment (indexes starter skills, creates SQLite schema)
lcs setup

# Invoke
lcs call-me "scaffold a Python microservice and add telemetry" --execute
```

---

## Known limitations

- Standalone CLI does not automatically invoke native LLM subagents (see §8 above).
- No PyPI release yet — install from the built wheel or source distribution.
- `main` branch merge, final tag, and PyPI publish require explicit operator authorization.
- No graphical capability browser or web UI in this release.

---

## Frozen invariant verification

The following core modules and SQL schemas are protected by cryptographic checksums and must not be modified between releases:

```
capability_retrieval_v1.py        b7d476236d2f5add...
capability_retrieval_v1_1.py      2a29c3dcec1e7920...
capability_parameter_v1.py        469b743cf6af1f68...
capability_planning_v1.py         eb81b3255d58958d...
governance_policy_v1.py           5273f17e83d1c90c...
lcs/schemas/lcs_schema_m3_migration.sql   65652fa722ddb4fe...
lcs/schemas/lcs_schema_m4_migration.sql   6644e0ead9752ba2...
lcs/schemas/lcs_schema_m5_sqlite_compat.sql  88d13292f7888fe7...
lcs/schemas/lcs_schema_v2b.sql    49ee7ff523e6740f...
```

Verify at any time: `python3 scripts/verify_frozen_hashes.py`

---

## Changelog summary (since v3.1.0)

| Commit | Change |
|---|---|
| `e7d9848` | feat(orchestration): package starter capability catalog and enforce semantic phase ordering |
| `629c582` | test(orchestration): replace fragile wall-clock duration with deterministic interval overlap assertions |
| `a3ca123` | feat(orchestration): multi-branch DAG scheduling, DAG edge validation, and call-me acceptance tests |
| `70e55a4` | fix(security): cross-platform Windows filesystem authorization, embedded CLI argument validation |
| `80e016f` | fix(security): cross-platform Windows filesystem authorization and Stage 7.3 hardening |

---

*LCS is released under the MIT License — see [LICENSE](./LICENSE) for the full terms.*
*Copyright (c) 2026 Vellor Pavan*
