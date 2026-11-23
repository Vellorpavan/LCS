# Changelog

All notable changes to the Living Capability System (LCS) are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.2.0] - 2026-11-23

### Added
- **Universal Local-First Setup & Persistence Engine (`lcs setup`)**:
  - Idempotent CLI setup command with user-global (`~/.lcs`) and project-local (`./.lcs`) configuration targets.
  - Multi-project filesystem isolation preventing cross-project database or cache leakage.
  - Non-destructive diagnostic health checks (`lcs setup --check` / `--doctor`) and automated repair (`lcs setup --repair`).
  - Executable resolution across terminal sessions without active virtual environments.
- **Pluggable Host Adapter Architecture & Dynamic Agent Discovery**:
  - Declarative custom agent adapter contract (`DeclarativeCustomAdapterSpec`, `DeclarativeHostAdapter`).
  - Dynamic discovery of ambient workspace markers, instruction files, and skills.
  - Capability negotiation across CLI, MCP, slash commands, and subagent delegation.
  - Rigorous security validation blocking path traversal (`CustomAdapterSecurityError`) and arbitrary shell injection in custom command templates.
- **Universal Model Context Protocol (MCP) Interface & Anti-Self-Authorization**:
  - Unified `lcs_call_me` MCP tool exposing governed capability orchestration to external LLM callers.
  - Anti-self-authorization enforcement: callers cannot self-authorize by sending `decision="APPROVED"`; execution strictly requires an independently authenticated, scoped governance token.
- **Cross-Agent Project Context Hydration**:
  - State hydration (`ProjectContextHydrator`) transferring active tasks and capability dependencies when switching coding agents on the same project.
  - Bounded context selection with cryptographic provenance tracking and token budgeting.
- **Native Windows Cross-Process Concurrency & Filesystem Parity**:
  - Genuine Win32 cross-process file locking in `lcs/locking.py` utilizing `kernel32.LockFileEx` and `kernel32.UnlockFileEx` via OS file handles.
  - Secure Windows-native filesystem emulation in `cas_storage_engine_v2b.py` preserving path confinement without unsafe shortcuts.
  - Process tree termination on Windows via `taskkill /F /T` preventing orphaned child processes.
- **Cross-Platform GitHub Actions CI Matrix**:
  - 12-job matrix covering Ubuntu Linux, macOS, and native Windows Server 2022 across Python 3.10, 3.11, 3.12, and 3.13.

### Changed
- Standardized preferred user-facing command invocation across all supported environments to exact `/call-me <task>`.
- Preserved existing host configuration files and required explicit `--force` confirmation before overwriting conflicting command artifacts.
- Improved error handling in concurrent DAG execution to ensure proper cleanup and parameter propagation across threads.

### Security & Invariance
- 100% bit-for-bit SHA-256 invariance preserved across all five frozen core Python modules.
- Formally validated database migration history across all 4 sequential schemas (`lcs/schemas/`).
- Full repository regression suite passed with 541/541 tests green.

---

## [3.2.0rc1] - 2026-11-21

### Added
- **OpenAI Codex Environment Adapter & Ambient Rule Discovery**:
  - Full adapter implementation in `lcs/adapters/codex.py`.
  - Discovers ambient workspace rules (`AGENTS.md`, `CLAUDE.md`, `RULES.md`, `.cursorrules`).
  - Detects active Codex sessions via `CODEX_THREAD_ID` and `CODEX_SESSION_ID`.
- **Multi-Tier Execution Verification Gates**:
  - Implemented in `lcs/verification/gates.py` for Skills, Scripts, MCP Tools, Agents, and Templates.
  - Eliminates the "exit 0 fallacy" via Tier 1 identity verification, Tier 3 execution proofs, and Tier 4 contract compliance.
  - Scans stderr for fatal execution tracebacks (`FATAL_STDERR_PATTERNS`) and verifies non-empty output artifacts.
- **Thread-Safe Persistent MCP Connection Pooling**:
  - Implemented in `lcs/mcp_server.py` with double-checked locking (`threading.RLock`).
  - Automatic process reuse across sequential tool calls, child process health monitoring, and clean `SIGTERM`/`SIGKILL` teardown.
- **Concurrent Branching DAG Execution Engine**:
  - Implemented in `execution_engine_v1.py` with `ThreadPoolExecutor`.
  - Independent parallel steps execute concurrently in topological waves with thread-safe SQLite connections.
  - Parameter propagation from upstream dependencies and reverse compensation unwinding on step failures.
- **Multi-Agent Subagent Delegation Harness**:
  - Implemented in `lcs/subagents/bridge.py` via `AntigravitySubagentBridge`.
  - Structured parent/child task contracts, transcript loop bounds enforcement (`max_iterations`), and honest fail-closed reporting on unsupported hosts.
- **Live OpenCode Host Integration Suite**:
  - Verified integration with local binary (`/Users/pavan/.opencode/bin/opencode`).
  - Supports modern OpenCode v2.3+ config format (`mcp.servers`) and `opencode mcp add`.

### Changed
- Refined `AntigravityAdapter.detect_active` to prioritize explicit foreign workspace markers (`CLAUDE.md`, `opencode.json`) over ambient shell variables.
- Refined deliverable detection in `execution_engine_v1.py` to exclude input targets (`target_file`), focusing strictly on declared output deliverables.
- Reconciled uncompleted plan step records on failure to enforce honest `SKIPPED` status logging across execution audit ledgers.

### Security & Invariants
- 100% SHA-256 hash invariance preserved across all 5 frozen core modules.
- Zero database schema migrations or drift (`lcs/schemas/`).
- Strict filesystem confinement enforced by `PathSecurityValidator` (symlink escape and traversal rejection).

---

## [3.1.0] - 2026-11-20

### Added
- Unified Capability Inventory (`lcs/inventory/`) with live cross-host catalog scanning.
- Deep Capability Retriever with transitive dependency hydration and referenced asset delivery.
- Token-optimized context transfer with diamond deduplication and cycle detection.
- Fast local cache warming with filesystem watcher reconciliation (`lcs/cache/`).
- Thin conversational intake interface `/call-me` (`lcs/interface/`).

---

## [3.0.1] - 2026-11-19

### Added
- Standalone packaging and wheel distribution (`lcs-core`).
- Clean-environment validation and SQLite schema migration engine (`lcs/schemas/`).
- Cross-platform POSIX descriptor-relative storage engine (`cas_storage_engine_v2b.py`).
- HMAC-SHA256 dual-gate execution governance engine (`governance_policy_v1.py`).
