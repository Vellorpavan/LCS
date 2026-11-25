# CALL ME — Universal AI Capability Orchestrator
## User & Developer Onboarding Guide

Welcome to **Call Me** — the universal, intelligent, synchronized, local-first capability orchestration system.

---

## 1. Quick Start: Install Once

### On macOS / Linux:
```bash
curl -fsSL https://raw.githubusercontent.com/pavan/LCS/feature/call-me-v3.2.0/install.sh | bash
```
Or locally from source:
```bash
./install.sh
```

### On Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/pavan/LCS/feature/call-me-v3.2.0/install.ps1 | iex
```
Or locally:
```powershell
.\install.ps1
```

The installer automatically:
- Creates an isolated Python virtual environment (`~/.lcs/venv`).
- Installs the `call-me` and `lcs` executables into `~/.local/bin` (or `AppData\Local\Programs\CallMe\bin`).
- Detects installed AI hosts (Antigravity, Claude Code, OpenCode, Codex).
- Idempotently installs the `/call-me` slash command.

---

## 2. Using Call Me in Your AI Host

Simply open your AI host (e.g. Antigravity, Claude Code, OpenCode) and type:

```
/call-me <any natural language objective>
```

### Examples:
- `/call-me Build a Python telemetry service with health monitoring and automated unit tests`
- `/call-me Design an accessible React design system modal component and verify with Playwright`
- `/call-me Model a 3D mechanical gear assembly in Blender with PBR materials and GLTF export`
- `/call-me Conduct an OWASP Top 10 security review on our auth endpoints and write regression tests`

---

## 3. How Call Me Works: 4-Phase Closed-Loop Protocol

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ 1. HYBRID PLAN  │ ──> │ 2. NATIVE WAVES  │ ──> │ 3. VERIFICATION  │ ──> │ 4. CAS RECEIPT  │
│ Semantic Search │     │ Specialist Agent │     │ Physical File &  │     │ Cryptographic   │
│ & DAG Assembly  │     │ Dispatch (Waves) │     │ Automated Tests  │     │ Audit Ledger    │
└─────────────────┘     └──────────────────┘     └──────────────────┘     └─────────────────┘
```

1. **Intelligent Retrieval & DAG Planning**:
   Call Me parses your objective, performs local hybrid semantic retrieval over 750+ catalog capabilities, decomposes complex requests into dependency-ordered waves, and hydrates authoritative specialist instructions.
2. **Native Host Specialist Dispatch**:
   In supported hosts (such as Antigravity), Call Me coordinates native subagents (`invoke_subagent`), assigning specialist personas for each task in parallel waves.
3. **Physical Deliverable Verification Gate**:
   Call Me verifies that expected files exist physically on disk, are non-empty, are confined to the workspace, and pass automated test suites (e.g. `pytest`, `unittest`).
4. **Durable Verification Receipt**:
   Cryptographic SHA-256 digests of all generated files and test logs are sealed into SQLite and Content-Addressable Storage (CAS).

---

## 4. CLI Commands Reference

Call Me provides intuitive CLI commands:

```bash
# Check version
call-me --version

# Inspect host environment and capabilities
call-me setup --check

# Generate a structured execution plan
call-me plan "Build a telemetry service and write tests" --format-json

# Verify physical deliverables and automated tests
call-me verify <run-id> --workspace <path> --files main.py test_main.py --commands "python3 -m unittest test_main.py"

# Inspect previously persisted verification receipt
call-me verify <run-id> --inspect
```

Legacy aliases remain 100% backward compatible:
- `lcs call-me "<task>"`
- `lcs call-me-plan "<task>"`
- `lcs call-me-verify <run-id>`
- `lcs verify <run-id>`

---

## 5. Security & Isolation Invariants

- **Application-Level Workspace Confinement**: Rejects directory traversal (`..`), symlink escapes, and Windows NTFS alternate data streams (`:`).
- **Subprocess Credential Scrubbing**: Strips sensitive environment variables (`*_KEY`, `*_SECRET`, `*_TOKEN`, `*_AUTH`) before executing verification commands.
- **Binary Allowlist**: Permits only authorized compilers and test runners (`python`, `pytest`, `cargo`, `go`, `node`, `npm`).
- **Anti-Fabrication & Anti-Tamper**: Rejects unrecognized or fabricated run IDs at Tier 1; verifies cryptographic artifact digests against originating plans.
- **Honest Sandboxing**: Transparently reports application-level governance boundaries without falsely claiming kernel-level OS virtualization.
