# Contributing to Living Capability System (LCS)

Thank you for your interest in contributing to the Living Capability System (LCS)! LCS is a cryptographic, zero-trust capability discovery, planning, governance, and execution engine designed for coding agents.

## Architectural Invariants (Must Read Before Contributing)

LCS enforces strict mathematical and architectural constraints to guarantee zero-trust execution:

1. **Frozen Core Modules**:
   - The five core modules (`capability_retrieval_v1.py`, `capability_retrieval_v1_1.py`, `capability_parameter_v1.py`, `capability_planning_v1.py`, `governance_policy_v1.py`) are cryptographically frozen.
   - Their SHA-256 digests are verified bit-for-bit in CI via `scripts/verify_frozen_hashes.py`. Pull requests that alter these files will fail CI.
2. **Database Schemas & Migrations**:
   - Database schema files in `lcs/schemas/` are version-locked.
   - New database requirements must be introduced as sequential, backward-compatible migration scripts evaluated through `migration_manager.py`.
3. **Cross-Platform Compatibility**:
   - LCS supports macOS (Darwin), Ubuntu Linux, and native Windows.
   - Filesystem operations must not assume POSIX-only APIs. Always use cross-platform primitives and verify directory descriptors and locking via `lcs/locking.py`.
4. **Dual-Gate Governance & Auditability**:
   - All capability executions must pass Policy Gate 1 (attestation & versioning) and Approver Gate 2 (human consent).
   - Execution tokens cannot be self-authorized, and all state transitions are immutably logged to the hash-chained audit ledger.

---

## Local Development Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Vellorpavan/LCS.git
   cd LCS
   ```

2. **Create a Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

4. **Verify System Setup**:
   ```bash
   python3 scripts/verify_frozen_hashes.py
   pytest -q
   ```

---

## Testing Guidelines

- All new features and bug fixes require automated tests.
- Run tests locally before opening a pull request:
  ```bash
  pytest tests/
  ```
- Verify clean-room wheel building:
  ```bash
  python3 -m build --wheel
  ```

---

## Pull Request Process

1. Create a feature branch from `main`: `git checkout -b feature/your-feature-name`.
2. Ensure commit messages follow Conventional Commits formatting (e.g., `feat:`, `fix:`, `docs:`, `test:`).
3. Confirm that no secret keys, temporary test databases, or personal paths are committed.
4. Verify all 12 matrix jobs pass on the GitHub Actions CI workflow.
5. Open a Pull Request referencing the relevant issue and detailing the verification evidence.
