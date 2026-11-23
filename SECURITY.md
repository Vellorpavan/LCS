# Security Policy

## Supported Versions

Security updates and vulnerability remediation are actively provided for the following releases:

| Version | Supported | Status |
| :--- | :---: | :--- |
| `3.2.x` | Yes | Active Production Release |
| `3.1.x` | Yes | Critical Security Fixes Only |
| `< 3.1.0` | No | End of Life |

---

## Core Security Model & Invariants

The Living Capability System (LCS) is architected around strict zero-trust invariants:

1. **Fail-Closed Governance**:
   - Capability execution requires dual-gate approval: Policy Gate 1 (attestation and resource limits) and Gate 2 (explicit human operator consent).
   - Execution tokens are single-use, single-scope, and protected against replay attacks.
2. **Cryptographic Integrity**:
   - Core Python algorithms and database migration schemas are frozen and verified by SHA-256 digests.
   - All execution events are appended to a tamper-evident, SHA-256 hash-chained audit ledger.
3. **Filesystem Confinement**:
   - Content-Addressable Storage (CAS) operations enforce strict boundaries to prevent path traversal, directory symlink escapes, and unauthorized file access.
4. **Agent Isolation**:
   - Host adapters and MCP connections operate in sandboxed environments with bounded permissions and no ambient privilege escalation.

---

## Reporting a Security Vulnerability

If you identify a security vulnerability in LCS, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Preferred reporting channel: Submit a confidential vulnerability report via [GitHub Security Advisories](https://github.com/Vellorpavan/LCS/security/advisories).
3. Alternative reporting channel: Contact the project maintainer directly via email at: **vellorpavan@gmail.com**.
4. Include:
   - Description of the vulnerability and attack vector.
   - Steps to reproduce or a minimal proof-of-concept.
   - Affected versions and operating environments.
   - Potential impact on governance, isolation, or data confidentiality.

### Our Response Commitment
- **Initial Acknowledgment**: Within 48 hours of report receipt.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Disclosure**: Coordinated disclosure after remediation is validated across supported platforms.
