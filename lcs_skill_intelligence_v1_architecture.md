# LCS — Skill Intelligence V1: Architecture and Specification

**Author:** Senior Software Architect  
**Date:** November 12, 2026  
**Status:** FINAL ARCHITECTURE SPECIFICATION (Pre-Implementation Baseline)  
**Version:** 1.2.0  

---

## 1. Executive Summary & Problem Space

### 1.1 Problem Statement
In modern agentic AI engineering, operational knowledge is expressed across multiple distinct artifact types: procedural workflows, interactive slash commands, ambient behavioral rules, agent instructions, and agent configurations. Today, these artifacts exist in fragmented, vendor-specific silos across heterogeneous AI environments:
- **Google Antigravity:** Directory-centric skill bundles (`SKILL.md`), built-in system skills, and plugin-contributed skills.
- **Claude Code:** Directory skills (`SKILL.md`), single-file slash commands (`~/.claude/commands/*.md`), ambient rules (`~/.claude/rules/*.md`, `CLAUDE.md`), and hooks.
- **OpenCode:** Centralized project manifests (`opencode.json`), declared instruction arrays (`"instructions": [...]`), command templates (`.opencode/commands/*.md`), and agent configurations.

Prior agent architectures suffer from three critical defects:
1. **Conflated Taxonomy:** All Markdown prompt files are naively lumped together as "skills", confusing ambient rules with callable macros and procedural playbooks.
2. **Opaque & Unverified Ingestion:** Artifacts are ingested without provenance, content-addressable integrity, or safety quarantine, exposing agents to prompt injection and configuration drift.
3. **Siloed Planning:** Planners operate exclusively across raw executable tools (e.g. MCP RPC endpoints) and cannot incorporate procedural behavioral guidance into multi-step execution plans.

### 1.2 Objective: Skill Intelligence V1
**Skill Intelligence V1** establishes a non-destructive, read-only capability intelligence layer in the Living Capability System (LCS) that:
- **Discovers** artifacts across Google Antigravity, Claude Code, and OpenCode environments from dynamically resolved, authorized root directories.
- **Classifies** each artifact into its precise taxonomic type (`SKILL`, `COMMAND`, `RULE`, `AGENT_INSTRUCTION`, `AGENT_CONFIGURATION`) or flags it safely as `UNKNOWN` / `UNSUPPORTED`.
- **Ingests** raw exact-byte contents into Content-Addressed Storage (CAS) with deterministic SHA-256 and JCS-canonicalized bundle manifest digests.
- **Understands** and extracts structured semantic profiles, strictly distinguishing explicitly declared metadata from inferred template variables.
- **Normalizes** entities into canonical LCS URNs (`urn:lcs:<entity_kind>:<namespace>:<identifier>`).
- **Indexes** artifacts for retrieval, providing an explicit compatibility strategy with existing frozen retrieval engines (`retrieval_v1` and `retrieval_v1_1`).
- **Terminates Lifecycle at `AVAILABLE`:** Discovery, profiling, and indexing operate entirely offline without requiring agent activation or task execution.

### 1.3 Strict Safety & Execution Invariants
- **Zero Arbitrary Code Execution:** Skill Intelligence V1 processes instructions and assets as passive data. It **never** executes skill scripts, runs shell commands, or spawns subprocesses.
- **Zero Tool / Network Calls:** Ingestion is entirely local and read-only.
- **Frozen Modules Respected:** The frozen modules (`capability_retrieval_v1.py`, `capability_retrieval_v1_1.py`, `capability_parameter_v1.py`, `capability_planning_v1.py`, and `governance_policy_v1.py`) remain completely untouched.

---

## 2. Artifact Taxonomy & Classification

To eliminate the flawed assumption that every Markdown prompt file is a "skill", LCS establishes a strict taxonomy that accounts for both valid and non-conforming artifacts.

```
+---------------------------------------------------------------------------------------------------+
|                                     LCS ARTIFACT TAXONOMY                                         |
+-------------------+-------------------+-------------------+-------------------+-------------------+
|       SKILL       |      COMMAND      |       RULE        | AGENT_INSTRUCTION |AGENT_CONFIGURATION|
+-------------------+-------------------+-------------------+-------------------+-------------------+
| Procedural        | Interactive slash | Ambient,          | Foundational      | Structural actor  |
| playbook bundle   | command macro     | persistent rule   | system prompt     | configuration     |
| (SKILL.md +       | template          | constraint        | guidance          | (roles, tools,    |
| scripts/assets)   | ($ARGUMENTS)      | (always active)   | (session init)    | subagent limits)  |
+-------------------+-------------------+-------------------+-------------------+-------------------+
| urn:lcs:skill:... |urn:lcs:command:...| urn:lcs:rule:...  |urn:lcs:instruct:..| urn:lcs:agent:... |
+-------------------+-------------------+-------------------+-------------------+-------------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
           [ UNKNOWN_ARTIFACT ]                              [ UNSUPPORTED_ARTIFACT ]
      Ambiguous structure or unverified               Non-instructional formats, raw code,
      format (sent to Quarantine)                     or binaries (excluded from indexing)
```

### 2.1 Formal Boundary Definitions

| Artifact Type | Primary Purpose | Invocation Mechanism | Input / Parameter Contract | Discovery Indicators |
|---|---|---|---|---|
| **`SKILL`** | Procedural methodology, domain playbook, multi-phase heuristic guide | On-demand by agent planner or explicit reference | Optional contextual requirements; references tools | Directory containing `SKILL.md` (YAML frontmatter + Markdown body) + optional `scripts/`, `references/` |
| **`COMMAND`** | Interactive user macro / slash shortcut | User typing `/<name>` or orchestrator dispatch | Freeform user arguments (`$ARGUMENTS`), positional flags | Single `.md` file in `commands/` directories (e.g. `~/.claude/commands/plan.md`) |
| **`RULE`** | Persistent behavioral constraint, coding standard, safety rule | Continuous ambient enforcement (always in context) | None (declarative guidelines and invariants) | `.md` files in `rules/`, `CLAUDE.md`, `.cursorrules`, `RULE[...]` tags |
| **`AGENT_INSTRUCTION`** | Persona baseline, system prompt injection | Injected at agent initialization | Contextual environment variables | Paths declared in `opencode.json` `"instructions": [...]` or prompt files |
| **`AGENT_CONFIGURATION`** | Definition of an autonomous actor (tools, permissions, limits) | Spawned as subagent or main orchestrator | Task brief, delegated inputs, tool grants | JSON object in `opencode.json` `"agent": {...}`, subagent yaml/json specs |
| **`UNKNOWN_ARTIFACT`** | Ambiguous candidate that fails formal syntax validation | None (quarantined) | None | Malformed YAML frontmatter, broken encoding, conflicting markers |
| **`UNSUPPORTED_ARTIFACT`** | File in search root that is not an instruction or config artifact | None (skipped) | None | Images, binaries, raw unannotated scripts, arbitrary data files |

> [!IMPORTANT]
> **No Forced Categorization Invariant:** An unsupported, unannotated, or ambiguous file is **never** forced into one of the five primary operational categories. If an artifact cannot be deterministically classified, it is marked `UNKNOWN_ARTIFACT` (and quarantined) or `UNSUPPORTED_ARTIFACT` (and skipped).

---

## 3. Dynamic Discovery Roots & Traversal Safety

### 3.1 Dynamic Root Whitelist (Zero Hardcoded Paths)
Discovery is strictly confined to an explicit whitelist of authorized root directories resolved dynamically at runtime:

```
+---------------------------------------------------------------------------------------------------+
|                               DYNAMIC DISCOVERY ROOT RESOLUTION                                   |
+---------------------------+-----------------------------------+-----------------------------------+
|         Category          |           Dynamic Resolution Rule          |      Target Sub-Paths     |
+---------------------------+-----------------------------------+-----------------------------------+
| Antigravity Global        | os.path.expanduser("~/.gemini/config/skills") | Direct SKILL.md bundles   |
| Antigravity Built-in      | os.path.expanduser("~/.gemini/antigravity/builtin/skills") | System core skills |
| Antigravity Plugins       | os.path.expanduser("~/.gemini/config/plugins") | */skills/*/SKILL.md       |
| Claude Code Global        | os.path.expanduser("~/.claude") | skills/, commands/, rules/        |
| Active Workspace          | os.path.realpath(ctx.config.root_dir) | .agents/skills/, .claude/, .opencode/ |
| Canonical LCS Root        | os.path.realpath(LCSConfig.resolve().root_dir) | Project root configurations |
+---------------------------+-----------------------------------+-----------------------------------+
```

- **Zero Machine-Specific Hardcoding:** Paths such as `/Users/pavan/...` are strictly prohibited in the codebase and configuration defaults. All user paths utilize `os.path.expanduser("~")`, and all workspace paths resolve via the runtime configuration engine (`LCSConfig.resolve()`).
- **Comprehensive Antigravity Coverage:** Explicitly incorporates all documented Antigravity paths:
  1. `~/.gemini/config/skills/` (user global skills)
  2. `~/.gemini/antigravity/builtin/skills/` (system built-in skills)
  3. `~/.gemini/config/plugins/*/skills/` (installed plugin skills)
  4. `<workspace_root>/.agents/skills/` (workspace-local skills)
  5. `<workspace_root>/.gemini/skills/` (workspace-local Gemini skills)

### 3.2 Filesystem Confinement & TOCTOU Defense
To prevent path traversal, symlink escapes, and Time-of-Check / Time-of-Use (TOCTOU) exploits:
1. **Canonical Root Confinement:**
   Every candidate path undergoes realpath resolution and is verified against authorized roots:
   $$\text{os.path.commonpath}([\text{os.path.realpath}(path), authorized\_root]) == authorized\_root$$
   Any path attempting to escape into system directories (`/etc`, `/usr`, `/var`, `~/.ssh`) triggers an immediate `SecurityViolation` and is dropped.
2. **Descriptor-Relative TOCTOU Defense:**
   Between directory walking and reading, an attacker or concurrent process could replace an authorized file or parent directory with a symlink.
   To eliminate this window:
   - File opening uses `os.open(resolved_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))`.
   - Immediately following `os.open`, `os.fstat(fd)` verifies:
     - The opened descriptor is a regular file (`stat.S_ISREG(st.st_mode)`).
     - The descriptor is NOT a FIFO, socket, device, or directory.
     - The file size does not exceed the size ceiling ($1\text{ MB}$ for text, $5\text{ MB}$ for assets).
   - Data is read directly from the verified file descriptor (`os.read`), neutralizing symlink replacement attacks.
3. **Traversal Bounds:** Maximum recursion depth of **5 levels** and symlink loop detection via a `visited_inodes: Set[Tuple[int, int]]` set tracking `(st_dev, st_ino)`.

---

## 4. CAS Storage, Bundle Manifest Hashing & Change Detection

### 4.1 Exact-Byte Preservation in CAS
LCS Content-Addressed Storage (`SecureCASStorageEngine`) guarantees byte-level fidelity:
- Files are ingested as raw binary streams (`open(path, 'rb')`).
- **Zero Text Normalization:** Line endings (`\r\n` vs `\n`), trailing whitespace, UTF-8 BOMs, and indentation are preserved exactly as written on disk.
- The SHA-256 digest of the exact byte stream forms the primary CAS address:
  $$\text{CAS Address} = \text{SHA-256}(\text{RawFileBytes})$$

### 4.2 Deterministic Bundle Manifest Digest
For skills containing auxiliary subdirectories (`scripts/`, `references/`, `examples/`, `resources/`), LCS calculates a **Deterministic Bundle Manifest Digest** (not an arbitrary Merkle tree, but a canonical, verifiable manifest digest):

```
                        [ Deterministic Bundle Manifest Digest ]
                             = SHA-256(JCS(ManifestPayload))
                                             |
            +--------------------------------+--------------------------------+
            |                                                                 |
            v                                                                 v
    [ Root SKILL.md ]                                              [ Sorted Asset Entries ]
   SHA-256(SKILL.md)                                            [ [rel_path_1, sha256_1],
                                                                  [rel_path_2, sha256_2], ... ]
```

**Algorithm:**
1. Collect all relative file paths within the skill bundle directory.
2. Sort relative paths lexicographically by UTF-8 bytes (`rel_path.encode('utf-8')`).
3. For each file, compute its CAS raw digest: `h_i = SHA-256(file_bytes)`.
4. Construct the canonical manifest dictionary:
   ```json
   {
     "assets": [
       {"path": "examples/sample.py", "sha256": "3a..."},
       {"path": "scripts/check.sh", "sha256": "9f..."}
     ],
     "root_file": {"path": "SKILL.md", "sha256": "4b..."},
     "schema_version": "lcs.skill.bundle.v1"
   }
   ```
5. Apply RFC 8785 JCS canonicalization to produce deterministic UTF-8 bytes.
6. Compute the manifest digest:
   $$\text{BundleDigest} = \text{SHA-256}(\text{canonical\_bytes})$$

### 4.3 Change Detection: Correctness Guarantees vs. Opportunistic Caching
To resolve the classical "unchanged-mtime" failure mode (where files are updated without updating `st_mtime` due to 1-second filesystem timestamp granularity, backup restores, git checkouts, or `touch -m` operations):
- **Authoritative Invariant:** **Cryptographic content hashing (SHA-256) is the sole authoritative proof of content identity.**
- **Cache Policy:**
  - `st_mtime` and `st_size` serve strictly as an *opportunistic pre-filter* to avoid disk reads during rapid background idle polling.
  - When an authoritative command is invoked (e.g. `lcs skill discover`, `lcs skill inspect`, or plan synthesis), LCS computes the SHA-256 digest of the file bytes.
  - If `st_mtime` is unchanged but computed SHA-256 differs from the stored CAS address, **content hash takes absolute precedence**. The change is detected, a new CAS blob is written, and the profile is regenerated.
  - This architecture explicitly documents that **guaranteed change detection is provided by SHA-256 byte comparison**, never by `st_mtime` alone.

---

## 5. Universal Skill Lifecycle (Terminating at AVAILABLE)

In Skill Intelligence V1, the lifecycle strictly terminates at `AVAILABLE`. Execution and task verification are explicitly assigned to future runtime engine milestones.

```
+---------------------------------------------------------------------------------------------------+
|                                  LCS SKILL LIFECYCLE (V1)                                         |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [ DISCOVERED ] ──> [ READ ] ──> [ UNDERSTOOD ] ──> [ INDEXED ] ──> [ AVAILABLE ]                 |
|        |               |               |                 |                 |                      |
|        v               v               v                 v                 |                      |
|  [ QUARANTINED / POLICY_BLOCKED / UNSUPPORTED ] <--------+                 |                      |
|  (Syntax errors, path traversal, file size limit, policy deny)             |                      |
|                                                                            |                      |
+----------------------------------------------------------------------------+----------------------+
                                                                             |
                                                  +--------------------------+
                                                  |  FUTURE RUNTIME MILESTONES (NON-V1)
                                                  v  (Requires Execution Engine)
                                          [ ACTIVATED ] ──> [ EXECUTING ] ──> [ VERIFIED ]
```

### 5.1 Stage Definitions & Transition Rules

1. **`DISCOVERED`:**
   - *Entry:* An authorized discovery scanner locates an artifact matching taxonomy criteria.
   - *Operations:* Record `source_path`, resolve symlinks, verify path containment within authorized roots, classify artifact taxonomy type (`SKILL`, `COMMAND`, `RULE`, `AGENT_INSTRUCTION`, `AGENT_CONFIGURATION`, `UNKNOWN_ARTIFACT`, `UNSUPPORTED_ARTIFACT`).
   - *State Persistence:* Insert into `artifact_discovery_records` with status `DISCOVERED`.

2. **`READ`:**
   - *Entry:* File size $\le$ 1MB, symlink safely verified via `O_NOFOLLOW` descriptor.
   - *Operations:* Ingest exact raw bytes into CAS (`cas_blobs`), compute `raw_content_digest`, compute Merkle `bundle_digest` for directory bundles.
   - *Failure:* If file cannot be read, contains invalid descriptors, or exceeds size limit, transition to `QUARANTINED`.

3. **`UNDERSTOOD`:**
   - *Entry:* Raw content digest stored in CAS.
   - *Operations:* Deterministic parser parses YAML frontmatter and Markdown AST. Generates structured `SkillSemanticProfile` distinguishing `EXPLICIT`, `EXTRACTED`, `INFERRED`, and `UNKNOWN` evidence.
   - *Failure:* If YAML is corrupt or file is not valid UTF-8, transition to `QUARANTINED` with error log.

4. **`INDEXED`:**
   - *Entry:* Semantic profile generated and stored in CAS.
   - *Operations:* Formulate canonical URN (`urn:lcs:<entity_kind>:<namespace>:<id>`). Populate search index with keywords, trigger conditions, name, and summary.
   - *State Persistence:* Entity registered in LCS capability catalog.

5. **`AVAILABLE`:**
   - *Entry:* Successfully indexed and passed static security review.
   - *Operations:* Evaluated against Governance Gate 1 trust policy (source origin whitelist, path restriction).
   - *Exit:* The artifact is now active in the catalog, visible to search queries, and eligible for multi-capability plan synthesis.

6. **Future Stages (Explicitly Non-V1):**
   - **`ACTIVATED`:** Injected into an LLM agent context window during task execution.
   - **`EXECUTING`:** The agent executes steps under the guidance of the skill.
   - **`VERIFIED`:** Post-execution verification confirming compliance with skill rules.

---

## 6. Deduplication & Context-Aware Precedence

### 6.1 Separation of Content CAS from Discovery Identity
A single skill may be installed in multiple locations (e.g. symlinked across `~/.agents/skills/`, `~/.claude/skills/`, and a local project workspace).
LCS decouples storage from discovery identity:
- **CAS Deduplication:** If five skill files share identical bytes, only **one** CAS blob exists in `cas_blobs`.
- **Distinct Discovery Records:** Each environment discovery retains its own independent record in `artifact_discovery_records`, preserving exact filesystem location, discovery timestamp, and environment origin.

### 6.2 Context-Aware Precedence Resolution
Rather than applying a single rigid universal override rule, precedence is resolved **dynamically based on the active query context**:

```
                           [ Active Query / Task Context ]
                                         |
         +-------------------------------+-------------------------------+
         |                                                               |
         v                                                               v
[ Workspace Context Active ]                                    [ Global Context Active ]
Precedence Order:                                               Precedence Order:
1. Active Workspace Artifacts (<workspace>/.agents/skills)      1. Active Host Environment
2. Active Host Environment (e.g. Claude Code if inside Claude)     (Claude Code vs Antigravity)
3. Other Discovered Global Environments                         2. User Global Artifacts
4. System Built-in Packages                                     3. System Built-in Packages
```

---

## 7. Parameter Extraction: Explicit vs. Inferred

A critical architectural requirement is distinguishing formal input parameters from informal prompt template placeholders.

```
                                  [ Parameter Parser ]
                                           |
         +---------------------------------+---------------------------------+
         |                                                                   |
         v                                                                   v
[ Formally Declared Parameters ]                                [ Inferred Template Placeholders ]
- Extracted from YAML frontmatter:                               - Extracted from Markdown text:
  parameters:                                                      $ARGUMENTS, ${target_dir},
    target: {type: string, required: true}                         {{filename}}, <input_path>
- EvidenceSource: EXPLICIT                                       - EvidenceSource: INFERRED
- Required status: As formally declared                          - Required status: ALWAYS OPTIONAL by default
- Binding: Formal schema validation                              - Binding: Soft context variable expansion
```

### 7.1 Classification Rules
1. **Explicit Parameters (`EvidenceSource.EXPLICIT`):**
   - Declared in YAML frontmatter under `parameters` or `inputs` dictionary.
   - Explicit `required: true/false` flags are respected.
   - Typed schema definitions (string, boolean, integer, path) are validated.
2. **Inferred Template Placeholders (`EvidenceSource.INFERRED`):**
   - Regular expression extraction of `$ARGUMENTS`, `$FILE`, `${var_name}`, `{{var_name}}`.
   - **Crucial Rule:** Placeholders are **never** automatically marked as mandatory user inputs. In slash commands and prompt templates, `$ARGUMENTS` is frequently an optional qualifier or empty invocation.
   - Inferred variables default to `required = False`, `param_type = "string"`, and are annotated with:
     `notes = "Inferred from template placeholder. Defaulted to optional."`

---

## 8. Retrieval Compatibility & Integration Strategy

### 8.1 Primary Codebase Inspection of Existing Retrieval
A direct inspection of the existing codebase reveals how retrieval operates:
1. **Frozen Engine Ingestion Mechanism:**
   Both `capability_retrieval_v1.py` (lines 310–332) and `capability_retrieval_v1_1.py` (lines 475–490) execute:
   ```python
   cur.execute("SELECT capability_urn FROM capability_declarations;")
   all_urns = [r[0] for r in cur.fetchall()]
   for urn in all_urns:
       profile = self.profile_service.get_profile(urn)
       scored = self._score_candidate(profile, processed)
   ```
2. **Profile Loading Mechanism:**
   `CapabilityProfileService.get_profile(urn)` reads from `capability_semantic_profiles`, loads the JSON blob from CAS, and constructs a `CapabilitySemanticProfile`.
3. **Scoring Function:**
   `_score_candidate` evaluates `profile.display_name.value`, `profile.description.value`, `profile.category.value`, and `profile.inputs`.

### 8.2 Architectural Compatibility Verdict & Dual-Track Integration
Based on this architectural reality:
- **Direct Capability Catalog Registration (Full V1/V1.1 Compatibility):**
  Because `SUPPORTED_ENTITY_KINDS` in `capability_registry_v2b.py` already includes `"skill"`, any skill registered in `capability_declarations` with an associated profile in `capability_semantic_profiles` is **automatically picked up, scored, and returned by both frozen retrieval engines** without modifying a single line of frozen code.
- **Dedicated Skill Retrieval Adapter (`UnifiedRetrievalCoordinator`):**
  While the frozen engines can score skills, they lack awareness of:
  - Artifact taxonomic filtering (e.g. `skills_only`, `commands_only`, `rules_only`).
  - Active workspace precedence overrides.
  - FTS5 trigger-phrase matching from `capability_fts`.
  
  Therefore, LCS implements a **Unified Retrieval Coordinator** (`UnifiedRetrievalCoordinator` in `lcs/retrieval.py`):
  - Wraps the frozen retrieval engine (`CapabilityRetrievalEngineV1` or `V1_1`) as an immutable delegate.
  - Queries `capability_fts` for trigger-phrase boosts.
  - Applies dynamic context-aware precedence filtering (Workspace > Global > Built-in).
  - Preserves 100% frozen module byte invariance.

---

## 9. Practical V1 Scope & Acceptance Criteria

### 9.1 In-Scope for V1
1. Multi-environment discovery across Google Antigravity, Claude Code, and OpenCode dynamically resolved roots.
2. Taxonomy classification: `SKILL`, `COMMAND`, `RULE`, `AGENT_INSTRUCTION`, `AGENT_CONFIGURATION`, `UNKNOWN_ARTIFACT`, `UNSUPPORTED_ARTIFACT`.
3. Exact-byte CAS storage and deterministic JCS bundle manifest digest calculation.
4. Content-hash-based change detection with SHA-256 correctness guarantees.
5. Semantic profiling with explicit vs. inferred parameter separation.
6. Safe descriptor-relative (`O_NOFOLLOW`) path confinement and quarantine isolation.
7. Retrieval integration via existing catalog registration and `UnifiedRetrievalCoordinator`.
8. Context-aware precedence resolution.
9. CLI commands: `lcs skill discover`, `lcs skill list`, `lcs skill inspect <urn>`, `lcs skill search <query>`.

### 9.2 Acceptance Criteria
1. **Taxonomic Separation:** Successfully classifies 100% of discovered artifacts into one of the 5 primary categories or flags them as `UNKNOWN` / `UNSUPPORTED`. Zero forced categorizations.
2. **Dynamic Root Discovery:** Discovers artifacts from dynamically resolved roots across Antigravity, Claude Code, and OpenCode without a single hardcoded machine path.
3. **Descriptor-Relative Safety:** Reads all files through verified file descriptors with `O_NOFOLLOW`, rejecting symlinks escaping authorized roots.
4. **CAS Integrity:** All ingested artifacts verify byte-for-byte against their CAS SHA-256 addresses; bundles produce deterministic JCS manifest digests.
5. **Parameter Invariance:** Inferred template variables (`$ARGUMENTS`, `${path}`) are never marked as mandatory inputs unless backed by explicit frontmatter declarations.
6. **Correctness Guarantee in Change Detection:** SHA-256 content comparison guarantees change detection regardless of `st_mtime` drift.
7. **Zero-Modification Retrieval:** Frozen retrieval engines return skills without any edits to `capability_retrieval_v1.py` or `capability_retrieval_v1_1.py`.
8. **Frozen Code Invariance:** Zero lines changed in frozen modules. Checksums remain identical.
9. **Full Regression Pass:** All 230 existing tests continue to pass 100% cleanly.
10. **Lifecycle Termination:** 100% of discovered artifacts terminate their lifecycle at `AVAILABLE` (or `QUARANTINED`); zero artifacts require execution to become available.

---

## 10. Change Summary, Unresolved Limitations & Implementation Verdict

### 10.1 Change Summary (Revision 1.2.0 vs 1.1.0)
1. **Discovery Root Whitelist:** Removed all hardcoded machine paths; dynamically resolves workspace and LCS root; added full Antigravity built-in and plugin paths.
2. **Retrieval Compatibility Documented with Code Evidence:** Proved that frozen retrieval engines query `capability_declarations` and `capability_semantic_profiles`, enabling direct retrieval plus an external `UnifiedRetrievalCoordinator` wrapper.
3. **Change Detection Guarantee:** Explicitly defined SHA-256 content hashing as the authoritative correctness guarantee, documenting `st_mtime` limitations.
4. **Unknown / Unsupported Classification:** Introduced `UNKNOWN_ARTIFACT` and `UNSUPPORTED_ARTIFACT` with strict rules against forced categorization.
5. **Bundle Manifest Digest & TOCTOU Defense:** Renamed bundle hash to deterministic manifest digest; specified `os.open` with `O_NOFOLLOW` and `fstat` descriptor checks.

### 10.2 Unresolved Technical Limitations
1. **Filesystem Cross-Platform `O_NOFOLLOW`:** Windows does not support `O_NOFOLLOW` on standard `open`; on Windows platforms, safe resolution will rely on `os.path.realpath` plus `fstat` re-verification.
2. **Dynamic NPM OpenCode Plugins:** Plugins that dynamically register tools via node runtime APIs (without local disk schemas or manifests) cannot be statically discovered in V1.

### 10.3 Final Implementation Readiness Verdict
$$\mathbf{VERDICT:}\quad \mathbf{READY}$$
The specification is complete, evidence-grounded, strictly scoped to V1 requirements, preserves all frozen milestones, and is ready for implementation upon user authorization.
