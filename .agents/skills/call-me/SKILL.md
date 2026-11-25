---
name: call-me
description: Explicit entry point into the Living Capability System (LCS) universal multi-agent intelligence and capability orchestration engine.
category: orchestration
---
<!-- LCS-MANAGED-COMMAND-ARTIFACT -->

# /call-me — Call Me & Living Capability System Orchestrator

## Invocation Syntax
`/call-me <natural language task description>`

When the user invokes `/call-me <objective>`, execute the full closed-loop multi-agent orchestration protocol:

## Execution Modes
- **Autonomous Host Execution**: Invoking `/call-me` activates the multi-agent closed-loop orchestration protocol, requesting the structured plan and dispatching native specialist agents.
- **Standalone CLI Execution**: Running `lcs call-me --handoff` performs pre-flight retrieval, planning, and governance checks, outputting hydrated instructions for operator inspection.

## Orchestration Protocol

### Phase 1: Host-Assisted Semantic Reasoning & Structured Plan
Request the structured DAG plan and execution waves from Call Me:
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me-plan "$*" --format-json || python3 -m lcs.cli call-me-plan "$*" --format-json
```
Parse the JSON response. Extract:
- `request_id`: Unique run identifier.
- `workspace_root`: Authorized workspace directory.
- `semantic_reasoning`: Decomposed `requirements`, `selections` (with `agent_id`, `paired_skills`, `justification`), `rejected_candidates`, and `gaps`.
- `execution_waves`: Ordered topological stages `[[step_id, ...], ...]`.
- `dag_edges`: Dependency pairs `[[from_step, to_step], ...]`.
- `steps`: Step specifications containing `capability_urn`, `role`, `agent_id`, `paired_skills`, `instructions`, `expected_deliverables`, and `verification_criteria`.

If `semantic_reasoning.gaps` is non-empty, evaluate whether authorized discovery can acquire the missing capability or report the capability gap transparently. If planning fails or returns an error, stop immediately and report the failure.

### Phase 2: Closed-Loop Execution & Synchronized Adaptation by Waves
Iterate through each wave in `execution_waves` sequentially:
1. For each step in the wave:
   - When native specialist agent dispatch is supported (`invoke_subagent`):
     - Dispatch the specialist subagent using the selected `agent_id` / `role` and all `paired_skills`:
       - `TypeName`: `"self"`
       - `Role`: `step["agent_id"]` or `step["role"]`
       - `Prompt`: Hydrated `instructions` from the step + `paired_skills`, specifying:
         - Authorized workspace: `workspace_root`
         - Expected deliverables: `expected_deliverables`
         - Verification criteria: `verification_criteria`
         - Contract path: `.lcs/project_contract.json`
         - Any artifacts or context produced by preceding waves
     - Record the native `conversationId` as invocation evidence. If a specialist mutates a shared interface in `.lcs/project_contract.json`, check `get_stale_components()` and redispatch affected consumer specialists with `invocation_id` and `adaptation_evidence` before marking them `ACTIVE`.
   - When native agent dispatch is unavailable:
     - Execute the hydrated instructions directly within the coordinator turn, strictly confined to `workspace_root` and producing the declared deliverables.
2. Every step must create or update real physical files in the workspace. An instruction handoff alone must not be marked as completed physical work.

### Phase 3: Artifact & Functional Verification Gate
Once all waves complete, invoke LCS's closed-loop verification gate (which inherits mandatory plan deliverables, required test commands, and contract synchronization state):
```bash
command -v call-me >/dev/null 2>&1 && call-me verify "<request_id>" --workspace "<workspace_root>" --format-json || python3 -m lcs.cli call-me-verify "<request_id>" --workspace "<workspace_root>" --format-json
```
The verification gate strictly enforces:
- Path confinement (rejects directory traversal `..`, sibling prefix collisions, symlink escapes, and NTFS ADS streams).
- Physical file existence and non-emptiness (>0 bytes) with cryptographic SHA-256 digests (`artifact_verified`).
- Automated functional test command execution exiting with code 0 under authorized test binaries (`functional_verified`).
- Zero stale (`NEEDS_UPDATE`) contract components in `.lcs/project_contract.json`.

### Phase 4: Truthful Outcome Reporting
- If the verification gate passes (`is_verified: true` and `state: VERIFIED`), report SUCCESS with the run ID, list of verified files, and test results.
- If verification fails (missing files, empty files, failed tests, or governance violations), report FAILURE with diagnostic evidence. Never report SUCCEEDED when verification has failed or deliverables are missing.
