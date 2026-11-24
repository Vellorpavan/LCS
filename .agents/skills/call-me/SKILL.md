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

### Phase 1: Request Structured Plan
Request the structured DAG plan and execution waves from Call Me:
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me-plan "$*" --format-json || python3 -m lcs.cli call-me-plan "$*" --format-json
```
Parse the JSON response. Extract:
- `request_id`: Unique run identifier.
- `workspace_root`: Authorized workspace directory.
- `execution_waves`: Ordered topological stages `[[step_id, ...], ...]`.
- `dag_edges`: Dependency pairs `[[from_step, to_step], ...]`.
- `steps`: Dictionary of step specifications containing `capability_id`, `instructions`, `expected_deliverables`, and `verification_criteria`.

If planning fails or returns an error, stop immediately and report the failure.

### Phase 2: Closed-Loop Execution by Waves
Iterate through each wave in `execution_waves` sequentially:
1. For each step in the wave:
   - When native specialist agent dispatch is supported (`invoke_subagent`):
     - Dispatch the specialist subagent with:
       - `TypeName`: `"self"` (or appropriate specialist agent type)
       - `Role`: Domain specialist role (e.g., "Telemetry Service Specialist", "Code Quality Specialist")
       - `Prompt`: Hydrated `instructions` from the step, specifying:
         - Authorized workspace: `workspace_root`
         - Expected deliverables: `expected_deliverables`
         - Verification criteria: `verification_criteria`
         - Any artifacts or context produced by preceding waves
     - Await completion. If a specialist fails or reports errors, abort dependent downstream waves.
   - When native agent dispatch is unavailable:
     - Execute the hydrated instructions directly within the coordinator turn, strictly confined to `workspace_root` and producing the declared deliverables.
2. Every step must create or update real physical files in the workspace. An instruction handoff alone must not be marked as completed physical work.

### Phase 3: Deliverable & Test Verification Gate
Once all waves complete, invoke LCS's physical deliverable verification gate:
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me-verify "<request_id>" --workspace "<workspace_root>" --files <expected_files...> --commands "<verification_commands...>" || python3 -m lcs.cli call-me-verify "<request_id>" --workspace "<workspace_root>" --files <expected_files...> --commands "<verification_commands...>"
```
The verification gate strictly verifies:
- Path confinement (rejects directory traversal `..` and NTFS ADS streams).
- Physical file existence and non-emptiness (>0 bytes).
- Automated test command execution exits with code 0 under authorized test binaries.

### Phase 4: Truthful Outcome Reporting
- If the verification gate passes (`is_verified: true` and `state: VERIFIED`), report SUCCESS with the run ID, list of verified files, and test results.
- If verification fails (missing files, empty files, failed tests, or governance violations), report FAILURE with diagnostic evidence. Never report SUCCEEDED when verification has failed or deliverables are missing.
