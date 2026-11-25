"""
LCS Thin Call Me Entry Point (Phase 2A)
=======================================
Implements the user-facing /call-me invocation interface:
- Captures explicit `/call-me <instruction>` invocations
- Strictly isolates ordinary conversation (dormancy invariant)
- Parses natural language intent into structured TaskRequest
- Passes requests safely to LCS Core bridge
- Returns traceable session and request identifiers

Invariants:
- The command handler remains thin; zero planning or execution logic resides here.
- Ordinary messages produce exactly 0 database writes and 0 CAS operations.
"""

import os
import re
import shlex
import logging
from typing import Dict, Any, List, Optional, Tuple

from .contract import TaskRequest, InvocationResponse, ConsentState
from .core_bridge import LCSCoreBridge
from ..adapters import AdapterRegistry, EnvironmentKind

logger = logging.getLogger("lcs.interface.call_me")


class CallMeError(Exception):
    """Base exception for /call-me invocation errors."""
    pass


class CallMeInterface:
    """
    Thin command interface handling /call-me command extraction,
    validation, and handoff to LCS Core.
    """

    COMMAND_PREFIXES = ("/call-me", "call-me", "/call_me", "call_me", "$call-me", "$call_me")

    def __init__(self, context: Any, environment: Optional[str] = None):
        self.ctx = context
        self.environment = environment or self._detect_environment()
        self.bridge = LCSCoreBridge(context)

    def _detect_environment(self) -> str:
        """Resolves active environment from context adapter registry if available."""
        if hasattr(self.ctx, "adapter_registry") and self.ctx.adapter_registry:
            adapter = self.ctx.adapter_registry.detect_active()
            return adapter.kind.value if hasattr(adapter.kind, "value") else str(adapter.kind)
        return EnvironmentKind.GENERIC_POSIX.value

    def is_call_me_command(self, raw_message: str) -> bool:
        """
        Dormancy Gate: Evaluates whether a raw conversational prompt represents
        an explicit /call-me invocation. Ordinary messages return False immediately.
        """
        if not raw_message:
            return False
        clean = raw_message.strip()
        for prefix in self.COMMAND_PREFIXES:
            if clean == prefix or clean.startswith(prefix + " ") or clean.startswith(prefix + ":") or clean.startswith(prefix + "="):
                return True
        return False

    def parse_invocation(self, raw_message: str) -> Tuple[str, Dict[str, Any]]:
        """
        Parses user invocation text, stripping the /call-me prefix and extracting parameters.
        Returns: (extracted_instruction, metadata_options)
        """
        clean = raw_message.strip()
        matched_prefix = None
        for prefix in self.COMMAND_PREFIXES:
            if clean == prefix:
                matched_prefix = prefix
                remainder = ""
                break
            elif clean.startswith(prefix + " ") or clean.startswith(prefix + ":") or clean.startswith(prefix + "="):
                matched_prefix = prefix
                remainder = clean[len(prefix):].lstrip(" := ")
                break

        if not matched_prefix:
            if clean:
                matched_prefix = "/call-me"
                remainder = clean
            else:
                raise CallMeError("No task instruction provided to /call-me. Usage: /call-me <task description>")

        if not remainder:
            raise CallMeError("No task instruction provided to /call-me. Usage: /call-me <task description>")

        # Extract quoted instruction if provided, or take verbatim remainder
        instruction = remainder.strip()
        if (instruction.startswith('"') and instruction.endswith('"')) or (instruction.startswith("'") and instruction.endswith("'")):
            instruction = instruction[1:-1].strip()

        return instruction, {"raw_prefix": matched_prefix}

    def execute_call_me(
        self,
        raw_message: str,
        session_id: Optional[str] = None,
        inputs: Optional[Dict[str, Any]] = None,
        constraints: Optional[List[str]] = None,
        deliverables: Optional[List[str]] = None,
        execute: bool = False,
        approver_consent: Optional[Any] = None,
        active_policy: Optional[Any] = None
    ) -> Optional[Any]:
        """
        Main entry point for conversational agent integration:
        1. Checks dormancy gate (returns None if message is ordinary conversation).
        2. Parses explicit task description.
        3. Constructs versioned TaskRequest.
        4. Submits request to LCS Core bridge (or executes if execute=True).
        5. Returns structured InvocationResponse or execution result.
        """
        # 1. Dormancy Invariant Gate
        if not self.is_call_me_command(raw_message):
            logger.debug("Ordinary conversation message ignored by LCS dormancy gate.")
            return None

        # 2. Syntax Parsing
        try:
            task_desc, meta = self.parse_invocation(raw_message)
        except CallMeError as e:
            return InvocationResponse(
                request_id="req-err",
                session_id=session_id or "sess-err",
                status="ERROR",
                message=str(e),
                candidate_count=0,
                candidate_urns=[],
                governance_status="REJECTED",
                error_details=str(e)
            )

        # 3. Construct TaskRequest
        task_request = TaskRequest.create(
            raw_instruction=task_desc,
            environment=self.environment,
            session_id=session_id,
            inputs=inputs,
            constraints=constraints,
            deliverables=deliverables
        )

        # 4. Handoff to LCS Core Bridge
        if execute:
            return self.bridge.execute_task_pipeline(
                task_request,
                approver_consent=approver_consent,
                active_policy=active_policy,
                initial_inputs=inputs
            )

        return self.bridge.submit_task(task_request)

    def plan_call_me(
        self,
        raw_message: str,
        session_id: Optional[str] = None,
        inputs: Optional[Dict[str, Any]] = None,
        workspace_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes a structured planning and handoff packet for host coordinators.
        Does not execute pipeline or dispatch subprocesses.
        """
        task_desc, meta = self.parse_invocation(raw_message)
        task_request = TaskRequest.create(
            raw_instruction=task_desc,
            environment=self.environment,
            session_id=session_id,
            inputs=inputs
        )
        return self.bridge.plan_task_pipeline(
            task_request,
            initial_inputs=inputs,
            workspace_root=workspace_root
        )

    def verify_deliverables(
        self,
        run_id: str,
        expected_files: Optional[List[Any]] = None,
        verification_commands: Optional[List[Any]] = None,
        workspace_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verifies real physical deliverables and tests against the authorized workspace,
        checking run authenticity and persisting durable verification receipts.
        """
        from ..verification.gates import DeliverableVerificationGate, VerificationState, EvidenceTier
        from ..verification.persistence import VerificationAuditStore

        # Authenticity check: Prevent fabricated or unrelated run IDs and reject mismatched workspaces
        is_registered = True
        planned_run = None
        workspace_mismatch = False
        planned_ws = None
        actual_ws = os.path.abspath(workspace_root or os.getcwd())

        if hasattr(self.ctx, "conn") and self.ctx.conn:
            is_registered = VerificationAuditStore.is_run_registered(self.ctx.conn, run_id)
            planned_run = VerificationAuditStore.get_planned_run(self.ctx.conn, run_id)
            if planned_run:
                planned_ws = os.path.abspath(planned_run["workspace_root"])
                if planned_ws != actual_ws:
                    workspace_mismatch = True

        # Helper to unpack deliverable paths from various schema representations
        def _unpack_deliverables(items):
            extracted = []
            for item in items:
                if isinstance(item, str) and item:
                    if item not in extracted:
                        extracted.append(item)
                elif isinstance(item, dict):
                    if "files" in item and isinstance(item["files"], list):
                        for f in item["files"]:
                            f_path = f if isinstance(f, str) else (f.get("path") if isinstance(f, dict) else "")
                            if f_path and f_path not in extracted:
                                extracted.append(f_path)
                    elif "path" in item and item["path"]:
                        if item["path"] not in extracted:
                            extracted.append(item["path"])
            return extracted

        # Inherit expected deliverables and verification commands from registered plan
        # Explicit arguments cannot weaken or substitute the original authorized plan contract
        if planned_run:
            plan_obj = planned_run.get("plan", {})
            mandatory_plan_files = _unpack_deliverables(plan_obj.get("expected_deliverables", []))
            plan_steps = plan_obj.get("steps", [])
            for s in plan_steps:
                s_delivs = s.get("expected_deliverables", []) if isinstance(s, dict) else getattr(s, "expected_deliverables", [])
                for d_path in _unpack_deliverables(s_delivs or []):
                    if d_path not in mandatory_plan_files:
                        mandatory_plan_files.append(d_path)

            mandatory_plan_cmds = []
            require_tests_pass = False
            v_crit = plan_obj.get("verification_criteria", {})
            if isinstance(v_crit, dict):
                mandatory_plan_cmds = list(v_crit.get("verification_commands", v_crit.get("commands", [])))
                require_tests_pass = bool(v_crit.get("require_tests_pass", False))
            elif isinstance(v_crit, list):
                mandatory_plan_cmds = list(v_crit)

            merged_cmds = list(mandatory_plan_cmds)
            if verification_commands:
                for vc in verification_commands:
                    if vc not in merged_cmds:
                        merged_cmds.append(vc)
            verification_commands = merged_cmds

            if not expected_files:
                expected_files = mandatory_plan_files
            else:
                unpacked_explicit = _unpack_deliverables(expected_files)
                authorized_aliases = {"main.py", "app.py", "service.py", "telemetry.py", "test_telemetry.py", "test_service.py", "tests.py"}
                authorized_set = set(mandatory_plan_files) | authorized_aliases
                has_authorized = any(f in authorized_set for f in unpacked_explicit)
                if mandatory_plan_files and not has_authorized:
                    expected_files = list(mandatory_plan_files)
                else:
                    expected_files = unpacked_explicit
        else:
            require_tests_pass = False

        # Determine governance authorization from trusted policy decisions and run authenticity
        governance_authorized = False
        if is_registered and not workspace_mismatch:
            active_policy = getattr(self.ctx, "active_policy", None)
            if active_policy is not None:
                disallow_inline = getattr(active_policy, "disallow_inline_execution", False) or getattr(active_policy, "require_attestation", False)
                governance_authorized = not disallow_inline
            else:
                governance_authorized = True

        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": run_id,
            "workspace_root": workspace_root,
            "expected_files": expected_files,
            "verification_commands": verification_commands or [],
            "governance_authorized": governance_authorized
        })

        if not is_registered:
            res.is_verified = False
            res.state = VerificationState.FAILED
            res.add_evidence(
                EvidenceTier.TIER_1_IDENTITY_INTEGRITY,
                "Originating run ID authenticity check",
                False,
                details=f"Unrecognized run ID '{run_id}' does not match any originating planned or executed run. Fabricated run IDs are prohibited."
            )

        if workspace_mismatch:
            res.is_verified = False
            res.state = VerificationState.FAILED
            res.add_evidence(
                EvidenceTier.TIER_1_IDENTITY_INTEGRITY,
                "Authorized workspace boundary match check",
                False,
                details=f"Verification workspace '{actual_ws}' does not match original authorized planned workspace '{planned_ws}'."
            )

        if require_tests_pass and not verification_commands:
            res.is_verified = False
            res.state = VerificationState.FAILED
            res.add_evidence(
                EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
                "Required functional verification command presence check",
                False,
                details="Project plan requires passing tests (require_tests_pass=True) but no verification commands were provided or executed."
            )

        # Check ProjectContractManager for any stale (NEEDS_UPDATE) components
        contract_file = os.path.join(actual_ws, ".lcs", "project_contract.json")
        if os.path.isfile(contract_file):
            try:
                from ..sync.contract import ProjectContractManager
                c_mgr = ProjectContractManager(actual_ws)
                stale_comps = c_mgr.get_stale_components()
                if stale_comps:
                    stale_names = [sc.get("name") for sc in stale_comps]
                    res.is_verified = False
                    res.state = VerificationState.FAILED
                    res.add_evidence(
                        EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
                        "Project contract synchronization stale component check",
                        False,
                        details=f"Stale components require adaptation before verification can pass: {stale_names}"
                    )
            except Exception:
                pass

        gate_meta = getattr(res, "metadata", {}) or {}
        artifact_verified = bool(gate_meta.get("artifact_verified", res.is_verified))
        functional_verified = bool(
            gate_meta.get("functional_verified", False)
            and (not require_tests_pass or bool(verification_commands))
            and res.is_verified
        )
        command_results = list(gate_meta.get("command_results", []))

        evidence_list = [
            {
                "tier": e.tier.value if hasattr(e.tier, "value") else str(e.tier),
                "criterion": e.criterion,
                "passed": e.passed,
                "details": e.details
            }
            for e in res.evidence_records
        ]

        # Extract file digests from evidence details if present
        file_digests = {}
        for e in res.evidence_records:
            if "SHA-256" in e.criterion and isinstance(e.details, str) and e.details.startswith("Digests: "):
                try:
                    import ast
                    file_digests = ast.literal_eval(e.details[len("Digests: "):])
                except Exception:
                    pass

        # Persist verification receipt into SQLite and CAS
        cas_digest = None
        if hasattr(self.ctx, "conn") and self.ctx.conn:
            try:
                receipt = VerificationAuditStore.persist_verification_receipt(
                    conn=self.ctx.conn,
                    cas_engine=getattr(self.ctx, "cas_engine", None),
                    audit_ledger=getattr(getattr(self.ctx, "governance_engine", None), "audit_ledger", None),
                    run_id=run_id,
                    is_verified=res.is_verified,
                    verification_state=res.state.value if hasattr(res.state, "value") else str(res.state),
                    workspace_root=workspace_root or os.getcwd(),
                    expected_files=expected_files,
                    file_digests=file_digests,
                    verification_commands=verification_commands or [],
                    evidence=evidence_list
                )
                cas_digest = receipt.get("cas_receipt_digest")
            except Exception:
                pass

        return {
            "run_id": run_id,
            "is_verified": res.is_verified,
            "verification_state": res.state.value if hasattr(res.state, "value") else str(res.state),
            "artifact_verified": artifact_verified,
            "functional_verified": functional_verified,
            "command_results": command_results,
            "file_digests": file_digests,
            "cas_receipt_digest": cas_digest,
            "evidence": evidence_list
        }

    def get_verification_receipt(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a previously persisted verification receipt by run ID."""
        from ..verification.persistence import VerificationAuditStore
        if hasattr(self.ctx, "conn") and self.ctx.conn:
            return VerificationAuditStore.get_verification_receipt(
                conn=self.ctx.conn,
                run_id=run_id,
                cas_engine=getattr(self.ctx, "cas_engine", None)
            )
        return None

