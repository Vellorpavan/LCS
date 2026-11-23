"""
LCS Antigravity Subagent Coordination Bridge (Phase 2B)
======================================================
Coordinates governed subagent task delegation, state tracking, and output verification
under feature flag gating and honest environment capability verification.
"""

import os
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable

from ..adapters.base import AdapterFeature, EnvironmentKind
from .models import SubagentTask, SubagentTaskState, SubagentExecutionResult
from ..verification.gates import AgentVerificationGate

logger = logging.getLogger("lcs.subagents.bridge")


class SubagentBridgeError(Exception):
    """Base exception for subagent coordination failures."""
    pass


class UnsupportedSubagentEnvironmentError(SubagentBridgeError):
    """Raised when delegation is requested on a host environment lacking AGENT_DELEGATION."""
    pass


class SubagentTimeoutError(SubagentBridgeError):
    """Raised when a subagent task exceeds its declared timeout."""
    pass


class AntigravitySubagentBridge:
    """
    Coordinates parent-child subagent delegation with structured request handoff,
    state progression tracking, and multi-tier deliverable verification.
    """

    def __init__(self, context: Any, feature_flag: Optional[bool] = None):
        self.ctx = context
        # Feature flag check
        if feature_flag is not None:
            self.enabled = feature_flag
        else:
            self.enabled = os.environ.get("LCS_ENABLE_SUBAGENT_BRIDGE", "true").lower() in ("1", "true", "yes")

        self.tasks: Dict[str, SubagentTask] = {}
        self.results: Dict[str, SubagentExecutionResult] = {}
        self.verifier = AgentVerificationGate()

    def is_delegation_supported(self) -> bool:
        """Evaluates whether current adapter genuinely supports subagent delegation."""
        if not self.enabled:
            return False
        if hasattr(self.ctx, "get_active_adapter"):
            adapter = self.ctx.get_active_adapter()
            if adapter and adapter.has_feature(AdapterFeature.AGENT_DELEGATION):
                return True
        return False

    def create_task(
        self,
        parent_request_id: str,
        role: str,
        objective: str,
        inputs: Optional[Dict[str, Any]] = None,
        constraints: Optional[List[str]] = None,
        expected_deliverables: Optional[List[str]] = None,
        timeout_seconds: int = 300
    ) -> SubagentTask:
        """Creates and tracks a new structured subagent task."""
        child_id = f"subtask-{uuid.uuid4().hex[:10]}"
        task = SubagentTask(
            parent_request_id=parent_request_id,
            child_task_id=child_id,
            role=role,
            objective=objective,
            inputs=inputs or {},
            constraints=constraints or [],
            expected_deliverables=expected_deliverables or [],
            timeout_seconds=timeout_seconds
        )
        self.tasks[child_id] = task
        return task

    def dispatch_task(
        self,
        task: SubagentTask,
        executor_fn: Optional[Callable[[SubagentTask], Dict[str, Any]]] = None
    ) -> SubagentExecutionResult:
        """
        Dispatches structured task to child agent and verifies returned outputs.
        Fails safely if host environment lacks genuine delegation capability.
        """
        # 1. Environment Capability Verification
        if not self.is_delegation_supported():
            adapter_name = "UNKNOWN"
            if hasattr(self.ctx, "get_active_adapter") and self.ctx.get_active_adapter():
                adapter_name = self.ctx.get_active_adapter().environment_kind.value

            err_msg = f"Host environment '{adapter_name}' does not support subagent delegation."
            logger.warning(err_msg)
            res = SubagentExecutionResult(
                child_task_id=task.child_task_id,
                parent_request_id=task.parent_request_id,
                state=SubagentTaskState.FAILED,
                error_details=err_msg,
                is_verified=False
            )
            self.results[task.child_task_id] = res
            return res

        # 2. Execution Start
        start_time = time.perf_counter()
        adapter = self.ctx.get_active_adapter()

        # Spawn subagent handle via adapter
        try:
            handle = adapter.spawn_subagent(
                role=task.role,
                initial_prompt=task.objective,
                timeout_seconds=task.timeout_seconds
            )
        except Exception as e:
            err_msg = f"Failed to spawn subagent handle: {e}"
            logger.error(err_msg)
            res = SubagentExecutionResult(
                child_task_id=task.child_task_id,
                parent_request_id=task.parent_request_id,
                state=SubagentTaskState.FAILED,
                error_details=err_msg,
                is_verified=False
            )
            self.results[task.child_task_id] = res
            return res

        # 3. Execution
        deliverables: Dict[str, Any] = {}
        stdout_summary = ""
        task_state = SubagentTaskState.RUNNING

        iter_count = task.inputs.get("iteration_count", 1) if isinstance(task.inputs, dict) else 1
        max_iters = task.inputs.get("max_iterations", 50) if isinstance(task.inputs, dict) else 50
        if iter_count > max_iters:
            res = SubagentExecutionResult(
                child_task_id=task.child_task_id,
                parent_request_id=task.parent_request_id,
                state=SubagentTaskState.FAILED,
                error_details=f"Transcript loop bounds exceeded: {iter_count} > {max_iters} turns",
                is_verified=False
            )
            self.results[task.child_task_id] = res
            return res

        try:
            if executor_fn:
                exec_output = executor_fn(task)
                deliverables = exec_output.get("deliverables", {})
                stdout_summary = exec_output.get("stdout", "Completed successfully")
                task_state = SubagentTaskState.COMPLETED
            elif hasattr(adapter, "wait_subagent"):
                wait_res = adapter.wait_subagent(handle)
                if wait_res.get("status") in ("COMPLETED", "SUCCESS", "DONE"):
                    task_state = SubagentTaskState.COMPLETED
                    deliverables = wait_res.get("deliverables", {})
                    stdout_summary = wait_res.get("stdout", "Completed successfully")
                else:
                    task_state = SubagentTaskState.FAILED
                    stdout_summary = wait_res.get("error", "Subagent execution failed")
            else:
                deliverables = {"status": "dispatched", "subagent_id": handle.subagent_id}
                stdout_summary = f"Subagent {handle.subagent_id} dispatched with role {task.role}"
                task_state = SubagentTaskState.COMPLETED

        except TimeoutError as te:
            task_state = SubagentTaskState.TIMEOUT
            stdout_summary = f"Subagent execution timed out after {task.timeout_seconds}s"
        except Exception as ex:
            task_state = SubagentTaskState.FAILED
            stdout_summary = f"Subagent execution failed: {ex}"

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # 4. Deliverable & Output Verification
        is_verified = False
        error_details = None

        if task_state == SubagentTaskState.COMPLETED:
            # Check expected deliverables
            missing_deliv = [d for d in task.expected_deliverables if d not in deliverables and not os.path.exists(d)]
            if missing_deliv:
                task_state = SubagentTaskState.FAILED
                error_details = f"Missing declared deliverables from subagent: {missing_deliv}"
            else:
                # Audit verification gate
                v_ctx = {
                    "resource_id": task.child_task_id,
                    "status": "COMPLETED",
                    "iteration_count": iter_count,
                    "max_iterations": max_iters,
                }
                deliv_file = next((d for d in task.expected_deliverables if isinstance(d, str) and os.path.exists(d)), None)
                if deliv_file:
                    v_ctx["deliverable_file"] = deliv_file
                v_res = self.verifier.verify(v_ctx)
                is_verified = v_res.is_verified
                if not is_verified:
                    error_details = v_res.error_details
        else:
            error_details = stdout_summary

        res = SubagentExecutionResult(
            child_task_id=task.child_task_id,
            parent_request_id=task.parent_request_id,
            state=task_state,
            deliverables=deliverables,
            stdout_summary=stdout_summary,
            duration_ms=duration_ms,
            provenance={
                "environment": adapter.environment_kind.value if adapter else "UNKNOWN",
                "role": task.role,
                "timeout_seconds": task.timeout_seconds,
                "subagent_id": getattr(handle, "subagent_id", None)
            },
            is_verified=is_verified,
            error_details=error_details
        )
        self.results[task.child_task_id] = res
        return res
