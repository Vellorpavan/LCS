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

    COMMAND_PREFIXES = ("/call-me", "call-me", "/call_me", "call_me")

    def __init__(self, context: Any, environment: Optional[str] = None):
        self.ctx = context
        self.environment = environment or self._detect_environment()
        self.bridge = LCSCoreBridge(context)

    def _detect_environment(self) -> str:
        """Resolves active environment from context adapter registry if available."""
        if hasattr(self.ctx, "adapter_registry") and self.ctx.adapter_registry:
            adapter = self.ctx.adapter_registry.detect_active()
            return adapter.kind.value
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
            raise CallMeError(f"Message does not start with an authorized /call-me prefix: '{raw_message[:30]}...'")

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
        deliverables: Optional[List[str]] = None
    ) -> Optional[InvocationResponse]:
        """
        Main entry point for conversational agent integration:
        1. Checks dormancy gate (returns None if message is ordinary conversation).
        2. Parses explicit task description.
        3. Constructs versioned TaskRequest.
        4. Submits request to LCS Core bridge.
        5. Returns structured InvocationResponse.
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
        return self.bridge.submit_task(task_request)
