"""
LCS Local Project Context Hydration Subsystem (Stage 3)
======================================================
Provides cross-agent context hydration, bounded selection, session continuity,
and strict project isolation when switching between compatible coding agents
working on the same project.

Guarantees:
- Strict POSIX isolation: Project A can never read or leak state from Project B.
- Bounded token selection with provenance tracking and no instruction summarization.
- Deterministic multi-agent detection and seamless handoff.
"""

import os
import re
import json
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from ..skills import SafeFileReader, MAX_INSTRUCTION_FILE_SIZE
from ..config import LCSConfig

logger = logging.getLogger("lcs.hydration.project_context")


class ProjectContextError(Exception):
    """Base error for project context operations."""
    pass


class ProjectIsolationViolationError(ProjectContextError):
    """Raised when a path or operation attempts to cross project workspace boundaries."""
    pass


@dataclass
class ContextItem:
    """An individual verified context item (rule, instruction, skill, or state)."""
    kind: str  # "SHARED_RULE", "HOST_INSTRUCTION", "WORKSPACE_SKILL", "SESSION_STATE"
    name: str
    relative_path: str
    content: str
    digest: str
    size_bytes: int
    estimated_tokens: int
    source_origin: str = "WORKSPACE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "relative_path": self.relative_path,
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "estimated_tokens": self.estimated_tokens,
            "source_origin": self.source_origin,
            "content": self.content
        }


@dataclass
class ProjectContextPayload:
    """
    Complete, bounded, provenance-preserving context transfer payload
    for cross-agent handoff on a project.
    """
    workspace_root: str
    active_host: str
    shared_rules: List[Dict[str, Any]] = field(default_factory=list)
    host_instructions: List[Dict[str, Any]] = field(default_factory=list)
    active_skills: List[Dict[str, Any]] = field(default_factory=list)
    session_id: Optional[str] = None
    session_state: Optional[Dict[str, Any]] = None
    total_estimated_tokens: int = 0
    token_budget: Optional[int] = None
    budget_exceeded: bool = False
    omitted_references: List[str] = field(default_factory=list)
    provenance_hashes: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace_root": self.workspace_root,
            "active_host": self.active_host,
            "shared_rules": self.shared_rules,
            "host_instructions": self.host_instructions,
            "active_skills": self.active_skills,
            "session_id": self.session_id,
            "session_state": self.session_state,
            "total_estimated_tokens": self.total_estimated_tokens,
            "token_budget": self.token_budget,
            "budget_exceeded": self.budget_exceeded,
            "omitted_references": self.omitted_references,
            "provenance_hashes": self.provenance_hashes,
            "created_at": self.created_at
        }


class ProjectContextHydrator:
    """
    Coordinates local-first context discovery, bounded selection,
    and cross-agent handoff within project boundaries.
    """

    SHARED_RULE_FILES = ("AGENTS.md", "CLAUDE.md", ".cursorrules", "RULES.md")
    SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")

    def __init__(self, context: Optional[Any] = None):
        self.ctx = context

    def estimate_tokens(self, text: str) -> int:
        """Estimates token count using standard 4-characters per token heuristic."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def verify_workspace_containment(self, target_path: str, workspace_root: str) -> str:
        """
        Enforces strict POSIX isolation: target_path must resolve strictly
        within workspace_root. Prevents directory traversal, symlink escape,
        and cross-project information leakage.
        """
        real_ws = os.path.realpath(workspace_root)
        real_target = os.path.realpath(target_path)

        if real_target != real_ws and not real_target.startswith(real_ws + os.sep):
            raise ProjectIsolationViolationError(
                f"Security Isolation Violation: Path '{target_path}' resolves to '{real_target}', "
                f"which is outside authorized workspace root '{real_ws}'."
            )
        return real_target

    def save_session_state(self, workspace_root: str, session_id: str, state_data: Dict[str, Any]) -> str:
        """
        Persists session continuity state for cross-agent switching on a project.
        Enforces strict session ID validation and project isolation.
        """
        if not self.SESSION_ID_PATTERN.match(session_id):
            raise ProjectContextError(
                f"Invalid session identifier '{session_id}'. Must be alphanumeric, dashes, dots, or underscores."
            )

        real_ws = os.path.realpath(workspace_root)
        if not os.path.isdir(real_ws):
            raise ProjectContextError(f"Workspace directory does not exist: '{workspace_root}'")

        sessions_dir = os.path.join(real_ws, ".lcs", "sessions")
        os.makedirs(sessions_dir, exist_ok=True)

        session_path = os.path.join(sessions_dir, f"{session_id}.json")
        self.verify_workspace_containment(session_path, real_ws)

        record = {
            "session_id": session_id,
            "workspace_root": real_ws,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "data": state_data
        }

        # Atomic write
        tmp_path = f"{session_path}.tmp.{os.getpid()}"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
            os.replace(tmp_path, session_path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        return session_path

    def load_session_state(self, workspace_root: str, session_id: str) -> Optional[Dict[str, Any]]:
        """Loads persistent session continuity state within workspace boundaries."""
        if not self.SESSION_ID_PATTERN.match(session_id):
            raise ProjectContextError(f"Invalid session identifier '{session_id}'")

        real_ws = os.path.realpath(workspace_root)
        session_path = os.path.join(real_ws, ".lcs", "sessions", f"{session_id}.json")

        if not os.path.isfile(session_path):
            return None

        self.verify_workspace_containment(session_path, real_ws)

        try:
            with open(session_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            return payload.get("data")
        except Exception as e:
            logger.warning(f"Failed to read session state '{session_path}': {e}")
            return None

    def hydrate_project_context(
        self,
        workspace_root: str,
        target_agent: Optional[str] = None,
        token_budget: Optional[int] = None,
        session_id: Optional[str] = None
    ) -> ProjectContextPayload:
        """
        Deep-hydrates the complete local project context for the active or target agent:
        1. Enforces workspace isolation.
        2. Detects the active or target host adapter deterministically.
        3. Ingests shared rules and host-specific instructions verbatim.
        4. Ingests workspace skills with provenance hashes.
        5. Loads session continuity state if available.
        6. Applies bounded token selection without truncating included instruction text.
        """
        real_ws = os.path.realpath(workspace_root)
        if not os.path.isdir(real_ws):
            raise ProjectContextError(f"Target workspace does not exist: '{workspace_root}'")

        # 1. Host resolution
        active_host = target_agent
        active_adapter = None
        if self.ctx and hasattr(self.ctx, "adapter_registry") and self.ctx.adapter_registry:
            if target_agent:
                active_adapter = self.ctx.adapter_registry.get(target_agent)
            if not active_adapter:
                active_adapter = self.ctx.adapter_registry.get_active_adapter(real_ws)
            if active_adapter:
                active_host = active_adapter.kind.value if hasattr(active_adapter.kind, "value") else str(active_adapter.kind)
        if not active_host:
            active_host = "generic_posix"

        # 2. Collect Context Candidates
        shared_rule_items: List[ContextItem] = []
        host_inst_items: List[ContextItem] = []
        skill_items: List[ContextItem] = []
        provenance_map: Dict[str, str] = {}

        # 2a. Shared project rules
        for rule_file in self.SHARED_RULE_FILES:
            rule_path = os.path.join(real_ws, rule_file)
            if os.path.isfile(rule_path):
                self.verify_workspace_containment(rule_path, real_ws)
                content_bytes, _ = SafeFileReader.read_exact_bytes(rule_path, MAX_INSTRUCTION_FILE_SIZE)
                digest = hashlib.sha256(content_bytes).hexdigest()
                text = content_bytes.decode("utf-8", errors="replace")
                tokens = self.estimate_tokens(text)
                rel_path = os.path.relpath(rule_path, real_ws)
                item = ContextItem(
                    kind="SHARED_RULE",
                    name=rule_file,
                    relative_path=rel_path,
                    content=text,
                    digest=digest,
                    size_bytes=len(content_bytes),
                    estimated_tokens=tokens
                )
                shared_rule_items.append(item)
                provenance_map[rel_path] = digest

        # 2b. Host-specific instructions
        if active_adapter:
            try:
                roots = active_adapter.discover_capability_roots(real_ws)
                for root in roots:
                    if root.origin != "WORKSPACE" and not root.root_path.startswith(real_ws):
                        continue
                    self.verify_workspace_containment(root.root_path, real_ws)
                    # Check instructions in root
                    if os.path.isfile(root.root_path):
                        content_bytes, _ = SafeFileReader.read_exact_bytes(root.root_path, MAX_INSTRUCTION_FILE_SIZE)
                        digest = hashlib.sha256(content_bytes).hexdigest()
                        text = content_bytes.decode("utf-8", errors="replace")
                        rel_path = os.path.relpath(root.root_path, real_ws)
                        item = ContextItem(
                            kind="HOST_INSTRUCTION",
                            name=os.path.basename(root.root_path),
                            relative_path=rel_path,
                            content=text,
                            digest=digest,
                            size_bytes=len(content_bytes),
                            estimated_tokens=self.estimate_tokens(text)
                        )
                        host_inst_items.append(item)
                        provenance_map[rel_path] = digest
            except Exception as e:
                logger.debug(f"Adapter capability root inspection warning: {e}")

        # 2c. Workspace skills
        skill_search_roots = [
            os.path.join(real_ws, ".agents", "skills"),
            os.path.join(real_ws, "skills"),
            os.path.join(real_ws, ".claude", "commands"),
            os.path.join(real_ws, ".opencode", "skills"),
        ]
        for s_root in skill_search_roots:
            if not os.path.isdir(s_root):
                continue
            self.verify_workspace_containment(s_root, real_ws)
            for entry in os.scandir(s_root):
                if entry.is_dir():
                    manifest = os.path.join(entry.path, "SKILL.md")
                    if os.path.isfile(manifest):
                        self.verify_workspace_containment(manifest, real_ws)
                        content_bytes, _ = SafeFileReader.read_exact_bytes(manifest, MAX_INSTRUCTION_FILE_SIZE)
                        digest = hashlib.sha256(content_bytes).hexdigest()
                        text = content_bytes.decode("utf-8", errors="replace")
                        rel_path = os.path.relpath(manifest, real_ws)
                        item = ContextItem(
                            kind="WORKSPACE_SKILL",
                            name=entry.name,
                            relative_path=rel_path,
                            content=text,
                            digest=digest,
                            size_bytes=len(content_bytes),
                            estimated_tokens=self.estimate_tokens(text)
                        )
                        skill_items.append(item)
                        provenance_map[rel_path] = digest
                elif entry.is_file() and entry.name.endswith(".md"):
                    content_bytes, _ = SafeFileReader.read_exact_bytes(entry.path, MAX_INSTRUCTION_FILE_SIZE)
                    digest = hashlib.sha256(content_bytes).hexdigest()
                    text = content_bytes.decode("utf-8", errors="replace")
                    rel_path = os.path.relpath(entry.path, real_ws)
                    item = ContextItem(
                        kind="WORKSPACE_SKILL",
                        name=entry.name.removesuffix(".md"),
                        relative_path=rel_path,
                        content=text,
                        digest=digest,
                        size_bytes=len(content_bytes),
                        estimated_tokens=self.estimate_tokens(text)
                    )
                    skill_items.append(item)
                    provenance_map[rel_path] = digest

        # 2d. Session continuity
        session_data = None
        if session_id:
            session_data = self.load_session_state(real_ws, session_id)

        # 3. Bounded Token Selection
        # Priority order: Host Instructions -> Shared Rules -> Session State -> Workspace Skills
        accumulated_tokens = 0
        budget_exceeded = False
        omitted_refs: List[str] = []

        final_host_inst: List[Dict[str, Any]] = []
        final_shared_rules: List[Dict[str, Any]] = []
        final_skills: List[Dict[str, Any]] = []

        # Add Host Instructions
        for item in host_inst_items:
            if token_budget is not None and (accumulated_tokens + item.estimated_tokens) > token_budget:
                budget_exceeded = True
                omitted_refs.append(f"host_instruction:{item.name} ({item.relative_path})")
            else:
                accumulated_tokens += item.estimated_tokens
                final_host_inst.append(item.to_dict())

        # Add Shared Rules
        for item in shared_rule_items:
            if token_budget is not None and (accumulated_tokens + item.estimated_tokens) > token_budget:
                budget_exceeded = True
                omitted_refs.append(f"shared_rule:{item.name} ({item.relative_path})")
            else:
                accumulated_tokens += item.estimated_tokens
                final_shared_rules.append(item.to_dict())

        # Account for Session State tokens
        if session_data:
            sess_str = json.dumps(session_data)
            sess_tokens = self.estimate_tokens(sess_str)
            if token_budget is not None and (accumulated_tokens + sess_tokens) > token_budget:
                budget_exceeded = True
                omitted_refs.append(f"session_state:{session_id}")
                session_data = {"status": "OMITTED_DUE_TO_TOKEN_BUDGET", "session_id": session_id}
            else:
                accumulated_tokens += sess_tokens

        # Add Workspace Skills
        for item in skill_items:
            if token_budget is not None and (accumulated_tokens + item.estimated_tokens) > token_budget:
                budget_exceeded = True
                omitted_refs.append(f"skill:{item.name} ({item.relative_path})")
            else:
                accumulated_tokens += item.estimated_tokens
                final_skills.append(item.to_dict())

        return ProjectContextPayload(
            workspace_root=real_ws,
            active_host=active_host,
            shared_rules=final_shared_rules,
            host_instructions=final_host_inst,
            active_skills=final_skills,
            session_id=session_id,
            session_state=session_data,
            total_estimated_tokens=accumulated_tokens,
            token_budget=token_budget,
            budget_exceeded=budget_exceeded,
            omitted_references=omitted_refs,
            provenance_hashes=provenance_map
        )
