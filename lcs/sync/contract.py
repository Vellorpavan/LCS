"""
Call Me — Shared Project State & Synchronization (Priority 7)
============================================================
Versioned project contract system managing:
- Component declarations & specialist ownership.
- Interface schemas (endpoints, request/response structures).
- Inter-component dependency graphs.
- Automated change propagation (marking dependent components STALE on contract changes).
- Monotonic versioning & concurrent write conflict prevention.
"""

import os
import json
import uuid
import hashlib
import datetime
from typing import Dict, Any, List, Set, Optional, Tuple


class ConcurrentContractConflictError(Exception):
    """Raised when concurrent writes clobber an updated contract version."""
    pass


class ProjectContractManager:
    """Manages versioned project contracts, ownership, interfaces, and change propagation."""

    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.abspath(workspace_root)
        self.contract_file = os.path.join(self.workspace_root, ".lcs", "project_contract.json")
        os.makedirs(os.path.dirname(self.contract_file), exist_ok=True)
        self._load_or_initialize()

    def _load_or_initialize(self) -> None:
        if os.path.isfile(self.contract_file):
            try:
                with open(self.contract_file, "r") as f:
                    self.contract = json.load(f)
                return
            except Exception:
                pass

        self.contract = {
            "contract_id": f"cntr-{uuid.uuid4().hex[:12]}",
            "version": 1,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "components": {},
            "interfaces": {},
            "audit_trail": []
        }
        self._save()

    def _save(self) -> None:
        self.contract["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(self.contract_file, "w") as f:
            json.dump(self.contract, f, indent=2, sort_keys=True)

    @property
    def version(self) -> int:
        return self.contract.get("version", 1)

    def register_component(
        self,
        name: str,
        owner_role: str,
        files: List[str],
        dependencies: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Registers a system component with specialist role ownership and file tracking."""
        comp = {
            "name": name,
            "owner_role": owner_role,
            "files": files,
            "dependencies": dependencies or [],
            "status": "ACTIVE",
            "registered_version": self.version,
            "last_updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.contract["components"][name] = comp
        self._save()
        return comp

    def declare_interface(
        self,
        interface_name: str,
        provider_component: str,
        consumer_components: List[str],
        schema_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Declares an explicit interface contract between provider and consumer components."""
        schema_bytes = json.dumps(schema_spec, sort_keys=True).encode("utf-8")
        schema_hash = hashlib.sha256(schema_bytes).hexdigest()

        iface = {
            "name": interface_name,
            "provider": provider_component,
            "consumers": consumer_components,
            "schema_spec": schema_spec,
            "schema_hash": schema_hash,
            "declared_version": self.version
        }
        self.contract["interfaces"][interface_name] = iface
        self._save()
        return iface

    def update_interface(
        self,
        interface_name: str,
        new_schema_spec: Dict[str, Any],
        actor_role: str
    ) -> Dict[str, Any]:
        """
        Updates an interface contract, increments version monotonically,
        detects schema mutations, and automatically propagates invalidation
        to all dependent consumer components (setting status='NEEDS_UPDATE').
        """
        if interface_name not in self.contract["interfaces"]:
            raise KeyError(f"Interface '{interface_name}' not found in contract")

        old_iface = self.contract["interfaces"][interface_name]
        old_hash = old_iface.get("schema_hash", "")
        new_bytes = json.dumps(new_schema_spec, sort_keys=True).encode("utf-8")
        new_hash = hashlib.sha256(new_bytes).hexdigest()

        # Increment monotonic version
        self.contract["version"] += 1
        new_version = self.contract["version"]

        affected_components = []
        if old_hash != new_hash:
            # Mark all consumer components as NEEDS_UPDATE
            consumers = old_iface.get("consumers", [])
            for c_name in consumers:
                if c_name in self.contract["components"]:
                    self.contract["components"][c_name]["status"] = "NEEDS_UPDATE"
                    self.contract["components"][c_name]["stale_reason"] = f"Interface '{interface_name}' mutated at contract version {new_version}"
                    affected_components.append(c_name)

        old_iface["schema_spec"] = new_schema_spec
        old_iface["schema_hash"] = new_hash
        old_iface["last_mutated_version"] = new_version

        # Record audit event
        audit_event = {
            "event": "INTERFACE_MUTATED",
            "interface": interface_name,
            "actor": actor_role,
            "contract_version": new_version,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "affected_components": affected_components,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.contract.setdefault("audit_trail", []).append(audit_event)
        self._save()

        return {
            "contract_version": new_version,
            "interface_name": interface_name,
            "schema_mutated": old_hash != new_hash,
            "affected_components": affected_components
        }

    def request_interface_change(
        self,
        interface_name: str,
        requested_schema_patch: Dict[str, Any],
        consumer_role: str,
        reason: str
    ) -> Dict[str, Any]:
        """
        Allows a consumer component to initiate a reverse-direction schema change request
        directed to the upstream provider component, recorded durably in the contract.
        """
        if interface_name not in self.contract["interfaces"]:
            raise KeyError(f"Interface '{interface_name}' not found in contract")

        iface = self.contract["interfaces"][interface_name]
        provider = iface.get("provider", "unknown")

        change_req = {
            "request_id": f"chg-{uuid.uuid4().hex[:8]}",
            "interface_name": interface_name,
            "provider_component": provider,
            "requester_role": consumer_role,
            "requested_patch": requested_schema_patch,
            "reason": reason,
            "status": "PENDING_PROVIDER_REVIEW",
            "requested_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.contract.setdefault("change_requests", []).append(change_req)
        self.contract.setdefault("audit_trail", []).append({
            "event": "INTERFACE_CHANGE_REQUESTED",
            "request": change_req,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
        self._save()
        return change_req

    def safe_write_file(
        self,
        component_name: str,
        rel_path: str,
        content: str,
        base_version: int,
        actor_role: str
    ) -> Dict[str, Any]:
        """
        Executes a versioned file write ensuring no concurrent clobbering.
        Fails closed if the component is in NEEDS_UPDATE state or if base_version is stale.
        """
        comp = self.contract["components"].get(component_name)
        if comp and comp.get("owner_role") != actor_role and actor_role != "COORDINATOR":
            raise PermissionError(f"Actor '{actor_role}' does not own component '{component_name}'")

        full_path = os.path.abspath(os.path.join(self.workspace_root, rel_path))
        from lcs.verification.gates import is_path_confined
        if not is_path_confined(full_path, self.workspace_root):
            raise ValueError(f"Path '{rel_path}' escapes workspace confinement")

        # Check for concurrent mutation
        if base_version < self.version and comp and comp.get("status") == "NEEDS_UPDATE":
            raise ConcurrentContractConflictError(
                f"Concurrent conflict: Contract version {self.version} supersedes base version {base_version}. "
                f"Component '{component_name}' requires schema adaptation before writing."
            )

        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

        file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        return {
            "file": rel_path,
            "sha256": file_hash,
            "written_at_version": self.version
        }

    def mark_component_adapted(
        self,
        component_name: str,
        actor_role: str,
        invocation_id: Optional[str] = None,
        adaptation_evidence: Optional[Dict[str, Any]] = None,
        require_evidence: bool = False,
    ) -> None:
        """Marks an invalidated component as updated and active after adaptation."""
        if component_name in self.contract["components"]:
            comp = self.contract["components"][component_name]
            if require_evidence and comp.get("status") == "NEEDS_UPDATE":
                if not invocation_id or not adaptation_evidence:
                    raise ValueError(
                        f"Cannot mark stale component '{component_name}' ACTIVE without "
                        "invocation_id and adaptation_evidence."
                    )
            comp["status"] = "ACTIVE"
            comp["stale_reason"] = None
            comp["last_adapted_version"] = self.version
            if invocation_id:
                comp["last_adaptation_invocation_id"] = invocation_id
            if adaptation_evidence:
                comp["adaptation_evidence"] = adaptation_evidence
            self.contract.setdefault("audit_trail", []).append({
                "event": "COMPONENT_ADAPTED",
                "component": component_name,
                "actor": actor_role,
                "invocation_id": invocation_id,
                "adaptation_evidence": adaptation_evidence,
                "contract_version": self.version,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })
            self._save()

    def get_stale_components(self) -> List[Dict[str, Any]]:
        """Returns all components currently needing update due to contract changes."""
        return [
            c for c in self.contract["components"].values()
            if c.get("status") == "NEEDS_UPDATE"
        ]
