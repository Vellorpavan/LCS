"""
LCS Application Context
=======================
Central context managing initialized LCS storage, registry, policy, and discovery services.
"""

import os
import sqlite3
from typing import Optional
from .config import LCSConfig
from .adapters.codex import CodexAdapter
from .migrations import MigrationManager
from .storage import SecureCASStorageEngine
from .registry import CapabilityRegistrationService
from .policy import InterfacePolicyService
from .discovery import (
    DiscoveryIndexService,
    CapabilityDiscoveryPipeline
)
from .profile import CapabilityProfileService
from .retrieval import (
    CapabilityRetrievalEngine,
    CapabilityRetrievalEngineV1,
    CapabilityRetrievalEngineV11
)
from .parameter import ParameterUnderstandingEngineV1
from .planning import CapabilityPlanningEngineV1
from .governance import ExecutionGovernanceEngineV1
from .skills import SkillIntelligenceServiceV1, UnifiedRetrievalCoordinator
from .execution import ExecutionEngineV1
from .adapters import (
    AdapterRegistry,
    ActivationIntegrityVerifier,
    AntigravityAdapter,
    ClaudeCodeAdapter,
    OpenCodeAdapter,
    GenericPOSIXAdapter,
)
from .cache import (
    LocalCapabilityCache,
    FilesystemWatcher,
    DeltaEngine,
)
from .interface import (
    CallMeInterface,
    SlashCommandGenerator,
)
from .hydration import (
    HydrationEngine,
    HydratedCapability,
    ResourceUtilizationState,
    ProjectContextHydrator,
)
from .dependencies import (
    DependencyResolver,
    DependencyGraph,
)
from .verification import (
    UnifiedResourceVerifier,
    VerificationState,
)
from .subagents import (
    AntigravitySubagentBridge,
    SubagentTask,
)
from .inventory import (
    UnifiedCapabilityInventory,
    DeepCapabilityRetriever,
)


class LCSContext:
    """
    Unified context managing all Living Capability System subsystems.
    """

    def __init__(self, config: Optional[LCSConfig] = None, auto_migrate: bool = True):
        self.config = config or LCSConfig.resolve()
        self.config.ensure_directories()

        # Database and migrations
        self.migration_manager = MigrationManager(
            db_path=self.config.db_path,
            schema_dir=self.config.schema_dir
        )
        if auto_migrate:
            self.migration_manager.apply_pending()

        # SQLite Connection
        self.conn = self.migration_manager.get_connection()

        try:
            # Storage Engine
            self.cas_engine = SecureCASStorageEngine(
                cas_root=self.config.cas_root,
                trusted_anchor=self.config.root_dir,
                key_store_dir=self.config.key_store_dir
            )
            self.key_store = self.cas_engine.key_store

            # Core Services
            self.cap_service = CapabilityRegistrationService(self.conn, self.cas_engine)
            self.iface_service = InterfacePolicyService(self.conn, self.cas_engine, self.cap_service)
            self.index_service = DiscoveryIndexService(self.conn)
            self.profile_service = CapabilityProfileService(self.conn, self.cas_engine)

            # Unified Discovery Pipeline
            self.discovery_pipeline = CapabilityDiscoveryPipeline(
                conn=self.conn,
                cas_engine=self.cas_engine,
                cap_service=self.cap_service,
                iface_service=self.iface_service,
                index_service=self.index_service
            )

            # Capability Intelligence: Natural Language Retrieval Engines
            self.retrieval_engine_v1 = CapabilityRetrievalEngineV1(
                conn=self.conn,
                profile_service=self.profile_service,
                index_service=self.index_service,
                iface_service=self.iface_service
            )
            self.retrieval_engine_v11 = CapabilityRetrievalEngineV11(
                conn=self.conn,
                profile_service=self.profile_service,
                index_service=self.index_service,
                iface_service=self.iface_service
            )
            # Default retrieval engine points to V1.1
            self.retrieval_engine = self.retrieval_engine_v11

            # Capability Intelligence: Parameter Understanding Engine V1
            self.parameter_engine = ParameterUnderstandingEngineV1(
                conn=self.conn,
                profile_service=self.profile_service
            )

            # Capability Intelligence: Multi-Capability Planning Engine V1
            self.planning_engine = CapabilityPlanningEngineV1(
                conn=self.conn,
                profile_service=self.profile_service,
                retrieval_engine=self.retrieval_engine,
                parameter_engine=self.parameter_engine
            )

            # Execution Governance Engine V1
            self.governance_engine = ExecutionGovernanceEngineV1(
                conn=self.conn,
                cas_engine=self.cas_engine,
                iface_service=self.iface_service,
                profile_service=self.profile_service,
                key_store=self.cas_engine.key_store,
                audit_dir=os.path.join(self.config.root_dir, "audit")
            )

            # Skill Intelligence V1
            self.skill_service = SkillIntelligenceServiceV1(
                conn=self.conn,
                cas_engine=self.cas_engine,
                profile_service=self.profile_service,
                index_service=self.index_service,
                retrieval_engine=self.retrieval_engine,
                workspace_root=self.config.root_dir,
                iface_service=self.iface_service
            )
            self.retrieval_coordinator = self.skill_service.retrieval_coordinator

            # Environment Adapters & Live Verification
            self.activation_verifier = ActivationIntegrityVerifier(self.conn)
            discovery_root = self.config.root_dir
            if self.config.user_state_dir and os.path.realpath(self.config.root_dir) == os.path.realpath(self.config.user_state_dir):
                discovery_root = self.config.workspace_root or os.getcwd()
            elif os.path.basename(discovery_root) == ".lcs":
                discovery_root = os.path.dirname(discovery_root)
            self.adapter_registry = AdapterRegistry()
            self.adapter_registry.register(CodexAdapter(workspace_root=discovery_root))
            self.adapter_registry.register(AntigravityAdapter(workspace_root=discovery_root))
            self.adapter_registry.register(ClaudeCodeAdapter(workspace_root=discovery_root))
            self.adapter_registry.register(OpenCodeAdapter(workspace_root=discovery_root))
            self.adapter_registry.register(GenericPOSIXAdapter(workspace_root=discovery_root))

            # Dynamically load custom agent adapters from .lcs/agents and ~/.lcs/agents
            from .adapters.custom import DynamicAdapterLoader
            DynamicAdapterLoader.load_all(
                registry=self.adapter_registry,
                config=self.config,
                workspace_root=discovery_root
            )

            # Execution Engine V1
            self.execution_engine = ExecutionEngineV1(
                conn=self.conn,
                cas_engine=self.cas_engine,
                governance_engine=self.governance_engine,
                profile_service=self.profile_service,
                key_store=self.cas_engine.key_store,
                audit_ledger=self.governance_engine.audit_ledger,
                workspace_root=discovery_root
            )

            # High-Performance Local Cache & Filesystem Watcher (Phase 1C)
            self.cache = LocalCapabilityCache(
                conn=self.conn,
                cas_engine=self.cas_engine,
                resolver=self.skill_service.resolver,
                activation_verifier=self.activation_verifier
            )
            self.fs_watcher = FilesystemWatcher(
                roots=[self.config.root_dir],
                resolver=self.skill_service.resolver
            )
            # Prime in-memory cache from catalog
            self.cache.warm_cache()

            # Thin Call Me Entry Point (Phase 2A)
            self.call_me = CallMeInterface(self)
            self.command_generator = SlashCommandGenerator

            # Phase 2B: Full Capability Utilization & Execution Readiness
            self.hydration_engine = HydrationEngine(
                conn=self.conn,
                cas_engine=self.cas_engine,
                resolver=self.skill_service.resolver
            )
            self.project_context_hydrator = ProjectContextHydrator(self)
            self.dependency_resolver = DependencyResolver
            self.resource_verifier = UnifiedResourceVerifier
            self.subagent_bridge = AntigravitySubagentBridge(self)
            if hasattr(self, "execution_engine") and self.execution_engine:
                self.execution_engine.subagent_bridge = self.subagent_bridge

            # Unified Capability Inventory & Deep Capability Utilization (Milestone 1)
            self.inventory = UnifiedCapabilityInventory(
                conn=self.conn,
                cas_engine=self.cas_engine,
                workspace_root=discovery_root,
                iface_service=self.iface_service
            )
            self.deep_retriever = DeepCapabilityRetriever(
                inventory=self.inventory,
                policy_service=self.iface_service
            )
        except Exception:
            self.close()
            raise

    def get_active_adapter(self):
        """Resolves the active environment adapter for current workspace."""
        return self.adapter_registry.detect_active()

    def close(self) -> None:
        """Closes all active resources cleanly."""
        if hasattr(self, "fs_watcher") and self.fs_watcher and self.fs_watcher.is_active:
            try:
                self.fs_watcher.stop()
            except Exception:
                pass
        if hasattr(self, "execution_engine") and self.execution_engine:
            try:
                self.execution_engine.close()
            except Exception:
                pass
        if hasattr(self, "cas_engine") and self.cas_engine:
            try:
                self.cas_engine.close()
            except Exception:
                pass
        if hasattr(self, "conn") and self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

    def __enter__(self) -> "LCSContext":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

