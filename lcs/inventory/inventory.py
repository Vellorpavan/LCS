"""
LCS Unified Capability Inventory Service
========================================
Implements the central, multi-host, cross-paradigm capability inventory.

Core Responsibilities:
1. Cross-Host Discovery: Scans and normalizes Agents, Skills, Tools, MCP Servers,
   Commands, Scripts, Workflows, Rules, Templates, and References.
2. Precedence & Conflict Management: Strict tier resolution (WORKSPACE > HOST > USER_GLOBAL > BUILTIN)
   with explicit version conflict tracking.
3. Operational Health: Probes reachability, connectivity, and executable status.
4. Storage Parity: Integrates seamlessly with existing SQLite artifact records and CAS storage.
"""

import os
import re
import json
import logging
import hashlib
import datetime
from typing import Dict, Any, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None

from .models import (
    ResourceType,
    OperationalLifecycleState,
    ExecutionRequirement,
    ProvenanceRecord,
    UnifiedResourceRecord,
    ConflictRecord,
)
from ..adapters.base import OperationalStatus, EnvironmentKind, CapabilityRoot
from ..adapters.probes import LiveProbeEngine
from ..skills import SafeFileReader, MAX_INSTRUCTION_FILE_SIZE

logger = logging.getLogger("lcs.inventory")

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't",
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by",
    "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't",
    "down", "during", "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't", "have",
    "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here", "here's", "hers", "herself", "him",
    "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't",
    "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself", "no", "nor",
    "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out",
    "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so", "some",
    "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there",
    "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through", "to",
    "too", "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were",
    "weren't", "what", "what's", "when", "when's", "where", "where's", "which", "while", "who", "who's",
    "whom", "why", "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're",
    "you've", "your", "yours", "yourself", "yourselves"
}

PREF_ORDER = {
    "WORKSPACE": 0,
    "HOST": 1,
    "USER_GLOBAL": 2,
    "BUILTIN": 3
}


def _canonical_entity_kind(rtype: ResourceType) -> str:
    if rtype in (ResourceType.TOOL, ResourceType.MCP_TOOL, ResourceType.MCP_SERVER):
        return "tool"
    elif rtype == ResourceType.AGENT:
        return "agent"
    return "skill"


def _canonical_identifier(name: str) -> str:
    ident = re.sub(r'[^a-z0-9-]+', '-', name.lower().replace('_', '-')).strip('-')
    return ident or "unnamed"


class UnifiedCapabilityInventory:
    """
    Authoritative registry and discovery engine for all capability resources.
    """

    def __init__(
        self,
        conn: Any,
        cas_engine: Optional[Any] = None,
        workspace_root: Optional[str] = None,
        iface_service: Optional[Any] = None
    ):
        self.conn = conn
        self.cas_engine = cas_engine
        self.workspace_root = os.path.realpath(workspace_root or os.getcwd())
        self.iface_service = iface_service
        self._inventory: Dict[str, UnifiedResourceRecord] = {}
        self._conflicts: List[ConflictRecord] = []
        self._initialized = False

    @property
    def total_count(self) -> int:
        return len(self._inventory)

    def initialize_environment(self, adapters: Optional[List[Any]] = None) -> Dict[str, int]:
        """
        Discovers all available capabilities across active host adapters and SQLite tables.
        Returns a breakdown of discovered resources by ResourceType.
        """
        self._inventory.clear()
        self._conflicts.clear()

        # 1. Ingest existing records from SQLite catalog
        self._load_from_sqlite_catalog()

        # 1b. Ingest packaged starter skills if available
        starter_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "starter_skills"))
        if os.path.isdir(starter_dir):
            starter_root = CapabilityRoot(
                root_path=starter_dir,
                precedence_tier="SYSTEM",
                origin="system",
                is_writable=False
            )
            self._scan_capability_root(starter_root, "system")

        # 2. Ingest from Host Adapters if provided
        if adapters:
            for adapter in adapters:
                try:
                    self._discover_from_adapter(adapter)
                except Exception as e:
                    logger.warning(f"Error discovering from adapter {getattr(adapter, 'adapter_id', 'unknown')}: {e}")

        # 3. Perform live reachability probes and dependency completeness checks
        self._evaluate_operational_states()

        self._initialized = True
        return self.get_inventory_summary()

    def get_by_urn(self, urn: str) -> Optional[UnifiedResourceRecord]:
        return self._inventory.get(urn)

    def list_all(
        self,
        resource_type: Optional[ResourceType] = None,
        lifecycle_state: Optional[OperationalLifecycleState] = None
    ) -> List[UnifiedResourceRecord]:
        results = list(self._inventory.values())
        if resource_type:
            results = [r for r in results if r.resource_type == resource_type]
        if lifecycle_state:
            results = [r for r in results if r.lifecycle_state == lifecycle_state]
        return results

    def _score_record(self, record: UnifiedResourceRecord, clean_q: str, query_tokens: List[str]) -> float:
        """Computes query relevance score with precedence and operational health boosts."""
        score = 0.0
        r_name = record.name.lower()
        r_display = record.display_name.lower()
        r_desc = record.description.lower()

        # Exact query matches
        if clean_q == r_name:
            score += 100.0
        elif clean_q in r_name and len(clean_q) >= 4:
            score += 50.0

        if clean_q == r_display:
            score += 60.0
        elif clean_q in r_display and len(clean_q) >= 4:
            score += 30.0

        if clean_q in r_desc and len(clean_q) >= 5:
            score += 20.0

        # Word boundary token matching
        r_name_words = set(re.split(r'[^a-zA-Z0-9_\-]+', r_name)) | set(re.split(r'[^a-zA-Z0-9]+', r_name))
        r_display_words = set(re.split(r'[^a-zA-Z0-9_\-]+', r_display)) | set(re.split(r'[^a-zA-Z0-9]+', r_display))
        r_desc_words = set(re.split(r'[^a-zA-Z0-9_\-]+', r_desc)) | set(re.split(r'[^a-zA-Z0-9]+', r_desc))

        for token in query_tokens:
            token_variants = {token}
            if token.endswith("s") and len(token) > 3:
                token_variants.add(token[:-1])
            if token.endswith("ing") and len(token) > 5:
                token_variants.add(token[:-3])
            if token.endswith("ed") and len(token) > 4:
                token_variants.add(token[:-2])

            if any(v in r_name_words or any(v in w for w in r_name_words if len(v) >= 4) for v in token_variants):
                score += 20.0
            if any(v in r_display_words or any(v in w for w in r_display_words if len(v) >= 4) for v in token_variants):
                score += 15.0
            if any(v in r_desc_words for v in token_variants):
                score += 10.0
            if any(any(v == tag.lower() for tag in record.tags) for v in token_variants):
                score += 15.0
            elif any(any(v in tag.lower() for tag in record.tags if len(v) >= 4) for v in token_variants):
                score += 8.0

        # Precedence boost
        tier = record.provenance.precedence_tier
        if tier == "WORKSPACE":
            score *= 1.2
        elif tier == "HOST":
            score *= 1.1

        # Operational health boost
        if record.lifecycle_state in (OperationalLifecycleState.EXECUTABLE, OperationalLifecycleState.AUTHORIZED):
            score *= 1.1
        elif record.lifecycle_state in (OperationalLifecycleState.UNAVAILABLE, OperationalLifecycleState.BLOCKED):
            score *= 0.5

        return score

    def search(
        self,
        query: str,
        limit: int = 10,
        resource_types: Optional[List[ResourceType]] = None
    ) -> List[UnifiedResourceRecord]:
        """
        Performs ranked query matching across name, display_name, description, tags, and content.
        Disallows self-referential call-me selection, supports multi-intent decomposition,
        and enforces a minimum relevance threshold.
        """
        clean_q = query.strip().lower()
        if not clean_q:
            return list(self._inventory.values())[:limit]

        # Multi-intent decomposition (e.g. "extract data and generate report")
        sub_intents = [s.strip() for s in re.split(r'\b(?:and|then|followed by|after that)\b|[,;&]', clean_q) if len(s.strip()) > 3]
        if len(sub_intents) > 1:
            selected_urns = set()
            multi_results = []
            for sub in sub_intents:
                sub_scored = []
                sub_tokens = [t for t in re.split(r'[^a-zA-Z0-9_\-]+', sub) if len(t) > 2 and t not in STOPWORDS]
                if not sub_tokens:
                    continue
                for record in self._inventory.values():
                    if record.name.lower() in ("call-me", "call_me") or record.urn.lower().endswith((":call-me", ":call_me")):
                        continue
                    if resource_types and record.resource_type not in resource_types:
                        continue
                    s = self._score_record(record, sub, sub_tokens)
                    if s >= 10.0:
                        sub_scored.append((s, record))
                sub_scored.sort(key=lambda x: x[0], reverse=True)
                for _, rec in sub_scored[:2]:
                    if rec.urn not in selected_urns:
                        selected_urns.add(rec.urn)
                        multi_results.append(rec)
            if multi_results:
                return multi_results[:limit]

        query_tokens = [t for t in re.split(r'[^a-zA-Z0-9_\-]+', clean_q) if len(t) > 2 and t not in STOPWORDS]
        if not query_tokens:
            return []

        scored_records: List[Tuple[float, UnifiedResourceRecord]] = []

        for record in self._inventory.values():
            # Disallow self-referential selection of call-me
            if record.name.lower() in ("call-me", "call_me") or record.urn.lower().endswith((":call-me", ":call_me")):
                continue

            if resource_types and record.resource_type not in resource_types:
                continue

            score = self._score_record(record, clean_q, query_tokens)
            if score >= 10.0:
                scored_records.append((score, record))

        scored_records.sort(key=lambda x: x[0], reverse=True)
        return [rec for _, rec in scored_records[:limit]]

    def get_conflicts(self) -> List[ConflictRecord]:
        return list(self._conflicts)

    def get_inventory_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in self._inventory.values():
            k = r.resource_type.value
            counts[k] = counts.get(k, 0) + 1
        return counts

    # =========================================================================
    # Internal Ingestion & Normalization
    # =========================================================================

    def _load_from_sqlite_catalog(self):
        """Loads records from artifact_discovery_records, mcp_server_registrations, and agent_declarations."""
        cur = self.conn.cursor()

        # 1. Artifact Discovery Records
        try:
            cur.execute("""
                SELECT a.canonical_urn, a.name, a.display_name, a.taxonomy_kind, a.environment_origin,
                       a.precedence_tier, a.source_path, a.resolved_path, a.is_bundle, a.bundle_root_path,
                       a.raw_content_digest, a.lifecycle_state, a.provenance_json, c.description
                FROM artifact_discovery_records a
                LEFT JOIN capabilities c ON a.canonical_urn = c.capability_urn;
            """)
            for row in cur.fetchall():
                (urn, name, display_name, taxonomy_kind, origin, tier,
                 src_path, res_path, is_bundle, bundle_root, raw_digest,
                 lifecycle_state, prov_json, db_desc) = row

                # Map taxonomy_kind to ResourceType
                rtype = ResourceType.SKILL
                if taxonomy_kind == "COMMAND":
                    rtype = ResourceType.COMMAND
                elif taxonomy_kind == "RULE":
                    rtype = ResourceType.RULE
                elif taxonomy_kind == "AGENT_INSTRUCTION":
                    rtype = ResourceType.AGENT_INSTRUCTION
                elif taxonomy_kind == "AGENT_CONFIGURATION":
                    rtype = ResourceType.AGENT

                tier_str = "WORKSPACE" if tier == 0 else "USER_GLOBAL"
                raw_text = ""
                if res_path and os.path.exists(res_path):
                    try:
                        raw_bytes, _ = SafeFileReader.read_exact_bytes(res_path, MAX_INSTRUCTION_FILE_SIZE)
                        raw_text = raw_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        pass

                # Parse frontmatter / description
                description = (db_desc and db_desc.strip()) or self._extract_description(raw_text)
                reqs = self._extract_execution_requirements(raw_text, rtype)
                deps = self._extract_dependencies(raw_text)

                prov = ProvenanceRecord(
                    origin_host=origin.lower() if origin else "generic_posix",
                    precedence_tier=tier_str,
                    source_path=src_path,
                    resolved_path=res_path or src_path,
                    content_hash=raw_digest
                )

                rec = UnifiedResourceRecord(
                    urn=urn,
                    name=name,
                    resource_type=rtype,
                    display_name=display_name or name,
                    description=description,
                    raw_content=raw_text,
                    raw_content_digest=raw_digest,
                    provenance=prov,
                    lifecycle_state=OperationalLifecycleState.DISCOVERED,
                    execution_requirements=reqs,
                    is_bundle=bool(is_bundle),
                    bundle_root_path=bundle_root,
                    declared_dependencies=deps,
                    security_flags=self._audit_security(raw_text)
                )
                self._register_resource_with_conflict_resolution(rec)
        except Exception as e:
            logger.debug(f"Catalog artifact query error: {e}")

        # 2. MCP Server Registrations
        try:
            cur.execute("SELECT server_id, server_name, transport_type, command_line FROM mcp_server_registrations;")
            for s_id, s_name, transport, cmd in cur.fetchall():
                clean_ident = _canonical_identifier(s_name)
                urn = f"urn:lcs:tool:mcp:{clean_ident}"
                prov = ProvenanceRecord(
                    origin_host="mcp",
                    precedence_tier="HOST",
                    source_path=cmd or "",
                    resolved_path=cmd or "",
                    content_hash=hashlib.sha256((cmd or s_name).encode()).hexdigest()
                )
                rec = UnifiedResourceRecord(
                    urn=urn,
                    name=s_name,
                    resource_type=ResourceType.MCP_SERVER,
                    display_name=s_name,
                    description=f"Local MCP Server ({transport}): {cmd}",
                    raw_content=cmd or "",
                    raw_content_digest=prov.content_hash,
                    provenance=prov,
                    lifecycle_state=OperationalLifecycleState.CONFIGURED,
                    metadata={"transport": transport, "command_line": cmd}
                )
                self._register_resource_with_conflict_resolution(rec)
        except Exception as e:
            logger.debug(f"MCP server query error: {e}")

        # 3. Agent Declarations
        try:
            cur.execute("SELECT agent_urn, display_name, description, provenance_json FROM agent_declarations;")
            for a_urn, d_name, desc, p_json in cur.fetchall():
                prov = ProvenanceRecord(
                    origin_host="agent_runtime",
                    precedence_tier="WORKSPACE",
                    source_path="db://agent_declarations",
                    resolved_path="db://agent_declarations",
                    content_hash=hashlib.sha256((a_urn + (desc or "")).encode()).hexdigest()
                )
                rec = UnifiedResourceRecord(
                    urn=a_urn,
                    name=d_name or a_urn,
                    resource_type=ResourceType.AGENT,
                    display_name=d_name or a_urn,
                    description=desc or "Autonomous Agent",
                    raw_content=desc or "",
                    raw_content_digest=prov.content_hash,
                    provenance=prov,
                    lifecycle_state=OperationalLifecycleState.CONFIGURED
                )
                self._register_resource_with_conflict_resolution(rec)
        except Exception as e:
            logger.debug(f"Agent declarations query error: {e}")

    def _discover_from_adapter(self, adapter: Any):
        """Uses an EnvironmentAdapter to discover roots and MCP servers."""
        env_kind = getattr(adapter, "environment_kind", EnvironmentKind.GENERIC_POSIX)
        env_name = env_kind.value if hasattr(env_kind, "value") else str(env_kind)

        # 1. Discover capability roots
        if hasattr(adapter, "discover_capability_roots"):
            roots: List[CapabilityRoot] = adapter.discover_capability_roots(self.workspace_root)
            for root in roots:
                self._scan_capability_root(root, env_name)

        # 2. Discover MCP configs
        if hasattr(adapter, "discover_mcp_servers"):
            mcp_entries = adapter.discover_mcp_servers(self.workspace_root)
            for entry in mcp_entries:
                s_name = getattr(entry, "server_name", getattr(entry, "server_id", "mcp"))
                clean_ident = _canonical_identifier(s_name)
                urn = f"urn:lcs:tool:{env_name}:mcp-{clean_ident}"
                cmd = f"{entry.command} {' '.join(entry.args)}"
                prov = ProvenanceRecord(
                    origin_host=env_name,
                    precedence_tier="HOST",
                    source_path=entry.source_file or cmd,
                    resolved_path=entry.cwd or entry.source_file or cmd,
                    content_hash=hashlib.sha256(cmd.encode()).hexdigest()
                )
                rec = UnifiedResourceRecord(
                    urn=urn,
                    name=s_name,
                    resource_type=ResourceType.MCP_SERVER,
                    display_name=f"{s_name} ({env_name})",
                    description=f"Configured MCP Server via {env_name}: {cmd}",
                    raw_content=cmd,
                    raw_content_digest=prov.content_hash,
                    provenance=prov,
                    lifecycle_state=OperationalLifecycleState.CONFIGURED,
                    metadata={"command": entry.command, "args": entry.args, "cwd": entry.cwd}
                )
                self._register_resource_with_conflict_resolution(rec)

    def _scan_capability_root(self, root: CapabilityRoot, env_name: str):
        """Scans a physical directory root for skills, commands, rules, scripts, workflows."""
        r_path = root.root_path
        if not os.path.exists(r_path) or not os.path.isdir(r_path):
            return

        tier = root.precedence_tier

        for item in os.listdir(r_path):
            if (item.startswith(".") and item != ".cursorrules") or item in ("__pycache__", "node_modules"):
                continue

            full_path = os.path.join(r_path, item)

            # Case A: Directory bundle (e.g. skill folder with SKILL.md)
            if os.path.isdir(full_path):
                skill_file = os.path.join(full_path, "SKILL.md")
                workflow_file = os.path.join(full_path, "WORKFLOW.md")
                readme_file = os.path.join(full_path, "README.md")

                target_file = None
                rtype = ResourceType.SKILL

                if os.path.exists(skill_file):
                    target_file = skill_file
                    rtype = ResourceType.SKILL
                elif os.path.exists(workflow_file):
                    target_file = workflow_file
                    rtype = ResourceType.WORKFLOW
                elif os.path.exists(readme_file):
                    target_file = readme_file
                    rtype = ResourceType.SKILL

                if target_file and os.path.exists(target_file):
                    try:
                        raw_bytes, _ = SafeFileReader.read_exact_bytes(target_file, MAX_INSTRUCTION_FILE_SIZE)
                        content = raw_bytes.decode("utf-8", errors="replace")
                        digest = hashlib.sha256(content.encode()).hexdigest()
                        clean_ident = _canonical_identifier(item)
                        urn = f"urn:lcs:{_canonical_entity_kind(rtype)}:{env_name}:{clean_ident}"
                        desc = self._extract_description(content)
                        reqs = self._extract_execution_requirements(content, rtype)
                        deps = self._extract_dependencies(content)

                        # Discover auxiliary assets
                        aux_files = self._index_bundle_auxiliary_files(full_path, target_file)

                        prov = ProvenanceRecord(
                            origin_host=env_name,
                            precedence_tier=tier,
                            source_path=full_path,
                            resolved_path=os.path.realpath(full_path),
                            content_hash=digest
                        )

                        rec = UnifiedResourceRecord(
                            urn=urn,
                            name=item,
                            resource_type=rtype,
                            display_name=item,
                            description=desc,
                            raw_content=content,
                            raw_content_digest=digest,
                            provenance=prov,
                            lifecycle_state=OperationalLifecycleState.DISCOVERED,
                            execution_requirements=reqs,
                            is_bundle=True,
                            bundle_root_path=full_path,
                            auxiliary_files=aux_files,
                            declared_dependencies=deps,
                            security_flags=self._audit_security(content)
                        )
                        self._register_resource_with_conflict_resolution(rec)
                    except Exception as e:
                        logger.debug(f"Failed scanning bundle {full_path}: {e}")

            # Case B: Standalone files (.md, .py, .sh)
            elif os.path.isfile(full_path):
                ext = os.path.splitext(item)[1].lower()
                rtype = None

                if ext == ".md" or item == ".cursorrules":
                    if item.upper() in ("CLAUDE.MD", "AGENTS.MD", "RULES.MD", ".CURSORRULES") or item == ".cursorrules":
                        rtype = ResourceType.RULE
                    else:
                        rtype = ResourceType.COMMAND
                elif ext in (".py", ".sh", ".bash", ".js", ".ts"):
                    rtype = ResourceType.SCRIPT

                if rtype:
                    try:
                        raw_bytes, _ = SafeFileReader.read_exact_bytes(full_path, MAX_INSTRUCTION_FILE_SIZE)
                        content = raw_bytes.decode("utf-8", errors="replace")
                        digest = hashlib.sha256(content.encode()).hexdigest()
                        clean_name = os.path.splitext(item)[0]
                        clean_ident = _canonical_identifier(clean_name)
                        urn = f"urn:lcs:{_canonical_entity_kind(rtype)}:{env_name}:{clean_ident}"

                        prov = ProvenanceRecord(
                            origin_host=env_name,
                            precedence_tier=tier,
                            source_path=full_path,
                            resolved_path=os.path.realpath(full_path),
                            content_hash=digest
                        )

                        rec = UnifiedResourceRecord(
                            urn=urn,
                            name=clean_name,
                            resource_type=rtype,
                            display_name=item,
                            description=self._extract_description(content),
                            raw_content=content,
                            raw_content_digest=digest,
                            provenance=prov,
                            lifecycle_state=OperationalLifecycleState.DISCOVERED,
                            execution_requirements=self._extract_execution_requirements(content, rtype),
                            declared_dependencies=self._extract_dependencies(content),
                            security_flags=self._audit_security(content)
                        )
                        self._register_resource_with_conflict_resolution(rec)
                    except Exception as e:
                        logger.debug(f"Failed reading standalone file {full_path}: {e}")

    def _index_bundle_auxiliary_files(self, bundle_root: str, primary_file: str) -> Dict[str, Dict[str, Any]]:
        """Indexes auxiliary scripts, templates, references inside a bundle."""
        aux: Dict[str, Dict[str, Any]] = {}
        real_primary = os.path.realpath(primary_file)
        real_bundle = os.path.realpath(bundle_root)

        for root, dirs, files in os.walk(real_bundle, followlinks=False):
            for f in files:
                fpath = os.path.join(root, f)
                real_fpath = os.path.realpath(fpath)
                if not (real_fpath == real_bundle or real_fpath.startswith(real_bundle + os.sep)):
                    continue  # Refuse symlink escapes outside the bundle boundary
                if real_fpath == real_primary:
                    continue
                rel = os.path.relpath(real_fpath, real_bundle).replace("\\", "/")
                ext = os.path.splitext(f)[1].lower()

                akind = "REFERENCE"
                if ext in (".py", ".sh", ".bash", ".js", ".ts"):
                    akind = "SCRIPT"
                elif ext in (".j2", ".jinja", ".template"):
                    akind = "TEMPLATE"

                try:
                    size = os.path.getsize(fpath)
                    aux[rel] = {
                        "path": fpath,
                        "relative_path": rel,
                        "kind": akind,
                        "size_bytes": size
                    }
                except Exception:
                    pass

        return aux

    def _register_resource_with_conflict_resolution(self, record: UnifiedResourceRecord):
        """
        Registers a resource or resolves conflicts according to precedence tiers:
        WORKSPACE (0) > HOST (1) > USER_GLOBAL (2) > BUILTIN (3).
        If the same resource is re-scanned with updated content, updates the record.
        """
        existing = self._inventory.get(record.urn)
        if not existing:
            # Check by name and type
            for ex in self._inventory.values():
                if ex.name == record.name and ex.resource_type == record.resource_type:
                    existing = ex
                    break

        if not existing:
            self._inventory[record.urn] = record
            self._persist_and_bind_capability(record)
            return

        # Case 1: Same resource re-scanned (update content)
        if existing.urn == record.urn or (
            existing.provenance.source_path and existing.provenance.source_path == record.provenance.source_path
        ):
            self._inventory[record.urn] = record
            self._persist_and_bind_capability(record)
            return

        # Case 2: Conflict resolution based on tier between different locations
        exist_tier = PREF_ORDER.get(existing.provenance.precedence_tier, 99)
        new_tier = PREF_ORDER.get(record.provenance.precedence_tier, 99)

        if new_tier < exist_tier:
            # New record has higher priority
            self._conflicts.append(ConflictRecord(
                urn=record.urn,
                name=record.name,
                conflicting_versions=[existing.provenance.version, record.provenance.version],
                locations=[existing.provenance.source_path, record.provenance.source_path],
                chosen_record_urn=record.urn,
                resolution_reason=f"Higher precedence tier ({record.provenance.precedence_tier} over {existing.provenance.precedence_tier})"
            ))
            if existing.urn in self._inventory:
                del self._inventory[existing.urn]
            self._inventory[record.urn] = record
            self._persist_and_bind_capability(record)
        else:
            # Existing record preserved
            self._conflicts.append(ConflictRecord(
                urn=existing.urn,
                name=existing.name,
                conflicting_versions=[existing.provenance.version, record.provenance.version],
                locations=[existing.provenance.source_path, record.provenance.source_path],
                chosen_record_urn=existing.urn,
                resolution_reason=f"Retained existing higher/equal precedence tier ({existing.provenance.precedence_tier} vs {record.provenance.precedence_tier})"
            ))

    def _persist_and_bind_capability(self, record: UnifiedResourceRecord):
        """Ensures the capability is registered in SQLite entity_urn_registry, capabilities, artifact_discovery_records, capability_declarations, and interface_declarations."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.conn:
                raw_bytes = record.raw_content.encode("utf-8")
                calc_sha = hashlib.sha256(raw_bytes).hexdigest()
                raw_digest = record.raw_content_digest if (record.raw_content_digest and len(record.raw_content_digest) == 64) else calc_sha
                raw_len = len(raw_bytes)

                # Store raw content in CAS and content_chunk_blobs if CAS is available
                if self.cas_engine:
                    if not self.cas_engine.blob_exists(raw_digest):
                        try:
                            pub_id = f"pub_{raw_digest[:8]}"
                            tmp_name, _, _ = self.cas_engine.write_payload_to_staging(pub_id, "tok_lcs", raw_digest, raw_bytes)
                            self.cas_engine.publish_staging_to_cas(tmp_name, raw_digest)
                        except Exception:
                            pass

                self.conn.execute("""
                    INSERT OR IGNORE INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                    VALUES (?, ?, 'NONE', ?);
                """, (raw_digest, raw_len, raw_len))

                # 1. entity_urn_registry & capabilities (register as PENDING then ACTIVE to satisfy triggers)
                self.conn.execute("""
                    INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state)
                    VALUES (?, 'CAPABILITY', 'PENDING');
                """, (record.urn,))
                self.conn.execute("""
                    INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description)
                    VALUES (?, ?, ?, ?);
                """, (record.urn, record.name, record.provenance.version, record.description))
                self.conn.execute("""
                    UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;
                """, (record.urn,))

                # 2. artifact_discovery_records (for SKILL, COMMAND, RULE, etc.)
                if record.resource_type in (ResourceType.SKILL, ResourceType.COMMAND, ResourceType.RULE, ResourceType.AGENT_INSTRUCTION, ResourceType.AGENT):
                    tax_kind = "SKILL"
                    if record.resource_type == ResourceType.COMMAND:
                        tax_kind = "COMMAND"
                    elif record.resource_type == ResourceType.RULE:
                        tax_kind = "RULE"
                    elif record.resource_type == ResourceType.AGENT_INSTRUCTION:
                        tax_kind = "AGENT_INSTRUCTION"
                    elif record.resource_type == ResourceType.AGENT:
                        tax_kind = "AGENT_CONFIGURATION"

                    art_id = f"art-{hashlib.sha256(record.urn.encode()).hexdigest()[:12]}"
                    tier_int = PREF_ORDER.get(record.provenance.precedence_tier, 1)

                    bundle_digest = getattr(record.provenance, "bundle_manifest_hash", None)
                    if record.is_bundle and not bundle_digest and record.bundle_root_path and os.path.isdir(record.bundle_root_path):
                        from ..skills import BundleManifestHasher
                        try:
                            bundle_digest, _, _ = BundleManifestHasher.compute_bundle_manifest(record.bundle_root_path)
                        except Exception:
                            bundle_digest = None

                    self.conn.execute("""
                        INSERT OR REPLACE INTO artifact_discovery_records (
                            artifact_id, canonical_urn, name, display_name, taxonomy_kind,
                            environment_origin, precedence_tier, source_path, resolved_path,
                            is_bundle, bundle_root_path, file_size_bytes, st_mtime, st_ino, st_dev,
                            raw_content_digest, bundle_manifest_digest, lifecycle_state, provenance_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AVAILABLE', '{}');
                    """, (
                        art_id, record.urn, record.name, record.display_name, tax_kind,
                        record.provenance.origin_host.upper(), tier_int,
                        record.provenance.source_path, record.provenance.resolved_path,
                        1 if record.is_bundle else 0, record.bundle_root_path,
                        raw_len, 0.0, 0, 0,
                        raw_digest, bundle_digest
                    ))

                # 3. capability_declarations
                self.conn.execute("""
                    INSERT OR REPLACE INTO capability_declarations (
                        capability_urn, definition_blob_digest, schema_version, display_name, capability_type
                    ) VALUES (?, ?, 1, ?, ?);
                """, (record.urn, raw_digest, record.display_name, "skill"))

                # 4. Interface and Agent Declarations
                parts = record.urn.split(":")
                srv_name = parts[3].replace("mcp.", "") if len(parts) >= 4 else record.provenance.origin_host.lower()
                iface_urn = f"urn:lcs:interface:mcp.{srv_name}:v1"
                agent_urn = f"urn:lcs:agent:mcp.{srv_name}:host"

                self.conn.execute("""
                    INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state)
                    VALUES (?, 'CAPABILITY', 'PENDING');
                """, (agent_urn,))
                self.conn.execute("""
                    INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description)
                    VALUES (?, ?, '1.0.0', 'Host agent');
                """, (agent_urn, f"{srv_name} Host Agent"))
                self.conn.execute("""
                    UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;
                """, (agent_urn,))
                self.conn.execute("""
                    INSERT OR IGNORE INTO agent_declarations (agent_urn, display_name, description, provenance_json)
                    VALUES (?, ?, 'Host agent for discovered capabilities', '{}');
                """, (agent_urn, f"{srv_name} Host Agent"))

                cap_ref_urn = record.urn
                if record.resource_type == ResourceType.AGENT or record.urn.startswith("urn:lcs:agent:"):
                    cap_ref_urn = f"urn:lcs:skill:{srv_name}:default"
                    self.conn.execute("""
                        INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state)
                        VALUES (?, 'CAPABILITY', 'PENDING');
                    """, (cap_ref_urn,))
                    self.conn.execute("""
                        INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description)
                        VALUES (?, ?, '1.0.0', 'Agent skill capability');
                    """, (cap_ref_urn, f"{record.name} skill"))
                    self.conn.execute("""
                        UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;
                    """, (cap_ref_urn,))
                    self.conn.execute("""
                        INSERT OR REPLACE INTO capability_declarations (
                            capability_urn, definition_blob_digest, schema_version, display_name, capability_type
                        ) VALUES (?, ?, 1, ?, 'skill');
                    """, (cap_ref_urn, raw_digest, f"{record.name} skill"))

                from ..policy import InterfaceDeclaration, InterfaceCapabilityRef
                iface_decl = InterfaceDeclaration(
                    interface_urn=iface_urn,
                    agent_urn=agent_urn,
                    interface_version=1,
                    display_name=f"{srv_name} Interface",
                    description=f"Auto-registered interface for {srv_name}",
                    schema_version=1,
                    capabilities=[InterfaceCapabilityRef(
                        capability_urn=cap_ref_urn,
                        expected_definition_digest=raw_digest
                    )],
                    provenance={"author": "lcs", "created_at": now_iso, "source_origin": srv_name, "license": "MIT"}
                )

                decl_bytes = json.dumps(iface_decl.to_dict()).encode("utf-8")
                decl_digest = hashlib.sha256(decl_bytes).hexdigest()
                decl_len = len(decl_bytes)

                if self.cas_engine:
                    if not self.cas_engine.blob_exists(decl_digest):
                        try:
                            tmp_name, _, _ = self.cas_engine.write_payload_to_staging(f"pub_{decl_digest[:8]}", "tok_lcs", decl_digest, decl_bytes)
                            self.cas_engine.publish_staging_to_cas(tmp_name, decl_digest)
                        except Exception:
                            pass

                self.conn.execute("""
                    INSERT OR IGNORE INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                    VALUES (?, ?, 'NONE', ?);
                """, (decl_digest, decl_len, decl_len))

                self.conn.execute("""
                    INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state)
                    VALUES (?, 'CAPABILITY', 'PENDING');
                """, (iface_urn,))
                self.conn.execute("""
                    INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description)
                    VALUES (?, ?, '1.0.0', 'Discovered interface');
                """, (iface_urn, f"{srv_name} Interface"))
                self.conn.execute("""
                    UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;
                """, (iface_urn,))

                self.conn.execute("""
                    INSERT OR IGNORE INTO interface_declarations (
                        interface_urn, agent_urn, interface_version, display_name, description, declaration_blob_digest, schema_version
                    ) VALUES (?, ?, 1, ?, ?, ?, 1);
                """, (iface_urn, agent_urn, f"{srv_name} Interface", f"Auto-registered interface for {srv_name}", decl_digest))

                bnd_id = f"bnd_{hashlib.sha256((iface_urn + record.urn).encode()).hexdigest()[:16]}"
                self.conn.execute("""
                    INSERT OR REPLACE INTO interface_capability_bindings (
                        binding_id, interface_urn, capability_urn, expected_definition_digest, bound_at
                    ) VALUES (?, ?, ?, ?, ?);
                """, (bnd_id, iface_urn, record.urn, raw_digest, now_iso))
                if cap_ref_urn != record.urn:
                    bnd_id2 = f"bnd_{hashlib.sha256((iface_urn + cap_ref_urn).encode()).hexdigest()[:16]}"
                    self.conn.execute("""
                        INSERT OR REPLACE INTO interface_capability_bindings (
                            binding_id, interface_urn, capability_urn, expected_definition_digest, bound_at
                        ) VALUES (?, ?, ?, ?, ?);
                    """, (bnd_id2, iface_urn, cap_ref_urn, raw_digest, now_iso))

                if self.iface_service:
                    try:
                        self.iface_service.attest_interface(iface_urn)
                    except Exception:
                        pass

            # Ingest into live memory inventory
            self._register_resource_with_conflict_resolution(record)
        except Exception as e:
            logger.debug(f"Failed to persist capability '{record.urn}' to db: {e}", exc_info=True)

    def _evaluate_operational_states(self):
        """Evaluates reachability, dependencies, and execution readiness."""
        for record in self._inventory.values():
            # Check physical reachability
            res_path = record.provenance.resolved_path
            is_reachable = True

            if res_path and not res_path.startswith("db://"):
                if not os.path.exists(res_path):
                    record.lifecycle_state = OperationalLifecycleState.UNAVAILABLE
                    is_reachable = False
                elif not os.access(res_path, os.R_OK):
                    record.lifecycle_state = OperationalLifecycleState.UNAVAILABLE
                    is_reachable = False

            if not is_reachable:
                continue

            # Check binary requirements
            bin_missing = False
            for req_bin in record.execution_requirements.required_binaries:
                probe = LiveProbeEngine.probe_binary(req_bin)
                if probe.status != OperationalStatus.AVAILABLE:
                    record.missing_dependencies.append(f"binary:{req_bin}")
                    bin_missing = True

            # Check declared dependencies
            for dep in record.declared_dependencies:
                dep_name = dep.get("name", "")
                dep_mandatory = dep.get("mandatory", True)
                if not dep_mandatory:
                    continue

                found = any(r.name == dep_name or r.urn == dep_name for r in self._inventory.values())
                if not found and dep_name:
                    record.missing_dependencies.append(dep_name)

            if record.missing_dependencies or bin_missing:
                record.lifecycle_state = OperationalLifecycleState.CONFIGURED
            else:
                record.lifecycle_state = OperationalLifecycleState.EXECUTABLE

    # =========================================================================
    # Metadata Parsing & Security Extraction
    # =========================================================================

    def _extract_description(self, raw_text: str) -> str:
        if not raw_text:
            return ""
        # Check YAML frontmatter
        if raw_text.startswith("---"):
            parts = raw_text.split("---", 2)
            if len(parts) >= 3:
                for line in parts[1].splitlines():
                    if line.strip().startswith("description:"):
                        return line.split("description:", 1)[1].strip().strip("\"'")

        # First markdown heading or non-empty paragraph
        for line in raw_text.splitlines():
            s = line.strip()
            if s.startswith("# "):
                return s[2:].strip()
            if s and not s.startswith(("#", "-", "*", "```", "---")):
                return s[:120]
        return ""

    def _extract_execution_requirements(self, raw_text: str, rtype: ResourceType) -> ExecutionRequirement:
        req_bins = []
        runtime = "generic_posix"

        if rtype == ResourceType.SCRIPT:
            if "#!/usr/bin/env python" in raw_text or "#!/usr/bin/python" in raw_text:
                runtime = "python"
                req_bins.append("python3")
            elif "#!/bin/bash" in raw_text or "#!/usr/bin/env bash" in raw_text:
                runtime = "bash"
                req_bins.append("bash")
            elif "#!/usr/bin/env node" in raw_text:
                runtime = "node"
                req_bins.append("node")

        # Scan for common tool requirements
        for b in ["git", "curl", "sqlite3", "tar", "gzip"]:
            if re.search(r'\b' + b + r'\b', raw_text):
                if b not in req_bins:
                    req_bins.append(b)

        return ExecutionRequirement(
            runtime_environment=runtime,
            required_binaries=req_bins
        )

    def _extract_dependencies(self, raw_text: str) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        if not raw_text.startswith("---"):
            return deps

        parts = raw_text.split("---", 2)
        if len(parts) < 3:
            return deps

        in_deps = False
        for line in parts[1].splitlines():
            s = line.strip()
            if s.startswith("dependencies:"):
                in_deps = True
                continue
            if in_deps:
                if s.startswith("- "):
                    dname = s[2:].strip().strip("\"'")
                    if dname:
                        deps.append({"name": dname, "mandatory": True, "type": "SKILL"})
                elif s and not s.startswith("#") and ":" in s:
                    in_deps = False
        return deps

    def _audit_security(self, raw_text: str) -> List[str]:
        flags: List[str] = []
        if not raw_text:
            return flags

        # Check prompt injection patterns without rewriting content
        suspicious_patterns = [
            (r'(ignore|disregard|forget)\s+(all\s+)?(previous|prior)\s+(instructions|directives|prompts)', "PROMPT_INJECTION_IGNORE_PREVIOUS"),
            (r'system\s+prompt\s+override', "PROMPT_INJECTION_SYSTEM_OVERRIDE"),
            (r'you\s+are\s+now\s+in\s+developer\s+mode', "PROMPT_INJECTION_JAILBREAK"),
            (r'(bypass|disable|circumvent)\s+(all\s+)?(governance|security|safety|restrictions)', "GOVERNANCE_BYPASS_ATTEMPT"),
            (r'<script.*?>', "EMBEDDED_HTML_SCRIPT_TAG"),
            (r'(sudo\s+)?rm\s+-rf\s+[/~]', "DESTRUCTIVE_COMMAND_ROOT_REMOVAL"),
            (r'(curl|wget)\s+[^|\n]+\|\s*(sh|bash|zsh)', "INSECURE_REMOTE_EXECUTION_PIPE"),
            (r'chmod\s+777\b', "INSECURE_PERMISSIVE_FILE_ACCESS"),
            (r'(nc|ncat|netcat)\s+-[a-zA-Z]*e\b', "REVERSE_SHELL_PATTERN"),
        ]
        for pat, tag in suspicious_patterns:
            if re.search(pat, raw_text, re.IGNORECASE):
                flags.append(tag)

        return flags
