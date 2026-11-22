"""
LCS Capability Instruction Hydration Engine (Phase 2B)
======================================================
Retrieves authoritative instructions, auxiliary files, and declared dependencies
with complete provenance tracking and zero instruction summarization.
"""

import os
import re
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    import yaml
except ImportError:
    yaml = None

from skill_discovery_v1 import (
    SafeFileReader,
    BundleManifestHasher,
    MAX_INSTRUCTION_FILE_SIZE,
    MAX_ASSET_FILE_SIZE,
    MAX_DIRECTORY_RECURSION_DEPTH,
    MalformedArtifactError
)
from .models import (
    ResourceUtilizationState,
    AuxiliaryFileRecord,
    DependencyReference,
    HydratedCapability,
)

logger = logging.getLogger("lcs.hydration.engine")


class HydrationError(Exception):
    """Base exception for capability hydration failures."""
    pass


class HydrationEngine:
    """
    Coordinates authoritative deep instruction hydration from CAS and disk.
    """

    def __init__(self, conn: Any, cas_engine: Any, resolver: Any = None):
        self.conn = conn
        self.cas_engine = cas_engine
        self.resolver = resolver

    def hydrate_capability(self, capability_urn: str) -> HydratedCapability:
        """
        Deep-hydrates a capability from its registered discovery and CAS records.
        Preserves original raw instructions without replacement or truncation.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT artifact_id, canonical_urn, name, display_name, taxonomy_kind,
                   environment_origin, source_path, resolved_path, is_bundle,
                   bundle_root_path, raw_content_digest, bundle_manifest_digest,
                   lifecycle_state, provenance_json
            FROM artifact_discovery_records
            WHERE canonical_urn = ?;
        """, (capability_urn,))
        row = cur.fetchone()

        if not row:
            name_cand = capability_urn.split(":")[-1]
            cur.execute("""
                SELECT artifact_id, canonical_urn, name, display_name, taxonomy_kind,
                       environment_origin, source_path, resolved_path, is_bundle,
                       bundle_root_path, raw_content_digest, bundle_manifest_digest,
                       lifecycle_state, provenance_json
                FROM artifact_discovery_records
                WHERE name = ? LIMIT 1;
            """, (name_cand,))
            row = cur.fetchone()

        if not row:
            raise HydrationError(f"Capability URN not registered in catalog: '{capability_urn}'")

        (
            artifact_id, urn, name, display_name, taxonomy_kind,
            origin, source_path, resolved_path, is_bundle,
            bundle_root, raw_digest, bundle_digest,
            lifecycle_state, provenance_json
        ) = row

        # 1. Retrieve Authoritative Root Instruction Bytes
        raw_bytes = None
        source_location = "CAS"

        # Try CAS first
        if self.cas_engine and self.cas_engine.blob_exists(raw_digest):
            raw_bytes = self.cas_engine.read_blob(raw_digest)
        elif resolved_path and os.path.exists(resolved_path):
            raw_bytes, _ = SafeFileReader.read_exact_bytes(resolved_path, MAX_INSTRUCTION_FILE_SIZE)
            source_location = "DISK"
            # Verify digest
            computed_digest = hashlib.sha256(raw_bytes).hexdigest()
            if computed_digest != raw_digest:
                raise HydrationError(
                    f"Content digest mismatch for '{urn}': expected {raw_digest}, got {computed_digest}"
                )
        else:
            raise HydrationError(f"Authoritative instructions missing from both CAS and disk for '{urn}'")

        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raw_text = raw_bytes.decode("utf-8", errors="replace")

        # 2. Retrieve Auxiliary Files for Bundles
        auxiliary_files: Dict[str, AuxiliaryFileRecord] = {}
        if is_bundle and bundle_root and os.path.exists(bundle_root):
            auxiliary_files = self._load_auxiliary_files(bundle_root, resolved_path)

        # 3. Extract Declared Dependencies
        dependencies = self._extract_dependencies(raw_text, auxiliary_files, bundle_root)

        # 4. Validate Dependency Completeness
        missing_deps = self._find_missing_dependencies(dependencies, auxiliary_files)

        # 5. Build Provenance Record
        provenance = {
            "artifact_id": artifact_id,
            "origin_environment": origin,
            "source_location": source_location,
            "source_path": source_path,
            "resolved_path": resolved_path,
            "is_bundle": bool(is_bundle),
            "bundle_root_path": bundle_root,
            "lifecycle_state": lifecycle_state,
            "raw_byte_length": len(raw_bytes),
        }

        state = (
            ResourceUtilizationState.HYDRATED
            if not missing_deps
            else ResourceUtilizationState.RETRIEVED
        )

        return HydratedCapability(
            capability_urn=urn,
            name=name,
            raw_instructions=raw_text,
            instruction_digest=raw_digest,
            state=state,
            source_path=source_path,
            cas_digest=raw_digest,
            is_bundle=bool(is_bundle),
            bundle_root_path=bundle_root,
            bundle_manifest_digest=bundle_digest,
            auxiliary_files=auxiliary_files,
            dependencies=dependencies,
            provenance=provenance,
            is_complete=(len(missing_deps) == 0),
            missing_dependencies=missing_deps
        )

    def _load_auxiliary_files(
        self,
        bundle_root: str,
        root_file_path: Optional[str]
    ) -> Dict[str, AuxiliaryFileRecord]:
        """Safely walks and loads all auxiliary bundle assets."""
        res_dir = os.path.realpath(bundle_root)
        aux_files: Dict[str, AuxiliaryFileRecord] = {}
        base_depth = len(res_dir.rstrip(os.sep).split(os.sep))

        for root, dirs, files in os.walk(res_dir, followlinks=False):
            cur_depth = len(root.split(os.sep)) - base_depth
            if cur_depth > MAX_DIRECTORY_RECURSION_DEPTH:
                dirs.clear()
                continue

            for f in files:
                file_path = os.path.join(root, f)
                if root_file_path and os.path.realpath(file_path) == os.path.realpath(root_file_path):
                    continue  # Skip root instruction file

                rel_path = os.path.relpath(file_path, res_dir).replace("\\", "/")
                # Skip hidden/cache
                if any(part.startswith(".") for part in rel_path.split("/")):
                    continue
                if "__pycache__" in rel_path:
                    continue

                try:
                    fbytes, _ = SafeFileReader.read_exact_bytes(file_path, MAX_ASSET_FILE_SIZE)
                    fdigest = hashlib.sha256(fbytes).hexdigest()
                    aux_files[rel_path] = AuxiliaryFileRecord(
                        relative_path=rel_path,
                        absolute_path=file_path,
                        content_bytes=fbytes,
                        digest=fdigest,
                        size_bytes=len(fbytes)
                    )
                except Exception as e:
                    logger.warning(f"Failed to load auxiliary asset '{file_path}': {e}")

        return aux_files

    def _extract_dependencies(
        self,
        raw_text: str,
        auxiliary_files: Dict[str, AuxiliaryFileRecord],
        bundle_root: Optional[str]
    ) -> List[DependencyReference]:
        """Extracts declared dependencies from frontmatter, markdown links, and auxiliary references."""
        deps: List[DependencyReference] = []
        seen_names: Set[str] = set()

        # Parse YAML frontmatter if present
        if raw_text.startswith("---"):
            parts = raw_text.split("---", 2)
            if len(parts) >= 3:
                try:
                    meta = {}
                    if yaml is not None:
                        try:
                            meta = yaml.safe_load(parts[1]) or {}
                        except Exception:
                            meta = {}
                    else:
                        in_deps = False
                        for line in parts[1].splitlines():
                            s = line.strip()
                            if s.startswith("dependencies:"):
                                in_deps = True
                                continue
                            if in_deps:
                                if s.startswith("- "):
                                    dname = s[2:].strip().strip("\"'")
                                    if dname and dname not in seen_names:
                                        deps.append(DependencyReference(
                                            name=dname,
                                            target_urn_or_path=dname,
                                            resource_type="SKILL",
                                            is_mandatory=True
                                        ))
                                        seen_names.add(dname)
                                elif s and not s.startswith("#") and ":" in s:
                                    in_deps = False

                    if isinstance(meta, dict):
                        # dependencies: [ ... ]
                        for dep_item in meta.get("dependencies", []):
                            if isinstance(dep_item, str) and dep_item not in seen_names:
                                deps.append(DependencyReference(
                                    name=dep_item,
                                    target_urn_or_path=dep_item,
                                    resource_type="SKILL",
                                    is_mandatory=True
                                ))
                                seen_names.add(dep_item)
                            elif isinstance(dep_item, dict) and "name" in dep_item:
                                dname = dep_item["name"]
                                if dname not in seen_names:
                                    deps.append(DependencyReference(
                                        name=dname,
                                        target_urn_or_path=dep_item.get("target", dname),
                                        resource_type=dep_item.get("type", "SKILL").upper(),
                                        is_mandatory=dep_item.get("mandatory", True),
                                        version_spec=dep_item.get("version")
                                    ))
                                    seen_names.add(dname)

                        # tools: [ ... ]
                        for tool in meta.get("tools", []):
                            tname = tool if isinstance(tool, str) else tool.get("name")
                            if tname and tname not in seen_names:
                                deps.append(DependencyReference(
                                    name=tname,
                                    target_urn_or_path=tname,
                                    resource_type="MCP_TOOL",
                                    is_mandatory=True
                                ))
                                seen_names.add(tname)
                except Exception as e:
                    logger.debug(f"Frontmatter dependency parsing error: {e}")

        # Extract markdown file references e.g. [script](scripts/deploy.py)
        link_matches = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', raw_text)
        for link_text, link_target in link_matches:
            clean_target = link_target.split("#")[0].strip().replace("\\", "/").lstrip("./")
            if clean_target.startswith(("http://", "https://", "mailto:")):
                continue

            # Classify auxiliary file dependency
            ext = os.path.splitext(clean_target)[1].lower()
            rtype = "DOCUMENTATION"
            if ext in (".py", ".sh", ".bash", ".js", ".ts"):
                rtype = "SCRIPT"
            elif ext in (".j2", ".jinja", ".template"):
                rtype = "TEMPLATE"

            if clean_target not in seen_names and (clean_target in auxiliary_files or (bundle_root and os.path.exists(os.path.join(bundle_root, clean_target)))):
                deps.append(DependencyReference(
                    name=clean_target,
                    target_urn_or_path=clean_target,
                    resource_type=rtype,
                    is_mandatory=True,
                    description=link_text
                ))
                seen_names.add(clean_target)

        return deps

    def _find_missing_dependencies(
        self,
        dependencies: List[DependencyReference],
        auxiliary_files: Dict[str, AuxiliaryFileRecord]
    ) -> List[str]:
        """Identifies missing mandatory dependencies."""
        missing = []
        cur = self.conn.cursor()

        for dep in dependencies:
            if not dep.is_mandatory:
                continue

            # Case A: Local auxiliary bundle file
            norm_target = dep.target_urn_or_path.replace("\\", "/").lstrip("./")
            if norm_target in auxiliary_files:
                continue

            # Case B: Registered catalog capability URN or name
            cur.execute("""
                SELECT count(*) FROM artifact_discovery_records
                WHERE canonical_urn = ? OR name = ?;
            """, (dep.target_urn_or_path, dep.name))
            if cur.fetchone()[0] > 0:
                continue

            # Case C: MCP server registration
            try:
                cur.execute("SELECT count(*) FROM mcp_server_registrations WHERE server_name = ?;", (dep.name,))
                if cur.fetchone()[0] > 0:
                    continue
            except Exception:
                pass

            missing.append(dep.name)

        return missing
