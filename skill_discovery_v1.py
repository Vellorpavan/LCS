#!/usr/bin/env python3
"""
LCS Stage 1 — Skill Intelligence V1: Discovery Foundation
=========================================================
Implements the foundational discovery, dynamic root resolution, multi-environment
adapter crawling (Antigravity, Claude Code, OpenCode), artifact taxonomy
classification, descriptor-relative safe reading, exact-byte preservation, and
deterministic bundle manifest digest calculation.

Governed strictly by: lcs_skill_intelligence_v1_architecture.md
Complies with LCS Core Invariants:
  - Zero arbitrary code execution (passive parsing only).
  - Zero tool / subprocess / shell execution.
  - Zero network access.
  - Descriptor-relative TOCTOU and symlink escape defenses.
  - Untrusted data posture and quarantine isolation.
"""

import os
import sys
import stat
import json
import uuid
import hashlib
import re
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from datetime import datetime, timezone
import errno

# Reusable RFC 8785 JSON Canonicalization Scheme (JCS) serializer
from governance_policy_v1 import canonicalize_jcs


# ============================================================================
# 1. Constants & Security Limits
# ============================================================================

MAX_INSTRUCTION_FILE_SIZE = 1 * 1024 * 1024      # 1 MB for Markdown / text instructions
MAX_ASSET_FILE_SIZE = 5 * 1024 * 1024            # 5 MB for auxiliary assets / scripts
MAX_DIRECTORY_RECURSION_DEPTH = 5                # Maximum traversal recursion depth


# ============================================================================
# 2. Exceptions
# ============================================================================

class SkillDiscoveryError(Exception):
    """Base exception for LCS Skill Discovery errors."""
    pass


class PathTraversalSecurityError(SkillDiscoveryError):
    """Raised when an inspected path resolves outside authorized discovery roots."""
    pass


class DescriptorSecurityError(SkillDiscoveryError):
    """Raised when a file descriptor violates safety checks (FIFO, device, socket, symlink)."""
    pass


class FileSizeExceededError(SkillDiscoveryError):
    """Raised when a candidate file exceeds configured size boundaries."""
    pass


class SymlinkCycleError(SkillDiscoveryError):
    """Raised when directory traversal encounters a circular symlink cycle."""
    pass


class MalformedArtifactError(SkillDiscoveryError):
    """Raised when an artifact structure cannot be parsed or is corrupted."""
    pass


# ============================================================================
# 3. Taxonomy & Enums
# ============================================================================

class ArtifactTaxonomyKind(str, Enum):
    """
    Formal 5-tier artifact taxonomy plus failure/ambiguity states.
    Prevents conflating all Markdown prompt files as 'skills'.
    """
    SKILL = "SKILL"
    COMMAND = "COMMAND"
    RULE = "RULE"
    AGENT_INSTRUCTION = "AGENT_INSTRUCTION"
    AGENT_CONFIGURATION = "AGENT_CONFIGURATION"
    UNKNOWN_ARTIFACT = "UNKNOWN_ARTIFACT"
    UNSUPPORTED_ARTIFACT = "UNSUPPORTED_ARTIFACT"


class EnvironmentOrigin(str, Enum):
    """Identifies the discovering environment adapter."""
    GOOGLE_ANTIGRAVITY = "ANTIGRAVITY"
    ANTIGRAVITY = "ANTIGRAVITY"
    CLAUDE_CODE = "CLAUDE_CODE"
    OPENCODE = "OPENCODE"
    GENERIC_WORKSPACE = "GENERIC_WORKSPACE"


class PrecedenceTier(int, Enum):
    """Precedence hierarchy for context-aware override resolution."""
    SYSTEM_BUILTIN = 1
    USER_GLOBAL = 2
    GLOBAL_ENVIRONMENT = 2
    WORKSPACE = 3


class SkillLifecycleState(str, Enum):
    """
    V1 Lifecycle states terminating at AVAILABLE.
    Runtime execution (ACTIVATED, VERIFIED) is deferred to future runtime milestones.
    """
    DISCOVERED = "DISCOVERED"
    READ = "READ"
    UNDERSTOOD = "UNDERSTOOD"
    INDEXED = "INDEXED"
    AVAILABLE = "AVAILABLE"
    QUARANTINED = "QUARANTINED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"


# ============================================================================
# 4. Data Models: Discovered Artifact & Provenance Record
# ============================================================================

@dataclass
class DiscoveredArtifactRecord:
    """
    Represents an immutable discovery record for a single artifact on disk.
    Preserves raw filesystem provenance, exact byte digest, and taxonomy kind.
    """
    artifact_id: str
    name: str
    display_name: str
    taxonomy_kind: ArtifactTaxonomyKind
    environment_origin: EnvironmentOrigin
    precedence_tier: PrecedenceTier
    source_path: str
    resolved_path: str
    is_bundle: bool
    bundle_root_path: Optional[str]
    file_size_bytes: int
    st_mtime: float
    st_ino: int
    st_dev: int
    raw_content_digest: str                     # SHA-256 of root instruction file
    bundle_manifest_digest: Optional[str]       # Deterministic bundle manifest digest
    canonical_urn: str
    lifecycle_state: SkillLifecycleState
    provenance: Dict[str, Any] = field(default_factory=dict)
    quarantine_reasons: List[str] = field(default_factory=list)

    @property
    def content_sha256(self) -> str:
        return self.raw_content_digest

    @property
    def size_bytes(self) -> int:
        return self.file_size_bytes

    @property
    def origin_environment(self) -> EnvironmentOrigin:
        return self.environment_origin

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["taxonomy_kind"] = self.taxonomy_kind.value
        d["environment_origin"] = self.environment_origin.value
        d["precedence_tier"] = self.precedence_tier.value
        d["lifecycle_state"] = self.lifecycle_state.value
        return d


# ============================================================================
# 5. Safe Filesystem Traversal & Descriptor-Relative Reader
# ============================================================================

class SafeFileReader:
    """
    Reads files safely using POSIX descriptor-relative operations (O_NOFOLLOW / O_CLOEXEC)
    and fstat verification, eliminating Time-of-Check / Time-of-Use (TOCTOU) symlink swaps.
    """

    @staticmethod
    def read_exact_bytes(
        path: str,
        max_size: int = MAX_INSTRUCTION_FILE_SIZE,
        max_bytes: Optional[int] = None
    ) -> Tuple[bytes, os.stat_result]:
        """
        Safely opens and reads exact raw bytes from path via file descriptor inspection.
        Returns (bytes, stat_result). Preserves exact bytes without normalization.
        """
        limit = max_bytes if max_bytes is not None else max_size
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
        # Apply O_NOFOLLOW if supported on the operating system
        if hasattr(os, "O_NOFOLLOW") and os.O_NOFOLLOW != 0:
            flags |= os.O_NOFOLLOW
        else:
            if os.path.islink(path):
                raise DescriptorSecurityError(f"Symlink rejected on platform lacking O_NOFOLLOW: {path}")

        try:
            fd = os.open(path, flags)
        except OSError as e:
            if getattr(e, "errno", None) in (getattr(errno, "ELOOP", 62), getattr(errno, "EMLINK", 31)) or os.path.islink(path):
                raise DescriptorSecurityError(f"Symlink rejected by O_NOFOLLOW: {path} ({e})") from e
            raise DescriptorSecurityError(f"Failed to open descriptor for '{path}': {e}") from e

        try:
            st = os.fstat(fd)
            # Ensure descriptor points to a regular file
            if not stat.S_ISREG(st.st_mode):
                raise DescriptorSecurityError(
                    f"Descriptor target for '{path}' is not a regular file (mode: {oct(st.st_mode)})"
                )

            # Enforce size ceiling
            if st.st_size > limit:
                raise FileSizeExceededError(
                    f"File '{path}' size {st.st_size} bytes exceeds maximum allowed limit of {limit} bytes"
                )

            # Read directly from descriptor
            content = os.read(fd, limit + 1)
            if len(content) > limit:
                raise FileSizeExceededError(
                    f"File '{path}' exceeded maximum size during read ({len(content)} > {limit})"
                )

            return content, st
        finally:
            os.close(fd)


# ============================================================================
# 6. Dynamic Discovery Root Resolver
# ============================================================================

class DiscoveryRootResolver:
    """
    Dynamically resolves authorized discovery roots across Antigravity, Claude Code,
    and OpenCode without any machine-specific hardcoded paths.
    Enforces strict path confinement via os.path.commonpath.
    """

    def __init__(
        self,
        workspace_root: Optional[str] = None,
        home_dir: Optional[str] = None,
        canonical_lcs_root: Optional[str] = None
    ):
        self.workspace_root = os.path.realpath(workspace_root) if workspace_root else os.path.realpath(os.getcwd())
        self.user_home = os.path.realpath(home_dir) if home_dir else os.path.realpath(os.path.expanduser("~"))
        self.canonical_lcs_root = os.path.realpath(canonical_lcs_root) if canonical_lcs_root else self.workspace_root

    @property
    def antigravity_global(self) -> str:
        return os.path.realpath(os.path.join(self.user_home, ".gemini", "config", "skills"))

    @property
    def antigravity_builtin(self) -> str:
        return os.path.realpath(os.path.join(self.user_home, ".gemini", "antigravity", "builtin", "skills"))

    @property
    def antigravity_plugins(self) -> str:
        return os.path.realpath(os.path.join(self.user_home, ".gemini", "config", "plugins"))

    @property
    def claude_global(self) -> str:
        return os.path.realpath(os.path.join(self.user_home, ".claude"))

    @property
    def agents_global(self) -> str:
        return os.path.realpath(os.path.join(self.user_home, ".agents", "skills"))

    @property
    def agents_workspace(self) -> str:
        return os.path.realpath(os.path.join(self.workspace_root, ".agents", "skills"))

    @property
    def claude_workspace(self) -> str:
        return os.path.realpath(os.path.join(self.workspace_root, ".claude"))

    @property
    def opencode_workspace(self) -> str:
        return os.path.realpath(os.path.join(self.workspace_root, ".opencode"))

    @property
    def lcs_root(self) -> str:
        return self.canonical_lcs_root

    def get_all_authorized_roots(self) -> List[str]:
        """Returns all dynamically defined authorized root paths (existing or prospective)."""
        roots = [
            self.workspace_root,
            self.antigravity_global,
            self.antigravity_builtin,
            self.antigravity_plugins,
            self.claude_global,
            self.agents_global,
            self.agents_workspace,
            self.claude_workspace,
            self.opencode_workspace,
            self.lcs_root
        ]
        seen: Set[str] = set()
        out: List[str] = []
        for r in roots:
            rp = os.path.realpath(r)
            if rp not in seen:
                seen.add(rp)
                out.append(rp)
        return out

    def get_authorized_roots(self) -> List[str]:
        """Returns the deduplicated list of authorized realpath discovery roots that exist on disk."""
        return [r for r in self.get_all_authorized_roots() if os.path.exists(r)]

    def is_path_confined(self, path: str, authorized_roots: Optional[List[str]] = None) -> bool:
        """Checks whether the canonical realpath of path lies within at least one authorized root."""
        roots = authorized_roots or self.get_all_authorized_roots()
        resolved = os.path.realpath(path)
        for r in roots:
            try:
                if os.path.commonpath([resolved, r]) == r:
                    return True
            except ValueError:
                continue
        return False

    def is_confined(self, path: str, authorized_roots: Optional[List[str]] = None) -> bool:
        """Convenience alias for is_path_confined."""
        return self.is_path_confined(path, authorized_roots)

    def assert_path_confined(self, path: str, authorized_roots: Optional[List[str]] = None) -> str:
        """
        Asserts path confinement. Returns resolved canonical path or raises PathTraversalSecurityError.
        """
        roots = authorized_roots or self.get_all_authorized_roots()
        resolved = os.path.realpath(path)
        if not self.is_path_confined(resolved, roots):
            raise PathTraversalSecurityError(
                f"PATH_TRAVERSAL_DETECTED: Target path '{path}' (resolved: '{resolved}') "
                f"escapes all authorized discovery roots: {roots}"
            )
        return resolved

    def assert_confined(self, path: str, authorized_roots: Optional[List[str]] = None) -> str:
        """Convenience alias for assert_path_confined."""
        return self.assert_path_confined(path, authorized_roots)


# ============================================================================
# 7. Artifact Taxonomy Classifier
# ============================================================================

class ArtifactTaxonomyClassifier:
    """
    Classifies discovered files into the 5-tier taxonomy or flags them as
    UNKNOWN_ARTIFACT / UNSUPPORTED_ARTIFACT. Strictly enforces the No Forced
    Categorization Invariant.
    """

    @classmethod
    def classify(
        cls,
        file_path: str,
        env_origin: Optional[EnvironmentOrigin] = None,
        raw_header: bytes = b""
    ) -> Tuple[ArtifactTaxonomyKind, str]:
        """
        High-level classifier helper that inspects the file header if not provided.
        """
        if not raw_header and os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    raw_header = f.read(4096)
            except OSError:
                pass
        return cls.classify_file(file_path, env_origin or EnvironmentOrigin.ANTIGRAVITY, raw_header)

    @staticmethod
    def extract_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
        """
        Extracts YAML frontmatter metadata and body from markdown text using safe YAML parsing.
        """
        if not text.startswith("---"):
            return {}, text
        parts = text.split("---", 2)
        if len(parts) < 3:
            return {}, text
        fm_block = parts[1]
        body = parts[2].lstrip("\r\n")

        metadata: Dict[str, Any] = {}
        try:
            import yaml
            parsed = yaml.safe_load(fm_block)
            if isinstance(parsed, dict):
                metadata = parsed
                return metadata, body
        except Exception:
            pass

        # Fallback to key-value parser if YAML parser fails
        for line in fm_block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip().strip("\"'")
                metadata[k] = v
        return metadata, body

    @staticmethod
    def classify_file(
        file_path: str,
        env_origin: EnvironmentOrigin,
        raw_header: bytes = b""
    ) -> Tuple[ArtifactTaxonomyKind, str]:
        """
        Classifies an artifact given its path, environment, and initial header bytes.
        Returns (ArtifactTaxonomyKind, classification_reason).
        """
        norm_path = file_path.replace("\\", "/")
        base_name = os.path.basename(file_path)

        # 1. Non-text / unsupported extensions
        ext = os.path.splitext(base_name)[1].lower()
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".ico", ".blend", ".tar", ".gz", ".zip", ".exe", ".so", ".dylib"):
            return ArtifactTaxonomyKind.UNSUPPORTED_ARTIFACT, f"Binary/media extension '{ext}' is unsupported"
        if ext in (".py", ".sh", ".js", ".ts", ".rs", ".go") and not base_name.startswith("SKILL"):
            return ArtifactTaxonomyKind.UNSUPPORTED_ARTIFACT, f"Raw code script '{base_name}' without manifest"

        # 2. SKILL classification (must be SKILL.md or inside a skill bundle)
        if base_name == "SKILL.md":
            # Check for YAML frontmatter indicators in header
            try:
                header_text = raw_header.decode("utf-8", errors="replace")
                if header_text.startswith("---") and ("name:" in header_text or "description:" in header_text):
                    return ArtifactTaxonomyKind.SKILL, "Standard SKILL.md with YAML frontmatter"
                elif header_text.startswith("#"):
                    return ArtifactTaxonomyKind.SKILL, "SKILL.md with top-level markdown heading"
                else:
                    return ArtifactTaxonomyKind.UNKNOWN_ARTIFACT, "SKILL.md lacks frontmatter or valid markdown heading"
            except Exception as e:
                return ArtifactTaxonomyKind.UNKNOWN_ARTIFACT, f"Corrupted SKILL.md text encoding: {e}"

        # 3. COMMAND classification
        if "/commands/" in norm_path or norm_path.endswith(".command.md"):
            if ext == ".md":
                return ArtifactTaxonomyKind.COMMAND, "Markdown file located in a commands/ directory"

        # 4. RULE classification
        if "/rules/" in norm_path or base_name in ("CLAUDE.md", ".cursorrules") or ".rule." in base_name:
            if ext in (".md", ""):
                return ArtifactTaxonomyKind.RULE, f"Ambient rule file ('{base_name}') in rules/ or root context"

        # 5. AGENT_INSTRUCTION classification
        if "/instructions/" in norm_path or "/prompts/" in norm_path or base_name in ("AGENTS.md", "instructions.md"):
            if ext == ".md":
                return ArtifactTaxonomyKind.AGENT_INSTRUCTION, f"Instruction prompt ('{base_name}') located in instructions/, prompts/, or root"

        # 6. AGENT_CONFIGURATION classification
        if base_name in ("opencode.json", "agent.json") or "/agents/" in norm_path and ext in (".json", ".yaml", ".yml"):
            return ArtifactTaxonomyKind.AGENT_CONFIGURATION, f"Agent structural configuration ('{base_name}')"

        # 7. Unclassified Markdown
        if ext == ".md":
            return ArtifactTaxonomyKind.UNKNOWN_ARTIFACT, f"Unannotated Markdown file '{base_name}' outside standard conventions"

        return ArtifactTaxonomyKind.UNSUPPORTED_ARTIFACT, f"Unsupported file extension '{ext}' for operational intelligence"


# ============================================================================
# 8. Deterministic Bundle Manifest Hasher
# ============================================================================

class BundleManifestHasher:
    """
    Computes a Deterministic Bundle Manifest Digest over auxiliary directory assets
    using sorted relative paths and RFC 8785 JCS canonicalization.
    """

    @staticmethod
    def compute_bundle_digest(bundle_files: List[Dict[str, Any]]) -> str:
        """
        Computes deterministic SHA-256 digest over a list of bundle file metadata dicts.
        Sorts items by UTF-8 relative path and canonicalizes via RFC 8785 JCS.
        """
        def sort_key(item: Dict[str, Any]):
            p = item.get("path") or item.get("relative_path") or ""
            return p.encode("utf-8")

        sorted_files = sorted(bundle_files, key=sort_key)
        manifest_dict = {
            "assets": sorted_files,
            "schema_version": "lcs.skill.bundle.v1"
        }
        canonical_bytes = canonicalize_jcs(manifest_dict)
        return hashlib.sha256(canonical_bytes).hexdigest()

    @staticmethod
    def compute_bundle_manifest(
        bundle_dir: str,
        root_filename: str = "SKILL.md",
        resolver: Optional[DiscoveryRootResolver] = None
    ) -> Tuple[str, bytes, List[Dict[str, Any]]]:
        """
        Walks bundle_dir safely, hashes all auxiliary files (scripts, references, templates),
        canonicalizes via JCS, and computes the deterministic bundle manifest SHA-256 digest.
        Returns (bundle_manifest_digest, canonical_manifest_bytes, asset_records).
        """
        res_dir = os.path.realpath(bundle_dir)
        if resolver:
            resolver.assert_path_confined(res_dir)

        root_file_path = os.path.join(res_dir, root_filename)
        if not os.path.exists(root_file_path):
            raise MalformedArtifactError(f"Bundle directory '{bundle_dir}' lacks root file '{root_filename}'")

        root_bytes, _ = SafeFileReader.read_exact_bytes(root_file_path, MAX_INSTRUCTION_FILE_SIZE)
        root_sha = hashlib.sha256(root_bytes).hexdigest()

        collected_assets: List[Tuple[str, str]] = []
        visited_inodes: Set[Tuple[int, int]] = set()

        # Walk auxiliary directory assets with depth limit <= 5
        base_depth = len(res_dir.rstrip(os.sep).split(os.sep))

        for root, dirs, files in os.walk(res_dir, followlinks=False):
            cur_depth = len(root.split(os.sep)) - base_depth
            if cur_depth > MAX_DIRECTORY_RECURSION_DEPTH:
                dirs.clear()
                continue

            try:
                st = os.stat(root)
                inode_key = (st.st_dev, st.st_ino)
                if inode_key in visited_inodes:
                    raise SymlinkCycleError(f"Symlink directory cycle detected at '{root}'")
                visited_inodes.add(inode_key)
            except OSError:
                continue

            for f in files:
                if f == root_filename and root == res_dir:
                    continue  # Root instruction file handled separately

                file_path = os.path.join(root, f)
                rel_path = os.path.relpath(file_path, res_dir).replace("\\", "/")

                # Skip hidden files and cache dirs
                if any(part.startswith(".") for part in rel_path.split("/")):
                    continue
                if "__pycache__" in rel_path:
                    continue

                try:
                    # Read asset via descriptor-relative safe reader (max 5 MB)
                    asset_bytes, _ = SafeFileReader.read_exact_bytes(file_path, MAX_ASSET_FILE_SIZE)
                    asset_sha = hashlib.sha256(asset_bytes).hexdigest()
                    collected_assets.append((rel_path, asset_sha))
                except (FileSizeExceededError, DescriptorSecurityError):
                    # Record corrupted/oversized assets safely
                    collected_assets.append((rel_path, "sha256:oversized_or_inaccessible"))

        # Lexicographically sort relative paths by UTF-8 bytes
        collected_assets.sort(key=lambda item: item[0].encode("utf-8"))

        manifest_dict = {
            "assets": [
                {"path": item[0], "sha256": item[1]}
                for item in collected_assets
            ],
            "root_file": {
                "path": root_filename,
                "sha256": root_sha
            },
            "schema_version": "lcs.skill.bundle.v1"
        }

        canonical_bytes = canonicalize_jcs(manifest_dict)
        bundle_digest = hashlib.sha256(canonical_bytes).hexdigest()

        asset_records = [
            {"relative_path": p, "blob_digest": h}
            for p, h in collected_assets
        ]

        return bundle_digest, canonical_bytes, asset_records


# ============================================================================
# 9. Discovery Adapters (Antigravity, Claude Code, OpenCode)
# ============================================================================

class AntigravityDiscoveryAdapter:
    """Discovers Antigravity skills, builtins, plugins, and workspace skills."""

    def __init__(self, resolver: DiscoveryRootResolver):
        self.resolver = resolver

    def discover(self) -> List[DiscoveredArtifactRecord]:
        records: List[DiscoveredArtifactRecord] = []
        user_home = self.resolver.user_home
        ws_root = self.resolver.workspace_root

        search_targets = [
            # (path, precedence_tier, is_plugin_dir)
            (os.path.join(user_home, ".gemini", "config", "skills"), PrecedenceTier.USER_GLOBAL, False),
            (os.path.join(user_home, ".gemini", "antigravity", "builtin", "skills"), PrecedenceTier.SYSTEM_BUILTIN, False),
            (os.path.join(user_home, ".gemini", "config", "plugins"), PrecedenceTier.USER_GLOBAL, True),
            (os.path.join(ws_root, ".agents", "skills"), PrecedenceTier.WORKSPACE, False),
            (os.path.join(ws_root, ".gemini", "skills"), PrecedenceTier.WORKSPACE, False),
        ]

        for base_dir, tier, is_plugin in search_targets:
            if not os.path.exists(base_dir):
                continue

            if is_plugin:
                # Plugins directory structure: plugins/<plugin_name>/skills/<skill_name>/SKILL.md
                try:
                    for plugin_name in os.listdir(base_dir):
                        p_skills = os.path.join(base_dir, plugin_name, "skills")
                        if os.path.isdir(p_skills):
                            self._scan_skills_dir(p_skills, tier, records, plugin_name=plugin_name)
                except OSError:
                    continue
            else:
                self._scan_skills_dir(base_dir, tier, records)

        return records

    def _scan_skills_dir(
        self,
        skills_dir: str,
        tier: PrecedenceTier,
        out_records: List[DiscoveredArtifactRecord],
        plugin_name: Optional[str] = None
    ) -> None:
        try:
            entries = os.listdir(skills_dir)
        except OSError:
            return

        for entry in entries:
            entry_path = os.path.join(skills_dir, entry)
            # Check if this is a directory containing SKILL.md (or symlink to one)
            skill_md = os.path.join(entry_path, "SKILL.md") if os.path.isdir(entry_path) else entry_path

            if not os.path.exists(skill_md):
                continue

            # Verify path confinement
            try:
                resolved_skill_md = self.resolver.assert_path_confined(skill_md)
            except PathTraversalSecurityError as e:
                # Quarantined due to escaping authorized roots
                out_records.append(self._create_quarantined_record(
                    skill_md, entry, tier, EnvironmentOrigin.ANTIGRAVITY, [str(e)]
                ))
                continue

            is_bundle = os.path.isdir(entry_path) and any(
                os.path.exists(os.path.join(entry_path, sub))
                for sub in ("scripts", "references", "examples", "resources")
            )

            # Read raw bytes safely
            try:
                raw_bytes, st = SafeFileReader.read_exact_bytes(resolved_skill_md, MAX_INSTRUCTION_FILE_SIZE)
                raw_digest = hashlib.sha256(raw_bytes).hexdigest()
            except Exception as e:
                out_records.append(self._create_quarantined_record(
                    skill_md, entry, tier, EnvironmentOrigin.ANTIGRAVITY, [f"Read failed: {e}"]
                ))
                continue

            # Classify taxonomy
            tax_kind, _ = ArtifactTaxonomyClassifier.classify_file(
                resolved_skill_md, EnvironmentOrigin.ANTIGRAVITY, raw_bytes[:4096]
            )

            # Calculate bundle manifest if it's a directory bundle
            bundle_manifest_digest = None
            if is_bundle:
                try:
                    bundle_manifest_digest, _, _ = BundleManifestHasher.compute_bundle_manifest(
                        entry_path, resolver=self.resolver
                    )
                except Exception as e:
                    bundle_manifest_digest = None

            clean_name = re.sub(r"[^a-z0-9_-]", "-", entry.lower()).strip("-")
            ns_prefix = f"antigravity.{'plugin.' + plugin_name if plugin_name else 'global' if tier == PrecedenceTier.USER_GLOBAL else 'builtin' if tier == PrecedenceTier.SYSTEM_BUILTIN else 'workspace'}"
            urn = f"urn:lcs:skill:{ns_prefix}:{clean_name}"

            display_name = " ".join(word.capitalize() for word in clean_name.replace("_", "-").split("-"))

            rec = DiscoveredArtifactRecord(
                artifact_id=f"art-{uuid.uuid4().hex[:12]}",
                name=clean_name,
                display_name=display_name,
                taxonomy_kind=tax_kind,
                environment_origin=EnvironmentOrigin.ANTIGRAVITY,
                precedence_tier=tier,
                source_path=skill_md,
                resolved_path=resolved_skill_md,
                is_bundle=is_bundle,
                bundle_root_path=entry_path if is_bundle else None,
                file_size_bytes=len(raw_bytes),
                st_mtime=st.st_mtime,
                st_ino=st.st_ino,
                st_dev=st.st_dev,
                raw_content_digest=raw_digest,
                bundle_manifest_digest=bundle_manifest_digest,
                canonical_urn=urn,
                lifecycle_state=SkillLifecycleState.DISCOVERED,
                provenance={
                    "adapter": "AntigravityDiscoveryAdapter",
                    "plugin_name": plugin_name,
                    "tier_name": tier.name,
                    "discovery_root": skills_dir,
                    "entrypoint_path": resolved_skill_md,
                    "discovered_at_iso": datetime.now(timezone.utc).isoformat()
                }
            )
            out_records.append(rec)

    def _create_quarantined_record(
        self,
        path: str,
        name: str,
        tier: PrecedenceTier,
        env: EnvironmentOrigin,
        reasons: List[str]
    ) -> DiscoveredArtifactRecord:
        clean_name = re.sub(r"[^a-z0-9_-]", "-", name.lower()).strip("-")
        return DiscoveredArtifactRecord(
            artifact_id=f"art-quarantine-{uuid.uuid4().hex[:8]}",
            name=clean_name or "quarantined",
            display_name=clean_name.capitalize(),
            taxonomy_kind=ArtifactTaxonomyKind.UNKNOWN_ARTIFACT,
            environment_origin=env,
            precedence_tier=tier,
            source_path=path,
            resolved_path=os.path.realpath(path),
            is_bundle=False,
            bundle_root_path=None,
            file_size_bytes=0,
            st_mtime=0.0,
            st_ino=0,
            st_dev=0,
            raw_content_digest="sha256:quarantined",
            bundle_manifest_digest=None,
            canonical_urn=f"urn:lcs:skill:quarantined:{clean_name}",
            lifecycle_state=SkillLifecycleState.QUARANTINED,
            provenance={"adapter": "AntigravityDiscoveryAdapter", "error": reasons},
            quarantine_reasons=reasons
        )


class ClaudeCodeDiscoveryAdapter:
    """Discovers Claude Code skills, commands, rules, and workspace assets."""

    def __init__(self, resolver: DiscoveryRootResolver):
        self.resolver = resolver

    def discover(self) -> List[DiscoveredArtifactRecord]:
        records: List[DiscoveredArtifactRecord] = []
        user_home = self.resolver.user_home
        ws_root = self.resolver.workspace_root

        # 1. Claude global skills
        claude_global_skills = os.path.join(user_home, ".claude", "skills")
        self._scan_skills(claude_global_skills, PrecedenceTier.USER_GLOBAL, records)

        # 2. Claude workspace skills
        claude_ws_skills = os.path.join(ws_root, ".claude", "skills")
        self._scan_skills(claude_ws_skills, PrecedenceTier.WORKSPACE, records)

        # 3. Claude commands (global & workspace)
        claude_global_cmds = os.path.join(user_home, ".claude", "commands")
        self._scan_commands(claude_global_cmds, PrecedenceTier.USER_GLOBAL, records)
        claude_ws_cmds = os.path.join(ws_root, ".claude", "commands")
        self._scan_commands(claude_ws_cmds, PrecedenceTier.WORKSPACE, records)

        # 4. Claude rules (global & workspace)
        claude_rules_dir = os.path.join(user_home, ".claude", "rules")
        self._scan_rules(claude_rules_dir, PrecedenceTier.USER_GLOBAL, records)
        claude_md = os.path.join(ws_root, "CLAUDE.md")
        if os.path.exists(claude_md):
            self._scan_single_file(claude_md, PrecedenceTier.WORKSPACE, ArtifactTaxonomyKind.RULE, records)

        # 5. Claude agent instructions
        agents_md = os.path.join(ws_root, "AGENTS.md")
        if os.path.exists(agents_md):
            self._scan_single_file(agents_md, PrecedenceTier.WORKSPACE, ArtifactTaxonomyKind.AGENT_INSTRUCTION, records)

        return records

    def _scan_skills(self, skills_dir: str, tier: PrecedenceTier, out_records: List[DiscoveredArtifactRecord]) -> None:
        if not os.path.exists(skills_dir):
            return
        try:
            for entry in os.listdir(skills_dir):
                entry_path = os.path.join(skills_dir, entry)
                skill_md = os.path.join(entry_path, "SKILL.md") if os.path.isdir(entry_path) else entry_path
                if os.path.exists(skill_md):
                    self._ingest_file(skill_md, entry, tier, EnvironmentOrigin.CLAUDE_CODE, ArtifactTaxonomyKind.SKILL, out_records, is_bundle=os.path.isdir(entry_path), bundle_root=entry_path if os.path.isdir(entry_path) else None)
        except OSError:
            pass

    def _scan_commands(self, cmds_dir: str, tier: PrecedenceTier, out_records: List[DiscoveredArtifactRecord]) -> None:
        if not os.path.exists(cmds_dir):
            return
        try:
            for f in os.listdir(cmds_dir):
                if f.endswith(".md"):
                    p = os.path.join(cmds_dir, f)
                    name = f[:-3]
                    self._ingest_file(p, name, tier, EnvironmentOrigin.CLAUDE_CODE, ArtifactTaxonomyKind.COMMAND, out_records)
        except OSError:
            pass

    def _scan_rules(self, rules_dir: str, tier: PrecedenceTier, out_records: List[DiscoveredArtifactRecord]) -> None:
        if not os.path.exists(rules_dir):
            return
        try:
            for f in os.listdir(rules_dir):
                if f.endswith(".md"):
                    p = os.path.join(rules_dir, f)
                    name = f[:-3]
                    self._ingest_file(p, name, tier, EnvironmentOrigin.CLAUDE_CODE, ArtifactTaxonomyKind.RULE, out_records)
        except OSError:
            pass

    def _scan_single_file(self, path: str, tier: PrecedenceTier, kind: ArtifactTaxonomyKind, out_records: List[DiscoveredArtifactRecord]) -> None:
        name = os.path.splitext(os.path.basename(path))[0]
        self._ingest_file(path, name, tier, EnvironmentOrigin.CLAUDE_CODE, kind, out_records)

    def _ingest_file(
        self,
        path: str,
        name: str,
        tier: PrecedenceTier,
        env: EnvironmentOrigin,
        expected_kind: ArtifactTaxonomyKind,
        out_records: List[DiscoveredArtifactRecord],
        is_bundle: bool = False,
        bundle_root: Optional[str] = None
    ) -> None:
        try:
            res_path = self.resolver.assert_path_confined(path)
            raw_bytes, st = SafeFileReader.read_exact_bytes(res_path, MAX_INSTRUCTION_FILE_SIZE)
            raw_digest = hashlib.sha256(raw_bytes).hexdigest()
        except Exception as e:
            out_records.append(DiscoveredArtifactRecord(
                artifact_id=f"art-err-{uuid.uuid4().hex[:8]}",
                name=name,
                display_name=name.capitalize(),
                taxonomy_kind=ArtifactTaxonomyKind.UNKNOWN_ARTIFACT,
                environment_origin=env,
                precedence_tier=tier,
                source_path=path,
                resolved_path=os.path.realpath(path),
                is_bundle=is_bundle,
                bundle_root_path=bundle_root,
                file_size_bytes=0,
                st_mtime=0.0,
                st_ino=0,
                st_dev=0,
                raw_content_digest="sha256:error",
                bundle_manifest_digest=None,
                canonical_urn=f"urn:lcs:{expected_kind.value.lower()}:quarantined:{name}",
                lifecycle_state=SkillLifecycleState.QUARANTINED,
                quarantine_reasons=[str(e)]
            ))
            return

        tax_kind, _ = ArtifactTaxonomyClassifier.classify_file(res_path, env, raw_bytes[:4096])
        if tax_kind in (ArtifactTaxonomyKind.UNKNOWN_ARTIFACT, ArtifactTaxonomyKind.UNSUPPORTED_ARTIFACT):
            tax_kind = expected_kind

        bundle_manifest_digest = None
        if is_bundle and bundle_root:
            try:
                bundle_manifest_digest, _, _ = BundleManifestHasher.compute_bundle_manifest(bundle_root, resolver=self.resolver)
            except Exception:
                bundle_manifest_digest = None

        clean_name = re.sub(r"[^a-z0-9_-]", "-", name.lower()).strip("-")
        kind_prefix = "command" if tax_kind == ArtifactTaxonomyKind.COMMAND else "rule" if tax_kind == ArtifactTaxonomyKind.RULE else "skill"
        ns_prefix = f"claude.{'workspace' if tier == PrecedenceTier.WORKSPACE else 'global'}"
        urn = f"urn:lcs:{kind_prefix}:{ns_prefix}:{clean_name}"

        out_records.append(DiscoveredArtifactRecord(
            artifact_id=f"art-{uuid.uuid4().hex[:12]}",
            name=clean_name,
            display_name=" ".join(w.capitalize() for w in clean_name.replace("_", "-").split("-")),
            taxonomy_kind=tax_kind,
            environment_origin=env,
            precedence_tier=tier,
            source_path=path,
            resolved_path=res_path,
            is_bundle=is_bundle,
            bundle_root_path=bundle_root,
            file_size_bytes=len(raw_bytes),
            st_mtime=st.st_mtime,
            st_ino=st.st_ino,
            st_dev=st.st_dev,
            raw_content_digest=raw_digest,
            bundle_manifest_digest=bundle_manifest_digest,
            canonical_urn=urn,
            lifecycle_state=SkillLifecycleState.DISCOVERED,
            provenance={
                "adapter": "ClaudeCodeDiscoveryAdapter",
                "discovery_path": path,
                "entrypoint_path": res_path,
                "discovered_at_iso": datetime.now(timezone.utc).isoformat()
            }
        ))


class OpenCodeDiscoveryAdapter:
    """Discovers OpenCode declared instructions, commands, and agent configs."""

    def __init__(self, resolver: DiscoveryRootResolver):
        self.resolver = resolver

    def discover(self) -> List[DiscoveredArtifactRecord]:
        records: List[DiscoveredArtifactRecord] = []
        user_home = self.resolver.user_home
        ws_root = self.resolver.workspace_root

        manifest_candidates = [
            os.path.join(ws_root, "opencode.json"),
            os.path.join(ws_root, ".opencode", "opencode.json"),
            os.path.join(user_home, ".claude", ".opencode", "opencode.json")
        ]

        for m_path in manifest_candidates:
            if not os.path.exists(m_path):
                continue

            try:
                res_m_path = self.resolver.assert_path_confined(m_path)
                raw_bytes, st = SafeFileReader.read_exact_bytes(res_m_path, MAX_INSTRUCTION_FILE_SIZE)
                config_data = json.loads(raw_bytes.decode("utf-8"))
            except Exception as e:
                continue

            manifest_dir = os.path.dirname(res_m_path)
            tier = PrecedenceTier.WORKSPACE if self.resolver.is_path_confined(m_path, [ws_root]) else PrecedenceTier.USER_GLOBAL

            # Record the agent configuration itself
            records.append(DiscoveredArtifactRecord(
                artifact_id=f"art-{uuid.uuid4().hex[:12]}",
                name="opencode-config",
                display_name="OpenCode Manifest Configuration",
                taxonomy_kind=ArtifactTaxonomyKind.AGENT_CONFIGURATION,
                environment_origin=EnvironmentOrigin.OPENCODE,
                precedence_tier=tier,
                source_path=m_path,
                resolved_path=res_m_path,
                is_bundle=False,
                bundle_root_path=None,
                file_size_bytes=len(raw_bytes),
                st_mtime=st.st_mtime,
                st_ino=st.st_ino,
                st_dev=st.st_dev,
                raw_content_digest=hashlib.sha256(raw_bytes).hexdigest(),
                bundle_manifest_digest=None,
                canonical_urn="urn:lcs:agent:opencode.config:manifest",
                lifecycle_state=SkillLifecycleState.DISCOVERED,
                provenance={
                    "adapter": "OpenCodeDiscoveryAdapter",
                    "manifest": m_path,
                    "entrypoint_path": res_m_path,
                    "discovered_at_iso": datetime.now(timezone.utc).isoformat()
                }
            ))

            # 1. Process "instructions" array
            ingested_inst = set()
            for inst_rel in config_data.get("instructions", []):
                inst_full = os.path.join(manifest_dir, inst_rel)
                if os.path.exists(inst_full):
                    self._ingest_instruction(inst_full, tier, records)
                    ingested_inst.add(os.path.realpath(inst_full))

            # Also check default instructions.md in manifest_dir
            default_inst = os.path.join(manifest_dir, "instructions.md")
            if os.path.exists(default_inst) and os.path.realpath(default_inst) not in ingested_inst:
                self._ingest_instruction(default_inst, tier, records)

            # 2. Process commands directory
            cmds_dir = os.path.join(manifest_dir, "commands")
            if os.path.exists(cmds_dir) and os.path.isdir(cmds_dir):
                for cf in os.listdir(cmds_dir):
                    if cf.endswith(".md"):
                        p = os.path.join(cmds_dir, cf)
                        self._ingest_command(p, tier, records)

        return records

    def _ingest_instruction(self, path: str, tier: PrecedenceTier, out_records: List[DiscoveredArtifactRecord]) -> None:
        try:
            res_path = self.resolver.assert_path_confined(path)
            raw_bytes, st = SafeFileReader.read_exact_bytes(res_path, MAX_INSTRUCTION_FILE_SIZE)
            name = os.path.splitext(os.path.basename(path))[0]
            clean_name = re.sub(r"[^a-z0-9_-]", "-", name.lower()).strip("-")
            tax_kind = ArtifactTaxonomyKind.SKILL if os.path.basename(path) == "SKILL.md" else ArtifactTaxonomyKind.AGENT_INSTRUCTION
            kind_prefix = "skill" if tax_kind == ArtifactTaxonomyKind.SKILL else "instruct"

            out_records.append(DiscoveredArtifactRecord(
                artifact_id=f"art-{uuid.uuid4().hex[:12]}",
                name=clean_name,
                display_name=clean_name.replace("_", "-").capitalize(),
                taxonomy_kind=tax_kind,
                environment_origin=EnvironmentOrigin.OPENCODE,
                precedence_tier=tier,
                source_path=path,
                resolved_path=res_path,
                is_bundle=False,
                bundle_root_path=None,
                file_size_bytes=len(raw_bytes),
                st_mtime=st.st_mtime,
                st_ino=st.st_ino,
                st_dev=st.st_dev,
                raw_content_digest=hashlib.sha256(raw_bytes).hexdigest(),
                bundle_manifest_digest=None,
                canonical_urn=f"urn:lcs:{kind_prefix}:opencode.instruction:{clean_name}",
                lifecycle_state=SkillLifecycleState.DISCOVERED,
                provenance={
                    "adapter": "OpenCodeDiscoveryAdapter",
                    "instruction_path": path,
                    "entrypoint_path": res_path,
                    "discovered_at_iso": datetime.now(timezone.utc).isoformat()
                }
            ))
        except Exception:
            pass

    def _ingest_command(self, path: str, tier: PrecedenceTier, out_records: List[DiscoveredArtifactRecord]) -> None:
        try:
            res_path = self.resolver.assert_path_confined(path)
            raw_bytes, st = SafeFileReader.read_exact_bytes(res_path, MAX_INSTRUCTION_FILE_SIZE)
            name = os.path.splitext(os.path.basename(path))[0]
            clean_name = re.sub(r"[^a-z0-9_-]", "-", name.lower()).strip("-")

            out_records.append(DiscoveredArtifactRecord(
                artifact_id=f"art-{uuid.uuid4().hex[:12]}",
                name=clean_name,
                display_name=clean_name.replace("_", "-").capitalize(),
                taxonomy_kind=ArtifactTaxonomyKind.COMMAND,
                environment_origin=EnvironmentOrigin.OPENCODE,
                precedence_tier=tier,
                source_path=path,
                resolved_path=res_path,
                is_bundle=False,
                bundle_root_path=None,
                file_size_bytes=len(raw_bytes),
                st_mtime=st.st_mtime,
                st_ino=st.st_ino,
                st_dev=st.st_dev,
                raw_content_digest=hashlib.sha256(raw_bytes).hexdigest(),
                bundle_manifest_digest=None,
                canonical_urn=f"urn:lcs:command:opencode.command:{clean_name}",
                lifecycle_state=SkillLifecycleState.DISCOVERED,
                provenance={
                    "adapter": "OpenCodeDiscoveryAdapter",
                    "command_path": path,
                    "entrypoint_path": res_path,
                    "discovered_at_iso": datetime.now(timezone.utc).isoformat()
                }
            ))
        except Exception:
            pass


# ============================================================================
# 10. Unified Skill Discovery Engine V1
# ============================================================================

class SkillDiscoveryEngineV1:
    """
    Central coordinator orchestrating dynamic discovery root resolution,
    adapter execution, artifact classification, safe descriptor-relative reading,
    and deduplication.
    """

    def __init__(
        self,
        workspace_root: Optional[str] = None,
        resolver: Optional[DiscoveryRootResolver] = None
    ):
        self.resolver = resolver if resolver is not None else DiscoveryRootResolver(workspace_root=workspace_root)
        self.antigravity_adapter = AntigravityDiscoveryAdapter(self.resolver)
        self.claude_adapter = ClaudeCodeDiscoveryAdapter(self.resolver)
        self.opencode_adapter = OpenCodeDiscoveryAdapter(self.resolver)

    def discover_all(
        self,
        include_unsupported: bool = False,
        include_quarantined: bool = True
    ) -> List[DiscoveredArtifactRecord]:
        """
        Executes all environment adapters and returns normalized discovery records.
        Applies filter options.
        """
        all_records: List[DiscoveredArtifactRecord] = []
        all_records.extend(self.antigravity_adapter.discover())
        all_records.extend(self.claude_adapter.discover())
        all_records.extend(self.opencode_adapter.discover())

        filtered = []
        for r in all_records:
            if not include_unsupported and r.taxonomy_kind == ArtifactTaxonomyKind.UNSUPPORTED_ARTIFACT:
                continue
            if not include_quarantined and r.lifecycle_state == SkillLifecycleState.QUARANTINED:
                continue
            filtered.append(r)

        return filtered

    def discover_environment(self, env: EnvironmentOrigin) -> List[DiscoveredArtifactRecord]:
        """Runs a specific environment adapter."""
        if env == EnvironmentOrigin.ANTIGRAVITY:
            return self.antigravity_adapter.discover()
        elif env == EnvironmentOrigin.CLAUDE_CODE:
            return self.claude_adapter.discover()
        elif env == EnvironmentOrigin.OPENCODE:
            return self.opencode_adapter.discover()
        return []

    def read_artifact_bytes(self, record: DiscoveredArtifactRecord) -> bytes:
        """
        Reads exact raw bytes from an authorized artifact record via descriptor-relative safety.
        """
        self.resolver.assert_path_confined(record.resolved_path)
        content, _ = SafeFileReader.read_exact_bytes(record.resolved_path, MAX_INSTRUCTION_FILE_SIZE)
        return content

    def compute_bundle_manifest(self, record: DiscoveredArtifactRecord) -> Optional[Tuple[str, bytes, List[Dict[str, Any]]]]:
        """
        Computes the deterministic bundle manifest digest for a directory bundle record.
        """
        if not record.is_bundle or not record.bundle_root_path:
            return None
        return BundleManifestHasher.compute_bundle_manifest(record.bundle_root_path, resolver=self.resolver)
