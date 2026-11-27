"""
Official Vercel Find Skills Provider & Authorized On-Demand Acquisition
=======================================================================
Integrates `vercel-labs/skills` (`npx skills find` / `npx skills add`) as a
first-class external capability discovery and governance-gated acquisition
provider for Call Me.

Upstream reference:
- Repository: https://github.com/vercel-labs/skills
- Skill instructions: https://github.com/vercel-labs/skills/blob/main/skills/find-skills/SKILL.md
- Registry: https://skills.sh/
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


OFFICIAL_FIND_SKILLS_REPO = "vercel-labs/skills"
OFFICIAL_FIND_SKILLS_SPEC = "vercel-labs/skills@find-skills"
PINNED_SKILLS_CLI = "skills@1.4.4"
MIN_NODE_VERSION: Tuple[int, int] = (22, 20)

DEFAULT_TRUSTED_OWNERS: Set[str] = {
    "vercel-labs",
    "anthropics",
    "github",
    "microsoft",
    "openai",
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")
_FIND_ENTRY_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)@(?P<skill>[A-Za-z0-9_.-]+)"
    r"(?:\s+(?P<installs>[\d.]+[KkMm]?)\s+installs?)?$"
)

_STOP_WORDS: Set[str] = {
    "a", "an", "the", "and", "or", "with", "for", "to", "of", "in", "on", "by",
    "into", "from", "using", "via", "that", "this", "is", "are", "be", "as",
    "our", "your", "my", "its", "their", "his", "her", "we", "you", "they",
    "build", "create", "make", "write", "implement", "develop", "generate",
    "transform", "update", "add", "existing", "project", "new", "clean", "clear",
    "good", "best", "world", "class", "system", "tool", "app", "service",
    "exceptional", "professionally", "designed", "visually", "compelling",
    "technically", "accurate", "open-source", "project's",
}

_UNSAFE_PATTERNS: List[Tuple[str, str]] = [
    (r"curl\s+[^|\n]+\|\s*(?:ba)?sh", "Remote pipe-to-shell command detected"),
    (r"wget\s+[^|\n]+\|\s*(?:ba)?sh", "Remote wget pipe-to-shell command detected"),
    (r"rm\s+-rf\s+/(?:\s|$)", "Destructive root deletion command detected"),
    (r"ignore\s+(?:all\s+)?previous\s+instructions", "Prompt injection override attempt detected"),
    (r"override\s+(?:call\s*me|lcs)?\s*governance", "Governance bypass instruction detected"),
    (r"~/\.ssh|/\.ssh/id_rsa", "Sensitive SSH credential access detected"),
    (r"exfiltrat(?:e|ion)", "Potential data exfiltration instruction detected"),
]


class AcquisitionPolicy(str, Enum):
    ASK = "ASK"
    TRUSTED_AUTO = "TRUSTED_AUTO"
    OFFLINE = "OFFLINE"

    @classmethod
    def resolve(cls, explicit: Optional[str] = None) -> "AcquisitionPolicy":
        raw = (explicit or os.environ.get("CALL_ME_ACQUISITION_POLICY") or "ASK").strip().upper()
        try:
            return cls(raw)
        except ValueError:
            return cls.ASK


@dataclass
class SkillsCliEnvironment:
    node_path: Optional[str]
    node_version: Optional[str]
    node_compatible: bool
    npm_path: Optional[str]
    npx_path: Optional[str]
    find_skills_installed: bool
    find_skills_urn: Optional[str]
    pinned_cli: str = PINNED_SKILLS_CLI
    official_source: str = OFFICIAL_FIND_SKILLS_SPEC
    reason: Optional[str] = None

    @property
    def can_run_cli(self) -> bool:
        return bool(self.node_path and self.npx_path and self.node_compatible)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["can_run_cli"] = self.can_run_cli
        return d


@dataclass
class ExternalSkillCandidate:
    owner: str
    repo: str
    skill: str
    installs: int = 0
    installs_label: str = ""
    skills_sh_url: str = ""
    skill_md_content: str = ""
    skill_md_url: str = ""
    relevance_score: float = 0.0
    is_trusted_source: bool = False
    is_safe: bool = True
    is_duplicate: bool = False
    safety_issues: List[str] = field(default_factory=list)
    supporting_resources: List[str] = field(default_factory=list)
    rejection_reason: Optional[str] = None

    @property
    def package_spec(self) -> str:
        return f"{self.owner}/{self.repo}@{self.skill}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["package_spec"] = self.package_spec
        d.pop("skill_md_content", None)
        return d


@dataclass
class AcquisitionReceipt:
    package_spec: str
    skill_name: str
    source_url: str
    policy: str
    authorization_decision: str  # AUTHORIZED, APPROVAL_REQUIRED, DENIED, OFFLINE_BLOCKED, FAILED
    command: List[str]
    exit_code: Optional[int] = None
    installed_path: Optional[str] = None
    content_digest: Optional[str] = None
    lockfile_commit: Optional[str] = None
    scope: str = "project"
    latency_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _parse_installs(label: str) -> int:
    if not label:
        return 0
    s = label.strip().upper()
    mult = 1
    if s.endswith("K"):
        mult = 1_000
        s = s[:-1]
    elif s.endswith("M"):
        mult = 1_000_000
        s = s[:-1]
    try:
        return int(float(s) * mult)
    except ValueError:
        return 0


def _parse_node_version(ver_text: str) -> Optional[Tuple[int, int]]:
    m = re.search(r"v?(\d+)\.(\d+)", ver_text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def detect_skills_cli_environment(
    inventory: Optional[Any] = None,
    which_fn: Callable[[str], Optional[str]] = shutil.which,
    run_fn: Callable[..., Any] = subprocess.run,
) -> SkillsCliEnvironment:
    """Detects Node.js >= 22.20, npm/npx, and whether find-skills is already installed."""
    node_path = which_fn("node")
    npm_path = which_fn("npm")
    npx_path = which_fn("npx")

    node_version = None
    node_compatible = False
    reason = None

    if not node_path or not npx_path:
        reason = "Node.js and npx are required for external Find Skills CLI discovery"
    else:
        try:
            proc = run_fn(
                [node_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            node_version = (proc.stdout or "").strip()
            parsed = _parse_node_version(node_version)
            if parsed and parsed >= MIN_NODE_VERSION:
                node_compatible = True
            else:
                reason = f"Node.js >= {MIN_NODE_VERSION[0]}.{MIN_NODE_VERSION[1]} required (found {node_version or 'unknown'})"
        except Exception as exc:
            reason = f"Failed to probe Node.js version: {exc}"

    find_skills_installed = False
    find_skills_urn = None
    if inventory is not None and hasattr(inventory, "list_all"):
        for rec in inventory.list_all():
            if getattr(rec, "name", "").lower() in ("find-skills", "find_skills"):
                find_skills_installed = True
                find_skills_urn = getattr(rec, "urn", None)
                break

    return SkillsCliEnvironment(
        node_path=node_path,
        node_version=node_version,
        node_compatible=node_compatible,
        npm_path=npm_path,
        npx_path=npx_path,
        find_skills_installed=find_skills_installed,
        find_skills_urn=find_skills_urn,
        reason=reason,
    )


def generate_discovery_queries(requirement_text: str, objective: str = "") -> List[str]:
    """Generates bounded, domain-general discovery queries from an uncovered requirement."""
    cleaned_req = re.sub(r"^\s*/?call-me\b[:\s]*", "", requirement_text or "", flags=re.IGNORECASE)
    cleaned_obj = re.sub(r"^\s*/?call-me\b[:\s]*", "", objective or "", flags=re.IGNORECASE)
    raw_tokens = [
        re.sub(r"\.(?:md|py|ts|tsx|js|json|yaml|yml|html|css|sh)$", "", t.lower())
        for t in re.split(r"[^A-Za-z0-9_+#.-]+", cleaned_req)
        if len(t) >= 2
    ]
    core = [t for t in raw_tokens if t and t not in _STOP_WORDS and t != "call-me"]
    if not core:
        core = [
            re.sub(r"\.(?:md|py|ts|tsx|js|json|yaml|yml|html|css|sh)$", "", t.lower())
            for t in re.split(r"[^A-Za-z0-9_+#.-]+", cleaned_obj)
            if len(t) >= 3 and t.lower() not in _STOP_WORDS and t.lower() != "call-me"
        ]

    queries: List[str] = []
    if core:
        queries.append(core[0])
        if len(core) > 1:
            queries.append(" ".join(core[:2]))
        if len(core) > 2:
            queries.append(" ".join(core[:3]))
    elif requirement_text.strip():
        queries.append(requirement_text.strip()[:40])

    # Deduplicate preserving order, max 3 queries per requirement
    seen: Set[str] = set()
    unique: List[str] = []
    for q in queries:
        qn = q.strip()
        if qn and qn not in seen:
            seen.add(qn)
            unique.append(qn)
    return unique[:3]


def parse_skills_find_output(stdout: str) -> List[ExternalSkillCandidate]:
    """Parses `npx skills find <query>` output into structured ExternalSkillCandidate objects."""
    clean = _ANSI_RE.sub("", stdout or "")
    lines = [ln.strip() for ln in clean.splitlines()]
    candidates: List[ExternalSkillCandidate] = []
    seen_specs: Set[str] = set()

    for idx, line in enumerate(lines):
        m = _FIND_ENTRY_RE.match(line)
        if not m:
            continue
        owner = m.group("owner")
        repo = m.group("repo")
        skill = m.group("skill")
        installs_label = m.group("installs") or ""
        spec = f"{owner}/{repo}@{skill}"
        if spec in seen_specs:
            continue
        seen_specs.add(spec)

        url = f"https://skills.sh/{owner}/{repo}/{skill}"
        if idx + 1 < len(lines) and "https://skills.sh/" in lines[idx + 1]:
            u_match = re.search(r"https://skills\.sh/\S+", lines[idx + 1])
            if u_match:
                url = u_match.group(0)

        candidates.append(
            ExternalSkillCandidate(
                owner=owner,
                repo=repo,
                skill=skill,
                installs=_parse_installs(installs_label),
                installs_label=installs_label,
                skills_sh_url=url,
            )
        )
    return candidates


def _default_fetch_skill_md(candidate: ExternalSkillCandidate) -> Tuple[str, str]:
    """Fetches upstream SKILL.md from GitHub raw URLs with short bounded timeouts."""
    urls = [
        f"https://raw.githubusercontent.com/{candidate.owner}/{candidate.repo}/main/skills/{candidate.skill}/SKILL.md",
        f"https://raw.githubusercontent.com/{candidate.owner}/{candidate.repo}/main/{candidate.skill}/SKILL.md",
        f"https://raw.githubusercontent.com/{candidate.owner}/{candidate.repo}/master/skills/{candidate.skill}/SKILL.md",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CallMe-LCS/3.2"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    return resp.read().decode("utf-8", errors="replace"), url
        except Exception:
            continue
    return "", ""


def evaluate_candidate(
    candidate: ExternalSkillCandidate,
    requirement_text: str,
    existing_inventory: Optional[Any] = None,
    trusted_owners: Optional[Set[str]] = None,
    fetch_skill_md_fn: Optional[Callable[[ExternalSkillCandidate], Tuple[str, str]]] = None,
) -> ExternalSkillCandidate:
    """
    Evaluates an external skill candidate on semantic relevance, SKILL.md content,
    security risks, source reputation, duplication, and supporting install counts.
    """
    trusted = trusted_owners if trusted_owners is not None else DEFAULT_TRUSTED_OWNERS
    candidate.is_trusted_source = candidate.owner.lower() in {o.lower() for o in trusted}

    # Check duplication against installed inventory
    if existing_inventory is not None and hasattr(existing_inventory, "list_all"):
        existing_names = {getattr(r, "name", "").lower() for r in existing_inventory.list_all()}
        if candidate.skill.lower() in existing_names:
            candidate.is_duplicate = True
            candidate.rejection_reason = f"Skill '{candidate.skill}' already installed in inventory"

    fetcher = fetch_skill_md_fn or _default_fetch_skill_md
    content, md_url = fetcher(candidate)
    candidate.skill_md_content = content
    candidate.skill_md_url = md_url

    # Security / governance safety scan on SKILL.md
    if content:
        for pat, desc in _UNSAFE_PATTERNS:
            if re.search(pat, content, re.IGNORECASE):
                candidate.is_safe = False
                candidate.safety_issues.append(desc)
        # Detect supporting resources mentioned in SKILL.md
        for res_match in re.findall(r"(?:scripts|references|templates|assets)/[A-Za-z0-9_.-]+", content):
            if res_match not in candidate.supporting_resources:
                candidate.supporting_resources.append(res_match)
    if not candidate.is_safe:
        candidate.rejection_reason = f"Security/governance rejection: {'; '.join(candidate.safety_issues)}"

    # Generalized semantic eligibility gate (before ranking; popularity never rescues ineligible candidates)
    from .semantic_reasoner import SemanticReasoner
    elig = SemanticReasoner.assess_semantic_eligibility(
        name=candidate.skill,
        description="",
        instructions=content,
        requirement_text=requirement_text,
    )
    if not elig.eligible:
        candidate.relevance_score = 0.0
        if not candidate.rejection_reason:
            candidate.rejection_reason = elig.contradiction_reason or f"Ineligible for '{requirement_text}'"
        return candidate

    score = elig.relevance_score
    if candidate.is_trusted_source:
        score += 10.0
    # Popularity is strictly a minor tie-breaker among already-eligible candidates (max +2.0)
    if candidate.installs >= 10_000:
        score += 2.0
    elif candidate.installs >= 1_000:
        score += 1.0
    elif candidate.installs >= 100:
        score += 0.5

    if not candidate.is_safe:
        score = 0.0
    candidate.relevance_score = round(score, 2)

    if candidate.relevance_score < 20.0 and not candidate.rejection_reason:
        candidate.rejection_reason = f"Low semantic relevance ({candidate.relevance_score:.1f} < 20.0) for '{requirement_text}'"

    return candidate


class FindSkillsAcquisitionCoordinator:
    """
    Coordinates external discovery via `vercel-labs/skills`, governance-backed
    acquisition, immediate inventory refresh, hydration, and DAG replanning
    within a single Call Me invocation.
    """

    def __init__(
        self,
        policy: Optional[AcquisitionPolicy] = None,
        trusted_owners: Optional[Set[str]] = None,
        max_iterations: int = 2,
        max_acquisitions: int = 2,
        run_fn: Callable[..., Any] = subprocess.run,
        which_fn: Callable[[str], Optional[str]] = shutil.which,
        fetch_skill_md_fn: Optional[Callable[[ExternalSkillCandidate], Tuple[str, str]]] = None,
    ):
        self.policy = policy or AcquisitionPolicy.resolve()
        self.trusted_owners = trusted_owners if trusted_owners is not None else set(DEFAULT_TRUSTED_OWNERS)
        self.max_iterations = max_iterations
        self.max_acquisitions = max_acquisitions
        self.run_fn = run_fn
        self.which_fn = which_fn
        self.fetch_skill_md_fn = fetch_skill_md_fn

    def _run_skills_cli(self, args: List[str], cwd: str, timeout: int = 45) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["DISABLE_TELEMETRY"] = "1"
        env["DO_NOT_TRACK"] = "1"
        npx_bin = self.which_fn("npx") or "npx"
        cmd = [npx_bin, "--yes", PINNED_SKILLS_CLI] + args
        return self.run_fn(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def acquire_candidate(
        self,
        candidate: ExternalSkillCandidate,
        workspace_root: str,
        approved: Optional[bool] = None,
        global_install: bool = False,
    ) -> AcquisitionReceipt:
        """Installs a vetted external skill candidate under governance policy."""
        t0 = time.perf_counter()
        cmd = ["npx", "--yes", PINNED_SKILLS_CLI, "add", candidate.package_spec, "-y"]
        if global_install:
            cmd.append("-g")
        scope = "global" if global_install else "project"

        if self.policy == AcquisitionPolicy.OFFLINE:
            return AcquisitionReceipt(
                package_spec=candidate.package_spec,
                skill_name=candidate.skill,
                source_url=candidate.skills_sh_url,
                policy=self.policy.value,
                authorization_decision="OFFLINE_BLOCKED",
                command=cmd,
                scope=scope,
                error="Acquisition blocked by OFFLINE policy",
            )

        if not candidate.is_safe:
            return AcquisitionReceipt(
                package_spec=candidate.package_spec,
                skill_name=candidate.skill,
                source_url=candidate.skills_sh_url,
                policy=self.policy.value,
                authorization_decision="DENIED",
                command=cmd,
                scope=scope,
                error=candidate.rejection_reason or "Candidate failed safety evaluation",
            )

        if approved is False:
            return AcquisitionReceipt(
                package_spec=candidate.package_spec,
                skill_name=candidate.skill,
                source_url=candidate.skills_sh_url,
                policy=self.policy.value,
                authorization_decision="DENIED",
                command=cmd,
                scope=scope,
                error="External skill acquisition denied by approver",
            )

        is_auto_trusted = self.policy == AcquisitionPolicy.TRUSTED_AUTO and candidate.is_trusted_source
        if not approved and not is_auto_trusted:
            return AcquisitionReceipt(
                package_spec=candidate.package_spec,
                skill_name=candidate.skill,
                source_url=candidate.skills_sh_url,
                policy=self.policy.value,
                authorization_decision="APPROVAL_REQUIRED",
                command=cmd,
                scope=scope,
                error=f"Approval required under policy={self.policy.value} for '{candidate.package_spec}'",
            )

        try:
            abs_ws = os.path.realpath(workspace_root)
            raw_skill_dir = os.path.join(abs_ws, ".agents", "skills", candidate.skill)
            preexisting_skill_dir = os.path.exists(raw_skill_dir)

            cli_args = ["add", candidate.package_spec, "-y"]
            if global_install:
                cli_args.append("-g")
            proc = self._run_skills_cli(cli_args, cwd=workspace_root, timeout=120)
            elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
            if proc.returncode != 0:
                return AcquisitionReceipt(
                    package_spec=candidate.package_spec,
                    skill_name=candidate.skill,
                    source_url=candidate.skills_sh_url,
                    policy=self.policy.value,
                    authorization_decision="FAILED",
                    command=cmd,
                    exit_code=proc.returncode,
                    scope=scope,
                    latency_ms=elapsed,
                    error=(proc.stderr or proc.stdout or f"Exit code {proc.returncode}")[:400],
                )

            # Locate installed SKILL.md inside workspace (.agents/skills/<skill>/SKILL.md)
            skill_dir = os.path.realpath(raw_skill_dir)
            if os.path.commonpath([abs_ws, skill_dir]) != abs_ws or os.path.islink(raw_skill_dir):
                return AcquisitionReceipt(
                    package_spec=candidate.package_spec,
                    skill_name=candidate.skill,
                    source_url=candidate.skills_sh_url,
                    policy=self.policy.value,
                    authorization_decision="INTEGRITY_MISMATCH",
                    command=cmd,
                    exit_code=proc.returncode,
                    scope=scope,
                    latency_ms=elapsed,
                    error="Path confinement or unsafe symlink violation on installed skill directory",
                )

            skill_md_path = os.path.join(skill_dir, "SKILL.md")
            digest = None
            if os.path.isfile(skill_md_path):
                installed_bytes = open(skill_md_path, "rb").read()
                digest = hashlib.sha256(installed_bytes).hexdigest()

                # Verify evaluated vs installed content digest if upstream SKILL.md was evaluated
                if candidate.skill_md_content:
                    eval_digest = hashlib.sha256(candidate.skill_md_content.encode("utf-8")).hexdigest()
                    if digest != eval_digest:
                        if not preexisting_skill_dir:
                            shutil.rmtree(skill_dir, ignore_errors=True)
                        return AcquisitionReceipt(
                            package_spec=candidate.package_spec,
                            skill_name=candidate.skill,
                            source_url=candidate.skills_sh_url,
                            policy=self.policy.value,
                            authorization_decision="INTEGRITY_MISMATCH",
                            command=cmd,
                            exit_code=proc.returncode,
                            content_digest=digest,
                            scope=scope,
                            latency_ms=elapsed,
                            error=f"Evaluated vs installed SKILL.md digest mismatch ({eval_digest[:12]} != {digest[:12]})",
                        )

                # Scan installed SKILL.md and any scripts/ for unsafe patterns
                installed_text = installed_bytes.decode("utf-8", errors="replace")
                for root_d, _, fnames in os.walk(skill_dir):
                    for fn in fnames:
                        fpath = os.path.join(root_d, fn)
                        if os.path.islink(fpath) and os.path.commonpath([skill_dir, os.path.realpath(fpath)]) != skill_dir:
                            if not preexisting_skill_dir:
                                shutil.rmtree(skill_dir, ignore_errors=True)
                            return AcquisitionReceipt(
                                package_spec=candidate.package_spec,
                                skill_name=candidate.skill,
                                source_url=candidate.skills_sh_url,
                                policy=self.policy.value,
                                authorization_decision="INTEGRITY_MISMATCH",
                                command=cmd,
                                exit_code=proc.returncode,
                                scope=scope,
                                latency_ms=elapsed,
                                error=f"Unsafe symlink escape detected at '{fn}'",
                            )
                        if fn.endswith((".md", ".sh", ".py", ".ps1", ".js")):
                            ftext = open(fpath, "r", encoding="utf-8", errors="replace").read()
                            for pat, desc in _UNSAFE_PATTERNS:
                                if re.search(pat, ftext, re.IGNORECASE):
                                    if not preexisting_skill_dir:
                                        shutil.rmtree(skill_dir, ignore_errors=True)
                                    return AcquisitionReceipt(
                                        package_spec=candidate.package_spec,
                                        skill_name=candidate.skill,
                                        source_url=candidate.skills_sh_url,
                                        policy=self.policy.value,
                                        authorization_decision="DENIED",
                                        command=cmd,
                                        exit_code=proc.returncode,
                                        scope=scope,
                                        latency_ms=elapsed,
                                        error=f"Quarantined unsafe installed file '{fn}': {desc}",
                                    )

            # Read skills-lock.json if generated
            lock_commit = None
            lock_path = os.path.join(abs_ws, "skills-lock.json")
            if os.path.isfile(lock_path):
                try:
                    lock_data = json.loads(open(lock_path, "r", encoding="utf-8").read())
                    entry = (lock_data.get("skills") or {}).get(candidate.skill) or {}
                    lock_commit = entry.get("commit") or entry.get("computedHash")
                except Exception:
                    pass

            return AcquisitionReceipt(
                package_spec=candidate.package_spec,
                skill_name=candidate.skill,
                source_url=candidate.skills_sh_url,
                policy=self.policy.value,
                authorization_decision="AUTHORIZED",
                command=cmd,
                exit_code=proc.returncode,
                installed_path=skill_dir if os.path.isdir(skill_dir) else None,
                content_digest=digest,
                lockfile_commit=lock_commit,
                scope=scope,
                latency_ms=elapsed,
            )
        except Exception as exc:
            return AcquisitionReceipt(
                package_spec=candidate.package_spec,
                skill_name=candidate.skill,
                source_url=candidate.skills_sh_url,
                policy=self.policy.value,
                authorization_decision="FAILED",
                command=cmd,
                scope=scope,
                latency_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                error=str(exc),
            )

    def resolve_gaps(
        self,
        objective: str,
        gaps: List[Any],
        inventory: Any,
        workspace_root: str,
        approval_callback: Optional[Callable[[ExternalSkillCandidate], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Detects CLI readiness, searches Find Skills for uncovered gaps, evaluates
        candidates, acquires authorized skills, and returns structured evidence.
        """
        t_start = time.perf_counter()
        initial_count = inventory.total_count if hasattr(inventory, "total_count") else 0
        env_info = detect_skills_cli_environment(inventory, which_fn=self.which_fn, run_fn=self.run_fn)

        report: Dict[str, Any] = {
            "policy": self.policy.value,
            "environment": env_info.to_dict(),
            "initial_capability_count": initial_count,
            "final_capability_count": initial_count,
            "queries_executed": [],
            "candidates_evaluated": [],
            "rejected_candidates": [],
            "receipts": [],
            "acquired_skills": [],
            "bootstrap_receipt": None,
            "status": "NO_ACTION",
            "latency_ms": 0.0,
        }

        if not gaps:
            report["latency_ms"] = round((time.perf_counter() - t_start) * 1000.0, 2)
            return report

        if self.policy == AcquisitionPolicy.OFFLINE:
            report["status"] = "OFFLINE"
            report["latency_ms"] = round((time.perf_counter() - t_start) * 1000.0, 2)
            return report

        if not env_info.can_run_cli:
            report["status"] = "CLI_UNAVAILABLE"
            report["error"] = env_info.reason
            report["latency_ms"] = round((time.perf_counter() - t_start) * 1000.0, 2)
            return report

        # Optionally bootstrap find-skills itself if absent and authorized
        if not env_info.find_skills_installed:
            boot_cand = ExternalSkillCandidate(
                owner="vercel-labs",
                repo="skills",
                skill="find-skills",
                skills_sh_url="https://skills.sh/vercel-labs/skills/find-skills",
                is_trusted_source=True,
                is_safe=True,
            )
            boot_approved = True if self.policy == AcquisitionPolicy.TRUSTED_AUTO else (
                approval_callback(boot_cand) if approval_callback else None
            )
            if boot_approved:
                boot_rec = self.acquire_candidate(boot_cand, workspace_root, approved=True)
                report["bootstrap_receipt"] = boot_rec.to_dict()

        seen_queries: Set[str] = set()
        acquired_specs: Set[str] = set()
        iterations = 0

        for gap in gaps:
            if iterations >= self.max_iterations or len(report["acquired_skills"]) >= self.max_acquisitions:
                break
            req_text = getattr(gap, "requirement_text", None) or getattr(gap, "discovery_query", "") or str(gap)
            queries = generate_discovery_queries(req_text, objective)
            found_for_gap = False

            for q in queries:
                if q in seen_queries or iterations >= self.max_iterations:
                    continue
                seen_queries.add(q)
                iterations += 1
                report["queries_executed"].append(q)

                try:
                    proc = self._run_skills_cli(["find", q], cwd=workspace_root, timeout=30)
                except Exception as exc:
                    report["rejected_candidates"].append({"query": q, "reason": f"Search failed: {exc}"})
                    continue

                if proc.returncode != 0:
                    report["rejected_candidates"].append({"query": q, "reason": f"npx skills find exited {proc.returncode}"})
                    continue

                raw_cands = parse_skills_find_output(proc.stdout)
                evaluated: List[ExternalSkillCandidate] = []
                for c in raw_cands[:5]:
                    ev = evaluate_candidate(
                        c,
                        req_text,
                        existing_inventory=inventory,
                        trusted_owners=self.trusted_owners,
                        fetch_skill_md_fn=self.fetch_skill_md_fn,
                    )
                    report["candidates_evaluated"].append(ev.to_dict())
                    if ev.is_safe and not ev.is_duplicate and ev.relevance_score >= 20.0:
                        evaluated.append(ev)
                    else:
                        report["rejected_candidates"].append({
                            "package_spec": ev.package_spec,
                            "reason": ev.rejection_reason or "Below relevance/safety threshold",
                        })

                if self.policy == AcquisitionPolicy.TRUSTED_AUTO and approval_callback is None:
                    evaluated.sort(key=lambda x: (x.is_trusted_source, x.relevance_score), reverse=True)
                else:
                    evaluated.sort(key=lambda x: x.relevance_score, reverse=True)
                if not evaluated:
                    continue

                for best in evaluated[:3]:
                    if best.package_spec in acquired_specs:
                        continue

                    user_approved = approval_callback(best) if approval_callback else None
                    receipt = self.acquire_candidate(best, workspace_root, approved=user_approved)
                    report["receipts"].append(receipt.to_dict())

                    if receipt.authorization_decision == "AUTHORIZED":
                        acquired_specs.add(best.package_spec)
                        report["acquired_skills"].append(best.skill)
                        found_for_gap = True
                        break
                    elif receipt.authorization_decision in ("APPROVAL_REQUIRED", "DENIED", "OFFLINE_BLOCKED"):
                        report["status"] = receipt.authorization_decision
                        found_for_gap = True
                        break
                if found_for_gap:
                    break

            if not found_for_gap and report["status"] == "NO_ACTION":
                report["status"] = "NO_SUITABLE_CANDIDATE"

        if report["acquired_skills"]:
            report["status"] = "ACQUIRED"
        report["latency_ms"] = round((time.perf_counter() - t_start) * 1000.0, 2)
        return report
