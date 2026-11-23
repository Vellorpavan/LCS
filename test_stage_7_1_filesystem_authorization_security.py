"""
Stage 7.1 — Final Security & Filesystem Authorization Regression Suite
======================================================================
Validates zero-trust filesystem authorization in ExecutionEngineV1 and PathSecurityValidator:
1. Workspace escape attempts (relative traversal, absolute escapes).
2. Symlink and junction traversal rejection (O_NOFOLLOW, realpath containment).
3. Untrusted working directory confinement (os.getcwd() cannot expand authorization).
4. Cross-project isolation between independent project directories.
5. Ambiguous or invalid authorization roots fail closed.
"""

import os
import sys
import json
import hashlib
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.governance import ApproverConsent, ApproverRole
from lcs.planning import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition
from lcs.policy import InterfaceTrustPolicy
from lcs.inventory.models import UnifiedResourceRecord, ResourceType, ProvenanceRecord
from execution_engine_v1 import (
    PathSecurityValidator,
    PathTraversalExecutionError,
    ExecutionEngineV1,
    PreflightVerificationError,
)


@pytest.fixture
def isolated_security_env(tmp_path):
    """Provides isolated workspaces for security testing."""
    ws_a = tmp_path / "workspace_alpha"
    ws_b = tmp_path / "workspace_beta"
    untrusted = tmp_path / "untrusted_dir"
    home = tmp_path / "user_home"

    ws_a.mkdir(parents=True, exist_ok=True)
    ws_b.mkdir(parents=True, exist_ok=True)
    untrusted.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)

    return {
        "ws_a": str(ws_a.resolve()),
        "ws_b": str(ws_b.resolve()),
        "untrusted": str(untrusted.resolve()),
        "home": str(home.resolve()),
        "tmp_path": tmp_path,
    }


# ============================================================================
# 1. Workspace Escape & Traversal Rejection
# ============================================================================

def test_relative_path_traversal_escape_rejected(isolated_security_env):
    """Verifies that relative traversal escaping authorized roots is blocked."""
    ws_a = isolated_security_env["ws_a"]
    untrusted = isolated_security_env["untrusted"]

    # Target outside workspace via relative traversal
    escape_path = os.path.join(ws_a, "..", "untrusted_dir", "malicious.txt")
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(escape_path, [ws_a])
    assert "escapes authorized roots" in str(exc_info.value)


def test_absolute_path_escape_rejected(isolated_security_env):
    """Verifies that absolute paths outside authorized roots are blocked."""
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    target_in_b = os.path.join(ws_b, "sensitive_data.txt")
    with open(target_in_b, "w") as f:
        f.write("CONFIDENTIAL")

    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(target_in_b, [ws_a])
    assert "escapes authorized roots" in str(exc_info.value)


# ============================================================================
# 2. Symlink & Junction Traversal Rejection
# ============================================================================

def test_symlink_escape_rejected(isolated_security_env):
    """Verifies that symlinks inside workspace pointing outside are rejected."""
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    outside_file = os.path.join(ws_b, "external_secret.txt")
    with open(outside_file, "w") as f:
        f.write("SECRET_KEY_12345")

    link_inside_a = os.path.join(ws_a, "leak_symlink.txt")
    try:
        os.symlink(outside_file, link_inside_a)
    except OSError:
        pytest.skip("Symlink creation not permitted in this environment")

    # Realpath resolves outside ws_a, must be rejected
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(link_inside_a, [ws_a])
    assert "escapes authorized roots" in str(exc_info.value) or "Symlink rejected" in str(exc_info.value)


def test_directory_symlink_traversal_rejected(isolated_security_env):
    """Verifies that directory symlinks pointing outside workspace are rejected."""
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    dir_link = os.path.join(ws_a, "linked_dir")
    try:
        os.symlink(ws_b, dir_link)
    except OSError:
        pytest.skip("Symlink creation not permitted in this environment")

    escaped_target = os.path.join(dir_link, "subfile.txt")
    with pytest.raises(PathTraversalExecutionError):
        PathSecurityValidator.validate_file_path(escaped_target, [ws_a])


# ============================================================================
# 3. Untrusted Working Directory Confinement (os.getcwd() Cannot Expand Roots)
# ============================================================================

def test_cwd_cannot_expand_authorized_workspace(isolated_security_env, monkeypatch):
    """
    CRITICAL INVARIANT:
    When ExecutionEngineV1 is initialized with an authorized workspace_root,
    running in an untrusted current working directory MUST NOT authorize files
    in that untrusted working directory.
    """
    ws_a = isolated_security_env["ws_a"]
    untrusted = isolated_security_env["untrusted"]

    # Switch current working directory to untrusted
    monkeypatch.chdir(untrusted)
    assert os.path.realpath(os.getcwd()) == os.path.realpath(untrusted)

    # Initialize execution engine explicitly for workspace_alpha
    cfg_a = LCSConfig.resolve(root_override=os.path.join(ws_a, ".lcs"), workspace_root=ws_a)
    with LCSContext(config=cfg_a, auto_migrate=True) as ctx:
        assert os.path.realpath(ctx.execution_engine.workspace_root) == os.path.realpath(ws_a)

        # File in untrusted working directory
        untrusted_file = os.path.join(untrusted, "leak.txt")
        with open(untrusted_file, "w") as f:
            f.write("UNTRUSTED")

        # Attempt to validate path in untrusted cwd against ws_a workspace_root
        with pytest.raises(PathTraversalExecutionError) as exc_info:
            PathSecurityValidator.validate_file_path(
                untrusted_file,
                [ctx.execution_engine.workspace_root]
            )
        assert "escapes authorized roots" in str(exc_info.value)


# ============================================================================
# 4. Cross-Project Isolation in Execution Pipeline
# ============================================================================

def test_cross_project_deliverable_escape_rejected_at_execution(isolated_security_env):
    """
    Verifies that during actual plan execution, an input or output deliverable
    targeting another project directory is rejected fail-closed.
    """
    import hashlib
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    cfg_a = LCSConfig.resolve(root_override=os.path.join(ws_a, ".lcs"), workspace_root=ws_a)
    with LCSContext(config=cfg_a, auto_migrate=True) as ctx:
        # Step script inside workspace_alpha
        script_path = os.path.join(ws_a, "step.py")
        with open(script_path, "w") as f:
            f.write("print('EXECUTED')\n")

        # Register capability properly in inventory
        content_hash = hashlib.sha256(open(script_path, "rb").read()).hexdigest()
        rec = UnifiedResourceRecord(
            urn="urn:lcs:skill:test:escape",
            name="escape-step",
            resource_type=ResourceType.SKILL,
            display_name="Escape Step",
            description="Testing escape",
            raw_content=open(script_path).read(),
            raw_content_digest=content_hash,
            provenance=ProvenanceRecord(
                origin_host="generic_posix",
                precedence_tier="WORKSPACE",
                source_path=script_path,
                resolved_path=script_path,
                content_hash=content_hash
            )
        )
        ctx.inventory._persist_and_bind_capability(rec)

        # Target deliverable maliciously aimed at workspace_beta
        target_in_b = os.path.join(ws_b, "stolen_data.txt")

        step = PlanStep(
            step_id="step-escape",
            step_index=1,
            capability_urn="urn:lcs:skill:test:escape",
            display_name="Escape Step",
            sub_goal="Escape to Project B",
            selection_reason="Testing cross-project boundary",
            input_bindings={
                "target_script": StepInputBinding("target_script", "string", False, bound_value=script_path),
                "output_target": StepInputBinding("output_target", "string", False, bound_value=target_in_b),
            },
            output_definitions={"result": StepOutputDefinition("result", "string")},
            dependencies=[]
        )

        plan = ExecutionPlan(
            plan_id="plan-escape-01",
            request_query="Cross-project escape test",
            plan_type="SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=[step],
            dag_edges=[],
            execution_order=["step-escape"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Testing boundary escape"
        )

        consent = ApproverConsent("auditor@local", ApproverRole.HUMAN_OPERATOR, "AUDIT")
        policy = InterfaceTrustPolicy("permissive", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
        token, _ = ctx.governance_engine.approve_plan(plan, approver=consent, active_policy=policy)

        # Execution MUST fail closed due to PathTraversalExecutionError on output_target
        res = ctx.execution_engine.execute_plan(plan, token)
        assert res.lifecycle_state.value in ("FAILED", "ABORTED")
        assert not os.path.exists(target_in_b)
        rec = res.step_records[0]
        assert rec.status.value in ("FAILED", "ERROR")
        assert "escapes authorized roots" in (rec.error_details or "") or "escapes authorized roots" in (res.error_message or "")


# ============================================================================
# 5. Ambiguous or Invalid Roots Fail Closed
# ============================================================================

def test_ambiguous_and_empty_authorized_roots_fail_closed(isolated_security_env):
    """Verifies that empty or nonexistent authorized roots fail closed."""
    ws_a = isolated_security_env["ws_a"]
    test_file = os.path.join(ws_a, "valid.txt")
    with open(test_file, "w") as f:
        f.write("OK")

    # Nonexistent root
    with pytest.raises(PathTraversalExecutionError):
        PathSecurityValidator.validate_file_path(test_file, ["/nonexistent/root/path/12345"])

    # Path outside single root
    with pytest.raises(PathTraversalExecutionError):
        PathSecurityValidator.validate_file_path("/etc/hosts", [ws_a])


# ============================================================================
# 6. Windows & Cross-Platform Path Format Security
# ============================================================================

def test_windows_drive_relative_rejected(isolated_security_env):
    """Verifies that Windows drive-relative paths (e.g. C:foo) are rejected."""
    ws_a = isolated_security_env["ws_a"]
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path("C:evil_relative_data.txt", [ws_a])
    assert "drive-relative" in str(exc_info.value).lower()


def test_windows_raw_device_namespace_rejected(isolated_security_env):
    """Verifies that Win32 device namespace paths (\\\\.\\, \\\\?\\) are rejected."""
    ws_a = isolated_security_env["ws_a"]
    for prefix in ("\\\\.\\PhysicalDrive0", "\\\\?\\C:\\malicious", "//./PhysicalDrive0", "//?/C:/malicious"):
        with pytest.raises(PathTraversalExecutionError) as exc_info:
            PathSecurityValidator.validate_file_path(prefix, [ws_a])
        assert "device namespace" in str(exc_info.value).lower()


def test_windows_unc_path_rejected(isolated_security_env):
    """Verifies that UNC paths targeting external shares are rejected."""
    ws_a = isolated_security_env["ws_a"]
    for unc in ("\\\\evil-server\\share\\data.txt", "//evil-server/share/data.txt"):
        with pytest.raises(PathTraversalExecutionError) as exc_info:
            PathSecurityValidator.validate_file_path(unc, [ws_a])
        assert "unc path" in str(exc_info.value).lower()


def test_mixed_separators_in_workspace_allowed(isolated_security_env):
    """Verifies that legitimate mixed-separator paths inside workspace resolve correctly."""
    ws_a = isolated_security_env["ws_a"]
    sub_dir = os.path.join(ws_a, "nested", "folder")
    os.makedirs(sub_dir, exist_ok=True)
    target_file = os.path.join(sub_dir, "valid.txt")
    with open(target_file, "w") as f:
        f.write("VALID")

    # Mixed separators
    mixed_path = f"{ws_a}/nested\\folder/valid.txt"
    resolved = PathSecurityValidator.validate_file_path(mixed_path, [ws_a])
    assert resolved == os.path.realpath(target_file)


def test_is_path_parameter_classification():
    """Verifies accurate detection of path vs non-path parameters without false positives."""
    # Definite paths (True positives)
    assert PathSecurityValidator.is_path_parameter("/etc/passwd", "data")
    assert PathSecurityValidator.is_path_parameter("C:\\Windows\\System32", "target")
    assert PathSecurityValidator.is_path_parameter("D:/a/LCS/ws_b/stolen.txt", "output_target")
    assert PathSecurityValidator.is_path_parameter("..\\..\\secret.txt", "arg")
    assert PathSecurityValidator.is_path_parameter("sub/dir/file.txt", "input")
    assert PathSecurityValidator.is_path_parameter("result.csv", "output_file")
    assert PathSecurityValidator.is_path_parameter("script.py", "target_script")
    assert PathSecurityValidator.is_path_parameter("something", "target_path", "string")
    assert PathSecurityValidator.is_path_parameter("something", "param", "filepath")

    # False positive protection (Definite non-paths)
    # 1. URLs and endpoints
    assert not PathSecurityValidator.is_path_parameter("https://api.github.com/v1/repos", "url", "string")
    assert not PathSecurityValidator.is_path_parameter("http://localhost:8080/metrics", "endpoint", "string")
    assert not PathSecurityValidator.is_path_parameter("ftp://files.example.com/pub", "download_url", "string")
    assert not PathSecurityValidator.is_path_parameter("ws://socket.example.com/v1", "socket", "string")

    # 2. JSON data structures
    assert not PathSecurityValidator.is_path_parameter('{"key": "val/with/slash"}', "config", "string")
    assert not PathSecurityValidator.is_path_parameter('["a/b", "c/d"]', "items", "string")

    # 3. Protocol identifiers and URNs
    assert not PathSecurityValidator.is_path_parameter("urn:lcs:skill:test/run", "id", "string")
    assert not PathSecurityValidator.is_path_parameter("mailto:user/dept@example.com", "contact", "string")

    # 4. MIME types and content formats
    assert not PathSecurityValidator.is_path_parameter("application/json", "content_type", "string")
    assert not PathSecurityValidator.is_path_parameter("text/html", "mime_type", "string")

    # 5. Git branches, model names, and generic slash-separated identifiers
    assert not PathSecurityValidator.is_path_parameter("refs/heads/feature/login", "branch", "string")
    assert not PathSecurityValidator.is_path_parameter("google/gemini-1.5-pro", "model", "string")

    # 6. Natural language prose and mathematical/query expressions
    assert not PathSecurityValidator.is_path_parameter("Pass/Fail decision needed", "comment", "string")
    assert not PathSecurityValidator.is_path_parameter("SELECT a/b FROM table", "query", "string")
    assert not PathSecurityValidator.is_path_parameter("line 1\nline 2/with/slash", "text", "string")

    # 7. Generic non-path values
    assert not PathSecurityValidator.is_path_parameter("AUDIT", "role", "string")
    assert not PathSecurityValidator.is_path_parameter("hello world", "message", "string")
    assert not PathSecurityValidator.is_path_parameter("search query for users", "query", "string")
    assert not PathSecurityValidator.is_path_parameter("true", "flag", "boolean")
    assert not PathSecurityValidator.is_path_parameter("", "empty", "string")
    assert not PathSecurityValidator.is_path_parameter("   ", "blank", "string")
    assert not PathSecurityValidator.is_path_parameter(12345, "number", "int")


def test_legitimate_relative_output_target_in_workspace_execution(isolated_security_env):
    """Verifies that a legitimate relative output deliverable in the workspace succeeds."""
    ws_a = isolated_security_env["ws_a"]
    home = isolated_security_env["home"]

    config = LCSConfig(
        root_dir=ws_a,
        db_path=os.path.join(ws_a, "lcs.db"),
        cas_root=os.path.join(ws_a, "cas"),
        key_store_dir=os.path.join(ws_a, "keys"),
        schema_dir=os.path.abspath("lcs/schemas"),
        workspace_root=ws_a,
    )
    config.ensure_directories()

    with LCSContext(config=config, auto_migrate=True) as ctx:
        script_path = os.path.join(ws_a, "gen.py")
        with open(script_path, "w") as f:
            f.write("""import sys, os
out = "legitimate_output.txt"
for i, arg in enumerate(sys.argv):
    if arg == "--output_target" and i + 1 < len(sys.argv):
        out = sys.argv[i+1]
open(out, "w").write("GENERATED")
""")

        content_hash = hashlib.sha256(open(script_path, "rb").read()).hexdigest()
        rec = UnifiedResourceRecord(
            urn="urn:lcs:skill:test:gen",
            name="gen-step",
            resource_type=ResourceType.SKILL,
            display_name="Gen Step",
            description="Testing legitimate gen",
            raw_content=open(script_path).read(),
            raw_content_digest=content_hash,
            provenance=ProvenanceRecord(
                origin_host="generic_posix",
                precedence_tier="WORKSPACE",
                source_path=script_path,
                resolved_path=script_path,
                content_hash=content_hash
            )
        )
        ctx.inventory._persist_and_bind_capability(rec)

        step = PlanStep(
            step_id="step-gen",
            step_index=1,
            capability_urn="urn:lcs:skill:test:gen",
            display_name="Gen Step",
            sub_goal="Gen within Project A",
            selection_reason="Testing legitimate in-workspace deliverable",
            input_bindings={
                "target_script": StepInputBinding("target_script", "string", False, bound_value=script_path),
                "output_target": StepInputBinding("output_target", "string", False, bound_value="legitimate_output.txt"),
            },
            output_definitions={"result": StepOutputDefinition("result", "string")},
            dependencies=[]
        )

        plan = ExecutionPlan(
            plan_id="plan-gen-01",
            request_query="Legitimate output test",
            plan_type="SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=[step],
            dag_edges=[],
            execution_order=["step-gen"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Testing legitimate deliverable"
        )

        consent = ApproverConsent("auditor@local", ApproverRole.HUMAN_OPERATOR, "AUDIT")
        policy = InterfaceTrustPolicy("permissive", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
        token, _ = ctx.governance_engine.approve_plan(plan, approver=consent, active_policy=policy)

        res = ctx.execution_engine.execute_plan(plan, token)
        assert res.lifecycle_state.value == "SUCCEEDED"
        rec = res.step_records[0]
        # output_target should remain relative to preserve template formatting
        assert rec.input_arguments["output_target"] == "legitimate_output.txt"
        assert os.path.exists(os.path.join(ws_a, "legitimate_output.txt"))


# ============================================================================
# 8. Stage 7.3 Adversarial Regression Tests: Schema-First & TOCTOU Defense
# ============================================================================

def test_explicit_path_type_with_url_like_value_rejected(isolated_security_env):
    """
    Ensures that when a parameter is explicitly typed as a path in the schema,
    passing a URL-like value does not bypass validation; it is recognized as a
    path parameter and rejected because remote URLs are not local paths.
    """
    ws_a = isolated_security_env["ws_a"]

    # 1. Classification check: Schema-first precedence treats explicit path type as path
    assert PathSecurityValidator.is_path_parameter("https://attacker.com/payload.py", "target_script", "path")
    assert PathSecurityValidator.is_path_parameter("http://169.254.169.254/latest/meta-data", "cfg_file", "filepath")

    # 2. Validator check: Remote URI scheme is rejected
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path("https://attacker.com/payload.py", [ws_a], base_dir=ws_a)
    assert "URI scheme 'https' is not an authorized local filesystem path" in str(exc_info.value)

    # 3. Execution plan check: Plan fails closed
    config = LCSConfig(
        root_dir=ws_a,
        db_path=os.path.join(ws_a, "lcs.db"),
        cas_root=os.path.join(ws_a, "cas"),
        key_store_dir=os.path.join(ws_a, "keys"),
        schema_dir=os.path.abspath("lcs/schemas"),
        workspace_root=ws_a,
    )
    config.ensure_directories()

    with LCSContext(config=config, auto_migrate=True) as ctx:
        script_path = os.path.join(ws_a, "gen.py")
        with open(script_path, "w") as f:
            f.write("print('hello')\n")
        content_hash = hashlib.sha256(open(script_path, "rb").read()).hexdigest()
        rec = UnifiedResourceRecord(
            urn="urn:lcs:skill:test:gen",
            name="gen-step",
            resource_type=ResourceType.SKILL,
            display_name="Gen Step",
            description="Testing legitimate gen",
            raw_content=open(script_path).read(),
            raw_content_digest=content_hash,
            provenance=ProvenanceRecord(
                origin_host="generic_posix",
                precedence_tier="WORKSPACE",
                source_path=script_path,
                resolved_path=script_path,
                content_hash=content_hash
            )
        )
        ctx.inventory._persist_and_bind_capability(rec)

        step = PlanStep(
            step_id="step-url-attack",
            step_index=1,
            capability_urn="urn:lcs:skill:test:gen",
            display_name="URL Attack Step",
            sub_goal="Attempt URL path bypass",
            selection_reason="Testing URL bypass prevention",
            input_bindings={
                "target_script": StepInputBinding("target_script", "path", True, bound_value="https://attacker.com/evil.py")
            },
            output_definitions={"result": StepOutputDefinition("result", "string")},
            dependencies=[]
        )
        plan = ExecutionPlan(
            plan_id="plan-url-attack-01",
            request_query="URL bypass test",
            plan_type="SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=[step],
            dag_edges=[],
            execution_order=["step-url-attack"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Testing URL bypass prevention"
        )
        consent = ApproverConsent("auditor@local", ApproverRole.HUMAN_OPERATOR, "AUDIT")
        policy = InterfaceTrustPolicy("permissive", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
        token, _ = ctx.governance_engine.approve_plan(plan, approver=consent, active_policy=policy)

        res = ctx.execution_engine.execute_plan(plan, token)
        assert res.lifecycle_state.value in ("FAILED", "ABORTED")
        assert "URI scheme" in res.step_records[0].error_details


def test_explicit_path_type_with_json_like_value_rejected(isolated_security_env):
    """
    Ensures that when a parameter is explicitly typed as a path, passing a JSON
    payload does not bypass validation and is rejected as an invalid path.
    """
    ws_a = isolated_security_env["ws_a"]

    json_payload = '{"target": "/etc/shadow", "action": "exfiltrate"}'
    # 1. Classification check: Schema-first precedence treats explicit path type as path
    assert PathSecurityValidator.is_path_parameter(json_payload, "dest_file", "path")

    # 2. Validator check: JSON structure is rejected
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(json_payload, [ws_a], base_dir=ws_a)
    assert "JSON formatted string is not a valid filesystem path" in str(exc_info.value)


def test_explicit_path_type_with_multiline_value_rejected(isolated_security_env):
    """
    Ensures that multiline values passed to explicit path parameters do not bypass
    validation and are rejected to prevent command injection and log forging.
    """
    ws_a = isolated_security_env["ws_a"]

    multiline_payload = "/var/log/app.log\n/bin/cat /etc/passwd"
    # 1. Classification check
    assert PathSecurityValidator.is_path_parameter(multiline_payload, "log_path", "path")

    # 2. Validator check: Newline control characters are rejected
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(multiline_payload, [ws_a], base_dir=ws_a)
    assert "forbidden newline or control characters" in str(exc_info.value)


def test_file_uri_scheme_handling_and_confinement(isolated_security_env):
    """
    Tests handling of file:// URIs:
    - In-workspace file:// URIs resolve to authorized canonical paths.
    - Out-of-workspace file:// URIs are rejected.
    """
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    local_file = os.path.join(ws_a, "valid_data.txt")
    with open(local_file, "w") as f:
        f.write("VALID DATA")

    external_file = os.path.join(ws_b, "stolen_secret.txt")
    with open(external_file, "w") as f:
        f.write("SECRET")

    # In-workspace file:// URI succeeds
    valid_uri = f"file://{local_file}"
    resolved = PathSecurityValidator.validate_file_path(valid_uri, [ws_a], base_dir=ws_a)
    assert resolved == os.path.realpath(local_file)

    # Out-of-workspace file:// URI fails
    evil_uri = f"file://{external_file}"
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(evil_uri, [ws_a], base_dir=ws_a)
    assert "escapes authorized roots" in str(exc_info.value)


def test_ntfs_alternate_data_streams_rejected(isolated_security_env):
    """Verifies that NTFS Alternate Data Stream (ADS) syntax is strictly rejected across platforms."""
    ws_a = isolated_security_env["ws_a"]

    ads_targets = [
        "payload.txt:hidden_stream",
        "output.csv::$DATA",
        "nested/dir/file.py:stream:$DATA"
    ]
    for ads in ads_targets:
        with pytest.raises(PathTraversalExecutionError) as exc_info:
            PathSecurityValidator.validate_file_path(ads, [ws_a], base_dir=ws_a)
        assert "NTFS Alternate Data Stream (ADS) path syntax rejected" in str(exc_info.value)


def test_windows_dos_reserved_device_names_rejected(isolated_security_env):
    """Verifies that Windows DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) are rejected."""
    ws_a = isolated_security_env["ws_a"]

    dos_devices = ["con", "prn", "aux", "nul", "com1", "com2", "lpt1", "lpt2", "nul.txt", "con.json"]
    for dev in dos_devices:
        with pytest.raises(PathTraversalExecutionError) as exc_info:
            PathSecurityValidator.validate_file_path(dev, [ws_a], base_dir=ws_a)
        assert "Windows reserved DOS device name rejected" in str(exc_info.value)


def test_symlink_toctou_rejection_at_validator(isolated_security_env):
    """
    Verifies that symlinks within the workspace pointing to files are rejected
    by descriptor-level O_NOFOLLOW / symlink verification to prevent TOCTOU race conditions.
    """
    ws_a = isolated_security_env["ws_a"]

    real_file = os.path.join(ws_a, "target_toctou.txt")
    with open(real_file, "w") as f:
        f.write("ORIGINAL CONTENT")

    link_file = os.path.join(ws_a, "toctou_link.txt")
    try:
        os.symlink(real_file, link_file)
    except OSError:
        pytest.skip("Symlink creation not permitted in this environment")

    # Symlink within workspace should be rejected by O_NOFOLLOW / symlink check
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(link_file, [ws_a], base_dir=ws_a)
    assert "Symlink rejected" in str(exc_info.value) or "escapes authorized roots" in str(exc_info.value)


