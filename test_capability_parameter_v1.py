"""
Unit & Integration Tests for LCS Capability Parameter Understanding V1
======================================================================
Verifies all 12 functional and integration testing requirements:
1. All required parameters supplied -> READY
2. Missing required parameters -> INCOMPLETE (with clarifying questions)
3. Missing optional parameters -> READY (omitted optional parameters do not block)
4. Valid type mapping (string, integer, float, boolean, array, object)
5. Invalid type mapping (non-coercible types rejected with clear errors)
6. Allowed-value constraints (enum validation, valid vs invalid enum values)
7. Explicit versus inferred values (tracking is_explicit and mapping methods)
8. Ambiguous input (conflicting or multiple candidate values for same parameter)
9. Unknown input fields (tracked, inspected, and strict validation option)
10. Multiple parameters in one request (extracted and mapped concurrently)
11. Empty input (INCOMPLETE with questions or READY for 0-param capabilities)
12. Regression against existing semantic profiles and retrieval engine integrations.
"""

import os
import sys
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy
from capability_parameter_v1 import (
    ParameterReadinessStatus,
    MappingMethod,
    ParameterRequirement,
    MappedParameter,
    ParameterReadinessResult,
    ParameterUnderstandingEngineV1
)
from capability_profile_v2b import EvidenceSource, CapabilitySemanticProfile


# ----------------------------------------------------------------------------
# Test Fixtures: Realistic Capability Schemas from Corpus
# ----------------------------------------------------------------------------

@pytest.fixture
def param_engine():
    """Provides a standalone ParameterUnderstandingEngineV1."""
    return ParameterUnderstandingEngineV1()


@pytest.fixture
def git_commit_schema():
    """Realistic schema from git_vcs_server.py: inspect_git_commit."""
    return {
        "type": "object",
        "properties": {
            "repo_path": {"type": "string", "description": "Filesystem path to local git repository"},
            "commit_hash": {"type": "string", "description": "Full or abbreviated SHA-1 commit hash"}
        },
        "required": ["repo_path", "commit_hash"]
    }


@pytest.fixture
def git_clone_schema():
    """Realistic schema from git_vcs_server.py: clone_git_repository (with optional depth and branch)."""
    return {
        "type": "object",
        "properties": {
            "repo_url": {"type": "string", "description": "Remote git URL (HTTPS or SSH)"},
            "target_dir": {"type": "string", "description": "Destination directory path"},
            "depth": {"type": "integer", "description": "Shallow clone depth", "default": 0, "minimum": 0},
            "branch": {"type": "string", "description": "Optional branch name"}
        },
        "required": ["repo_url", "target_dir"]
    }


@pytest.fixture
def crypto_jwt_schema():
    """Realistic schema from crypto_security_server.py: verify_jwt_signature (with enum)."""
    return {
        "type": "object",
        "properties": {
            "token": {"type": "string", "description": "Encoded JWT string"},
            "algorithm": {"type": "string", "enum": ["RS256", "ES256", "HS256"], "default": "RS256"},
            "public_key": {"type": "string", "description": "Verification key"}
        },
        "required": ["token", "public_key"]
    }


@pytest.fixture
def statistical_variance_schema():
    """Realistic schema from sdk analytics: calculate_statistical_variance (array + optional int)."""
    return {
        "type": "object",
        "properties": {
            "samples": {"type": "array", "items": {"type": "number"}, "description": "Numerical samples list"},
            "ddof": {"type": "integer", "default": 1, "description": "Delta degrees of freedom", "minimum": 0}
        },
        "required": ["samples"]
    }


@pytest.fixture
def zero_param_schema():
    """Explicit zero-parameter schema."""
    return {
        "type": "object",
        "properties": {},
        "required": []
    }


@pytest.fixture(scope="module")
def populated_lcs_context():
    """Provides a fully populated LCSContext for end-to-end integration tests."""
    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(cfg)
        policy = InterfaceTrustPolicy(
            policy_name="test-params-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        proj_root = os.path.dirname(os.path.abspath(__file__))
        servers = [
            ("git-vcs", "evaluation_fixtures/git_vcs_server.py"),
            ("crypto-security", "evaluation_fixtures/crypto_security_server.py")
        ]

        for s_name, s_rel in servers:
            s_path = os.path.join(proj_root, s_rel)
            ctx.discovery_pipeline.discover_and_register_mcp_server(
                command=[sys.executable, s_path],
                server_name=s_name,
                trust_policy=policy
            )

        yield ctx
        ctx.close()


# ----------------------------------------------------------------------------
# 1. All Required Parameters Supplied -> READY
# ----------------------------------------------------------------------------

def test_1_all_required_parameters_supplied(param_engine, git_commit_schema):
    """Verifies that providing all required parameters yields READY status."""
    user_input = "repo_path=/Users/pavan/repo commit_hash=4a5b6c7d8e9f0123456789abcdef0123456789ab"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input=user_input,
        raw_schema=git_commit_schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert len(res.missing_required) == 0
    assert "repo_path" in res.mapped_parameters
    assert res.mapped_parameters["repo_path"].is_valid
    assert res.mapped_parameters["repo_path"].normalized_value == "/Users/pavan/repo"
    assert "commit_hash" in res.mapped_parameters
    assert res.mapped_parameters["commit_hash"].is_valid
    assert res.mapped_parameters["commit_hash"].normalized_value == "4a5b6c7d8e9f0123456789abcdef0123456789ab"
    assert len(res.clarifying_questions) == 0


# ----------------------------------------------------------------------------
# 2. Missing Required Parameters -> INCOMPLETE
# ----------------------------------------------------------------------------

def test_2_missing_required_parameters(param_engine, git_commit_schema):
    """Verifies that missing required parameters yields INCOMPLETE and produces clarifying questions."""
    user_input = "repo_path=/Users/pavan/repo"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input=user_input,
        raw_schema=git_commit_schema
    )

    assert res.status == ParameterReadinessStatus.INCOMPLETE
    assert res.missing_required == ["commit_hash"]
    assert "repo_path" in res.mapped_parameters
    assert len(res.clarifying_questions) == 1
    assert "commit_hash" in res.clarifying_questions[0]
    assert "Full or abbreviated SHA-1 commit hash" in res.clarifying_questions[0]


# ----------------------------------------------------------------------------
# 3. Missing Optional Parameters -> READY
# ----------------------------------------------------------------------------

def test_3_missing_optional_parameters(param_engine, git_clone_schema):
    """Verifies that omitting optional parameters does not block READY status and distinguishes defaults."""
    user_input = "repo_url=https://github.com/example/repo target_dir=/tmp/target"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:clone-git-repository",
        user_input=user_input,
        raw_schema=git_clone_schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert len(res.missing_required) == 0
    # Optional parameter WITHOUT default is correctly recorded in missing_optional
    assert "branch" in res.missing_optional
    # Optional parameter WITH default is satisfied by default and NOT in missing_optional
    assert "depth" not in res.missing_optional
    assert "depth" in res.mapped_parameters
    assert not res.mapped_parameters["depth"].is_explicit
    assert res.mapped_parameters["depth"].mapping_method == MappingMethod.DEFAULT_VALUE
    assert res.mapped_parameters["depth"].normalized_value == 0
    assert "1 parameter(s) satisfied by schema default" in res.explanation
    assert "1 optional parameter(s) omitted without default" in res.explanation


# ----------------------------------------------------------------------------
# 4. Valid Type Mapping (string, integer, float, boolean, array, object)
# ----------------------------------------------------------------------------

def test_4_valid_type_mapping(param_engine):
    """Verifies valid type conversion and normalization across all JSON-compatible types."""
    schema = {
        "type": "object",
        "properties": {
            "str_val": {"type": "string"},
            "int_val": {"type": "integer"},
            "float_val": {"type": "number"},
            "bool_val": {"type": "boolean"},
            "arr_val": {"type": "array", "items": {"type": "integer"}},
            "obj_val": {"type": "object"}
        },
        "required": ["str_val", "int_val", "float_val", "bool_val", "arr_val", "obj_val"]
    }

    user_input = {
        "str_val": "  hello world  ",
        "int_val": "42",
        "float_val": "3.14159",
        "bool_val": "yes",
        "arr_val": [10, 20, 30],
        "obj_val": {"key": "value"}
    }

    res = param_engine.evaluate_readiness(
        capability="custom:types",
        user_input=user_input,
        raw_schema=schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert res.mapped_parameters["str_val"].normalized_value == "hello world"
    assert res.mapped_parameters["int_val"].normalized_value == 42
    assert res.mapped_parameters["float_val"].normalized_value == 3.14159
    assert res.mapped_parameters["bool_val"].normalized_value is True
    assert res.mapped_parameters["arr_val"].normalized_value == [10, 20, 30]
    assert res.mapped_parameters["obj_val"].normalized_value == {"key": "value"}


# ----------------------------------------------------------------------------
# 5. Invalid Type Mapping -> INVALID
# ----------------------------------------------------------------------------

def test_5_invalid_type_mapping(param_engine, statistical_variance_schema):
    """Verifies that incompatible types fail validation and produce INVALID status."""
    # ddof expects integer, given "not_a_number"
    user_input = "samples=[1.0, 2.0] ddof=not_a_number"
    res = param_engine.evaluate_readiness(
        capability="custom:stat",
        user_input=user_input,
        raw_schema=statistical_variance_schema
    )

    assert res.status == ParameterReadinessStatus.INVALID
    assert not res.mapped_parameters["ddof"].is_valid
    assert "cannot parse 'not_a_number' as integer" in res.mapped_parameters["ddof"].validation_error


def test_5_invalid_array_element_type(param_engine, statistical_variance_schema):
    """Verifies that array elements violating item type constraints are rejected."""
    # samples expects array of numbers, but contains a non-numeric string
    user_input = {"samples": [1.0, "invalid_num"]}
    res = param_engine.evaluate_readiness(
        capability="custom:stat",
        user_input=user_input,
        raw_schema=statistical_variance_schema
    )

    assert res.status == ParameterReadinessStatus.INVALID
    assert not res.mapped_parameters["samples"].is_valid
    assert "Array item error" in res.mapped_parameters["samples"].validation_error


# ----------------------------------------------------------------------------
# 6. Allowed-Value Constraints (Enum)
# ----------------------------------------------------------------------------

def test_6_allowed_value_constraints_valid(param_engine, crypto_jwt_schema):
    """Verifies valid enum selection succeeds."""
    user_input = "token=xyz public_key=abc algorithm=ES256"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.crypto:jwt",
        user_input=user_input,
        raw_schema=crypto_jwt_schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert res.mapped_parameters["algorithm"].normalized_value == "ES256"
    assert res.mapped_parameters["algorithm"].is_valid


def test_6_allowed_value_constraints_invalid(param_engine, crypto_jwt_schema):
    """Verifies invalid enum selection is rejected with clear allowed-values explanation."""
    user_input = "token=xyz public_key=abc algorithm=BLOWFISH"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.crypto:jwt",
        user_input=user_input,
        raw_schema=crypto_jwt_schema
    )

    assert res.status == ParameterReadinessStatus.INVALID
    assert not res.mapped_parameters["algorithm"].is_valid
    assert "Allowed values: ['RS256', 'ES256', 'HS256']" in res.mapped_parameters["algorithm"].validation_error


# ----------------------------------------------------------------------------
# 7. Explicit Versus Inferred / Default Values
# ----------------------------------------------------------------------------

def test_7_explicit_versus_inferred_values(param_engine, crypto_jwt_schema):
    """Verifies clear distinction between explicitly supplied and schema default values."""
    # Provide token and public_key explicitly, omit algorithm (default RS256)
    user_input = "token=token123 public_key=key456"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.crypto:jwt",
        user_input=user_input,
        raw_schema=crypto_jwt_schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert res.mapped_parameters["token"].is_explicit is True
    assert res.mapped_parameters["token"].mapping_method == MappingMethod.EXPLICIT_KEY_VALUE
    assert res.mapped_parameters["public_key"].is_explicit is True

    # algorithm should be non-explicit default
    assert res.mapped_parameters["algorithm"].is_explicit is False
    assert res.mapped_parameters["algorithm"].mapping_method == MappingMethod.DEFAULT_VALUE
    assert res.mapped_parameters["algorithm"].normalized_value == "RS256"


# ----------------------------------------------------------------------------
# 8. Ambiguous Input
# ----------------------------------------------------------------------------

def test_8_ambiguous_input_conflicting_values(param_engine, git_commit_schema):
    """Verifies that supplying multiple conflicting values for a parameter is flagged as ambiguous."""
    user_input = "repo_path=/var/repo1 repo_path=/var/repo2 commit_hash=1234567"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input=user_input,
        raw_schema=git_commit_schema
    )

    assert res.status == ParameterReadinessStatus.INVALID
    assert not res.mapped_parameters["repo_path"].is_valid
    assert "Conflicting values" in res.mapped_parameters["repo_path"].validation_error


def test_8_ambiguous_semantic_slot_extraction(param_engine, git_commit_schema):
    """Verifies that multiple unassigned filesystem paths in natural language are flagged as ambiguous."""
    user_input = "inspect commit 1234567 in /first/repo/path or /second/repo/path"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input=user_input,
        raw_schema=git_commit_schema
    )

    assert res.status == ParameterReadinessStatus.INVALID
    assert not res.mapped_parameters["repo_path"].is_valid
    assert "Ambiguous input: multiple filesystem paths" in res.mapped_parameters["repo_path"].validation_error


# ----------------------------------------------------------------------------
# 9. Unknown Input Fields
# ----------------------------------------------------------------------------

def test_9_unknown_input_fields_tracked(param_engine, git_commit_schema):
    """Verifies that unrecognized inputs are tracked and inspected."""
    user_input = "repo_path=/var/repo commit_hash=1234567 extra_unsupported_arg=foobar"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input=user_input,
        raw_schema=git_commit_schema
    )

    # Standard mode permits extra fields while tracking them
    assert res.status == ParameterReadinessStatus.READY
    assert "extra_unsupported_arg" in res.unknown_inputs
    assert res.unknown_inputs["extra_unsupported_arg"] == "foobar"


def test_9_unknown_input_fields_strict_mode(param_engine, git_commit_schema):
    """Verifies that strict schema enforcement rejects unknown input parameters."""
    user_input = "repo_path=/var/repo commit_hash=1234567 extra_unsupported_arg=foobar"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input=user_input,
        raw_schema=git_commit_schema,
        strict_unknowns=True
    )

    assert res.status == ParameterReadinessStatus.INVALID
    assert "Unknown input parameters not allowed" in res.explanation


# ----------------------------------------------------------------------------
# 10. Multiple Parameters in One Request
# ----------------------------------------------------------------------------

def test_10_multiple_parameters_in_one_request(param_engine):
    """Verifies that 3+ parameters in a complex request are parsed and mapped correctly."""
    diff_schema = {
        "type": "object",
        "properties": {
            "repo_path": {"type": "string"},
            "revision_a": {"type": "string"},
            "revision_b": {"type": "string"},
            "context_lines": {"type": "integer", "default": 3}
        },
        "required": ["repo_path", "revision_a", "revision_b"]
    }

    user_input = "--repo_path /home/user/project --revision_a main --revision_b feature-x --context_lines 5"
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:format-git-diff",
        user_input=user_input,
        raw_schema=diff_schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert res.mapped_parameters["repo_path"].normalized_value == "/home/user/project"
    assert res.mapped_parameters["revision_a"].normalized_value == "main"
    assert res.mapped_parameters["revision_b"].normalized_value == "feature-x"
    assert res.mapped_parameters["context_lines"].normalized_value == 5


# ----------------------------------------------------------------------------
# 11. Empty Input
# ----------------------------------------------------------------------------

def test_11_empty_input_for_required_capability(param_engine, git_commit_schema):
    """Verifies that empty input for a capability with required parameters returns INCOMPLETE."""
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input="",
        raw_schema=git_commit_schema
    )

    assert res.status == ParameterReadinessStatus.INCOMPLETE
    assert set(res.missing_required) == {"repo_path", "commit_hash"}
    assert len(res.clarifying_questions) == 2


def test_11_empty_input_for_zero_parameter_capability(param_engine, zero_param_schema):
    """Verifies that empty input for a zero-parameter capability returns READY."""
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.system:get-system-info",
        user_input="",
        raw_schema=zero_param_schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert len(res.missing_required) == 0
    assert len(res.mapped_parameters) == 0


def test_11_arguments_supplied_to_zero_parameter_capability(param_engine, zero_param_schema):
    """Verifies that supplying arguments to a zero-parameter capability returns INCOMPATIBLE."""
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.system:get-system-info",
        user_input="param1=foo param2=bar",
        raw_schema=zero_param_schema
    )

    assert res.status == ParameterReadinessStatus.INCOMPATIBLE
    assert "takes zero input parameters" in res.explanation


# ----------------------------------------------------------------------------
# 12. Regression & End-to-End Context Integration
# ----------------------------------------------------------------------------

def test_12_end_to_end_context_integration(populated_lcs_context):
    """Verifies integration with live LCSContext, registered capabilities, and semantic profiles."""
    ctx = populated_lcs_context
    assert hasattr(ctx, "parameter_engine")
    assert isinstance(ctx.parameter_engine, ParameterUnderstandingEngineV1)

    # 1. Inspect registered git-vcs tool: parse-git-status
    urn = "urn:lcs:tool:mcp.git-vcs:parse-git-status"
    res1 = ctx.parameter_engine.evaluate_readiness(
        capability=urn,
        user_input="repo_path=/Users/pavan/Desktop/LCS"
    )

    assert res1.status == ParameterReadinessStatus.READY
    assert res1.mapped_parameters["repo_path"].normalized_value == "/Users/pavan/Desktop/LCS"

    # 2. Inspect with missing parameters
    res2 = ctx.parameter_engine.evaluate_readiness(
        capability=urn,
        user_input=""
    )
    assert res2.status == ParameterReadinessStatus.INCOMPLETE
    assert "repo_path" in res2.missing_required
    assert len(res2.clarifying_questions) == 1

    # 3. Test CLI formatting output
    cli_text = ctx.parameter_engine.format_cli_output(res1)
    assert "LIVING CAPABILITY SYSTEM (LCS) — CAPABILITY PARAMETER UNDERSTANDING" in cli_text
    assert "Readiness Status:    READY" in cli_text
    assert "repo_path: \"/Users/pavan/Desktop/LCS\"" in cli_text


def test_12_cli_command_invocation(populated_lcs_context, monkeypatch, capsys):
    """Verifies that 'lcs params' CLI command works end-to-end with human and JSON output."""
    from lcs.cli import main

    root_dir = populated_lcs_context.config.root_dir

    # 1. Human-readable CLI invocation
    argv1 = ["--root", root_dir, "params", "urn:lcs:tool:mcp.git-vcs:parse-git-status", "repo_path=/Users/test/repo"]
    ret1 = main(argv1)
    assert ret1 == 0
    out1, _ = capsys.readouterr()
    assert "Readiness Status:    READY" in out1
    assert "repo_path" in out1

    # 2. JSON formatted CLI invocation
    argv2 = ["--root", root_dir, "params", "urn:lcs:tool:mcp.git-vcs:parse-git-status", "--json", '{"repo_path": "/Users/test/repo"}', "--format-json"]
    ret2 = main(argv2)
    assert ret2 == 0
    out2, _ = capsys.readouterr()
    assert '"status": "READY"' in out2
    assert '"normalized_value": "/Users/test/repo"' in out2

    # 3. Missing argument CLI invocation
    argv3 = ["--root", root_dir, "params", "urn:lcs:tool:mcp.git-vcs:parse-git-status", ""]
    ret3 = main(argv3)
    assert ret3 == 0
    out3, _ = capsys.readouterr()
    assert "Readiness Status:    INCOMPLETE" in out3
    assert "Please provide required parameter 'repo_path'" in out3


# ============================================================================
# SEMANTIC VERIFICATION TESTS (Targeted Audit Areas)
# ============================================================================

def test_semantic_required_parameter_satisfied_by_default(param_engine):
    """Verifies that a valid schema default satisfies a required parameter when omitted."""
    schema = {
        "type": "object",
        "properties": {
            "req_with_default": {"type": "integer", "default": 42},
            "req_without_default": {"type": "string"}
        },
        "required": ["req_with_default", "req_without_default"]
    }

    # Only supply req_without_default; req_with_default should be satisfied by default 42
    res = param_engine.evaluate_readiness(
        capability="custom:defaults",
        user_input='req_without_default="custom_str"',
        raw_schema=schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert len(res.missing_required) == 0
    assert res.mapped_parameters["req_with_default"].normalized_value == 42
    assert res.mapped_parameters["req_with_default"].is_explicit is False
    assert res.mapped_parameters["req_with_default"].mapping_method == MappingMethod.DEFAULT_VALUE
    assert res.mapped_parameters["req_without_default"].normalized_value == "custom_str"
    assert res.mapped_parameters["req_without_default"].is_explicit is True


def test_semantic_user_value_overrides_default(param_engine):
    """Verifies that user-supplied value takes strict precedence over default."""
    schema = {
        "type": "object",
        "properties": {
            "threshold": {"type": "number", "default": 0.5}
        },
        "required": ["threshold"]
    }

    res = param_engine.evaluate_readiness(
        capability="custom:override",
        user_input="threshold=0.95",
        raw_schema=schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert res.mapped_parameters["threshold"].normalized_value == 0.95
    assert res.mapped_parameters["threshold"].is_explicit is True
    assert res.mapped_parameters["threshold"].mapping_method == MappingMethod.EXPLICIT_KEY_VALUE


def test_semantic_no_type_only_blind_assignment(param_engine):
    """Verifies that values are NEVER assigned to parameters solely because their data type looks compatible."""
    schema = {
        "type": "object",
        "properties": {
            "target_dir": {"type": "string", "description": "Target directory path"},
            "retry_count": {"type": "integer", "description": "Number of retry attempts"}
        },
        "required": ["target_dir", "retry_count"]
    }

    # Text contains a string and an integer, but they have no semantic or keyword link to target_dir or retry_count
    # e.g.: "Process 5 apples with apple_pie"
    res = param_engine.evaluate_readiness(
        capability="custom:blind",
        user_input="Process 5 apples with apple_pie",
        raw_schema=schema
    )

    # 5 should NOT be assigned to retry_count, and apple_pie should NOT be assigned to target_dir
    assert res.status == ParameterReadinessStatus.INCOMPLETE
    assert "target_dir" in res.missing_required
    assert "retry_count" in res.missing_required
    assert "target_dir" not in res.mapped_parameters
    assert "retry_count" not in res.mapped_parameters


def test_semantic_quoted_word_not_treated_as_path(param_engine, git_commit_schema):
    """Verifies that a quoted word (e.g. branch name 'main') is NOT treated as a filesystem path."""
    user_input = 'inspect commit a1b2c3d in /var/repo with branch "main"'
    res = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        user_input=user_input,
        raw_schema=git_commit_schema
    )

    assert res.status == ParameterReadinessStatus.READY
    assert res.mapped_parameters["repo_path"].normalized_value == "/var/repo"
    assert res.mapped_parameters["repo_path"].is_valid is True
    assert res.mapped_parameters["commit_hash"].normalized_value == "a1b2c3d"


def test_semantic_multiple_arrays_flagged_as_ambiguous(param_engine, statistical_variance_schema):
    """Verifies that multiple unkeyed candidate arrays in natural language are flagged as ambiguous."""
    user_input = "calculate statistical variance for [1.0, 2.0] and [3.0, 4.0]"
    res = param_engine.evaluate_readiness(
        capability="custom:stat",
        user_input=user_input,
        raw_schema=statistical_variance_schema
    )

    assert res.status == ParameterReadinessStatus.INVALID
    assert not res.mapped_parameters["samples"].is_valid
    assert "Ambiguous input: multiple array structures" in res.mapped_parameters["samples"].validation_error


def test_semantic_unknown_schema_versus_zero_param_incompatible(param_engine, zero_param_schema):
    """Verifies clear distinction between unknown schema and zero-parameter incompatible input."""
    # 1. Unknown schema: profile has EvidenceSource.UNKNOWN
    unknown_profile = {
        "inputs": {"value": None, "evidence": EvidenceSource.UNKNOWN, "notes": "No schema"}
    }
    res_unknown = param_engine.evaluate_readiness(
        capability=unknown_profile,
        user_input="foo=bar"
    )
    assert res_unknown.status == ParameterReadinessStatus.INCOMPATIBLE
    assert "unknown input schema parameters" in res_unknown.explanation

    # 2. Zero-parameter schema: known schema that explicitly takes 0 parameters
    res_zero = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:mcp.system:get-sys-info",
        user_input="foo=bar",
        raw_schema=zero_param_schema
    )
    assert res_zero.status == ParameterReadinessStatus.INCOMPATIBLE
    assert "takes zero input parameters" in res_zero.explanation


def test_semantic_nested_object_validation(param_engine):
    """Verifies object validation accepts valid dict/JSON and rejects non-object strings."""
    schema = {
        "type": "object",
        "properties": {
            "metadata": {"type": "object", "description": "Structured metadata dictionary"}
        },
        "required": ["metadata"]
    }

    # Valid dict
    res_valid = param_engine.evaluate_readiness(
        capability="custom:obj",
        user_input={"metadata": {"env": "prod", "version": 1}},
        raw_schema=schema
    )
    assert res_valid.status == ParameterReadinessStatus.READY
    assert res_valid.mapped_parameters["metadata"].normalized_value == {"env": "prod", "version": 1}

    # Invalid object (scalar string)
    res_invalid = param_engine.evaluate_readiness(
        capability="custom:obj",
        user_input='metadata="not_a_json_dict"',
        raw_schema=schema
    )
    assert res_invalid.status == ParameterReadinessStatus.INVALID
    assert "failed to parse JSON object" in res_invalid.mapped_parameters["metadata"].validation_error


def test_semantic_all_four_readiness_statuses_mutually_consistent(param_engine, git_commit_schema, zero_param_schema):
    """Verifies that all 4 statuses (READY, INCOMPLETE, INVALID, INCOMPATIBLE) are uniquely produced."""
    # 1. READY
    res_ready = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:test:inspect",
        user_input="repo_path=/var/repo commit_hash=a1b2c3d",
        raw_schema=git_commit_schema
    )
    assert res_ready.status == ParameterReadinessStatus.READY

    # 2. INCOMPLETE
    res_incomplete = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:test:inspect",
        user_input="repo_path=/var/repo",
        raw_schema=git_commit_schema
    )
    assert res_incomplete.status == ParameterReadinessStatus.INCOMPLETE

    # 3. INVALID
    res_invalid = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:test:inspect",
        user_input="repo_path=/var/repo commit_hash=123 repo_path=/different/repo",
        raw_schema=git_commit_schema
    )
    assert res_invalid.status == ParameterReadinessStatus.INVALID

    # 4. INCOMPATIBLE
    res_incompatible = param_engine.evaluate_readiness(
        capability="urn:lcs:tool:test:zero",
        user_input="arg=val",
        raw_schema=zero_param_schema
    )
    assert res_incompatible.status == ParameterReadinessStatus.INCOMPATIBLE
