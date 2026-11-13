"""
Unit & Integration Tests for LCS Capability Retrieval Engine V1.1
================================================================
Verifies that V1.1 successfully resolves all 9 documented V1 failure modes:
1. S05: Polygonal area calculation with domain terms (parcel, footprint).
2. S09: Semantic version deconstruction (major, minor, patch).
3. S11: 2FA / authenticator terminology mapping to TOTP tokens.
4. S12: Colloquial encryption ("scramble", "symmetric cipher key").
5. S13: Action directionality inversion (decrypt vs encrypt ranking).
6. S14: Checksum and fingerprint terminology mapping to SHA-256 digest.
7. S15: Certificate expiration morphological mapping (expiry, expiration).
8. S16: ICMP reachability mapping to ping host.
9. S19: Git commit attribution dual-target resolution.

Also verifies:
- Retention of 100% abstention precision on ambiguous and out-of-domain queries.
- Clean coexistence of frozen V1 and V1.1 engines in LCSContext.
"""

import os
import sys
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy
from capability_retrieval_v1 import CapabilityRetrievalEngine as CapabilityRetrievalEngineV1
from capability_retrieval_v1_1 import (
    CapabilityRetrievalEngineV11,
    QueryProcessorV11,
    ProcessedQueryV11
)

PROJ_ROOT = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
def populated_lcs_context():
    """Provides an LCSContext populated with all 40 capabilities across 7 servers."""
    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(cfg)
        policy = InterfaceTrustPolicy(
            policy_name="test-retrieval-v11-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        servers = [
            ("doc-tools", "mcp_test_server_fixture.py"),
            ("geo-tools", "integration_tests/independent_mcp_server.py"),
            ("sdk-analytics", "integration_tests/mcp_sdk_server.py"),
            ("crypto-security", "evaluation_fixtures/crypto_security_server.py"),
            ("system-devops", "evaluation_fixtures/system_devops_server.py"),
            ("git-vcs", "evaluation_fixtures/git_vcs_server.py"),
            ("data-transform", "evaluation_fixtures/data_transform_server.py")
        ]

        for s_name, s_rel in servers:
            s_path = os.path.join(PROJ_ROOT, s_rel)
            ctx.discovery_pipeline.discover_and_register_mcp_server(
                command=[sys.executable, s_path],
                server_name=s_name,
                trust_policy=policy
            )

        yield ctx
        ctx.close()


def test_morphological_normalizer_stem():
    """Verifies that conservative derivational stemmer conflates irregular technical roots."""
    stemmer = QueryProcessorV11.stem
    assert stemmer("expiration") == "expir"
    assert stemmer("expiry") == "expir"
    assert stemmer("expires") == "expir"
    assert stemmer("polygonal") == "polygon"
    assert stemmer("polygons") == "polygon"
    assert stemmer("committed") == "commit"
    assert stemmer("authenticator") == "authenticat"
    assert stemmer("authentication") == "authenticat"
    assert stemmer("deconstruction") == "deconstruct"
    assert stemmer("deconstruct") == "deconstruct"
    assert stemmer("statistical") == "statistic"
    assert stemmer("statistics") == "statistic"


def test_query_processor_action_intent_and_hints():
    """Verifies that QueryProcessorV11 detects action intent and input/output hints."""
    q1 = "Recover original plaintext from encrypted ciphertext payload"
    pq1 = QueryProcessorV11.process(q1)
    assert pq1.action_intent == "DECRYPT"
    assert "ciphertext" in pq1.source_input_hints
    assert "plaintext" in pq1.target_output_hints

    q2 = "Scramble secret text with a symmetric cipher key and nonce"
    pq2 = QueryProcessorV11.process(q2)
    assert pq2.action_intent == "ENCRYPT"


def test_failure_s05_polygonal_area(populated_lcs_context):
    """Failure S05: 'Measure the square footprint of this multi-point polygonal parcel'."""
    q = "Measure the square footprint of this multi-point polygonal parcel"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.geo-tools:calculate-polygon-area"
    assert top.relevance_score >= 0.40


def test_failure_s09_semver_deconstruction(populated_lcs_context):
    """Failure S09: 'Deconstruct release version numbering into major minor and patch levels'."""
    q = "Deconstruct release version numbering into major minor and patch levels"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.sdk-analytics:parse-semver-expression"
    assert top.relevance_score >= 0.25


def test_failure_s11_2fa_authenticator(populated_lcs_context):
    """Failure S11: 'Generate a 2FA two-factor authenticator code from our seed key'."""
    q = "Generate a 2FA two-factor authenticator code from our seed key"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.crypto-security:generate-totp-token"
    assert top.relevance_score >= 0.40


def test_failure_s12_colloquial_encryption(populated_lcs_context):
    """Failure S12: 'Scramble secret text with a symmetric cipher key and nonce'."""
    q = "Scramble secret text with a symmetric cipher key and nonce"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm"
    assert top.relevance_score >= 0.40


def test_failure_s13_directionality_inversion(populated_lcs_context):
    """
    Failure S13: 'Recover original plaintext from encrypted ciphertext payload'.
    Must rank decrypt_aes_gcm #1, strictly above encrypt_aes_gcm.
    """
    q = "Recover original plaintext from encrypted ciphertext payload"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=5)
    assert not res.abstained
    assert len(res.candidates) >= 1
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.crypto-security:decrypt-aes-gcm"

    # Verify directionality adjustment was applied
    assert top.directionality_adjustment is not None
    assert "boost" in top.directionality_adjustment.lower()

    # If encrypt_aes_gcm is in candidates, verify its score is penalised below decrypt
    encrypt_cand = next((c for c in res.candidates if c.capability_urn == "urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm"), None)
    if encrypt_cand:
        assert top.relevance_score > encrypt_cand.relevance_score
        assert "penaliz" in encrypt_cand.directionality_adjustment.lower()


def test_failure_s14_checksum_fingerprint(populated_lcs_context):
    """Failure S14: 'Generate a SHA256 checksum fingerprint for this payload'."""
    q = "Generate a SHA256 checksum fingerprint for this payload"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.crypto-security:hash-sha256-digest"
    assert top.relevance_score >= 0.25


def test_failure_s15_cert_expiration(populated_lcs_context):
    """Failure S15: 'Look at the SSL cert expiration date on our web server'."""
    q = "Look at the SSL cert expiration date on our web server"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.crypto-security:inspect-tls-certificate"
    assert top.relevance_score >= 0.25


def test_failure_s16_icmp_reachability(populated_lcs_context):
    """Failure S16: 'Check if a target machine answers ICMP packets across the internet'."""
    q = "Check if a target machine answers ICMP packets across the internet"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    assert top.capability_urn == "urn:lcs:tool:mcp.system-devops:ping-network-host"
    assert top.relevance_score >= 0.40


def test_failure_s19_git_attribution(populated_lcs_context):
    """Failure S19: 'Who committed the latest code changes in this git repo'."""
    q = "Who committed the latest code changes in this git repo"
    res = populated_lcs_context.retrieval_engine_v11.retrieve(q, limit=3)
    assert not res.abstained
    assert len(res.candidates) > 0
    top = res.candidates[0]
    valid_targets = {
        "urn:lcs:tool:mcp.git-vcs:inspect-git-commit",
        "urn:lcs:tool:mcp.git-vcs:extract-git-blame"
    }
    assert top.capability_urn in valid_targets
    assert top.relevance_score >= 0.40


def test_abstention_preserved(populated_lcs_context):
    """Verifies that out-of-domain and ambiguous requests continue to abstain 100%."""
    ood_queries = [
        "Send an email message with attachment via SMTP",
        "Transcribe voice audio recording from MP3 to text",
        "Deploy a Docker container to a remote Kubernetes cluster",
        "Scrape product prices from Amazon ecommerce web page"
    ]
    for q in ood_queries:
        res = populated_lcs_context.retrieval_engine_v11.retrieve(q)
        assert res.abstained is True
        assert res.abstention_code in ("NO_SUITABLE_CAPABILITY_FOUND", "AMBIGUOUS_REQUEST")
        assert len(res.candidates) == 0

    ambig_queries = [
        "Inspect data...",
        "Run analysis...",
        "Manage items..."
    ]
    for q in ambig_queries:
        res = populated_lcs_context.retrieval_engine_v11.retrieve(q)
        assert res.abstained is True


def test_engine_coexistence_and_cli_output(populated_lcs_context):
    """Verifies both V1 and V1.1 engines coexist in LCSContext cleanly."""
    ctx = populated_lcs_context
    assert hasattr(ctx, "retrieval_engine_v1")
    assert hasattr(ctx, "retrieval_engine_v11")
    assert ctx.retrieval_engine is ctx.retrieval_engine_v11

    # Compare on S13: V1 inverts, V1.1 does not
    q = "Recover original plaintext from encrypted ciphertext payload"
    res_v1 = ctx.retrieval_engine_v1.retrieve(q)
    res_v11 = ctx.retrieval_engine_v11.retrieve(q)

    # In V1, encrypt_aes_gcm ranks #1 due to parameter match 'plaintext'
    assert res_v1.candidates[0].capability_urn == "urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm"
    # In V1.1, decrypt_aes_gcm ranks #1
    assert res_v11.candidates[0].capability_urn == "urn:lcs:tool:mcp.crypto-security:decrypt-aes-gcm"

    # Test CLI output formatting
    out = ctx.retrieval_engine_v11.format_cli_output(res_v11)
    assert "LIVING CAPABILITY SYSTEM (LCS) — RETRIEVAL V1.1" in out
    assert "Action Intent:       DECRYPT" in out
    assert "Decrypt Aes Gcm" in out
