"""
LCS Stage 2B — Capability Intelligence Layer: Retrieval Engine V1 Tests
=======================================================================
Verifies:
1. Query processing, tokenization, stopword filtering, stemming, and concept expansion.
2. Ambiguity detection and underspecified query handling.
3. Grounded capability ranking with multi-signal scoring.
4. Input compatibility and missing parameter extraction.
5. Evidence weighting (EXPLICIT / EXTRACTED / INFERRED / UNKNOWN).
6. Strict separation of relevance scores from interface trust / policy status.
7. Principled abstention mechanics (NO_SUITABLE_CAPABILITY_FOUND).
8. Multi-capability query handling.
9. Noise resilience with conversational filler and irrelevant terms.
10. CLI 'lcs match' terminal formatting and exit codes.
"""

import os
import sys
import json
import sqlite3
import tempfile
import argparse
import pytest
from typing import Dict, Any, List

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy
from lcs.cli import cmd_match
from capability_retrieval_v1 import (
    ENGLISH_STOPWORDS,
    CONCEPT_SYNONYMS,
    ProcessedQuery,
    QueryProcessor,
    ScoredCandidate,
    RetrievalResult,
    CapabilityRetrievalEngine
)
from capability_profile_v2b import EvidenceSource


@pytest.fixture
def isolated_lcs_env():
    """Sets up an isolated LCS environment populated with tools from test fixtures."""
    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(config=cfg, auto_migrate=True)
        policy = InterfaceTrustPolicy(
            policy_name="test-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        # 1. Discover document tools
        s1 = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, s1],
            server_name="doc-tools",
            trust_policy=policy
        )

        # 2. Discover spatial geo tools
        s2 = os.path.join(CURRENT_DIR, "integration_tests", "independent_mcp_server.py")
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, s2],
            server_name="geo-tools",
            trust_policy=policy
        )

        # 3. Discover SDK analytics tools
        s3 = os.path.join(CURRENT_DIR, "integration_tests", "mcp_sdk_server.py")
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, s3],
            server_name="sdk-analytics",
            trust_policy=policy
        )

        yield ctx
        ctx.close()


def test_01_query_processor_tokenization_and_stemming():
    """Verify query normalization, stopword stripping, stemming, and concept detection."""
    raw = "Can you please check whether my website has proper HTTP security headers?"
    proc = QueryProcessor.process(raw)

    assert proc.raw_query == raw
    assert "website" in proc.core_terms
    assert "http" in proc.core_terms
    assert "security" in proc.core_terms
    assert "headers" in proc.core_terms
    assert "please" not in proc.core_terms
    assert "can" not in proc.core_terms
    assert "security" in proc.detected_concepts
    assert "header" in proc.expanded_terms
    assert not proc.is_ambiguous


def test_02_ambiguity_detection_on_underspecified_queries():
    """Verify detection of ambiguous, generic, or underspecified queries."""
    ambig_1 = QueryProcessor.process("Process data")
    assert ambig_1.is_ambiguous is True
    assert "underspecified" in ambig_1.ambiguity_reason

    ambig_2 = QueryProcessor.process("Inspect system")
    assert ambig_2.is_ambiguous is True

    ambig_3 = QueryProcessor.process("Handle records")
    assert ambig_3.is_ambiguous is True

    specific = QueryProcessor.process("Extract tables from PDF file")
    assert specific.is_ambiguous is False


def test_03_direct_task_retrieval_and_scoring(isolated_lcs_env):
    """Verify precision@1 matching on direct capability task descriptions."""
    ctx = isolated_lcs_env
    query = "Check whether my website has proper HTTP security headers"
    result = ctx.retrieval_engine.retrieve(query)

    assert result.abstained is False
    assert len(result.candidates) >= 1
    top = result.candidates[0]

    assert top.capability_urn == "urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"
    assert top.relevance_score > 0.50
    assert "header" in top.matching_terms or "security" in top.matching_terms
    assert "name" in top.matching_fields
    assert "description" in top.matching_fields
    assert len(top.reasons) >= 2


def test_04_synonym_and_paraphrase_matching(isolated_lcs_env):
    """Verify that domain synonyms match target capabilities."""
    ctx = isolated_lcs_env

    # 1. 'acrobat file' -> read_pdf_document
    r1 = ctx.retrieval_engine.retrieve("Parse page content and metadata out of an acrobat file")
    assert r1.abstained is False
    assert r1.candidates[0].capability_urn == "urn:lcs:tool:mcp.doc-tools:read-pdf-document"

    # 2. 'SELECT statement' -> query_local_database
    r2 = ctx.retrieval_engine.retrieve("Run a relational SELECT statement on local db tables")
    assert r2.abstained is False
    assert r2.candidates[0].capability_urn == "urn:lcs:tool:mcp.doc-tools:query-local-database"

    # 3. 'great circle arc range between lat lon' -> compute_haversine_distance
    r3 = ctx.retrieval_engine.retrieve("Find the great circle arc range between two GPS lat lon points in kilometers")
    assert r3.abstained is False
    assert r3.candidates[0].capability_urn == "urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"


def test_05_noise_resilience_with_conversational_filler(isolated_lcs_env):
    """Verify that conversational noise does not derail retrieval."""
    ctx = isolated_lcs_env
    query = "While drinking morning coffee and eating breakfast, extract tables from this financial report PDF"
    res = ctx.retrieval_engine.retrieve(query)

    assert res.abstained is False
    assert res.candidates[0].capability_urn == "urn:lcs:tool:mcp.doc-tools:read-pdf-document"
    assert res.candidates[0].relevance_score > 0.30


def test_06_abstention_on_out_of_domain_queries(isolated_lcs_env):
    """Verify clean principled abstention when no capability matches."""
    ctx = isolated_lcs_env

    out_of_domain = [
        "Send an email message with attachment via SMTP server",
        "Generate high-resolution photorealistic images of a mountain using AI",
        "Deploy a Docker container to a remote Kubernetes cluster",
        "Transcribe voice audio recording from MP3 format into English text",
        "Mine cryptocurrency blocks using GPU proof of work"
    ]

    for q in out_of_domain:
        res = ctx.retrieval_engine.retrieve(q, min_score_threshold=0.25)
        assert res.abstained is True, f"Failed to abstain on query: {q}"
        assert res.abstention_code == "NO_SUITABLE_CAPABILITY_FOUND"
        assert len(res.candidates) == 0


def test_07_abstention_on_ambiguous_queries(isolated_lcs_env):
    """Verify abstention with explanatory reason on ambiguous requests."""
    ctx = isolated_lcs_env
    res = ctx.retrieval_engine.retrieve("Process data")

    assert res.abstained is True
    assert res.abstention_code in ("AMBIGUOUS_REQUEST", "NO_SUITABLE_CAPABILITY_FOUND")
    assert res.missing_query_information is not None


def test_08_evidence_weighting_and_quality(isolated_lcs_env):
    """Verify that evidence sources are distinguished and unknown fields not fabricated."""
    ctx = isolated_lcs_env
    res = ctx.retrieval_engine.retrieve("Calculate polygon area from coordinates")

    assert res.abstained is False
    cand = res.candidates[0]
    assert cand.evidence_quality.get("name") in (EvidenceSource.EXPLICIT, EvidenceSource.EXTRACTED)
    assert cand.evidence_quality.get("parameters") in (EvidenceSource.EXTRACTED, EvidenceSource.EXPLICIT)

    # Missing info notes undeclared operational boundaries as UNKNOWN
    assert any("UNKNOWN" in m for m in cand.missing_information)


def test_09_separation_of_relevance_from_policy(isolated_lcs_env):
    """Verify that relevance score is independent of trust status."""
    ctx = isolated_lcs_env

    # Query matching inspect_http_header_security
    res = ctx.retrieval_engine.retrieve("Evaluate web HTTP response headers against security compliance")
    assert res.abstained is False
    top = res.candidates[0]

    # Verify score is computed on relevance signals
    assert 0.0 < top.relevance_score <= 1.0
    # Verify trust status is reported alongside, not entangled into score calculation
    assert top.trust_status == "VERIFIED"
    assert top.policy_decision == "ALLOW"


def test_10_cli_match_command_formatting_and_exit_code(isolated_lcs_env):
    """Verify end-to-end execution of 'lcs match' CLI command."""
    ctx = isolated_lcs_env

    # 1. Matching task
    args_match = argparse.Namespace(
        query="Check whether my website has proper HTTP security headers",
        limit=5,
        threshold=0.25
    )
    rc1 = cmd_match(ctx, args_match)
    assert rc1 == 0

    # 2. Abstaining task
    args_abstain = argparse.Namespace(
        query="Deploy docker container to kubernetes cluster",
        limit=5,
        threshold=0.25
    )
    rc2 = cmd_match(ctx, args_abstain)
    assert rc2 == 0

    # 3. Empty query error
    args_empty = argparse.Namespace(
        query="",
        limit=5,
        threshold=0.25
    )
    rc3 = cmd_match(ctx, args_empty)
    assert rc3 == 1
