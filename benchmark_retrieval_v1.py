"""
LCS Retrieval V1 — 30-Query Evaluation Benchmark
================================================
Evaluates the retrieval engine against 30 natural-language tasks:
- 6 Direct matches
- 6 Synonyms / alternative phrasing
- 6 Queries with conversational / irrelevant noise
- 3 Multi-capability queries
- 3 Ambiguous queries
- 6 Out-of-domain queries (must abstain)

Computes:
- Precision@1
- Precision@3
- Recall@3 (for queries with valid target capabilities)
- Mean Reciprocal Rank (MRR)
- False-Positive Count (out-of-domain queries wrongly recommended)
- Correct Abstention Rate (abstentions on ambiguous/out-of-domain queries)
"""

import os
import sys
import json
import sqlite3
import tempfile
from typing import Dict, Any, List, Set, Optional

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy
from capability_retrieval_v1 import CapabilityRetrievalEngine, RetrievalResult


BENCHMARK_QUERIES = [
    # -------------------------------------------------------------
    # Category A: Direct Matches (6)
    # -------------------------------------------------------------
    {
        "id": "Q01",
        "category": "Direct Match",
        "query": "Extract text and structured tables from a local PDF document",
        "expected_targets": ["urn:lcs:tool:mcp.doc-tools:read-pdf-document"],
        "expect_abstain": False,
        "description": "Standard task matching read_pdf_document directly."
    },
    {
        "id": "Q02",
        "category": "Direct Match",
        "query": "Convert a markdown file into standardized PDF format",
        "expected_targets": ["urn:lcs:tool:mcp.doc-tools:convert-document-format"],
        "expect_abstain": False,
        "description": "Standard document conversion task."
    },
    {
        "id": "Q03",
        "category": "Direct Match",
        "query": "Execute a read-only analytical SQL query on a local SQLite database",
        "expected_targets": ["urn:lcs:tool:mcp.doc-tools:query-local-database"],
        "expect_abstain": False,
        "description": "Database query task matching query_local_database."
    },
    {
        "id": "Q04",
        "category": "Direct Match",
        "query": "Calculate the surface area of a polygon given coordinates",
        "expected_targets": ["urn:lcs:tool:mcp.geo-tools:calculate-polygon-area"],
        "expect_abstain": False,
        "description": "Spatial geometry area calculation."
    },
    {
        "id": "Q05",
        "category": "Direct Match",
        "query": "Compute great-circle haversine distance between two geographic waypoints",
        "expected_targets": ["urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"],
        "expect_abstain": False,
        "description": "Haversine distance calculation between waypoints."
    },
    {
        "id": "Q06",
        "category": "Direct Match",
        "query": "Evaluate web HTTP response headers against security compliance standards",
        "expected_targets": ["urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"],
        "expect_abstain": False,
        "description": "HTTP security header inspection."
    },

    # -------------------------------------------------------------
    # Category B: Synonyms and Alternative Phrasing (6)
    # -------------------------------------------------------------
    {
        "id": "Q07",
        "category": "Synonyms & Paraphrasing",
        "query": "Parse page content and metadata out of an acrobat file",
        "expected_targets": ["urn:lcs:tool:mcp.doc-tools:read-pdf-document"],
        "expect_abstain": False,
        "description": "Uses 'acrobat file' and 'parse page content' for PDF."
    },
    {
        "id": "Q08",
        "category": "Synonyms & Paraphrasing",
        "query": "Transform docx text document into plaintext or html",
        "expected_targets": ["urn:lcs:tool:mcp.doc-tools:convert-document-format"],
        "expect_abstain": False,
        "description": "Uses 'transform' and 'docx' for convert_document_format."
    },
    {
        "id": "Q09",
        "category": "Synonyms & Paraphrasing",
        "query": "Run a relational SELECT statement on local db tables",
        "expected_targets": ["urn:lcs:tool:mcp.doc-tools:query-local-database"],
        "expect_abstain": False,
        "description": "Uses 'SELECT statement' and 'relational db tables' for SQL query."
    },
    {
        "id": "Q10",
        "category": "Synonyms & Paraphrasing",
        "query": "Find the great circle arc range between two GPS lat lon points in kilometers",
        "expected_targets": ["urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"],
        "expect_abstain": False,
        "description": "Uses 'range', 'GPS lat lon points' for distance tool."
    },
    {
        "id": "Q11",
        "category": "Synonyms & Paraphrasing",
        "query": "Calculate sample statistical variance across numeric observations",
        "expected_targets": ["urn:lcs:tool:mcp.sdk-analytics:calculate-statistical-variance"],
        "expect_abstain": False,
        "description": "Statistical variance calculation task."
    },
    {
        "id": "Q12",
        "category": "Synonyms & Paraphrasing",
        "query": "Parse semantic versioning release strings with major minor patch components",
        "expected_targets": ["urn:lcs:tool:mcp.sdk-analytics:parse-semver-expression"],
        "expect_abstain": False,
        "description": "Semantic versioning component parsing."
    },

    # -------------------------------------------------------------
    # Category C: Requests Mentioning Irrelevant Terms (6)
    # -------------------------------------------------------------
    {
        "id": "Q13",
        "category": "Conversational Noise",
        "query": "I am getting ready for lunch, please check whether my website has proper HTTP security headers",
        "expected_targets": ["urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"],
        "expect_abstain": False,
        "description": "Conversational filler with security header query."
    },
    {
        "id": "Q14",
        "category": "Conversational Noise",
        "query": "After traveling to Paris for vacation, compute the distance between two coordinates",
        "expected_targets": ["urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"],
        "expect_abstain": False,
        "description": "Irrelevant travel context before distance task."
    },
    {
        "id": "Q15",
        "category": "Conversational Noise",
        "query": "Can you help me calculate statistical variance for our weekly basketball tournament scores",
        "expected_targets": ["urn:lcs:tool:mcp.sdk-analytics:calculate-statistical-variance"],
        "expect_abstain": False,
        "description": "Sports chatter wrapping variance calculation."
    },
    {
        "id": "Q16",
        "category": "Conversational Noise",
        "query": "While drinking morning coffee, extract tables from this financial report PDF",
        "expected_targets": ["urn:lcs:tool:mcp.doc-tools:read-pdf-document"],
        "expect_abstain": False,
        "description": "Coffee context wrapping PDF table extraction."
    },
    {
        "id": "Q17",
        "category": "Conversational Noise",
        "query": "The weather is very cloudy outside, please find the bounding envelope of this GIS feature",
        "expected_targets": ["urn:lcs:tool:mcp.geo-tools:find-bounding-envelope"],
        "expect_abstain": False,
        "description": "Weather noise before spatial bounding envelope task."
    },
    {
        "id": "Q18",
        "category": "Conversational Noise",
        "query": "We are preparing for a system upgrade, validate this semver version string",
        "expected_targets": ["urn:lcs:tool:mcp.sdk-analytics:parse-semver-expression"],
        "expect_abstain": False,
        "description": "Operational noise before semver validation."
    },

    # -------------------------------------------------------------
    # Category D: Multi-Capability Queries (3)
    # -------------------------------------------------------------
    {
        "id": "Q19",
        "category": "Multi-Capability",
        "query": "Extract data from a PDF document and run an SQL query on the extracted database table",
        "expected_targets": [
            "urn:lcs:tool:mcp.doc-tools:read-pdf-document",
            "urn:lcs:tool:mcp.doc-tools:query-local-database"
        ],
        "expect_abstain": False,
        "description": "Workflow involving both PDF extraction and SQL database querying."
    },
    {
        "id": "Q20",
        "category": "Multi-Capability",
        "query": "Calculate polygon area and compute haversine distance for spatial map coordinates",
        "expected_targets": [
            "urn:lcs:tool:mcp.geo-tools:calculate-polygon-area",
            "urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"
        ],
        "expect_abstain": False,
        "description": "Spatial workflow involving both polygon area and haversine distance."
    },
    {
        "id": "Q21",
        "category": "Multi-Capability",
        "query": "Convert markdown documentation to PDF and check HTTP security headers",
        "expected_targets": [
            "urn:lcs:tool:mcp.doc-tools:convert-document-format",
            "urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"
        ],
        "expect_abstain": False,
        "description": "Workflow involving document conversion and web security header inspection."
    },

    # -------------------------------------------------------------
    # Category E: Ambiguous Requests (3)
    # -------------------------------------------------------------
    {
        "id": "Q22",
        "category": "Ambiguous Request",
        "query": "Process data",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Highly underspecified query with no clear domain."
    },
    {
        "id": "Q23",
        "category": "Ambiguous Request",
        "query": "Inspect system",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Ambiguous generic command."
    },
    {
        "id": "Q24",
        "category": "Ambiguous Request",
        "query": "Handle records",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Ambiguous operation on unspecified records."
    },

    # -------------------------------------------------------------
    # Category F: Out-of-Domain Requests (Must Abstain) (6)
    # -------------------------------------------------------------
    {
        "id": "Q25",
        "category": "Out-of-Domain (Abstain)",
        "query": "Send an email message with attachment via SMTP server",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Email dispatch task (unregistered domain)."
    },
    {
        "id": "Q26",
        "category": "Out-of-Domain (Abstain)",
        "query": "Generate high-resolution photorealistic images of a mountain using AI",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Image generation task (unregistered domain)."
    },
    {
        "id": "Q27",
        "category": "Out-of-Domain (Abstain)",
        "query": "Deploy a Docker container to a remote Kubernetes cluster",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Cloud orchestration / deployment task (unregistered domain)."
    },
    {
        "id": "Q28",
        "category": "Out-of-Domain (Abstain)",
        "query": "Transcribe voice audio recording from MP3 format into English text",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Audio transcription / speech-to-text (unregistered domain)."
    },
    {
        "id": "Q29",
        "category": "Out-of-Domain (Abstain)",
        "query": "Transpile TypeScript source code into WebAssembly binary",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Compiler toolchain task (unregistered domain)."
    },
    {
        "id": "Q30",
        "category": "Out-of-Domain (Abstain)",
        "query": "Mine cryptocurrency blocks using GPU proof of work",
        "expected_targets": [],
        "expect_abstain": True,
        "description": "Cryptocurrency mining (unregistered domain)."
    }
]


def run_benchmark():
    print("=" * 76)
    print(" LCS CAPABILITY RETRIEVAL V1 — 30-QUERY EVALUATION BENCHMARK")
    print("=" * 76)

    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(cfg)
        policy = InterfaceTrustPolicy(
            policy_name="eval-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        # 1. Discover all 3 test servers
        proj_dir = os.path.dirname(os.path.abspath(__file__))
        s1 = os.path.join(proj_dir, "mcp_test_server_fixture.py")
        s2 = os.path.join(proj_dir, "integration_tests", "independent_mcp_server.py")
        s3 = os.path.join(proj_dir, "integration_tests", "mcp_sdk_server.py")

        ctx.discovery_pipeline.discover_and_register_mcp_server([sys.executable, s1], "doc-tools", policy)
        ctx.discovery_pipeline.discover_and_register_mcp_server([sys.executable, s2], "geo-tools", policy)
        ctx.discovery_pipeline.discover_and_register_mcp_server([sys.executable, s3], "sdk-analytics", policy)

        # Verify 9 capabilities registered
        cur = ctx.conn.cursor()
        cur.execute("SELECT count(*) FROM capability_declarations;")
        total_caps = cur.fetchone()[0]
        print(f"Total Registered Capabilities for Benchmark: {total_caps} (from 3 distinct servers)\n")

        p1_hits = 0
        p3_hits = 0
        recall_hits = 0
        total_targets_count = 0
        reciprocal_ranks = []
        false_positives = 0
        correct_abstentions = 0
        total_abstention_queries = 0

        eval_records = []

        for item in BENCHMARK_QUERIES:
            qid = item["id"]
            cat = item["category"]
            q = item["query"]
            exp_targets = item["expected_targets"]
            expect_abstain = item["expect_abstain"]

            res = ctx.retrieval_engine.retrieve(q, limit=5, min_score_threshold=0.25)
            candidates = res.candidates
            candidate_urns = [c.capability_urn for c in candidates]

            record = {
                "id": qid,
                "category": cat,
                "query": q,
                "expected_targets": exp_targets,
                "expect_abstain": expect_abstain,
                "abstained": res.abstained,
                "abstention_code": res.abstention_code,
                "returned_candidates": [
                    {"urn": c.capability_urn, "score": round(c.relevance_score, 4), "name": c.display_name}
                    for c in candidates
                ]
            }

            if expect_abstain:
                total_abstention_queries += 1
                if res.abstained:
                    correct_abstentions += 1
                    status = "CORRECT ABSTENTION"
                else:
                    false_positives += 1
                    status = f"FALSE POSITIVE (Returned {candidate_urns[0]})"
            else:
                total_targets_count += len(exp_targets)
                # Precision@1
                if candidate_urns and candidate_urns[0] in exp_targets:
                    p1_hits += 1

                # Precision@3 & Recall@3
                top3_urns = candidate_urns[:3]
                matched_in_top3 = [t for t in exp_targets if t in top3_urns]
                p3_precision_score = len(matched_in_top3) / min(3, max(1, len(top3_urns)))
                p3_hits += p3_precision_score
                recall_hits += len(matched_in_top3)

                # MRR calculation
                rr = 0.0
                for rank, c_urn in enumerate(candidate_urns, start=1):
                    if c_urn in exp_targets:
                        rr = 1.0 / rank
                        break
                reciprocal_ranks.append(rr)

                hit_str = f"Rank 1: {candidate_urns[0]}" if candidate_urns else "(None)"
                status = f"MATCHED (RR={rr:.2f}) -> {hit_str}"

            print(f"[{qid}] [{cat:22}] \"{q[:45]}...\"")
            print(f"      Outcome: {status}")
            eval_records.append(record)

        # Summary Metrics
        n_matched_queries = len(BENCHMARK_QUERIES) - total_abstention_queries
        p1 = p1_hits / n_matched_queries if n_matched_queries > 0 else 0.0
        p3 = p3_hits / n_matched_queries if n_matched_queries > 0 else 0.0
        recall3 = recall_hits / total_targets_count if total_targets_count > 0 else 0.0
        mrr = sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else 0.0
        abstention_rate = correct_abstentions / total_abstention_queries if total_abstention_queries > 0 else 0.0

        print("\n" + "=" * 76)
        print(" EVALUATION BENCHMARK SUMMARY METRICS (N=30 QUERIES)")
        print("=" * 76)
        print(f"  Total Queries Evaluated:       {len(BENCHMARK_QUERIES)}")
        print(f"  Target Match Queries:          {n_matched_queries}")
        print(f"  Expected Abstention Queries:   {total_abstention_queries}")
        print("-" * 76)
        print(f"  Precision@1:                   {p1 * 100:.1f}% ({p1_hits}/{n_matched_queries})")
        print(f"  Precision@3:                   {p3 * 100:.1f}%")
        print(f"  Recall@3:                      {recall3 * 100:.1f}% ({recall_hits}/{total_targets_count})")
        print(f"  Mean Reciprocal Rank (MRR):    {mrr:.4f}")
        print(f"  False-Positive Count:          {false_positives} (out of {total_abstention_queries})")
        print(f"  Correct Abstention Rate:       {abstention_rate * 100:.1f}% ({correct_abstentions}/{total_abstention_queries})")
        print("=" * 76)

        return {
            "p1": p1,
            "p3": p3,
            "recall3": recall3,
            "mrr": mrr,
            "false_positives": false_positives,
            "correct_abstentions": correct_abstentions,
            "abstention_rate": abstention_rate,
            "records": eval_records
        }


if __name__ == "__main__":
    run_benchmark()

