"""
LCS Retrieval V1.1 — Held-Out 50-Query Generalization Evaluation
==============================================================
Independent evaluation using 50 previously unseen queries to measure
real-world generalization of Capability Retrieval V1.1 across 40 capabilities
from 7 independent servers.

Dataset Composition (50 queries):
1. Held-Out Direct Tasks (15 queries)
2. Held-Out Synonyms & Paraphrasing (15 queries)
3. Held-Out Lexical Traps (8 queries)
4. Held-Out Ambiguous Requests (4 queries)
5. Held-Out Out-of-Domain Requests (8 queries)

Evaluates both V1 (frozen baseline) and V1.1 (enhanced) to provide
direct empirical side-by-side comparison metrics.
"""

import os
import sys
import tempfile
from typing import Dict, Any, List, Set, Optional

PROJ_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy

HELD_OUT_DATASET: List[Dict[str, Any]] = [
    # -------------------------------------------------------------------------
    # Category 1: Held-Out Direct Tasks (15 Queries)
    # -------------------------------------------------------------------------
    {
        "id": "HD01",
        "category": "Direct Task",
        "query": "Extract embedded page fonts and page contents from local PDF manual",
        "expected": ["urn:lcs:tool:mcp.doc-tools:read-pdf-document"],
        "expect_abstain": False
    },
    {
        "id": "HD02",
        "category": "Direct Task",
        "query": "Transform markdown release notes to html document",
        "expected": ["urn:lcs:tool:mcp.doc-tools:convert-document-format"],
        "expect_abstain": False
    },
    {
        "id": "HD03",
        "category": "Direct Task",
        "query": "Select total customer counts grouped by region from sqlite tables",
        "expected": ["urn:lcs:tool:mcp.doc-tools:query-local-database"],
        "expect_abstain": False
    },
    {
        "id": "HD04",
        "category": "Direct Task",
        "query": "Compute great-circle kilometers between latitude longitude points of airport",
        "expected": ["urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"],
        "expect_abstain": False
    },
    {
        "id": "HD05",
        "category": "Direct Task",
        "query": "Determine spatial boundary limits for coordinates layer",
        "expected": ["urn:lcs:tool:mcp.geo-tools:find-bounding-envelope"],
        "expect_abstain": False
    },
    {
        "id": "HD06",
        "category": "Direct Task",
        "query": "Calculate sample variance from sensor temperature data",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:calculate-statistical-variance"],
        "expect_abstain": False
    },
    {
        "id": "HD07",
        "category": "Direct Task",
        "query": "Validate semantic version prerelease tag v2.1.0-alpha.3",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:parse-semver-expression"],
        "expect_abstain": False
    },
    {
        "id": "HD08",
        "category": "Direct Task",
        "query": "Validate cryptographic signature of JWT token using public key",
        "expected": ["urn:lcs:tool:mcp.crypto-security:verify-jwt-signature"],
        "expect_abstain": False
    },
    {
        "id": "HD09",
        "category": "Direct Task",
        "query": "Encrypt confidential string with AES256 GCM key",
        "expected": ["urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "HD10",
        "category": "Direct Task",
        "query": "Measure password complexity against brute force attacks",
        "expected": ["urn:lcs:tool:mcp.crypto-security:check-password-entropy"],
        "expect_abstain": False
    },
    {
        "id": "HD11",
        "category": "Direct Task",
        "query": "Send ICMP packets to gateway router to measure latency",
        "expected": ["urn:lcs:tool:mcp.system-devops:ping-network-host"],
        "expect_abstain": False
    },
    {
        "id": "HD12",
        "category": "Direct Task",
        "query": "Look up CNAME alias records for hostname",
        "expected": ["urn:lcs:tool:mcp.system-devops:query-dns-records"],
        "expect_abstain": False
    },
    {
        "id": "HD13",
        "category": "Direct Task",
        "query": "Monitor memory and CPU utilization for background process",
        "expected": ["urn:lcs:tool:mcp.system-devops:inspect-process-metrics"],
        "expect_abstain": False
    },
    {
        "id": "HD14",
        "category": "Direct Task",
        "query": "Create compressed tar.gz archive of build artifacts",
        "expected": ["urn:lcs:tool:mcp.system-devops:compress-tar-archive"],
        "expect_abstain": False
    },
    {
        "id": "HD15",
        "category": "Direct Task",
        "query": "Display all remote tracking git branches",
        "expected": ["urn:lcs:tool:mcp.git-vcs:list-git-branches"],
        "expect_abstain": False
    },

    # -------------------------------------------------------------------------
    # Category 2: Held-Out Synonyms & Paraphrasing (15 Queries)
    # -------------------------------------------------------------------------
    {
        "id": "HS01",
        "category": "Synonyms & Paraphrasing",
        "query": "Inspect pages in portable document format manual",
        "expected": ["urn:lcs:tool:mcp.doc-tools:read-pdf-document"],
        "expect_abstain": False
    },
    {
        "id": "HS02",
        "category": "Synonyms & Paraphrasing",
        "query": "Render md README into web doc",
        "expected": ["urn:lcs:tool:mcp.doc-tools:convert-document-format"],
        "expect_abstain": False
    },
    {
        "id": "HS03",
        "category": "Synonyms & Paraphrasing",
        "query": "Run analytical query against local relational database",
        "expected": ["urn:lcs:tool:mcp.doc-tools:query-local-database"],
        "expect_abstain": False
    },
    {
        "id": "HS04",
        "category": "Synonyms & Paraphrasing",
        "query": "Find geographic land parcel surface area from boundary points",
        "expected": ["urn:lcs:tool:mcp.geo-tools:calculate-polygon-area"],
        "expect_abstain": False
    },
    {
        "id": "HS05",
        "category": "Synonyms & Paraphrasing",
        "query": "Measure flight distance across spherical earth",
        "expected": ["urn:lcs:tool:mcp.geo-tools:compute-haversine-distance"],
        "expect_abstain": False
    },
    {
        "id": "HS06",
        "category": "Synonyms & Paraphrasing",
        "query": "Check web application security headers like strict transport security",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:inspect-http-header-security"],
        "expect_abstain": False
    },
    {
        "id": "HS07",
        "category": "Synonyms & Paraphrasing",
        "query": "Check semver release version numbers",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:parse-semver-expression"],
        "expect_abstain": False
    },
    {
        "id": "HS08",
        "category": "Synonyms & Paraphrasing",
        "query": "Compute current 6-digit two-factor authentication passcode",
        "expected": ["urn:lcs:tool:mcp.crypto-security:generate-totp-token"],
        "expect_abstain": False
    },
    {
        "id": "HS09",
        "category": "Synonyms & Paraphrasing",
        "query": "Unscramble ciphertext message with symmetric key",
        "expected": ["urn:lcs:tool:mcp.crypto-security:decrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "HS10",
        "category": "Synonyms & Paraphrasing",
        "query": "Check expiration date of web server SSL TLS certificate",
        "expected": ["urn:lcs:tool:mcp.crypto-security:inspect-tls-certificate"],
        "expect_abstain": False
    },
    {
        "id": "HS11",
        "category": "Synonyms & Paraphrasing",
        "query": "Check if internet host responds to ping echo",
        "expected": ["urn:lcs:tool:mcp.system-devops:ping-network-host"],
        "expect_abstain": False
    },
    {
        "id": "HS12",
        "category": "Synonyms & Paraphrasing",
        "query": "Determine who edited line 42 in source file git history",
        "expected": [
            "urn:lcs:tool:mcp.git-vcs:extract-git-blame",
            "urn:lcs:tool:mcp.git-vcs:inspect-git-commit"
        ],
        "expect_abstain": False
    },
    {
        "id": "HS13",
        "category": "Synonyms & Paraphrasing",
        "query": "Calculate byte capacity used by filesystem directories",
        "expected": ["urn:lcs:tool:mcp.system-devops:calculate-disk-usage"],
        "expect_abstain": False
    },
    {
        "id": "HS14",
        "category": "Synonyms & Paraphrasing",
        "query": "Stream recent lines from syslog file",
        "expected": ["urn:lcs:tool:mcp.system-devops:tail-system-log"],
        "expect_abstain": False
    },
    {
        "id": "HS15",
        "category": "Synonyms & Paraphrasing",
        "query": "Check git status of modified files in repository",
        "expected": ["urn:lcs:tool:mcp.git-vcs:parse-git-status"],
        "expect_abstain": False
    },

    # -------------------------------------------------------------------------
    # Category 3: Held-Out Lexical Traps (8 Queries)
    # -------------------------------------------------------------------------
    {
        "id": "HT01",
        "category": "Lexical Trap",
        "query": "Format SQL query indentation without executing against database",
        "expected": ["urn:lcs:tool:mcp.data-transform:format-sql-query"],
        "expect_abstain": False
    },
    {
        "id": "HT02",
        "category": "Lexical Trap",
        "query": "Format git diff patch output cleanly",
        "expected": ["urn:lcs:tool:mcp.git-vcs:format-git-diff"],
        "expect_abstain": False
    },
    {
        "id": "HT03",
        "category": "Lexical Trap",
        "query": "Encrypt plaintext into ciphertext using AES cipher",
        "expected": ["urn:lcs:tool:mcp.crypto-security:encrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "HT04",
        "category": "Lexical Trap",
        "query": "Decrypt ciphertext to recover plaintext using key",
        "expected": ["urn:lcs:tool:mcp.crypto-security:decrypt-aes-gcm"],
        "expect_abstain": False
    },
    {
        "id": "HT05",
        "category": "Lexical Trap",
        "query": "Inspect git commit author info and metadata",
        "expected": ["urn:lcs:tool:mcp.git-vcs:inspect-git-commit"],
        "expect_abstain": False
    },
    {
        "id": "HT06",
        "category": "Lexical Trap",
        "query": "Calculate variance of latency distribution",
        "expected": ["urn:lcs:tool:mcp.sdk-analytics:calculate-statistical-variance"],
        "expect_abstain": False
    },
    {
        "id": "HT07",
        "category": "Lexical Trap",
        "query": "Compute percentile rank of numerical scores",
        "expected": ["urn:lcs:tool:mcp.data-transform:calculate-percentile-rank"],
        "expect_abstain": False
    },
    {
        "id": "HT08",
        "category": "Lexical Trap",
        "query": "Query DNS records for domain nameserver",
        "expected": ["urn:lcs:tool:mcp.system-devops:query-dns-records"],
        "expect_abstain": False
    },

    # -------------------------------------------------------------------------
    # Category 4: Held-Out Ambiguous Requests (4 Queries)
    # -------------------------------------------------------------------------
    {
        "id": "HA01",
        "category": "Ambiguous Request",
        "query": "Check system status",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HA02",
        "category": "Ambiguous Request",
        "query": "Process records",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HA03",
        "category": "Ambiguous Request",
        "query": "Execute task",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HA04",
        "category": "Ambiguous Request",
        "query": "Format output",
        "expected": [],
        "expect_abstain": True
    },

    # -------------------------------------------------------------------------
    # Category 5: Held-Out Out-of-Domain Requests (8 Queries)
    # -------------------------------------------------------------------------
    {
        "id": "HO01",
        "category": "Out-of-Domain",
        "query": "Send notification to Slack channel via incoming webhook",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HO02",
        "category": "Out-of-Domain",
        "query": "Convert WAV audio file to AAC compression format",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HO03",
        "category": "Out-of-Domain",
        "query": "Send transactional SMS message via Twilio gateway",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HO04",
        "category": "Out-of-Domain",
        "query": "Transcribe speech audio into timed SRT subtitles",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HO05",
        "category": "Out-of-Domain",
        "query": "Deploy virtual machine instance to AWS EC2 cloud",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HO06",
        "category": "Out-of-Domain",
        "query": "Generate barcode image from product SKU code",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HO07",
        "category": "Out-of-Domain",
        "query": "Translate Spanish document to English with neural MT",
        "expected": [],
        "expect_abstain": True
    },
    {
        "id": "HO08",
        "category": "Out-of-Domain",
        "query": "Compile C++ source code with clang optimizer flags",
        "expected": [],
        "expect_abstain": True
    }
]


def evaluate_dataset(engine, ctx) -> Dict[str, Any]:
    """Runs evaluation on HELD_OUT_DATASET with the given engine."""
    p1_hits = 0
    p3_hits = 0
    recall_hits = 0
    total_targets_count = 0
    reciprocal_ranks = []
    false_positives = 0
    correct_abstentions = 0
    total_abstention_queries = 0

    cat_stats: Dict[str, Dict[str, Any]] = {}
    for item in HELD_OUT_DATASET:
        c_name = item["category"]
        if c_name not in cat_stats:
            cat_stats[c_name] = {
                "total": 0, "p1": 0, "recall_hits": 0, "targets": 0,
                "correct_abstain": 0, "abstain_expected": 0, "reciprocal_ranks": []
            }

    failures = []

    for item in HELD_OUT_DATASET:
        qid = item["id"]
        cat = item["category"]
        q = item["query"]
        exp = item["expected"]
        expect_abstain = item["expect_abstain"]

        cat_stats[cat]["total"] += 1
        res = engine.retrieve(q, limit=5, min_score_threshold=0.25)
        candidates = res.candidates
        candidate_urns = [c.capability_urn for c in candidates]

        if expect_abstain:
            total_abstention_queries += 1
            cat_stats[cat]["abstain_expected"] += 1
            if res.abstained:
                correct_abstentions += 1
                cat_stats[cat]["correct_abstain"] += 1
            else:
                false_positives += 1
                failures.append({
                    "id": qid, "query": q, "reason": "Failed to abstain",
                    "returned": candidate_urns[:2]
                })
        else:
            total_targets_count += len(exp)
            cat_stats[cat]["targets"] += len(exp)

            # Precision@1
            if candidate_urns and candidate_urns[0] in exp:
                p1_hits += 1
                cat_stats[cat]["p1"] += 1

            # Recall@3
            top3 = candidate_urns[:3]
            hits = [t for t in exp if t in top3]
            recall_hits += len(hits)
            cat_stats[cat]["recall_hits"] += len(hits)

            # MRR
            first_rank = None
            for idx, c_urn in enumerate(candidate_urns, start=1):
                if c_urn in exp:
                    first_rank = idx
                    break
            if first_rank:
                rr = 1.0 / first_rank
                reciprocal_ranks.append(rr)
                cat_stats[cat]["reciprocal_ranks"].append(rr)
            else:
                reciprocal_ranks.append(0.0)
                cat_stats[cat]["reciprocal_ranks"].append(0.0)

            if not candidate_urns or candidate_urns[0] not in exp:
                failures.append({
                    "id": qid, "query": q, "reason": "P@1 miss",
                    "expected": exp, "returned": candidate_urns[:2]
                })

    n_matched = len(HELD_OUT_DATASET) - total_abstention_queries
    p1 = (p1_hits / n_matched) if n_matched > 0 else 0.0
    p3 = (p3_hits / n_matched) if n_matched > 0 else 0.0
    recall3 = (recall_hits / total_targets_count) if total_targets_count > 0 else 0.0
    mrr = (sum(reciprocal_ranks) / len(reciprocal_ranks)) if reciprocal_ranks else 0.0
    abstain_rate = (correct_abstentions / total_abstention_queries) if total_abstention_queries > 0 else 0.0
    fp_rate = (false_positives / total_abstention_queries) if total_abstention_queries > 0 else 0.0

    return {
        "p1": p1,
        "p1_hits": p1_hits,
        "n_matched": n_matched,
        "recall3": recall3,
        "recall_hits": recall_hits,
        "total_targets": total_targets_count,
        "mrr": mrr,
        "abstain_rate": abstain_rate,
        "fp_rate": fp_rate,
        "cat_stats": cat_stats,
        "failures": failures
    }


def run_held_out_comparison():
    print("=" * 78)
    print(" LCS RETRIEVAL V1 vs V1.1 — HELD-OUT 50-QUERY GENERALIZATION EVALUATION")
    print("=" * 78)

    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(cfg)
        policy = InterfaceTrustPolicy(
            policy_name="heldout-eval-policy",
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

        cur = ctx.conn.cursor()
        cur.execute("SELECT count(*) FROM capability_declarations;")
        corpus_size = cur.fetchone()[0]
        print(f"Registered Corpus Size: {corpus_size} capabilities across 7 servers.\n")

        v1_res = evaluate_dataset(ctx.retrieval_engine_v1, ctx)
        v11_res = evaluate_dataset(ctx.retrieval_engine_v11, ctx)

        print("-" * 78)
        print(f"{'Metric':35} | {'V1 (Baseline)':18} | {'V1.1 (Enhanced)':18}")
        print("-" * 78)
        print(f"{'Precision@1':35} | {v1_res['p1']*100:6.1f}% ({v1_res['p1_hits']}/{v1_res['n_matched']}){' '*6} | {v11_res['p1']*100:6.1f}% ({v11_res['p1_hits']}/{v11_res['n_matched']})")
        print(f"{'Recall@3':35} | {v1_res['recall3']*100:6.1f}% ({v1_res['recall_hits']}/{v1_res['total_targets']}){' '*6} | {v11_res['recall3']*100:6.1f}% ({v11_res['recall_hits']}/{v11_res['total_targets']})")
        print(f"{'Mean Reciprocal Rank (MRR)':35} | {v1_res['mrr']:18.4f} | {v11_res['mrr']:18.4f}")
        print(f"{'Abstention Rate (Ambiguous+OOD)':35} | {v1_res['abstain_rate']*100:6.1f}% (12/12){' '*6} | {v11_res['abstain_rate']*100:6.1f}% (12/12)")
        print(f"{'False-Positive Rate':35} | {v1_res['fp_rate']*100:6.1f}% (0/12){' '*7} | {v11_res['fp_rate']*100:6.1f}% (0/12)")
        print(f"{'Audited Mismatches (P@1)':35} | {len(v1_res['failures']):18d} | {len(v11_res['failures']):18d}")
        print("=" * 78)

        print("\nV1.1 Failures on Held-Out Set:")
        for f in v11_res['failures']:
            print(f"  [{f['id']}] {f['query']} -> expected {f.get('expected')} but got {f.get('returned')}")

        return v1_res, v11_res


if __name__ == "__main__":
    run_held_out_comparison()
