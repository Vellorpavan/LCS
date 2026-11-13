"""
LCS Retrieval V1.1 vs V1 — Untouched Blind 100-Query Evaluation Benchmark
========================================================================
Independent blind evaluation executing frozen Capability Retrieval V1 and V1.1
against a 40-capability corpus across 7 independent servers.

Dataset Composition (100 queries from blind_retrieval_benchmark_100.json):
1. Direct Task Requests (25 queries)
2. Synonyms & Paraphrasing (20 queries)
3. Lexical Traps (15 queries)
4. Multi-Capability Requests (10 queries)
5. Ambiguous / Underspecified Requests (10 queries)
6. Out-of-Domain Requests (20 queries)

Integrity Rules:
- Retrieval engines V1 and V1.1 are strictly FROZEN.
- Ground truth loaded from evaluation/blind_retrieval_benchmark_100.json.
- Computes Precision@1, Precision@3, Recall@3, MRR, Correct Abstention Rate,
  False-Positive Rate, Multi-Capability Recall, category breakdowns, and failure audit.
"""

import os
import sys
import json
import tempfile
from typing import Dict, Any, List, Set, Optional

PROJ_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy

BENCHMARK_PATH = os.path.join(PROJ_ROOT, "evaluation", "blind_retrieval_benchmark_100.json")


def load_benchmark_dataset() -> List[Dict[str, Any]]:
    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_engine_on_benchmark(engine, dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Runs evaluation on the 100-query benchmark dataset with the given engine."""
    p1_hits = 0
    p3_hits = 0
    recall_hits = 0
    total_targets_count = 0
    reciprocal_ranks = []
    false_positives = 0
    correct_abstentions = 0
    total_abstention_queries = 0

    # Multi-capability specific tracking
    multi_cap_targets = 0
    multi_cap_hits_top3 = 0
    multi_cap_both_in_top3 = 0
    multi_cap_queries = 0

    cat_stats: Dict[str, Dict[str, Any]] = {}
    for item in dataset:
        c_name = item["category"]
        if c_name not in cat_stats:
            cat_stats[c_name] = {
                "total": 0,
                "p1_hits": 0,
                "p3_hits": 0,
                "recall_hits": 0,
                "targets": 0,
                "correct_abstain": 0,
                "abstain_expected": 0,
                "false_positives": 0,
                "reciprocal_ranks": []
            }

    failures: List[Dict[str, Any]] = []

    for item in dataset:
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
                cat_stats[cat]["false_positives"] += 1
                failures.append({
                    "id": qid,
                    "category": cat,
                    "query": q,
                    "reason": "Failed to abstain (False Positive)",
                    "expected": exp,
                    "returned": [
                        {"urn": c.capability_urn, "score": round(c.relevance_score, 4), "name": c.display_name}
                        for c in candidates[:3]
                    ],
                    "abstained": False,
                    "abstention_code": None
                })
        else:
            total_targets_count += len(exp)
            cat_stats[cat]["targets"] += len(exp)

            # Precision@1
            p1_hit = bool(candidate_urns and candidate_urns[0] in exp)
            if p1_hit:
                p1_hits += 1
                cat_stats[cat]["p1_hits"] += 1

            # Precision@3 and Recall@3
            top3 = candidate_urns[:3]
            matched_top3 = [t for t in exp if t in top3]
            query_p3 = len(matched_top3) / min(3, max(1, len(top3))) if top3 else 0.0
            p3_hits += query_p3
            cat_stats[cat]["p3_hits"] += query_p3

            recall_hits += len(matched_top3)
            cat_stats[cat]["recall_hits"] += len(matched_top3)

            # MRR
            first_rank = None
            for idx, c_urn in enumerate(candidate_urns, start=1):
                if c_urn in exp:
                    first_rank = idx
                    break
            rr = (1.0 / first_rank) if first_rank else 0.0
            reciprocal_ranks.append(rr)
            cat_stats[cat]["reciprocal_ranks"].append(rr)

            # Multi-capability metrics
            if cat == "Multi-Capability":
                multi_cap_queries += 1
                multi_cap_targets += len(exp)
                multi_cap_hits_top3 += len(matched_top3)
                if len(matched_top3) == len(exp):
                    multi_cap_both_in_top3 += 1

            # Failure tracking (P@1 miss or incomplete retrieval)
            if not p1_hit or (cat == "Multi-Capability" and len(matched_top3) < len(exp)):
                failure_reason = "P@1 miss" if not p1_hit else "Partial multi-capability retrieval in top-3"
                if res.abstained:
                    failure_reason = f"Erroneous abstention ({res.abstention_code})"
                failures.append({
                    "id": qid,
                    "category": cat,
                    "query": q,
                    "reason": failure_reason,
                    "expected": exp,
                    "returned": [
                        {"urn": c.capability_urn, "score": round(c.relevance_score, 4), "name": c.display_name}
                        for c in candidates[:3]
                    ],
                    "abstained": res.abstained,
                    "abstention_code": res.abstention_code,
                    "rank1_urn": candidate_urns[0] if candidate_urns else None,
                    "matched_top3": matched_top3
                })

    n_matched = len(dataset) - total_abstention_queries
    p1 = (p1_hits / n_matched) if n_matched > 0 else 0.0
    p3 = (p3_hits / n_matched) if n_matched > 0 else 0.0
    recall3 = (recall_hits / total_targets_count) if total_targets_count > 0 else 0.0
    mrr = (sum(reciprocal_ranks) / len(reciprocal_ranks)) if reciprocal_ranks else 0.0
    abstain_rate = (correct_abstentions / total_abstention_queries) if total_abstention_queries > 0 else 0.0
    fp_rate = (false_positives / total_abstention_queries) if total_abstention_queries > 0 else 0.0

    multi_cap_recall = (multi_cap_hits_top3 / multi_cap_targets) if multi_cap_targets > 0 else 0.0
    multi_cap_complete_rate = (multi_cap_both_in_top3 / multi_cap_queries) if multi_cap_queries > 0 else 0.0

    return {
        "p1": p1,
        "p1_hits": p1_hits,
        "p3": p3,
        "n_matched": n_matched,
        "recall3": recall3,
        "recall_hits": recall_hits,
        "total_targets": total_targets_count,
        "mrr": mrr,
        "abstain_rate": abstain_rate,
        "correct_abstentions": correct_abstentions,
        "total_abstention_queries": total_abstention_queries,
        "fp_rate": fp_rate,
        "false_positives": false_positives,
        "multi_cap_recall": multi_cap_recall,
        "multi_cap_hits_top3": multi_cap_hits_top3,
        "multi_cap_targets": multi_cap_targets,
        "multi_cap_complete_rate": multi_cap_complete_rate,
        "multi_cap_both_in_top3": multi_cap_both_in_top3,
        "multi_cap_queries": multi_cap_queries,
        "cat_stats": cat_stats,
        "failures": failures
    }


def run_blind_benchmark():
    dataset = load_benchmark_dataset()
    print("=" * 84)
    print(" LCS RETRIEVAL V1.1 vs V1 — UNTOUCHED BLIND 100-QUERY BENCHMARK")
    print("=" * 84)
    print(f"Loaded benchmark dataset with {len(dataset)} queries from:")
    print(f"  {BENCHMARK_PATH}\n")

    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(cfg)
        policy = InterfaceTrustPolicy(
            policy_name="blind-eval-policy",
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

        print("Populating isolated LCSContext with 7 MCP servers...")
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
        print(f"Registered Corpus Size: {corpus_size} capabilities across {len(servers)} servers.\n")

        print("Executing Capability Retrieval V1 (Baseline)...")
        v1_res = evaluate_engine_on_benchmark(ctx.retrieval_engine_v1, dataset)

        print("Executing Capability Retrieval V1.1 (Enhanced)...")
        v11_res = evaluate_engine_on_benchmark(ctx.retrieval_engine_v11, dataset)

        print("\n" + "=" * 84)
        print(" HEAD-TO-HEAD BENCHMARK RESULTS")
        print("=" * 84)
        print(f"{'Metric':36} | {'V1 (Frozen Baseline)':20} | {'V1.1 (Enhanced)':20}")
        print("-" * 84)
        print(f"{'Precision@1':36} | {v1_res['p1']*100:6.1f}% ({v1_res['p1_hits']}/{v1_res['n_matched']}){' '*7} | {v11_res['p1']*100:6.1f}% ({v11_res['p1_hits']}/{v11_res['n_matched']})")
        print(f"{'Precision@3':36} | {v1_res['p3']*100:6.1f}%{' '*14} | {v11_res['p3']*100:6.1f}%")
        print(f"{'Recall@3':36} | {v1_res['recall3']*100:6.1f}% ({v1_res['recall_hits']}/{v1_res['total_targets']}){' '*7} | {v11_res['recall3']*100:6.1f}% ({v11_res['recall_hits']}/{v11_res['total_targets']})")
        print(f"{'Mean Reciprocal Rank (MRR)':36} | {v1_res['mrr']:20.4f} | {v11_res['mrr']:20.4f}")
        print(f"{'Correct Abstention Rate':36} | {v1_res['abstain_rate']*100:6.1f}% ({v1_res['correct_abstentions']}/{v1_res['total_abstention_queries']}){' '*7} | {v11_res['abstain_rate']*100:6.1f}% ({v11_res['correct_abstentions']}/{v11_res['total_abstention_queries']})")
        print(f"{'False-Positive Rate':36} | {v1_res['fp_rate']*100:6.1f}% ({v1_res['false_positives']}/{v1_res['total_abstention_queries']}){' '*7} | {v11_res['fp_rate']*100:6.1f}% ({v11_res['false_positives']}/{v11_res['total_abstention_queries']})")
        print(f"{'Multi-Capability Recall@3':36} | {v1_res['multi_cap_recall']*100:6.1f}% ({v1_res['multi_cap_hits_top3']}/{v1_res['multi_cap_targets']}){' '*7} | {v11_res['multi_cap_recall']*100:6.1f}% ({v11_res['multi_cap_hits_top3']}/{v11_res['multi_cap_targets']})")
        print(f"{'Multi-Cap Complete Top-3 Rate':36} | {v1_res['multi_cap_complete_rate']*100:6.1f}% ({v1_res['multi_cap_both_in_top3']}/{v1_res['multi_cap_queries']}){' '*7} | {v11_res['multi_cap_complete_rate']*100:6.1f}% ({v11_res['multi_cap_both_in_top3']}/{v11_res['multi_cap_queries']})")
        print(f"{'Failure Count (P@1 / FP)':36} | {len(v1_res['failures']):20d} | {len(v11_res['failures']):20d}")
        print("=" * 84)

        print("\n" + "=" * 84)
        print(" CATEGORY-BY-CATEGORY BREAKDOWN")
        print("=" * 84)
        categories = [
            "Direct Task",
            "Synonyms & Paraphrasing",
            "Lexical Trap",
            "Multi-Capability",
            "Ambiguous Request",
            "Out-of-Domain"
        ]

        for cat in categories:
            s1 = v1_res["cat_stats"][cat]
            s11 = v11_res["cat_stats"][cat]
            print(f"\n--- Category: {cat} (Total Queries: {s1['total']}) ---")
            if s1["abstain_expected"] > 0:
                print(f"  Abstention Rate: V1={s1['correct_abstain']/s1['total']*100:5.1f}% ({s1['correct_abstain']}/{s1['total']}) | V1.1={s11['correct_abstain']/s11['total']*100:5.1f}% ({s11['correct_abstain']}/{s11['total']})")
                print(f"  False Positives: V1={s1['false_positives']} | V1.1={s11['false_positives']}")
            else:
                v1_cat_p1 = (s1["p1_hits"] / s1["total"]) * 100
                v11_cat_p1 = (s11["p1_hits"] / s11["total"]) * 100
                v1_cat_rec = (s1["recall_hits"] / s1["targets"]) * 100 if s1["targets"] > 0 else 0
                v11_cat_rec = (s11["recall_hits"] / s11["targets"]) * 100 if s11["targets"] > 0 else 0
                v1_cat_mrr = sum(s1["reciprocal_ranks"]) / len(s1["reciprocal_ranks"]) if s1["reciprocal_ranks"] else 0
                v11_cat_mrr = sum(s11["reciprocal_ranks"]) / len(s11["reciprocal_ranks"]) if s11["reciprocal_ranks"] else 0
                print(f"  P@1:      V1={v1_cat_p1:5.1f}% ({s1['p1_hits']}/{s1['total']}) | V1.1={v11_cat_p1:5.1f}% ({s11['p1_hits']}/{s11['total']})")
                print(f"  Recall@3: V1={v1_cat_rec:5.1f}% ({s1['recall_hits']}/{s1['targets']}) | V1.1={v11_cat_rec:5.1f}% ({s11['recall_hits']}/{s11['targets']})")
                print(f"  MRR:      V1={v1_cat_mrr:5.4f} | V1.1={v11_cat_mrr:5.4f}")

        print("\n" + "=" * 84)
        print(f" COMPLETE FAILURE AUDIT: RETRIEVAL V1 (Total Failures: {len(v1_res['failures'])})")
        print("=" * 84)
        for idx, f in enumerate(v1_res["failures"], start=1):
            print(f"[{idx:02d}] ID: {f['id']} | Category: {f['category']}")
            print(f"     Query:    \"{f['query']}\"")
            print(f"     Reason:   {f['reason']}")
            print(f"     Expected: {f['expected']}")
            if f.get("returned"):
                c_str = ", ".join([f"{c['urn']} ({c['score']})" for c in f["returned"]])
                print(f"     Got Top:  [{c_str}]")
            else:
                print(f"     Got Top:  (None - Abstained: code={f.get('abstention_code')})")

        print("\n" + "=" * 84)
        print(f" COMPLETE FAILURE AUDIT: RETRIEVAL V1.1 (Total Failures: {len(v11_res['failures'])})")
        print("=" * 84)
        if not v11_res["failures"]:
            print("  ZERO FAILURES! Perfect performance across all 100 queries.")
        else:
            for idx, f in enumerate(v11_res["failures"], start=1):
                print(f"[{idx:02d}] ID: {f['id']} | Category: {f['category']}")
                print(f"     Query:    \"{f['query']}\"")
                print(f"     Reason:   {f['reason']}")
                print(f"     Expected: {f['expected']}")
                if f.get("returned"):
                    c_str = ", ".join([f"{c['urn']} ({c['score']})" for c in f["returned"]])
                    print(f"     Got Top:  [{c_str}]")
                else:
                    print(f"     Got Top:  (None - Abstained: code={f.get('abstention_code')})")

        # Save results to JSON
        output_results = {
            "v1": {
                "p1": v1_res["p1"],
                "p1_hits": v1_res["p1_hits"],
                "p3": v1_res["p3"],
                "recall3": v1_res["recall3"],
                "recall_hits": v1_res["recall_hits"],
                "total_targets": v1_res["total_targets"],
                "mrr": v1_res["mrr"],
                "abstain_rate": v1_res["abstain_rate"],
                "correct_abstentions": v1_res["correct_abstentions"],
                "fp_rate": v1_res["fp_rate"],
                "false_positives": v1_res["false_positives"],
                "multi_cap_recall": v1_res["multi_cap_recall"],
                "multi_cap_complete_rate": v1_res["multi_cap_complete_rate"],
                "failure_count": len(v1_res["failures"]),
                "failures": v1_res["failures"]
            },
            "v1_1": {
                "p1": v11_res["p1"],
                "p1_hits": v11_res["p1_hits"],
                "p3": v11_res["p3"],
                "recall3": v11_res["recall3"],
                "recall_hits": v11_res["recall_hits"],
                "total_targets": v11_res["total_targets"],
                "mrr": v11_res["mrr"],
                "abstain_rate": v11_res["abstain_rate"],
                "correct_abstentions": v11_res["correct_abstentions"],
                "fp_rate": v11_res["fp_rate"],
                "false_positives": v11_res["false_positives"],
                "multi_cap_recall": v11_res["multi_cap_recall"],
                "multi_cap_complete_rate": v11_res["multi_cap_complete_rate"],
                "failure_count": len(v11_res["failures"]),
                "failures": v11_res["failures"]
            }
        }
        res_json_path = os.path.join(PROJ_ROOT, "evaluation", "blind_retrieval_benchmark_100_results.json")
        with open(res_json_path, "w", encoding="utf-8") as f:
            json.dump(output_results, f, indent=2)
        print(f"\nSaved detailed results JSON to: {res_json_path}")


if __name__ == "__main__":
    run_blind_benchmark()
