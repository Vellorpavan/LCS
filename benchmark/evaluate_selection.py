"""
Call Me Selection Intelligence — Evaluation Benchmark Runner
============================================================
Evaluates Call Me capability retrieval & selection against the 105-query benchmark:
- Precision@1, Precision@3, Precision@5
- Recall@1, Recall@3, Recall@5
- F1@1, F1@3, F1@5
- Mean Reciprocal Rank (MRR)
- Correct Abstention Rate (out-of-domain)
- Performance breakdown by Domain
- Performance breakdown by Train vs Eval (held-out) split
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import json
import time
from typing import Dict, Any, List, Set, Tuple

from lcs.config import LCSConfig
from lcs.context import LCSContext


def evaluate_dataset(dataset_path: str, mode: str = "lexical") -> Dict[str, Any]:
    with open(dataset_path, "r") as f:
        queries = json.load(f)

    # Initialize Context and Inventory
    config = LCSConfig.resolve()
    ctx = LCSContext(config)
    if hasattr(ctx, "adapter_registry") and ctx.inventory.total_count == 0:
        ctx.inventory.initialize_environment(ctx.adapter_registry.list_all())

    inventory = ctx.inventory

    results = []
    splits = {"train": [], "eval": []}
    domains: Dict[str, List[Dict[str, Any]]] = {}

    start_time = time.perf_counter()

    for item in queries:
        qid = item["id"]
        q_text = item["query"]
        expected = set(c.lower() for c in item["expected_capabilities"])
        expect_abstain = item.get("expect_abstain", False)
        domain = item.get("domain", "general")
        split = item.get("split", "eval")

        # Run selection
        if mode == "semantic_reasoner":
            from lcs.intelligence.semantic_reasoner import SemanticReasoner
            r_res = SemanticReasoner.reason_locally(q_text, inventory)
            retrieved_names = [s.name.lower() for s in r_res.selections[:5]]
        else:
            matches = inventory.search(q_text, limit=5)
            retrieved_names = [m.name.lower() for m in matches]

        # Calculate metrics for this query
        is_abstained = (len(retrieved_names) == 0)

        if expect_abstain:
            # Query is out of domain: must abstain or return no match
            p1 = 1.0 if is_abstained else 0.0
            p3 = 1.0 if is_abstained else 0.0
            p5 = 1.0 if is_abstained else 0.0
            r1 = 1.0 if is_abstained else 0.0
            r3 = 1.0 if is_abstained else 0.0
            r5 = 1.0 if is_abstained else 0.0
            mrr = 1.0 if is_abstained else 0.0
            abstention_correct = is_abstained
        else:
            abstention_correct = False
            # Check hits at rank 1, 3, 5
            hits_1 = [n for n in retrieved_names[:1] if any(exp in n or n in exp for exp in expected)]
            hits_3 = [n for n in retrieved_names[:3] if any(exp in n or n in exp for exp in expected)]
            hits_5 = [n for n in retrieved_names[:5] if any(exp in n or n in exp for exp in expected)]

            p1 = len(hits_1) / 1.0 if retrieved_names else 0.0
            p3 = len(hits_3) / min(3, len(retrieved_names)) if retrieved_names else 0.0
            p5 = len(hits_5) / min(5, len(retrieved_names)) if retrieved_names else 0.0

            n_expected = max(1, len(expected))
            r1 = len(hits_1) / n_expected
            r3 = len(hits_3) / n_expected
            r5 = len(hits_5) / n_expected

            # MRR
            mrr = 0.0
            for rank, name in enumerate(retrieved_names, 1):
                if any(exp in name or name in exp for exp in expected):
                    mrr = 1.0 / rank
                    break

        f1_3 = (2 * p3 * r3 / (p3 + r3)) if (p3 + r3) > 0 else 0.0

        q_res = {
            "id": qid,
            "domain": domain,
            "split": split,
            "query": q_text,
            "expected": list(expected),
            "retrieved": retrieved_names,
            "expect_abstain": expect_abstain,
            "is_abstained": is_abstained,
            "abstention_correct": abstention_correct,
            "p@1": p1,
            "p@3": p3,
            "p@5": p5,
            "r@1": r1,
            "r@3": r3,
            "r@5": r5,
            "f1@3": f1_3,
            "mrr": mrr
        }
        results.append(q_res)
        splits[split].append(q_res)
        domains.setdefault(domain, []).append(q_res)

    elapsed_s = time.perf_counter() - start_time

    def compute_summary(query_list: List[Dict[str, Any]]) -> Dict[str, float]:
        if not query_list:
            return {}
        n = len(query_list)
        return {
            "count": n,
            "p@1": sum(q["p@1"] for q in query_list) / n,
            "p@3": sum(q["p@3"] for q in query_list) / n,
            "p@5": sum(q["p@5"] for q in query_list) / n,
            "r@1": sum(q["r@1"] for q in query_list) / n,
            "r@3": sum(q["r@3"] for q in query_list) / n,
            "r@5": sum(q["r@5"] for q in query_list) / n,
            "f1@3": sum(q["f1@3"] for q in query_list) / n,
            "mrr": sum(q["mrr"] for q in query_list) / n,
            "abstention_accuracy": (
                sum(1 for q in query_list if q["expect_abstain"] and q["abstention_correct"]) /
                max(1, sum(1 for q in query_list if q["expect_abstain"]))
            ) if any(q["expect_abstain"] for q in query_list) else 1.0
        }

    overall = compute_summary(results)
    train_non_adv = [r for r in splits["train"] if not r["expect_abstain"]]
    eval_non_adv = [r for r in splits["eval"] if not r["expect_abstain"]]
    adversarial_list = [r for r in results if r["expect_abstain"]]

    train_summary = compute_summary(train_non_adv)
    eval_summary = compute_summary(eval_non_adv)
    adversarial_summary = compute_summary(adversarial_list)

    domain_summaries = {d: compute_summary(qlist) for d, qlist in domains.items()}

    report = {
        "benchmark_mode": mode,
        "total_queries": len(queries),
        "total_catalog_capabilities": inventory.total_count,
        "elapsed_seconds": round(elapsed_s, 3),
        "latency_per_query_ms": round((elapsed_s / len(queries)) * 1000, 2),
        "overall": overall,
        "train_split": train_summary,
        "eval_split (held-out)": eval_summary,
        "adversarial_split": adversarial_summary,
        "domain_breakdown": domain_summaries,
        "details": results
    }

    return report


if __name__ == "__main__":
    dataset = sys.argv[1] if len(sys.argv) > 1 else "benchmark/dataset_100_objectives.json"
    if not os.path.isfile(dataset):
        print(f"Error: dataset {dataset} not found. Run generate_dataset.py first.")
        sys.exit(1)

    print(f"Running Call Me Selection Intelligence Benchmark on {dataset}...")
    report = evaluate_dataset(dataset, mode="hybrid_semantic")

    out_report = "benchmark/benchmark_results_fresh_eval.json" if "fresh" in dataset else "benchmark/benchmark_results_hybrid.json"
    with open(out_report, "w") as f:
        json.dump(report, f, indent=2)

    # Load baseline for comparison if available
    base_file = "benchmark/benchmark_results_baseline.json"
    base_report = None
    if os.path.isfile(base_file):
        try:
            with open(base_file, "r") as f:
                base_report = json.load(f)
        except Exception:
            pass

    print("\n" + "=" * 72)
    print(" CALL ME SELECTION INTELLIGENCE BENCHMARK RESULTS (HYBRID SEMANTIC)")
    print("=" * 72)
    print(f"  Total Queries:         {report['total_queries']}")
    print(f"  Catalog Capabilities:  {report['total_catalog_capabilities']}")
    print(f"  Latency per Query:     {report['latency_per_query_ms']} ms")

    print("\n--- HELD-OUT EVALUATION SET (43 queries) ---")
    ev = report["eval_split (held-out)"]
    bev = base_report["eval_split (held-out)"] if base_report else {}
    p1_d = f" (delta: {(ev['p@1'] - bev.get('p@1', 0)) * 100:+.2f}%)" if bev else ""
    p3_d = f" (delta: {(ev['p@3'] - bev.get('p@3', 0)) * 100:+.2f}%)" if bev else ""
    r3_d = f" (delta: {(ev['r@3'] - bev.get('r@3', 0)) * 100:+.2f}%)" if bev else ""
    f1_d = f" (delta: {(ev['f1@3'] - bev.get('f1@3', 0)) * 100:+.2f}%)" if bev else ""
    mrr_d = f" (delta: {ev['mrr'] - bev.get('mrr', 0):+.4f})" if bev else ""
    abs_d = f" (delta: {(ev['abstention_accuracy'] - bev.get('abstention_accuracy', 0)) * 100:+.2f}%)" if bev else ""

    print(f"  Precision@1:           {ev['p@1'] * 100:.2f}%{p1_d}")
    print(f"  Precision@3:           {ev['p@3'] * 100:.2f}%{p3_d}")
    print(f"  Recall@3:              {ev['r@3'] * 100:.2f}%{r3_d}")
    print(f"  F1@3:                  {ev['f1@3'] * 100:.2f}%{f1_d}")
    print(f"  MRR (Mean Recip Rank): {ev['mrr']:.4f}{mrr_d}")
    print(f"  Abstention Accuracy:   {ev['abstention_accuracy'] * 100:.2f}%{abs_d}")

    print("\n--- OVERALL BENCHMARK (105 queries across 11 domains) ---")
    ov = report["overall"]
    bov = base_report["overall"] if base_report else {}
    op1_d = f" (delta: {(ov['p@1'] - bov.get('p@1', 0)) * 100:+.2f}%)" if bov else ""
    op3_d = f" (delta: {(ov['p@3'] - bov.get('p@3', 0)) * 100:+.2f}%)" if bov else ""
    or3_d = f" (delta: {(ov['r@3'] - bov.get('r@3', 0)) * 100:+.2f}%)" if bov else ""
    of1_d = f" (delta: {(ov['f1@3'] - bov.get('f1@3', 0)) * 100:+.2f}%)" if bov else ""
    omrr_d = f" (delta: {ov['mrr'] - bov.get('mrr', 0):+.4f})" if bov else ""
    oabs_d = f" (delta: {(ov['abstention_accuracy'] - bov.get('abstention_accuracy', 0)) * 100:+.2f}%)" if bov else ""

    print(f"  Precision@1:           {ov['p@1'] * 100:.2f}%{op1_d}")
    print(f"  Precision@3:           {ov['p@3'] * 100:.2f}%{op3_d}")
    print(f"  Recall@3:              {ov['r@3'] * 100:.2f}%{or3_d}")
    print(f"  F1@3:                  {ov['f1@3'] * 100:.2f}%{of1_d}")
    print(f"  MRR:                   {ov['mrr']:.4f}{omrr_d}")
    print(f"  Abstention Accuracy:   {ov['abstention_accuracy'] * 100:.2f}%{oabs_d}")
    print(f"\nDetailed report written to: {out_report}")
