"""
Comparative Experiments & Benchmark Runner
===========================================
Executes systematic empirical evaluations:
1. Strategy Comparison: Static vs. New-Only Retrain vs. Balanced Mixture
2. Retrospective Harvesting Window Sensitivity (100, 300, 500, 1000 samples)
3. Concept Drift Detector Comparison (ADWIN vs. Page-Hinkley)
4. Confusion Matrix and Performance Metric Reporting (Accuracy, Precision, Recall, F1, FPR, FNR)
"""

import json
import os
import sys
import time

from closed_loop_engine import ClosedLoopSimulationEngine

def run_strategy_benchmarks(dataset_path: Optional[str] = None):
    dataset_name = os.path.basename(dataset_path) if dataset_path else "Canadian Institute for Cybersecurity (CIC) Generator"
    print("=" * 82)
    print("EXPERIMENT 1: RETRAINING STRATEGY COMPARISON UNDER CONCEPT DRIFT")
    print(f"Data Source: {dataset_name}")
    print("=" * 82)
    strategies = ["static", "new_only", "balanced_mixture"]
    results = {}

    for strat in strategies:
        print(f"\n---> Running Simulation with Strategy: [{strat.upper()}] ...")
        engine = ClosedLoopSimulationEngine(retraining_strategy=strat, seed=42, dataset_csv=dataset_path)
        summary = engine.run_simulation(total_samples=1500)
        results[strat] = summary

        post = summary["post_retrain_metrics"]
        overall = summary["overall_metrics"]

        print(f"     [Server Crashes]       : {summary['server_total_crashes']}")
        print(f"     [ADWIN Alarms]         : {summary['adwin_alarms_count']}")
        print(f"     [Post-Retrain Accuracy]: {post.get('accuracy', 0.0):.4f}")
        print(f"     [Post-Retrain Recall]  : {post.get('recall', 0.0):.4f}  (Miss Rate FNR: {post.get('fnr', 0.0):.4f})")
        print(f"     [Post-Retrain Prec]    : {post.get('precision', 0.0):.4f}  (False Alarm FPR: {post.get('fpr', 0.0):.4f})")
        print(f"     [Post-Retrain F1-Score]: {post.get('f1_score', 0.0):.4f}")

    # Print Comparison Table
    print("\n" + "=" * 88)
    print(f"{'STRATEGY':<18} | {'ACCURACY':<9} | {'RECALL':<8} | {'PRECISION':<9} | {'F1-SCORE':<9} | {'FPR (FA)':<9} | {'CRASHES'}")
    print("-" * 88)
    for strat in strategies:
        p = results[strat]["post_retrain_metrics"]
        crashes = results[strat]["server_total_crashes"]
        print(f"{strat.capitalize():<18} | {p['accuracy']:<9.4f} | {p['recall']:<8.4f} | {p['precision']:<9.4f} | {p['f1_score']:<9.4f} | {p['fpr']:<9.4f} | {crashes}")
    print("=" * 88)

    return results

def run_window_sensitivity_benchmark():
    print("\n" + "=" * 78)
    print("EXPERIMENT 2: RETRAINING WINDOW SENSITIVITY (100, 300, 500, 1000 SAMPLES)")
    print("=" * 78)
    window_sizes = [100, 300, 500, 1000]
    window_results = {}

    for w in window_sizes:
        print(f"\n---> Evaluating Retraining Window Size: {w} samples ...")
        engine = ClosedLoopSimulationEngine(
            retraining_strategy="balanced_mixture",
            seed=42,
            buffer_capacity=w
        )
        t0 = time.time()
        summary = engine.run_simulation(total_samples=1500)
        elapsed = (time.time() - t0) * 1000.0  # ms
        p = summary["post_retrain_metrics"]

        window_results[w] = {
            "window": w,
            "accuracy": p["accuracy"],
            "recall": p["recall"],
            "precision": p["precision"],
            "f1": p["f1_score"],
            "fpr": p["fpr"],
            "latency_ms": elapsed
        }

        print(f"     Window {w:4d} | Acc: {p['accuracy']:.4f} | Recall: {p['recall']:.4f} | F1: {p['f1_score']:.4f} | Elapsed: {elapsed:.1f}ms")

    print("\n" + "=" * 78)
    print(f"{'WINDOW SIZE':<14} | {'ACCURACY':<9} | {'RECALL':<8} | {'PRECISION':<9} | {'F1-SCORE':<9} | {'LATENCY (ms)'}")
    print("-" * 78)
    for w in window_sizes:
        r = window_results[w]
        print(f"{r['window']:<14} | {r['accuracy']:<9.4f} | {r['recall']:<8.4f} | {r['precision']:<9.4f} | {r['f1']:<9.4f} | {r['latency_ms']:.1f}")
    print("=" * 78)

    return window_results

if __name__ == "__main__":
    default_dataset = os.path.join(os.path.dirname(__file__), "data", "cic_ids2017_wednesday_slowloris.csv")
    dataset_arg = None
    if len(sys.argv) > 1:
        dataset_arg = sys.argv[1]
    elif os.path.exists(default_dataset):
        dataset_arg = default_dataset

    benchmarks = run_strategy_benchmarks(dataset_arg)
    window_bench = run_window_sensitivity_benchmark()

    # Save benchmark outputs to JSON for documentation & frontend visualization
    output_path = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(output_path, "w") as f:
        json.dump({
            "strategies": benchmarks,
            "window_sensitivity": window_bench
        }, f, indent=2)
    print(f"\n[OK] Benchmark results successfully exported to: {output_path}")

