"""
Comparative Multi-Model Benchmark Suite
=======================================
Benchmarks Online Logistic Regression (Ours) against Streaming Gaussian Naive Bayes,
Streaming Margin Perceptron, and Static Baselines under Non-Stationary Concept Drift.
"""

import sys
import os
import time
import json
from typing import Dict, List

from traffic_generator import NetworkTrafficGenerator
from classifier import OnlineLogisticRegression, StreamingNaiveBayes, StreamingPerceptron

def run_multi_model_benchmark(seed: int = 42) -> Dict:
    gen = NetworkTrafficGenerator(seed=seed)
    feat_keys = NetworkTrafficGenerator.FEATURE_KEYS

    # 1. Baseline dataset (300 samples: 250 Benign, 50 Classic SYN Flood)
    base_flows = [
        gen.generate_benign_flow(i) if i % 6 != 0 else gen.generate_classic_ddos_flow(i)
        for i in range(300)
    ]
    base_X = [f.to_vector(feat_keys) for f in base_flows]
    base_y = [f.label for f in base_flows]

    # 2. Test dataset post-drift (200 samples: 100 Benign, 100 Stealth Slowloris)
    drift_flows = [
        gen.generate_benign_flow(1000 + i) if i % 2 == 0 else gen.generate_mutated_ddos_flow(1000 + i)
        for i in range(200)
    ]
    drift_X = [f.to_vector(feat_keys) for f in drift_flows]
    drift_y = [f.label for f in drift_flows]

    # 3. Harvested crash flows (50 Slowloris from server socket dump)
    crash_flows = [gen.generate_mutated_ddos_flow(2000 + i) for i in range(50)]
    crash_X = [f.to_vector(feat_keys) for f in crash_flows]
    crash_y = [1] * 50

    models = {
        "Online Logistic Regression (Ours)": OnlineLogisticRegression(feature_names=feat_keys),
        "Streaming Gaussian Naive Bayes": StreamingNaiveBayes(feature_names=feat_keys),
        "Streaming Margin Perceptron": StreamingPerceptron(feature_names=feat_keys),
    }

    results = {}

    for name, model in models.items():
        # Baseline training
        if hasattr(model, 'fit_initial'):
            model.fit_initial(base_X, base_y)
        elif hasattr(model, 'fit_batch'):
            model.fit_batch(base_X, base_y)

        # Measure microsecond inference latency
        t0 = time.perf_counter()
        for x in base_X:
            model.predict(x)
        infer_us = ((time.perf_counter() - t0) / len(base_X)) * 1e6

        # Evaluate pre-drift baseline
        pre_metrics = model.evaluate(base_X, base_y)

        # Evaluate under concept drift BEFORE retraining (unmitigated failure)
        unmitigated_eval = model.evaluate(drift_X, drift_y)

        # Retrain on Balanced Mixture
        t0 = time.perf_counter()
        if hasattr(model, 'retrain_mixture'):
            model.retrain_mixture(
                baseline_X=base_X,
                baseline_y=base_y,
                crash_X=crash_X,
                crash_y=crash_y,
                recent_benign_X=[f.to_vector(feat_keys) for f in base_flows[:30]],
                epochs=35
            )
        elif hasattr(model, 'fit_batch'):
            comb_X = list(base_X) + list(crash_X) * 3
            comb_y = list(base_y) + list(crash_y) * 3
            model.fit_batch(comb_X, comb_y)
        t_retrain = (time.perf_counter() - t0) * 1000.0

        # Evaluate post-retraining recovery
        post_eval = model.evaluate(drift_X, drift_y)

        results[name] = {
            "inference_latency_us": round(infer_us, 2),
            "retraining_latency_ms": round(t_retrain, 2),
            "baseline_accuracy": round(pre_metrics["accuracy"] * 100, 2),
            "unmitigated_drift_fnr": round(unmitigated_eval["fnr"] * 100, 2),
            "post_retrain_accuracy": round(post_eval["accuracy"] * 100, 2),
            "post_retrain_recall": round(post_eval["recall"] * 100, 2),
            "post_retrain_fpr": round(post_eval["fpr"] * 100, 2)
        }

    return results

if __name__ == "__main__":
    print("=" * 80)
    print("COMPARATIVE MULTI-MODEL BENCHMARK UNDER NON-STATIONARY CONCEPT DRIFT")
    print("=" * 80)
    res = run_multi_model_benchmark()
    
    header = f"{'Classifier Model':<35} | {'Infer (us)':<10} | {'Retrain (ms)':<12} | {'Drift FNR':<10} | {'Post-Acc':<9} | {'Post-Recall':<11} | {'FPR':<6}"
    print(header)
    print("-" * len(header))
    for model_name, m in res.items():
        print(f"{model_name:<35} | {m['inference_latency_us']:<10} | {m['retraining_latency_ms']:<12} | {m['unmitigated_drift_fnr']:<9}% | {m['post_retrain_accuracy']:<8}% | {m['post_retrain_recall']:<10}% | {m['post_retrain_fpr']}%")
    print("=" * 80)
