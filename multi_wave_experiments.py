"""
Multi-Wave Sequential Concept Drift Experiments
===============================================
Evaluates continuous adaptive self-healing across three sequential attack waves:
  - Wave 1 (0 -> 500): Classic SYN Flood (Volumetric Baseline)
  - Wave 2 (500 -> 1400): Stealth Slowloris (Connection Starvation)
  - Wave 3 (1400 -> 2500): Polymorphic HTTP POST Jitter (Variable Payload & Anomalous Ports)
"""

import sys
import os
import time
import json
from typing import Dict, List

from traffic_generator import NetworkTrafficGenerator, TrafficFlow
from classifier import OnlineLogisticRegression
from system_monitor import ServerHealthMonitor

class MultiWaveTrafficGenerator(NetworkTrafficGenerator):
    def generate_wave3_jitter_flow(self, timestamp: float) -> TrafficFlow:
        self.flow_counter += 1
        packet_rate = self._sample_gaussian(65.0, 10.0, min_val=20.0)
        pkt_size_mean = self._sample_gaussian(340.0, 40.0, min_val=100.0)
        pkt_size_std = self._sample_gaussian(130.0, 25.0, min_val=15.0)
        byte_rate = packet_rate * pkt_size_mean
        duration = self._sample_gaussian(42.0, 6.0, min_val=20.0)

        features = {
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "flow_duration": duration,
            "packet_size_mean": pkt_size_mean,
            "packet_size_std": pkt_size_std,
            "syn_ratio": max(0.05, min(0.35, self._sample_gaussian(0.22, 0.04))),
            "ack_ratio": max(0.40, min(0.85, self._sample_gaussian(0.65, 0.05))),
            "dest_port_entropy": self._sample_gaussian(4.2, 0.3, min_val=2.5),
            "src_ip_entropy": self._sample_gaussian(2.1, 0.25, min_val=0.8),
            "inter_arrival_time_mean": self._sample_gaussian(45.0, 10.0, min_val=10.0)
        }
        return TrafficFlow(self.flow_counter, timestamp, features, label=1, attack_type="Wave3_POST_Jitter")

    def stream_multi_wave_traffic(self, total_samples: int = 2500):
        t = 0.0
        for step in range(total_samples):
            t += 1.0
            if step < 500:
                if self.rng.random() < 0.15:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)
            elif step < 1400:
                if self.rng.random() < 0.25:
                    yield self.generate_mutated_ddos_flow(t, drift_intensity=1.0)
                else:
                    yield self.generate_benign_flow(t)
            else:
                if self.rng.random() < 0.30:
                    yield self.generate_wave3_jitter_flow(t)
                else:
                    yield self.generate_benign_flow(t)

def run_multi_wave_benchmark(total_samples: int = 2500) -> Dict:
    gen = MultiWaveTrafficGenerator(seed=42)
    feat_keys = NetworkTrafficGenerator.FEATURE_KEYS

    model = OnlineLogisticRegression(feature_names=feat_keys)
    server = ServerHealthMonitor(max_connections=45, crash_cpu_threshold=35.0)

    # Pre-train on 300 baseline flows
    base_flows = [gen.generate_benign_flow(i) if i % 6 != 0 else gen.generate_classic_ddos_flow(i) for i in range(300)]
    base_X = [f.to_vector(feat_keys) for f in base_flows]
    base_y = [f.label for f in base_flows]
    model.fit_initial(base_X, base_y)

    cumulative_attack_harvest = []
    cumulative_benign_harvest = []

    wave_metrics = {
        "Wave 1 (SYN Flood)": {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "Wave 2 (Slowloris)": {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "Wave 3 (POST Jitter)": {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}
    }

    crashes = []
    retrain_events = []

    for step, flow in enumerate(gen.stream_multi_wave_traffic(total_samples=total_samples)):
        x_raw = flow.to_vector(feat_keys)
        prob = model.predict_proba(x_raw)
        pred = 1 if prob >= 0.50 else 0

        server_status = server.process_traffic_event(flow.flow_id, flow, flow.timestamp, pred)

        if step < 500:
            wkey = "Wave 1 (SYN Flood)"
        elif step < 1400:
            wkey = "Wave 2 (Slowloris)"
        else:
            wkey = "Wave 3 (POST Jitter)"

        m = wave_metrics[wkey]
        m["total"] += 1
        if flow.label == 1 and pred == 1: m["tp"] += 1
        elif flow.label == 0 and pred == 1: m["fp"] += 1
        elif flow.label == 0 and pred == 0: m["tn"] += 1
        elif flow.label == 1 and pred == 0: m["fn"] += 1

        if server_status["is_crashed"]:
            crashes.append(step)
            hanging = server.get_exhausted_socket_flows()
            new_attack_X = [f.to_vector(feat_keys) for f in hanging]
            cumulative_attack_harvest.extend(new_attack_X)

            recent_b = server.get_verified_benign_flows(max_samples=40)
            recent_b_X = [f.to_vector(feat_keys) for f in recent_b]
            cumulative_benign_harvest.extend(recent_b_X)

            t0 = time.perf_counter()
            model.retrain_mixture(
                baseline_X=base_X,
                baseline_y=base_y,
                crash_X=cumulative_attack_harvest,
                crash_y=[1] * len(cumulative_attack_harvest),
                recent_benign_X=cumulative_benign_harvest[-50:],
                epochs=35
            )
            t_retrain = (time.perf_counter() - t0) * 1000.0

            retrain_events.append({
                "step": step,
                "wave": wkey,
                "harvested_sockets": len(new_attack_X),
                "total_learned_attacks": len(cumulative_attack_harvest),
                "latency_ms": round(t_retrain, 2)
            })
            server.recover_server()

    summary = {}
    total_samples_all = 0
    total_tp = total_fp = total_tn = total_fn = 0
    for wkey, m in wave_metrics.items():
        tot = m["total"]
        total_samples_all += tot
        total_tp += m["tp"]
        total_fp += m["fp"]
        total_tn += m["tn"]
        total_fn += m["fn"]
        acc = (m["tp"] + m["tn"]) / max(1, tot)
        rec = m["tp"] / max(1, m["tp"] + m["fn"])
        prec = m["tp"] / max(1, m["tp"] + m["fp"])
        fpr = m["fp"] / max(1, m["fp"] + m["tn"])
        summary[wkey] = {
            "samples": tot,
            "accuracy": round(acc * 100, 2),
            "recall": round(rec * 100, 2),
            "precision": round(prec * 100, 2),
            "fpr": round(fpr * 100, 2),
            "tp": m["tp"], "fp": m["fp"], "tn": m["tn"], "fn": m["fn"]
        }

    overall_acc = (total_tp + total_tn) / max(1, total_samples_all)
    overall_rec = total_tp / max(1, total_tp + total_fn)
    overall_prec = total_tp / max(1, total_tp + total_fp)
    overall_fpr = total_fp / max(1, total_fp + total_tn)

    output_data = {
        "wave_summary": summary,
        "overall": {
            "total_samples": total_samples_all,
            "accuracy": round(overall_acc * 100, 2),
            "recall": round(overall_rec * 100, 2),
            "precision": round(overall_prec * 100, 2),
            "fpr": round(overall_fpr * 100, 2),
            "total_crashes": len(crashes),
            "crashes_steps": crashes
        },
        "retrain_events": retrain_events
    }

    with open("multi_wave_results.json", "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data

if __name__ == "__main__":
    print("=" * 80)
    print("MULTI-WAVE COMPOUND CONCEPT DRIFT BENCHMARK (2,500 STREAMING FLOWS)")
    print("=" * 80)
    res = run_multi_wave_benchmark(total_samples=2500)
    
    header = f"{'Attack Wave Phase':<25} | {'Samples':<8} | {'Accuracy':<9} | {'Recall':<8} | {'Precision':<10} | {'FPR':<6}"
    print(header)
    print("-" * len(header))
    for wkey, m in res["wave_summary"].items():
        print(f"{wkey:<25} | {m['samples']:<8} | {m['accuracy']:<8}% | {m['recall']:<7}% | {m['precision']:<9}% | {m['fpr']}%")
    print("-" * len(header))
    ov = res["overall"]
    print(f"{'OVERALL LIFECYCLE':<25} | {ov['total_samples']:<8} | {ov['accuracy']:<8}% | {ov['recall']:<7}% | {ov['precision']:<9}% | {ov['fpr']}%")
    print("=" * 80)
    print(f"Total Server Crashes Intercepted: {ov['total_crashes']} (Steps: {ov['crashes_steps']})")
    for r in res["retrain_events"]:
        print(f"  -> Retrain Event at Step {r['step']} ({r['wave']}): Harvested {r['harvested_sockets']} Sockets | Latency: {r['latency_ms']} ms")
    print("Exported multi_wave_results.json successfully.")
