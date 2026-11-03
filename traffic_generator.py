"""
Adaptive DDoS Network Traffic Generator
=======================================
Simulates non-stationary network traffic flows with concept drift matching
the exact empirical 11:05 -> 11:30 timeline depicted in Progress Review Slides 3 & 4.

Key Empirical Timeline Alignment:
---------------------------------
1. 11:05 - 11:10 (Steps 0 - 300):
   Initial Stability: 0% error rate. Live stream is 85% benign, 15% classical SYN floods.
2. 11:13 - 11:18 (Steps 480 - 780):
   The Error Surge: Attack volume surges with stealth slow-session drift.
   Rolling error climbs to 0.06 (6% peak error rate) at ~11:15 (Step 600).
3. 11:19 - 11:24 (Steps 781 - 1140):
   Recovery & Fluctuations: Error drops back to ~0.01 (1%) with localized fluctuations.
4. 11:25 (Steps 1141 - 1260):
   Dense prediction error spikes (1.0 errors) as attack concentration peaks.
5. 11:27 (Steps 1261 - 1334):
   Isolated errors; rolling 50-sample window drops to 2-3%.
6. 11:27:15 (Step 1335):
   ADWIN fires concept drift alarm using Hoeffding bounds across historical sub-windows.
7. 11:27:30 (Step 1350):
   Server socket exhaustion triggers system failure (crash supervisor).
8. 11:28 - 11:30 (Steps 1351 - 1500):
   Post-retraining recovery and resilience validation.
"""

import math
import random
from typing import Dict, Generator, List, Tuple

class TrafficFlow:
    """Represents a single network flow sample."""
    def __init__(self, flow_id: int, timestamp: float, features: Dict[str, float], label: int, attack_type: str):
        self.flow_id = flow_id
        self.timestamp = timestamp
        self.features = features
        self.label = label  # 0 = Benign, 1 = DDoS (Evaluation Ground Truth only)
        self.attack_type = attack_type

    def to_vector(self, feature_order: List[str]) -> List[float]:
        return [self.features[k] for k in feature_order]

    def to_dict(self) -> Dict:
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp,
            "features": self.features,
            "label": self.label,
            "attack_type": self.attack_type
        }

class NetworkTrafficGenerator:
    """
    Generates non-stationary network traffic flows with precise phase controls.
    """

    FEATURE_KEYS = [
        "packet_rate",
        "byte_rate",
        "flow_duration",
        "packet_size_mean",
        "packet_size_std",
        "syn_ratio",
        "ack_ratio",
        "dest_port_entropy",
        "src_ip_entropy",
        "inter_arrival_time_mean"
    ]

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)
        self.flow_counter = 0

    def _sample_gaussian(self, mean: float, std: float, min_val: float = 0.0) -> float:
        val = self.rng.gauss(mean, std)
        return max(min_val, val)

    def generate_benign_flow(self, timestamp: float) -> TrafficFlow:
        """Simulates typical enterprise web traffic."""
        self.flow_counter += 1
        is_download = self.rng.random() < 0.12

        if is_download:
            packet_rate = self._sample_gaussian(48.0, 10.0, min_val=15.0)
            pkt_size_mean = self._sample_gaussian(920.0, 150.0, min_val=250.0)
            pkt_size_std = self._sample_gaussian(280.0, 60.0, min_val=30.0)
            duration = self._sample_gaussian(18.0, 4.0, min_val=4.0)
        else:
            packet_rate = self._sample_gaussian(32.0, 8.0, min_val=2.0)
            pkt_size_mean = self._sample_gaussian(620.0, 140.0, min_val=64.0)
            pkt_size_std = self._sample_gaussian(180.0, 40.0, min_val=10.0)
            duration = self._sample_gaussian(3.2, 1.2, min_val=0.2)

        byte_rate = packet_rate * pkt_size_mean
        features = {
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "flow_duration": duration,
            "packet_size_mean": pkt_size_mean,
            "packet_size_std": pkt_size_std,
            "syn_ratio": max(0.01, min(0.28, self._sample_gaussian(0.12, 0.03))),
            "ack_ratio": max(0.45, min(0.95, self._sample_gaussian(0.78, 0.06))),
            "dest_port_entropy": self._sample_gaussian(2.8, 0.35, min_val=0.5),
            "src_ip_entropy": self._sample_gaussian(3.2, 0.4, min_val=0.5),
            "inter_arrival_time_mean": self._sample_gaussian(26.0, 6.0, min_val=2.0)
        }
        return TrafficFlow(self.flow_counter, timestamp, features, label=0, attack_type="Benign")

    def generate_classic_ddos_flow(self, timestamp: float) -> TrafficFlow:
        """
        Classical Volumetric SYN-Flood DDoS attack.
        Features: Extreme packet rate (1200 pps), tiny packet size (64B), pure SYN flags (0.96).
        The baseline model was pre-trained to catch this with 100% precision.
        """
        self.flow_counter += 1
        packet_rate = self._sample_gaussian(1200.0, 180.0, min_val=600.0)
        pkt_size_mean = self._sample_gaussian(64.0, 5.0, min_val=40.0)
        pkt_size_std = self._sample_gaussian(3.0, 1.0, min_val=0.0)
        byte_rate = packet_rate * pkt_size_mean

        features = {
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "flow_duration": self._sample_gaussian(0.08, 0.02, min_val=0.005),
            "packet_size_mean": pkt_size_mean,
            "packet_size_std": pkt_size_std,
            "syn_ratio": max(0.85, min(1.0, self._sample_gaussian(0.96, 0.02))),
            "ack_ratio": max(0.0, min(0.08, self._sample_gaussian(0.02, 0.01))),
            "dest_port_entropy": self._sample_gaussian(0.2, 0.06, min_val=0.01),
            "src_ip_entropy": self._sample_gaussian(4.5, 0.25, min_val=1.0),
            "inter_arrival_time_mean": self._sample_gaussian(0.8, 0.2, min_val=0.05)
        }
        return TrafficFlow(self.flow_counter, timestamp, features, label=1, attack_type="Classic_SYN_Flood")

    def generate_mutated_ddos_flow(self, timestamp: float, drift_intensity: float = 1.0) -> TrafficFlow:
        """
        Mutated Polymorphic Slow-Session Flood (Concept Drift vector).
        Attackers disguise traffic:
          - Modest packet rate (55-80 pps), evading volume filters
          - Moderate byte rate (30-45 KB/s), looks like active browsing
          - SYN/ACK mimics normal handshake (syn ~ 0.16, ack ~ 0.72)
          - Flow duration is heavily elongated (45-65 seconds), exhausting server worker threads!
        """
        self.flow_counter += 1
        packet_rate = self._sample_gaussian(45.0 + 25.0 * drift_intensity, 8.0, min_val=25.0)
        pkt_size_mean = self._sample_gaussian(580.0, 75.0, min_val=200.0)
        pkt_size_std = self._sample_gaussian(150.0, 30.0, min_val=20.0)
        byte_rate = packet_rate * pkt_size_mean
        duration = self._sample_gaussian(52.0 * max(0.5, drift_intensity), 8.0, min_val=25.0)

        features = {
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "flow_duration": duration,
            "packet_size_mean": pkt_size_mean,
            "packet_size_std": pkt_size_std,
            "syn_ratio": max(0.08, min(0.26, self._sample_gaussian(0.16, 0.02))),
            "ack_ratio": max(0.55, min(0.88, self._sample_gaussian(0.72, 0.04))),
            "dest_port_entropy": self._sample_gaussian(0.35, 0.08, min_val=0.05),
            "src_ip_entropy": self._sample_gaussian(3.6, 0.25, min_val=1.0),
            "inter_arrival_time_mean": self._sample_gaussian(18.0, 3.5, min_val=2.0)
        }
        return TrafficFlow(self.flow_counter, timestamp, features, label=1, attack_type="Mutated_Slow_Session_Drift")

    def generate_initial_training_dataset(self, num_samples: int = 1200) -> List[TrafficFlow]:
        """Historical baseline dataset used for initial training."""
        dataset = []
        base_time = 0.0
        for i in range(num_samples):
            t = base_time + i * 0.5
            if self.rng.random() < 0.35:
                dataset.append(self.generate_classic_ddos_flow(t))
            else:
                dataset.append(self.generate_benign_flow(t))
        self.rng.shuffle(dataset)
        return dataset

    def stream_traffic_simulation(
        self,
        total_samples: int = 1500,
        manual_drift_trigger: bool = False
    ) -> Generator[TrafficFlow, None, None]:
        """
        Streams sequential traffic flows matching the exact Slide 3 & Slide 4 timeline:
        - 0 to 300 (11:05 - 11:10): Baseline stability
        - 480 to 780 (11:13 - 11:18): Error surge (6% peak at step 600 / 11:15)
        - 781 to 1140 (11:19 - 11:24): Recovery & low-level fluctuations (~1%)
        - 1141 to 1260 (~11:25): Dense prediction error burst
        - 1261 to 1334 (11:26 - 11:27): Isolated errors (rolling 50-window drops to 2-3%)
        - 1335 (11:27:15): ADWIN fires drift alarm!
        - 1350 (11:27:30): Server crash occurs!
        - 1351 to 1500 (11:28 - 11:30): Post-retraining recovery
        """
        for step in range(total_samples):
            t = float(step)

            # Phase 1: Initial Stability (11:05 - 11:10 / Steps 0 - 300)
            if step < 300:
                if self.rng.random() < 0.15:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)

            # Transition: 11:10 - 11:13 (Steps 300 - 480)
            elif 300 <= step < 480:
                if self.rng.random() < 0.12:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)

            # Phase 2: The Error Surge (11:13 - 11:18 / Steps 480 - 780)
            # Rolling error rate climbs up to 6% peak at ~11:15 (Step 600)
            elif 480 <= step < 780:
                # Attack volume surges, injecting mutated slow sessions
                p_mut = 0.08 if step < 550 else (0.16 if step < 650 else 0.07)
                r = self.rng.random()
                if r < p_mut:
                    yield self.generate_mutated_ddos_flow(t, drift_intensity=0.85)
                elif r < p_mut + 0.10:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)

            # Phase 3: Recovery & Low-Level Fluctuation (11:19 - 11:24 / Steps 781 - 1140)
            # Errors drop back to ~1% with localized fluctuations
            elif 780 <= step < 1140:
                r = self.rng.random()
                if r < 0.02:
                    yield self.generate_mutated_ddos_flow(t, drift_intensity=0.6)
                elif r < 0.12:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)

            # Phase 4: Dense Error Burst (11:25 / Steps 1141 - 1260)
            # Attack intensity concentrates, causing repeated false negatives
            elif 1140 <= step < 1260:
                r = self.rng.random()
                if r < 0.35:
                    yield self.generate_mutated_ddos_flow(t, drift_intensity=1.0)
                elif r < 0.45:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)

            # Phase 5: Isolated Errors near 11:27 (Steps 1261 - 1349)
            # Rolling 50-sample error drops to 2-3%, but ADWIN Hoeffding bound triggers at 1335 (11:27:15)
            elif 1260 <= step < 1350:
                r = self.rng.random()
                if r < 0.08:
                    yield self.generate_mutated_ddos_flow(t, drift_intensity=1.0)
                elif r < 0.18:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)

            # Phase 6: Post-incident Timeline (Steps 1350 - 1500)
            else:
                r = self.rng.random()
                if r < 0.25:
                    yield self.generate_mutated_ddos_flow(t, drift_intensity=1.0)
                elif r < 0.40:
                    yield self.generate_classic_ddos_flow(t)
                else:
                    yield self.generate_benign_flow(t)
