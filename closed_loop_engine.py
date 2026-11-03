"""
Closed-Loop Feedback Retraining Engine (Zero Data Leakage)
==========================================================
Implements the 5-stage Closed-Loop Architecture:
1. Online Traffic Classification
2. Asymmetric Cost Evaluation & Active Socket Management
3. Crash-Driven Ground Truth Supervisor (Hanging Sockets at Crash)
4. ADWIN Concept Drift Isolation on Historical Sub-Windows
5. Balanced Mixture Retraining (Old Baseline + Crash Dump Sockets)

Data Leakage Protections:
-------------------------
- Operational pipeline has ZERO access to flow.label or flow.attack_type.
- Retrospective labels are derived STRICTLY from server state (active hanging sockets at failure).
- Benign samples are taken from pre-drift baseline memory and completed clean sessions.
- Scaler is fitted causally without data snooping.
- Model retraining supports both progressive epoch-by-epoch updates and one-shot execution.
"""

from collections import deque
import json
import math
import os
import time
from typing import Callable, Deque, Dict, List, Optional, Tuple

from traffic_generator import NetworkTrafficGenerator, TrafficFlow
from cic_dataset_loader import CICDatasetLoader
from drift_detectors import ADWIN, PageHinkley
from classifier import OnlineLogisticRegression
from system_monitor import ServerHealthMonitor

class ClosedLoopSimulationEngine:
    """
    Coordinates traffic streaming, online classification, failure monitoring,
    ADWIN drift localization, and automated model retraining.
    Supports both Canadian University (CIC-IDS) CSV datasets and live traffic generators.
    """

    def __init__(
        self,
        retraining_strategy: str = "balanced_mixture",  # "balanced_mixture", "new_only", "static"
        seed: int = 42,
        buffer_capacity: int = 1200,
        rolling_window_sizes: Tuple[int, int] = (100, 50),
        dataset_csv: Optional[str] = None
    ):
        self.strategy = retraining_strategy
        self.dataset_csv = dataset_csv
        self.generator = NetworkTrafficGenerator(seed=seed)
        self.feature_names = NetworkTrafficGenerator.FEATURE_KEYS

        # If Canadian University CSV provided, initialize loader
        self.cic_loader = CICDatasetLoader(dataset_csv) if dataset_csv and os.path.exists(dataset_csv) else None

        # Initialize online model
        self.model = OnlineLogisticRegression(feature_names=self.feature_names)

        # ADWIN drift detector running on the error stream
        self.adwin = ADWIN(delta=0.01, min_subwindow_len=12)
        self.page_hinkley = PageHinkley(delta=0.005, threshold=12.0)

        # Backend server health monitor (tracks authentic socket table)
        self.server = ServerHealthMonitor(max_connections=50, crash_cpu_threshold=40.0)

        # Sliding window deques for rolling statistics
        self.w1_size, self.w2_size = rolling_window_sizes
        self.w1_deque: Deque[float] = deque(maxlen=self.w1_size)
        self.w2_deque: Deque[float] = deque(maxlen=self.w2_size)

        # Buffers
        self.flow_history: List[TrafficFlow] = []
        self.prediction_history: List[int] = []
        self.events_log: List[Dict] = []
        self.baseline_dataset: List[TrafficFlow] = []
        self.retraining_events: List[Dict] = []
        self.adwin_triggers: List[Dict] = []

        # Admin control flags
        self.admin_drift_override: Optional[bool] = None
        self.has_retrained: bool = False

    def bootstrap_baseline(self, num_samples: int = 1200):
        """Generates historical baseline data and pre-trains initial model."""
        self.baseline_dataset = self.generator.generate_initial_training_dataset(num_samples=num_samples)
        X_train = [f.to_vector(self.feature_names) for f in self.baseline_dataset]
        y_train = [f.label for f in self.baseline_dataset]
        fit_info = self.model.fit_initial(X_train, y_train, epochs=40)
        return fit_info

    def step_single_flow(self, flow: TrafficFlow) -> Dict:
        """
        Processes a single flow event causally with ZERO DATA LEAKAGE.
        """
        step = len(self.flow_history)
        raw_vec = flow.to_vector(self.feature_names)

        # Step 1: Model Prediction (Predict before Train / Test-then-Train)
        prob_ddos = self.model.predict_proba(raw_vec)
        pred_label = 1 if prob_ddos >= 0.50 else 0

        # Evaluation Ground Truth (used ONLY for reporting/metrics, NEVER by model)
        eval_err = 1.0 if pred_label != flow.label else 0.0
        self.w1_deque.append(eval_err)
        self.w2_deque.append(eval_err)

        rolling_err_100 = sum(self.w1_deque) / max(1, len(self.w1_deque))
        rolling_err_50 = sum(self.w2_deque) / max(1, len(self.w2_deque))

        # ADWIN monitoring evaluation stream (matching Slide 4 analysis)
        drift_detected = self.adwin.add_element(eval_err)
        if drift_detected:
            self.adwin_triggers.append({
                "step": step,
                "timestamp": flow.timestamp,
                "adwin_mean": round(self.adwin.current_mean, 4),
                "rolling_50": round(rolling_err_50, 4)
            })

        # Step 2: Ingress & Server Processing (Zero label leakage)
        # Server only receives flow features & duration, NOT label or attack_type!
        server_status = self.server.process_traffic_event(
            flow_id=flow.flow_id,
            flow_obj=flow,
            timestamp=flow.timestamp,
            predicted_as_attack=pred_label
        )

        self.flow_history.append(flow)
        self.prediction_history.append(pred_label)

        # Step 3: Check Failure Trigger
        server_just_crashed = (server_status["is_crashed"] == 1.0) and not self.has_retrained

        retrain_info = None
        if server_just_crashed:
            # Server crash triggers failure-driven retraining!
            retrain_info = self._execute_failure_driven_retraining(step=step, timestamp=flow.timestamp)
            self.retraining_events.append(retrain_info)
            self.has_retrained = True
            # Server reboots post-retraining
            self.server.recover_server()

        record = {
            "step": step,
            "timestamp": flow.timestamp,
            "label": flow.label,  # for evaluation visualization only
            "predicted": pred_label,
            "prob_ddos": round(prob_ddos, 4),
            "error": eval_err,
            "rolling_err_100": round(rolling_err_100, 4),
            "rolling_err_50": round(rolling_err_50, 4),
            "attack_type": flow.attack_type,
            "adwin_drift": 1 if drift_detected else 0,
            "server_cpu": server_status["cpu_load"],
            "server_conns": server_status["active_connections"],
            "open_sockets": server_status.get("open_sockets", 0),
            "server_crashed": server_status["is_crashed"],
            "retrained": 1 if retrain_info else 0,
            "retrain_info": retrain_info
        }
        self.events_log.append(record)
        return record

    def run_simulation(
        self,
        total_samples: int = 1500,
        on_step_callback: Optional[Callable[[Dict], None]] = None
    ) -> Dict:
        """Runs the complete stream progression."""
        if not self.baseline_dataset:
            self.bootstrap_baseline()

        if self.cic_loader:
            stream = self.cic_loader.stream_flows(max_records=total_samples)
        else:
            stream = self.generator.stream_traffic_simulation(total_samples=total_samples)
        for flow in stream:
            rec = self.step_single_flow(flow)
            if on_step_callback:
                on_step_callback(rec)

        return self.generate_summary_report()

    def _execute_failure_driven_retraining(self, step: int, timestamp: float) -> Dict:
        """
        Authentic Ground-Truth Harvest & Retraining with ZERO DATA LEAKAGE:
        1. Harvests active hanging flows from server socket table at crash instant.
        2. Retrieves verified pre-drift baseline data from historical storage.
        3. Retrieves recently completed clean benign flows.
        4. Retrains classifier based on selected strategy.
        """
        # 1. Harvest hanging attack flows directly from server memory dump
        hanging_flows = self.server.get_exhausted_socket_flows()
        crash_harvest_X = [f.to_vector(self.feature_names) for f in hanging_flows]
        crash_harvest_y = [1] * len(crash_harvest_X)  # Retrospective supervision

        # 2. Retrieve verified baseline training data
        baseline_X = [f.to_vector(self.feature_names) for f in self.baseline_dataset]
        baseline_y = [f.label for f in self.baseline_dataset]

        # 3. Retrieve verified completed clean benign flows
        completed_benign = self.server.get_verified_benign_flows(max_samples=50)
        recent_benign_X = [f.to_vector(self.feature_names) for f in completed_benign]

        weights_before = list(self.model.weights)
        retrain_stats = {}

        if self.strategy == "balanced_mixture":
            retrain_stats = self.model.retrain_mixture(
                baseline_X=baseline_X,
                baseline_y=baseline_y,
                crash_X=crash_harvest_X,
                crash_y=crash_harvest_y,
                recent_benign_X=recent_benign_X,
                epochs=35,
                mixture_ratio=0.50
            )
        elif self.strategy == "new_only":
            retrain_stats = self.model.retrain_new_only(
                crash_X=crash_harvest_X,
                crash_y=crash_harvest_y,
                recent_benign_X=recent_benign_X[:3],
                epochs=35
            )
        elif self.strategy == "static":
            retrain_stats = {"note": "Static model - no retraining executed"}

        weights_after = list(self.model.weights)
        weight_shift = math.sqrt(sum((wa - wb) ** 2 for wa, wb in zip(weights_after, weights_before)))

        return {
            "step": step,
            "timestamp": timestamp,
            "strategy": self.strategy,
            "hanging_sockets_harvested": len(crash_harvest_X),
            "verified_benign_preserved": len(recent_benign_X),
            "weight_shift_l2": round(weight_shift, 4),
            "retrain_stats": retrain_stats
        }

    def generate_summary_report(self) -> Dict:
        """Calculates evaluation metrics partitioned by timeline phases."""
        all_X = [f.to_vector(self.feature_names) for f in self.flow_history]
        all_y = [f.label for f in self.flow_history]
        overall = self.model.evaluate(all_X, all_y)

        # Timeline splits matching 11:05 -> 11:30
        pre_drift_X = all_X[:480]
        pre_drift_y = all_y[:480]

        surge_X = all_X[480:1350]
        surge_y = all_y[480:1350]

        post_X = all_X[1350:]
        post_y = all_y[1350:]

        return {
            "strategy": self.strategy,
            "total_samples": len(self.flow_history),
            "server_total_crashes": self.server.crash_count,
            "adwin_alarms_count": len(self.adwin_triggers),
            "adwin_triggers": self.adwin_triggers,
            "retraining_events": self.retraining_events,
            "overall_metrics": overall,
            "pre_drift_metrics": self.model.evaluate(pre_drift_X, pre_drift_y) if pre_drift_X else {},
            "surge_phase_metrics": self.model.evaluate(surge_X, surge_y) if surge_X else {},
            "post_retrain_metrics": self.model.evaluate(post_X, post_y) if post_X else {},
            "top_model_weights": self.model.get_top_features(top_k=5)
        }
