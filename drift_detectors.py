"""
Concept Drift Detection Module: ADWIN & Page-Hinkley
====================================================
Pure-Python, zero-dependency implementations of:
1. ADWIN (Adaptive Windowing) - Bifet & Gavaldà (2007)
2. Page-Hinkley Cumulative Sum Change Detector - Page (1954), Hinkley (1970)

Used to detect distributional shifts in model error streams or feature spaces.
"""

import math
from typing import List, Optional, Tuple

class ADWIN:
    """
    ADWIN (ADaptive WINdowing) Drift Detector.
    
    Theoretical Basis:
    Maintains a dynamic sliding window W of recent values. When the difference between
    the means of two sub-windows W0 and W1 exceeds a Hoeffding-bound threshold epsilon_cut,
    the older sub-window is discarded and a concept drift alarm is triggered.
    
    Mathematical Formulation:
      n0 = len(W0), n1 = len(W1), n = n0 + n1
      Harmonic sample size m = (n0 * n1) / (n0 + n1)
      epsilon_cut = sqrt((1 / (2 * m)) * ln(4 * n / delta))
      
      Drift condition: |mu_W0 - mu_W1| >= epsilon_cut
    """

    def __init__(self, delta: float = 0.05, max_buckets: int = 1000, min_subwindow_len: int = 10):
        """
        Args:
            delta: Confidence parameter. Bound on false positive alarm probability (e.g. 0.05 = 95% confidence).
            max_buckets: Maximum items in sliding window to cap memory.
            min_subwindow_len: Minimum sub-window size to evaluate statistical test.
        """
        self.delta = delta
        self.max_buckets = max_buckets
        self.min_subwindow_len = min_subwindow_len
        self.window: List[float] = []
        self.total_sum: float = 0.0
        self.drift_detected: bool = False
        self.warning_detected: bool = False
        self.last_drift_index: int = 0
        self.step_count: int = 0

    def add_element(self, value: float) -> bool:
        """
        Add a new scalar observation (e.g., 0 for correct prediction, 1 for error)
        to the window and evaluate drift hypothesis.
        
        Returns:
            True if concept drift is detected, False otherwise.
        """
        self.step_count += 1
        self.drift_detected = False
        self.window.append(float(value))
        self.total_sum += float(value)

        # Enforce maximum capacity
        if len(self.window) > self.max_buckets:
            dropped = self.window.pop(0)
            self.total_sum -= dropped

        # Evaluate sub-windows for distribution shift
        n = len(self.window)
        if n < self.min_subwindow_len * 2:
            return False

        # Test cut points along the window
        # We step through potential split points W = W0 + W1
        step_stride = max(1, n // 20)  # Check candidate splits
        best_diff = 0.0
        best_cut_idx = -1

        w0_sum = 0.0
        for i in range(n - 1):
            w0_sum += self.window[i]
            n0 = i + 1
            n1 = n - n0

            if n0 < self.min_subwindow_len or n1 < self.min_subwindow_len:
                continue

            if (n0 % step_stride != 0) and (n0 != n - self.min_subwindow_len):
                continue

            w1_sum = self.total_sum - w0_sum
            mu0 = w0_sum / n0
            mu1 = w1_sum / n1
            diff = abs(mu0 - mu1)

            m = (n0 * n1) / (n0 + n1)
            # Hoeffding bound with confidence delta
            epsilon_cut = math.sqrt((1.0 / (2.0 * m)) * math.log((4.0 * n) / self.delta))

            if diff >= epsilon_cut and diff > best_diff:
                best_diff = diff
                best_cut_idx = i

        if best_cut_idx != -1:
            # Drift confirmed! Discard the older distribution regime (W0)
            self.drift_detected = True
            self.last_drift_index = self.step_count
            discard_len = best_cut_idx + 1
            discarded_sum = sum(self.window[:discard_len])
            self.window = self.window[discard_len:]
            self.total_sum -= discarded_sum
            return True

        return False

    @property
    def current_mean(self) -> float:
        if not self.window:
            return 0.0
        return self.total_sum / len(self.window)

    @property
    def window_size(self) -> int:
        return len(self.window)

    def reset(self):
        self.window.clear()
        self.total_sum = 0.0
        self.drift_detected = False
        self.warning_detected = False


class PageHinkley:
    """
    Page-Hinkley Change-Point Detector.
    
    Sequential analysis technique (CUSUM derivative) designed to detect abrupt
    increases in the mean of a streaming variable while being robust to noise.
    
    Formulation:
      m_t = cumulative sum of (x_i - mean - delta)
      M_t = min(m_i for i <= t)
      Alarm when: m_t - M_t > threshold
    """

    def __init__(self, delta: float = 0.005, threshold: float = 15.0, alpha: float = 0.99):
        """
        Args:
            delta: Allowable slack parameter to prevent drift on small fluctuations.
            threshold: Cumulative deviation required to trip an alarm.
            alpha: Decay factor for running mean estimation.
        """
        self.delta = delta
        self.threshold = threshold
        self.alpha = alpha
        self.sample_count: int = 0
        self.running_mean: float = 0.0
        self.cum_sum: float = 0.0
        self.min_cum_sum: float = 0.0
        self.drift_detected: bool = False

    def add_element(self, value: float) -> bool:
        self.sample_count += 1
        self.drift_detected = False

        if self.sample_count == 1:
            self.running_mean = value
            self.cum_sum = 0.0
            self.min_cum_sum = 0.0
            return False

        # Update running mean
        self.running_mean = self.alpha * self.running_mean + (1.0 - self.alpha) * value
        deviation = value - self.running_mean - self.delta
        self.cum_sum += deviation

        if self.cum_sum < self.min_cum_sum:
            self.min_cum_sum = self.cum_sum

        ph_stat = self.cum_sum - self.min_cum_sum
        if ph_stat > self.threshold:
            self.drift_detected = True
            # Reset after alarm
            self.cum_sum = 0.0
            self.min_cum_sum = 0.0
            return True

        return False

    def reset(self):
        self.sample_count = 0
        self.running_mean = 0.0
        self.cum_sum = 0.0
        self.min_cum_sum = 0.0
        self.drift_detected = False

