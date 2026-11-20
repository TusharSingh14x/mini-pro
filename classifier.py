"""
Online Traffic Classifier: Standardized Logistic Regression
===========================================================
Pure-Python implementation with L2 Regularization, SGD, and Balanced Mixture Retraining.
Provides transparent weight inspection and metric calculation for academic demonstrations.
"""

import math
import random
from typing import Dict, List, Optional, Tuple

class StandardScaler:
    """Standardizes features by removing the mean and scaling to unit variance."""
    def __init__(self):
        self.means: List[float] = []
        self.stds: List[float] = []
        self.fitted: bool = False

    def fit(self, X: List[List[float]]):
        if not X:
            return
        n_samples = len(X)
        n_features = len(X[0])

        self.means = [0.0] * n_features
        for row in X:
            for j in range(n_features):
                self.means[j] += row[j]
        self.means = [m / n_samples for m in self.means]

        self.stds = [0.0] * n_features
        for row in X:
            for j in range(n_features):
                diff = row[j] - self.means[j]
                self.stds[j] += diff * diff
        self.stds = [math.sqrt(s / max(1, n_samples - 1)) for s in self.stds]
        # Avoid division by zero
        self.stds = [s if s > 1e-8 else 1.0 for s in self.stds]
        self.fitted = True

    def transform_row(self, row: List[float]) -> List[float]:
        if not self.fitted:
            return row
        return [(row[j] - self.means[j]) / self.stds[j] for j in range(len(row))]

    def transform(self, X: List[List[float]]) -> List[List[float]]:
        return [self.transform_row(row) for row in X]


class OnlineLogisticRegression:
    """
    Logistic Regression Classifier with Stochastic Gradient Descent (SGD).
    Supports initial batch fitting, online sequential updates, and Balanced Mixture Retraining.
    """

    def __init__(
        self,
        feature_names: List[str],
        learning_rate: float = 0.05,
        l2_lambda: float = 0.001,
        decision_threshold: float = 0.50
    ):
        self.feature_names = feature_names
        self.n_features = len(feature_names)
        self.lr = learning_rate
        self.l2_lambda = l2_lambda
        self.threshold = decision_threshold

        self.scaler = StandardScaler()
        # Initialize weights with small random Gaussian values
        rng = random.Random(42)
        self.weights = [rng.gauss(0.0, 0.05) for _ in range(self.n_features)]
        self.bias = 0.0

    @staticmethod
    def _sigmoid(z: float) -> float:
        # Clip z to avoid numerical overflow in exp(-z)
        z_clipped = max(-50.0, min(50.0, z))
        return 1.0 / (1.0 + math.exp(-z_clipped))

    def predict_proba_raw(self, x_scaled: List[float]) -> float:
        """Compute P(y=1 | x) for scaled features."""
        dot = sum(w * x for w, x in zip(self.weights, x_scaled)) + self.bias
        return self._sigmoid(dot)

    def predict_proba(self, raw_features: List[float]) -> float:
        """Standardize raw feature vector and return DDoS probability."""
        x_scaled = self.scaler.transform_row(raw_features)
        return self.predict_proba_raw(x_scaled)

    def predict(self, raw_features: List[float]) -> int:
        """Classify flow: 1 for DDoS, 0 for Benign."""
        prob = self.predict_proba(raw_features)
        return 1 if prob >= self.threshold else 0

    def fit_initial(
        self,
        X_raw: List[List[float]],
        y: List[int],
        epochs: int = 40,
        batch_size: int = 32
    ) -> Dict[str, float]:
        """
        Initial offline training on historical baseline data.
        Fits feature scaler and optimizes weights using mini-batch SGD.
        """
        self.scaler.fit(X_raw)
        X = self.scaler.transform(X_raw)
        n = len(X)
        indices = list(range(n))
        rng = random.Random(1337)

        final_loss = 0.0
        for _ in range(epochs):
            rng.shuffle(indices)
            epoch_loss = 0.0
            for start_idx in range(0, n, batch_size):
                batch_indices = indices[start_idx : start_idx + batch_size]
                b_size = len(batch_indices)

                # Gradient accumulators
                dw = [0.0] * self.n_features
                db = 0.0

                for i in batch_indices:
                    xi = X[i]
                    yi = y[i]
                    p = self.predict_proba_raw(xi)
                    err = p - yi  # Gradient of cross-entropy w.r.t logits

                    # Cross-entropy loss accumulation
                    p_safe = max(1e-12, min(1.0 - 1e-12, p))
                    sample_loss = -(yi * math.log(p_safe) + (1 - yi) * math.log(1.0 - p_safe))
                    epoch_loss += sample_loss

                    for j in range(self.n_features):
                        dw[j] += err * xi[j]
                    db += err

                # Weight update with L2 regularization
                for j in range(self.n_features):
                    self.weights[j] -= self.lr * ((dw[j] / b_size) + self.l2_lambda * self.weights[j])
                self.bias -= self.lr * (db / b_size)

            final_loss = epoch_loss / n

        return {"train_loss": final_loss}

    def retrain_mixture(
        self,
        baseline_X: List[List[float]],
        baseline_y: List[int],
        crash_X: List[List[float]],
        crash_y: List[int],
        recent_benign_X: List[List[float]],
        epochs: int = 35,
        mixture_ratio: float = 0.50
    ) -> Dict[str, float]:
        """
        The Proposed Balanced Mixture Retraining Strategy:
        Combines historical baseline data + crash window DDoS data + recent benign samples.
        Prevents catastrophic forgetting while incorporating new attack vectors.
        """
        # Formulate combined dataset
        combined_X = []
        combined_y = []

        # 1. Add historical baseline data (stabilizer)
        combined_X.extend(baseline_X)
        combined_y.extend(baseline_y)

        # 2. Add newly isolated crash DDoS data (weighted adaptation)
        # We can oversample or blend to match desired mixture balance
        repeat_factor = max(1, int(len(baseline_X) * mixture_ratio / max(1, len(crash_X))))
        for _ in range(repeat_factor):
            combined_X.extend(crash_X)
            combined_y.extend(crash_y)

        # 3. Add recent benign verification data to guard against false alarms
        for bx in recent_benign_X:
            combined_X.append(bx)
            combined_y.append(0)

        # Refit scaler on combined distribution to accommodate drifted feature ranges
        self.scaler.fit(combined_X)
        X_scaled = self.scaler.transform(combined_X)

        n = len(X_scaled)
        indices = list(range(n))
        rng = random.Random(999)

        loss = 0.0
        for _ in range(epochs):
            rng.shuffle(indices)
            epoch_loss = 0.0
            batch_size = 32
            for start in range(0, n, batch_size):
                b_idx = indices[start : start + batch_size]
                b_len = len(b_idx)
                dw = [0.0] * self.n_features
                db = 0.0

                for i in b_idx:
                    xi = X_scaled[i]
                    yi = combined_y[i]
                    p = self.predict_proba_raw(xi)
                    err = p - yi

                    p_safe = max(1e-12, min(1.0 - 1e-12, p))
                    epoch_loss += -(yi * math.log(p_safe) + (1 - yi) * math.log(1.0 - p_safe))

                    for j in range(self.n_features):
                        dw[j] += err * xi[j]
                    db += err

                for j in range(self.n_features):
                    self.weights[j] -= self.lr * ((dw[j] / b_len) + self.l2_lambda * self.weights[j])
                self.bias -= self.lr * (db / b_len)
            loss = epoch_loss / n

        return {"mixture_loss": loss, "total_samples_trained": n}

    def retrain_new_only(
        self,
        crash_X: List[List[float]],
        crash_y: List[int],
        recent_benign_X: List[List[float]],
        epochs: int = 35
    ) -> Dict[str, float]:
        """
        Approach A (Naive Retraining on New Data Only).
        Demonstrates 'Catastrophic Forgetting': adapts quickly to new attack,
        but loses classification boundary for baseline normal traffic.
        """
        combined_X = list(crash_X)
        combined_y = list(crash_y)

        for bx in recent_benign_X:
            combined_X.append(bx)
            combined_y.append(0)

        self.scaler.fit(combined_X)
        X_scaled = self.scaler.transform(combined_X)

        n = len(X_scaled)
        indices = list(range(n))
        rng = random.Random(777)

        loss = 0.0
        for _ in range(epochs):
            rng.shuffle(indices)
            epoch_loss = 0.0
            batch_size = min(16, n)
            for start in range(0, n, batch_size):
                b_idx = indices[start : start + batch_size]
                b_len = len(b_idx)
                dw = [0.0] * self.n_features
                db = 0.0

                for i in b_idx:
                    xi = X_scaled[i]
                    yi = combined_y[i]
                    p = self.predict_proba_raw(xi)
                    err = p - yi

                    p_safe = max(1e-12, min(1.0 - 1e-12, p))
                    epoch_loss += -(yi * math.log(p_safe) + (1 - yi) * math.log(1.0 - p_safe))

                    for j in range(self.n_features):
                        dw[j] += err * xi[j]
                    db += err

                for j in range(self.n_features):
                    self.weights[j] -= self.lr * ((dw[j] / b_len) + self.l2_lambda * self.weights[j])
                self.bias -= self.lr * (db / b_len)
            loss = epoch_loss / n

        return {"new_only_loss": loss, "total_samples_trained": n}

    def get_top_features(self, top_k: int = 5) -> List[Tuple[str, float]]:
        """Returns top influential features based on absolute weight values."""
        paired = list(zip(self.feature_names, self.weights))
        paired.sort(key=lambda item: abs(item[1]), reverse=True)
        return paired[:top_k]

    def evaluate(self, X_raw: List[List[float]], y: List[int]) -> Dict[str, float]:
        """Calculates standard NIDS performance metrics: Accuracy, Precision, Recall, F1, FPR, FNR."""
        tp = fp = tn = fn = 0
        for xi, yi in zip(X_raw, y):
            pred = self.predict(xi)
            if yi == 1 and pred == 1:
                tp += 1
            elif yi == 0 and pred == 1:
                fp += 1
            elif yi == 0 and pred == 0:
                tn += 1
            elif yi == 1 and pred == 0:
                fn += 1

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / max(1, total)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = (2 * precision * recall) / max(1e-8, precision + recall)
        fpr = fp / max(1, fp + tn)  # False Positive Rate
        fnr = fn / max(1, fn + tp)  # False Negative Rate (Miss Rate)

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "fpr": fpr,
            "fnr": fnr,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "total_samples": total
        }

    def explain(self, x_raw: List[float], top_k: int = 5) -> Dict:
        """
        Explainable AI (XAI) Dynamic Feature Attribution:
        Decomposes classification logit into exact per-feature contributions:
        logit(p) = bias + sum(w_j * x_norm_j).
        Returns human-readable explanation and percentage attributions.
        """
        x_norm = self.scaler.transform_row(x_raw)
        p_ddos = self.predict_proba_raw(x_norm)
        pred_label = 1 if p_ddos >= 0.50 else 0
        decision_str = "DDoS Attack" if pred_label == 1 else "Benign Traffic"

        z = self.bias + sum(w * x for w, x in zip(self.weights, x_norm))
        total_abs = sum(abs(w * x) for w, x in zip(self.weights, x_norm)) + 1e-8

        contributions = []
        for name, raw_v, norm_v, w in zip(self.feature_names, x_raw, x_norm, self.weights):
            phi = w * norm_v
            pct = (abs(phi) / total_abs) * 100.0
            contributions.append({
                "feature": name,
                "raw_value": round(raw_v, 3),
                "normalized_value": round(norm_v, 3),
                "weight": round(w, 4),
                "attribution": round(phi, 4),
                "percentage_impact": round(pct, 1),
                "supports_attack": phi > 0
            })

        contributions.sort(key=lambda item: abs(item["attribution"]), reverse=True)
        top_attribs = contributions[:top_k]

        reasons = []
        for item in top_attribs[:3]:
            direction = "elevating" if item["supports_attack"] else "reducing"
            reasons.append(f"{item['feature']}={item['raw_value']} ({direction} attack probability by {item['percentage_impact']}%)")

        summary = f"Flow classified as {decision_str} (p={p_ddos:.3f}) primarily due to: {'; '.join(reasons)}."

        return {
            "prediction": pred_label,
            "decision": decision_str,
            "probability": round(p_ddos, 4),
            "base_bias": round(self.bias, 4),
            "logit_z": round(z, 4),
            "top_features": top_attribs,
            "summary": summary
        }


class StreamingNaiveBayes:
    """Online Gaussian Naive Bayes with Welford running variance updates."""
    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.d = len(feature_names)
        self.class_counts = {0: 0, 1: 0}
        self.means = {0: [0.0]*self.d, 1: [0.0]*self.d}
        self.m2 = {0: [0.0]*self.d, 1: [0.0]*self.d}

    def fit_batch(self, X: List[List[float]], y: List[int]):
        for xi, yi in zip(X, y):
            self.update(xi, yi)

    def update(self, x: List[float], y: int):
        self.class_counts[y] += 1
        n = self.class_counts[y]
        for j in range(self.d):
            delta = x[j] - self.means[y][j]
            self.means[y][j] += delta / n
            delta2 = x[j] - self.means[y][j]
            self.m2[y][j] += delta * delta2

    def predict_proba(self, x: List[float]) -> float:
        total = self.class_counts[0] + self.class_counts[1]
        if total == 0:
            return 0.5
        prior0 = math.log(max(1, self.class_counts[0]) / total)
        prior1 = math.log(max(1, self.class_counts[1]) / total)
        log_lik0 = prior0
        log_lik1 = prior1
        for j in range(self.d):
            var0 = max(1e-4, self.m2[0][j] / max(1, self.class_counts[0] - 1))
            var1 = max(1e-4, self.m2[1][j] / max(1, self.class_counts[1] - 1))
            diff0 = x[j] - self.means[0][j]
            diff1 = x[j] - self.means[1][j]
            log_lik0 += -0.5 * math.log(2 * math.pi * var0) - (diff0 * diff0) / (2 * var0)
            log_lik1 += -0.5 * math.log(2 * math.pi * var1) - (diff1 * diff1) / (2 * var1)
        log_diff = max(-50.0, min(50.0, log_lik1 - log_lik0))
        return 1.0 / (1.0 + math.exp(-log_diff))

    def predict(self, x: List[float]) -> int:
        return 1 if self.predict_proba(x) >= 0.50 else 0

    def evaluate(self, X: List[List[float]], y: List[int]) -> Dict:
        tp = fp = tn = fn = 0
        for xi, yi in zip(X, y):
            pred = self.predict(xi)
            if yi == 1 and pred == 1: tp += 1
            elif yi == 0 and pred == 1: fp += 1
            elif yi == 0 and pred == 0: tn += 1
            elif yi == 1 and pred == 0: fn += 1
        tot = tp + fp + tn + fn
        return {
            "accuracy": (tp + tn) / max(1, tot),
            "precision": tp / max(1, tp + fp),
            "recall": tp / max(1, tp + fn),
            "f1": (2 * tp) / max(1, 2 * tp + fp + fn),
            "fpr": fp / max(1, fp + tn),
            "fnr": fn / max(1, fn + tp)
        }


class StreamingPerceptron:
    """Online Margin Perceptron with causal online scaling."""
    def __init__(self, feature_names: List[str], lr: float = 0.05):
        self.feature_names = feature_names
        self.d = len(feature_names)
        self.lr = lr
        self.weights = [0.0] * self.d
        self.bias = 0.0
        self.scaler = StandardScaler()

    def fit_batch(self, X: List[List[float]], y: List[int], epochs: int = 20):
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        for _ in range(epochs):
            for xi, yi in zip(X_scaled, y):
                target = 1 if yi == 1 else -1
                score = self.bias + sum(w * x for w, x in zip(self.weights, xi))
                if target * score <= 0:
                    for j in range(self.d):
                        self.weights[j] += self.lr * target * xi[j]
                    self.bias += self.lr * target

    def predict(self, x_raw: List[float]) -> int:
        xi = self.scaler.transform_row(x_raw)
        score = self.bias + sum(w * x for w, x in zip(self.weights, xi))
        return 1 if score >= 0 else 0

    def evaluate(self, X: List[List[float]], y: List[int]) -> Dict:
        tp = fp = tn = fn = 0
        for xi, yi in zip(X, y):
            pred = self.predict(xi)
            if yi == 1 and pred == 1: tp += 1
            elif yi == 0 and pred == 1: fp += 1
            elif yi == 0 and pred == 0: tn += 1
            elif yi == 1 and pred == 0: fn += 1
        tot = tp + fp + tn + fn
        return {
            "accuracy": (tp + tn) / max(1, tot),
            "precision": tp / max(1, tp + fp),
            "recall": tp / max(1, tp + fn),
            "f1": (2 * tp) / max(1, 2 * tp + fp + fn),
            "fpr": fp / max(1, fp + tn),
            "fnr": fn / max(1, fn + tp)
        }

