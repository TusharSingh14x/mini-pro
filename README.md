# Adaptive DDoS Classification via Failure-Driven Drift Retraining

> **3rd Year B.Tech Mini Project | Progress Review Implementation & Research Codebase**  
> **Presenters:** Eshan Jogwar & Tushar Singh | Department of Computer Engineering | 2026

---

## 🚀 Quick Start Guide

### 1. Run the Empirical Benchmark Suite
Executes the full comparative experiment across all three retraining strategies (Static, New-Only, Balanced Mixture) and generates sensitivity tables:
```bash
python3 run_experiments.py
```

### 2. Launch the Interactive Jury Demonstration Dashboard
Start the local demonstration server and open the live UI in your browser:
```bash
python3 demo_server.py
```
Open **[http://localhost:8080](http://localhost:8080)** or directly open `dashboard.html` in Safari / Chrome.

---

## 🎯 Project Overview & Core Concept

Network Intrusion Detection Systems (NIDS) fail in the real world because attackers mutate their attack signatures (**Concept Drift**), rendering static classifiers ineffective. 

Existing solutions fail because of the **Supervision Bottleneck**: machine learning models cannot retrain without true labels, and human security analysts cannot re-label packets in real-time before servers go down.

### Our Solution: The Closed-Loop Feedback Architecture
1. **The Asymmetric Cost of Failure:** A False Positive merely blocks a request, but a **False Negative** (DDoS misclassified as Benign) crashes the server.
2. **Crash = Ground Truth:** When the server crashes from resource exhaustion, the failure acts as an **automatic external supervisor**. It retroactively identifies the preceding unmitigated traffic as DDoS.
3. **ADWIN Drift Isolation:** We run the **ADWIN (Adaptive Windowing)** algorithm on the error stream to mathematically isolate the exact change-point timestamp where traffic parameters drifted.
4. **Balanced Mixture Retraining:** We combine:
   - Newly harvested crash DDoS flows (New vectors)
   - Recent verified benign samples
   - Historical baseline training data
   This prevents **catastrophic forgetting** while giving the model immunity against the new attack vector!

---

## 📊 Summary of Benchmark Results

| Strategy | Post-Retrain Accuracy | Recall (Catch Rate) | Miss Rate (FNR) | Precision | False Alarm (FPR) | Server Crashes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Approach B: Static (No Retrain)** | 62.13% | 14.97% | **85.03%** | 100.0% | 0.00% | **7 Crashes** |
| **Approach A: Retrain on New Only** | 98.13% | 95.81% | 4.19% | 100.0% | 0.00% | 1 Crash (Unstable) |
| **Our Approach: Balanced Mixture** | **100.00%** | **100.00%** | **0.00%** | **100.00%** | **0.00%** | **1 Crash (Resolved!)** |

---

## 📂 Codebase Structure

* [`traffic_generator.py`](traffic_generator.py): Realistic non-stationary network traffic generator with concept drift, generating flow features (packet rate, byte rate, duration, SYN/ACK ratios, entropy).
* [`drift_detectors.py`](drift_detectors.py): Pure-Python, zero-dependency implementations of **ADWIN** (Bifet & Gavaldà 2007) and **Page-Hinkley** (Page 1954, Hinkley 1970).
* [`classifier.py`](classifier.py): Online Logistic Regression with feature standardization, SGD, L2 regularization, and Balanced Mixture retraining.
* [`system_monitor.py`](system_monitor.py): Backend server health model tracking active connections, CPU saturation, and emitting failure-driven crash events.
* [`closed_loop_engine.py`](closed_loop_engine.py): The 5-stage closed loop orchestrator connecting traffic, classification, failure detection, ADWIN drift isolation, and retraining.
* [`run_experiments.py`](run_experiments.py): Automated experiment runner evaluating all strategies, window sizes, and metrics.
* [`demo_server.py`](demo_server.py): Zero-dependency HTTP & REST server for live presentation.
* [`dashboard.html`](dashboard.html): Interactive visual dashboard with real-time animated closed loop architecture, canvas rolling error rate chart, and server load meters.
* [`PROJECT_REPORT.md`](PROJECT_REPORT.md): Comprehensive, publication-grade academic report with literature review, theoretical derivations, empirical findings, and jury Q&A.

