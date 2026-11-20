# University Project Report (LaTeX Monolithic Master Document)

## Document Overview
* **File Name:** [`FINAL_PROJECT_REPORT.tex`](file:///Users/testaccount/Desktop/miniP/FINAL_PROJECT_REPORT.tex) *(also mirrored at [`report/main.tex`](file:///Users/testaccount/Desktop/miniP/report/main.tex))*
* **Target Output:** ~45 Pages (40–50 Pages standard B.Tech University Final Submission)
* **Format:** Standard A4 Paper, 12pt Font, 1.5 Line Spacing (`\onehalfspacing`), 1-inch Margins
* **Title:** Adaptive DDoS Classification via Failure-Driven Drift Retraining: Using System Crashes as Ground Truth to Detect Drift and Retrain on Old + New Data Mixtures
* **Authors:** **Tushar Singh** (Lead / 1st Author), Eshan Jogwar, Rudra
* **Department:** Department of Computer Engineering
* **Academic Year:** 2025–2026

---

## How to Compile in Overleaf (Recommended - 1 Click)

1. Open **[Overleaf](https://www.overleaf.com)** and log in.
2. Click **New Project** $\to$ **Blank Project** (name it e.g. `Mini_Project_Report`).
3. Open `main.tex` in the Overleaf editor.
4. Copy the entire contents of [`FINAL_PROJECT_REPORT.tex`](file:///Users/testaccount/Desktop/miniP/FINAL_PROJECT_REPORT.tex) and paste it into `main.tex` (replacing everything).
5. Click **Recompile** (green button).
   * *Note: No external `.bib` or image files are required! All citations are embedded directly, and all diagrams are written in native vector TikZ.*

---

## How to Compile Locally (Command Line)

If MacTeX, TeX Live, or MiKTeX is installed:
```bash
pdflatex FINAL_PROJECT_REPORT.tex
pdflatex FINAL_PROJECT_REPORT.tex
```
*(Running it twice ensures all cross-references, table of contents, and list of figures resolve automatically).*

---

## Report Structure Summary

1. **Preliminary Pages (Roman Numerals i--x):**
   - Title Page (University format, authors, department, guide)
   - Certificate (Signatures for Guide, HOD, and External Examiner)
   - Student Declaration of Originality
   - Academic Acknowledgements
   - Executive Abstract & Keywords
   - Table of Contents (`\tableofcontents`)
   - List of Figures (`\listoffigures`)
   - List of Tables (`\listoftables`)
   - List of Abbreviations (24 technical network security acronyms)

2. **Main Chapters (Arabic Numerals 1--N):**
   - **Chapter 1: Introduction (4--5 pages):** Background, Concept Drift taxonomy, Ground Truth Dilemma, Cost Asymmetry, Problem Statement, Objectives, Scope.
   - **Chapter 2: Literature Review (6--8 pages):** Generations of NIDS, Stationarity Trap, Streaming Hoeffding Trees, ADWIN vs Page-Hinkley, Catastrophic Forgetting, CIC benchmark datasets, Master Literature Comparison Matrix (Table 2.1).
   - **Chapter 3: Problem Analysis and Requirements (4--5 pages):** Adversarial mutation (Volumetric SYN to Slowloris), Socket Table Exhaustion differential equations, Functional Requirements (FR-1 to FR-8), Non-Functional Requirements (NFR-1 to NFR-6), Use Cases, Feasibility Analysis.
   - **Chapter 4: System Design and Architecture (6--7 pages):** Full 5-stage Closed-Loop Architecture (TikZ vector graphic), Component Dependency Diagram, Level 0 & Level 1 DFDs, UML Sequence Diagram, Server Health State Machine.
   - **Chapter 5: Methodology and Implementation (7--9 pages):** 10-feature CICFlowMeter schema table, Causal `OnlineStandardScaler`, Online Logistic Regression loss and gradient derivations, Server socket table manager, ADWIN algorithm pseudo-code, Mathematical Proof of why New-Only retraining fails, Balanced Mixture Retraining algorithm.
   - **Chapter 6: Results and Evaluation (5--7 pages):** Canadian University CIC-IDS2017 Wednesday Slowloris benchmark, Master Comparative Performance Matrix table, Full Confusion Matrices table, ADWIN vs Page-Hinkley comparison table, Retraining Window Sensitivity table (100--1000 samples, 144 ms latency), Model Weight Trajectory ($\|\Delta \mathbf{w}\|_2 = 3.0663$), Zero Data Leakage Verification.
   - **Chapter 7: Applications, Advantages and Limitations (2--3 pages):** Cloud Ingress, IoT Edge, SD-WAN, CDNs, System Advantages, Operational Limitations.
   - **Chapter 8: Conclusion and Future Scope (2--3 pages):** Summary of achievements, audit of completed Slide 6 roadmap milestones, future eBPF/XDP kernel acceleration, Kubernetes cluster federation.

3. **Final Sections:**
   - Embedded Bibliography (15 peer-reviewed citations)
   - **Appendix A:** Core Python Source Code Listings (`closed_loop_engine.py`, `classifier.py`)
   - **Appendix B:** Installation, CLI Admin Controller manual, Web Dashboard guide
