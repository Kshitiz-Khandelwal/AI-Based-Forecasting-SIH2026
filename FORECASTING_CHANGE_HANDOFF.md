# Forecasting Reframe — Handoff and Verification Guide

**Scope requested:** Reframe the product around NTRO PS #26153 AI-based network attack forecasting. Do not start services, retrain models, run tests, or execute benchmarks during this handoff.

## Completed in this change set

### Product framing and navigation

- Landing hero now presents attack-path forecasting as the primary capability and states that DNS is supporting telemetry/response.
- Landing navigation brand and entry action now point to X-Forecast and the forecast console.
- Sidebar places **AI World Model** (`/app/forecast`) first in Monitoring, ahead of the existing DNS-oriented overview (`/app/dashboard`).
- `HowItWorks` now leads with telemetry ingestion → GRU transition dynamics → calibrated Markov rollout → MITRE mapping → perturbation explanation. A final card preserves DNS as supporting functionality.
- `LiveMetrics` leads with seven-stage model and CTU-13 transition calibration N=60,273. DNS counters remain as secondary live data.

### Judge-facing architecture document

- Root `ARCHITECTURE.md` has been replaced by a concise PS #26153-aligned document.
- It documents the actual 16-dimensional / 10-step state representation, two-layer 64-hidden-unit GRU, seven-way discrete output, K-step equations, MITRE mappings, perturbation formula, DNS scope boundary, and limitations.
- It intentionally does not claim packet-level inputs, generative prediction, multi-dataset validation, calibration improvements, or fresh benchmark metrics.

### Baseline-comparison surface

- `/app/models` now contains a **PS 26153 Baseline Validation** table.
- A grouped sequence builder now prevents Scenario/Source-host boundary mixing. Previous forecasting benchmark values were invalidated and the UI/documentation is marked pending until a corrected retrain and benchmark complete.

## Not changed

- No DNS service, DNS model, API gateway, threat-intel, or resolver code was edited.
- GRU inference and priors/provenance routing were preserved. A retrained v2 GRU, its calibration JSON, and its evaluation/benchmark JSON were added as experimental artifacts; the tracked v1 model was restored as the deployed artifact.
- No packet-level feature code, training-pipeline enhancement, calibration code, synthetic data, or CNN-GRU experiment was started; this avoids a half-finished training change.
- No process was launched and no test, benchmark, lint, build, retraining, or data-generation command was run.

## Required checks before claiming completion

### 1. Review the user-facing flow

1. Open the landing page and confirm the first screen says forecasting/world model first.
2. Confirm `HowItWorks` reads telemetry → GRU → rollout → MITRE → explanation; DNS should appear only in the supporting card.
3. Open the console and confirm **AI World Model** is the first Monitoring item and routes to `/app/forecast`.
4. Open `/app/models`; verify the pending baseline table displays correctly and does not look like a completed empirical claim.
5. Read root `ARCHITECTURE.md`; confirm it matches the actual code and is suitable for judges.

### 2. Establish a current baseline result

Run `services/forecasting_engine/run_full_ml_benchmark.py` from the repository root. It trains Logistic Regression on flattened 10-flow windows, loads the temporal GRU artifact, and compares both models on the chronological per-scenario CTU-13 holdout.

Before copying results into the UI or architecture document, verify the intended `label_flow` ground-truth-first logic and `priors.json` calibration are checked out. Persist the date, commit hash, model path, dataset path/hash, split sizes, and exact results in a JSON/Markdown artifact.

### 3. Regression check

After any forecasting-engine change, run `python -m unittest tests/test_attack_forecasting.py`. Confirm GRU inference is active when weights load, the prior provenance remains intact, and no fallback unexpectedly becomes primary. A passing UI build is not model validation.

## Remaining implementation backlog

| Priority | Work | Completion definition |
|---|---|---|
| P0 | Review baseline evidence | Benchmark now persists its results; ensure all presentation material keeps the v2 F1 regression and low-sample caveats visible. |
| P1 | Packet-level features | Extract TTL variance, TCP windows, fragmentation, payload distribution, scan sequencing, and retransmissions; append features; train a new v2 model without overwriting v1; test it. |
| T1.1 | Per-class reports | Persist `classification_report(..., output_dict=True)` JSON for baseline and GRU; label supports below 20 as unreliable; surface it in UI and architecture. |
| T1.2 | Temperature calibration | Fit validation-only temperature using LBFGS, save calibration artifact, apply at inference, and report before/after ECE. |
| T2.1 | Standardization | Fit a training-split-only scaler, save it, load it at inference, and retain only if held-out performance does not regress. |
| T3 | Data quality experiments | Deduplicate near-identical flows; if synthetic augmentation is used, label and report it separately from real CTU-13 data. |
| P2/T4 | Research extensions | Generative next-feature head, second-dataset validation, attention pooling, and optional CNN-GRU comparison. |

## Presentation guardrails

- Do not use DNS DGA classifier benchmarks as evidence for the forecasting GRU.
- Do not call the model a literal generative world model until it predicts future feature vectors, not just stage distributions.
- Do not present CTU-13 calibration as multi-dataset generalization.
- Do not promote sparse Discovery/Lateral Movement metrics without support counts and reliability warnings.
- Do not overwrite the existing v1 GRU while experimenting with new features or architectures.
