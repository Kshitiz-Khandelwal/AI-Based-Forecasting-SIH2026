# Project Context — DNS Shield X-Forecast

**Purpose:** durable, evidence-first context for contributors working on the SIH project. Read this before editing forecasting, benchmarks, product copy, or presentation material.

## 1. Scope and current product position

The repository began as **DNS Shield**, a secure DNS filtering and threat-intelligence platform. The current requested framing prioritizes **NTRO PS #26153: AI-based network attack forecasting from network traffic data**:

- The forecasting engine consumes network-flow telemetry, estimates a seven-state MITRE-aligned attack stage, and rolls that state forward over forecast horizons.
- DNS detection/filtering remains a useful telemetry and response subsystem; it is not evidence that the forecasting model is accurate.
- The current temporal model is a two-layer PyTorch GRU over 10 flow windows and 16 extracted flow features. It produces a discrete stage distribution. It is **not yet** a generative future-feature world model.
- CTU-13 is the present forecasting dataset. It is not evidence of cross-dataset generalization.

Key code: `services/forecasting_engine/`, `services/flow_ingest/`, `frontend/src/app/app/forecast/`, and `services/api-gateway/app.py`.

## 2. Master-prompt goals relevant to this phase

The original master build specification remains the wider DNS-platform contract: deterministic local detection, explainable decisions, sandboxed response, microservice boundaries, reproducible performance/quality evaluation, and no fabricated metrics. The forecasting reframe adds the following goals:

1. Make temporal attack-path forecasting the primary user-facing story.
2. Keep DNS as supporting telemetry/response rather than presenting DNS DGA metrics as forecasting evidence.
3. Use chronological, scenario-aware, held-out evaluation and an explicit non-temporal baseline.
4. Preserve model provenance, per-class support, calibration, and exact artifact/result links.
5. Improve correctness before model size: grouped sequences, feature quality, split-safe preprocessing, and second-dataset validation precede CNN/attention/transformer experiments.

## 3. Verified repository baseline

At the time this document was written, `main` is at `97991fe` (`docs: exhaustively expand master prototype architecture and agent handoff guide`) and tracks `origin/main`. The only tracked forecasting model artifact is:

- `services/forecasting_engine/models/temporal_gru_forecaster.pt`

The committed repository has existing forecasting code, CTU-13 priors, a forecast UI, and reporting hooks. Historical documents may contain DNS benchmark numbers and older forecasting claims; do not reuse them as current forecasting evidence without reproducing them against the current code and corrected split/sequence policy.

## 4. Local working-tree state — not GitHub-confirmed

The workspace is dirty. Changes and untracked artifacts exist locally and are **not committed or pushed**. In particular, local modifications include the forecasting train/benchmark/inference code and `tests/test_attack_forecasting.py`; local untracked files include `evaluation_metrics.py`, a packet-feature extraction foundation, candidate v2 model artifacts, calibration/evaluation/benchmark JSON, and run logs.

This means all of the following require review and a clean rerun before being presented as project results:

- Any v2/v3 claim, F1/FPR claim, ECE/calibration claim, or model-selection claim.
- Any files named `temporal_gru_forecaster_grouped_v2*`, `temporal_gru_forecaster_v2*`, `forecasting_benchmark_results.json`, or local stdout/stderr logs.
- The local temperature-scaling implementation, despite being present in the working tree.

Never describe local files as saved to GitHub. Verify with `git status --short`, `git log -1 --oneline`, `git branch -vv`, and `git ls-files <path>`.

## 5. Confirmed correctness fix awaiting commit/review

The old sequence builder made a sliding window over flattened arrays. Because scenario partitions were concatenated first, windows could join flows from different scenarios or source hosts. That produces artificial attack histories and invalidates prior forecasting comparisons.

The current local edit to `TemporalSequenceDataset` accepts `group_ids` and builds windows independently for each `Scenario + SrcAddr` group. Both `train_temporal_gru.py` and `run_full_ml_benchmark.py` pass those group IDs, and `tests/test_attack_forecasting.py` contains a boundary test. This is the correct direction, but it is still a local uncommitted change until reviewed and committed.

Important: `benchmark_and_rollout.py` still uses a global chronological split and constructs a dataset without group IDs. It is not an approved source of post-fix benchmark evidence. Update it or retire it before using it in a report.

## 6. Model and artifact safety rules

- Do not overwrite `temporal_gru_forecaster.pt` during experimentation.
- Train candidates using a new explicit filename via `TEMPORAL_GRU_MODEL_FILENAME`, for example `temporal_gru_forecaster_grouped_v3.pt`.
- Candidate calibration/evaluation/benchmark files must share the candidate artifact stem and record model filename, dataset path/hash, git commit, split policy, grouping policy, seed, package versions, timestamp, and command.
- Promote a candidate only after it is independently rerun, reviewed, committed with its metrics, and chosen against the v1 baseline using predefined metrics. Preserve the previous deployed artifact.
- Never load a calibration file for a different model filename. The local inference code contains a filename guard; retain it.

## 7. Exact next implementation order

1. **Review and commit the grouped-builder fix** with its unit test. Also make every benchmark path obey the same grouping policy or mark it unsupported.
2. **Clean reproducibility run:** retrain a named grouped candidate and run the same grouped benchmark for Logistic Regression and GRU. Do not overwrite v1. Persist reproducibility metadata and per-class results.
3. **Model-selection gate:** compare weighted/macro F1, benign FPR, per-class recall/support, calibration (ECE), and latency. Mark support below 20 as unreliable. Do not select a model by one aggregate metric alone.
4. **Split-safe scaling ablation:** fit a scaler on training rows only, apply it to validation/test/inference, serialize it with the candidate, then compare against the no-scaler grouped baseline.
5. **Packet/flow feature work:** `packet_feature_extractor.py` now provides a separate ten-field PCAP aggregation foundation (TTL, TCP-window, fragment, payload-size, scan fan-out, and repeated-sequence signals). It is not connected to training, live ingestion, `FEATURE_NAMES`, or the deployed 16-dimensional model. Before using it, prove each field is available in both offline training and live ingestion; then version the combined schema, add tests, update the model input dimension, retrain a separately named candidate, and update documentation and artifact metadata together.
6. **Data quality:** deduplicate near-identical flows in training only; retain provenance. Any synthetic augmentation must be separated and reported from real-data metrics.
7. **Imbalance experiments:** focal loss/class weighting only as named experiments, with class supports and per-class metrics. Sparse Discovery/Lateral Movement results remain unreliable until more data exists.
8. **Architecture experiments:** compact 1D-CNN + GRU/BiGRU, then attention pooling, then a compact transformer only after the above and a second public dataset validation. EfficientNet is not a suitable default: it is a 2D image architecture, not a natural fit for flow sequences.
9. **Forecasting maturity:** add a next-feature prediction head only when labels, evaluation horizons, and real temporal sampling semantics support it. Until then call the system a stage-distribution forecaster, not a generative world model.

## 8. Commands and validation boundaries

Do not run training merely to change code. When authorized to validate, run from repository root and save output under a new candidate stem:

```powershell
python -m unittest tests/test_attack_forecasting.py
$env:TEMPORAL_GRU_MODEL_FILENAME = 'temporal_gru_forecaster_grouped_v3.pt'
python services/forecasting_engine/train_temporal_gru.py
python services/forecasting_engine/run_full_ml_benchmark.py
Remove-Item Env:TEMPORAL_GRU_MODEL_FILENAME
```

Before trusting `run_full_ml_benchmark.py`, ensure its candidate filename matches the artifact just trained. The benchmark trains Logistic Regression and loads the GRU; it writes a model-stemmed JSON report. Capture command output separately and inspect the JSON rather than copying terminal narration.

Do **not** use `benchmark_and_rollout.py` for corrected evidence until it is converted to scenario/source-host grouping. Dynamic/end-to-end tests may require local services; do not start services unless explicitly requested.

## 9. Non-negotiable evidence rules

1. No metric, latency, model comparison, or deployment statement without a saved artifact produced by the current code.
2. No claim that an implementation exists on GitHub unless it is committed, pushed, and visible through git history or a remote URL.
3. No DNS classifier result used to substantiate a network attack forecasting claim.
4. No claims of generalization, calibration improvement, or better accuracy from a single CTU-13 run.
5. No test pass reported unless the exact command was actually run after the relevant change.
6. Clearly label historical, local-uncommitted, pending, and verified results differently.
7. If validation contradicts an earlier narrative, correct the narrative; do not preserve the attractive number.

## 10. Related documents

- `ARCHITECTURE.md` — concise judge-facing current architecture, with pending corrected benchmark table.
- `FORECASTING_CHANGE_HANDOFF.md` — earlier reframe handoff; portions referring to v2 results are superseded by this document's verification rules.
- `AI_AGENT_HANDOFF.md` — operational checklist for the next agent.
- `AGENT_HANDOFF.md` and `HANDOFF.md` — historical DNS-platform handoffs; do not overwrite.
