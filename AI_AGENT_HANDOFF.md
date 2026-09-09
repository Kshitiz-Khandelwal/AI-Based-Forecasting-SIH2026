# AI Agent Handoff — Forecasting Correctness and Model-Quality Work

## Start here

Read `PROJECT_CONTEXT.md` first. This handoff is intentionally strict because prior reporting mixed local experiments, historical documents, and GitHub-confirmed work. The immediate objective is to produce a **reproducible, grouped-sequence forecasting baseline** before adding model complexity.

## Current handoff status

| Area | Status | Evidence boundary |
|---|---|---|
| Forecasting-first UI/docs reframe | Local modified working tree | Review diffs before commit; it is not on GitHub yet. |
| Seven-stage GRU / CTU-13 pipeline | Present in repository | Existing v1 artifact is tracked; quality claims must be rerun. |
| Grouped sequence builder | Local implementation added | Must be reviewed, unit-tested, committed, then used in all benchmark paths. |
| Boundary regression test | Local implementation added | `tests/test_attack_forecasting.py`; run it only when validation is authorized. |
| Per-class reporting / evaluation helper | Local implementation added | Do not call it verified until committed and exercised in a saved run. |
| Temperature scaling / v2 artifacts | Local uncommitted experimental files | Not deployable evidence; never narrate old results as settled. |
| Fresh, corrected benchmark | Not yet accepted | Required before any performance claim or candidate promotion. |
| Packet-feature foundation | Local implementation added | `packet_feature_extractor.py` aggregates ten PCAP-derived fields separately; it is not wired into training, live ingestion, `FEATURE_NAMES`, or the deployed 16-dimensional GRU. |
| Scaler/focal loss/CNN/attention/transformer | Not implemented as an accepted change | Follow the sequence below. |

## The bug that must stay fixed

`TemporalSequenceDataset` previously took a flattened feature array and made adjacent windows. After per-scenario pieces were concatenated, adjacency no longer meant the same scenario or source host. The local change groups rows by `Scenario + SrcAddr` and only makes windows within a group.

Guardrails:

- All train, validation, test, and baseline windows must use the same grouping definition.
- Keep order within each group chronological. Do not rely on `np.unique` ordering alone to create temporal order; source data must already be sorted appropriately.
- A group with `n` rows yields `max(0, n - seq_len)` targets under the present next-row target convention.
- Handle the no-complete-window case explicitly; do not silently fall back to global sequences.
- Update or prohibit `benchmark_and_rollout.py`, which still has incompatible global-split behavior.

## First task batch — safe to implement without retraining

1. Inspect grouped-window call sites in `train_temporal_gru.py` and `run_full_ml_benchmark.py`.
2. Refactor a shared group-aware featurization/splitting helper only if it reduces drift without changing semantics; add focused tests for group boundaries, ordering, mismatched group lengths, and groups shorter than `seq_len + 1`.
3. Bring `benchmark_and_rollout.py` into conformance or add an unmistakable runtime warning/retirement note and remove it from any official command/documentation.
4. Ensure every result writer records: artifact filename, input feature names/count, dataset identifier/hash, commit SHA, seed, split ratios, group key, sequence length, training command, timestamp, and library versions. Do not invent metadata—derive it programmatically.
5. Update the model/architecture UI only to show `Pending corrected grouped benchmark` until a saved reviewed result exists.
6. Review historical docs for any active page that exposes stale forecasting numbers; change only the active judge-facing surfaces, preserving historical records with a clear status label.

Avoid retraining, changing the deployed v1 artifact, generating synthetic data, or claiming results in this batch.

## Second task batch — only after Batch 1 is committed and authorized

Create a named candidate without changing v1:

```powershell
$env:TEMPORAL_GRU_MODEL_FILENAME = 'temporal_gru_forecaster_grouped_v3.pt'
python services/forecasting_engine/train_temporal_gru.py
python services/forecasting_engine/run_full_ml_benchmark.py
Remove-Item Env:TEMPORAL_GRU_MODEL_FILENAME
```

Run before/after focused tests:

```powershell
python -m unittest tests/test_attack_forecasting.py
```

Required review of the generated JSON:

- Verify candidate model name and calibration JSON refer to the same filename.
- Verify `sequence_grouping` is `Scenario + SrcAddr`.
- Verify all per-class supports are present; label supports below 20 unreliable.
- Compare Logistic Regression and GRU on exactly the same held-out grouped sequences.
- Report weighted and macro F1, benign FPR, per-class precision/recall/F1/support, ECE before/after calibration, and inference latency.
- Add the resulting command, commit, dataset fingerprint, and metrics to a committed Markdown report. If a metric regresses, record it plainly.

## Subsequent implementation queue

### A. Split-safe preprocessing

Add a `StandardScaler` or comparable transform fitted only on raw training rows. Serialize it as a candidate companion artifact; apply it in validation/test and inference. Make an ablation result mandatory before retaining it.

### B. Feature quality

`packet_feature_extractor.py` is a starting point, not a model-input change. It aggregates a separate ten-field schema from caller-supplied PCAP observations: TTL variation, TCP-window and payload-size statistics, fragments, source-port fan-out/scan indicators, and a repeated-TCP-sequence retransmission heuristic. It does not parse PCAP files itself, and it is not currently invoked by the training or deployed inference path.

Add packet/flow features only when data is available in both offline training and live ingestion. Candidate classes:

- packet-size distribution and burst statistics;
- TTL and inter-arrival variability;
- TCP window/flag/retransmission indicators;
- fragmentation flags;
- scan sequencing/fan-out indicators.

Version extractor schema and model input dimension. A model trained on a changed feature schema must never be loaded with the old extractor. Keep the present 16-dimensional GRU and its extractor untouched while an expanded-schema candidate is built and evaluated.

### C. Imbalance and data quality

Deduplicate near-identical training flows without touching held-out data. Keep sample provenance. Test focal loss and/or controlled oversampling only as isolated candidates. Never hide sparse-stage support behind weighted averages.

### D. Architectures

After A–C and a second public dataset, compare a small 1D-CNN + GRU/BiGRU, then attention pooling, then a compact transformer. Maintain a fixed baseline and fixed evaluation protocol. Do not use EfficientNet for one-dimensional flow telemetry absent a justified transformation and ablation.

### E. True forecasting

The current rollout is a stage-distribution projection with priors. A future-feature or next-state head needs its own target construction, horizon definition, and held-out forecasting metrics. Do not call it a generative world model until then.

## Git and deliverable discipline

Before reporting progress:

```powershell
git status --short
git diff --check
git diff -- services/forecasting_engine/train_temporal_gru.py services/forecasting_engine/run_full_ml_benchmark.py tests/test_attack_forecasting.py
git ls-files services/forecasting_engine/models
git branch -vv
```

Do not add large model binaries or transient logs blindly. Decide and document whether artifacts belong in Git LFS, a release store, or an ignored reproducible-artifact location. At minimum, commit source changes, tests, schema/version metadata, and a concise results JSON/Markdown report that can be regenerated. Do not say “saved in GitHub” until commit and push both succeed.

## Definition of done for the immediate milestone

The milestone is complete only when:

- every official temporal window builder is scenario/source-host-safe;
- focused regression tests pass from a clean checkout;
- a named candidate is trained without overwriting v1;
- Logistic Regression and candidate GRU are evaluated on the same grouped held-out sequences;
- results are saved with reproducibility metadata and per-class support;
- presentation/UI claims match those saved results and label limitations;
- source/tests/docs/results are committed and pushed, or the handoff explicitly says they are local only.

## Honesty rules

Never optimize the story at the cost of truth. A lower score after a correctness fix is useful information. A test that was not run is pending. A local artifact is local. A DNS result is not a forecasting result. A small class support is not a reliable class metric.
