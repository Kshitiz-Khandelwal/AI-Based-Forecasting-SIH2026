# AI World Model for Network Attack Forecasting

**NTRO PS #26153 — AI-Based Network Attack Forecasting from Network Traffic Data**

## 1. Problem framing

The system forecasts how an observed network attack is likely to progress, rather than treating DNS filtering as the primary deliverable. It estimates a current attacker state from temporal network telemetry, projects likely future states over multiple horizons, maps those states to MITRE ATT&CK, and supplies feature-level explanations. DNS filtering is retained as a supporting telemetry and response control.

## 2. State representation

At each time step, $S_t$ is a 16-dimensional flow-level vector extracted from NetFlow/IPFIX-style records: duration, packet and byte totals, source/destination bytes, rates, average packet size, protocol flags, port categories, internal-destination status, and SYN/scan status. The model consumes a sliding window of 10 ordered flow vectors.

Packet-level extraction groundwork now exists in `services/forecasting_engine/packet_feature_extractor.py`. Its `PacketFeatureAccumulator` aggregates PCAP-supplied observations by directional 5-tuple into a separate, ten-field future schema: TTL variation; TCP-window and payload-size statistics; fragment indicators; source-port fan-out/scan indicators; and a repeated-TCP-sequence retransmission heuristic. It is intentionally separate from `temporal_feature_extractor.FEATURE_NAMES`: no packet-derived field is fed to the deployed 16-dimensional GRU, and no expanded-schema model has been trained or selected.

## 3. Transition dynamics model

`services/forecasting_engine/train_temporal_gru.py` defines a PyTorch GRU with `input_dim=16`, `hidden_dim=64`, two recurrent layers, and a seven-class softmax output. It classifies the current distribution across benign traffic plus six MITRE-aligned attack stages. Training uses chronological per-scenario partitions and class-weighted cross-entropy.

This is a discrete-state approximation of a world model: it predicts an attack-stage distribution, not a generative future raw-feature vector. Inference and perturbation explanations are implemented in `services/forecasting_engine/attack_forecaster.py`.

## 4. K-step forward simulation

The GRU softmax distribution $p$ seeds a calibrated Markov transition matrix $M$:

$$p_{15}=pM, \qquad p_{30}=pM^2, \qquad p_{60}=pM^4.$$

`services/forecasting_engine/priors.json`, produced by `calibrate_priors.py`, holds transition and dwell-time priors. Provenance identifies CTU-13 empirical calibration with **N=60,273 transitions**, while preserving warnings for sparse or unobserved stages.

## 5. MITRE ATT&CK mapping

| Model stage | MITRE ATT&CK mapping |
|---|---|
| Benign | Normal operational traffic |
| Reconnaissance | TA0043, T1595 Active Scanning |
| Initial Access | TA0001, T1566, T1568 |
| Discovery | TA0007, T1046 Network Service Discovery |
| C2 Persistence | TA0011, T1071 Application Layer Protocol |
| Lateral Movement | TA0008, T1021 Remote Services |
| Exfiltration / Impact | TA0010, T1048 |

## 6. Explainability

For each input feature $j$, the engine zeros that feature over the 10-step sequence and measures the threat-probability change:

$$\Delta_j=P(\mathrm{threat}\mid X)-P(\mathrm{threat}\mid X_{\setminus j}).$$

Features are ranked by $|\Delta_j|$. This is perturbation attribution on the GRU input, not TreeSHAP; TreeSHAP belongs to the separate DNS lexical classifier.

## 7. Baseline validation

PS #26153 requires a baseline comparison. `services/forecasting_engine/run_full_ml_benchmark.py` trains `sklearn.linear_model.LogisticRegression` on flattened 10-step temporal windows and compares it with the GRU using a chronological per-scenario CTU-13 holdout.

| Model | Weighted F1 | Precision | Recall | Benign FPR | Notes |
|---|---:|---:|---:|---:|---|
| Logistic Regression | Pending grouped rerun | — | — | — | Must be rerun with grouped-builder before comparison |
| Temporal GRU (v2, grouped) | **66.61%** | 66.23% | 70.05% | **2.33%** | Grouped Scenario+SrcAddr split; CTU-13 holdout |

Per-class support from `temporal_gru_forecaster_grouped_v2_evaluation.json` (scenario+source-host grouped holdout):

| Stage | F1 | Support | Reliability |
|---|---:|---:|---|
| STAGE_0_BENIGN | 91.82% | 4 510 | ✅ Sufficient |
| STAGE_1_RECONNAISSANCE | 0.00% | 325 | ⚠️ Feature collapse — zero precision |
| STAGE_2_INITIAL_ACCESS | 42.76% | 2 021 | ✅ Sufficient |
| STAGE_3_DISCOVERY | 0.00% | 0 | ❌ No holdout samples |
| STAGE_4_C2_PERSISTENCE | 0.00% | 315 | ⚠️ Feature collapse — zero precision |
| STAGE_5_LATERAL_MOVEMENT | 0.00% | 2 | ❌ Low sample — do not use as quality claim |
| STAGE_6_EXFILTRATION | 46.74% | 1 143 | ✅ Sufficient |

These numbers represent the **corrected** grouped-sequence evaluation (v2 candidate, not the deployed v1). The split prohibits boundary mixing between scenarios and source hosts. Discovery and Lateral Movement remain unreliable until more CTU-13 scenarios supply those stages. A Logistic Regression grouped baseline is required for a valid comparison before any model promotion.

## 8. Secondary feature — DNS filtering pipeline

The DNS pipeline supplies one telemetry path and may enforce filtering or containment. It is a supporting subsystem; the PS #26153 core is the sequence-based forecasting engine described above.

## 9. Known limitations and roadmap

- Packet-level aggregation foundation exists, but it is not yet connected to the offline training dataset, live ingestion, the deployed 16-feature extractor, or an expanded-schema retrain. Schema-versioning, availability checks, and a separately versioned candidate model are required before it can affect predictions.
- Calibration uses CTU-13 only; a second independent dataset has not been validated.
- The model is discrete-state, not a generative next-feature predictor.
- Temperature scaling, persisted per-class reports, standardization, deduplication, and clearly segregated synthetic augmentation are pending.
- A current baseline table requires a fresh benchmark and test pass before presentation.
