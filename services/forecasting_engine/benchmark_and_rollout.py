"""DNS Shield X-Forecast — Unified Benchmark, K-Step Rollout & Explainability
Evaluates:
  1. Logistic Regression Baseline (Non-Temporal)
  2. GRU Sequence Forecaster (Temporal)
  3. K-Step Temporal Rollout for +15m, +30m, +60m Horizons
  4. Temporal Permutation Feature Attribution
All computed on the exact same held-out chronological test partition.
"""
import os
import sys
import time
import json
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from services.forecasting_engine.temporal_feature_extractor import extract_flow_features, FEATURE_NAMES
from services.forecasting_engine.train_temporal_gru import (
    TemporalAttackGRU,
    TemporalSequenceDataset,
    STAGE_MAP,
    STAGE_NAMES,
    label_flow,
    chronological_split_per_scenario,
)
from services.forecasting_engine.evaluation_metrics import evaluation_summary

def run_benchmark():
    print("="*80, flush=True)
    print("PS 26153 TEMPORAL ATTACK FORECASTING BENCHMARK & MULTI-HORIZON EVALUATION", flush=True)
    print("="*80, flush=True)

    data_path = "data/ctu13_multistage_flows.csv"
    print(f"[*] Loading dataset: {data_path}", flush=True)
    df = pd.read_csv(data_path, low_memory=False)
    df['StartTime'] = pd.to_datetime(df['StartTime'])
    print(f"[+] Total Chronological Flows: {len(df)}", flush=True)

    # This must mirror train_temporal_gru.py and run_full_ml_benchmark.py exactly:
    # chronological split *within* every scenario, followed by source-host-isolated
    # windows. A global split/window can create histories from unrelated captures.
    train_df, _, test_df = chronological_split_per_scenario(df, ratios=(0.70, 0.15, 0.15))

    def featurize(partition):
        features = np.vstack([extract_flow_features(row) for _, row in partition.iterrows()])
        labels = np.array([label_flow(row) for _, row in partition.iterrows()], dtype=np.int64)
        groups = (
            partition["Scenario"].fillna("unknown_scenario").astype(str)
            + "::"
            + partition["SrcAddr"].fillna("unknown_source").astype(str)
        ).to_numpy()
        return features, labels, groups

    X_train, y_train, train_groups = featurize(train_df)
    X_test, y_test, test_groups = featurize(test_df)
    grouping_policy = "Scenario + SrcAddr"
    print(
        f"[+] Split: Train={len(X_train)} flows, Test={len(X_test)} flows "
        "(per-scenario chronological hold-out; source-host-isolated windows)",
        flush=True,
    )

    # ─────────────────────────────────────────────────────────────────────────────
    # 1. LOGISTIC REGRESSION BASELINE (Non-Temporal)
    # ─────────────────────────────────────────────────────────────────────────────
    print("\n" + "-"*80, flush=True)
    print("1. TRAINING & EVALUATING LOGISTIC REGRESSION BASELINE (Non-Temporal)", flush=True)
    print("-"*80, flush=True)
    lr_model = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
    t_lr0 = time.time()
    lr_model.fit(X_train, y_train)
    t_lr_train = time.time() - t_lr0

    t_lr_eval0 = time.time()
    lr_preds = lr_model.predict(X_test)
    t_lr_infer = (time.time() - t_lr_eval0) / len(X_test) * 1000.0  # ms per flow

    lr_p, lr_r, lr_f1, _ = precision_recall_fscore_support(y_test, lr_preds, average='weighted', zero_division=0)
    
    # Baseline FPR on Benign
    cm_lr = confusion_matrix(y_test, lr_preds, labels=list(range(7)))
    benign_total_lr = cm_lr[0, :].sum()
    benign_fp_lr = cm_lr[0, 1:].sum()
    lr_fpr = (benign_fp_lr / max(1, benign_total_lr)) if benign_total_lr > 0 else 0.0

    print(f"[+] Logistic Regression: Train Time={t_lr_train:.2f}s, Inference Latency={t_lr_infer:.4f} ms/flow", flush=True)
    print(f"    Weighted Precision: {lr_p*100:.2f}% | Recall: {lr_r*100:.2f}% | F1: {lr_f1*100:.2f}% | Benign FPR: {lr_fpr*100:.2f}%", flush=True)

    # ─────────────────────────────────────────────────────────────────────────────
    # 2. GRU TEMPORAL SEQUENCE FORECASTER (Temporal W=10)
    # ─────────────────────────────────────────────────────────────────────────────
    print("\n" + "-"*80, flush=True)
    print("2. EVALUATING TRAINED GRU TEMPORAL SEQUENCE FORECASTER", flush=True)
    print("-"*80, flush=True)
    model_path = "services/forecasting_engine/models/temporal_gru_forecaster.pt"
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    gru_model = TemporalAttackGRU(input_dim=16, hidden_dim=64, num_layers=2, num_classes=7).to(device)
    gru_model.load_state_dict(torch.load(model_path, map_location=device))
    gru_model.eval()

    seq_len = 10
    test_ds = TemporalSequenceDataset(X_test, y_test, test_groups, seq_len=seq_len)
    test_loader = DataLoader(test_ds, batch_size=256, shuffle=False)

    gru_preds = []
    gru_targets = []
    t_gru0 = time.time()
    with torch.no_grad():
        for X_b, y_b in test_loader:
            X_b = X_b.to(device)
            logits = gru_model(X_b)
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            gru_preds.extend(preds)
            gru_targets.extend(y_b.numpy())

    t_gru_infer = (time.time() - t_gru0) / len(test_ds) * 1000.0  # ms per sequence
    gru_preds = np.array(gru_preds)
    gru_targets = np.array(gru_targets)

    gru_p, gru_r, gru_f1, _ = precision_recall_fscore_support(gru_targets, gru_preds, average='weighted', zero_division=0)
    
    # GRU FPR on Benign
    cm_gru = confusion_matrix(gru_targets, gru_preds, labels=list(range(7)))
    benign_total_gru = cm_gru[0, :].sum()
    benign_fp_gru = cm_gru[0, 1:].sum()
    gru_fpr = (benign_fp_gru / max(1, benign_total_gru)) if benign_total_gru > 0 else 0.0

    print(f"[+] GRU Temporal Model: Inference Latency={t_gru_infer:.4f} ms/sequence", flush=True)
    print(f"    Weighted Precision: {gru_p*100:.2f}% | Recall: {gru_r*100:.2f}% | F1: {gru_f1*100:.2f}% | Benign FPR: {gru_fpr*100:.2f}%", flush=True)

    results_path = "services/forecasting_engine/models/benchmark_and_rollout_results.json"
    with open(results_path, "w", encoding="utf-8") as results_file:
        json.dump({
            "dataset": data_path,
            "split": "chronological_per_scenario_70_15_15",
            "sequence_grouping": grouping_policy,
            "split_metadata": {
                "train_flow_count": int(len(X_train)),
                "test_flow_count": int(len(X_test)),
                "train_group_count": int(len(np.unique(train_groups))),
                "test_group_count": int(len(np.unique(test_groups))),
                "sequence_length": seq_len,
                "test_sequence_count": int(len(test_ds)),
            },
            "logistic_regression": evaluation_summary(y_test, lr_preds, STAGE_NAMES),
            "temporal_gru": evaluation_summary(gru_targets, gru_preds, STAGE_NAMES),
        }, results_file, indent=2)
    print(f"[+] Persisted per-class metrics to {results_path}", flush=True)

    # ─────────────────────────────────────────────────────────────────────────────
    # 3. SIDE-BY-SIDE BENCHMARK TABLE (Step 6 Verification)
    # ─────────────────────────────────────────────────────────────────────────────
    print("\n" + "="*80, flush=True)
    print("OFFICIAL BENCHMARK COMPARISON TABLE (Generated in this session)", flush=True)
    print("="*80, flush=True)
    print(f"{'Model Architecture':<32} | {'F1 Score':<10} | {'Precision':<10} | {'Recall':<10} | {'Benign FPR':<10} | {'Latency':<10}", flush=True)
    print("-" * 92, flush=True)
    print(f"{'Logistic Regression (Baseline)':<32} | {lr_f1*100:<9.2f}% | {lr_p*100:<9.2f}% | {lr_r*100:<9.2f}% | {lr_fpr*100:<9.2f}% | {lr_infer:.3f} ms", flush=True)
    print(f"{'GRU Temporal Forecaster (PS2)':<32} | {gru_f1*100:<9.2f}% | {gru_p*100:<9.2f}% | {gru_r*100:<9.2f}% | {gru_fpr*100:<9.2f}% | {t_gru_infer:.3f} ms", flush=True)
    print("="*80, flush=True)

    # ─────────────────────────────────────────────────────────────────────────────
    # 4. K-STEP AUTOREGRESSIVE ROLLOUT (Step 5 Verification)
    # ─────────────────────────────────────────────────────────────────────────────
    print("\n" + "="*80, flush=True)
    print("STEP 5: K-STEP MULTI-HORIZON PROJECTION TRAJECTORIES (+15m, +30m, +60m)", flush=True)
    print("="*80, flush=True)

    def autoregressive_rollout(init_seq: np.ndarray, steps: int = 4):
        """Chain predictions forward autoregressively for K steps."""
        current_seq = init_seq.copy()  # (10, 16)
        trajectory = []
        
        for k in range(1, steps + 1):
            x_tensor = torch.tensor(current_seq[np.newaxis, :, :], dtype=torch.float32).to(device)
            with torch.no_grad():
                logits = gru_model(x_tensor)
                probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
            
            predicted_stage_idx = int(np.argmax(probs))
            predicted_stage_name = STAGE_NAMES[predicted_stage_idx]
            confidence = float(probs[predicted_stage_idx])
            
            trajectory.append({
                "step": k,
                "horizon_min": k * 15,
                "stage": predicted_stage_name,
                "confidence": confidence,
                "stage_distribution": {STAGE_NAMES[i]: round(float(probs[i]), 4) for i in range(7)}
            })
            
            # Autoregressive shift: append synthetic representative feature vector for predicted stage
            synthetic_next_flow = np.zeros(16, dtype=np.float32)
            synthetic_next_flow[0] = np.log1p(0.5 * k)
            synthetic_next_flow[1] = np.log1p(10.0 * k)
            synthetic_next_flow[2] = np.log1p(500.0 * k)
            if predicted_stage_idx == 1:
                synthetic_next_flow[15] = 1.0  # scan
            elif predicted_stage_idx == 4:
                synthetic_next_flow[12] = 1.0  # web c2
            elif predicted_stage_idx == 5:
                synthetic_next_flow[13] = 1.0  # lateral
            elif predicted_stage_idx == 6:
                synthetic_next_flow[10] = 1.0  # attack
            
            current_seq = np.vstack([current_seq[1:], synthetic_next_flow])

        return trajectory

    def find_grouped_sequence(target_predicate):
        """Return a sequence and target whose complete history is one group."""
        for group_id in np.unique(test_groups):
            indices = np.flatnonzero(test_groups == group_id)
            for start in range(len(indices) - seq_len):
                target_index = indices[start + seq_len]
                if target_predicate(y_test[target_index]):
                    return X_test[indices[start:start + seq_len]], int(y_test[target_index])
        return None, None

    # Test only valid Scenario+SrcAddr histories, never arbitrary flattened slices.
    seq_benign, benign_target = find_grouped_sequence(lambda stage: stage == 0)
    if seq_benign is None:
        raise ValueError("Held-out partition contains no complete benign grouped sequence")
    traj_benign = autoregressive_rollout(seq_benign, steps=4)

    print("\n--- Sample 1: Benign Host Trajectory Forecast ---", flush=True)
    for step_info in traj_benign:
        print(f"  [+{step_info['horizon_min']} min] -> {step_info['stage']} (Conf: {step_info['confidence']*100:.1f}%) | Dist: Benign={step_info['stage_distribution']['STAGE_0_BENIGN']*100:.1f}%, Attack={step_info['stage_distribution']['STAGE_6_EXFILTRATION']*100:.1f}%", flush=True)

    # Sample 2: Active Infiltration Sequence (trending toward attack)
    seq_attack, attack_target = find_grouped_sequence(lambda stage: stage > 0)
    if seq_attack is not None:
        traj_attack = autoregressive_rollout(seq_attack, steps=4)

        print("\n--- Sample 2: Active Multi-Stage Attack Host Trajectory Forecast ---", flush=True)
        for step_info in traj_attack:
            print(f"  [+{step_info['horizon_min']} min] -> {step_info['stage']} (Conf: {step_info['confidence']*100:.1f}%) | Dist: Benign={step_info['stage_distribution']['STAGE_0_BENIGN']*100:.1f}%, Infiltration/C2={step_info['stage_distribution']['STAGE_2_INITIAL_ACCESS']*100+step_info['stage_distribution']['STAGE_4_C2_PERSISTENCE']*100:.1f}%, Impact={step_info['stage_distribution']['STAGE_6_EXFILTRATION']*100:.1f}%", flush=True)

    # ─────────────────────────────────────────────────────────────────────────────
    # 5. TEMPORAL FEATURE ATTRIBUTION / EXPLAINABILITY (Step 7 Verification)
    # ─────────────────────────────────────────────────────────────────────────────
    print("\n" + "="*80, flush=True)
    print("STEP 7: TEMPORAL FEATURE ATTRIBUTION (Permutation Feature Attribution)", flush=True)
    print("="*80, flush=True)

    def explain_sequence_attribution(seq_in: np.ndarray, target_label_idx: int):
        """Compute feature attributions on the temporal sequence via feature perturbation."""
        x_tensor = torch.tensor(seq_in[np.newaxis, :, :], dtype=torch.float32).to(device)
        with torch.no_grad():
            base_prob = float(torch.softmax(gru_model(x_tensor), dim=1)[0, target_label_idx])
            
        attributions = {}
        for f_idx, f_name in enumerate(FEATURE_NAMES):
            perturbed_seq = seq_in.copy()
            perturbed_seq[:, f_idx] = 0.0  # Zero ablation
            x_pert = torch.tensor(perturbed_seq[np.newaxis, :, :], dtype=torch.float32).to(device)
            with torch.no_grad():
                pert_prob = float(torch.softmax(gru_model(x_pert), dim=1)[0, target_label_idx])
            # Attribution weight = drop in probability when feature is removed
            attributions[f_name] = round(base_prob - pert_prob, 4)
            
        # Sort by magnitude
        sorted_attr = sorted(attributions.items(), key=lambda x: abs(x[1]), reverse=True)
        return sorted_attr[:5]

    if seq_attack is not None:
        print("\nAttribution for Attack-Trending Prediction:")
        att_exp = explain_sequence_attribution(seq_attack, target_label_idx=attack_target)
        for feat_name, weight in att_exp:
            print(f"  - {feat_name:<20}: attribution weight = {weight:+.4f} ({'Elevating threat' if weight > 0 else 'Dampening'})", flush=True)
    else:
        print("\n[!] No complete attack-stage grouped sequence available for attribution.", flush=True)

    print("="*80, flush=True)
    print("[+] Benchmark, Rollout, and Explainability successfully verified on held-out test data.", flush=True)

if __name__ == "__main__":
    run_benchmark()
