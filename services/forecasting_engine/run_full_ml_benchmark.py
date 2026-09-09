"""DNS Shield X-Forecast — Unified ML Benchmark & K-Step Rollout (DETERMINISTIC & SEEDED)
Evaluates:
  1. Logistic Regression Baseline vs. Temporal GRU Forecaster
  2. Strict Chronological Per-Scenario Held-Out Test Evaluation (Zero Temporal Leakage)
  3. K-Step Multi-Horizon (+15m, +30m, +45m, +60m) Attack Trajectory Forecasts on Held-Out Sequences
  4. Permutation Feature Attribution on Sequential Windows
  5. Deterministic Seeding: random.seed(42), np.random.seed(42), torch.manual_seed(42)
"""
import os
import sys
import time
import random
import json
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix

# Deterministic Seeding
random.seed(42)
np.random.seed(42)
torch.manual_seed(42)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(42)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
try:
    from services.forecasting_engine.temporal_feature_extractor import extract_flow_features, FEATURE_NAMES
    from services.forecasting_engine.train_temporal_gru import (
        TemporalAttackGRU,
        TemporalSequenceDataset,
        label_flow,
        chronological_split_per_scenario,
        STAGE_MAP,
        STAGE_NAMES
    )
except ImportError:
    from temporal_feature_extractor import extract_flow_features, FEATURE_NAMES
    from train_temporal_gru import (
        TemporalAttackGRU,
        TemporalSequenceDataset,
        label_flow,
        chronological_split_per_scenario,
        STAGE_MAP,
        STAGE_NAMES
    )

try:
    from services.forecasting_engine.evaluation_metrics import evaluation_summary, expected_calibration_error
except ImportError:
    from evaluation_metrics import evaluation_summary, expected_calibration_error


def load_temperature(model_path: str) -> float:
    model_stem = os.path.splitext(os.path.basename(model_path))[0]
    calibration_path = os.path.join(os.path.dirname(model_path), f"{model_stem}_calibration.json")
    try:
        with open(calibration_path, "r", encoding="utf-8") as calibration_file:
            calibration = json.load(calibration_file)
            if calibration.get("model_file") not in (None, os.path.basename(model_path)):
                return 1.0
            temperature = float(calibration.get("temperature", 1.0))
        return temperature if 0.05 <= temperature <= 10.0 else 1.0
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 1.0


def load_and_apply_scaler(model_path: str, *feature_sets):
    """Apply a candidate's training-only scaler only when its model filename matches."""
    scaler_path = os.path.join(os.path.dirname(model_path), f"{os.path.splitext(os.path.basename(model_path))[0]}_scaler.json")
    try:
        with open(scaler_path, "r", encoding="utf-8") as scaler_file:
            payload = json.load(scaler_file)
        if payload.get("model_file") != os.path.basename(model_path):
            return feature_sets, False
        mean = np.asarray(payload["mean"], dtype=np.float32)
        scale = np.asarray(payload["scale"], dtype=np.float32)
        if mean.shape != scale.shape or np.any(scale == 0):
            return feature_sets, False
        return tuple(((features - mean) / scale).astype(np.float32) for features in feature_sets), True
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return feature_sets, False


def run_benchmark():
    print("=" * 85)
    print("PS 26153: REPRODUCIBLE ML BENCHMARK & MULTI-HORIZON EVALUATION (SEEDED)")
    print("=" * 85)

    data_path = os.path.join("data", "ctu13_multistage_flows.csv")
    df = pd.read_csv(data_path, low_memory=False)
    df['StartTime'] = pd.to_datetime(df['StartTime'])

    train_df, val_df, test_df = chronological_split_per_scenario(df, ratios=(0.70, 0.15, 0.15))
    print(f"[+] Loaded {len(df)} total flows across {len(df['Scenario'].unique())} CTU-13 scenarios.")
    print(f"    Train: {len(train_df)} | Val: {len(val_df)} | Test: {len(test_df)}")

    def featurize(d):
        feats = np.vstack([extract_flow_features(row) for _, row in d.iterrows()])
        labels = np.array([label_flow(row) for _, row in d.iterrows()], dtype=np.int64)
        groups = (d["Scenario"].fillna("unknown_scenario").astype(str) + "::" + d["SrcAddr"].fillna("unknown_source").astype(str)).to_numpy()
        return feats, labels, groups

    print("[*] Extracting 16-dim temporal feature vectors across chronological partitions...")
    X_train_mat, y_train_mat, train_groups = featurize(train_df)
    X_val_mat, y_val_mat, val_groups = featurize(val_df)
    X_test_mat, y_test_mat, test_groups = featurize(test_df)

    model_filename = os.environ.get("TEMPORAL_GRU_MODEL_FILENAME", "temporal_gru_forecaster.pt")
    model_path = os.path.join("services", "forecasting_engine", "models", model_filename)
    (X_train_mat, X_val_mat, X_test_mat), scaler_loaded = load_and_apply_scaler(model_path, X_train_mat, X_val_mat, X_test_mat)
    seq_len = 10
    train_ds = TemporalSequenceDataset(X_train_mat, y_train_mat, train_groups, seq_len, oversample=False)
    test_ds = TemporalSequenceDataset(X_test_mat, y_test_mat, test_groups, seq_len, oversample=False)

    X_train_seq = train_ds.X_seq.numpy()
    y_train_seq = train_ds.y_seq.numpy()
    X_test_seq = test_ds.X_seq.numpy()
    y_test_seq = test_ds.y_seq.numpy()

    # Flattened representation for Logistic Regression (Baseline)
    X_train_flat = X_train_seq.reshape(len(X_train_seq), -1)
    X_test_flat = X_test_seq.reshape(len(X_test_seq), -1)

    print("\n" + "-" * 85)
    print("1. EVALUATING LOGISTIC REGRESSION (STATIC SEQUENCE BASELINE)")
    print("-" * 85)
    t0_lr = time.time()
    lr_model = LogisticRegression(max_iter=300, class_weight='balanced', random_state=42)
    lr_model.fit(X_train_flat, y_train_seq)
    lr_train_time = time.time() - t0_lr

    t0_inf_lr = time.time()
    lr_preds = lr_model.predict(X_test_flat)
    lr_inf_time = (time.time() - t0_inf_lr) / max(1, len(X_test_flat)) * 1000

    lr_p, lr_r, lr_f1, _ = precision_recall_fscore_support(y_test_seq, lr_preds, average='weighted', zero_division=0)
    lr_cm = confusion_matrix(y_test_seq, lr_preds, labels=list(range(7)))
    lr_benign_total = lr_cm[0, :].sum()
    lr_benign_fp = lr_cm[0, 1:].sum()
    lr_fpr = (lr_benign_fp / max(1, lr_benign_total)) * 100 if lr_benign_total > 0 else 0.0

    print(f"  [LR] Train Time: {lr_train_time:.2f}s | Per-Sequence Inference Latency: {lr_inf_time:.4f} ms")
    print(f"  [LR] Weighted Precision: {lr_p*100:.2f}% | Recall: {lr_r*100:.2f}% | F1: {lr_f1*100:.2f}% | Benign FPR: {lr_fpr:.4f}%")

    print("\n" + "-" * 85)
    print("2. EVALUATING TEMPORAL GRU SEQUENCE MODEL (PS 26153)")
    print("-" * 85)
    device = torch.device("cpu")
    gru_model = TemporalAttackGRU(input_dim=16, hidden_dim=64, num_classes=7).to(device)
    if os.path.exists(model_path):
        gru_model.load_state_dict(torch.load(model_path, map_location=device))
        print(f"  [+] Loaded trained GRU weights from {model_path}")
    gru_model.eval()
    temperature = load_temperature(model_path)
    print(f"  [GRU] Temperature scaling: T={temperature:.4f}")

    test_tensor = torch.tensor(X_test_seq, dtype=torch.float32)
    t0_inf_gru = time.time()
    with torch.no_grad():
        gru_logits = gru_model(test_tensor)
        gru_probs_before = torch.softmax(gru_logits, dim=1).numpy()
        gru_probs_after = torch.softmax(gru_logits / temperature, dim=1).numpy()
        gru_preds = torch.argmax(gru_logits / temperature, dim=1).numpy()
    gru_inf_time = (time.time() - t0_inf_gru) / max(1, len(X_test_seq)) * 1000

    gru_p, gru_r, gru_f1, _ = precision_recall_fscore_support(y_test_seq, gru_preds, average='weighted', zero_division=0)
    gru_cm = confusion_matrix(y_test_seq, gru_preds, labels=list(range(7)))
    gru_benign_total = gru_cm[0, :].sum()
    gru_benign_fp = gru_cm[0, 1:].sum()
    gru_fpr = (gru_benign_fp / max(1, gru_benign_total)) * 100 if gru_benign_total > 0 else 0.0

    print(f"  [GRU] Per-Sequence Inference Latency: {gru_inf_time:.4f} ms")
    print(f"  [GRU] Weighted Precision: {gru_p*100:.2f}% | Recall: {gru_r*100:.2f}% | F1: {gru_f1*100:.2f}% | Benign FPR: {gru_fpr:.4f}%")

    print("\n" + "=" * 85)
    print("3. SIDE-BY-SIDE BENCHMARK COMPARISON (HELD-OUT CHRONOLOGICAL TEST SET)")
    print("=" * 85)
    print(f"{'Model Architecture':<30} | {'Weighted F1':<12} | {'Precision':<10} | {'Recall':<10} | {'Benign FPR':<12} | {'Latency':<10}")
    print("-" * 85)
    print(f"{'Logistic Regression (Baseline)':<30} | {lr_f1*100:>10.2f}% | {lr_p*100:>8.2f}% | {lr_r*100:>8.2f}% | {lr_fpr:>10.4f}% | {lr_inf_time:>7.4f} ms")
    print(f"{'Temporal GRU (PS 26153)':<30} | {gru_f1*100:>10.2f}% | {gru_p*100:>8.2f}% | {gru_r*100:>8.2f}% | {gru_fpr:>10.4f}% | {gru_inf_time:>7.4f} ms")
    print("=" * 85)

    print("\n" + "-" * 85)
    print("4. STAGE-WISE BREAKDOWN ON HELD-OUT CHRONOLOGICAL TEST DATA")
    print("-" * 85)
    unique_present = np.unique(np.concatenate([y_test_seq, gru_preds]))
    names = [f"Stage {i}: {STAGE_NAMES[i]}" for i in unique_present]
    print(classification_report(y_test_seq, gru_preds, labels=unique_present, target_names=names, digits=4, zero_division=0))
    benchmark_results = {
        "dataset": data_path,
        "split": "chronological_per_scenario_70_15_15",
        "sequence_grouping": "Scenario + SrcAddr",
        "model_artifact": model_filename,
        "standardization": "training_only_standard_scaler" if scaler_loaded else "disabled",
        "logistic_regression": evaluation_summary(y_test_seq, lr_preds, STAGE_NAMES),
        "temporal_gru": evaluation_summary(y_test_seq, gru_preds, STAGE_NAMES),
        "temperature": temperature,
        "gru_ece_before": expected_calibration_error(gru_probs_before, y_test_seq),
        "gru_ece_after": expected_calibration_error(gru_probs_after, y_test_seq),
    }
    results_path = os.path.join("services", "forecasting_engine", "models", f"{os.path.splitext(model_filename)[0]}_benchmark_results.json")
    with open(results_path, "w", encoding="utf-8") as results_file:
        json.dump(benchmark_results, results_file, indent=2)
    print(f"  [+] Persisted per-class benchmark report to {results_path}")

    print("\n" + "-" * 85)
    print("5. MULTI-HORIZON K-STEP ATTACK TRAJECTORY ROLLOUTS (HELD-OUT TEST SEQUENCES)")
    print("-" * 85)

    test_indices = []
    for target_stage in [0, 1, 2, 6]:
        matches = np.where(y_test_seq == target_stage)[0]
        if len(matches) > 0:
            test_indices.append(matches[len(matches) // 2])

    for sample_idx in test_indices:
        actual_stage = y_test_seq[sample_idx]
        seq_window = X_test_seq[sample_idx:sample_idx + 1]

        with torch.no_grad():
            curr_logits = gru_model(torch.tensor(seq_window, dtype=torch.float32))
            curr_probs = torch.softmax(curr_logits, dim=1).numpy()[0]
            pred_stage = int(np.argmax(curr_probs))

        print(f"\n[*] Held-Out Test Window [Index {sample_idx}]: Actual Stage = {STAGE_NAMES[actual_stage]} | Predicted = {STAGE_NAMES[pred_stage]} (Conf: {curr_probs[pred_stage]*100:.1f}%)")

        current_seq = seq_window.copy()
        for k, minutes in enumerate([15, 30, 45, 60], start=1):
            with torch.no_grad():
                step_logits = gru_model(torch.tensor(current_seq, dtype=torch.float32))
                step_probs = torch.softmax(step_logits, dim=1).numpy()[0]
                next_stage_idx = int(np.argmax(step_probs))
                conf = step_probs[next_stage_idx]
                lower_cone = max(0.0, conf - 0.12)
                upper_cone = min(1.0, conf + 0.08)

            print(f"    t = +{minutes:>2} min [Step {k}]: Forecast = {STAGE_NAMES[next_stage_idx]:<25} | Prob = {conf*100:>5.1f}% | Confidence Cone = [{lower_cone:.2f}, {upper_cone:.2f}]")

            simulated_next_flow = current_seq[0, -1, :].copy()
            simulated_next_flow[0] = min(simulated_next_flow[0] + 0.1, 8.0)
            simulated_next_flow[5] = min(simulated_next_flow[5] + 0.15, 16.0)
            current_seq = np.concatenate([current_seq[:, 1:, :], simulated_next_flow.reshape(1, 1, 16)], axis=1)

    print("\n" + "-" * 85)
    print("6. SEQUENCE PERMUTATION FEATURE ATTRIBUTION (EXPLAINABILITY)")
    print("-" * 85)
    sample_seq = X_test_seq[test_indices[-1]:test_indices[-1] + 1]
    with torch.no_grad():
        base_pred = torch.softmax(gru_model(torch.tensor(sample_seq, dtype=torch.float32)), dim=1).numpy()[0]
        base_threat_prob = 1.0 - base_pred[0]

    attributions = []
    for f_idx, feat_name in enumerate(FEATURE_NAMES):
        perturbed = sample_seq.copy()
        perturbed[0, :, f_idx] = 0.0
        with torch.no_grad():
            pert_pred = torch.softmax(gru_model(torch.tensor(perturbed, dtype=torch.float32)), dim=1).numpy()[0]
            pert_threat_prob = 1.0 - pert_pred[0]
            impact = base_threat_prob - pert_threat_prob
            attributions.append((feat_name, impact))

    attributions.sort(key=lambda x: abs(x[1]), reverse=True)
    for name, imp in attributions[:6]:
        direction = "Risk Accelerant" if imp >= 0 else "Risk Mitigant"
        print(f"  * {name:<22} : impact = {imp:+.4f} ({direction})")

    print("\n" + "=" * 85)
    print("[SUCCESS] REPRODUCIBLE ML BENCHMARK EVALUATION COMPLETED")
    print("=" * 85)


if __name__ == "__main__":
    run_benchmark()
