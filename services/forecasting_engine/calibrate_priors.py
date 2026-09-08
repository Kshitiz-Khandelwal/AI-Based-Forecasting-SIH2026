"""DNS Shield X-Forecast — Empirical Prior Calibration Script
Calibrates the 7x7 Markov State Transition Matrix and Stage Dwell Times
from the real CTU-13 multi-stage botnet traffic dataset (data/ctu13_multistage_flows.csv).

Explicitly distinguishes:
  - High-Confidence Empirical (N >= 20 observed transitions)
  - Low-Confidence / Inherited Expert Prior (N < 20 observed transitions)

Outputs: services/forecasting_engine/priors.json
"""
import os
import sys
import json
import datetime
import numpy as np
import pandas as pd

# Path setup
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(ROOT, "data", "ctu13_multistage_flows.csv")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "priors.json")

sys.path.insert(0, os.path.join(ROOT, "services", "forecasting_engine"))
from train_temporal_gru import label_flow, STAGE_NAMES

# Baseline domain-expert priors (used for smoothing and low-sample fallback)
EXPERT_TRANSITION_MATRIX = {
    "STAGE_0_BENIGN": {"STAGE_0_BENIGN": 0.85, "STAGE_1_RECONNAISSANCE": 0.15},
    "STAGE_1_RECONNAISSANCE": {"STAGE_1_RECONNAISSANCE": 0.20, "STAGE_2_INITIAL_ACCESS": 0.65, "STAGE_0_BENIGN": 0.15},
    "STAGE_2_INITIAL_ACCESS": {"STAGE_2_INITIAL_ACCESS": 0.25, "STAGE_3_DISCOVERY": 0.40, "STAGE_4_C2_PERSISTENCE": 0.35},
    "STAGE_3_DISCOVERY": {"STAGE_3_DISCOVERY": 0.20, "STAGE_4_C2_PERSISTENCE": 0.45, "STAGE_5_LATERAL_MOVEMENT": 0.35},
    "STAGE_4_C2_PERSISTENCE": {"STAGE_4_C2_PERSISTENCE": 0.20, "STAGE_5_LATERAL_MOVEMENT": 0.40, "STAGE_6_EXFILTRATION": 0.40},
    "STAGE_5_LATERAL_MOVEMENT": {"STAGE_5_LATERAL_MOVEMENT": 0.10, "STAGE_6_EXFILTRATION": 0.90},
    "STAGE_6_EXFILTRATION": {"STAGE_6_EXFILTRATION": 0.95, "STAGE_0_BENIGN": 0.05}
}

EXPERT_STAGE_DURATIONS = [0.0, 10.0, 15.0, 12.0, 18.0, 22.0, 0.0]


def calibrate_priors():
    print("=" * 80)
    print("  DNS SHIELD: EMPIRICAL CALIBRATION OF MARKOV PRIORS & DWELL TIMES")
    print("  Dataset: CTU-13 Multistage Labeled NetFlows")
    print("=" * 80)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}")

    print(f"[*] Loading flow dataset from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    total_flows = len(df)
    print(f"[+] Loaded {total_flows:,} flows across {df['Scenario'].nunique()} scenarios.")

    print("[*] Annotating flows with ground-truth kill-chain stages via label_flow()...")
    df['stage'] = df.apply(label_flow, axis=1)
    df['StartTime'] = pd.to_datetime(df['StartTime'])
    df = df.sort_values(['Scenario', 'SrcAddr', 'StartTime']).reset_index(drop=True)

    # 1. Count transitions between consecutive flows per host session
    print("[*] Tracking sequential stage transitions...")
    transition_counts = np.zeros((7, 7), dtype=int)
    total_transitions = 0

    for (scen, src), group in df.groupby(['Scenario', 'SrcAddr']):
        stages = group['stage'].values
        for i in range(len(stages) - 1):
            s1 = int(stages[i])
            s2 = int(stages[i + 1])
            transition_counts[s1, s2] += 1
            total_transitions += 1

    print(f"[+] Observed {total_transitions:,} total sequential flow transitions.")

    # 2. Compute empirical dwell times per stage
    print("[*] Computing empirical stage dwell times (minutes)...")
    stage_durations_obs = {i: [] for i in range(7)}

    for (scen, src), group in df.groupby(['Scenario', 'SrcAddr']):
        stages = group['stage'].values
        times = group['StartTime'].values
        if len(stages) == 0:
            continue
        cur_stage = int(stages[0])
        start_t = times[0]
        for i in range(1, len(stages)):
            nxt_stage = int(stages[i])
            if nxt_stage != cur_stage:
                dur_min = (pd.to_datetime(times[i - 1]) - pd.to_datetime(start_t)).total_seconds() / 60.0
                stage_durations_obs[cur_stage].append(max(0.1, dur_min))
                cur_stage = nxt_stage
                start_t = times[i]
        dur_min = (pd.to_datetime(times[-1]) - pd.to_datetime(start_t)).total_seconds() / 60.0
        stage_durations_obs[cur_stage].append(max(0.1, dur_min))

    # 3. Construct calibrated transition matrix with Bayesian smoothing and sample-size gating
    calibrated_matrix = {}
    calibrated_matrix_np = np.zeros((7, 7), dtype=float)
    provenance_details = {}

    MIN_SAMPLES_THRESHOLD = 20  # Minimum observed transitions for high-confidence calibration

    for i in range(7):
        stage_name = STAGE_NAMES[i]
        row_counts = transition_counts[i]
        row_sum = int(np.sum(row_counts))
        expert_row = EXPERT_TRANSITION_MATRIX.get(stage_name, {})

        stage_meta = {
            "stage_id": stage_name,
            "total_observed_transitions": row_sum,
            "confidence_tier": "HIGH_CONFIDENCE_CALIBRATED" if row_sum >= MIN_SAMPLES_THRESHOLD else "LOW_CONFIDENCE_INHERITED_PRIOR",
            "pairs": {}
        }

        calibrated_row = {}
        if row_sum >= MIN_SAMPLES_THRESHOLD:
            # Bayesian smoothed combination with prior (alpha = 10 pseudo-counts)
            alpha = 10.0
            smoothed_row = np.zeros(7, dtype=float)
            for j in range(7):
                target_name = STAGE_NAMES[j]
                prior_prob = expert_row.get(target_name, 0.0)
                obs_count = row_counts[j]
                smoothed_row[j] = obs_count + alpha * prior_prob

            smoothed_row /= np.sum(smoothed_row)
            calibrated_matrix_np[i] = smoothed_row

            for j in range(7):
                target_name = STAGE_NAMES[j]
                prob = round(float(smoothed_row[j]), 4)
                if prob > 0.01:
                    calibrated_row[target_name] = prob
                obs_n = int(row_counts[j])
                stage_meta["pairs"][target_name] = {
                    "observed_n": obs_n,
                    "probability": prob,
                    "status": "calibrated" if obs_n >= MIN_SAMPLES_THRESHOLD else "smoothed_with_prior"
                }
        else:
            # Inherit expert-defined prior when data is insufficient (< 20 samples)
            for j in range(7):
                target_name = STAGE_NAMES[j]
                calibrated_matrix_np[i, j] = expert_row.get(target_name, 0.0)
                if expert_row.get(target_name, 0.0) > 0:
                    calibrated_row[target_name] = expert_row[target_name]
                stage_meta["pairs"][target_name] = {
                    "observed_n": int(row_counts[j]),
                    "probability": expert_row.get(target_name, 0.0),
                    "status": "inherited_expert_default"
                }

        calibrated_matrix[stage_name] = calibrated_row
        provenance_details[stage_name] = stage_meta

    # 4. Construct calibrated stage durations
    calibrated_durations = []
    dwell_provenance = {}

    for i in range(7):
        stage_name = STAGE_NAMES[i]
        obs = stage_durations_obs[i]
        n_obs = len(obs)
        expert_val = EXPERT_STAGE_DURATIONS[i]

        if n_obs >= MIN_SAMPLES_THRESHOLD and np.mean(obs) > 0.5:
            # High-confidence observed duration
            emp_mean = round(float(np.mean(obs)), 1)
            # Blend 50% empirical with 50% expert baseline for stability against tail outliers
            blended = round(0.5 * emp_mean + 0.5 * expert_val, 1)
            calibrated_durations.append(blended)
            dwell_provenance[stage_name] = {
                "duration_min": blended,
                "empirical_mean_min": emp_mean,
                "sample_size": n_obs,
                "status": "calibrated_empirical"
            }
        else:
            # Low-confidence fallback to domain prior
            calibrated_durations.append(expert_val)
            dwell_provenance[stage_name] = {
                "duration_min": expert_val,
                "empirical_mean_min": round(float(np.mean(obs)), 1) if n_obs > 0 else None,
                "sample_size": n_obs,
                "status": "expert_prior_default"
            }

    # 5. Build output payload
    payload = {
        "metadata": {
            "source_dataset": "CTU-13 Multistage NetFlow (5 scenarios, 83,010 flows)",
            "calibrated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_observed_transitions": total_transitions,
            "min_sample_threshold": MIN_SAMPLES_THRESHOLD,
            "script": "services/forecasting_engine/calibrate_priors.py"
        },
        "transition_matrix": calibrated_matrix,
        "transition_matrix_array": calibrated_matrix_np.tolist(),
        "stage_durations_min": calibrated_durations,
        "provenance_details": provenance_details,
        "dwell_provenance": dwell_provenance
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"\n[+] Successfully generated {OUTPUT_PATH}")
    print("\nCALIBRATION SUMMARY:")
    for s_name, meta in provenance_details.items():
        tier = meta['confidence_tier']
        n = meta['total_observed_transitions']
        print(f"  {s_name:<26}: N={n:<6} [{tier}]")
    print(f"\nCalibrated stage dwell times (min): {calibrated_durations}")
    return payload


if __name__ == "__main__":
    calibrate_priors()
