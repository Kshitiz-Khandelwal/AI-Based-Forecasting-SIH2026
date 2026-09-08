"""DNS Shield X-Forecast — Empirical Prior Calibration Script (v2.2)
Calibrates the 7x7 Markov State Transition Matrix and Stage Dwell Times
from the real CTU-13 multi-stage botnet traffic dataset (data/ctu13_multistage_flows.csv).

Fixes applied:
  1. Scaled Bayesian smoothing with effective sample capping (prevents escalation collapse on STAGE_0_BENIGN).
  2. Sanity floor on expected escalation transitions (minimum 2.5% probability floor).
  3. Real contiguous run dwell-time calculation using StartTime + Dur wall-clock spans (Option A).
  4. Full numerical consistency between transition_matrix (dict) and transition_matrix_array (list).
  5. Explicit separation of transition vs dwell-time calibration provenance.
  6. Transparent flagging of STAGE_3_DISCOVERY (N=0 real examples observed).
"""
import os
import sys
import json
import datetime
import numpy as np
import pandas as pd

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_PATH = os.path.join(ROOT, "data", "ctu13_multistage_flows.csv")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "priors.json")

sys.path.insert(0, os.path.join(ROOT, "services", "forecasting_engine"))
from train_temporal_gru import label_flow, STAGE_NAMES

# Baseline domain-expert priors
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
    print("=" * 85)
    print("  DNS SHIELD: STATISTICALLY ROBUST MARKOV PRIOR & DWELL TIME CALIBRATION")
    print("  Dataset: CTU-13 Multistage Labeled NetFlows")
    print("=" * 85)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}")

    print(f"[*] Loading flow dataset from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    total_flows = len(df)
    print(f"[+] Loaded {total_flows:,} flows across {df['Scenario'].nunique()} scenarios.")

    print("[*] Annotating flows with ground-truth kill-chain stages via label_flow()...")
    df['stage'] = df.apply(label_flow, axis=1)
    df['StartTime'] = pd.to_datetime(df['StartTime'])
    df['Dur'] = pd.to_numeric(df['Dur'], errors='coerce').fillna(0.0)
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

    # 2. Compute empirical dwell times per contiguous stage run (Option A: StartTime + Dur)
    print("[*] Computing empirical contiguous run dwell times (Option A: StartTime + Dur span)...")
    stage_durations_runs = {i: [] for i in range(7)}

    for (scen, src), group in df.groupby(['Scenario', 'SrcAddr']):
        stages = group['stage'].values
        starts = group['StartTime'].values
        durs = group['Dur'].values
        if len(stages) == 0:
            continue

        cur_stage = int(stages[0])
        run_start = starts[0]
        run_end = starts[0] + np.timedelta64(int(durs[0] * 1e9), 'ns')

        for i in range(1, len(stages)):
            s = int(stages[i])
            st = starts[i]
            dur_ns = int(durs[i] * 1e9)
            end_t = st + np.timedelta64(dur_ns, 'ns')

            if s == cur_stage:
                if end_t > run_end:
                    run_end = end_t
            else:
                total_sec = (run_end - run_start) / np.timedelta64(1, 's')
                stage_durations_runs[cur_stage].append(max(0.05, total_sec / 60.0))
                cur_stage = s
                run_start = st
                run_end = end_t

        total_sec = (run_end - run_start) / np.timedelta64(1, 's')
        stage_durations_runs[cur_stage].append(max(0.05, total_sec / 60.0))

    # 3. Robust Bayesian Smoothing with Effective Sample Capping and Sanity Floor (Fix 1)
    MIN_SAMPLES_THRESHOLD = 20
    MAX_EFFECTIVE_SAMPLES = 1000.0  # Cap raw count influence to prevent volume domination
    MIN_SANITY_FLOOR = 0.025        # 2.5% minimum floor for documented escalation paths

    calibrated_matrix = {}
    calibrated_matrix_np = np.zeros((7, 7), dtype=float)
    transition_provenance = {}

    for i in range(7):
        stage_name = STAGE_NAMES[i]
        row_counts = transition_counts[i].astype(float)
        row_sum = float(np.sum(row_counts))
        expert_row = EXPERT_TRANSITION_MATRIX.get(stage_name, {})

        stage_meta = {
            "stage_id": stage_name,
            "total_observed_transitions": int(row_sum),
            "status": "calibrated_empirical" if row_sum >= MIN_SAMPLES_THRESHOLD else "expert_prior_default",
            "data_coverage": "no_real_examples_observed" if row_sum == 0 else "observed_in_ctu13",
            "pairs": {}
        }

        if row_sum >= MIN_SAMPLES_THRESHOLD:
            # Scaled Bayesian smoothing: cap effective N to prevent prior annihilation
            eff_sum = min(row_sum, MAX_EFFECTIVE_SAMPLES)
            eff_counts = row_counts * (eff_sum / row_sum)
            alpha = max(25.0, 0.08 * eff_sum)

            prior_vec = np.zeros(7, dtype=float)
            for j in range(7):
                target_name = STAGE_NAMES[j]
                prior_vec[j] = expert_row.get(target_name, 0.0)

            smoothed = eff_counts + alpha * prior_vec
            smoothed /= np.sum(smoothed)

            # Enforce sanity floor for expected escalation transitions
            for j in range(7):
                target_name = STAGE_NAMES[j]
                if expert_row.get(target_name, 0.0) > 0.0:
                    if smoothed[j] < MIN_SANITY_FLOOR:
                        smoothed[j] = MIN_SANITY_FLOOR
            smoothed /= np.sum(smoothed)
            calibrated_matrix_np[i] = smoothed

            calibrated_row = {}
            for j in range(7):
                target_name = STAGE_NAMES[j]
                prob = round(float(smoothed[j]), 6)
                calibrated_row[target_name] = prob
                stage_meta["pairs"][target_name] = {
                    "observed_n": int(row_counts[j]),
                    "probability": prob,
                    "status": "calibrated" if row_counts[j] >= MIN_SAMPLES_THRESHOLD else "smoothed_prior_floor"
                }
            calibrated_matrix[stage_name] = calibrated_row
        else:
            # Inherit expert default if N < 20
            calibrated_row = {}
            for j in range(7):
                target_name = STAGE_NAMES[j]
                p = expert_row.get(target_name, 0.0)
                calibrated_matrix_np[i, j] = p
                calibrated_row[target_name] = round(float(p), 6)
                stage_meta["pairs"][target_name] = {
                    "observed_n": int(row_counts[j]),
                    "probability": round(float(p), 6),
                    "status": "inherited_expert_default"
                }
            calibrated_matrix[stage_name] = calibrated_row

        transition_provenance[stage_name] = stage_meta

    # 4. Calibrated Dwell Times (Fix 2: Option A with explicit provenance per stage)
    calibrated_durations = []
    dwell_time_provenance = {}

    for i in range(7):
        stage_name = STAGE_NAMES[i]
        runs = stage_durations_runs[i]
        n_runs = len(runs)
        expert_dur = EXPERT_STAGE_DURATIONS[i]

        if i == 0 or i == 6:
            # Terminal or clean baseline
            dwell_val = 0.0
            dwell_time_provenance[stage_name] = {
                "duration_min": 0.0,
                "empirical_mean_min": round(float(np.mean(runs)), 2) if n_runs > 0 else None,
                "sample_runs_n": n_runs,
                "status": "terminal_boundary_zero",
                "data_coverage": "observed_in_ctu13" if n_runs > 0 else "no_real_examples"
            }
            calibrated_durations.append(dwell_val)
        elif n_runs >= MIN_SAMPLES_THRESHOLD:
            # High-confidence contiguous run duration
            emp_mean = round(float(np.mean(runs)), 1)
            dwell_time_provenance[stage_name] = {
                "duration_min": emp_mean,
                "empirical_mean_min": emp_mean,
                "sample_runs_n": n_runs,
                "status": "calibrated_empirical",
                "data_coverage": "observed_in_ctu13"
            }
            calibrated_durations.append(emp_mean)
        else:
            # Low-confidence fallback to domain expert prior
            dwell_time_provenance[stage_name] = {
                "duration_min": expert_dur,
                "empirical_mean_min": round(float(np.mean(runs)), 2) if n_runs > 0 else None,
                "sample_runs_n": n_runs,
                "status": "expert_prior_default",
                "data_coverage": "no_real_examples_observed" if n_runs == 0 else "low_sample_support"
            }
            calibrated_durations.append(expert_dur)

    # 5. Build output payload
    payload = {
        "metadata": {
            "source_dataset": "CTU-13 Multistage NetFlow (5 scenarios, 83,010 flows)",
            "calibrated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_observed_transitions": total_transitions,
            "min_sample_threshold": MIN_SAMPLES_THRESHOLD,
            "max_effective_samples_cap": MAX_EFFECTIVE_SAMPLES,
            "min_sanity_floor": MIN_SANITY_FLOOR,
            "dwell_time_methodology": "Option A: Contiguous Run Wall-Clock Span (StartTime to EndTime + Dur)",
            "script": "services/forecasting_engine/calibrate_priors.py"
        },
        "transition_matrix": calibrated_matrix,
        "transition_matrix_array": calibrated_matrix_np.tolist(),
        "stage_durations_min": calibrated_durations,
        "transition_provenance": transition_provenance,
        "dwell_time_provenance": dwell_time_provenance
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(payload, f, indent=2)

    # 6. Diff & Human Audit Table (Fix 1 Requirement 3)
    print("\n" + "=" * 85)
    print("  HUMAN AUDIT & DIFF TABLE: EXPERT PRIORS vs CALIBRATED VALUES")
    print("=" * 85)
    print(f"{'Transition Path':<42} | {'Expert':<8} | {'Calibrated':<10} | {'Ratio':<7} | {'Audit Alert'}")
    print("-" * 85)

    for from_stage, targets in EXPERT_TRANSITION_MATRIX.items():
        for to_stage, exp_p in targets.items():
            cal_p = calibrated_matrix[from_stage][to_stage]
            ratio = cal_p / max(1e-6, exp_p)
            alert = "OK"
            if ratio > 5.0:
                alert = f"[WARN: >5x INCREASE ({ratio:.1f}x)]"
            elif ratio < 0.20:
                alert = f"[WARN: >5x DROP ({ratio:.2f}x)]"
            if cal_p < 0.01:
                alert = "[ALERT: DEGENERATE (<1%)]"
            elif cal_p <= MIN_SANITY_FLOOR:
                alert = "[HELD AT SANITY FLOOR]"

            path_str = f"{from_stage.replace('STAGE_', '')} -> {to_stage.replace('STAGE_', '')}"
            print(f"{path_str:<42} | {exp_p:<8.4f} | {cal_p:<10.6f} | {ratio:<7.2f} | {alert}")

    print("\n" + "=" * 85)
    print("  STAGE-BY-STAGE DUAL PROVENANCE SUMMARY")
    print("=" * 85)
    print(f"{'Stage':<26} | {'Transitions N':<13} | {'Trans Status':<22} | {'Runs N':<6} | {'Dwell Time':<10} | {'Dwell Status'}")
    print("-" * 85)
    for s_id in STAGE_NAMES:
        tp = transition_provenance[s_id]
        dp = dwell_time_provenance[s_id]
        s_clean = s_id.replace("STAGE_", "")
        print(f"{s_clean:<26} | {tp['total_observed_transitions']:<13} | {tp['status']:<22} | {dp['sample_runs_n']:<6} | {dp['duration_min']:<6.1f} min | {dp['status']}")

    print(f"\n[+] Priors saved successfully to {OUTPUT_PATH}")
    return payload


if __name__ == "__main__":
    calibrate_priors()
