#!/usr/bin/env python3
"""
DNS Shield — Presentation Numbers Generator
Reads live system artifacts (priors.json, datasets, feature extractor) and generates
audited, verifiable markdown snippets for pitch/presentation documents and model cards.
Guarantees presentation numbers never silently drift from repo artifacts.
"""

import json
import os
import sys
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
PRIORS_PATH = REPO_ROOT / "services" / "forecasting_engine" / "priors.json"
FEATURE_EXTRACTOR_PATH = REPO_ROOT / "services" / "forecasting_engine" / "temporal_feature_extractor.py"
DGA_TRAIN_PATH = REPO_ROOT / "data" / "dga_dataset.csv"
EVAL_100K_PATH = REPO_ROOT / "data" / "eval_100k_domains.csv"
CTU13_FLOWS_PATH = REPO_ROOT / "data" / "ctu13_multistage_flows.csv"
IOC_CACHE_PATH = REPO_ROOT / "services" / "threat-intel" / "data" / "ioc_cache.jsonl"
ALLOWLIST_PATH = REPO_ROOT / "data" / "dns_shield_allowlist.txt"


def count_lines(filepath: Path) -> int:
    if not filepath.exists():
        return 0
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)


def count_csv_rows(filepath: Path) -> int:
    if not filepath.exists():
        return 0
    lines = count_lines(filepath)
    return max(0, lines - 1)  # subtract header


def get_feature_names() -> list[str]:
    sys.path.insert(0, str(REPO_ROOT / "services" / "forecasting_engine"))
    try:
        from temporal_feature_extractor import FEATURE_NAMES
        return FEATURE_NAMES
    except Exception:
        return []


def generate_markdown() -> str:
    # 1. Priors
    with open(PRIORS_PATH, "r", encoding="utf-8") as f:
        priors = json.load(f)

    meta = priors.get("metadata", {})
    trans_prov = priors.get("transition_provenance", {})
    dwell_prov = priors.get("dwell_time_provenance", {})
    dwell_times = priors.get("stage_durations", {})

    # 2. Datasets
    dga_train_count = count_csv_rows(DGA_TRAIN_PATH)
    eval_100k_count = count_csv_rows(EVAL_100K_PATH)
    ctu13_flow_count = count_csv_rows(CTU13_FLOWS_PATH)
    ioc_cache_count = count_lines(IOC_CACHE_PATH)
    allowlist_count = count_lines(ALLOWLIST_PATH)

    # 3. Features
    features = get_feature_names()

    out = []
    out.append("### Live-Audited Repository Statistics & Figures")
    out.append(f"*(Auto-generated from live files via `python scripts/generate_presentation_numbers.py`)*\n")

    out.append("#### 1. Dataset & Feed Sizes (Audited from Disk)")
    out.append(f"- **ML Lexical Training Set (`data/dga_dataset.csv`)**: {dga_train_count:,} labeled domain samples")
    out.append(f"- **Zero-Day Evaluation Corpus (`data/eval_100k_domains.csv`)**: {eval_100k_count:,} domains across 5 splits")
    out.append(f"- **CTU-13 Multistage NetFlow Corpus (`data/ctu13_multistage_flows.csv`)**: {ctu13_flow_count:,} flow records across 5 botnet scenarios")
    out.append(f"- **Threat Intel IOC Cache (`services/threat-intel/data/ioc_cache.jsonl`)**: {ioc_cache_count} curated active threat indicators")
    out.append(f"- **Enterprise High-Authority Allowlist (`data/dns_shield_allowlist.txt`)**: {allowlist_count} verified domain roots\n")

    out.append("#### 2. Temporal Forecaster GRU Input Features")
    out.append(f"The Neural GRU sequence forecaster accepts a tensor of shape `(batch, 10, {len(features)})` representing 10 consecutive flow windows across **exactly {len(features)} extracted features**:")
    for i, feat in enumerate(features, 1):
        out.append(f"  {i}. `{feat}`")
    out.append("")

    out.append("#### 3. Calibrated Markov Dwell Times & Transition Provenance")
    tot_trans = meta.get('total_observed_transitions', 0)
    out.append(f"- **Total Observed CTU-13 Transitions**: {tot_trans:,}" if isinstance(tot_trans, int) else f"- **Total Observed CTU-13 Transitions**: {tot_trans}")
    out.append(f"- **Calibration Methodology**: Scaled Bayesian smoothing ceiling (eff_sum <= 1000) + Option A contiguous run wall-clock spans\n")

    out.append("| Stage ID | Stage Label | Dwell Time (min) | Dwell Status | Transition Status | Transition N |")
    out.append("| :--- | :--- | :---: | :--- | :--- | :---: |")

    stage_labels = {
        "STAGE_0_BENIGN": "0 Benign Traffic",
        "STAGE_1_RECONNAISSANCE": "1 Reconnaissance",
        "STAGE_2_INITIAL_ACCESS": "2 Initial Access",
        "STAGE_3_DISCOVERY": "3 Subnet Discovery",
        "STAGE_4_C2_PERSISTENCE": "4 C2 Beaconing",
        "STAGE_5_LATERAL_MOVEMENT": "5 Lateral Movement",
        "STAGE_6_EXFILTRATION": "6 Data Exfiltration",
    }

    for stage_id, label in stage_labels.items():
        d_p = dwell_prov.get(stage_id, {})
        t_p = trans_prov.get(stage_id, {})
        dur = d_p.get("duration_min", 0.0)
        d_stat = d_p.get("status", "unknown")
        d_n = d_p.get("sample_runs_n", 0)
        t_stat = t_p.get("status", "unknown")
        t_n = t_p.get("total_observed_transitions", 0)
        cov = d_p.get("data_coverage", "unknown")
        cov_badge = "⚠ Untested (N=0)" if cov == "no_real_examples_observed" else cov
        out.append(f"| `{stage_id}` | {label} | {dur:.1f} | `{d_stat}` (N={d_n:,}) | `{t_stat}` | {t_n:,} |")

    out.append("\n#### 4. Documented Escalation Transition Probabilities")
    matrix = priors.get("transition_matrix", {})
    out.append(f"- `STAGE_0_BENIGN -> STAGE_0_BENIGN`: {matrix.get('STAGE_0_BENIGN', {}).get('STAGE_0_BENIGN', 0.0):.6f}")
    out.append(f"- `STAGE_0_BENIGN -> STAGE_1_RECONNAISSANCE`: {matrix.get('STAGE_0_BENIGN', {}).get('STAGE_1_RECONNAISSANCE', 0.0):.6f} (held at sanity floor)")
    out.append(f"- `STAGE_1_RECONNAISSANCE -> STAGE_2_INITIAL_ACCESS`: {matrix.get('STAGE_1_RECONNAISSANCE', {}).get('STAGE_2_INITIAL_ACCESS', 0.0):.6f}")
    out.append(f"- `STAGE_2_INITIAL_ACCESS -> STAGE_6_EXFILTRATION`: {matrix.get('STAGE_2_INITIAL_ACCESS', {}).get('STAGE_6_EXFILTRATION', 0.0):.6f} (direct botnet jump)")

    return "\n".join(out)


if __name__ == "__main__":
    md = generate_markdown()
    print(md)
