"""
Burst-Length vs Window-Size Analysis — PS #26153 Diagnostic
============================================================
For each MITRE stage in CTU-13, computes the distribution of
consecutive same-stage run lengths per (Scenario, SrcAddr) group.
Compares against seq_len=10 to diagnose window/burst mismatch.

Also runs PCA on STAGE_2_INITIAL_ACCESS vs STAGE_6_EXFILTRATION
raw feature vectors to diagnose label/feature-space separability.

Outputs:
  docs/BURST_LENGTH_VS_WINDOW_ANALYSIS.md
  docs/pca_initial_access_vs_exfiltration.png
"""
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import numpy as np
import pandas as pd
from collections import defaultdict

try:
    from services.forecasting_engine.train_temporal_gru import (
        label_flow, chronological_split_per_scenario, STAGE_NAMES
    )
    from services.forecasting_engine.temporal_feature_extractor import extract_flow_features
except ImportError:
    from train_temporal_gru import label_flow, chronological_split_per_scenario, STAGE_NAMES
    from temporal_feature_extractor import extract_flow_features


# ──────────────────────────────────────────────────────────────────────────────
# TASK 1: Burst-length distribution per stage
# ──────────────────────────────────────────────────────────────────────────────

def compute_run_lengths(labels):
    """Return list of run lengths (consecutive same-label sequences)."""
    if len(labels) == 0:
        return {}
    runs = defaultdict(list)
    current_label = labels[0]
    current_len = 1
    for lbl in labels[1:]:
        if lbl == current_label:
            current_len += 1
        else:
            runs[current_label].append(current_len)
            current_label = lbl
            current_len = 1
    runs[current_label].append(current_len)
    return dict(runs)


def burst_analysis(df):
    """Compute per-stage run-length distributions across all (Scenario, SrcAddr) groups."""
    stage_runs = defaultdict(list)

    for (scenario, src), group in df.groupby(['Scenario', 'SrcAddr']):
        group = group.sort_values('StartTime').reset_index(drop=True)
        labels = [label_flow(row) for _, row in group.iterrows()]
        if not labels:
            continue
        run_dict = compute_run_lengths(labels)
        for stage_idx, run_list in run_dict.items():
            stage_runs[stage_idx].extend(run_list)

    return stage_runs


def percentile_str(arr, pct):
    if len(arr) == 0:
        return 'N/A'
    return f'{np.percentile(arr, pct):.1f}'


def build_markdown(stage_runs, seq_len, confusion_findings):
    lines = [
        '# Burst-Length vs Window-Size Analysis',
        '',
        '**Dataset**: CTU-13 (`data/ctu13_multistage_flows.csv`)',
        f'**Window size used in GRU training**: `seq_len = {seq_len}`',
        '',
        '## Purpose',
        '',
        'The GRU labels each 10-step window using the label of the LAST flow after',
        'the window (next-step prediction). If a Reconnaissance or C2 burst is only',
        '3-8 flows long, most windows straddling that burst will contain mostly-Benign',
        'context flows. The final hidden state can be pulled toward BENIGN even when',
        'the labeled flow is genuinely anomalous — this is the **window/burst dilution hypothesis**.',
        '',
        'The flat Logistic Regression has no such dilution: it sees only one flow at a time.',
        '',
        '## Run-Length Distribution by Stage',
        '',
        '| Stage | N Groups | Min | p10 | Median | p90 | Max | Mean | Runs < seq_len | % < seq_len |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|',
    ]

    for stage_idx, stage_name in enumerate(STAGE_NAMES):
        runs = stage_runs.get(stage_idx, [])
        if not runs:
            lines.append(f'| {stage_name} | 0 | — | — | — | — | — | — | — | — |')
            continue
        arr = np.array(runs)
        shorter = int((arr < seq_len).sum())
        pct_shorter = 100.0 * shorter / len(arr)
        lines.append(
            f'| {stage_name} | {len(arr)} | {int(arr.min())} | '
            f'{percentile_str(arr, 10)} | {np.median(arr):.1f} | '
            f'{percentile_str(arr, 90)} | {int(arr.max())} | {arr.mean():.1f} | '
            f'{shorter} | {pct_shorter:.1f}% |'
        )

    lines += [
        '',
        '## Dilution Hypothesis Assessment',
        '',
    ]

    for stage_idx, stage_name in enumerate(STAGE_NAMES):
        if stage_idx == 0:
            continue
        runs = stage_runs.get(stage_idx, [])
        if not runs:
            lines.append(f'- **{stage_name}**: No runs found (no data or never occurs)')
            continue
        arr = np.array(runs)
        pct_shorter = 100.0 * (arr < seq_len).sum() / len(arr)
        verdict = ('⚠️ HIGH DILUTION RISK' if pct_shorter > 60
                   else '⚠️ MODERATE DILUTION RISK' if pct_shorter > 30
                   else '✅ Low dilution risk')
        lines.append(
            f'- **{stage_name}**: Median run = {np.median(arr):.1f} flows, '
            f'{pct_shorter:.1f}% of runs shorter than seq_len={seq_len}. {verdict}'
        )

    lines += [
        '',
        '## Confusion Matrix Collapse Findings (v2 grouped model)',
        '',
        *[f'- {s}' for s in confusion_findings],
        '',
        '## Conclusion & Recommended Actions',
        '',
        'If most Recon/C2 burst runs are shorter than seq_len=10, the window-dilution',
        'hypothesis is confirmed. Recommended actions in priority order:',
        '',
        '1. **Try `seq_len=5`** (or closest value to the observed median Recon/C2 run length)',
        '   as a direct ablation — compare per-class F1 vs seq_len=10.',
        '2. **Try majority-vote window labeling** instead of next-step labeling to give',
        '   the model the strongest available signal from within the window itself.',
        '3. **Focal loss + jittered augmentation** (already implemented) — train v3 candidate.',
        '4. **UNSW-NB15 or CIC-IDS-2017 samples** for STAGE_3_DISCOVERY — CTU-13 has zero',
        '   holdout samples for this stage regardless of any windowing fix.',
        '',
        '---',
        '_Generated by `services/forecasting_engine/burst_length_analysis.py`_',
    ]

    return '\n'.join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# TASK 5: PCA — Initial Access vs Exfiltration feature separability
# ──────────────────────────────────────────────────────────────────────────────

def pca_separability(df):
    """Run PCA on STAGE_2_INITIAL_ACCESS vs STAGE_6_EXFILTRATION feature vectors."""
    print('[PCA] Extracting features for INITIAL_ACCESS and EXFILTRATION...')
    features, stage_labels = [], []

    for _, row in df.iterrows():
        lbl = label_flow(row)
        if lbl in (2, 6):
            features.append(extract_flow_features(row))
            stage_labels.append(lbl)

    if len(features) < 10:
        print('[PCA] Not enough samples for PCA analysis.')
        return None

    X = np.vstack(features)
    y = np.array(stage_labels)

    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    X_scaled = StandardScaler().fit_transform(X)
    pca = PCA(n_components=2, random_state=42)
    X_2d = pca.fit_transform(X_scaled)

    # Compute between-class vs within-class variance (simple separability metric)
    centroid_ia = X_2d[y == 2].mean(axis=0)
    centroid_ex = X_2d[y == 6].mean(axis=0)
    between_var = np.linalg.norm(centroid_ia - centroid_ex) ** 2
    within_var = (X_2d[y == 2].var(axis=0).sum() + X_2d[y == 6].var(axis=0).sum()) / 2
    separability_ratio = between_var / max(within_var, 1e-9)

    print(f'[PCA] Between-class distance²: {between_var:.4f}')
    print(f'[PCA] Within-class variance (avg): {within_var:.4f}')
    print(f'[PCA] Separability ratio (higher=better): {separability_ratio:.4f}')
    print(f'[PCA] Variance explained by PC1+PC2: {sum(pca.explained_variance_ratio_)*100:.1f}%')

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(8, 6))
        colors = {2: '#e05c5c', 6: '#3a7bd5'}
        labels_text = {2: 'STAGE_2_INITIAL_ACCESS', 6: 'STAGE_6_EXFILTRATION'}

        for stage in [2, 6]:
            mask = y == stage
            ax.scatter(X_2d[mask, 0], X_2d[mask, 1],
                       c=colors[stage], label=labels_text[stage],
                       alpha=0.4, s=12, linewidths=0)

        ax.scatter(*centroid_ia, marker='X', s=200, c='#c0392b', zorder=5, label='Centroid IA')
        ax.scatter(*centroid_ex, marker='X', s=200, c='#1a5276', zorder=5, label='Centroid EX')

        ax.set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]*100:.1f}% var)')
        ax.set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]*100:.1f}% var)')
        ax.set_title(
            f'PCA: Initial Access vs Exfiltration\n'
            f'Separability ratio: {separability_ratio:.3f} | '
            f'n_IA={int((y==2).sum())}, n_EX={int((y==6).sum())}'
        )
        ax.legend(fontsize=8)
        ax.grid(alpha=0.2)
        plt.tight_layout()

        out_path = os.path.join('docs', 'pca_initial_access_vs_exfiltration.png')
        plt.savefig(out_path, dpi=150)
        plt.close()
        print(f'[PCA] Saved plot → {out_path}')
    except ImportError:
        print('[PCA] matplotlib not available — skipping plot. Install with: pip install matplotlib')

    return {
        'between_class_distance_sq': float(between_var),
        'within_class_variance_avg': float(within_var),
        'separability_ratio': float(separability_ratio),
        'pc1_variance_explained': float(pca.explained_variance_ratio_[0]),
        'pc2_variance_explained': float(pca.explained_variance_ratio_[1]),
        'n_initial_access': int((y == 2).sum()),
        'n_exfiltration': int((y == 6).sum()),
        'interpretation': (
            'HEAVILY OVERLAPPING — labeling/feature problem likely, not just a model issue'
            if separability_ratio < 1.0 else
            'MODERATE OVERLAP — model may improve with better training'
            if separability_ratio < 5.0 else
            'WELL SEPARATED — feature space supports discrimination; training/loss issue'
        )
    }


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    data_path = os.path.join('data', 'ctu13_multistage_flows.csv')
    print(f'[+] Loading {data_path}...')
    df = pd.read_csv(data_path, low_memory=False)
    df['StartTime'] = pd.to_datetime(df['StartTime'])
    print(f'[+] Loaded {len(df)} flows across {df["Scenario"].nunique()} scenarios.')

    # ── Task 1 ──
    seq_len = 10
    print(f'\n[TASK 1] Computing burst-length distributions (seq_len={seq_len})...')
    stage_runs = burst_analysis(df)

    confusion_findings = [
        'STAGE_1_RECONNAISSANCE: 303/325 (93.2%) predicted as BENIGN by GRU v2',
        'STAGE_4_C2_PERSISTENCE: 315/315 (100.0%) predicted as BENIGN by GRU v2',
        'STAGE_2_INITIAL_ACCESS: predictions split between INITIAL_ACCESS and EXFILTRATION',
        'STAGE_5_LATERAL_MOVEMENT: 2/2 (100%) predicted as BENIGN — dataset gap',
        'Source: temporal_gru_forecaster_grouped_v2 confusion matrix (commit 2c16849)',
    ]

    md = build_markdown(stage_runs, seq_len, confusion_findings)

    os.makedirs('docs', exist_ok=True)
    md_path = os.path.join('docs', 'BURST_LENGTH_VS_WINDOW_ANALYSIS.md')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f'[+] Saved burst analysis -> {md_path}')

    # Print summary to stdout
    print(f'\n{"Stage":<30} {"Median run":>10} {"% < seq_len":>12} {"Risk":>25}')
    print('-' * 80)
    for stage_idx, stage_name in enumerate(STAGE_NAMES):
        runs = stage_runs.get(stage_idx, [])
        if not runs:
            print(f'{stage_name:<30} {"N/A":>10} {"N/A":>12} {"no data":>25}')
            continue
        arr = np.array(runs)
        pct = 100.0 * (arr < seq_len).sum() / len(arr)
        risk = ('HIGH DILUTION' if pct > 60 else 'MODERATE' if pct > 30 else 'LOW')
        print(f'{stage_name:<30} {np.median(arr):>10.1f} {pct:>11.1f}% {risk:>25}')

    # ── Task 5 ──
    print(f'\n[TASK 5] Running PCA: Initial Access vs Exfiltration...')
    pca_result = pca_separability(df)
    if pca_result:
        print(f'\n[PCA] Interpretation: {pca_result["interpretation"]}')

        import json
        pca_path = os.path.join('docs', 'pca_ia_vs_exfil_metrics.json')
        with open(pca_path, 'w', encoding='utf-8') as f:
            json.dump(pca_result, f, indent=2)
        print(f'[+] Saved PCA metrics → {pca_path}')


if __name__ == '__main__':
    main()
