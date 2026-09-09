"""DNS Shield X-Forecast — GRU Temporal Attack Sequence Forecaster
Guarantees (Master Prompt 4 compliant):
  1. Deterministic Reproducibility: SEED=42 applied to random, numpy, torch, DataLoader generator.
  2. Genuine Chronological Per-Scenario Splitting (70/15/15) with Zero Data Leakage.
  3. Ground-truth label string checked BEFORE port-based heuristic — C2 can't be
     silently overwritten by a port-bucket guess.
  4. Minority-stage oversampling within train split only (never across boundary).
  5. Focal loss (gamma=2.0) with inverse-frequency alpha for class imbalance.
  6. Jitter-augmented oversampling: 5% per-feature Gaussian noise prevents verbatim memorisation.
  7. label_strategy: 'next' (default), 'majority' (mode within window), or 'center' (mid-flow).
  8. seq_len and label_strategy are runtime-configurable via env vars TEMPORAL_GRU_SEQ_LEN /
     TEMPORAL_GRU_LABEL_STRATEGY without code changes.
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
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix
from sklearn.preprocessing import StandardScaler

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.cuda.manual_seed_all(SEED)  # harmless no-op on CPU-only machines

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
try:
    from services.forecasting_engine.temporal_feature_extractor import extract_flow_features, FEATURE_NAMES
except ImportError:
    from temporal_feature_extractor import extract_flow_features, FEATURE_NAMES

try:
    from services.forecasting_engine.evaluation_metrics import evaluation_summary, expected_calibration_error
except ImportError:
    from evaluation_metrics import evaluation_summary, expected_calibration_error

STAGE_MAP = {
    "STAGE_0_BENIGN": 0,
    "STAGE_1_RECONNAISSANCE": 1,
    "STAGE_2_INITIAL_ACCESS": 2,
    "STAGE_3_DISCOVERY": 3,
    "STAGE_4_C2_PERSISTENCE": 4,
    "STAGE_5_LATERAL_MOVEMENT": 5,
    "STAGE_6_EXFILTRATION": 6,
}
STAGE_NAMES = list(STAGE_MAP.keys())


def label_flow(row):
    """Map CTU-13 bidirectional flow records to MITRE ATT&CK Kill-Chain stages.

    Master Prompt 4 priority order: ground-truth label string ALWAYS wins over any
    port-based heuristic. Only fall back to port guessing when the label string
    carries no behavioral signal beyond the generic "From-Botnet-..." prefix.
    """
    lbl = str(row.get('Label', '')).lower()
    proto = str(row.get('Proto', '')).lower()
    dport_str = str(row.get('Dport', ''))
    tot_pkts = float(row.get('TotPkts', 1))
    dur = float(row.get('Dur', 0))
    src = str(row.get('SrcAddr', ''))

    if "botnet" not in lbl and "147.32.84.165" not in src:
        return 0  # STAGE_0_BENIGN

    # ---- PRIORITY 1: Dataset's own ground-truth label strings ----
    # These override ANY port-based guess. They are exact observations recorded
    # at capture time; port coincidence is inference.
    if "cc" in lbl or "c&c" in lbl or "irc" in lbl or "custom-encryption" in lbl:
        return 4  # STAGE_4_C2_PERSISTENCE — dataset explicitly annotated C2

    if "attack" in lbl or "ddos" in lbl:
        return 6  # STAGE_6_EXFILTRATION / IMPACT

    if "scan" in lbl or "portscan" in lbl or "attempt" in lbl:
        return 1  # STAGE_1_RECONNAISSANCE

    # ---- PRIORITY 2: Behavioral port/protocol heuristics ----
    # Only reached when the label string itself gives no behavioral detail.
    if "icmp" in proto and tot_pkts > 5:
        return 6  # ICMP flood → exfiltration/impact

    if dport_str in ['3389', '445', '88']:
        return 5  # STAGE_5_LATERAL_MOVEMENT (RDP / SMB / Kerberos)
                  # Only reached if ground truth didn't say this was C2 first.

    if dport_str in ['135', '161', '2869', '389', '636', '137', '138', '139']:
        return 3  # STAGE_3_DISCOVERY (RPC, SNMP, NetBIOS, SSDP, LDAP)

    if dport_str.startswith("0x") or (proto == "tcp" and tot_pkts <= 2 and dur < 0.05):
        return 1  # STAGE_1_RECONNAISSANCE (hex-port sweeps, SYN-only probes)

    if dport_str in ['53', '80', '443'] or "dns" in lbl or "http" in lbl:
        return 2  # STAGE_2_INITIAL_ACCESS

    return 2  # default fallback for generic botnet-established flows


def chronological_split_per_scenario(df, ratios=(0.70, 0.15, 0.15)):
    """Split within each CTU-13 scenario chronologically, then union.

    No shuffle at any point — temporal ordering is preserved exactly.
    """
    parts = {"train": [], "val": [], "test": []}
    for scenario_id, group in df.groupby("Scenario"):
        group = group.sort_values("StartTime").reset_index(drop=True)
        n = len(group)
        t_end = int(n * ratios[0])
        v_end = int(n * (ratios[0] + ratios[1]))
        parts["train"].append(group.iloc[:t_end])
        parts["val"].append(group.iloc[t_end:v_end])
        parts["test"].append(group.iloc[v_end:])
    train = pd.concat(parts["train"]).sort_values("StartTime").reset_index(drop=True)
    val = pd.concat(parts["val"]).sort_values("StartTime").reset_index(drop=True)
    test = pd.concat(parts["test"]).sort_values("StartTime").reset_index(drop=True)
    return train, val, test


class TemporalSequenceDataset(Dataset):
    def __init__(self, features, labels, group_ids=None, seq_len=10, oversample=False,
                 label_strategy: str = "next"):
        """Create windows strictly within an ordered scenario/source-host group.

        A window cannot cross a scenario or host boundary.  This avoids creating
        artificial attack histories from unrelated CTU-13 flows after partitions
        have been concatenated.

        Args:
            label_strategy: Controls what label is assigned to each window.
                'next'     — label of the flow AFTER the window (default; next-step prediction).
                'majority' — mode of labels WITHIN the window (majority vote).
                'center'   — label of the CENTER flow of the window (index seq_len // 2).
                'majority' and 'center' are diagnostic alternatives for the window-dilution
                hypothesis: if Recon/C2 bursts are shorter than seq_len, 'next' causes the
                window label to often be Benign (the burst ended before the window finished).
        """
        from scipy import stats as scipy_stats
        features = np.asarray(features, dtype=np.float32)
        labels = np.asarray(labels, dtype=np.int64)
        if label_strategy not in ("next", "majority", "center"):
            raise ValueError(f"label_strategy must be 'next', 'majority', or 'center'; got {label_strategy!r}")
        if group_ids is None:
            group_ids = np.zeros(len(features), dtype=np.int64)
        if len(group_ids) != len(features):
            raise ValueError("group_ids must contain one value for every feature row")
        X_seqs, y_seqs = [], []
        group_ids = np.asarray(group_ids)
        for group_id in np.unique(group_ids):
            group_indices = np.flatnonzero(group_ids == group_id)
            for start in range(len(group_indices) - seq_len):
                window_indices = group_indices[start:start + seq_len]
                target_index = group_indices[start + seq_len]
                X_seqs.append(features[window_indices])
                if label_strategy == "next":
                    y_seqs.append(labels[target_index])
                elif label_strategy == "majority":
                    window_labels = labels[window_indices]
                    majority = int(scipy_stats.mode(window_labels, keepdims=True).mode[0])
                    y_seqs.append(majority)
                elif label_strategy == "center":
                    center_index = window_indices[seq_len // 2]
                    y_seqs.append(labels[center_index])

        if not X_seqs:
            raise ValueError("No complete sequences: each scenario/source-host group needs more than seq_len flows")

        if oversample:
            # Jitter-augmented oversampling for minority attack stages WITHIN train split only.
            # Gaussian noise (std=0.05 * per-feature training std) ensures each copy is
            # distinct — prevents the model from memorising verbatim duplicates and
            # saturating early before learning hard minority-stage features.
            X_arr = np.array(X_seqs, dtype=np.float32)
            y_arr = np.array(y_seqs, dtype=np.int64)
            # Compute feature std over ALL training sequences for jitter scaling.
            # Shape: (seq_len, n_features) -> std over the first axis.
            feat_std = X_arr.reshape(-1, X_arr.shape[-1]).std(axis=0, keepdims=True)  # (1, 16)
            os_X, os_y = [X_arr], [y_arr]
            rng = np.random.RandomState(SEED)
            for c in range(1, 7):
                idx = np.where(y_arr == c)[0]
                if 0 < len(idx) < 1500:
                    reps = min(15, int(np.ceil(1500 / len(idx))))
                    for _ in range(reps):
                        # Add small Gaussian jitter — gives the model genuinely new examples
                        # rather than byte-identical copies that enable memorisation.
                        noise = rng.randn(*X_arr[idx].shape).astype(np.float32)
                        jitter_scale = 0.05 * feat_std[np.newaxis, :, :]  # broadcast (n, 10, 16)
                        os_X.append(X_arr[idx] + noise * jitter_scale)
                        os_y.append(y_arr[idx])
            X_seqs = np.concatenate(os_X, axis=0)
            y_seqs = np.concatenate(os_y, axis=0)

        self.X_seq = torch.tensor(np.array(X_seqs), dtype=torch.float32)
        self.y_seq = torch.tensor(np.array(y_seqs), dtype=torch.long)

    def __len__(self):
        return len(self.y_seq)

    def __getitem__(self, idx):
        return self.X_seq[idx], self.y_seq[idx]


class TemporalAttackGRU(nn.Module):
    def __init__(self, input_dim=16, hidden_dim=64, num_layers=2, num_classes=7):
        super().__init__()
        self.gru = nn.GRU(
            input_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.15 if num_layers > 1 else 0.0,
        )
        self.ln = nn.LayerNorm(hidden_dim)
        self.head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.15),
            nn.Linear(32, num_classes),
        )

    def forward(self, x):
        out, _ = self.gru(x)
        return self.head(self.ln(out[:, -1, :]))


def fit_temperature(logits: torch.Tensor, targets: torch.Tensor) -> float:
    """Fit a single validation-only temperature using NLL minimization."""
    temperature = torch.ones(1, device=logits.device, requires_grad=True)
    optimizer = torch.optim.LBFGS([temperature], lr=0.01, max_iter=50, line_search_fn="strong_wolfe")
    criterion = nn.CrossEntropyLoss()

    def closure():
        optimizer.zero_grad()
        loss = criterion(logits / temperature.clamp(min=0.05, max=10.0), targets)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(temperature.detach().clamp(min=0.05, max=10.0).item())


def fit_and_apply_standard_scaler(train_features, validation_features, test_features, enabled: bool):
    """Fit on training rows only, preventing validation/test distribution leakage."""
    if not enabled:
        return train_features, validation_features, test_features, None
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(train_features).astype(np.float32)
    return train_scaled, scaler.transform(validation_features).astype(np.float32), scaler.transform(test_features).astype(np.float32), scaler


def main():
    # Re-seed inside main() so 3 independent process runs are deterministic.
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    torch.cuda.manual_seed_all(SEED)

    print("=" * 80)
    print("PS 26153: DETERMINISTIC TEMPORAL GRU — MASTER PROMPT 4 COMPLIANT")
    print(f"  SEED={SEED} | label_flow: ground-truth-first priority order")
    print("=" * 80)

    data_path = os.path.join("data", "ctu13_multistage_flows.csv")
    df = pd.read_csv(data_path, low_memory=False)
    df['StartTime'] = pd.to_datetime(df['StartTime'])

    train_df, val_df, test_df = chronological_split_per_scenario(df)
    print(f"[+] Per-Scenario Chronological Split: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")
    train_sc = dict(train_df['Scenario'].value_counts())
    test_sc = dict(test_df['Scenario'].value_counts())
    print(f"    Train Scenarios: {train_sc}")
    print(f"    Test Scenarios:  {test_sc}")

    def featurize(d):
        feats = np.vstack([extract_flow_features(row) for _, row in d.iterrows()])
        labels = np.array([label_flow(row) for _, row in d.iterrows()], dtype=np.int64)
        groups = (d["Scenario"].fillna("unknown_scenario").astype(str) + "::" + d["SrcAddr"].fillna("unknown_source").astype(str)).to_numpy()
        return feats, labels, groups

    X_train, y_train, train_groups = featurize(train_df)
    X_val, y_val, val_groups = featurize(val_df)
    X_test, y_test, test_groups = featurize(test_df)
    scaler_enabled = os.environ.get("TEMPORAL_GRU_USE_STANDARD_SCALER", "0") == "1"
    X_train, X_val, X_test, scaler = fit_and_apply_standard_scaler(X_train, X_val, X_test, scaler_enabled)

    print(f"\n--- Stage Distribution Across Partitions (after label-priority fix) ---")
    train_counts = dict(zip(*np.unique(y_train, return_counts=True)))
    val_counts = dict(zip(*np.unique(y_val, return_counts=True)))
    test_counts = dict(zip(*np.unique(y_test, return_counts=True)))
    for i, name in enumerate(STAGE_NAMES):
        print(f"  {name:<26}: Train={train_counts.get(i, 0):>5} | Val={val_counts.get(i, 0):>5} | Test={test_counts.get(i, 0):>5}")

    # Verify: show Stage 5 Label composition so we can confirm C2 mislabeling is gone
    stage5_mask = y_train == 5
    if stage5_mask.sum() > 0:
        stage5_sample = train_df.iloc[:len(y_train)][stage5_mask[:len(train_df)]]['Label'].value_counts().head(10)
        print(f"\n  [VERIFY] Stage 5 Label composition in TRAIN:\n{stage5_sample}")
    stage5_test_mask = y_test == 5
    if stage5_test_mask.sum() > 0:
        stage5_test_sample = test_df.iloc[:len(y_test)][stage5_test_mask[:len(test_df)]]['Label'].value_counts().head(10)
        print(f"\n  [VERIFY] Stage 5 Label composition in TEST:\n{stage5_test_sample}")

    # seq_len and label_strategy are runtime-configurable for ablation experiments.
    # Set TEMPORAL_GRU_SEQ_LEN=5 to test the burst-length hypothesis (Task 3).
    # Set TEMPORAL_GRU_LABEL_STRATEGY=majority for majority-vote window labeling (Task 2).
    seq_len = int(os.environ.get("TEMPORAL_GRU_SEQ_LEN", "10"))
    label_strategy = os.environ.get("TEMPORAL_GRU_LABEL_STRATEGY", "next")
    if label_strategy not in ("next", "majority", "center"):
        raise ValueError(f"TEMPORAL_GRU_LABEL_STRATEGY must be next/majority/center; got {label_strategy!r}")

    model_dir = os.path.join("services", "forecasting_engine", "models")
    os.makedirs(model_dir, exist_ok=True)
    model_filename = os.environ.get("TEMPORAL_GRU_MODEL_FILENAME", "temporal_gru_forecaster.pt")
    model_path = os.path.join(model_dir, model_filename)
    artifact_stem = os.path.splitext(model_filename)[0]

    print(f"\n[CONFIG] seq_len={seq_len} | label_strategy={label_strategy!r} | model={model_filename}")

    # Oversample minority stages in TRAIN only; never across scenario/host boundary.
    train_ds = TemporalSequenceDataset(X_train, y_train, train_groups, seq_len,
                                       oversample=True, label_strategy=label_strategy)
    val_ds = TemporalSequenceDataset(X_val, y_val, val_groups, seq_len,
                                     oversample=False, label_strategy=label_strategy)
    test_ds = TemporalSequenceDataset(X_test, y_test, test_groups, seq_len,
                                      oversample=False, label_strategy=label_strategy)

    print(f"\n[+] Oversampled Train Sequences: {len(train_ds)} (scenario/source-host isolated)")


    # Master Prompt 4: DataLoader generator pinned for shuffle determinism
    _gen = torch.Generator()
    _gen.manual_seed(SEED)
    train_loader = DataLoader(train_ds, batch_size=256, shuffle=True, generator=_gen)
    val_loader = DataLoader(val_ds, batch_size=256, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=256, shuffle=False)

    device = torch.device("cpu")
    model = TemporalAttackGRU().to(device)

    # Focal loss (Lin et al. 2017):
    # Modulating factor (1 - p_t)^gamma down-weights well-classified easy examples (BENIGN)
    # and prevents them from overwhelming gradients, keeping focus on hard minority attacks.
    # p_t is computed from unweighted cross-entropy: p_t = exp(-unweighted_ce).
    # Moderate alpha scaling (square root inverse frequency of training sequences) provides
    # gentle class balancing without distorting p_t.
    seq_counts = np.array([max(1, int((train_ds.y_seq.numpy() == i).sum())) for i in range(7)], dtype=np.float32)
    inv_freq = 1.0 / np.sqrt(seq_counts)
    class_weights = torch.tensor(inv_freq / inv_freq.mean(), dtype=torch.float32)

    FOCAL_GAMMA = 2.0  # standard focal exponent

    class FocalLoss(nn.Module):
        """Focal loss with unweighted p_t calculation and outer alpha weighting."""
        def __init__(self, alpha: torch.Tensor = None, gamma: float = 2.0):
            super().__init__()
            self.alpha = alpha
            self.gamma = gamma
            self.ce = nn.CrossEntropyLoss(reduction='none')

        def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
            unweighted_ce = self.ce(logits, targets)
            p_t = torch.exp(-unweighted_ce).clamp(min=1e-6, max=1.0)
            focal_loss = ((1.0 - p_t) ** self.gamma) * unweighted_ce
            if self.alpha is not None:
                focal_loss = self.alpha[targets] * focal_loss
            return focal_loss.mean()

    criterion = FocalLoss(alpha=class_weights, gamma=FOCAL_GAMMA)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.003, weight_decay=1e-4)

    print(f"\n[*] Training GRU (Epochs=10, Batch=256, SeqLen={seq_len}, Strategy={label_strategy!r}, SEED={SEED})...")
    print(f"{'Epoch':<8} | {'Train Loss':<12} | {'Val Loss':<12} | {'Val Acc':<10} | {'Time':<8}")
    print("-" * 60)
    best_val_loss = float("inf")
    if scaler is not None:
        scaler_path = os.path.join(model_dir, f"{artifact_stem}_scaler.json")
        with open(scaler_path, "w", encoding="utf-8") as scaler_file:
            json.dump({"model_file": model_filename, "fit_split": "training_only", "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}, scaler_file, indent=2)
        print(f"[+] Saved training-only feature scaler to {scaler_path}")

    for epoch in range(1, 11):
        t0 = time.time()
        model.train()
        total_train_loss = 0.0
        for X_b, y_b in train_loader:
            optimizer.zero_grad()
            logits = model(X_b)
            loss = criterion(logits, y_b)
            loss.backward()
            optimizer.step()
            total_train_loss += loss.item() * len(y_b)
        avg_train_loss = total_train_loss / len(train_ds)

        model.eval()
        total_val_loss, correct_val = 0.0, 0
        with torch.no_grad():
            for X_b, y_b in val_loader:
                logits = model(X_b)
                loss = criterion(logits, y_b)
                total_val_loss += loss.item() * len(y_b)
                correct_val += (torch.argmax(logits, dim=1) == y_b).sum().item()
        avg_val_loss = total_val_loss / len(val_ds)
        val_acc = correct_val / len(val_ds)
        elapsed = time.time() - t0
        print(f"{epoch:<8} | {avg_train_loss:<12.4f} | {avg_val_loss:<12.4f} | {val_acc*100:<9.2f}% | {elapsed:.2f}s")
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            torch.save(model.state_dict(), model_path)

    print(f"\n[+] Saved optimal model weights to {model_path}")
    model.load_state_dict(torch.load(model_path, map_location=device, weights_only=True))
    model.eval()

    # Temperature is learned only from validation logits; test data remains untouched.
    val_logits, val_targets = [], []
    with torch.no_grad():
        for X_b, y_b in val_loader:
            val_logits.append(model(X_b))
            val_targets.append(y_b)
    val_logits_tensor = torch.cat(val_logits)
    val_targets_tensor = torch.cat(val_targets)
    temperature = fit_temperature(val_logits_tensor, val_targets_tensor)
    val_probs_before = torch.softmax(val_logits_tensor, dim=1).cpu().numpy()
    val_probs_after = torch.softmax(val_logits_tensor / temperature, dim=1).cpu().numpy()
    calibration_path = os.path.join(model_dir, f"{artifact_stem}_calibration.json")
    with open(calibration_path, "w", encoding="utf-8") as calibration_file:
        json.dump({"model_file": os.path.basename(model_path), "temperature": temperature, "fit_split": "validation", "ece_before": expected_calibration_error(val_probs_before, val_targets_tensor.numpy()), "ece_after": expected_calibration_error(val_probs_after, val_targets_tensor.numpy())}, calibration_file, indent=2)
    print(f"[+] Saved validation-only temperature calibration to {calibration_path} (T={temperature:.4f})")

    all_preds, all_targets = [], []
    with torch.no_grad():
        for X_b, y_b in test_loader:
            logits = model(X_b) / temperature
            all_preds.extend(torch.argmax(logits, dim=1).numpy())
            all_targets.extend(y_b.numpy())
    all_preds, all_targets = np.array(all_preds), np.array(all_targets)

    print("\n" + "=" * 80)
    print("HELD-OUT CHRONOLOGICAL TEST SET EVALUATION (Unseen Future Sequences)")
    print("=" * 80)
    unique_present = np.unique(np.concatenate([all_targets, all_preds]))
    names = [f"Stage {i}: {STAGE_NAMES[i]}" for i in unique_present]
    print(classification_report(all_targets, all_preds, labels=unique_present,
                                target_names=names, digits=4, zero_division=0))

    p, r, f1, _ = precision_recall_fscore_support(all_targets, all_preds, average='weighted', zero_division=0)
    print(f"Weighted Precision: {p*100:.2f}%")
    print(f"Weighted Recall:    {r*100:.2f}%")
    print(f"Weighted F1-Score:  {f1*100:.2f}%")

    cm = confusion_matrix(all_targets, all_preds, labels=list(range(7)))
    benign_total = cm[0, :].sum()
    benign_fp = cm[0, 1:].sum()
    fpr = (benign_fp / max(1, benign_total)) if benign_total > 0 else 0.0
    print(f"Benign FPR: {fpr*100:.4f}% ({benign_fp} false alarms / {benign_total} benign test flows)")
    results_path = os.path.join(model_dir, f"{artifact_stem}_evaluation.json")
    with open(results_path, "w", encoding="utf-8") as results_file:
        json.dump({"dataset": data_path, "split": "chronological_per_scenario_70_15_15", "sequence_grouping": "Scenario + SrcAddr", "standardization": "training_only_standard_scaler" if scaler is not None else "disabled", "temperature": temperature, "evaluation": evaluation_summary(all_targets, all_preds, STAGE_NAMES)}, results_file, indent=2)
    print(f"[+] Saved per-class held-out evaluation to {results_path}")
    print("=" * 80)

    # Per-stage train support table (for the final report)
    print("\n--- Per-Stage Train/Test Support ---")
    print(f"{'Stage':<28} | {'Train n':>8} | {'Test n':>7}")
    print("-" * 46)
    for i, name in enumerate(STAGE_NAMES):
        tr = train_counts.get(i, 0)
        te = test_counts.get(i, 0)
        print(f"  {name:<26} | {tr:>8} | {te:>7}")


if __name__ == "__main__":
    main()
