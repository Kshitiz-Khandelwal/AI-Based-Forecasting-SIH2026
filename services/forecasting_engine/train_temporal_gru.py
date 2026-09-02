"""DNS Shield X-Forecast — GRU Temporal Attack Sequence Forecaster
Guarantees (Master Prompt 4 compliant):
  1. Deterministic Reproducibility: SEED=42 applied to random, numpy, torch, DataLoader generator.
  2. Genuine Chronological Per-Scenario Splitting (70/15/15) with Zero Data Leakage.
  3. Ground-truth label string checked BEFORE port-based heuristic — C2 can't be
     silently overwritten by a port-bucket guess.
  4. Minority-stage oversampling within train split only (never across boundary).
  5. Weighted CrossEntropyLoss for class imbalance.
"""
import os
import sys
import time
import random
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix

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
    def __init__(self, features, labels, seq_len=10, oversample=False):
        X_seqs, y_seqs = [], []
        for i in range(len(features) - seq_len):
            X_seqs.append(features[i:i + seq_len])
            y_seqs.append(labels[i + seq_len])

        if oversample:
            # Oversample minority attack stages WITHIN train split only.
            # Target ~1 500 sequence examples per minority class max.
            X_arr = np.array(X_seqs, dtype=np.float32)
            y_arr = np.array(y_seqs, dtype=np.int64)
            os_X, os_y = [X_arr], [y_arr]
            for c in range(1, 7):
                idx = np.where(y_arr == c)[0]
                if 0 < len(idx) < 1500:
                    reps = min(15, int(np.ceil(1500 / len(idx))))
                    for _ in range(reps):
                        os_X.append(X_arr[idx])
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
        return feats, labels

    X_train, y_train = featurize(train_df)
    X_val, y_val = featurize(val_df)
    X_test, y_test = featurize(test_df)

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

    seq_len = 10
    # Master Prompt 4: oversample minority stages in TRAIN only
    train_ds = TemporalSequenceDataset(X_train, y_train, seq_len, oversample=True)
    val_ds = TemporalSequenceDataset(X_val, y_val, seq_len, oversample=False)
    test_ds = TemporalSequenceDataset(X_test, y_test, seq_len, oversample=False)

    print(f"\n[+] Oversampled Train Sequences: {len(train_ds)} (raw: {len(X_train) - seq_len})")

    # Master Prompt 4: DataLoader generator pinned for shuffle determinism
    _gen = torch.Generator()
    _gen.manual_seed(SEED)
    train_loader = DataLoader(train_ds, batch_size=256, shuffle=True, generator=_gen)
    val_loader = DataLoader(val_ds, batch_size=256, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=256, shuffle=False)

    device = torch.device("cpu")
    model = TemporalAttackGRU().to(device)

    # Weighted loss: inverse-frequency class weights on the raw (pre-oversampling) train labels
    class_counts = np.array([train_counts.get(i, 1) for i in range(7)], dtype=np.float32)
    class_weights = torch.tensor(1.0 / (class_counts + 1e-6), dtype=torch.float32)
    class_weights = class_weights / class_weights.sum() * 7  # normalize to ~1 mean
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.003, weight_decay=1e-4)

    print(f"\n[*] Training GRU (Epochs=10, Batch=256, SeqLen=10, SEED={SEED})...")
    print(f"{'Epoch':<8} | {'Train Loss':<12} | {'Val Loss':<12} | {'Val Acc':<10} | {'Time':<8}")
    print("-" * 60)
    best_val_loss = float("inf")
    model_dir = os.path.join("services", "forecasting_engine", "models")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "temporal_gru_forecaster.pt")

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

    all_preds, all_targets = [], []
    with torch.no_grad():
        for X_b, y_b in test_loader:
            logits = model(X_b)
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
