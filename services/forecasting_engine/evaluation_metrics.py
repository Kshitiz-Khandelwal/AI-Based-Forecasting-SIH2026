"""Shared, persisted evaluation utilities for the PS #26153 forecasting models."""
from __future__ import annotations

from typing import Any, Dict, Sequence

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support


def expected_calibration_error(probabilities: np.ndarray, targets: np.ndarray, bins: int = 15) -> float:
    """Top-label ECE. Lower values indicate better confidence calibration."""
    confidences = np.max(probabilities, axis=1)
    predictions = np.argmax(probabilities, axis=1)
    correct = predictions == targets
    ece = 0.0
    for low, high in zip(np.linspace(0.0, 1.0, bins, endpoint=False), np.linspace(1.0 / bins, 1.0, bins)):
        mask = (confidences >= low) & (confidences < high if high < 1.0 else confidences <= high)
        if np.any(mask):
            ece += float(np.mean(mask)) * abs(float(np.mean(confidences[mask])) - float(np.mean(correct[mask])))
    return float(ece)


def evaluation_summary(y_true: Sequence[int], y_pred: Sequence[int], stage_names: Sequence[str]) -> Dict[str, Any]:
    """Return aggregate and per-class metrics, flagging statistically weak classes."""
    labels = list(range(len(stage_names)))
    report = classification_report(y_true, y_pred, labels=labels, target_names=list(stage_names), output_dict=True, zero_division=0)
    per_class = {}
    for name in stage_names:
        row = report[name]
        support = int(row["support"])
        per_class[name] = {
            "precision": float(row["precision"]), "recall": float(row["recall"]),
            "f1": float(row["f1-score"]), "support": support,
            "reliability": "low-sample — metric not statistically reliable" if support < 20 else "sufficient-support",
        }
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    benign_total = int(cm[0, :].sum())
    benign_fpr = float(cm[0, 1:].sum() / max(1, benign_total))
    return {"weighted": {"precision": float(precision), "recall": float(recall), "f1": float(f1)}, "benign_fpr": benign_fpr, "per_class": per_class}
