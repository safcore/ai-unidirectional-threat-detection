"""
Security Evaluation Metrics and Inference Benchmarking Module.

Computes:
  - Accuracy, Macro F1/Precision/Recall, Weighted F1/Precision/Recall
  - Per-class Precision, Recall, F1, Support
  - Confusion Matrix
  - Binary Security Metrics (Attack vs BENIGN):
      * False Positive Rate (FPR): BENIGN misclassified as Attack (False Alarm)
      * False Negative Rate (FNR): Attack misclassified as BENIGN (Missed Attack)
      * FP Count & FN Count
  - Single-flow latency (ms/flow) & batch throughput (flows/sec)
"""

import time
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
)

logger = logging.getLogger(__name__)


def evaluate_classification(
    model: Any,
    X_eval: pd.DataFrame,
    y_eval: pd.Series,
    class_names: Optional[List[str]] = None,
    preprocessor: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Perform comprehensive security model evaluation on validation or test dataset.
    """
    start_time = time.time()
    if preprocessor:
        X_trans = preprocessor.transform(X_eval)
    else:
        X_trans = X_eval

    y_pred = model.predict(X_trans)
    eval_latency_sec = time.time() - start_time

    # Get unique sorted classes
    if class_names is None:
        class_names = sorted(list(set(y_eval.unique()).union(set(y_pred))))

    acc = float(accuracy_score(y_eval, y_pred))

    # Macro & Weighted metrics
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_eval, y_pred, average="macro", zero_division=0)
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(y_eval, y_pred, average="weighted", zero_division=0)

    # Per-class metrics
    p_per_class, r_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
        y_eval, y_pred, labels=class_names, average=None, zero_division=0
    )

    per_class_dict = {}
    for idx, cls_name in enumerate(class_names):
        per_class_dict[cls_name] = {
            "precision": round(float(p_per_class[idx]), 4),
            "recall": round(float(r_per_class[idx]), 4),
            "f1": round(float(f1_per_class[idx]), 4),
            "support": int(support_per_class[idx]),
        }

    # Confusion matrix
    cm = confusion_matrix(y_eval, y_pred, labels=class_names)
    cm_dict = {
        "labels": class_names,
        "matrix": cm.tolist(),
    }

    # Binary Security Metrics (BENIGN vs ATTACK)
    # Attack = 1, BENIGN = 0
    is_attack_true = (y_eval != "BENIGN")
    is_benign_pred = (y_pred == "BENIGN")
    false_negatives_count = int((is_attack_true & is_benign_pred).sum())
    total_attacks_true = int(is_attack_true.sum())
    fnr_missed_attack = round(float(false_negatives_count / total_attacks_true), 4) if total_attacks_true > 0 else 0.0

    is_benign_true = (y_eval == "BENIGN")
    is_attack_pred = (y_pred != "BENIGN")
    false_positives_count = int((is_benign_true & is_attack_pred).sum())
    total_benign_true = int(is_benign_true.sum())
    fpr_false_alarm = round(float(false_positives_count / total_benign_true), 4) if total_benign_true > 0 else 0.0

    # Overall attack recall (fraction of all attacks correctly identified as any attack class)
    is_attack_pred_any = (y_pred != "BENIGN")
    attacks_recalled = int((is_attack_true & is_attack_pred_any).sum())
    attack_recall = round(float(attacks_recalled / total_attacks_true), 4) if total_attacks_true > 0 else 0.0

    # Throughput
    num_samples = len(X_eval)
    throughput_fps = round(float(num_samples / eval_latency_sec), 2) if eval_latency_sec > 0 else 0.0
    latency_ms_per_flow = round(float((eval_latency_sec / num_samples) * 1000), 4) if num_samples > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "macro_precision": round(float(p_macro), 4),
        "macro_recall": round(float(r_macro), 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_precision": round(float(p_weighted), 4),
        "weighted_recall": round(float(r_weighted), 4),
        "weighted_f1": round(float(f1_weighted), 4),
        "attack_recall": attack_recall,
        "per_class": per_class_dict,
        "confusion_matrix": cm_dict,
        "false_negatives_count": false_negatives_count,
        "total_attacks": total_attacks_true,
        "false_negative_rate_missed_attacks": fnr_missed_attack,
        "false_positives_count": false_positives_count,
        "total_benign": total_benign_true,
        "false_positive_rate_false_alarms": fpr_false_alarm,
        "throughput_flows_per_sec": throughput_fps,
        "latency_ms_per_flow": latency_ms_per_flow,
    }


def benchmark_inference_speed(model: Any, X_sample: pd.DataFrame, preprocessor: Optional[Any] = None) -> Dict[str, float]:
    """Benchmark inference latency and throughput on a sample dataset batch."""
    if len(X_sample) == 0:
        return {"throughput_fps": 0.0, "latency_ms_per_flow": 0.0}

    if preprocessor:
        X_trans = preprocessor.transform(X_sample)
    else:
        X_trans = X_sample

    # Warmup
    _ = model.predict(X_trans[:10])

    start = time.time()
    _ = model.predict(X_trans)
    elapsed = time.time() - start

    num_samples = len(X_sample)
    fps = num_samples / elapsed if elapsed > 0 else 0.0
    ms_per_flow = (elapsed / num_samples) * 1000 if num_samples > 0 else 0.0

    return {
        "throughput_fps": round(fps, 2),
        "latency_ms_per_flow": round(ms_per_flow, 4),
        "total_batch_samples": num_samples,
        "total_batch_sec": round(elapsed, 4),
    }
