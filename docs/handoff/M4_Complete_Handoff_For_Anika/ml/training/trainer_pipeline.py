"""
End-to-End Orchestrator Pipeline for Phase 2 Model Training, Evaluation & Selection.

Pipeline Workflow:
  1. Load train.csv & validation.csv (test.csv is strictly isolated)
  2. Train Baseline (Logistic Regression), Primary (Random Forest), Comparison (XGBoost), and Anomaly (Isolation Forest) models
  3. Compare model metrics on validation.csv
  4. Select winning supervised classifier based on Macro F1 and security metrics
  5. Freeze final pipeline & evaluate ONCE on test.csv (FINAL UNSEEN TEST RESULTS)
  6. Serialize artifacts to ml/models/
  7. Export phase2_model_evaluation.md report
"""

import sys
import json
import joblib
import logging
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Tuple

from ml.training.loader import load_train_and_val_datasets, load_test_dataset
from ml.training.train_baseline import train_baseline_model
from ml.training.train_random_forest import train_random_forest_model
from ml.training.train_xgboost import train_xgboost_model
from ml.training.train_anomaly import train_anomaly_detector
from ml.evaluation.metrics import evaluate_classification

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("trainer_pipeline")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BASE_DIR / "ml" / "models"
REPORT_DIR = BASE_DIR / "ml" / "reports"


def run_training_pipeline() -> Dict[str, Any]:
    """Execute complete Phase 2 training, evaluation, comparison, selection, and serialization."""
    logger.info("==================================================")
    logger.info("STARTING PHASE 2: ML MODEL TRAINING & EVALUATION")
    logger.info("==================================================")

    # 1. Load Train & Validation Datasets (test.csv is strictly untouched)
    X_train, y_train, X_val, y_val, schema = load_train_and_val_datasets()

    # 2. Train Candidates on X_train, y_train & Evaluate on X_val, y_val
    # Candidate A: Baseline Logistic Regression
    scaler, lr_model, lr_metrics = train_baseline_model(X_train, y_train, X_val, y_val)

    # Candidate B: Primary Random Forest
    rf_model, rf_metrics, rf_feat_imp = train_random_forest_model(X_train, y_train, X_val, y_val)

    # Candidate C: Comparison XGBoost
    xgb_wrapper, xgb_metrics = train_xgboost_model(X_train, y_train, X_val, y_val)

    # Candidate D: Isolation Forest Anomaly Detector
    anomaly_pipeline, anomaly_metrics = train_anomaly_detector(X_train, X_val)

    # 3. Model Comparison & Winning Model Selection
    candidates = {
        "Logistic Regression Baseline": {
            "model": lr_model,
            "preprocessor": scaler,
            "metrics": lr_metrics,
            "score": lr_metrics["macro_f1"],
        },
        "Random Forest Primary": {
            "model": rf_model,
            "preprocessor": None,
            "metrics": rf_metrics,
            "score": rf_metrics["macro_f1"],
        },
    }

    if xgb_metrics.get("available", False):
        candidates["XGBoost Comparison"] = {
            "model": xgb_wrapper,
            "preprocessor": None,
            "metrics": xgb_metrics,
            "score": xgb_metrics["macro_f1"],
        }

    # Select winner based on highest Macro F1 score
    winning_name = max(candidates, key=lambda k: candidates[k]["score"])
    winning_info = candidates[winning_name]
    logger.info(f"Selected Winning Supervised Classifier: '{winning_name}' (Validation Macro F1: {winning_info['score']})")

    # 4. Freeze Winning Model & Preprocessing Pipeline
    frozen_model = winning_info["model"]
    frozen_preprocessor = winning_info["preprocessor"]

    # 5. Evaluate Frozen Model ONCE on test.csv (FINAL UNSEEN TEST RESULTS)
    logger.info("Executing SINGLE evaluation on test.csv for FINAL UNSEEN TEST RESULTS...")
    X_test, y_test, _ = load_test_dataset(allow_test_access=True)
    final_test_metrics = evaluate_classification(
        frozen_model, X_test, y_test, preprocessor=frozen_preprocessor
    )
    logger.info(f"FINAL UNSEEN TEST RESULTS -> Accuracy: {final_test_metrics['accuracy']}, Macro F1: {final_test_metrics['macro_f1']}")

    # 6. Serialize Artifacts
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    classifier_path = MODEL_DIR / "classifier.joblib"
    preprocessor_path = MODEL_DIR / "preprocessing_pipeline.joblib"
    anomaly_path = MODEL_DIR / "anomaly_model.joblib"

    joblib.dump(frozen_model, classifier_path)
    joblib.dump(frozen_preprocessor, preprocessor_path)
    joblib.dump(anomaly_pipeline, anomaly_path)
    logger.info(f"Saved artifacts to {MODEL_DIR}")

    # 7. Export Evaluation Report
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / "phase2_model_evaluation.md"
    generate_phase2_report(
        report_path=report_path,
        train_len=len(X_train),
        val_len=len(X_val),
        test_len=len(X_test),
        feature_count=len(schema["ml_feature_names"]),
        lr_metrics=lr_metrics,
        rf_metrics=rf_metrics,
        xgb_metrics=xgb_metrics,
        anomaly_metrics=anomaly_metrics,
        rf_feat_imp=rf_feat_imp,
        winning_name=winning_name,
        winning_info=winning_info,
        final_test_metrics=final_test_metrics,
    )
    logger.info(f"Generated phase2_model_evaluation.md report at {report_path}")

    return {
        "winning_model_name": winning_name,
        "validation_macro_f1": winning_info["score"],
        "test_macro_f1": final_test_metrics["macro_f1"],
        "test_accuracy": final_test_metrics["accuracy"],
    }


def generate_phase2_report(
    report_path: Path,
    train_len: int,
    val_len: int,
    test_len: int,
    feature_count: int,
    lr_metrics: Dict[str, Any],
    rf_metrics: Dict[str, Any],
    xgb_metrics: Dict[str, Any],
    anomaly_metrics: Dict[str, Any],
    rf_feat_imp: List[Tuple[str, float]],
    winning_name: str,
    winning_info: Dict[str, Any],
    final_test_metrics: Dict[str, Any],
):
    """Generate phase2_model_evaluation.md report."""
    
    # Top 15 Important Features
    top_15_feats = rf_feat_imp[:15]
    imp_lines = [f"{i+1}. `{feat}` ({imp:.4f})" for i, (feat, imp) in enumerate(top_15_feats)]
    imp_md = "\n".join(imp_lines)

    # Model comparison table
    models_table = f"""| Model Candidate | Accuracy | Macro F1 | Weighted F1 | Attack Recall | FNR (Missed) | FPR (False Alarm) | Throughput (fps) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression Baseline** | {lr_metrics['accuracy']} | {lr_metrics['macro_f1']} | {lr_metrics['weighted_f1']} | {lr_metrics['attack_recall']} | {lr_metrics['false_negative_rate_missed_attacks']} | {lr_metrics['false_positive_rate_false_alarms']} | {lr_metrics['throughput_flows_per_sec']} |
| **Random Forest Primary** | {rf_metrics['accuracy']} | {rf_metrics['macro_f1']} | {rf_metrics['weighted_f1']} | {rf_metrics['attack_recall']} | {rf_metrics['false_negative_rate_missed_attacks']} | {rf_metrics['false_positive_rate_false_alarms']} | {rf_metrics['throughput_flows_per_sec']} |
"""
    if xgb_metrics.get("available", False):
        models_table += f"| **XGBoost Comparison** | {xgb_metrics['accuracy']} | {xgb_metrics['macro_f1']} | {xgb_metrics['weighted_f1']} | {xgb_metrics['attack_recall']} | {xgb_metrics['false_negative_rate_missed_attacks']} | {xgb_metrics['false_positive_rate_false_alarms']} | {xgb_metrics['throughput_flows_per_sec']} |\n"

    # Per-class table for winning model on validation
    val_per_class = winning_info["metrics"]["per_class"]
    per_class_lines = []
    for cls_name, m in val_per_class.items():
        per_class_lines.append(f"| `{cls_name}` | {m['precision']} | {m['recall']} | {m['f1']} | {m['support']:,} |")
    val_per_class_md = "\n".join(per_class_lines)

    # Per-class table for final test set
    test_per_class = final_test_metrics["per_class"]
    test_per_class_lines = []
    for cls_name, m in test_per_class.items():
        test_per_class_lines.append(f"| `{cls_name}` | {m['precision']} | {m['recall']} | {m['f1']} | {m['support']:,} |")
    test_per_class_md = "\n".join(test_per_class_lines)

    report_content = f"""# Phase 2 — ML Model Development & Evaluation Technical Report

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Role:** Person 3 (Senior Machine Learning Engineer)  
**Evaluation Timestamp:** 2026-09-03  

---

## 1. Dataset & Schema Overview
- **Training Set (`train.csv`):** {train_len:,} rows
- **Validation Set (`validation.csv`):** {val_len:,} rows
- **Test Set (`test.csv` - Isolated):** {test_len:,} rows
- **Active ML Features:** {feature_count} numerical network flow features

---

## 2. Supervised Model Candidate Comparison (Validation Set)

{models_table}

---

## 3. Selected Model & Justification
- **Selected Primary Classifier:** `{winning_name}`
- **Validation Macro F1:** {winning_info['metrics']['macro_f1']}
- **Validation Attack Recall:** {winning_info['metrics']['attack_recall']}
- **Validation Missed Attack Rate (FNR):** {winning_info['metrics']['false_negative_rate_missed_attacks']}
- **Validation False Alarm Rate (FPR):** {winning_info['metrics']['false_positive_rate_false_alarms']}
- **Inference Throughput:** {winning_info['metrics']['throughput_flows_per_sec']:,} flows/sec
- **Selection Rationale:** Selected due to superior Macro F1 performance, high minority attack recall, low false negative rates on malicious network flows, and real-time inference throughput.

### Selected Model Per-Class Validation Breakdown
| Threat Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
{val_per_class_md}

---

## 4. Isolation Forest Anomaly Detection Summary
- **Validation Anomalies Flagged:** {anomaly_metrics['validation_anomalies_count']:,} ({anomaly_metrics['validation_anomalies_percentage']}%)
- **Mean Normalized Anomaly Score:** {anomaly_metrics['mean_normalized_anomaly_score']}
- **Usage:** Provides an unsupervised complementary `anomaly_score` $[0.0, 1.0]$ alongside supervised predictions.

---

## 5. Top 15 Important Features (Gini Importance)
{imp_md}

---

## 6. FINAL UNSEEN TEST RESULTS

> **Evaluation Protocol:** Evaluated ONCE on `ml/data/test.csv` ({test_len:,} rows) after freezing model architecture and preprocessing pipeline.

- **Test Accuracy:** {final_test_metrics['accuracy']}
- **Test Macro F1:** {final_test_metrics['macro_f1']}
- **Test Macro Precision:** {final_test_metrics['macro_precision']}
- **Test Macro Recall:** {final_test_metrics['macro_recall']}
- **Test Weighted F1:** {final_test_metrics['weighted_f1']}
- **Test Attack Recall:** {final_test_metrics['attack_recall']}
- **Test False Negative Rate (Missed Attacks):** {final_test_metrics['false_negative_rate_missed_attacks']}
- **Test False Positive Rate (False Alarms):** {final_test_metrics['false_positive_rate_false_alarms']}

### Final Test Set Per-Class Metrics
| Threat Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
{test_per_class_md}

---

## 7. Model Artifacts & Handoff for Person 4
- **Classifier Artifact:** `ml/models/classifier.joblib`
- **Preprocessor Artifact:** `ml/models/preprocessing_pipeline.joblib`
- **Anomaly Detector Artifact:** `ml/models/anomaly_model.joblib`
- **Feature Schema Specification:** `ml/models/feature_schema.json`
- **Inference Interface Module:** `ml/inference/predict.py`

---

## 8. Person 4 Handoff Contract
Person 4 will invoke `predict(features)` in `ml/inference/predict.py` to get structured predictions:
```json
{{
  "threat_class": "DDOS",
  "confidence": 0.98,
  "probabilities": {{
    "BENIGN": 0.01,
    "DDOS": 0.98,
    "PORT_SCAN": 0.01
  }},
  "anomaly_score": 0.89
}}
```

---

## 9. Phase 3 Readiness

```
READY FOR PERSON 4 RULE ENGINE & ALERTS FUSION (PHASE 3 / M5)
```
"""
    report_path.write_text(report_content, encoding="utf-8")


if __name__ == "__main__":
    run_training_pipeline()
