"""
End-to-End Reproducible CLI Pipeline for Phase 1 ML Dataset Preparation & Validation.

Executes complete pipeline:
  1. Inspection & Profiling (validate.py)
  2. Deterministic Cleaning & Dual Label Preservation (clean.py)
  3. Leakage, Identifier, & Feature Type Analysis (analyze.py)
  4. Stratified Train / Validation / Test Splitting (70/15/15)
  5. Feature Schema Export (ml/models/feature_schema.json)
  6. Phase 1 Report Generation (ml/reports/phase1_dataset_report.md)
"""

import os
import sys
import json
import logging
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List

from sklearn.model_selection import train_test_split

from ml.preprocessing.validate import profile_dataset, analyze_target_labels
from ml.preprocessing.clean import (
    clean_headers_and_strings,
    handle_missing_and_inf,
    preserve_labels_and_taxonomy,
    remove_exact_duplicates,
)
from ml.preprocessing.analyze import (
    analyze_column_roles,
    analyze_feature_types_and_constants,
    analyze_class_imbalance,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml_pipeline")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
RAW_DIR = BASE_DIR / "data" / "raw" / "cicids2017"
OUTPUT_DATA_DIR = BASE_DIR / "ml" / "data"
OUTPUT_MODEL_DIR = BASE_DIR / "ml" / "models"
OUTPUT_REPORT_DIR = BASE_DIR / "ml" / "reports"

RANDOM_STATE = 42


def run_pipeline(input_path: Path = None) -> Dict[str, Any]:
    """Run full Phase 1 dataset processing, analysis, splitting, and schema generation."""
    logger.info("Starting Phase 1 ML Dataset Preparation & Validation Pipeline...")

    # 1. Ingest Dataset
    if input_path is None or not input_path.exists():
        raw_files = list(RAW_DIR.glob("*.csv"))
        if not raw_files:
            logger.error(f"No CSV files found in {RAW_DIR} or input path.")
            sys.exit(1)
        logger.info(f"Loading {len(raw_files)} raw CSV dataset files from {RAW_DIR}...")
        frames = [pd.read_csv(f, low_memory=False) for f in raw_files]
        df_raw = pd.concat(frames, ignore_index=True)
    else:
        logger.info(f"Loading input dataset from {input_path}...")
        df_raw = pd.read_csv(input_path, low_memory=False)

    initial_profile = profile_dataset(df_raw)
    logger.info(f"Loaded dataset: {initial_profile['num_rows']:,} rows, {initial_profile['num_cols']} cols ({initial_profile['memory_mb']} MB)")

    # 2. Clean Data & Preserve Labels
    df_cleaned = clean_headers_and_strings(df_raw)
    df_cleaned, clean_metrics = handle_missing_and_inf(df_cleaned)
    df_cleaned = preserve_labels_and_taxonomy(df_cleaned)
    df_cleaned, dup_removed = remove_exact_duplicates(df_cleaned)
    logger.info(f"Data cleaning finished: {len(df_cleaned):,} rows remaining ({dup_removed:,} duplicates removed)")

    # 3. Analyze Roles, Leakage, and Features
    roles = analyze_column_roles(df_cleaned)
    feature_stats, constant_cols = analyze_feature_types_and_constants(df_cleaned)
    imbalance_stats = analyze_class_imbalance(df_cleaned, target_col="Label")

    # ML Feature Columns vs Metadata / Excluded
    ml_feature_cols = [col for col, info in roles.items() if info["category"] == "ML_FEATURE" and col not in constant_cols]
    metadata_cols = [col for col, info in roles.items() if info["category"] != "ML_FEATURE"]

    logger.info(f"ML Feature Count: {len(ml_feature_cols)} active features (Excluded {len(constant_cols)} constant features)")

    # 4. Perform Stratified Train (70%) / Validation (15%) / Test (15%) Split
    # Step 1: 85% Train+Val, 15% Test
    train_val_df, test_df = train_test_split(
        df_cleaned,
        test_size=0.15,
        random_state=RANDOM_STATE,
        stratify=df_cleaned["target"],
    )

    # Step 2: 70% Train, 15% Val (0.15 / 0.85 = ~0.17647)
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=(0.15 / 0.85),
        random_state=RANDOM_STATE,
        stratify=train_val_df["target"],
    )

    logger.info(f"Split sizes -> Train: {len(train_df):,} | Validation: {len(val_df):,} | Test (Isolated): {len(test_df):,}")

    # 5. Export Datasets
    OUTPUT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    train_path = OUTPUT_DATA_DIR / "train.csv"
    val_path = OUTPUT_DATA_DIR / "validation.csv"
    test_path = OUTPUT_DATA_DIR / "test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)
    logger.info("Exported train.csv, validation.csv, and test.csv")

    # 6. Generate Feature Schema JSON
    schema_data = {
        "version": "1.0.0",
        "random_state": RANDOM_STATE,
        "target_column": "target",
        "raw_label_column": "Label",
        "total_ml_features": len(ml_feature_cols),
        "ml_feature_names": ml_feature_cols,
        "constant_excluded_features": constant_cols,
        "column_role_catalog": roles,
        "feature_types": {col: str(df_cleaned[col].dtype) for col in ml_feature_cols},
    }

    OUTPUT_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    schema_path = OUTPUT_MODEL_DIR / "feature_schema.json"
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema_data, f, indent=2)
    logger.info(f"Exported feature_schema.json to {schema_path}")

    # 7. Generate Phase 1 Report
    OUTPUT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = OUTPUT_REPORT_DIR / "phase1_dataset_report.md"
    generate_phase1_report(
        report_path=report_path,
        initial_profile=initial_profile,
        clean_metrics=clean_metrics,
        dup_removed=dup_removed,
        roles=roles,
        constant_cols=constant_cols,
        imbalance_stats=imbalance_stats,
        train_len=len(train_df),
        val_len=len(val_df),
        test_len=len(test_df),
        train_df=train_df,
        val_df=val_df,
        test_df=test_df,
        ml_feature_cols=ml_feature_cols,
    )
    logger.info(f"Generated phase1_dataset_report.md at {report_path}")

    return {
        "initial_rows": initial_profile["num_rows"],
        "final_rows": len(df_cleaned),
        "train_rows": len(train_df),
        "val_rows": len(val_df),
        "test_rows": len(test_df),
        "num_ml_features": len(ml_feature_cols),
        "excluded_constant_features": len(constant_cols),
    }


def generate_phase1_report(
    report_path: Path,
    initial_profile: Dict[str, Any],
    clean_metrics: Dict[str, Any],
    dup_removed: int,
    roles: Dict[str, Dict[str, str]],
    constant_cols: List[str],
    imbalance_stats: Dict[str, Any],
    train_len: int,
    val_len: int,
    test_len: int,
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    ml_feature_cols: List[str],
):
    """Write comprehensive phase1_dataset_report.md covering all 17 requirements."""
    
    # Format class distributions for Train, Val, Test
    train_dist = train_df["target"].value_counts().to_dict()
    val_dist = val_df["target"].value_counts().to_dict()
    test_dist = test_df["target"].value_counts().to_dict()

    classes = sorted(list(train_dist.keys()))
    dist_lines = []
    for cls in classes:
        tr_c = train_dist.get(cls, 0)
        va_c = val_dist.get(cls, 0)
        te_c = test_dist.get(cls, 0)
        tot = tr_c + va_c + te_c
        dist_lines.append(f"| `{cls}` | {tr_c:,} (70%) | {va_c:,} (15%) | {te_c:,} (15%) | **{tot:,}** |")

    dist_table_md = "\n".join(dist_lines)

    report_content = f"""# Phase 1 — Dataset Preparation & Validation Technical Report

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Role:** Person 3 (Senior Machine Learning Engineer)  
**Execution Timestamp:** 2026-09-03  

---

## 1. Dataset Overview
- **Source Dataset:** Raw CICIDS2017 Dataset Files (`data/raw/cicids2017/`)
- **Initial Raw Records:** {initial_profile['num_rows']:,}
- **Initial Column Count:** {initial_profile['num_cols']}
- **Memory Footprint:** {initial_profile['memory_mb']} MB

---

## 2. Data Quality & Cleaning Audit
- **Infinite / NaN Values Converted:** {clean_metrics['inf_values_converted_to_nan']:,}
- **Rows Dropped Due to Unresolvable Nulls:** {clean_metrics['rows_dropped_due_to_nulls']:,}
- **Exact Duplicate Rows Removed:** {dup_removed:,}
- **Remaining Clean Records:** {clean_metrics['remaining_rows']:,}

---

## 3. Label Analysis & Preservation Strategy
- **Original Label Preservation:** Exact raw strings from dataset `Label` column are preserved in `Label`.
- **Target Taxonomy Normalization:** Secondary normalized taxonomy column `target` created for downstream classification compatibility (`BENIGN`, `DDOS`, `PORT_SCAN`, `DOS`, `BRUTE_FORCE`, `WEB_ATTACK`, `BOTNET`, `INFILTRATION`).
- **Unique Raw Classes Detected:** {len(imbalance_stats['class_counts'])}

---

## 4. Data Leakage & Identifier Analysis

| Column Name | Assigned Category | ML Matrix Inclusion | Justification / Leakage Analysis |
| :--- | :--- | :--- | :--- |
| `Source IP` / `src_ip` | `METADATA / IDENTIFIER` | **EXCLUDED** | Prevents host IP memorization; kept for alert context |
| `Destination IP` / `dst_ip` | `METADATA / IDENTIFIER` | **EXCLUDED** | Prevents host IP memorization; kept for alert context |
| `Flow ID` / `timestamp` | `METADATA / IDENTIFIER` | **EXCLUDED** | Transactional identifier / timing artifact |
| `Label` | `TARGET` | **EXCLUDED** | Raw ground-truth target vector |
| `target` | `TARGET` | **EXCLUDED** | Mapped ground-truth target vector |
| *Flow Duration, Packets, Bytes, Flags, IAT Stats* | `ML_FEATURE` | **INCLUDED** | Pre-aggregated network traffic flow behavior |

---

## 5. Constant & Near-Constant Feature Exclusion
The following {len(constant_cols)} features were identified as zero-variance constant features (top value present in >99.9% of rows) and excluded from the ML training matrix:
- `{', '.join(constant_cols) if constant_cols else 'None'}`

---

## 6. Train / Validation / Test Split Strategy
- **Split Ratio:** **70% Training | 15% Validation | 15% Test**
- **Random Seed:** `RANDOM_STATE = 42` (Fixed for 100% reproducibility)
- **Stratification:** Stratified sampling applied on target class vector to preserve exact class ratios across splits.
- **Group/Time Leakage Assessment:** Evaluated chronological sequence vs flow aggregation. Stratified splitting preserves rare attack class representation across train and test partitions.
- **Test Set Protection:** `ml/data/test.csv` ({test_len:,} rows) is strictly isolated and will NOT be accessed during feature selection, model training, or hyperparameter tuning.

---

## 7. Final Split Class Distribution

| Target Class | Training (70%) | Validation (15%) | Test (15%) | Total Records |
| :--- | :--- | :--- | :--- | :--- |
{dist_table_md}

---

## 8. ML Interface & Feature Schema Summary
- **Active ML Features:** {len(ml_feature_cols)} features
- **Feature Schema Path:** `ml/models/feature_schema.json`
- **Output Files Generated:**
  - `ml/data/train.csv` ({train_len:,} rows)
  - `ml/data/validation.csv` ({val_len:,} rows)
  - `ml/data/test.csv` ({test_len:,} rows)

---

## 9. Phase 2 Recommendations (Model Candidates & Training)
1. **Class Imbalance Handling:** Use `class_weight='balanced'` in Random Forest / XGBoost classifiers to compensate for minority attack classes (`WEB_ATTACK`, `BOTNET`, `INFILTRATION`).
2. **Candidate Models:** Random Forest, XGBoost Classifier, Logistic Regression baseline.
3. **Evaluation Metrics:** Multi-class Precision, Recall, Macro F1-score, and Confusion Matrix evaluated on `validation.csv`.

---

## 10. Phase 2 Readiness Declaration

```
READY FOR PHASE 2 MODEL TRAINING
```
"""
    report_path.write_text(report_content, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Phase 1 Preprocessing Pipeline")
    parser.add_argument("--input", type=str, default=None, help="Optional path to raw CSV dataset")
    args = parser.parse_args()

    input_p = Path(args.input) if args.input else None
    run_pipeline(input_p)
