"""
Leakage, Identifier, Feature Type, and Class Imbalance Analysis Module for Phase 1.

Analyzes every column in the dataset and categorizes it into:
  - ML_FEATURE: Safe numerical/categorical feature for ML model training
  - TARGET: Ground-truth class label ('Label' / 'target')
  - METADATA / IDENTIFIER: IP addresses, Timestamps, Flow IDs (retained for traceability, excluded from ML matrix)
  - POTENTIAL_LEAKAGE / EXCLUDED: Target-derived or post-detection fields
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

# Pre-defined known identifier and metadata columns
IDENTIFIER_COLS = {
    "source ip", "src_ip", "src ip",
    "destination ip", "dst_ip", "dst ip",
    "flow id", "flow_id", "session_id",
    "timestamp", "time_stamp",
}

# Known leakage / post-detection fields
LEAKAGE_COLS = {
    "attack_name", "threat_score", "alert_severity",
    "rule_result", "analyst_verdict", "detection_flag",
}


def analyze_column_roles(df: pd.DataFrame) -> Dict[str, Dict[str, str]]:
    """
    Classify every column in the dataset into ML_FEATURE, TARGET, METADATA, IDENTIFIER, or POTENTIAL_LEAKAGE.
    """
    roles = {}
    for col in df.columns:
        col_lower = col.strip().lower()

        if col_lower in ["label", "target"]:
            roles[col] = {
                "category": "TARGET",
                "reason": "Ground truth target class label",
                "use_in_ml": "NO (Target vector)",
            }
        elif col_lower in IDENTIFIER_COLS or "ip" in col_lower and "bytes" not in col_lower and "pkts" not in col_lower:
            roles[col] = {
                "category": "METADATA / IDENTIFIER",
                "reason": "Raw host IP or flow identifier (Excluded from ML matrix to prevent memorization)",
                "use_in_ml": "NO (Metadata only)",
            }
        elif col_lower in LEAKAGE_COLS or "verdict" in col_lower or "severity" in col_lower:
            roles[col] = {
                "category": "POTENTIAL_LEAKAGE",
                "reason": "Post-detection or target-derived field",
                "use_in_ml": "NO (Excluded due to data leakage)",
            }
        else:
            roles[col] = {
                "category": "ML_FEATURE",
                "reason": "Pre-aggregated network flow measurement",
                "use_in_ml": "YES",
            }
    return roles


def analyze_feature_types_and_constants(df: pd.DataFrame) -> Tuple[Dict[str, Any], List[str]]:
    """
    Analyze numerical statistics, detect constant / near-constant features (variance == 0).
    """
    stats = {}
    constant_cols = []
    total_rows = len(df)

    numeric_df = df.select_dtypes(include=[np.number])

    for col in numeric_df.columns:
        col_series = numeric_df[col]
        num_unique = col_series.nunique()
        min_val = float(col_series.min())
        max_val = float(col_series.max())
        mean_val = float(col_series.mean())
        std_val = float(col_series.std())
        
        # Check if constant or near-constant (top value > 99.9% of rows)
        top_val_freq = col_series.value_counts(normalize=True).iloc[0] if num_unique > 0 else 1.0
        is_constant = (num_unique <= 1) or (top_val_freq >= 0.999)

        if is_constant:
            constant_cols.append(col)

        stats[col] = {
            "unique_values": num_unique,
            "min": min_val,
            "max": max_val,
            "mean": round(mean_val, 4),
            "std": round(std_val, 4),
            "top_val_frequency_pct": round(float(top_val_freq * 100), 2),
            "is_constant": is_constant,
        }

    return stats, constant_cols


def analyze_class_imbalance(df: pd.DataFrame, target_col: str = "Label") -> Dict[str, Any]:
    """
    Analyze class proportions and calculate majority-to-minority imbalance ratio.
    """
    if target_col not in df.columns:
        matches = [c for c in df.columns if c.lower() == target_col.lower()]
        target_col = matches[0] if matches else df.columns[-1]

    counts = df[target_col].value_counts()
    percentages = (df[target_col].value_counts(normalize=True) * 100).round(2)

    maj_class = counts.index[0]
    min_class = counts.index[-1]
    maj_count = int(counts.values[0])
    min_count = int(counts.values[-1])
    imbalance_ratio = round(float(maj_count / min_count), 2) if min_count > 0 else 0.0

    return {
        "target_column": target_col,
        "total_samples": len(df),
        "class_counts": counts.to_dict(),
        "class_percentages": percentages.to_dict(),
        "majority_class": maj_class,
        "minority_class": min_class,
        "majority_minority_ratio": imbalance_ratio,
        "is_severely_imbalanced": imbalance_ratio > 10.0,
    }
