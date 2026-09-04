"""
Data Validation and Inspection Module for Phase 1.

Performs empirical profiling on raw flow datasets:
  - Row & column counts
  - Data types & memory usage
  - Missing value counts & percentages
  - Infinite / NaN value detection
  - Duplicate record analysis
  - Class distribution of raw labels
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)


def profile_dataset(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Perform complete data profiling on input DataFrame.

    Returns dictionary containing statistical metrics.
    """
    num_rows, num_cols = df.shape
    memory_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)

    # Missing values per column
    missing_counts = df.isnull().sum()
    missing_pcts = (missing_counts / num_rows) * 100

    missing_info = {
        col: {"count": int(count), "percentage": round(float(pct), 4)}
        for col, count, pct in zip(df.columns, missing_counts, missing_pcts)
        if count > 0
    }

    # Infinite values per numerical column
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_info = {}
    for col in numeric_cols:
        inf_count = int(np.isinf(df[col]).sum())
        if inf_count > 0:
            inf_info[col] = {
                "count": inf_count,
                "percentage": round(float((inf_count / num_rows) * 100), 4),
            }

    # Exact duplicates
    duplicate_rows = int(df.duplicated().sum())

    # Data types summary
    dtypes_summary = {col: str(dtype) for col, dtype in df.dtypes.items()}

    return {
        "num_rows": num_rows,
        "num_cols": num_cols,
        "memory_mb": round(memory_mb, 2),
        "missing_info": missing_info,
        "infinite_info": inf_info,
        "duplicate_rows": duplicate_rows,
        "data_types": dtypes_summary,
    }


def analyze_target_labels(df: pd.DataFrame, label_column: str = "Label") -> Dict[str, Any]:
    """
    Analyze ground-truth target class distribution without altering original labels.
    """
    if label_column not in df.columns:
        matching_cols = [c for c in df.columns if c.strip().lower() == label_column.lower()]
        if matching_cols:
            label_column = matching_cols[0]
        else:
            raise KeyError(f"Label column '{label_column}' not found in DataFrame.")

    raw_labels = df[label_column].astype(str).str.strip()
    counts = raw_labels.value_counts()
    percentages = (raw_labels.value_counts(normalize=True) * 100).round(4)

    distribution = {
        label: {"count": int(count), "percentage": float(pct)}
        for label, count, pct in zip(counts.index, counts.values, percentages.values)
    }

    return {
        "label_column": label_column,
        "total_samples": len(raw_labels),
        "unique_classes_count": len(counts),
        "distribution": distribution,
        "majority_class": counts.index[0],
        "minority_class": counts.index[-1],
        "majority_minority_ratio": round(float(counts.values[0] / counts.values[-1]), 2),
    }
