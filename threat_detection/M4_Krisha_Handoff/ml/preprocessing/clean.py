"""
Data Cleaning and Normalization Module for Phase 1.

Applies deterministic cleaning rules:
  - Whitespace trimming on headers and string values
  - Infinite value handling (np.inf / -np.inf -> NaN)
  - Missing value quantification & targeted imputation / row removal
  - Exact duplicate row removal
  - Dual label preservation (Original 'Label' string AND normalized 'target' taxonomy)
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

# Taxonomical Mapping for optional downstream target categorization
TAXONOMY_MAP = {
    "BENIGN": "BENIGN",
    "DDOS": "DDOS",
    "PORTSCAN": "PORT_SCAN",
    "DOS HULK": "DOS",
    "DOS GOLDENEYE": "DOS",
    "DOS SLOWLORIS": "DOS",
    "DOS SLOWHTTPTEST": "DOS",
    "FTP-PATATOR": "BRUTE_FORCE",
    "SSH-PATATOR": "BRUTE_FORCE",
    "WEB ATTACK \u2013 BRUTE FORCE": "WEB_ATTACK",
    "WEB ATTACK \u2013 XSS": "WEB_ATTACK",
    "WEB ATTACK \u2013 SQL INJECTION": "WEB_ATTACK",
    "WEB ATTACK - BRUTE FORCE": "WEB_ATTACK",
    "WEB ATTACK - XSS": "WEB_ATTACK",
    "WEB ATTACK - SQL INJECTION": "WEB_ATTACK",
    "BOT": "BOTNET",
    "INFILTRATION": "INFILTRATION",
    "HEARTBLEED": "OTHER_ATTACK",
}


def clean_headers_and_strings(df: pd.DataFrame) -> pd.DataFrame:
    """Strip leading/trailing whitespace from column names and string object fields."""
    cleaned = df.copy()
    cleaned.columns = cleaned.columns.astype(str).str.strip()

    for col in cleaned.select_dtypes(include=["object"]).columns:
        cleaned[col] = cleaned[col].astype(str).str.strip()

    return cleaned


def handle_missing_and_inf(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Detect and handle infinite and missing values deterministically.
    
    Returns cleaned DataFrame and detailed metrics report.
    """
    initial_rows = len(df)
    cleaned = df.copy()

    # Identify label column
    label_cols = [c for c in cleaned.columns if c.lower() == "label"]
    label_col = label_cols[0] if label_cols else "Label"

    # Replace infinite values with NaN for numeric features
    num_cols = [c for c in cleaned.select_dtypes(include=[np.number]).columns if c != label_col]
    
    inf_mask = np.isinf(cleaned[num_cols])
    inf_count_total = int(inf_mask.sum().sum())
    cleaned[num_cols] = cleaned[num_cols].replace([np.inf, -np.inf], np.nan)

    # Missing value analysis before imputation / removal
    missing_before = cleaned.isnull().sum()
    cols_with_nulls = missing_before[missing_before > 0]

    # Deterministic cleaning strategy:
    # 1. Fill missing numerical values with median of the feature if null pct < 1%
    # 2. Drop rows with unresolvable nulls or null labels
    for col in num_cols:
        null_count = cleaned[col].isnull().sum()
        if null_count > 0:
            null_pct = (null_count / initial_rows) * 100
            if null_pct < 1.0:
                median_val = cleaned[col].median()
                cleaned[col] = cleaned[col].fillna(median_val)
                logger.info(f"Imputed {null_count} missing values in column '{col}' with median {median_val}")

    # Drop any remaining rows with missing values (including missing labels)
    rows_before_drop = len(cleaned)
    cleaned = cleaned.dropna()
    rows_dropped_null = rows_before_drop - len(cleaned)

    metrics = {
        "initial_rows": initial_rows,
        "inf_values_converted_to_nan": inf_count_total,
        "cols_with_missing": cols_with_nulls.to_dict(),
        "rows_dropped_due_to_nulls": rows_dropped_null,
        "remaining_rows": len(cleaned),
    }

    return cleaned, metrics


def preserve_labels_and_taxonomy(df: pd.DataFrame) -> pd.DataFrame:
    """
    Preserve exact raw string label in 'Label' column AND add normalized 'target' taxonomy column.
    """
    cleaned = df.copy()
    label_cols = [c for c in cleaned.columns if c.lower() == "label"]
    if not label_cols:
        raise KeyError("No 'Label' column found to preserve.")
    
    label_col = label_cols[0]
    
    # Ensure exact string preservation for raw Label
    cleaned["Label"] = cleaned[label_col].astype(str).str.strip()

    # Create mapped target taxonomy column
    def map_taxonomy(raw_val: str) -> str:
        upper_val = raw_val.upper().strip()
        if upper_val in TAXONOMY_MAP:
            return TAXONOMY_MAP[upper_val]
        if "WEB ATTACK" in upper_val:
            return "WEB_ATTACK"
        if "PATATOR" in upper_val:
            return "BRUTE_FORCE"
        if "DOS" in upper_val:
            return "DOS"
        if "BENIGN" in upper_val:
            return "BENIGN"
        if "BOT" in upper_val:
            return "BOTNET"
        if "INFILTRATION" in upper_val:
            return "INFILTRATION"
        return "OTHER_ATTACK"

    cleaned["target"] = cleaned["Label"].apply(map_taxonomy)

    return cleaned


def remove_exact_duplicates(df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """Remove exact duplicate rows and return count removed."""
    initial = len(df)
    deduped = df.drop_duplicates().reset_index(drop=True)
    removed = initial - len(deduped)
    return deduped, removed
