"""
Data Cleaner and Normalizer Module.

Handles cleaning of raw tabular datasets (CSV/DataFrames), imputation of missing values,
removal of infinite/NaN entries, and label encoding for BENIGN, DGA, C2, and DATA_EXFILTRATION classes.
"""

import logging
from typing import Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class DataCleaner:
    """
    Standardized cleaner for security feature DataFrames.
    """

    LABEL_MAPPING = {
        "BENIGN": 0,
        "NORMAL": 0,
        "DGA": 1,
        "C2": 2,
        "BOTNET": 2,
        "DATA_EXFILTRATION": 3,
        "EXFILTRATION": 3,
        "INFILTRATION": 3,
    }

    INV_LABEL_MAPPING = {v: k for k, v in LABEL_MAPPING.items()}

    def __init__(self, fill_strategy: str = "median"):
        """
        Initialize data cleaner.

        Args:
            fill_strategy: Strategy for handling missing numerical values ('median', 'mean', 'zero').
        """
        self.fill_strategy = fill_strategy

    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean DataFrame by replacing infinite values, handling NaNs, and trimming whitespace.

        Args:
            df: Raw Pandas DataFrame.

        Returns:
            pd.DataFrame: Cleaned DataFrame.
        """
        if df.empty:
            logger.warning("Empty DataFrame provided to DataCleaner.")
            return df.copy()

        cleaned_df = df.copy()

        # Trim string columns
        for col in cleaned_df.select_dtypes(include=["object"]).columns:
            cleaned_df[col] = cleaned_df[col].astype(str).str.strip()

        # Replace infinity/-infinity with NaN
        cleaned_df = cleaned_df.replace([np.inf, -np.inf], np.nan)

        # Impute missing values for numeric columns
        numeric_cols = cleaned_df.select_dtypes(include=[np.number]).columns
        if not numeric_cols.empty:
            if self.fill_strategy == "median":
                cleaned_df[numeric_cols] = cleaned_df[numeric_cols].fillna(cleaned_df[numeric_cols].median())
            elif self.fill_strategy == "mean":
                cleaned_df[numeric_cols] = cleaned_df[numeric_cols].fillna(cleaned_df[numeric_cols].mean())
            else:
                cleaned_df[numeric_cols] = cleaned_df[numeric_cols].fillna(0)

        return cleaned_df

    def encode_labels(self, labels: pd.Series) -> pd.Series:
        """
        Map categorical text labels to integer class IDs.

        Args:
            labels: Series of label strings.

        Returns:
            pd.Series: Integer class IDs.
        """
        normalized_labels = labels.astype(str).str.upper().str.strip()
        encoded = normalized_labels.map(self.LABEL_MAPPING)

        if encoded.isnull().any():
            unmapped = normalized_labels[encoded.isnull()].unique()
            logger.warning(f"Unmapped labels found during encoding: {unmapped}. Defaulting to BENIGN (0).")
            encoded = encoded.fillna(0)

        return encoded.astype(int)
