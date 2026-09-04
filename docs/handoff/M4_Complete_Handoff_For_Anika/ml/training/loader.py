"""
Schema-Validated Dataset Loader for Phase 2.

Loads train.csv, validation.csv (and test.csv ONLY when explicitly requested for final evaluation)
validating input against ml/models/feature_schema.json.
"""

import json
import logging
import pandas as pd
from pathlib import Path
from typing import Tuple, List, Dict, Any

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "ml" / "data"
SCHEMA_PATH = BASE_DIR / "ml" / "models" / "feature_schema.json"


def load_feature_schema() -> Dict[str, Any]:
    """Load and return feature_schema.json specification."""
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"Feature schema file missing: {SCHEMA_PATH}")
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_and_extract_features(
    df: pd.DataFrame, schema: Dict[str, Any]
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Validate input DataFrame against feature schema, extract feature matrix X and target y.
    """
    feature_names = schema["ml_feature_names"]
    target_col = schema["target_column"]

    # Header whitespace cleanup
    df.columns = df.columns.astype(str).str.strip()

    # Validate target column
    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' missing from DataFrame columns.")

    # Validate all 66 ML features exist
    missing_features = [f for f in feature_names if f not in df.columns]
    if missing_features:
        raise ValueError(f"Dataset missing {len(missing_features)} required ML features: {missing_features}")

    # Extract feature matrix X in exact schema ordering
    X = df[feature_names].copy()
    y = df[target_col].copy()

    # Confirm numeric dtypes
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    
    if X.isnull().any().any():
        null_counts = X.isnull().sum()
        null_cols = null_counts[null_counts > 0].to_dict()
        raise ValueError(f"Feature matrix contains unexpected NaN/null values after numeric conversion: {null_cols}")

    return X, y


def load_train_and_val_datasets() -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series, Dict[str, Any]]:
    """
    Load train.csv and validation.csv strictly for Phase 2 model development.
    Does NOT touch test.csv.
    """
    schema = load_feature_schema()
    train_file = DATA_DIR / "train.csv"
    val_file = DATA_DIR / "validation.csv"

    if not train_file.exists() or not val_file.exists():
        raise FileNotFoundError("train.csv or validation.csv missing from ml/data/")

    logger.info("Loading train.csv and validation.csv with schema validation...")
    df_train = pd.read_csv(train_file, low_memory=False)
    df_val = pd.read_csv(val_file, low_memory=False)

    X_train, y_train = validate_and_extract_features(df_train, schema)
    X_val, y_val = validate_and_extract_features(df_val, schema)

    logger.info(f"Loaded Train X: {X_train.shape}, y: {y_train.shape} | Val X: {X_val.shape}, y: {y_val.shape}")
    return X_train, y_train, X_val, y_val, schema


def load_test_dataset(allow_test_access: bool = False) -> Tuple[pd.DataFrame, pd.Series, Dict[str, Any]]:
    """
    Load test.csv ONLY when explicitly allowed after final model selection.
    """
    if not allow_test_access:
        raise RuntimeError(
            "Access to test.csv is forbidden during model training and tuning! "
            "Set allow_test_access=True ONLY for final unseen evaluation."
        )

    schema = load_feature_schema()
    test_file = DATA_DIR / "test.csv"
    if not test_file.exists():
        raise FileNotFoundError("test.csv missing from ml/data/")

    logger.info("Loading test.csv for FINAL UNSEEN EVALUATION...")
    df_test = pd.read_csv(test_file, low_memory=False)
    X_test, y_test = validate_and_extract_features(df_test, schema)
    return X_test, y_test, schema
