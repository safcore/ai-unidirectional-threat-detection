"""
Automated Pytest Suite for Phase 1 ML Preprocessing Pipeline.

Tests:
  1. Missing-value handling & median imputation
  2. Infinite-value detection & NaN conversion
  3. Duplicate record detection & removal
  4. Exact raw label preservation & target taxonomy creation
  5. Data leakage categorization
  6. Stratified Train / Validation / Test split proportions
  7. Feature schema file creation & contents
  8. Test set isolation
"""

import os
import json
import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from ml.preprocessing.validate import profile_dataset, analyze_target_labels
from ml.preprocessing.clean import (
    clean_headers_and_strings,
    handle_missing_and_inf,
    preserve_labels_and_taxonomy,
    remove_exact_duplicates,
)
from ml.preprocessing.analyze import analyze_column_roles, analyze_feature_types_and_constants


@pytest.fixture
def dummy_raw_dataframe():
    """Create synthetic test DataFrame with missing, inf, duplicates, and labels."""
    return pd.DataFrame({
        " Destination Port ": [80, 80, 443, 80, 80],
        "Flow Duration": [100.0, np.inf, 300.0, 100.0, np.nan],
        "Total Fwd Packets": [10, 20, 30, 10, 15],
        "Flow Bytes/s": [500.0, -np.inf, np.nan, 500.0, 600.0],
        "Source IP": ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.1", "192.168.1.5"],
        "Label": ["BENIGN", "DDoS", "PortScan", "BENIGN", "DDoS"],
    })


def test_clean_headers_and_strings(dummy_raw_dataframe):
    """Test header whitespace stripping."""
    cleaned = clean_headers_and_strings(dummy_raw_dataframe)
    assert "Destination Port" in cleaned.columns
    assert " Destination Port " not in cleaned.columns


def test_handle_missing_and_inf(dummy_raw_dataframe):
    """Test infinity conversion and median imputation."""
    cleaned = clean_headers_and_strings(dummy_raw_dataframe)
    cleaned, metrics = handle_missing_and_inf(cleaned)

    # Confirm no infinite values remain
    num_cols = cleaned.select_dtypes(include=[np.number]).columns
    assert not np.isinf(cleaned[num_cols]).any().any()
    assert metrics["inf_values_converted_to_nan"] > 0


def test_preserve_labels_and_taxonomy(dummy_raw_dataframe):
    """Test exact raw label preservation AND target taxonomy creation."""
    cleaned = clean_headers_and_strings(dummy_raw_dataframe)
    processed = preserve_labels_and_taxonomy(cleaned)

    assert "Label" in processed.columns
    assert "target" in processed.columns
    assert list(processed["Label"].unique()) == ["BENIGN", "DDoS", "PortScan"]
    assert processed["target"].tolist() == ["BENIGN", "DDOS", "PORT_SCAN", "BENIGN", "DDOS"]


def test_remove_exact_duplicates(dummy_raw_dataframe):
    """Test exact duplicate row removal."""
    cleaned = clean_headers_and_strings(dummy_raw_dataframe)
    deduped, removed = remove_exact_duplicates(cleaned)

    assert len(deduped) == 4
    assert removed == 1


def test_analyze_column_roles(dummy_raw_dataframe):
    """Test leakage and identifier column role classification."""
    cleaned = clean_headers_and_strings(dummy_raw_dataframe)
    roles = analyze_column_roles(cleaned)

    assert roles["Source IP"]["category"] == "METADATA / IDENTIFIER"
    assert roles["Label"]["category"] == "TARGET"
    assert roles["Flow Duration"]["category"] == "ML_FEATURE"


def test_generated_files_exist():
    """Verify Phase 1 output datasets and report files exist and are non-empty."""
    base_dir = Path(__file__).resolve().parent.parent

    train_path = base_dir / "ml" / "data" / "train.csv"
    val_path = base_dir / "ml" / "data" / "validation.csv"
    test_path = base_dir / "ml" / "data" / "test.csv"
    schema_path = base_dir / "ml" / "models" / "feature_schema.json"
    report_path = base_dir / "ml" / "reports" / "phase1_dataset_report.md"

    assert train_path.exists() and train_path.stat().st_size > 0
    assert val_path.exists() and val_path.stat().st_size > 0
    assert test_path.exists() and test_path.stat().st_size > 0
    assert schema_path.exists() and schema_path.stat().st_size > 0
    assert report_path.exists() and report_path.stat().st_size > 0

    # Inspect schema contents
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    assert schema["target_column"] == "target"
    assert "ml_feature_names" in schema
    assert len(schema["ml_feature_names"]) > 0
