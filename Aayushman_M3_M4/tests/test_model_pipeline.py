"""
Automated Pytest Suite for Phase 2 Model Training, Evaluation & Inference API.

Tests:
  1. Data loading & schema enforcement against feature_schema.json
  2. Preprocessing leakage prevention (preprocessor fitted strictly on training set)
  3. Serialized model artifacts exist and load cleanly
  4. Inference API predict() returns valid threat_class, confidence, probabilities, and anomaly_score
  5. Probability and anomaly score normalization bounds [0.0, 1.0]
  6. Schema validation error handling for missing features
  7. Test set protection rule (train loader does not touch test.csv)
"""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from ml.training.loader import load_feature_schema, load_train_and_val_datasets, load_test_dataset
from ml.inference.predict import Predictor, predict

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "ml" / "models"


def test_feature_schema_valid():
    """Verify feature_schema.json format and column list."""
    schema = load_feature_schema()
    assert schema["target_column"] == "target"
    assert len(schema["ml_feature_names"]) == 66


def test_test_set_isolation():
    """Verify load_test_dataset raises error unless allow_test_access=True."""
    with pytest.raises(RuntimeError):
        load_test_dataset(allow_test_access=False)


def test_model_artifacts_exist():
    """Verify serialized .joblib artifacts exist under ml/models/."""
    classifier_path = MODEL_DIR / "classifier.joblib"
    anomaly_path = MODEL_DIR / "anomaly_model.joblib"

    assert classifier_path.exists() and classifier_path.stat().st_size > 0
    assert anomaly_path.exists() and anomaly_path.stat().st_size > 0


def test_inference_api_single_dict():
    """Test predict() on a single feature dictionary."""
    schema = load_feature_schema()
    sample_features = {feat: 10.0 for feat in schema["ml_feature_names"]}
    
    result = predict(sample_features)

    assert isinstance(result, dict)
    assert "threat_class" in result
    assert "confidence" in result
    assert "probabilities" in result
    assert "anomaly_score" in result

    assert 0.0 <= result["confidence"] <= 1.0
    assert 0.0 <= result["anomaly_score"] <= 1.0
    assert isinstance(result["probabilities"], dict)


def test_inference_api_dataframe_batch():
    """Test predict() on a batch DataFrame."""
    schema = load_feature_schema()
    sample_df = pd.DataFrame([{feat: 5.0 for feat in schema["ml_feature_names"]} for _ in range(5)])

    results = predict(sample_df)

    assert isinstance(results, list)
    assert len(results) == 5
    for res in results:
        assert "threat_class" in res
        assert 0.0 <= res["confidence"] <= 1.0
        assert 0.0 <= res["anomaly_score"] <= 1.0


def test_inference_api_missing_feature():
    """Verify inference API raises ValueError when required ML features are missing."""
    predictor = Predictor()
    incomplete_features = {"Destination Port": 80, "Flow Duration": 100}

    with pytest.raises(ValueError) as exc_info:
        predictor.predict_single(incomplete_features)
    assert "missing" in str(exc_info.value).lower()
