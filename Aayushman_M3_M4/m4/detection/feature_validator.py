"""
Feature Schema Contract Validation Module.

Validates incoming flow feature vectors against ml/models/feature_schema.json before inference.
Produces structured FEATURE_SCHEMA_MISMATCH error reports for malformed inputs.
"""

import json
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Tuple, Union, Optional

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = BASE_DIR / "ml" / "models" / "feature_schema.json"


class FeatureValidationError(Exception):
    """Custom exception raised when feature validation fails."""
    def __init__(self, message: str, details: Dict[str, Any]):
        super().__init__(message)
        self.details = details


def load_schema() -> Dict[str, Any]:
    """Load feature schema contract from ml/models/feature_schema.json."""
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"Feature schema file missing at {SCHEMA_PATH}")
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_feature_schema(
    features: Union[Dict[str, Any], pd.DataFrame]
) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    Validate input feature dictionary or DataFrame against schema.

    Returns:
        Tuple[is_valid, validation_error_dict, cleaned_feature_dict]
    """
    schema = load_schema()
    required_features = schema["ml_feature_names"]

    # Convert DataFrame to dict if single row
    if isinstance(features, pd.DataFrame):
        if len(features) == 0:
            err = {
                "status": "error",
                "error_type": "EMPTY_INPUT_DATAFRAME",
                "message": "Input DataFrame contains 0 rows.",
            }
            return False, err, {}
        feat_dict = features.iloc[0].to_dict()
    elif isinstance(features, dict):
        feat_dict = features
    else:
        err = {
            "status": "error",
            "error_type": "INVALID_INPUT_TYPE",
            "message": f"Expected dict or DataFrame, got {type(features).__name__}.",
        }
        return False, err, {}

    # Strip whitespace from keys if string
    cleaned_dict = {str(k).strip(): v for k, v in feat_dict.items()}

    missing_features = []
    invalid_type_features = []
    nan_features = []
    inf_features = []

    for req_feat in required_features:
        if req_feat not in cleaned_dict:
            missing_features.append(req_feat)
            continue

        val = cleaned_dict[req_feat]

        # Check for NaN / None
        if val is None or (isinstance(val, float) and np.isnan(val)):
            nan_features.append(req_feat)
            continue

        # Check for Infinity
        if isinstance(val, float) and np.isinf(val):
            inf_features.append(req_feat)
            continue

        # Try numeric conversion
        try:
            float(val)
        except (ValueError, TypeError):
            invalid_type_features.append(req_feat)

    # Detect extra features
    extra_features = [k for k in cleaned_dict.keys() if k not in required_features and k not in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "Label", "target", "timestamp"]]

    if missing_features or invalid_type_features or nan_features or inf_features:
        err = {
            "status": "error",
            "error_type": "FEATURE_SCHEMA_MISMATCH",
            "missing_features": missing_features,
            "invalid_type_features": invalid_type_features,
            "nan_features": nan_features,
            "inf_features": inf_features,
            "extra_features": extra_features,
            "expected_feature_count": len(required_features),
            "provided_feature_count": len(cleaned_dict),
        }
        return False, err, {}

    return True, None, cleaned_dict
