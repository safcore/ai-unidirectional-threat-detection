"""
Inference API & Predictor Module for Person 4 Handoff.

Provides single-flow and batch prediction capabilities using serialized model artifacts.
"""

import json
import joblib
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Union, List, Optional

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BASE_DIR / "ml" / "models"
SCHEMA_PATH = MODEL_DIR / "feature_schema.json"
CLASSIFIER_PATH = MODEL_DIR / "classifier.joblib"
PREPROCESSOR_PATH = MODEL_DIR / "preprocessing_pipeline.joblib"
ANOMALY_PATH = MODEL_DIR / "anomaly_model.joblib"


class Predictor:
    """
    Inference predictor wrapper loading serialized model artifacts and schema.
    """

    def __init__(self):
        self.schema = self._load_schema()
        self.feature_names = self.schema["ml_feature_names"]
        self.classifier = self._load_artifact(CLASSIFIER_PATH, "Classifier")
        self.preprocessor = self._load_artifact(PREPROCESSOR_PATH, "Preprocessor")
        self.anomaly_model = self._load_artifact(ANOMALY_PATH, "Anomaly Model")

    def _load_schema(self) -> Dict[str, Any]:
        if not SCHEMA_PATH.exists():
            raise FileNotFoundError(f"Schema file not found at {SCHEMA_PATH}")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def _load_artifact(self, path: Path, name: str) -> Any:
        if not path.exists():
            logger.warning(f"{name} artifact not found at {path}")
            return None
        return joblib.load(path)

    def predict_single(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference on a single network flow feature dictionary.

        Returns:
            Dict containing threat_class, confidence, probabilities, and anomaly_score.
        """
        df = pd.DataFrame([features])
        res = self.predict_batch(df)
        return res[0]

    def predict_batch(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Run inference on a DataFrame batch of network flow records.
        """
        df_clean = df.copy()
        df_clean.columns = df_clean.columns.astype(str).str.strip()

        # Check missing feature columns
        missing = [f for f in self.feature_names if f not in df_clean.columns]
        if missing:
            raise ValueError(f"Input data missing {len(missing)} required features: {missing}")

        # Order columns according to feature_schema.json
        X = df_clean[self.feature_names].copy()
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

        # Apply preprocessor if present
        if self.preprocessor:
            X_trans = self.preprocessor.transform(X)
        else:
            X_trans = X

        # Classifier predictions & probabilities
        preds = self.classifier.predict(X_trans)
        
        if hasattr(self.classifier, "predict_proba"):
            prob_matrix = self.classifier.predict_proba(X_trans)
            classes = list(self.classifier.classes_)
        elif hasattr(self.classifier, "model") and hasattr(self.classifier.model, "predict_proba"):
            prob_matrix = self.classifier.model.predict_proba(X_trans)
            classes = list(self.classifier.label_encoder.classes_)
        else:
            prob_matrix = None
            classes = []

        # Anomaly scores
        if self.anomaly_model:
            anom_res = self.anomaly_model.predict_anomaly(X)
            anom_scores = anom_res["normalized_anomaly_scores"]
        else:
            anom_scores = [0.0] * len(df_clean)

        results = []
        for i in range(len(df_clean)):
            pred_class = str(preds[i])
            if prob_matrix is not None:
                probs_dict = {str(classes[j]): round(float(prob_matrix[i][j]), 4) for j in range(len(classes))}
                confidence = round(float(np.max(prob_matrix[i])), 4)
            else:
                probs_dict = {pred_class: 1.0}
                confidence = 1.0

            results.append({
                "threat_class": pred_class,
                "confidence": confidence,
                "probabilities": probs_dict,
                "anomaly_score": round(float(anom_scores[i]), 4),
            })

        return results


# Singleton instance
_predictor_instance = None


def get_predictor() -> Predictor:
    """Get or create singleton Predictor instance."""
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = Predictor()
    return _predictor_instance


def predict(features: Union[Dict[str, Any], pd.DataFrame]) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Main Person 4 Handoff API function.

    Accepts a single feature dictionary or a DataFrame of flow records, returning structured prediction results.
    """
    predictor = get_predictor()
    if isinstance(features, dict):
        return predictor.predict_single(features)
    elif isinstance(features, pd.DataFrame):
        return predictor.predict_batch(features)
    else:
        raise TypeError("Input 'features' must be a dict or a pandas DataFrame.")
