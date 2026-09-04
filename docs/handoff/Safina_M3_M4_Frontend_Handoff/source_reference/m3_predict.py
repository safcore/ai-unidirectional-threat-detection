"""Inference adapter for the independent M3 DDoS and PortScan classifier."""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional

import joblib
import pandas as pd

from ml.config.m3_config import M3Config, get_m3_config


logger = logging.getLogger(__name__)


class M3Predictor:
    """Load and run the independent M3 model when its artifact is available."""

    def __init__(self, config: Optional[M3Config] = None):
        self.config = config or get_m3_config()
        self.model = None
        if self.config.model_path.exists():
            artifact = joblib.load(self.config.model_path)
            self.model = artifact["model"] if isinstance(artifact, dict) else artifact
            logger.info(f"Loaded M3 classifier model from {self.config.model_path}")
        else:
            logger.warning(f"M3 artifact not present at {self.config.model_path}")

    def predict(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.model is None:
            return None

        # Format features according to canonical 66-feature schema order
        dataframe = pd.DataFrame([{name: features[name] for name in self.config.feature_names}])
        prediction = str(self.model.predict(dataframe)[0])

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(dataframe)[0]
            classes = [str(value) for value in self.model.classes_]
            probability_map = {
                label: round(float(probability), 4)
                for label, probability in zip(classes, probabilities)
            }
            confidence = round(max(probability_map.values()), 4)
        else:
            probability_map = {prediction: 1.0}
            confidence = 1.0

        return {
            "threat_class": prediction,
            "confidence": confidence,
            "probabilities": probability_map,
            "anomaly_score": 0.0,
        }


_m3_predictor_instance = None


def get_m3_predictor() -> M3Predictor:
    global _m3_predictor_instance
    if _m3_predictor_instance is None:
        _m3_predictor_instance = M3Predictor()
    return _m3_predictor_instance


def predict_m3(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Standalone helper function to run M3 inference."""
    predictor = get_m3_predictor()
    return predictor.predict(features)
