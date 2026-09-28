"""Inference adapter for the independent M3 classifier artifact."""

from __future__ import annotations

import logging
from typing import Any

import joblib
import pandas as pd

from ml.config.m3_config import M3Config, get_m3_config


logger = logging.getLogger(__name__)


class M3Predictor:
    """Load and run the independent M3 model when its artifact is available."""

    def __init__(self, config: M3Config | None = None):
        self.config = config or get_m3_config()
        self.model = None
        if self.config.model_path.exists():
            artifact = joblib.load(self.config.model_path)
            self.model = artifact["model"] if isinstance(artifact, dict) else artifact
        else:
            logger.info("M3 artifact not present; continuing with M4 classification")

    def predict(self, features: dict[str, Any]) -> dict[str, Any] | None:
        if self.model is None:
            return None

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