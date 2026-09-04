"""
Isolation Forest Unsupervised Anomaly Detector Trainer (Phase 2).

Provides complementary anomaly detection signals alongside supervised threat classification.
"""

import logging
import numpy as np
import pandas as pd
from typing import Tuple, Any, Dict
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class AnomalyDetectorPipeline:
    """
    Wrapper around IsolationForest to manage raw score extraction and normalized anomaly score calculation.
    """

    def __init__(self, n_estimators: int = 100, contamination: float = 0.1):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.model = None
        self.min_score = 0.0
        self.max_score = 1.0

    def fit(self, X: pd.DataFrame) -> "AnomalyDetectorPipeline":
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1,
        )
        if len(X) > 100000:
            sample_X = X.sample(n=100000, random_state=42)
            self.model.fit(sample_X)
            raw_scores = self.model.score_samples(sample_X)
        else:
            self.model.fit(X)
            raw_scores = self.model.score_samples(X)
        self.min_score = float(raw_scores.min())
        self.max_score = float(raw_scores.max())
        return self

    def predict_anomaly(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Compute raw anomaly scores, binary anomaly labels (-1 = anomaly, 1 = normal),
        and normalized anomaly score in range [0.0, 1.0] where 1.0 = highly anomalous.
        """
        raw_scores = self.model.score_samples(X) # Higher = more normal, Lower = more anomalous
        raw_preds = self.model.predict(X) # 1 = normal, -1 = anomaly

        # Normalize to [0.0, 1.0] where 1.0 = max anomaly severity
        score_range = self.max_score - self.min_score if (self.max_score - self.min_score) != 0 else 1.0
        normalized_scores = np.clip((self.max_score - raw_scores) / score_range, 0.0, 1.0)

        return {
            "raw_anomaly_scores": raw_scores,
            "raw_predictions": raw_preds,
            "normalized_anomaly_scores": np.round(normalized_scores, 4),
        }


def train_anomaly_detector(
    X_train: pd.DataFrame, X_val: pd.DataFrame
) -> Tuple[Any, Dict[str, Any]]:
    """
    Fit IsolationForest anomaly detector on training dataset X_train and evaluate on X_val.
    """
    logger.info("Training Anomaly Detector: Isolation Forest...")
    pipeline = AnomalyDetectorPipeline(n_estimators=100, contamination=0.1)
    pipeline.fit(X_train)

    val_results = pipeline.predict_anomaly(X_val)
    anom_count = int((val_results["raw_predictions"] == -1).sum())
    anom_pct = round(float((anom_count / len(X_val)) * 100), 2)

    logger.info(f"Isolation Forest -> Validation Anomalies Flagged: {anom_count:,} ({anom_pct}%)")

    return pipeline, {
        "validation_anomalies_count": anom_count,
        "validation_anomalies_percentage": anom_pct,
        "mean_normalized_anomaly_score": round(float(val_results["normalized_anomaly_scores"].mean()), 4),
    }
