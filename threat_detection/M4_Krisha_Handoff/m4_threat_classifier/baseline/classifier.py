"""
Baseline Machine Learning Classifier Architecture.

Defines the modular classifier pipeline supporting Random Forest, XGBoost, and Logistic Regression
for threat predictions across BENIGN, DGA, C2, and DATA_EXFILTRATION classes.

NOTE: This module defines the architecture and configuration. Models will be trained only
after dataset acquisition in Phase 2.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple, List, Union
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

logger = logging.getLogger(__name__)


class BaselineThreatClassifier:
    """
    Modular classifier manager supporting Random Forest, XGBoost, and Logistic Regression.
    """

    CLASS_LABELS = {
        0: "BENIGN",
        1: "DGA",
        2: "C2",
        3: "DATA_EXFILTRATION",
    }

    def __init__(self, model_type: str = "rf", random_state: int = 42):
        """
        Initialize baseline threat classifier.

        Args:
            model_type: One of 'rf' (Random Forest), 'xgboost' (XGBoost), or 'lr' (Logistic Regression).
            random_state: Seed for reproducibility.
        """
        self.model_type = model_type.lower()
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = self._initialize_model()
        self.is_trained = False
        self.feature_names: List[str] = []

    def _initialize_model(self) -> Any:
        """Instantiate the specified scikit-learn or XGBoost model instance."""
        if self.model_type == "rf":
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                class_weight="balanced",
                random_state=self.random_state,
                n_jobs=-1,
            )
        elif self.model_type == "xgboost":
            if not XGBOOST_AVAILABLE:
                logger.warning("XGBoost not installed. Falling back to Random Forest.")
                return RandomForestClassifier(
                    n_estimators=100,
                    max_depth=15,
                    class_weight="balanced",
                    random_state=self.random_state,
                )
            return xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=self.random_state,
                eval_metric="mlogloss",
            )
        elif self.model_type == "lr":
            return LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=self.random_state,
            )
        else:
            raise ValueError(f"Unsupported model type '{self.model_type}'. Choose 'rf', 'xgboost', or 'lr'.")

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "BaselineThreatClassifier":
        """
        Train the model on feature matrix X and target labels y.

        Args:
            X: Feature matrix DataFrame.
            y: Encoded target labels Series.

        Returns:
            BaselineThreatClassifier: Self instance.
        """
        self.feature_names = list(X.columns)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_trained = True
        logger.info(f"Model ({self.model_type}) trained successfully on {X.shape[0]} samples.")
        return self

    def predict(self, X: Union[pd.DataFrame, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predict threat category and return prediction details.

        Args:
            X: Feature DataFrame or single feature dictionary.

        Returns:
            Dict containing predicted_class, confidence, and class_probabilities.
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet. Train the model or load a saved model artifact.")

        if isinstance(X, dict):
            X_df = pd.DataFrame([X])[self.feature_names]
        else:
            X_df = X[self.feature_names]

        X_scaled = self.scaler.transform(X_df)
        pred_id = int(self.model.predict(X_scaled)[0])
        probabilities = self.model.predict_proba(X_scaled)[0]

        pred_label = self.CLASS_LABELS.get(pred_id, "UNKNOWN")
        confidence = float(np.max(probabilities))

        class_probs = {self.CLASS_LABELS[i]: float(prob) for i, prob in enumerate(probabilities)}

        return {
            "predicted_class": pred_label,
            "class_id": pred_id,
            "confidence": round(confidence, 4),
            "class_probabilities": class_probs,
        }

    def save(self, filepath: str) -> None:
        """Save model pipeline state to disk."""
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained model.")
        state = {
            "model_type": self.model_type,
            "random_state": self.random_state,
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "is_trained": self.is_trained,
        }
        joblib.dump(state, filepath)
        logger.info(f"Saved model artifact to {filepath}")

    def load(self, filepath: str) -> "BaselineThreatClassifier":
        """Load model pipeline state from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        state = joblib.load(filepath)
        self.model_type = state["model_type"]
        self.random_state = state["random_state"]
        self.model = state["model"]
        self.scaler = state["scaler"]
        self.feature_names = state["feature_names"]
        self.is_trained = state["is_trained"]
        logger.info(f"Loaded model artifact from {filepath}")
        return self
