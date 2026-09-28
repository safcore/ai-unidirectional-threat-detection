"""
Module 3 (M3) — Model Wrapper & Serialization
==============================================
Encapsulates the offline scikit-learn RandomForestClassifier model.
Provides deterministic serialization, inference probabilities, and metadata tracking.
"""

import json
import os
from typing import List, Optional, Dict, Any
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from .features import MODEL_FEATURE_NAMES


class ThreatClassifier:
    """
    Lightweight CPU-compatible threat classifier based on RandomForest.
    Wraps scikit-learn for multi-class classification across:
    BENIGN, SYN_FLOOD, UDP_FLOOD, PORT_SCAN.
    """

    def __init__(
        self,
        n_estimators: int = 50,
        max_depth: int = 12,
        random_state: int = 42,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.feature_names: List[str] = list(MODEL_FEATURE_NAMES)
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
            class_weight="balanced",
            n_jobs=-1,
        )
        self.classes_: List[str] = []
        self.metadata: Dict[str, Any] = {}

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "ThreatClassifier":
        """Fit the model on sanitized feature matrix X and target y."""
        X_mat = X[self.feature_names].values
        self.model.fit(X_mat, y)
        self.classes_ = [str(c) for c in self.model.classes_]
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Predict target class."""
        X_mat = X[self.feature_names].values
        return self.model.predict(X_mat)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Predict class probability distribution."""
        X_mat = X[self.feature_names].values
        return self.model.predict_proba(X_mat)

    def get_feature_importances(self) -> Dict[str, float]:
        """Returns sorted feature importances from the trained trees."""
        if not hasattr(self.model, "feature_importances_"):
            return {}
        importances = self.model.feature_importances_
        return {
            feat: round(float(imp), 5)
            for feat, imp in sorted(
                zip(self.feature_names, importances),
                key=lambda item: item[1],
                reverse=True,
            )
        }

    def save(self, model_path: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Save model artifact and accompanying metadata JSON."""
        os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
        
        # Save model bundle
        bundle = {
            "model": self.model,
            "feature_names": self.feature_names,
            "classes_": self.classes_,
        }
        joblib.dump(bundle, model_path)

        # Save metadata
        if metadata is not None:
            self.metadata = metadata
        meta_path = os.path.splitext(model_path)[0] + "_metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

    @classmethod
    def load(cls, model_path: str) -> "ThreatClassifier":
        """Load trained model and metadata."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        bundle = joblib.load(model_path)
        inst = cls()
        inst.model = bundle["model"]
        inst.feature_names = bundle.get("feature_names", list(MODEL_FEATURE_NAMES))
        inst.classes_ = bundle.get("classes_", [str(c) for c in inst.model.classes_])

        meta_path = os.path.splitext(model_path)[0] + "_metadata.json"
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                inst.metadata = json.load(f)
        return inst
