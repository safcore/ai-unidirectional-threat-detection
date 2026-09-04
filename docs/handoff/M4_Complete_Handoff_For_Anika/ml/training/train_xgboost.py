"""
XGBoost Comparison Classifier Trainer (Phase 2).
"""

import logging
import pandas as pd
from typing import Tuple, Any, Dict, Optional
from sklearn.preprocessing import LabelEncoder
from ml.evaluation.metrics import evaluate_classification

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

logger = logging.getLogger(__name__)


class XGBoostPipelineWrapper:
    """
    Wrapper around XGBClassifier that manages label encoding for string target classes.
    """

    def __init__(self, n_estimators: int = 100, max_depth: int = 8, learning_rate: float = 0.1):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.label_encoder = LabelEncoder()
        self.model = None

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "XGBoostPipelineWrapper":
        y_encoded = self.label_encoder.fit_transform(y)
        num_classes = len(self.label_encoder.classes_)

        self.model = xgb.XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            objective="multi:softprob",
            num_class=num_classes,
            random_state=42,
            n_jobs=-1,
            eval_metric="mlogloss",
        )
        if len(X) > 200000:
            sample_idx = X.sample(n=200000, random_state=42).index
            self.model.fit(X.loc[sample_idx], y_encoded[sample_idx])
        else:
            self.model.fit(X, y_encoded)
        return self

    def predict(self, X: pd.DataFrame) -> Any:
        preds_encoded = self.model.predict(X)
        return self.label_encoder.inverse_transform(preds_encoded)

    def predict_proba(self, X: pd.DataFrame) -> Any:
        return self.model.predict_proba(X)


def train_xgboost_model(
    X_train: pd.DataFrame, y_train: pd.Series, X_val: pd.DataFrame, y_val: pd.Series
) -> Tuple[Optional[Any], Dict[str, Any]]:
    """
    Train XGBoost comparison model on X_train, y_train if xgboost package is installed.
    """
    if not XGBOOST_AVAILABLE:
        logger.warning("XGBoost is not installed in the environment. Skipping XGBoost comparison model.")
        return None, {"available": False, "reason": "XGBoost library missing"}

    logger.info("Training Comparison Model: XGBoost (XGBClassifier)...")
    wrapper = XGBoostPipelineWrapper(n_estimators=100, max_depth=8, learning_rate=0.1)
    wrapper.fit(X_train, y_train)

    eval_metrics = evaluate_classification(wrapper, X_val, y_val)
    eval_metrics["available"] = True
    logger.info(f"XGBoost -> Macro F1: {eval_metrics['macro_f1']}, Acc: {eval_metrics['accuracy']}")

    return wrapper, eval_metrics
