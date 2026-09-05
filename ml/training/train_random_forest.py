"""
Random Forest Primary Classifier Trainer (Phase 2).
"""

import logging
import pandas as pd
from typing import Tuple, Any, Dict, List
from sklearn.ensemble import RandomForestClassifier
from ml.evaluation.metrics import evaluate_classification

logger = logging.getLogger(__name__)


def train_random_forest_model(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    n_estimators: int = 100,
    max_depth: int = 18,
) -> Tuple[Any, Dict[str, Any], List[Tuple[str, float]]]:
    """
    Train RandomForestClassifier primary model on X_train, y_train.
    Evaluates on X_val, y_val and computes Gini feature importances.
    """
    logger.info(f"Training Primary Model: Random Forest (n_estimators={n_estimators}, max_depth={max_depth})...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=18,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    if len(X_train) > 300000:
        sample_idx = X_train.sample(n=300000, random_state=42).index
        model.fit(X_train.loc[sample_idx], y_train.loc[sample_idx])
    else:
        model.fit(X_train, y_train)

    # Evaluate on validation
    eval_metrics = evaluate_classification(model, X_val, y_val)
    logger.info(f"Random Forest -> Macro F1: {eval_metrics['macro_f1']}, Acc: {eval_metrics['accuracy']}")

    # Feature Importance
    importances = model.feature_importances_
    feat_imp = sorted(zip(X_train.columns, importances), key=lambda x: x[1], reverse=True)

    return model, eval_metrics, feat_imp
