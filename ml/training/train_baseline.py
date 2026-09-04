"""
Logistic Regression Baseline Trainer (Phase 2).

Uses StandardScaler fitted ONLY on training data.
"""

import logging
import pandas as pd
from typing import Tuple, Any, Dict
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from ml.evaluation.metrics import evaluate_classification

logger = logging.getLogger(__name__)


def train_baseline_model(
    X_train: pd.DataFrame, y_train: pd.Series, X_val: pd.DataFrame, y_val: pd.Series
) -> Tuple[Any, Any, Dict[str, Any]]:
    """
    Fit StandardScaler and LogisticRegression baseline model on X_train, y_train.
    Evaluates on X_val, y_val.
    """
    logger.info("Training Baseline Model: Logistic Regression (StandardScaler + LogisticRegression)...")

    # Fit scaler ONLY on X_train
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # Train model on scaled features (subsample 150k for fast baseline fitting if needed, or max_iter=200)
    model = LogisticRegression(
        max_iter=200,
        class_weight="balanced",
        random_state=42,
        solver="lbfgs",
    )
    if len(X_train) > 150000:
        sample_idx = X_train.sample(n=150000, random_state=42).index
        model.fit(X_train_scaled[sample_idx], y_train.iloc[sample_idx])
    else:
        model.fit(X_train_scaled, y_train)

    # Evaluate on validation
    eval_metrics = evaluate_classification(model, X_val, y_val, preprocessor=scaler)
    logger.info(f"Baseline Logistic Regression -> Macro F1: {eval_metrics['macro_f1']}, Acc: {eval_metrics['accuracy']}")

    return scaler, model, eval_metrics
