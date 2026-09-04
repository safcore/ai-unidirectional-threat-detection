"""Training entry point for the independent M3 classifier."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier

from ml.config.m3_config import M3Config, get_m3_config
from ml.evaluation.metrics import evaluate_classification
from ml.training.loader import load_test_dataset
from ml.training.m3_dataset import load_m3_train_and_validation


load_m3_test_dataset = load_test_dataset


def train_m3_classifier(
    output_path: Path | None = None,
    config: M3Config | None = None,
) -> Path:
    """Train M3 on the official train split and save a new artifact."""
    config = config or get_m3_config()
    output_path = output_path or config.model_path
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing M3 artifact: {output_path}")

    train_split, validation_split, _ = load_m3_train_and_validation(
        schema_path=config.feature_schema_path
    )
    model = RandomForestClassifier(
        n_estimators=config.n_estimators,
        max_depth=config.max_depth,
        class_weight=config.class_weight,
        random_state=config.random_state,
        n_jobs=config.n_jobs,
    )
    model.fit(train_split.features, train_split.labels)

    artifact = {
        "model": model,
        "metadata": {
            "model_type": "RandomForestClassifier",
            "training_dataset": {
                "train": "ml/data/train.csv",
                "validation": "ml/data/validation.csv",
            },
            "feature_schema": str(config.feature_schema_path),
            "classes": list(config.classes),
            "training_configuration": {
                "n_estimators": config.n_estimators,
                "max_depth": config.max_depth,
                "class_weight": config.class_weight,
                "n_jobs": config.n_jobs,
                "random_state": config.random_state,
                "training_rows": len(train_split.features),
                "validation_rows": len(validation_split.features),
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)
    return output_path


def evaluate_m3_classifier(
    model_path: Path | None = None,
    config: M3Config | None = None,
    report_path: Path | None = None,
) -> dict:
    """Evaluate an existing M3 artifact once on the untouched test split."""
    config = config or get_m3_config()
    model_path = model_path or config.model_path
    if not model_path.exists():
        raise FileNotFoundError(f"M3 artifact not found: {model_path}")

    artifact = joblib.load(model_path)
    model = artifact["model"] if isinstance(artifact, dict) else artifact
    features, labels, schema = load_m3_test_dataset(allow_test_access=True)
    labels = labels.astype("string").str.strip().str.upper()
    selected = labels.isin(config.classes)
    if not selected.any():
        raise ValueError(
            f"Test split contains none of the required M3 classes {config.classes}"
        )

    metrics = evaluate_classification(
        model,
        features.loc[selected].reset_index(drop=True),
        labels.loc[selected].reset_index(drop=True),
        class_names=list(config.classes),
    )
    metrics["evaluation_split"] = "test"
    metrics["evaluated_rows"] = int(selected.sum())
    metrics["classes"] = list(config.classes)

    if report_path is not None:
        artifact_metadata = artifact.get("metadata", {}) if isinstance(artifact, dict) else {}
        report = {
            "report_type": "M3 test-set evaluation results",
            "scope_note": "These results describe this test split only and are not real-world performance claims.",
            "evaluation_dataset": "ml/data/test.csv",
            "evaluation_split": metrics["evaluation_split"],
            "evaluated_samples": metrics["evaluated_rows"],
            "evaluated_classes": metrics["classes"],
            "accuracy": metrics["accuracy"],
            "macro_precision": metrics["macro_precision"],
            "macro_recall": metrics["macro_recall"],
            "macro_f1": metrics["macro_f1"],
            "per_class_metrics": metrics["per_class"],
            "confusion_matrix": metrics["confusion_matrix"],
            "m3_model_identifier": artifact_metadata.get(
                "model_type", type(model).__name__
            ),
            "feature_schema": {
                "path": str(config.feature_schema_path),
                "version": schema.get("version"),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return metrics