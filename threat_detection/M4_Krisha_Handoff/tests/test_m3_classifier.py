import json

import pandas as pd
import pytest

from ml.config.m3_config import M3Config
from ml.training.m3_dataset import M3DatasetSplit
from ml.training import train_m3_classifier as trainer_module


def test_m3_classifier_saves_model_and_metadata_without_overwriting(tmp_path, monkeypatch):
    feature_schema_path = tmp_path / "feature_schema.json"
    feature_schema_path.write_text(
        json.dumps({"ml_feature_names": ["feature"], "target_column": "target", "total_ml_features": 1}),
        encoding="utf-8",
    )
    config = M3Config(
        feature_schema_path=feature_schema_path,
        feature_names=("feature",),
        target_column="target",
        model_path=tmp_path / "m3.joblib",
        n_estimators=2,
        max_depth=2,
        n_jobs=1,
    )
    split = M3DatasetSplit(
        features=pd.DataFrame({"feature": [0.0, 1.0, 2.0]}),
        labels=pd.Series(["BENIGN", "DDOS", "PORT_SCAN"]),
    )
    monkeypatch.setattr(
        trainer_module,
        "load_m3_train_and_validation",
        lambda schema_path: (split, split, config),
    )

    artifact_path = trainer_module.train_m3_classifier(config=config)
    artifact = trainer_module.joblib.load(artifact_path)

    assert artifact["metadata"]["model_type"] == "RandomForestClassifier"
    assert artifact["metadata"]["classes"] == ["BENIGN", "DDOS", "PORT_SCAN"]
    assert artifact["metadata"]["training_configuration"]["random_state"] == 42
    with pytest.raises(FileExistsError):
        trainer_module.train_m3_classifier(config=config)


def test_m3_evaluation_uses_test_split_and_existing_metrics(tmp_path, monkeypatch):
    feature_schema_path = tmp_path / "feature_schema.json"
    feature_schema_path.write_text(
        json.dumps({"ml_feature_names": ["feature"], "target_column": "target", "total_ml_features": 1}),
        encoding="utf-8",
    )
    config = M3Config(
        feature_schema_path=feature_schema_path,
        feature_names=("feature",),
        target_column="target",
        model_path=tmp_path / "m3.joblib",
        n_estimators=3,
        max_depth=2,
        n_jobs=1,
    )
    model = trainer_module.RandomForestClassifier(
        n_estimators=3, max_depth=2, random_state=42, n_jobs=1
    )
    model.fit(
        pd.DataFrame({"feature": [0.0, 1.0, 2.0]}),
        pd.Series(["BENIGN", "DDOS", "PORT_SCAN"]),
    )
    trainer_module.joblib.dump({"model": model}, config.model_path)
    test_features = pd.DataFrame({"feature": [0.0, 1.0, 2.0, 9.0]})
    test_labels = pd.Series(["BENIGN", "DDOS", "PORT_SCAN", "DOS"])
    monkeypatch.setattr(
        trainer_module,
        "load_m3_test_dataset",
        lambda allow_test_access: (test_features, test_labels, {}),
    )

    report_path = tmp_path / "m3_test_evaluation.json"
    metrics = trainer_module.evaluate_m3_classifier(
        config=config,
        report_path=report_path,
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report_path.exists()
    assert report["report_type"] == "M3 test-set evaluation results"
    assert report["evaluation_dataset"] == "ml/data/test.csv"
    assert report["evaluation_split"] == "test"
    assert report["evaluated_samples"] == metrics["evaluated_rows"]
    assert report["evaluated_classes"] == metrics["classes"]
    assert report["accuracy"] == metrics["accuracy"]
    assert report["macro_precision"] == metrics["macro_precision"]
    assert report["macro_recall"] == metrics["macro_recall"]
    assert report["macro_f1"] == metrics["macro_f1"]
    assert report["per_class_metrics"] == metrics["per_class"]
    assert report["confusion_matrix"] == metrics["confusion_matrix"]
    assert "not real-world performance claims" in report["scope_note"]
    assert metrics["evaluation_split"] == "test"
    assert metrics["evaluated_rows"] == 3
    assert metrics["classes"] == ["BENIGN", "DDOS", "PORT_SCAN"]
    assert "accuracy" in metrics
    assert "macro_precision" in metrics
    assert "macro_recall" in metrics
    assert "macro_f1" in metrics
    assert set(metrics["per_class"]) == {"BENIGN", "DDOS", "PORT_SCAN"}
    assert metrics["confusion_matrix"]["labels"] == ["BENIGN", "DDOS", "PORT_SCAN"]