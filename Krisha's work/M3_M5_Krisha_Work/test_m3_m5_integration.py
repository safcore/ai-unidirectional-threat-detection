import json

import pandas as pd

from ml.config.m3_config import M3Config
from ml.detection.alert_generator import AlertGenerator
from ml.detection.decision_engine import DecisionResult
from ml.detection.detection_engine import DetectionEngine
from ml.detection.standardized_alert import build_standardized_alert
from ml.detection.standardized_alert import validate_standardized_alert
from ml.mitre.attack_mapper import MITREAttackMapper
from ml.training.loader import load_feature_schema
from ml.training import train_m3_classifier as trainer_module
from ml.training.m3_dataset import M3DatasetSplit
from ml.detection import stream_processor as stream_module


def test_m3_port_scan_flows_through_m5(tmp_path, monkeypatch):
    feature_schema_path = tmp_path / "feature_schema.json"
    feature_names = ["feature"]
    feature_schema_path.write_text(
        json.dumps({
            "ml_feature_names": feature_names,
            "target_column": "target",
            "total_ml_features": 1,
        }),
        encoding="utf-8",
    )
    train_split = M3DatasetSplit(
        features=pd.DataFrame({"feature": [0.0, 1.0, 2.0] * 3}),
        labels=pd.Series(["BENIGN", "DDOS", "PORT_SCAN"] * 3),
    )
    config = M3Config(
        feature_schema_path=feature_schema_path,
        feature_names=tuple(feature_names),
        target_column="target",
        model_path=tmp_path / "m3.joblib",
        n_estimators=3,
        max_depth=3,
        n_jobs=1,
    )
    monkeypatch.setattr(
        trainer_module,
        "load_m3_train_and_validation",
        lambda schema_path: (train_split, train_split, config),
    )

    artifact_path = trainer_module.train_m3_classifier(config=config)
    artifact = trainer_module.joblib.load(artifact_path)
    prediction = artifact["model"].predict_proba(pd.DataFrame({"feature": [2.0]}))[0]
    classes = list(artifact["model"].classes_)
    class_probabilities = dict(zip(classes, prediction))
    threat_class = str(artifact["model"].predict(pd.DataFrame({"feature": [2.0]}))[0])
    confidence = float(max(class_probabilities.values()))

    assert threat_class == "PORT_SCAN"
    assert confidence > 0.0

    decision = DecisionResult(
        decision="MALICIOUS",
        threat_class=threat_class,
        confidence=confidence,
        anomaly_score=0.0,
        reason="M3 classifier prediction",
    )
    legacy_alert = AlertGenerator().generate_alert(decision)
    event = {
        "status": "success",
        "event_id": "evt-m3-port-scan",
        "timestamp": "2026-09-03T12:00:00Z",
        "protocol": "TCP",
        "threat_class": threat_class,
        "decision": decision.decision,
        "confidence": confidence,
        "anomaly_score": decision.anomaly_score,
        "source": {"src_ip": "10.0.0.5", "src_port": 54321},
        "destination": {"dst_ip": "10.0.0.20", "dst_port": 80},
        "correlation_data": {
            "entity_id": "ent-10-0-0-5",
            "correlated_event_count": 1,
        },
        "alert": legacy_alert.to_dict(),
    }

    final_alert = build_standardized_alert(event, mapper=MITREAttackMapper())

    assert final_alert["threat_class"] == "PORT_SCAN"
    assert "confidence" in final_alert
    assert final_alert["evidence"]
    assert final_alert["mitre_mapping"]["technique_id"] == "T1046"
    assert final_alert["risk_score"] >= 0.0
    assert final_alert["severity"] == legacy_alert.severity
    assert {
        "alert_id", "timestamp", "source_ip", "destination_ip", "source_port",
        "destination_port", "protocol", "threat_class", "confidence", "severity",
        "risk_score", "evidence", "mitre_mapping", "ioc_data", "correlation_data",
        "ai_analysis",
    } <= final_alert.keys()


def test_stream_processor_routes_m3_result_to_m5(monkeypatch):
    engine = DetectionEngine()
    monkeypatch.setattr(
        engine.m3_predictor,
        "predict",
        lambda features: {
            "threat_class": "PORT_SCAN",
            "confidence": 0.96,
            "probabilities": {"BENIGN": 0.01, "PORT_SCAN": 0.96, "DDOS": 0.03},
            "anomaly_score": 0.0,
        },
    )
    monkeypatch.setattr(stream_module, "get_detection_engine", lambda: engine)

    processor = stream_module.StreamProcessor(max_queue_size=1, worker_count=1)
    features = {feature: 10.0 for feature in load_feature_schema()["ml_feature_names"]}
    assert processor.submit_flow(
        features,
        metadata={
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.20",
            "src_port": 54321,
            "dst_port": 80,
        },
    )

    try:
        event = processor.get_event(timeout=2.0)
    finally:
        processor.stop()

    assert event is not None
    assert event["classifications"]["m3"]["threat_class"] == "PORT_SCAN"
    assert event["threat_class"] == "PORT_SCAN"
    assert event["standardized_alert"]["mitre_mapping"]["technique_id"] == "T1046"
    assert event["standardized_alert"]["risk_score"] >= 0.0


def test_standardized_alert_validation_rejects_invalid_confidence():
    alert = {
        field: {} for field in (
            "alert_id", "timestamp", "source_ip", "destination_ip", "source_port",
            "destination_port", "protocol", "threat_class", "confidence", "severity",
            "risk_score", "evidence", "mitre_mapping", "ioc_data", "correlation_data",
            "ai_analysis",
        )
    }
    alert.update({"alert_id": "a", "threat_class": "DDOS", "confidence": 1.5,
                  "risk_score": 10.0, "evidence": []})

    try:
        validate_standardized_alert(alert)
    except ValueError as error:
        assert "confidence" in str(error)
    else:
        raise AssertionError("Invalid confidence should be rejected")