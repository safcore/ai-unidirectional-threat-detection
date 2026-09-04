"""Deterministic end-to-end M3, M4, and M5 demonstration."""

from __future__ import annotations

import json

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from ml.config.m3_config import get_m3_config
from ml.detection.alert_generator import AlertGenerator
from ml.detection.decision_engine import DecisionEngine
from ml.detection.decision_engine import DecisionResult
from ml.detection.standardized_alert import build_standardized_alert
from ml.inference.predict import predict as predict_m4
from ml.mitre.attack_mapper import MITREAttackMapper


def _fixture_model(feature_names: tuple[str, ...]) -> RandomForestClassifier:
    rows = []
    labels = []
    for label, marker in (("BENIGN", 0.0), ("DDOS", 1.0), ("PORT_SCAN", 2.0)):
        for _ in range(3):
            rows.append([marker] * len(feature_names))
            labels.append(label)

    model = RandomForestClassifier(
        n_estimators=11,
        max_depth=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,
    )
    model.fit(pd.DataFrame(rows, columns=feature_names), labels)
    return model


def _fixture_features(feature_names: tuple[str, ...], marker: float) -> dict[str, float]:
    return {name: marker for name in feature_names}


def _run_demo(
    name: str,
    features: dict[str, float],
    m3_model: RandomForestClassifier,
    feature_names: tuple[str, ...],
    destination_port: int,
) -> dict:
    feature_frame = pd.DataFrame([features], columns=feature_names)
    m3_probabilities = m3_model.predict_proba(feature_frame)[0]
    m3_classes = [str(value) for value in m3_model.classes_]
    m3_result = {
        "threat_class": str(m3_model.predict(feature_frame)[0]),
        "confidence": round(float(max(m3_probabilities)), 4),
        "probabilities": {
            label: round(float(probability), 4)
            for label, probability in zip(m3_classes, m3_probabilities)
        },
        "anomaly_score": 0.0,
    }
    m4_result = predict_m4(features)
    selected_result = (
        m3_result
        if m3_result["threat_class"] in {"DDOS", "PORT_SCAN"}
        else m4_result
    )

    decision_result = DecisionEngine().evaluate(selected_result)
    legacy_alert = AlertGenerator().generate_alert(decision_result)
    legacy_alert_payload = legacy_alert.to_dict()
    legacy_alert_payload["alert_id"] = f"alt-demo-{name.lower()}"
    legacy_alert_payload["timestamp"] = "2026-09-03T12:00:00Z"
    event = {
        "status": "success",
        "event_id": f"demo-{name.lower()}",
        "timestamp": "2026-09-03T12:00:00Z",
        "protocol": "TCP",
        "threat_class": decision_result.threat_class,
        "decision": decision_result.decision,
        "confidence": decision_result.confidence,
        "anomaly_score": decision_result.anomaly_score,
        "decision_reason": decision_result.reason,
        "source": {"src_ip": "10.0.0.5", "src_port": 54321},
        "destination": {"dst_ip": "10.0.0.20", "dst_port": destination_port},
        "classifications": {"m3": m3_result, "m4": m4_result},
        "evidence": [decision_result.reason],
        "correlation_data": {
            "entity_id": "ent-10-0-0-5",
            "correlated_event_count": 1,
        },
        "alert": legacy_alert_payload,
    }
    standardized_alert = build_standardized_alert(event, mapper=MITREAttackMapper())

    print(f"\n=== {name} DEMONSTRATION ===")
    print("M2 feature count:", len(features))
    print("M3 prediction:", json.dumps(m3_result, sort_keys=True))
    print("M4 prediction:", json.dumps(m4_result, sort_keys=True))
    print("Normalized threat event:")
    print(json.dumps(event, indent=2, sort_keys=True))
    print("Final standardized alert JSON:")
    print(json.dumps(standardized_alert, indent=2, sort_keys=True))
    return standardized_alert


def main() -> None:
    config = get_m3_config()
    m3_model = _fixture_model(config.feature_names)
    _run_demo(
        "DDoS",
        _fixture_features(config.feature_names, 1.0),
        m3_model,
        config.feature_names,
        destination_port=80,
    )
    _run_demo(
        "PortScan",
        _fixture_features(config.feature_names, 2.0),
        m3_model,
        config.feature_names,
        destination_port=22,
    )


if __name__ == "__main__":
    main()