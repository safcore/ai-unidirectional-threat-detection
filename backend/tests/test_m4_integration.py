"""Focused tests for the M4-to-Flask adapter."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import app.routes as routes
import app.m4_integration as integration
import app.m2_adapter as m2_adapter


def _features() -> dict[str, float]:
    schema_path = Path(__file__).resolve().parents[2] / "ml" / "models" / "feature_schema.json"
    with schema_path.open(encoding="utf-8") as schema_file:
        names = json.load(schema_file)["ml_feature_names"]
    return {name: 0.0 for name in names}


def _result():
    event = {
        "status": "success",
        "event_id": "evt-test",
        "timestamp": "2026-09-04T00:00:00+00:00",
        "threat_class": "PORT_SCAN",
        "decision": "MALICIOUS",
        "confidence": 0.96,
        "anomaly_score": 0.81,
        "classifications": {"m3": {"threat_class": "PORT_SCAN"}, "m4": {"threat_class": "PORT_SCAN"}},
        "source": {"src_ip": "10.0.0.5", "src_port": 54321},
        "destination": {"dst_ip": "10.0.0.20", "dst_port": 80},
        "alert": {"severity": "HIGH"},
    }
    incident = SimpleNamespace(
        mitre_mappings=[], iocs=[], explanation={"summary": "test"},
        to_dict=lambda: {"incident_id": "inc-test"},
    )
    alert = {
        "alert_id": "ALT-1", "timestamp": event["timestamp"], "threat": "Port Scan",
        "severity": "HIGH", "confidence": 0.96, "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.20", "source_port": 54321, "destination_port": 80,
        "protocol": "TCP", "mitre": {"tactic": "Discovery", "technique": "T1046", "technique_name": "Network Service Scanning"},
        "evidence": {},
    }
    return event, incident, alert


@pytest.fixture
def m4_client(client, monkeypatch):
    result = _result()
    monkeypatch.setattr(routes, "process_detection", MagicMock(return_value=result))
    return client, result


def test_detect_valid_preserves_classifications_and_stores_alert(m4_client):
    client, result = m4_client
    response = client.post("/api/detect", json={"features": _features(), "metadata": {"protocol": "TCP"}})
    assert response.status_code == 200
    body = response.get_json()
    assert body["event"]["classifications"]["m3"]["threat_class"] == "PORT_SCAN"
    assert body["event"]["classifications"]["m4"]["threat_class"] == "PORT_SCAN"
    assert body["alert"]["alert_id"] == result[2]["alert_id"]
    assert client.get("/api/alerts").get_json()["count"] == 1


def test_detect_publishes_sse_alert(m4_client, monkeypatch):
    client, _ = m4_client
    broadcast = MagicMock()
    monkeypatch.setattr(routes.stream_manager, "broadcast", broadcast)
    response = client.post("/api/detect", json={"features": _features(), "metadata": {}})
    assert response.status_code == 200
    broadcast.assert_called_once()
    assert broadcast.call_args.args[0]["threat"] == "Port Scan"


def test_detect_missing_features_returns_422(client):
    response = client.post("/api/detect", json={"metadata": {}})
    assert response.status_code == 422
    assert "features" in response.get_json()["details"][0]


def test_detect_invalid_features_returns_422(client):
    response = client.post("/api/detect", json={"features": {"not-a-feature": 1}, "metadata": {}})
    assert response.status_code == 422
    assert response.get_json()["error"] == "Invalid detection request"


def test_health_reports_m4(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["m4"]["available"] is True


def test_process_detection_triggers_detection_and_investigation(monkeypatch):
    event, incident, alert = _result()
    detection_engine = MagicMock()
    detection_engine.process.return_value = event.copy()
    incident_manager = MagicMock()
    incident_manager.process_event.return_value = incident
    monkeypatch.setattr(integration, "get_detection_engine", lambda: detection_engine)
    monkeypatch.setattr(integration, "get_incident_manager", lambda: incident_manager)

    actual_event, actual_incident, actual_alert = integration.process_detection(_features(), {"src_ip": "10.0.0.5"})

    detection_engine.process.assert_called_once()
    incident_manager.process_event.assert_called_once_with(actual_event)
    assert actual_incident is incident
    assert actual_alert["source_ip"] == "10.0.0.5"


def test_local_threat_intel_fixture_values():
    from ml.threat_intelligence import LocalThreatIntelProvider

    provider = LocalThreatIntelProvider()
    assert provider.lookup_ip("10.0.0.5")["reputation"] == "MALICIOUS"
    assert provider.lookup_ip("1.1.1.1")["reputation"] == "UNKNOWN"


def test_m2_adapter_preserves_canonical_features_and_flat_metadata():
    features = _features()
    normalized_features, metadata = m2_adapter.normalize_m2_output({
        "features": features,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.20",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
    })
    assert len(normalized_features) == 66
    assert normalized_features == features
    assert metadata["src_ip"] == "10.0.0.5"
    assert metadata["protocol"] == "TCP"


def test_m2_adapter_rejects_incompatible_behavioral_extractor_output():
    with pytest.raises(m2_adapter.M2AdapterError, match="canonical 66-feature schema"):
        m2_adapter.normalize_m2_output({"features": {"flow_duration": 1.0}})


def test_process_flow_reuses_store_and_sse(monkeypatch, tmp_store):
    event, incident, alert = _result()
    monkeypatch.setattr(m2_adapter, "process_detection", MagicMock(return_value=(event, incident, alert)))
    stream = MagicMock()
    monkeypatch.setattr("app.alert_store", tmp_store)
    monkeypatch.setattr("app.stream_manager", stream)

    actual_event, actual_incident, stored = m2_adapter.process_flow({"features": _features()})

    assert actual_event is event
    assert actual_incident is incident
    assert stored["alert_id"] == alert["alert_id"]
    assert tmp_store.get_by_id(alert["alert_id"]) == alert
    stream.broadcast.assert_called_once_with(alert)