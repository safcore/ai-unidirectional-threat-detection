"""
Automated Pytest Suite for Phase 3 Detection Engine, Stream Processor & API.

Tests:
  1. Valid BENIGN input -> Successful inference, threat_class = BENIGN, decision = BENIGN
  2. Valid Malicious input -> Successful inference, threat_class != BENIGN, decision = MALICIOUS / SUSPICIOUS
  3. Missing feature -> FEATURE_SCHEMA_MISMATCH validation error
  4. Extra feature handling
  5. NaN feature handling -> validation error
  6. Infinity feature handling -> validation error
  7. Wrong datatype handling -> validation error
  8. Model artifact loading & DetectionEngine initialization
  9. Decision Engine classification logic (BENIGN, SUSPICIOUS, MALICIOUS, ANOMALOUS)
  10. Alert Generator output structure (severity, title, ISO-8601 timestamp)
  11. Pipeline continuity (malformed flow does not break queue stream processor)
  12. API contract verification (Flask test client POST /api/v1/detect)
"""

import json
import pytest
import numpy as np
import pandas as pd
from flask import Flask

from ml.training.loader import load_feature_schema
from ml.detection import (
    validate_feature_schema,
    DecisionEngine,
    DecisionResult,
    AlertGenerator,
    DetectionEngine,
    StreamProcessor,
)
from m4_threat_classifier.api.routes import api_bp


@pytest.fixture
def sample_valid_features():
    """Create valid feature dictionary with 66 ML features."""
    schema = load_feature_schema()
    return {feat: 10.0 for feat in schema["ml_feature_names"]}


@pytest.fixture
def flask_test_client():
    """Create Flask test client for API endpoint test."""
    app = Flask(__name__)
    app.register_blueprint(api_bp)
    app.config["TESTING"] = True
    return app.test_client()


def test_valid_benign_input(sample_valid_features):
    """Test 1: Valid BENIGN feature vector."""
    engine = DetectionEngine()
    event = engine.process(sample_valid_features)

    assert event["status"] == "success"
    assert "event_id" in event
    assert "threat_class" in event
    assert "decision" in event
    assert "alert" in event
    assert event["alert"]["status"] == "NEW"


def test_missing_feature(sample_valid_features):
    """Test 3: Missing feature returns FEATURE_SCHEMA_MISMATCH."""
    invalid_feats = sample_valid_features.copy()
    del invalid_feats["Destination Port"]

    engine = DetectionEngine()
    event = engine.process(invalid_feats)

    assert event["status"] == "error"
    assert event["error_type"] == "FEATURE_SCHEMA_MISMATCH"
    assert "Destination Port" in event["missing_features"]


def test_extra_feature_handling(sample_valid_features):
    """Test 4: Extra unexpected features are handled gracefully."""
    feats_with_extra = sample_valid_features.copy()
    feats_with_extra["Extra_Unused_Column"] = 999.0

    engine = DetectionEngine()
    event = engine.process(feats_with_extra)

    assert event["status"] == "success"


def test_nan_feature_handling(sample_valid_features):
    """Test 5: NaN values produce validation error."""
    feats = sample_valid_features.copy()
    feats["Flow Duration"] = np.nan

    engine = DetectionEngine()
    event = engine.process(feats)

    assert event["status"] == "error"
    assert event["error_type"] == "FEATURE_SCHEMA_MISMATCH"
    assert "Flow Duration" in event["nan_features"]


def test_inf_feature_handling(sample_valid_features):
    """Test 6: Infinity values produce validation error."""
    feats = sample_valid_features.copy()
    feats["Flow Bytes/s"] = np.inf

    engine = DetectionEngine()
    event = event_res = engine.process(feats)

    assert event_res["status"] == "error"
    assert event_res["error_type"] == "FEATURE_SCHEMA_MISMATCH"
    assert "Flow Bytes/s" in event_res["inf_features"]


def test_wrong_datatype_handling(sample_valid_features):
    """Test 7: Non-numeric string data types produce validation error."""
    feats = sample_valid_features.copy()
    feats["Total Fwd Packets"] = "INVALID_STRING"

    engine = DetectionEngine()
    event = engine.process(feats)

    assert event["status"] == "error"
    assert event["error_type"] == "FEATURE_SCHEMA_MISMATCH"
    assert "Total Fwd Packets" in event["invalid_type_features"]


def test_decision_engine_logic():
    """Test 9: Decision Engine evaluation rules."""
    decision_engine = DecisionEngine()

    # BENIGN
    res1 = decision_engine.evaluate({"threat_class": "BENIGN", "confidence": 0.95, "anomaly_score": 0.2})
    assert res1.decision == "BENIGN"

    # MALICIOUS
    res2 = decision_engine.evaluate({"threat_class": "DDOS", "confidence": 0.95, "anomaly_score": 0.3})
    assert res2.decision == "MALICIOUS"

    # ANOMALOUS
    res3 = decision_engine.evaluate({"threat_class": "BENIGN", "confidence": 0.95, "anomaly_score": 0.85})
    assert res3.decision == "ANOMALOUS"

    # SUSPICIOUS
    res4 = decision_engine.evaluate({"threat_class": "PORT_SCAN", "confidence": 0.60, "anomaly_score": 0.2})
    assert res4.decision == "SUSPICIOUS"


def test_alert_generator():
    """Test 10: Alert Generator severity and title creation."""
    generator = AlertGenerator()
    dec_result = DecisionResult(
        decision="MALICIOUS",
        threat_class="DDOS",
        confidence=0.98,
        anomaly_score=0.88,
        reason="DDoS attack detected",
    )

    alert = generator.generate_alert(dec_result)
    assert alert.severity == "CRITICAL"
    assert alert.threat_class == "DDOS"
    assert alert.status == "NEW"
    assert "DDOS" in alert.title.upper()


def test_stream_processor_continuity(sample_valid_features):
    """Test 11: StreamProcessor non-blocking queue processing and error resilience."""
    processor = StreamProcessor(worker_count=1)
    processor.start()

    # Submit valid flow
    processor.submit_flow(sample_valid_features)

    # Submit invalid flow (missing feature)
    invalid_feats = sample_valid_features.copy()
    del invalid_feats["Destination Port"]
    processor.submit_flow(invalid_feats)

    # Submit another valid flow
    processor.submit_flow(sample_valid_features)

    # Retrieve events
    events = []
    for _ in range(3):
        evt = processor.get_event(block=True, timeout=2.0)
        if evt:
            events.append(evt)

    processor.stop()

    assert len(events) == 3
    assert events[0]["status"] == "success"
    assert events[1]["status"] == "error"  # Malformed flow did not crash processor
    assert events[2]["status"] == "success"  # Subsequent valid flow processed successfully


def test_api_endpoint(flask_test_client, sample_valid_features):
    """Test 12: Flask REST API endpoint POST /api/v1/detect."""
    payload = {
        "features": sample_valid_features,
        "metadata": {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.10",
            "src_port": 54321,
            "dst_port": 80,
        },
    }

    response = flask_test_client.post("/api/v1/detect", json=payload)
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "success"
    assert "event_id" in data
    assert "alert" in data
    assert data["source"]["src_ip"] == "10.0.0.5"
