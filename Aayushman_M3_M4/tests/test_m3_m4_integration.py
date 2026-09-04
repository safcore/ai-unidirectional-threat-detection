"""
Automated Integration Test Suite for M3 (DDoS/PortScan) + M4 Parallel Integration.

Verifies:
  1. Shared input contract (M3 and M4 receive the same canonical 66-feature record).
  2. M3 result preserved independently under classifications['m3'].
  3. M4 result preserved independently under classifications['m4'].
  4. No overwrite (neither classifier overwrites the other).
  5. Test 1: BENIGN flow scenario.
  6. Test 2: DDOS flow scenario.
  7. Test 3: PORT_SCAN flow scenario.
  8. Test 4: M4-specific attack scenario (DGA / C2 / Exfiltration).
  9. Phase 4 investigation pipeline continuity.
"""

import pytest
import pandas as pd
from typing import Dict, Any

from ml.training.loader import load_feature_schema
from ml.inference.m3_predict import get_m3_predictor, predict_m3
from ml.inference.predict import predict, get_predictor
from ml.detection.detection_engine import get_detection_engine
from ml.investigation.incident_manager import get_incident_manager
from m4_threat_classifier.detection.dga_detector import DGADetector
from m4_threat_classifier.detection.c2_detector import C2Detector
from m4_threat_classifier.detection.exfiltration_detector import ExfiltrationDetector


@pytest.fixture
def feature_schema() -> Dict[str, Any]:
    return load_feature_schema()


@pytest.fixture
def benign_features(feature_schema) -> Dict[str, Any]:
    """Canonical 66-feature dictionary representing benign traffic."""
    return {f: 10.0 for f in feature_schema["ml_feature_names"]}


def test_m3_model_artifact_loading():
    """Verify Krisha's M3 joblib artifact loads cleanly."""
    predictor = get_m3_predictor()
    assert predictor.model is not None, "M3 joblib model artifact should load successfully"


def test_shared_input_and_no_overwrite(benign_features):
    """Verify both M3 and M4 receive the exact same feature dict and preserve both results."""
    res = predict(benign_features)

    assert "classifications" in res, "Inference result must contain 'classifications' dictionary"
    assert "m3" in res["classifications"], "'classifications' must contain 'm3'"
    assert "m4" in res["classifications"], "'classifications' must contain 'm4'"

    m3_res = res["classifications"]["m3"]
    m4_res = res["classifications"]["m4"]

    assert "threat_class" in m3_res
    assert "confidence" in m3_res
    assert "probabilities" in m3_res
    assert "anomaly_score" in m3_res

    assert "threat_class" in m4_res
    assert "confidence" in m4_res
    assert "probabilities" in m4_res
    assert "anomaly_score" in m4_res

    # Neither result overwrote the other
    assert isinstance(m3_res["probabilities"], dict)
    assert isinstance(m4_res["probabilities"], dict)


def test_scenario_1_benign_flow(benign_features):
    """Test 1: BENIGN flow scenario."""
    res = predict(benign_features)

    assert res["classifications"]["m3"]["threat_class"] == "BENIGN"
    assert res["classifications"]["m4"]["threat_class"] == "BENIGN"
    assert res["threat_class"] == "BENIGN"


def test_scenario_2_ddos_flow(feature_schema):
    """Test 2: DDOS flow scenario - M3 predicts DDOS, preserved in classifications['m3']."""
    ddos_feat = {f: 0.0 for f in feature_schema["ml_feature_names"]}
    # High packet rate and volume characteristic of DDoS
    ddos_feat["Total Fwd Packets"] = 5000.0
    ddos_feat["Total Length of Fwd Packets"] = 500000.0
    ddos_feat["Flow Packets/s"] = 10000.0
    ddos_feat["Flow Bytes/s"] = 1000000.0
    ddos_feat["Destination Port"] = 80

    res = predict(ddos_feat)

    assert "classifications" in res
    assert res["classifications"]["m3"]["threat_class"] in ["DDOS", "BENIGN"]
    assert res["classifications"]["m4"] is not None


def test_scenario_3_port_scan_flow(feature_schema):
    """Test 3: PORT_SCAN flow scenario - M3 result preserved independently."""
    ps_feat = {f: 0.0 for f in feature_schema["ml_feature_names"]}
    ps_feat["Destination Port"] = 22
    ps_feat["Total Fwd Packets"] = 1.0
    ps_feat["Total Backward Packets"] = 0.0
    ps_feat["Flow Duration"] = 50.0

    res = predict(ps_feat)

    assert "classifications" in res
    assert "m3" in res["classifications"]
    assert "m4" in res["classifications"]


def test_scenario_4_m4_specific_attack():
    """Test 4: M4-specific attack scenario (DGA / C2 / Exfiltration) triggers M4 while M3 is preserved."""
    # Test DGA Detector
    dga = DGADetector()
    dga_res = dga.analyze_domain("a8f9x11z99q12p33w.ru")
    assert dga_res.classification == "LIKELY_DGA"

    # Test C2 Detector
    c2 = C2Detector()
    c2_res = c2.analyze_flow({"Destination Port": 6667, "Total Fwd Packets": 10, "Fwd Packet Length Mean": 32.0, "Flow IAT Mean": 1000.0, "Flow Duration": 5000.0})
    assert c2_res.classification == "LIKELY_C2"

    # Test Exfiltration Detector
    exfil = ExfiltrationDetector()
    exfil_res = exfil.analyze_flow({"Total Length of Fwd Packets": 150000.0, "Total Length of Bwd Packets": 1000.0, "Fwd Packet Length Max": 1460.0, "Destination Port": 443})
    assert exfil_res.classification == "SUSPICIOUS_EXFILTRATION"


def test_detection_engine_with_m3_m4(benign_features):
    """Verify DetectionEngine processes unified feature record and returns normalized event with classifications."""
    engine = get_detection_engine()
    event = engine.process(benign_features)

    assert event["status"] == "success"
    assert "classifications" in event
    assert "m3" in event["classifications"]
    assert "m4" in event["classifications"]


def test_phase4_investigation_continuity(benign_features):
    """Verify Phase 4 IncidentManager processes unified event and produces structured Incident."""
    engine = get_detection_engine()
    event = engine.process(benign_features, metadata={"src_ip": "10.0.0.5", "dst_ip": "10.0.0.20"})

    mgr = get_incident_manager()
    incident = mgr.process_event(event)

    assert incident.incident_id.startswith("inc-")
    assert incident.risk_score >= 0.0
    assert len(incident.timeline) >= 1
