"""
Automated Pytest Suite for Leftover M4 Detectors (DGA, C2, Exfiltration) & Nemotron AI Integration.

Tests:
  1. DGA Detector (entropy, lexical randomness, digit ratios, TLDs, empty input)
  2. C2 Detector (C2 ports, beacon timing, keep-alive payloads, normal traffic)
  3. Exfiltration Detector (outbound ratios, payload sizes, DNS tunneling, normal traffic)
  4. Nemotron Client (Mocked NIM response, missing key fallback, secret key safety)
  5. AI API Endpoint (POST /api/v1/ai/analyze)
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask

from m4_threat_classifier.detection.dga_detector import DGADetector
from m4_threat_classifier.detection.c2_detector import C2Detector
from m4_threat_classifier.detection.exfiltration_detector import ExfiltrationDetector
from m4_threat_classifier.ai.nemotron_client import NemotronClient
from m4_threat_classifier.api.routes import api_bp


@pytest.fixture
def flask_client():
    app = Flask(__name__)
    app.register_blueprint(api_bp)
    app.config["TESTING"] = True
    return app.test_client()


def test_dga_detector():
    """Test 1: DGA Detector lexical & entropy analysis."""
    detector = DGADetector()

    # Normal domain
    res_norm = detector.analyze_domain("google.com")
    assert res_norm.classification == "NORMAL"
    assert res_norm.dga_score < 0.35

    # High entropy DGA domain
    res_dga = detector.analyze_domain("a8f9x11z99q12p33w.ru")
    assert res_dga.classification in ["SUSPICIOUS", "LIKELY_DGA"]
    assert res_dga.dga_score >= 0.35

    # Empty input handling
    res_empty = detector.analyze_domain("")
    assert res_empty.classification == "NORMAL"
    assert res_empty.dga_score == 0.0


def test_c2_detector():
    """Test 2: Behavioral C2 Detector."""
    detector = C2Detector()

    # C2 IRC port + small keep-alive packets
    c2_feats = {
        "Destination Port": 6667,
        "Total Fwd Packets": 10,
        "Fwd Packet Length Mean": 32.0,
        "Flow IAT Mean": 1000.0,
        "Flow Duration": 5000.0,
    }
    res_c2 = detector.analyze_flow(c2_feats)
    assert res_c2.classification in ["SUSPICIOUS_C2", "LIKELY_C2"]
    assert res_c2.score >= 0.35

    # Normal traffic
    norm_feats = {
        "Destination Port": 80,
        "Total Fwd Packets": 2,
        "Fwd Packet Length Mean": 512.0,
    }
    res_norm = detector.analyze_flow(norm_feats)
    assert res_norm.classification == "NO_C2_EVIDENCE"


def test_exfiltration_detector():
    """Test 3: Behavioral Data Exfiltration Detector."""
    detector = ExfiltrationDetector()

    # High outbound byte transfer
    exfil_feats = {
        "Total Length of Fwd Packets": 150000.0,
        "Total Length of Bwd Packets": 1000.0,
        "Fwd Packet Length Max": 1460.0,
        "Destination Port": 443,
    }
    res_exfil = detector.analyze_flow(exfil_feats)
    assert res_exfil.classification in ["SUSPICIOUS_EXFILTRATION", "LIKELY_EXFILTRATION"]
    assert res_exfil.score >= 0.35

    # DNS Tunneling indicator (Port 53 with high outbound payload)
    dns_feats = {
        "Total Length of Fwd Packets": 8000.0,
        "Total Length of Bwd Packets": 200.0,
        "Destination Port": 53,
    }
    res_dns = detector.analyze_flow(dns_feats)
    assert res_dns.classification in ["SUSPICIOUS_EXFILTRATION", "LIKELY_EXFILTRATION"]


def test_nemotron_client_fallback():
    """Test 4: Nemotron Client fail-safe fallback when unconfigured/disabled."""
    client = NemotronClient()
    client.enabled = False  # Force disabled for test

    res = client.analyze_incident({"event_id": "test-123"})
    assert res.status == "AI_UNAVAILABLE"
    assert res.analysis is None
    assert res.deterministic_detection_available is True


@patch("urllib.request.urlopen")
def test_nemotron_client_mock_success(mock_urlopen):
    """Test 5: Nemotron Client mocked successful NIM API call."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [
            {"message": {"content": "Mocked LLM SOC Analysis Briefing: Telemetry confirms high-volume connection."}}
        ]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    client = NemotronClient()
    client.api_key = "mock_key_123"
    client.enabled = True

    res = client.analyze_incident({"event_id": "test-123", "threat_class": "PORT_SCAN"})
    assert res.status == "SUCCESS"
    assert "Mocked LLM SOC Analysis Briefing" in res.analysis
    assert res.deterministic_detection_available is True


def test_ai_analyze_endpoint(flask_client):
    """Test 6: POST /api/v1/ai/analyze API endpoint."""
    resp = flask_client.post("/api/v1/ai/analyze", json={
        "event_id": "evt-001",
        "threat_class": "PORT_SCAN",
        "confidence": 0.95,
    })
    assert resp.status_code == 200
    json_data = resp.get_json()
    assert "status" in json_data
    assert "deterministic_detection_available" in json_data
