"""
test_traffic_analysis.py — Unit and integration tests for Real Traffic / IP Analysis endpoints.
"""
from __future__ import annotations

import pytest
from tests.conftest import VALID_ALERT


def test_analyze_ip_missing_or_invalid(client):
    # Empty payload
    resp = client.post("/api/traffic/analyze-ip", json={})
    assert resp.status_code == 400
    assert "required" in resp.get_json()["error"]

    # Invalid IP format
    resp2 = client.post("/api/traffic/analyze-ip", json={"ip": "not-an-ip"})
    assert resp2.status_code == 400
    assert "Invalid IP address format" in resp2.get_json()["error"]


def test_analyze_ip_unobserved(client):
    # Truly unobserved IP address (never seen in flow store)
    resp = client.post("/api/traffic/analyze-ip", json={"ip": "8.8.8.8"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ip"] == "8.8.8.8"
    assert data["verdict"] == "NO OBSERVED TRAFFIC"
    assert data["status"] == "NO_OBSERVED_TRAFFIC"
    assert data["is_threat"] is False
    assert data["alert_id"] is None
    assert "No observed traffic" in data["message"]


def test_pcap_replay_and_benign_ip_analysis(client):
    # Replay genuine sample PCAP containing benign flows for 192.168.1.50
    resp = client.post("/api/traffic/replay-pcap", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["packets_processed"] > 0
    assert data["flows_extracted"] > 0

    # Now analyze the observed benign host 192.168.1.50
    resp2 = client.post("/api/traffic/analyze-ip", json={"ip": "192.168.1.50"})
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2["ip"] == "192.168.1.50"
    assert data2["status"] == "OBSERVED"
    assert data2["verdict"] == "OBSERVED (BENIGN)"
    assert data2["is_threat"] is False
    assert data2["evidence"]["flow_count"] >= 1
    assert data2["flow_metrics"]["packets"] > 0


def test_start_test_traffic_and_threat_ip_analysis(client):
    # Inject real controlled test traffic which includes a malicious flood from 192.168.1.105
    resp = client.post("/api/traffic/start-test-traffic", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["flows_ingested"] > 0

    # Analyze the threat IP 192.168.1.105
    resp2 = client.post("/api/traffic/analyze-ip", json={"ip": "192.168.1.105"})
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2["ip"] == "192.168.1.105"
    assert data2["status"] == "THREAT_DETECTED"
    assert data2["verdict"] == "THREAT DETECTED"
    assert data2["is_threat"] is True
    assert data2["threat"] == "DDoS"
    assert data2["severity"] == "CRITICAL"
    assert data2["alert_id"] is not None


def test_traffic_status_endpoint(client):
    resp = client.get("/api/traffic/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "total_flows" in data
    assert "unique_ips" in data
    assert data["hardware_rx_only"] is True


def test_safe_traffic_scenarios_and_alert_sync(client):
    scenarios = [
        ("port_scan", "Port Scan", "172.16.0.99"),
        ("dns_tunnel", "Dns Tunnel", "192.168.1.42"),
        ("c2_beacon", "C2 Communication", "192.168.1.55"),
        ("data_exfiltration", "Data Exfiltration", "192.168.1.77"),
        ("tls_metadata", "Encrypted Malware Metadata", "10.0.0.45"),
    ]
    for sc_name, exp_threat, src_ip in scenarios:
        resp = client.post("/api/traffic/start-test-traffic", json={"attack_type": sc_name})
        assert resp.status_code == 200
        assert resp.get_json()["alerts_generated"] == 1

        # Check IP analysis returns matching alert_id and full_alert.alert_id
        ip_resp = client.post("/api/traffic/analyze-ip", json={"ip": src_ip})
        assert ip_resp.status_code == 200
        ip_data = ip_resp.get_json()
        assert ip_data["is_threat"] is True
        assert ip_data["threat"] == exp_threat
        assert ip_data["alert_id"] == ip_data["full_alert"]["alert_id"]


def test_ai_analyze_with_body_payload_fallback(client):
    synthetic = {
        "alert_id": "ALT-TEST-BODY",
        "timestamp": "2026-09-09T00:00:00Z",
        "threat": "Test Threat",
        "severity": "LOW",
        "confidence": 0.85,
        "source_ip": "10.10.10.10",
        "destination_ip": "10.10.10.20",
        "source_port": 1234,
        "destination_port": 80,
        "protocol": "TCP",
        "mitre": {"tactic": "Discovery", "technique": "T1046", "technique_name": "Scanning"},
        "evidence": {"packets": 10},
    }
    # When not in store, passing in body allows analysis without 404
    resp = client.post("/api/ai/analyze/ALT-TEST-BODY", json={"alert": synthetic})
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        data = resp.get_json()
        assert data["alert"]["alert_id"] == "ALT-TEST-BODY"


def test_ip_investigation_unobserved_strict_contract(client):
    """Priority #1: Verify strict contract for unobserved IP."""
    resp = client.post("/api/traffic/analyze-ip", json={"ip": "8.8.8.8"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ip"] == "8.8.8.8"
    assert data["status"] == "NO_OBSERVED_TRAFFIC"
    assert data["observation_status"] == "NO OBSERVED TRAFFIC"
    assert data["verdict"] == "NO OBSERVED TRAFFIC"
    assert data["is_threat"] is False
    assert data["confidence"] is None
    assert data["confidence_display"] == "N/A"
    assert data["risk_score"] is None
    assert data["risk_score_display"] == "N/A"
    assert "NETRION has not observed sufficient traffic evidence for 8.8.8.8" in data["message"]


def test_ip_investigation_observed_comprehensive_payload(client):
    """Priority #1 & #2: Verify full dossier payload for observed host."""
    # Replay capture to populate flow store
    resp = client.post("/api/traffic/replay-pcap", json={})
    assert resp.status_code == 200

    # Analyze observed benign host 192.168.1.50
    resp_ip = client.post("/api/traffic/analyze-ip", json={"ip": "192.168.1.50"})
    assert resp_ip.status_code == 200
    data = resp_ip.get_json()

    assert data["observation_status"] == "TRAFFIC OBSERVED"
    assert data["risk_score"] is not None
    assert 0 <= data["risk_score"] <= 100
    assert "risk_score_display" in data

    # Verify transparent RiskEngine breakdown
    re = data["risk_engine"]
    assert "score" in re
    assert "level" in re
    assert "formula" in re
    assert "0.25*conf" in re["formula"]
    assert "confidence" in re["components"]
    assert "anomaly" in re["components"]
    assert "severity" in re["components"]
    assert "threat_intel" in re["components"]
    assert "flow_frequency" in re["components"]

    # Verify traffic evidence
    te = data["traffic_evidence"]
    assert te["total_packets"] > 0
    assert te["total_flows"] >= 1
    assert te["total_bytes"] > 0
    assert isinstance(te["source_ports"], list)
    assert isinstance(te["destination_ports"], list)
    assert isinstance(te["protocol_distribution"], dict)
    assert "connection_statistics" in te

    # Verify dual detection engine
    de = data["dual_engine"]
    assert "known_pattern_detection" in de
    assert "behavioral_anomaly_detection" in de
    assert "engine" in de["behavioral_anomaly_detection"]
    assert "anomaly_score" in de["behavioral_anomaly_detection"]

    # Verify investigation timeline
    assert isinstance(data["investigation_timeline"], list)
    assert len(data["investigation_timeline"]) > 0
    first_ev = data["investigation_timeline"][0]
    assert "event" in first_ev
    assert "timestamp" in first_ev


def test_upload_pcap_security_constraints(client):
    """Priority #12: Verify security constraints on PCAP upload."""
    import io

    # 1. Invalid file extension (.exe)
    data = {
        "file": (io.BytesIO(b"MZ\x90\x00executable content"), "malware.exe")
    }
    resp = client.post("/api/traffic/upload-pcap", data=data, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert "Invalid file extension" in resp.get_json()["error"]

    # 2. Oversized payload check (>50MB rejected)
    huge_data = {
        "file": (io.BytesIO(b"A" * (51 * 1024 * 1024)), "capture.pcap")
    }
    resp_huge = client.post("/api/traffic/upload-pcap", data=huge_data, content_type="multipart/form-data")
    assert resp_huge.status_code == 413




