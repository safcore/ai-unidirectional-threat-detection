"""Comprehensive unit tests for Alert Normalization Engine."""
import pytest
from app.alert_normalizer import normalize_alert
from app.models import validate_alert


def test_normalize_valid_canonical_alert():
    raw = {
        "alert_id": "ALT-042",
        "timestamp": "2026-09-05T12:00:00Z",
        "threat": "Port Scan",
        "severity": "HIGH",
        "confidence": 0.95,
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "source_port": 45000,
        "destination_port": 80,
        "protocol": "TCP",
        "mitre": {
            "tactic": "Discovery",
            "technique": "T1046",
            "technique_name": "Network Service Scanning",
        },
        "evidence": {"packets": 100},
    }
    normalized = normalize_alert(raw)
    assert normalized["alert_id"] == "ALT-042"
    assert normalized["severity"] == "HIGH"
    assert validate_alert(normalized) == []


def test_normalize_missing_fields_repaired():
    # Only minimal threat info
    raw = {
        "threat_class": "SYN_FLOOD",
        "src_ip": "172.16.0.4",
        "dst_ip": "10.0.0.100",
    }
    normalized = normalize_alert(raw)
    assert normalized["alert_id"].startswith("ALT-")
    assert normalized["threat"] == "SYN Flood"
    assert normalized["source_ip"] == "172.16.0.4"
    assert normalized["destination_ip"] == "10.0.0.100"
    assert normalized["source_port"] == 0
    assert normalized["destination_port"] == 0
    assert normalized["protocol"] == "OTHER"
    assert normalized["mitre"]["technique"] == "T1498"
    assert isinstance(normalized["evidence"], dict)
    assert validate_alert(normalized) == []


def test_normalize_invalid_ports():
    raw = {
        "src_port": -5,
        "dst_port": 999999,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "threat": "Test",
    }
    normalized = normalize_alert(raw)
    assert normalized["source_port"] == 0
    assert normalized["destination_port"] == 0
    assert validate_alert(normalized) == []


def test_normalize_invalid_severity():
    raw = {
        "severity": "UNKNOWN_CRITICAL_LEVEL",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    normalized = normalize_alert(raw)
    assert normalized["severity"] == "LOW"
    assert validate_alert(normalized) == []


def test_normalize_invalid_confidence():
    raw = {
        "confidence": 15.5,  # Exceeds 1.0
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    normalized = normalize_alert(raw)
    assert normalized["confidence"] == 1.0

    raw_neg = {"confidence": -0.8, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
    normalized_neg = normalize_alert(raw_neg)
    assert normalized_neg["confidence"] == 0.0


def test_normalize_invalid_alert_id():
    # UUID from member handoff should be replaced by ALT-NNN
    raw = {
        "alert_id": "550e8400-e29b-41d4-a716-446655440000",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    normalized = normalize_alert(raw)
    assert normalized["alert_id"].startswith("ALT-")
    assert validate_alert(normalized) == []


def test_normalize_evidence_conversion():
    # Evidence as list of strings
    raw_list = {
        "evidence": ["High SYN packet rate", "No ACK received"],
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    normalized = normalize_alert(raw_list)
    assert isinstance(normalized["evidence"], dict)
    assert "indicators" in normalized["evidence"]
    assert len(normalized["evidence"]["indicators"]) == 2
    assert validate_alert(normalized) == []


def test_normalize_mitre_mapping_conversion():
    # MITRE as malformed object
    raw = {
        "mitre": {"technique_id": "INVALID_TECHNIQUE", "tactic": "Custom"},
        "threat": "DDoS Attack",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    normalized = normalize_alert(raw)
    assert normalized["mitre"]["technique"] == "T1000"
    assert normalized["mitre"]["tactic"] == "Custom"
    assert validate_alert(normalized) == []
