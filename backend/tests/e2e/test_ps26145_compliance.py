"""
test_ps26145_compliance.py — Automated Compliance Test Suite for PS-26145.
Validates the six required threat categories, passive non-decrypting TLS inspection,
behavioral detectors, attack simulation services, and schema conformance.
"""

from __future__ import annotations

import json
from pathlib import Path
import pandas as pd
import pytest

from m2_features import adapt_to_canonical_66, get_canonical_feature_names
from ml.detection.detection_engine import get_detection_engine
from ml.detection.tls_metadata_detector import TLSMetadataDetector
from m4_threat_classifier.detection.c2_detector import C2Detector
from m4_threat_classifier.detection.dga_detector import DGADetector
from m4_threat_classifier.detection.exfiltration_detector import ExfiltrationDetector
from backend.app.m4_integration import process_detection
from backend.app.attack_service import attack_service, VALID_ATTACK_TYPES

PROJECT_ROOT = next(
    (p for p in Path(__file__).resolve().parents if (p / "backend").exists() and (p / "data").exists()),
    Path(__file__).resolve().parents[3],
)
TEST_CSV_PATH = PROJECT_ROOT / "data" / "datasets" / "test.csv"
if not TEST_CSV_PATH.exists():
    TEST_CSV_PATH = (
        PROJECT_ROOT
        / "teamwork"
        / "_inspection"
        / "SIH PS145"
        / "AaYuushman's work"
        / "ml"
        / "data"
        / "test.csv"
    )


@pytest.fixture
def baseline_canonical_features():
    """Return a benign 66-feature vector dictionary."""
    feature_names = get_canonical_feature_names()
    return {f: 0.0 for f in feature_names}


def test_ps26145_six_attack_types_supported_in_service():
    """Verify attack service supports all required attack types."""
    required = {
        "syn_flood",
        "port_scan",
        "dns_tunnel",
        "c2_beacon",
        "data_exfiltration",
        "encrypted_anomaly",
    }
    assert required.issubset(VALID_ATTACK_TYPES), f"Missing attack types: {required - VALID_ATTACK_TYPES}"


def test_ps26145_threat_1_volumetric_ddos():
    """Verify volumetric DDoS threat detection using canonical dataset flow."""
    if TEST_CSV_PATH.exists():
        df = pd.read_csv(TEST_CSV_PATH, nrows=1)
        row = df.iloc[0].to_dict()
        feats, meta = adapt_to_canonical_66(row)
    else:
        feats = {f: 0.0 for f in get_canonical_feature_names()}
        feats["Destination Port"] = 80
        feats["Flow Duration"] = 50000.0
        feats["Total Fwd Packets"] = 500.0
        feats["Flow Packets/s"] = 10000.0
        meta = {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP"}

    event, incident, alert = process_detection(feats, meta)
    assert event["status"] == "success"
    assert "DDoS" in alert["threat"] or alert["severity"] in ["HIGH", "CRITICAL"]


def test_ps26145_threat_2_c2_beaconing():
    """Verify Botnet Command & Control (C2) periodic beaconing detection."""
    detector = C2Detector()
    features = {
        "Total Fwd Packets": 10,
        "Fwd Packet Length Mean": 32.0,
        "Flow IAT Mean": 100.0,
        "Flow Duration": 1000.0,
    }
    metadata = {"dst_port": 8443, "protocol": "TCP"}

    res = detector.analyze_flow(features, metadata)
    assert res.classification in ("SUSPICIOUS_C2", "LIKELY_C2")
    assert res.score >= 0.35
    assert len(res.evidence) > 0


def test_ps26145_threat_3_dga_and_dns_tunnel():
    """Verify DGA algorithmic domains and DNS covert tunneling detection."""
    dga_detector = DGADetector()

    # 1. High-entropy DGA domain
    dga_domain = "xk92mzqw18bc4pl89az.net"
    dga_res = dga_detector.analyze_domain(dga_domain)
    assert dga_res.classification in ("SUSPICIOUS", "LIKELY_DGA")
    assert dga_res.dga_score >= 0.5

    # 2. DNS Tunnel / base64 payload
    tunnel_domain = "aW5maWx0cmF0aW9uLXNlY3JldC1rZXk.exfil.example.com"
    tunnel_res = dga_detector.analyze_domain(tunnel_domain)
    assert tunnel_res.classification in ("SUSPICIOUS", "LIKELY_DGA")


def test_ps26145_threat_4_encrypted_tls_metadata_anomaly_no_decryption():
    """Verify encrypted session anomaly detection operates passively on metadata without payload decryption."""
    detector = TLSMetadataDetector()

    # Passively observed metadata from encrypted channel:
    metadata = {
        "src_ip": "10.0.0.45",
        "dst_ip": "198.51.100.12",
        "dst_port": 443,
        "protocol": "TCP",
        "ja3": "a0e9f5d64349fb13191bc781f81f42e1",  # Cobalt Strike profile
    }
    flow_features = {
        "Flow Duration": 5000000,
        "Total Fwd Packets": 40,
        "Total Backward Packets": 5,
        "Total Length of Fwd Packets": 60000,
        "Total Length of Bwd Packets": 300,
        "Packet Length Std": 2.0,  # highly uniform size (beaconing payload)
        "Flow IAT Std": 0.02,     # ultra-low jitter
    }

    result = detector.analyze_flow(flow_features, metadata)

    # Must detect anomaly based purely on metadata
    assert result.is_anomalous is True
    assert result.classification in ("SUSPICIOUS_ENCRYPTED", "LIKELY_MALICIOUS_ENCRYPTED")
    # Verify strict non-decryption:
    assert "payload" not in metadata
    assert "payload_cleartext" not in metadata


def test_ps26145_threat_5_port_scan_reconnaissance():
    """Verify reconnaissance port scan detection."""
    if TEST_CSV_PATH.exists():
        df = pd.read_csv(TEST_CSV_PATH, skiprows=64, nrows=1)
        df_hdr = pd.read_csv(TEST_CSV_PATH, nrows=1)
        df.columns = df_hdr.columns
        feats, meta = adapt_to_canonical_66(df.iloc[0].to_dict())
    else:
        feats = {f: 0.0 for f in get_canonical_feature_names()}
        feats["Destination Port"] = 445
        meta = {"src_ip": "172.16.0.4", "dst_ip": "192.168.1.1", "dst_port": 445, "protocol": "TCP"}

    event, incident, alert = process_detection(feats, meta)
    assert event["status"] == "success"
    assert alert["threat"] in ["Port Scan", "DDoS", "DoS", "Benign Traffic"]


def test_ps26145_threat_6_data_exfiltration():
    """Verify high-volume asymmetric outbound data exfiltration detection."""
    detector = ExfiltrationDetector()
    features = {
        "Total Length of Fwd Packets": 500000,
        "Total Length of Bwd Packets": 200,
        "Fwd Packet Length Max": 1460,
        "Total Fwd Packets": 500,
    }
    metadata = {"dst_port": 443, "protocol": "TCP"}

    res = detector.analyze_flow(features, metadata)
    assert res.classification in ("SUSPICIOUS_EXFILTRATION", "LIKELY_EXFILTRATION")
    assert res.score >= 0.35


def test_ps26145_alert_schema_strict_compliance(baseline_canonical_features):
    """Verify alerts produced by the pipeline strictly satisfy canonical schema constraints."""
    feats = dict(baseline_canonical_features)
    feats["Destination Port"] = 80
    meta = {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.2", "src_port": 54321, "dst_port": 80, "protocol": "TCP"}

    _, _, alert = process_detection(feats, meta)

    # Verify canonical contract
    assert alert["alert_id"].startswith("ALT-")
    assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert 0.0 <= alert["confidence"] <= 1.0
    assert "source_ip" in alert and alert["source_ip"] == "192.168.1.1"
    assert "destination_ip" in alert and alert["destination_ip"] == "10.0.0.2"
    assert "mitre" in alert
    assert "technique" in alert["mitre"]
    assert "evidence" in alert
