"""
Interactive / Automated Test Runner for M4 Threat Classifier.
Run this script to test all components:
  1. DGA Detector
  2. C2 Behavioral Detector
  3. Data Exfiltration Detector
  4. Phase 4 Threat Intelligence & Incident Manager
  5. NVIDIA Nemotron AI Client (with live .env API key)
"""

import sys
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("m4_tester")


def test_dga():
    print("\n--- 1. TESTING DGA DETECTOR ---")
    from m4_threat_classifier.detection.dga_detector import DGADetector
    dga = DGADetector()

    domains = ["google.com", "a8f9x11z99q12p33w.ru", "123456789.xyz"]
    for dom in domains:
        res = dga.analyze_domain(dom)
        print(f"Domain: '{res.domain}' -> Class: {res.classification} | Score: {res.dga_score:.4f} | Reason: {res.reason}")


def test_c2():
    print("\n--- 2. TESTING C2 BEHAVIORAL DETECTOR ---")
    from m4_threat_classifier.detection.c2_detector import C2Detector
    c2 = C2Detector()

    c2_payload = {
        "Destination Port": 6667,
        "Total Fwd Packets": 12,
        "Fwd Packet Length Mean": 32.0,
        "Flow IAT Mean": 1000.0,
        "Flow Duration": 5000.0,
    }
    res = c2.analyze_flow(c2_payload)
    print(f"Port 6667 Flow -> Class: {res.classification} | Score: {res.score:.4f} | Evidence: {res.evidence}")


def test_exfiltration():
    print("\n--- 3. TESTING EXFILTRATION DETECTOR ---")
    from m4_threat_classifier.detection.exfiltration_detector import ExfiltrationDetector
    exfil = ExfiltrationDetector()

    exfil_payload = {
        "Total Length of Fwd Packets": 150000.0,
        "Total Length of Bwd Packets": 1000.0,
        "Fwd Packet Length Max": 1460.0,
        "Destination Port": 443,
    }
    res = exfil.analyze_flow(exfil_payload)
    print(f"High Outbound Flow -> Class: {res.classification} | Score: {res.score:.4f} | Evidence: {res.evidence}")


def test_phase4():
    print("\n--- 4. TESTING PHASE 4 INVESTIGATION PIPELINE ---")
    from ml.training.loader import load_feature_schema
    from ml.detection.detection_engine import get_detection_engine
    from ml.investigation.incident_manager import get_incident_manager

    schema = load_feature_schema()
    feat = {f: 10.0 for f in schema["ml_feature_names"]}
    meta = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.20", "src_port": 54321, "dst_port": 80}

    engine = get_detection_engine()
    event = engine.process(feat, metadata=meta)

    mgr = get_incident_manager()
    incident = mgr.process_event(event)

    print(f"Incident ID: {incident.incident_id}")
    print(f"Risk Score: {incident.risk_score:.1f} / 100 ({incident.risk_level})")
    print(f"Extracted IOCs: {len(incident.iocs)}")
    print(f"MITRE Mappings: {len(incident.mitre_mappings)}")


def test_nemotron():
    print("\n--- 5. TESTING NVIDIA NEMOTRON AI CLIENT ---")
    from m4_threat_classifier.ai.nemotron_client import get_nemotron_client
    client = get_nemotron_client()
    diag = client.get_safe_diagnostics()

    print(f"Configured: {diag['Configured']}")
    print(f"Base URL: {diag['Base URL']}")
    print(f"Model: {diag['Model']}")

    sample_incident = {
        "incident_id": "inc-10-0-0-5",
        "threat_class": "PORT_SCAN",
        "confidence": 0.95,
        "risk_score": 61.9,
    }
    res = client.analyze_incident(sample_incident)
    print(f"Status: {res.status}")
    if res.analysis:
        print(f"Response Preview:\n{res.analysis[:200]}...")
    else:
        print(f"Limitations / Fallback: {res.limitations}")


if __name__ == "__main__":
    print("==================================================")
    print("M4 SYSTEM INTEGRATED COMPONENT TEST")
    print("==================================================")
    test_dga()
    test_c2()
    test_exfiltration()
    test_phase4()
    test_nemotron()
    print("\n==================================================")
    print("ALL TESTS EXECUTED CLEANLY")
    print("==================================================")
