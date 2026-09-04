"""
Phase 4 Demonstration Scenario & Evaluation Pipeline Script.

Demonstrates controlled 4-stage attack progression sequence:
  Event 1: PORT_SCAN (Source 10.0.0.5 -> Target Server 10.0.0.20)
  Event 2: PORT_SCAN (Source 10.0.0.5 -> Target Server 10.0.0.20)
  Event 3: BRUTE_FORCE (Source 10.0.0.5 -> Target Server 10.0.0.20)
  Event 4: WEB_ATTACK (Source 10.0.0.5 -> Target Server 10.0.0.20)

Demonstrates:
  4 Events -> Correlation -> 1 Incident Created -> MITRE Mappings -> Risk Score -> Attack Chain -> Timeline -> Explainability
"""

import time
import json
import logging
from typing import Dict, Any, List
from ml.training.loader import load_feature_schema
from ml.detection.detection_engine import get_detection_engine
from ml.investigation.incident_manager import get_incident_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phase4_evaluation")


def run_phase4_demo_scenario() -> Dict[str, Any]:
    """Execute Phase 4 Demonstration Scenario."""
    logger.info("==================================================")
    logger.info("STARTING PHASE 4 DEMONSTRATION SCENARIO")
    logger.info("==================================================")

    schema = load_feature_schema()
    base_features = {feat: 10.0 for feat in schema["ml_feature_names"]}

    engine = get_detection_engine()
    mgr = get_incident_manager()

    # 4-stage attack sequence payload
    synthetic_sequence = [
        {"threat": "PORT_SCAN", "port": 80, "time": "2026-09-03T10:30:01Z"},
        {"threat": "PORT_SCAN", "port": 443, "time": "2026-09-03T10:30:15Z"},
        {"threat": "BRUTE_FORCE", "port": 22, "time": "2026-09-03T10:31:00Z"},
        {"threat": "WEB_ATTACK", "port": 8080, "time": "2026-09-03T10:32:00Z"},
    ]

    events: List[Dict[str, Any]] = []

    for idx, seq in enumerate(synthetic_sequence):
        feat = base_features.copy()
        feat["Destination Port"] = seq["port"]
        metadata = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.20",
            "src_port": 50000 + idx,
            "dst_port": seq["port"],
        }
        
        evt = engine.process(feat, metadata=metadata)
        # Override threat class for demo sequence alignment
        evt["threat_class"] = seq["threat"]
        evt["timestamp"] = seq["time"]
        events.append(evt)

        # Ingest into Phase 4 Incident Manager
        incident = mgr.process_event(evt)
        logger.info(f"Processed Event {idx+1} ({seq['threat']}) -> Incident ID: {incident.incident_id}, Risk: {incident.risk_score:.1f} ({incident.risk_level})")

    logger.info(f"Phase 4 Demonstration Complete -> Created Incident ID: {incident.incident_id}")
    logger.info(f"Total Correlated Events: {len(incident.events)}")
    logger.info(f"MITRE ATT&CK Techniques Mapped: {len(incident.mitre_mappings)}")
    logger.info(f"Attack Chain Progression Length: {len(incident.attack_chain)}")

    return incident.to_dict()


if __name__ == "__main__":
    res = run_phase4_demo_scenario()
    print("="*60)
    print("DEMONSTRATION SCENARIO INCIDENT RESULT:")
    print("="*60)
    print(json.dumps(res, indent=2))
    print("="*60)
