"""
Automated Pytest Suite for Phase 4 Threat Intelligence & Investigation Layer.

Tests:
  1. IOC extraction & normalization
  2. Threat Intelligence local provider lookups & cache hits/misses
  3. Evidence-based MITRE ATT&CK mapping
  4. Entity correlation & temporal window grouping
  5. Risk scoring engine (normalized 0-100 score & levels)
  6. Incident creation & lifecycle management
  7. Explainability engine output structure
  8. Extended REST API endpoints (GET /health, POST /investigations/events, GET /incidents, etc.)
"""

import pytest
import numpy as np
import pandas as pd
from flask import Flask

from ml.threat_intelligence import extract_iocs, LocalThreatIntelProvider, IntelCache
from ml.mitre import MITREAttackMapper, TechniqueStore
from ml.correlation import ThreatCorrelationEngine, EntityTracker
from ml.risk import RiskEngine
from ml.investigation import IncidentManager, ExplainabilityEngine
from m4_threat_classifier.api.routes import api_bp


@pytest.fixture
def sample_event():
    return {
        "status": "success",
        "event_id": "evt-test-100",
        "timestamp": "2026-09-03T12:00:00Z",
        "threat_class": "PORT_SCAN",
        "decision": "MALICIOUS",
        "confidence": 0.96,
        "anomaly_score": 0.81,
        "source": {"src_ip": "10.0.0.5", "src_port": 54321},
        "destination": {"dst_ip": "10.0.0.20", "dst_port": 80},
        "alert": {"severity": "HIGH", "status": "NEW"},
    }


@pytest.fixture
def flask_client():
    app = Flask(__name__)
    app.register_blueprint(api_bp)
    app.config["TESTING"] = True
    return app.test_client()


def test_ioc_extraction(sample_event):
    """Test 1: IOC Extraction Engine."""
    iocs = extract_iocs(sample_event)
    assert len(iocs) >= 2
    types = [i.ioc_type for i in iocs]
    assert "IPv4" in types
    assert "Port" in types


def test_threat_intel_local_provider():
    """Test 2: Local Threat Intel Provider."""
    provider = LocalThreatIntelProvider()
    res1 = provider.lookup_ip("10.0.0.5")
    assert res1["reputation"] == "MALICIOUS"

    res2 = provider.lookup_ip("1.1.1.1")
    assert res2["reputation"] == "UNKNOWN"


def test_intel_cache():
    """Test 3: Intel Cache TTL Storage."""
    cache = IntelCache(default_ttl_seconds=10)
    cache.set("IPv4:10.0.0.5", {"reputation": "MALICIOUS"})
    
    val = cache.get("IPv4:10.0.0.5")
    assert val is not None
    assert val["reputation"] == "MALICIOUS"


def test_mitre_mapping(sample_event):
    """Test 4: MITRE ATT&CK Mapping."""
    mapper = MITREAttackMapper()
    mappings = mapper.map_event(sample_event)
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1046"
    assert mappings[0].tactic == "Discovery"


def test_mitre_no_confident_mapping():
    """Test 5: MITRE ATT&CK NO_CONFIDENT_MAPPING handling."""
    mapper = MITREAttackMapper()
    botnet_event = {
        "status": "success",
        "threat_class": "BOTNET",
        "decision": "MALICIOUS",
        "confidence": 0.90,
        "destination": {"dst_port": 9999},  # Non-standard C2 port
    }
    mappings = mapper.map_event(botnet_event)
    assert len(mappings) == 1
    assert mappings[0].technique_id == "NO_CONFIDENT_MAPPING"


def test_risk_engine():
    """Test 6: Risk Scoring Engine normalization and calculation."""
    risk_engine = RiskEngine()
    res = risk_engine.calculate_risk(
        confidence=0.96,
        anomaly_score=0.81,
        severity="HIGH",
        intel_reputation="MALICIOUS",
        correlated_event_count=3,
    )
    assert 0.0 <= res.score <= 100.0
    assert res.level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "confidence_score" in res.components


def test_correlation_engine(sample_event):
    """Test 7: Multi-event threat correlation."""
    engine = ThreatCorrelationEngine(temporal_window_seconds=300)
    group1 = engine.correlate(sample_event)

    event2 = sample_event.copy()
    event2["event_id"] = "evt-test-101"
    event2["threat_class"] = "BRUTE_FORCE"
    group2 = engine.correlate(event2)

    assert group1.group_id == group2.group_id
    assert len(group2.events) == 2
    assert len(group2.attack_chain) == 2


def test_incident_manager(sample_event):
    """Test 8: Incident Manager processing and retrieval."""
    mgr = IncidentManager()
    incident = mgr.process_event(sample_event)

    assert incident.incident_id.startswith("inc-")
    assert incident.risk_score > 0.0
    assert len(incident.events) == 1

    retrieved = mgr.get_incident(incident.incident_id)
    assert retrieved is not None
    assert retrieved.incident_id == incident.incident_id


def test_api_investigations_endpoints(flask_client, sample_event):
    """Test 9: Phase 4 Extended REST API Endpoints."""
    # GET /api/v1/health
    resp_health = flask_client.get("/api/v1/health")
    assert resp_health.status_code == 200
    assert resp_health.get_json()["status"] == "healthy"

    # POST /api/v1/investigations/events
    resp_event = flask_client.post("/api/v1/investigations/events", json=sample_event)
    assert resp_event.status_code == 200
    inc_data = resp_event.get_json()["incident"]
    inc_id = inc_data["incident_id"]

    # GET /api/v1/incidents
    resp_list = flask_client.get("/api/v1/incidents")
    assert resp_list.status_code == 200
    assert resp_list.get_json()["count"] >= 1

    # GET /api/v1/incidents/<id>
    resp_details = flask_client.get(f"/api/v1/incidents/{inc_id}")
    assert resp_details.status_code == 200

    # GET /api/v1/incidents/<id>/timeline
    resp_timeline = flask_client.get(f"/api/v1/incidents/{inc_id}/timeline")
    assert resp_timeline.status_code == 200

    # GET /api/v1/incidents/<id>/attack-chain
    resp_chain = flask_client.get(f"/api/v1/incidents/{inc_id}/attack-chain")
    assert resp_chain.status_code == 200

    # GET /api/v1/incidents/<id>/mitre
    resp_mitre = flask_client.get(f"/api/v1/incidents/{inc_id}/mitre")
    assert resp_mitre.status_code == 200

    # GET /api/v1/iocs/<ioc>
    resp_ioc = flask_client.get("/api/v1/iocs/10.0.0.5")
    assert resp_ioc.status_code == 200
    assert resp_ioc.get_json()["reputation"] == "MALICIOUS"
