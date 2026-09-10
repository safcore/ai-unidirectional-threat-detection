"""
conftest.py — Shared pytest fixtures.

Uses an in-memory (tmp) alert store so tests never touch backend/data/alerts.json.
AI calls are always mocked — tests NEVER require a real NVIDIA API key.
"""
from __future__ import annotations

import os
import sys
import pytest
_backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_project_root = os.path.dirname(_backend_dir)
for _p in (_project_root, os.path.join(_project_root, "scripts"), _backend_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import app as app_module
from app import create_app, alert_store as _default_store
from app.alert_store import AlertStore


@pytest.fixture(autouse=True)
def isolate_alert_store(tmp_path, monkeypatch):
    """Ensure every test in the entire test suite runs with an isolated AlertStore."""
    isolated = AlertStore(data_path=str(tmp_path / "test_alerts.json"))

    # Patch in app module
    monkeypatch.setattr(app_module, "alert_store", isolated)

    # Patch in routes
    try:
        import app.routes as routes_mod
        monkeypatch.setattr(routes_mod, "alert_store", isolated)
    except Exception:
        pass

    # Patch in ai_routes
    try:
        import app.ai_routes as ai_mod
        monkeypatch.setattr(ai_mod, "alert_store", isolated)
    except Exception:
        pass

    # Patch in attack_service
    try:
        import app.attack_service as atk_mod
        monkeypatch.setattr(atk_mod, "alert_store", isolated)
    except Exception:
        pass

    # Patch in backend.app (if imported under alternate name)
    try:
        import backend.app as b_app
        monkeypatch.setattr(b_app, "alert_store", isolated)
    except Exception:
        pass

    try:
        import backend.app.routes as b_routes
        monkeypatch.setattr(b_routes, "alert_store", isolated)
    except Exception:
        pass

    yield isolated
    # Teardown: ensure any background attack simulation threads are stopped and joined
    try:
        import app.attack_service as atk_mod
        atk_mod.attack_service.stop_all()
    except Exception:
        pass


@pytest.fixture()
def tmp_store(isolate_alert_store):
    """Alias for backwards compatibility with tests requesting tmp_store fixture."""
    return isolate_alert_store


@pytest.fixture()
def client(tmp_store, monkeypatch):
    """
    A Flask test client wired to an isolated tmp_store and fresh stream_manager.
    Monkeypatches the module-level singletons so routes use the temp store.
    """
    # Disable real external network AI calls during unit/integration tests
    from unittest.mock import MagicMock
    mock_ai = MagicMock()
    mock_ai.analyze_alert.return_value = {
        "ai_summary": "Test mock analysis",
        "threat_assessment": "Test assessment",
        "risk_level": "LOW",
        "confidence": 0.85,
        "why_suspicious": "Test reason",
        "attack_stage": "Test stage",
        "mitre_context": "Test context",
        "recommended_actions": ["Action 1"],
        "investigation_priority": "LOW",
    }
    mock_ai.correlate_alerts.return_value = {
        "related": False,
        "confidence": 0.5,
        "summary": "Mock correlation",
        "common_indicators": [],
        "possible_attack_chain": [],
        "recommended_actions": [],
    }
    mock_ai.health.return_value = {
        "ai_enabled": True,
        "provider": "MOCK",
        "status": "available",
        "model": "mock",
    }
    try:
        import app.ai_routes as ai_routes_module
        monkeypatch.setattr(ai_routes_module, "ai_service", mock_ai)
    except Exception:
        pass
    monkeypatch.setattr(app_module, "ai_service", mock_ai)

    flask_app = create_app({"TESTING": True})
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# ── Sample valid alert ────────────────────────────────────────────────────────

VALID_ALERT = {
    "alert_id": "ALT-999",
    "timestamp": "2026-09-02T14:00:00Z",
    "threat": "Port Scan",
    "severity": "HIGH",
    "confidence": 0.94,
    "source_ip": "192.168.1.10",
    "destination_ip": "192.168.1.20",
    "source_port": 45321,
    "destination_port": 22,
    "protocol": "TCP",
    "mitre": {
        "tactic": "Discovery",
        "technique": "T1046",
        "technique_name": "Network Service Scanning",
    },
    "evidence": {"packets": 152, "connections": 87, "ports_scanned": 42},
}

# ── Sample AI analysis response ───────────────────────────────────────────────

MOCK_AI_ANALYSIS = {
    "alert_id": "ALT-999",
    "ai_summary": "Systematic port scan detected from internal host targeting gateway.",
    "threat_assessment": "The source host 192.168.1.10 probed 42 ports on the destination with 87 connections and 152 packets. This pattern is consistent with automated reconnaissance. Detection confidence is high at 0.94.",
    "risk_level": "HIGH",
    "confidence": 0.91,
    "why_suspicious": [
        "42 unique ports scanned in a short time window",
        "87 connections to a single destination is above normal baseline",
        "TCP SYN pattern consistent with network service discovery tools",
    ],
    "attack_stage": "Reconnaissance",
    "mitre_context": {
        "tactic": "Discovery",
        "technique": "T1046",
        "technique_name": "Network Service Scanning",
    },
    "recommended_actions": [
        "Investigate the source host 192.168.1.10 for unauthorized scanning tools",
        "Review firewall rules to limit outbound scanning",
        "Check endpoint processes on source host for scheduled tasks or scripts",
    ],
    "investigation_priority": "HIGH",
    "_cached": False,
}

MOCK_CORRELATION = {
    "related": True,
    "confidence": 0.85,
    "summary": "The alerts share a common source subnet and sequential MITRE tactics suggesting a multi-stage attack.",
    "common_indicators": ["Shared source subnet 192.168.1.0/24", "Sequential Discovery→Exfiltration tactics"],
    "possible_attack_chain": ["ALT-001 (Discovery)", "ALT-002 (Exfiltration)"],
    "recommended_actions": ["Isolate source subnet", "Review all traffic from 192.168.1.0/24"],
}
