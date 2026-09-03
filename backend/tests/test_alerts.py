"""Tests for /api/alerts endpoints."""
import copy
import pytest
from tests.conftest import VALID_ALERT


# ── GET /api/alerts ────────────────────────────────────────────────────────────

def test_get_alerts_empty(client):
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["alerts"] == []
    assert data["count"] == 0


def test_get_alerts_after_post(client):
    client.post("/api/alerts", json=VALID_ALERT)
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 1
    assert data["alerts"][0]["alert_id"] == "ALT-999"


def test_get_alerts_severity_filter(client):
    client.post("/api/alerts", json=VALID_ALERT)
    resp = client.get("/api/alerts?severity=LOW")
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 0

    resp2 = client.get("/api/alerts?severity=HIGH")
    assert resp2.get_json()["count"] == 1


# ── GET /api/alerts/<id> ───────────────────────────────────────────────────────

def test_get_single_alert(client):
    client.post("/api/alerts", json=VALID_ALERT)
    resp = client.get("/api/alerts/ALT-999")
    assert resp.status_code == 200
    assert resp.get_json()["alert_id"] == "ALT-999"


def test_get_missing_alert(client):
    resp = client.get("/api/alerts/ALT-000")
    assert resp.status_code == 404
    assert "error" in resp.get_json()


# ── POST /api/alerts ───────────────────────────────────────────────────────────

def test_post_valid_alert(client):
    resp = client.post("/api/alerts", json=VALID_ALERT)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["alert_id"] == "ALT-999"
    assert data["severity"] == "HIGH"


def test_post_non_json(client):
    resp = client.post("/api/alerts", data="not json", content_type="text/plain")
    assert resp.status_code == 400


def test_post_missing_required_field(client):
    bad = copy.deepcopy(VALID_ALERT)
    del bad["threat"]
    resp = client.post("/api/alerts", json=bad)
    assert resp.status_code == 422
    body = resp.get_json()
    assert body["error"] == "Invalid alert"
    assert any("threat" in d for d in body["details"])


def test_post_invalid_severity(client):
    bad = copy.deepcopy(VALID_ALERT)
    bad["alert_id"] = "ALT-998"
    bad["severity"] = "EXTREME"
    resp = client.post("/api/alerts", json=bad)
    assert resp.status_code == 422
    assert "severity" in str(resp.get_json()["details"])


def test_post_invalid_confidence(client):
    bad = copy.deepcopy(VALID_ALERT)
    bad["alert_id"] = "ALT-997"
    bad["confidence"] = 1.5
    resp = client.post("/api/alerts", json=bad)
    assert resp.status_code == 422


def test_post_duplicate_alert(client):
    client.post("/api/alerts", json=VALID_ALERT)
    resp = client.post("/api/alerts", json=VALID_ALERT)
    assert resp.status_code == 409
    assert "Duplicate" in resp.get_json()["error"]


def test_post_invalid_alert_id_format(client):
    bad = copy.deepcopy(VALID_ALERT)
    bad["alert_id"] = "INVALID-ID"
    resp = client.post("/api/alerts", json=bad)
    assert resp.status_code == 422


def test_post_missing_timestamp(client):
    bad = copy.deepcopy(VALID_ALERT)
    bad["alert_id"] = "ALT-996"
    del bad["timestamp"]
    resp = client.post("/api/alerts", json=bad)
    assert resp.status_code == 422


# ── GET /api/stats ─────────────────────────────────────────────────────────────

def test_stats_empty(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total_alerts"] == 0
    assert data["critical"] == 0


def test_stats_after_posts(client):
    client.post("/api/alerts", json=VALID_ALERT)      # HIGH / Port Scan

    ddos = copy.deepcopy(VALID_ALERT)
    ddos["alert_id"] = "ALT-100"
    ddos["severity"] = "CRITICAL"
    ddos["threat"] = "DDoS"
    client.post("/api/alerts", json=ddos)

    resp = client.get("/api/stats")
    data = resp.get_json()
    assert data["total_alerts"] == 2
    assert data["high"] == 1
    assert data["critical"] == 1
    assert data["threat_types"]["Port Scan"] == 1
    assert data["threat_types"]["DDoS"] == 1
