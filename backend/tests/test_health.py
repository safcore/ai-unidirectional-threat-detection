"""Tests for / and /api/health endpoints."""
import pytest


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["service"] in ("PS-145 Threat Detection Backend", "NETRION Threat Detection Backend")
    assert "endpoints" in data


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "threat-detection-backend"
    assert "sse_clients" in data


def test_404(client):
    resp = client.get("/api/nonexistent")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "Not found"


def test_method_not_allowed(client):
    resp = client.delete("/api/health")
    assert resp.status_code == 405
