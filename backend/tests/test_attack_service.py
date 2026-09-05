"""
Tests for AttackService and /api/attack/* endpoints.
"""
from __future__ import annotations

import time
import pytest
from app.attack_service import AttackService, attack_service


@pytest.fixture
def fresh_attack_service():
    svc = AttackService()
    yield svc
    svc.stop_all()


class TestAttackServiceUnit:
    def test_start_syn_flood_simulation(self, fresh_attack_service):
        job = fresh_attack_service.start_attack(
            "syn_flood",
            {"target": "127.0.0.1", "port": 80, "rate": 50, "duration": 1.0, "simulation": True},
        )
        assert job["attack_id"].startswith("ATK-")
        assert job["attack_type"] == "syn_flood"
        assert job["status"] in ("running", "completed")

        # Let it complete or wait briefly
        time.sleep(0.5)
        status = fresh_attack_service.get_status(job["attack_id"])
        assert status["found"] is True
        assert status["attack"]["attack_type"] == "syn_flood"

    def test_start_port_scan_simulation(self, fresh_attack_service):
        job = fresh_attack_service.start_attack(
            "port_scan",
            {"target": "127.0.0.1", "port_start": 80, "port_end": 85, "simulation": True},
        )
        assert job["attack_id"].startswith("ATK-")
        assert job["attack_type"] == "port_scan"

    def test_start_dns_tunnel_simulation(self, fresh_attack_service):
        job = fresh_attack_service.start_attack(
            "dns_tunnel",
            {"target": "8.8.8.8", "domain": "test.local", "rate": 5, "duration": 1.0, "simulation": True},
        )
        assert job["attack_id"].startswith("ATK-")
        assert job["attack_type"] == "dns_tunnel"

    def test_invalid_attack_type_raises(self, fresh_attack_service):
        with pytest.raises(ValueError, match="Invalid attack_type"):
            fresh_attack_service.start_attack("unknown_exploit")

    def test_stop_attack(self, fresh_attack_service):
        job = fresh_attack_service.start_attack(
            "syn_flood",
            {"duration": 10.0, "simulation": True},
        )
        stopped = fresh_attack_service.stop_attack(job["attack_id"])
        assert stopped is not None
        assert stopped["status"] in ("stopping", "stopped")

    def test_stop_unknown_attack_returns_none(self, fresh_attack_service):
        assert fresh_attack_service.stop_attack("ATK-999") is None

    def test_stop_all(self, fresh_attack_service):
        fresh_attack_service.start_attack("syn_flood", {"duration": 10.0, "simulation": True})
        fresh_attack_service.start_attack("dns_tunnel", {"duration": 10.0, "simulation": True})
        stopped_count = fresh_attack_service.stop_all()
        assert stopped_count >= 2


class TestAttackApiEndpoints:
    def test_start_attack_endpoint(self, client):
        resp = client.post(
            "/api/attack/start",
            json={"attack_type": "syn_flood", "params": {"duration": 1.0, "simulation": True}},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "started"
        assert "attack_id" in data["attack"]
        attack_id = data["attack"]["attack_id"]

        # Check status
        status_resp = client.get(f"/api/attack/status?attack_id={attack_id}")
        assert status_resp.status_code == 200
        assert status_resp.get_json()["found"] is True

        # Stop it
        stop_resp = client.post("/api/attack/stop", json={"attack_id": attack_id})
        assert stop_resp.status_code == 200

    def test_start_missing_type_returns_400(self, client):
        resp = client.post("/api/attack/start", json={"params": {}})
        assert resp.status_code == 400

    def test_start_invalid_type_returns_400(self, client):
        resp = client.post("/api/attack/start", json={"attack_type": "nuke_server"})
        assert resp.status_code == 400

    def test_status_all_endpoint(self, client):
        resp = client.get("/api/attack/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "active_attacks" in data
        assert "attacks" in data

    def test_stop_all_endpoint(self, client):
        resp = client.post("/api/attack/stop", json={})
        assert resp.status_code == 200
        assert "stopped_count" in resp.get_json()
