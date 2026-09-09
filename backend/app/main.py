"""
main.py — Entry point for the PS-145 Flask backend.

Run with:
    python -m app.main
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any

# Ensure backend directory is in sys.path when started from ps145 root or backend
current_dir = os.path.dirname(os.path.abspath(__file__))  # backend/app
backend_dir = os.path.dirname(current_dir)                # backend
project_root = os.path.dirname(backend_dir)               # project root
if project_root not in sys.path:
    sys.path.insert(0, project_root)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# ── Load environment before importing app singletons ──────────────────────────
from app.env_loader import load_env
_env_path = load_env()

from app import create_app, alert_store, ai_service

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Mock data loader ──────────────────────────────────────────────────────────

MOCK_ALERTS: list[dict[str, Any]] = [
    {
        "alert_id": "ALT-001",
        "timestamp": "2026-09-02T08:00:00Z",
        "threat": "Port Scan",
        "severity": "HIGH",
        "confidence": 0.94,
        "source_ip": "10.0.0.45",
        "destination_ip": "192.168.1.1",
        "source_port": 45321,
        "destination_port": 22,
        "protocol": "TCP",
        "mitre": {
            "tactic": "Discovery",
            "technique": "T1046",
            "technique_name": "Network Service Scanning",
        },
        "evidence": {"packets": 152, "connections": 87, "ports_scanned": 42},
    },
    {
        "alert_id": "ALT-002",
        "timestamp": "2026-09-02T08:15:00Z",
        "threat": "DDoS",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "source_ip": "172.16.10.5",
        "destination_ip": "192.168.1.20",
        "source_port": 4000,
        "destination_port": 80,
        "protocol": "TCP",
        "mitre": {
            "tactic": "Impact",
            "technique": "T1498",
            "technique_name": "Network Denial of Service",
        },
        "evidence": {"packets": 50000, "connections": 1000, "ports_scanned": 0},
    },
    {
        "alert_id": "ALT-003",
        "timestamp": "2026-09-02T08:30:00Z",
        "threat": "C2 Communication",
        "severity": "CRITICAL",
        "confidence": 0.91,
        "source_ip": "192.168.1.77",
        "destination_ip": "10.10.10.10",
        "source_port": 51234,
        "destination_port": 443,
        "protocol": "HTTPS",
        "mitre": {
            "tactic": "Command and Control",
            "technique": "T1071",
            "technique_name": "Application Layer Protocol",
        },
        "evidence": {"packets": 340, "connections": 12, "flow_duration_ms": 180000},
    },
    {
        "alert_id": "ALT-004",
        "timestamp": "2026-09-02T09:00:00Z",
        "threat": "Suspicious DNS",
        "severity": "MEDIUM",
        "confidence": 0.77,
        "source_ip": "192.168.1.55",
        "destination_ip": "8.8.8.8",
        "source_port": 54321,
        "destination_port": 53,
        "protocol": "DNS",
        "mitre": {
            "tactic": "Command and Control",
            "technique": "T1071.004",
            "technique_name": "DNS",
        },
        "evidence": {"queries": 250, "unique_domains": 80, "packets": 500},
    },
    {
        "alert_id": "ALT-005",
        "timestamp": "2026-09-02T09:30:00Z",
        "threat": "Brute Force",
        "severity": "HIGH",
        "confidence": 0.89,
        "source_ip": "10.0.1.33",
        "destination_ip": "192.168.1.10",
        "source_port": 60000,
        "destination_port": 22,
        "protocol": "TCP",
        "mitre": {
            "tactic": "Credential Access",
            "technique": "T1110",
            "technique_name": "Brute Force",
        },
        "evidence": {"failed_attempts": 350, "connections": 350, "packets": 700},
    },
    {
        "alert_id": "ALT-006",
        "timestamp": "2026-09-02T10:00:00Z",
        "threat": "Data Exfiltration",
        "severity": "CRITICAL",
        "confidence": 0.86,
        "source_ip": "192.168.1.88",
        "destination_ip": "172.20.0.99",
        "source_port": 45678,
        "destination_port": 443,
        "protocol": "HTTPS",
        "mitre": {
            "tactic": "Exfiltration",
            "technique": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
        },
        "evidence": {"bytes_transferred": 524288000, "connections": 45, "packets": 8200},
    },
    {
        "alert_id": "ALT-007",
        "timestamp": "2026-09-02T10:30:00Z",
        "threat": "Port Scan",
        "severity": "MEDIUM",
        "confidence": 0.72,
        "source_ip": "10.0.2.15",
        "destination_ip": "192.168.1.5",
        "source_port": 33445,
        "destination_port": 3389,
        "protocol": "TCP",
        "mitre": {
            "tactic": "Discovery",
            "technique": "T1046",
            "technique_name": "Network Service Scanning",
        },
        "evidence": {"packets": 60, "connections": 30, "ports_scanned": 15},
    },
    {
        "alert_id": "ALT-008",
        "timestamp": "2026-09-02T11:00:00Z",
        "threat": "Brute Force",
        "severity": "HIGH",
        "confidence": 0.93,
        "source_ip": "10.0.3.7",
        "destination_ip": "192.168.1.15",
        "source_port": 61000,
        "destination_port": 3389,
        "protocol": "TCP",
        "mitre": {
            "tactic": "Credential Access",
            "technique": "T1110",
            "technique_name": "Brute Force",
        },
        "evidence": {"failed_attempts": 500, "connections": 500, "packets": 1000},
    },
]


def _load_mock_data() -> None:
    """Load mock alerts if the store is empty (fresh start)."""
    existing = alert_store.get_all()
    if not existing:
        alert_store.reset(MOCK_ALERTS)
        logger.info("Loaded %d mock alerts for demo/development", len(MOCK_ALERTS))
    else:
        logger.info("Alert store already has %d alert(s) — skipping mock load", len(existing))


# ── Main ──────────────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    _load_mock_data()

    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))

    logger.info("=" * 60)
    logger.info("  PS-145 Threat Detection Backend")
    logger.info("  Listening on http://%s:%d", host, port)
    logger.info("  Health:    http://%s:%d/api/health", host, port)
    logger.info("  Alerts:    http://%s:%d/api/alerts", host, port)
    logger.info("  Stats:     http://%s:%d/api/stats", host, port)
    logger.info("  Stream:    http://%s:%d/api/stream", host, port)
    logger.info("  AI Health: http://%s:%d/api/ai/health", host, port)
    ai_status = ai_service.health()
    has_key = bool(os.environ.get("NVIDIA_API_KEY", "").strip())
    logger.info("  ENV File:  %s", _env_path or "NOT FOUND")
    logger.info("  AI Key:    %s", "DETECTED (configured)" if has_key else "NOT SET")
    logger.info("  AI Status: %s (model=%s)",
                ai_status["status"], ai_status["model"])
    if not ai_status["ai_enabled"]:
        logger.warning("  AI:        DISABLED — set NVIDIA_API_KEY in backend/.env")
    logger.info("=" * 60)

    # threaded=True is required for SSE (each client gets its own thread)
    app.run(host=host, port=port, threaded=True, debug=False)
