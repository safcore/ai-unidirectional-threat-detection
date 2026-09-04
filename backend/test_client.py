#!/usr/bin/env python3
"""
test_client.py — Synthetic alert test client for PS-145.

Sends realistic mock alerts to the Flask backend to verify the full pipeline:
    test_client.py  →  Flask  →  alert_store  →  SSE  →  React dashboard

IMPORTANT: This client only sends synthetic JSON alerts.
It does NOT perform any actual network attacks or scans.

Usage:
    # Send all sample alerts (one by one, with delay):
    python test_client.py

    # Send a single specific alert type:
    python test_client.py --threat "DDoS"

    # Loop continuously (for SSE demo):
    python test_client.py --loop

    # Target a different host:
    python test_client.py --url http://192.168.1.5:8000
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


BASE_URL = "http://127.0.0.1:8000"

# ── Sample alert templates ────────────────────────────────────────────────────
# Uses private/RFC-5737 test IP addresses only (10.x, 192.168.x, 172.16.x).

SAMPLE_ALERTS = [
    {
        "alert_id": "ALT-101",
        "timestamp": "",  # filled at send time
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
        "alert_id": "ALT-102",
        "timestamp": "",
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
        "alert_id": "ALT-103",
        "timestamp": "",
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
        "alert_id": "ALT-104",
        "timestamp": "",
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
        "alert_id": "ALT-105",
        "timestamp": "",
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
        "alert_id": "ALT-106",
        "timestamp": "",
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
]


# ── HTTP helper ───────────────────────────────────────────────────────────────

def post_alert(base_url: str, alert: dict) -> tuple[int, dict]:
    """POST a single alert; returns (status_code, response_body)."""
    url = f"{base_url}/api/alerts"
    payload = json.dumps(alert).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read())
        return exc.code, body
    except urllib.error.URLError as exc:
        print(f"[ERROR] Cannot connect to {url}: {exc.reason}")
        print("  → Make sure the Flask server is running:  python -m app.main")
        sys.exit(1)


def check_health(base_url: str) -> bool:
    """Verify the backend is up before sending alerts."""
    try:
        with urllib.request.urlopen(f"{base_url}/api/health", timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("status") == "healthy"
    except Exception:
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="PS-145 synthetic alert test client")
    parser.add_argument("--url", default=BASE_URL, help="Flask backend base URL")
    parser.add_argument("--threat", help="Only send alerts matching this threat type")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between alerts")
    parser.add_argument("--loop", action="store_true", help="Loop forever (for SSE demo)")
    args = parser.parse_args()

    print(f"[PS-145 Test Client]  target: {args.url}")
    print("NOTE: This client sends SYNTHETIC alert data only. No real attacks.\n")

    # Check health first
    if not check_health(args.url):
        print(f"[ERROR] Backend not healthy at {args.url}/api/health")
        sys.exit(1)
    print("[OK] Backend is healthy\n")

    alerts = SAMPLE_ALERTS
    if args.threat:
        alerts = [a for a in alerts if a["threat"].lower() == args.threat.lower()]
        if not alerts:
            print(f"[WARN] No alerts found for threat: {args.threat}")
            return

    counter = 200  # unique ID offset for loop mode

    iteration = 0
    while True:
        iteration += 1
        print(f"── Iteration {iteration} {'(loop mode)' if args.loop else ''} ──")

        for template in alerts:
            alert = dict(template)
            # Assign fresh timestamp
            alert["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # In loop mode, generate unique IDs each time
            if args.loop and iteration > 1:
                counter += 1
                alert["alert_id"] = f"ALT-{counter}"

            status, body = post_alert(args.url, alert)

            if status == 201:
                print(f"  [201 CREATED]  {alert['alert_id']:10s}  {alert['severity']:8s}  {alert['threat']}")
            elif status == 409:
                print(f"  [409 SKIP]     {alert['alert_id']:10s}  (duplicate — already exists)")
            else:
                print(f"  [{status} ERROR]  {alert['alert_id']:10s}  {body}")

            time.sleep(args.delay)

        if not args.loop:
            break

        # Small extra pause between loop iterations
        time.sleep(2.0)

    print("\n[Done] All alerts sent.")
    print(f"  Check dashboard: {args.url}/api/alerts")
    print(f"  Check stats:     {args.url}/api/stats")


if __name__ == "__main__":
    main()
