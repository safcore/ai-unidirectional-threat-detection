"""
models.py — Pydantic-free validation for the standard Alert contract.

We deliberately avoid Pydantic to keep the dependency surface minimal for a
2-day prototype.  All validation is done with plain Python so every team
member can read it without extra framework knowledge.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# ── Constants ─────────────────────────────────────────────────────────────────

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "OTHER"}
ALERT_ID_RE = re.compile(r"^ALT-[0-9]+$")
TECHNIQUE_RE = re.compile(r"^T[0-9]+(\.[0-9]+)?$")

REQUIRED_TOP_LEVEL = [
    "alert_id", "timestamp", "threat", "severity", "confidence",
    "source_ip", "destination_ip", "source_port", "destination_port",
    "protocol", "mitre", "evidence",
]
REQUIRED_MITRE = ["tactic", "technique", "technique_name"]


# ── Validation ────────────────────────────────────────────────────────────────

def validate_alert(data: Any) -> list[str]:
    """
    Validate an alert dict against the PS-145 alert contract.

    Returns a list of error strings.  An empty list means the alert is valid.
    """
    if not isinstance(data, dict):
        return ["Alert must be a JSON object"]

    errors: list[str] = []

    # 1. Required top-level fields
    for field in REQUIRED_TOP_LEVEL:
        if field not in data:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        # Cannot continue further checks without the basic structure
        return errors

    # 2. alert_id format
    if not isinstance(data["alert_id"], str) or not ALERT_ID_RE.match(data["alert_id"]):
        errors.append("'alert_id' must be a string matching pattern ALT-NNN (e.g. ALT-001)")

    # 3. timestamp — must be a valid ISO 8601 date-time string
    ts = data["timestamp"]
    if not isinstance(ts, str):
        errors.append("'timestamp' must be an ISO 8601 string")
    else:
        try:
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"'timestamp' is not a valid ISO 8601 date-time: {ts!r}")

    # 4. threat
    if not isinstance(data["threat"], str) or not data["threat"].strip():
        errors.append("'threat' must be a non-empty string")

    # 5. severity
    if data["severity"] not in VALID_SEVERITIES:
        errors.append(f"'severity' must be one of {sorted(VALID_SEVERITIES)}, got: {data['severity']!r}")

    # 6. confidence
    conf = data["confidence"]
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        errors.append("'confidence' must be a number between 0.0 and 1.0")

    # 7. IPs (basic non-empty string check; full regex would be overkill here)
    for ip_field in ("source_ip", "destination_ip"):
        if not isinstance(data[ip_field], str) or not data[ip_field].strip():
            errors.append(f"'{ip_field}' must be a non-empty string")

    # 8. Ports
    for port_field in ("source_port", "destination_port"):
        p = data[port_field]
        if not isinstance(p, int) or not (0 <= p <= 65535):
            errors.append(f"'{port_field}' must be an integer between 0 and 65535")

    # 9. Protocol
    if data["protocol"] not in VALID_PROTOCOLS:
        errors.append(f"'protocol' must be one of {sorted(VALID_PROTOCOLS)}, got: {data['protocol']!r}")

    # 10. mitre object
    mitre = data["mitre"]
    if not isinstance(mitre, dict):
        errors.append("'mitre' must be an object")
    else:
        for mf in REQUIRED_MITRE:
            if mf not in mitre:
                errors.append(f"Missing required field in 'mitre': '{mf}'")
        technique = mitre.get("technique", "")
        if isinstance(technique, str) and not TECHNIQUE_RE.match(technique):
            errors.append(f"'mitre.technique' must match pattern T<number> (e.g. T1046), got: {technique!r}")

    # 11. evidence must be an object (even if empty)
    if not isinstance(data["evidence"], dict):
        errors.append("'evidence' must be an object")

    return errors
