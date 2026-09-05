"""
alert_normalizer.py — Centralized Alert Normalization Engine
=============================================================
Enforces the canonical PS-145 alert schema contract (shared/alert_schema.json)
for all incoming alerts from M1, M2, M3, M4, or external detection sources before
they enter storage, routes, or SSE broadcasts.
"""

from __future__ import annotations

import re
import threading
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import validate_alert, VALID_SEVERITIES, VALID_PROTOCOLS, ALERT_ID_RE, TECHNIQUE_RE

logger = logging.getLogger("alert_normalizer")

_counter_lock = threading.Lock()
_global_alert_counter = 0


def _get_next_alert_id() -> str:
    """Generate the next sequential ALT-NNN identifier."""
    global _global_alert_counter
    with _counter_lock:
        _global_alert_counter += 1
        return f"ALT-{_global_alert_counter:03d}"


def set_alert_counter_baseline(max_id_num: int):
    """Set the counter baseline from existing store to avoid collisions."""
    global _global_alert_counter
    with _counter_lock:
        if max_id_num > _global_alert_counter:
            _global_alert_counter = max_id_num


def normalize_threat_name(threat: Any) -> str:
    """Convert raw threat classes into clean human-readable names."""
    if not threat or not isinstance(threat, str):
        return "Suspicious Activity"
    t = threat.strip().replace("_", " ")
    # Special common cases
    name_map = {
        "ddos": "DDoS",
        "dos": "DoS",
        "port scan": "Port Scan",
        "syn flood": "SYN Flood",
        "udp flood": "UDP Flood",
        "c2": "C2 Communication",
        "c2 communication": "C2 Communication",
        "dga": "DGA Domain Activity",
        "data exfiltration": "Data Exfiltration",
        "exfiltration": "Data Exfiltration",
        "brute force": "Brute Force",
        "web attack": "Web Attack",
        "botnet": "Botnet Activity",
        "infiltration": "Infiltration",
        "benign": "Benign Traffic",
    }
    return name_map.get(t.lower(), t.title())


def normalize_severity(sev: Any) -> str:
    """Clamp severity to canonical enum: LOW, MEDIUM, HIGH, CRITICAL."""
    if not sev or not isinstance(sev, str):
        return "LOW"
    s = sev.strip().upper()
    if s in VALID_SEVERITIES:
        return s
    if s in ("INFO", "INFORMATIONAL", "DEBUG"):
        return "LOW"
    return "LOW"


def normalize_protocol(proto: Any) -> str:
    """Clamp protocol to canonical enum."""
    if not proto or not isinstance(proto, str):
        return "OTHER"
    p = proto.strip().upper()
    if p in VALID_PROTOCOLS:
        return p
    return "OTHER"


def normalize_mitre(mitre_data: Any, threat_name: str = "") -> Dict[str, str]:
    """Ensure MITRE object has tactic, technique (T<num>), and technique_name."""
    default_mapping = {
        "tactic": "Defense Evasion",
        "technique": "T1000",
        "technique_name": threat_name or "Unclassified Threat",
    }

    if not isinstance(mitre_data, dict):
        # Fallbacks based on threat
        t_lower = threat_name.lower()
        if "port scan" in t_lower or "recon" in t_lower:
            return {"tactic": "Discovery", "technique": "T1046", "technique_name": "Network Service Scanning"}
        elif "ddos" in t_lower or "syn flood" in t_lower or "udp flood" in t_lower or "dos" in t_lower:
            return {"tactic": "Impact", "technique": "T1498", "technique_name": "Network Denial of Service"}
        elif "c2" in t_lower or "beacon" in t_lower:
            return {"tactic": "Command and Control", "technique": "T1071", "technique_name": "Application Layer Protocol"}
        elif "exfil" in t_lower:
            return {"tactic": "Exfiltration", "technique": "T1048", "technique_name": "Exfiltration Over Alternative Protocol"}
        elif "dns" in t_lower or "dga" in t_lower:
            return {"tactic": "Command and Control", "technique": "T1568", "technique_name": "Dynamic Resolution"}
        return default_mapping

    tactic = str(mitre_data.get("tactic") or default_mapping["tactic"]).strip()
    technique = str(mitre_data.get("technique") or mitre_data.get("technique_id") or "T1000").strip()
    technique_name = str(mitre_data.get("technique_name") or default_mapping["technique_name"]).strip()

    if not TECHNIQUE_RE.match(technique):
        technique = "T1000"

    return {
        "tactic": tactic,
        "technique": technique,
        "technique_name": technique_name,
    }


def normalize_evidence(evidence_data: Any) -> Dict[str, Any]:
    """Ensure evidence is an object/dict."""
    if isinstance(evidence_data, dict):
        return dict(evidence_data)
    if isinstance(evidence_data, (list, tuple)):
        return {"indicators": [str(x) for x in evidence_data]}
    if evidence_data is not None:
        return {"details": str(evidence_data)}
    return {}


def normalize_alert(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes any member alert dictionary to strictly satisfy shared/alert_schema.json.
    Raises ValueError if mandatory data cannot be repaired.
    """
    if not isinstance(raw_alert, dict):
        raise ValueError("Alert must be a dictionary")

    # 1. Alert ID
    alert_id = raw_alert.get("alert_id")
    if not alert_id or not isinstance(alert_id, str) or not ALERT_ID_RE.match(alert_id):
        alert_id = _get_next_alert_id()

    # 2. Timestamp
    ts = raw_alert.get("timestamp")
    if not ts:
        ts = datetime.now(timezone.utc).isoformat()
    elif isinstance(ts, (int, float)):
        ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    elif isinstance(ts, str):
        try:
            # Validate ISO format
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc).isoformat()

    # 3. Threat
    threat_raw = raw_alert.get("threat") or raw_alert.get("threat_class") or raw_alert.get("title") or "Cyber Threat"
    threat = normalize_threat_name(str(threat_raw))

    # 4. Severity
    severity = normalize_severity(raw_alert.get("severity"))

    # 5. Confidence
    try:
        conf = float(raw_alert.get("confidence", 0.85))
        conf = max(0.0, min(1.0, conf))
    except (ValueError, TypeError):
        conf = 0.50

    # 6. Source IP & Port
    source_ip = raw_alert.get("source_ip") or raw_alert.get("src_ip")
    if not source_ip and isinstance(raw_alert.get("source"), dict):
        source_ip = raw_alert["source"].get("src_ip")
    source_ip = str(source_ip or "0.0.0.0").strip()

    source_port = raw_alert.get("source_port") or raw_alert.get("src_port")
    if source_port is None and isinstance(raw_alert.get("source"), dict):
        source_port = raw_alert["source"].get("src_port")
    try:
        source_port = int(source_port)
        if not (0 <= source_port <= 65535):
            source_port = 0
    except (ValueError, TypeError):
        source_port = 0

    # 7. Destination IP & Port
    dst_ip = raw_alert.get("destination_ip") or raw_alert.get("dst_ip")
    if not dst_ip and isinstance(raw_alert.get("destination"), dict):
        dst_ip = raw_alert["destination"].get("dst_ip")
    destination_ip = str(dst_ip or "0.0.0.0").strip()

    dst_port = raw_alert.get("destination_port") or raw_alert.get("dst_port")
    if dst_port is None and isinstance(raw_alert.get("destination"), dict):
        dst_port = raw_alert["destination"].get("dst_port")
    try:
        destination_port = int(dst_port)
        if not (0 <= destination_port <= 65535):
            destination_port = 0
    except (ValueError, TypeError):
        destination_port = 0

    # 8. Protocol
    protocol = normalize_protocol(raw_alert.get("protocol"))

    # 9. MITRE
    mitre = normalize_mitre(raw_alert.get("mitre") or raw_alert.get("mitre_mapping"), threat_name=threat)

    # 10. Evidence
    evidence = normalize_evidence(raw_alert.get("evidence"))

    normalized = {
        "alert_id": alert_id,
        "timestamp": ts,
        "threat": threat,
        "severity": severity,
        "confidence": conf,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "mitre": mitre,
        "evidence": evidence,
    }

    # Validate against strict contract
    errors = validate_alert(normalized)
    if errors:
        raise ValueError(f"Failed to normalize alert into valid contract: {errors}")

    return normalized
