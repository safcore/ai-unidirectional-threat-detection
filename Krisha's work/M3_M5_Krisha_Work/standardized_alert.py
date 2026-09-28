"""M5 adapter for the standardized alert payload."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from ml.mitre.attack_mapper import MITREAttackMapper
from ml.risk.risk_engine import RiskEngine


REQUIRED_ALERT_FIELDS = {
    "alert_id", "timestamp", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "threat_class", "confidence", "severity",
    "risk_score", "evidence", "mitre_mapping", "ioc_data", "correlation_data",
    "ai_analysis",
}


def validate_standardized_alert(alert: dict[str, Any]) -> dict[str, Any]:
    missing = sorted(REQUIRED_ALERT_FIELDS - alert.keys())
    if missing:
        raise ValueError(f"Standardized alert missing required fields: {missing}")
    if not isinstance(alert["alert_id"], str) or not alert["alert_id"]:
        raise ValueError("Standardized alert alert_id must be a non-empty string")
    if not isinstance(alert["threat_class"], str) or not alert["threat_class"]:
        raise ValueError("Standardized alert threat_class must be a non-empty string")
    if not isinstance(alert["confidence"], (int, float)) or not 0.0 <= alert["confidence"] <= 1.0:
        raise ValueError("Standardized alert confidence must be between 0 and 1")
    if not isinstance(alert["risk_score"], (int, float)) or not 0.0 <= alert["risk_score"] <= 100.0:
        raise ValueError("Standardized alert risk_score must be between 0 and 100")
    if not isinstance(alert["evidence"], list) or not all(isinstance(item, str) for item in alert["evidence"]):
        raise ValueError("Standardized alert evidence must be a list of strings")
    if alert["mitre_mapping"] is not None and not isinstance(alert["mitre_mapping"], dict):
        raise ValueError("Standardized alert mitre_mapping must be an object or null")
    for field in ("ioc_data", "correlation_data", "ai_analysis"):
        if not isinstance(alert[field], dict):
            raise ValueError(f"Standardized alert {field} must be an object")
    return alert


def build_standardized_alert(
    event: dict[str, Any],
    mapper: MITREAttackMapper | None = None,
    risk_engine: RiskEngine | None = None,
) -> dict[str, Any]:
    """Enrich a normalized event without replacing M4 alert generation."""
    mapper = mapper or MITREAttackMapper()
    risk_engine = risk_engine or RiskEngine()
    mappings = mapper.map_event(event)
    mapping = mappings[0].to_dict() if mappings else None

    legacy_alert = event.get("alert", {})
    severity = legacy_alert.get("severity", "INFO")
    risk_result = risk_engine.calculate_risk(
        confidence=float(event.get("confidence", 0.0)),
        anomaly_score=float(event.get("anomaly_score", 0.0)),
        severity=severity,
        intel_reputation=event.get("intel_reputation", "UNKNOWN"),
        correlated_event_count=int(event.get("correlation_data", {}).get("correlated_event_count", 1)),
    )
    source = event.get("source", {})
    destination = event.get("destination", {})
    evidence = event.get("evidence") or (mapping.get("evidence", []) if mapping else [])
    if not evidence and event.get("telemetry"):
        evidence = [
            f"Observed feature {name}={value}"
            for name, value in event["telemetry"].items()
        ]

    alert = {
        "alert_id": legacy_alert.get("alert_id", f"alt-{uuid.uuid4()}"),
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source_ip": source.get("src_ip"),
        "destination_ip": destination.get("dst_ip"),
        "source_port": source.get("src_port"),
        "destination_port": destination.get("dst_port"),
        "protocol": event.get("protocol"),
        "threat_class": event.get("threat_class"),
        "confidence": float(event.get("confidence", 0.0)),
        "severity": severity,
        "risk_score": risk_result.score,
        "evidence": evidence,
        "mitre_mapping": mapping,
        "ioc_data": event.get("ioc_data", {"extracted_iocs": [], "intel_hits": []}),
        "correlation_data": event.get(
            "correlation_data",
            {"entity_id": None, "correlated_event_count": 1},
        ),
        "ai_analysis": event.get(
            "ai_analysis",
            {"status": "NOT_REQUESTED", "model": None},
        ),
    }
    return validate_standardized_alert(alert)