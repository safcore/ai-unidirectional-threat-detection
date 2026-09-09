"""Adapter between the M4 engine and the existing Flask alert contract."""
from __future__ import annotations

import json
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from ml.detection.detection_engine import get_detection_engine
from ml.investigation.incident_manager import get_incident_manager


_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "ml" / "models" / "feature_schema.json"
_alert_counter = 0
_alert_counter_lock = threading.Lock()


def _feature_names() -> set[str]:
    with _SCHEMA_PATH.open("r", encoding="utf-8") as schema_file:
        return set(json.load(schema_file)["ml_feature_names"])


def validate_detection_input(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return ["Request body must be a JSON object"]
    features = data.get("features")
    if not isinstance(features, dict):
        return ["'features' must be an object containing the 66 M2 features"]

    expected = _feature_names()
    missing = sorted(expected - set(features))
    extra = sorted(set(features) - expected)
    errors: list[str] = []
    if missing:
        errors.append(f"Missing features: {', '.join(missing)}")
    if extra:
        errors.append(f"Unexpected features: {', '.join(extra)}")

    metadata = data.get("metadata", {})
    if metadata is not None and not isinstance(metadata, dict):
        errors.append("'metadata' must be an object")
    elif isinstance(metadata, dict):
        for field in ("src_port", "dst_port"):
            if field in metadata and (
                not isinstance(metadata[field], int) or not 0 <= metadata[field] <= 65535
            ):
                errors.append(f"'{field}' must be an integer between 0 and 65535")
        for field in ("src_ip", "dst_ip"):
            if field in metadata and (not isinstance(metadata[field], str) or not metadata[field].strip()):
                errors.append(f"'{field}' must be a non-empty string")
    return errors


def m4_available() -> bool:
    try:
        _feature_names()
        get_detection_engine
        get_incident_manager
        return True
    except Exception:
        return False


def _next_alert_id() -> str:
    global _alert_counter
    with _alert_counter_lock:
        if _alert_counter == 0:
            existing_alerts = []
            try:
                from app import alert_store as _store
                existing_alerts = _store.get_all()
            except Exception:
                try:
                    from backend.app import alert_store as _store
                    existing_alerts = _store.get_all()
                except Exception:
                    pass

            for a in existing_alerts:
                aid = str(a.get("alert_id", ""))
                m = re.match(r"^ALT-(\d+)$", aid)
                if m:
                    _alert_counter = max(_alert_counter, int(m.group(1)))

        _alert_counter += 1
        return f"ALT-{_alert_counter}"


def _mitre_mapping(incident: Any) -> dict[str, Any]:
    mappings = getattr(incident, "mitre_mappings", []) or []
    if mappings:
        mapping = mappings[0]
        return {
            "tactic": mapping.get("tactic", "Unknown"),
            "technique": mapping.get("technique_id", "T0000"),
            "technique_name": mapping.get("technique_name", "No confident mapping"),
        }
    # The frontend contract requires a MITRE object even when no mapping exists.
    return {"tactic": "Unknown", "technique": "T0000", "technique_name": "No confident mapping"}


def event_to_alert(event: dict[str, Any], incident: Any) -> dict[str, Any]:
    source = event.get("source") or {}
    destination = event.get("destination") or {}
    raw_alert = event.get("alert") or {}
    severity = raw_alert.get("severity", "LOW")
    if severity == "INFO":
        severity = "LOW"
    candidate = {
        "alert_id": _next_alert_id(),
        "timestamp": event.get("timestamp") or raw_alert.get("timestamp"),
        "threat": str(event.get("threat_class", "UNKNOWN")).replace("_", " ").title(),
        "severity": severity,
        "confidence": max(0.0, min(1.0, float(event.get("confidence", 0.0)))),
        "source_ip": source.get("src_ip") or "UNKNOWN",
        "destination_ip": destination.get("dst_ip") or "UNKNOWN",
        "source_port": source.get("src_port") if source.get("src_port") is not None else 0,
        "destination_port": destination.get("dst_port") if destination.get("dst_port") is not None else 0,
        "protocol": (event.get("metadata") or {}).get("protocol", "OTHER"),
        "mitre": _mitre_mapping(incident),
        "evidence": {
            "decision_reason": event.get("decision_reason"),
            "anomaly_score": event.get("anomaly_score"),
            "classifications": event.get("classifications", {}),
            "investigation": getattr(incident, "explanation", {}),
            "iocs": getattr(incident, "iocs", []),
        },
    }
    try:
        from app.alert_normalizer import normalize_alert
        return normalize_alert(candidate)
    except ImportError:
        try:
            from backend.app.alert_normalizer import normalize_alert
            return normalize_alert(candidate)
        except ImportError:
            return candidate


def process_detection(features: dict[str, Any], metadata: dict[str, Any]) -> tuple[dict[str, Any], Any, dict[str, Any]]:
    event = get_detection_engine().process(features, metadata=metadata)
    if event.get("status") != "success":
        raise ValueError(event)
    event["metadata"] = metadata
    incident = get_incident_manager().process_event(event)
    alert = event_to_alert(event, incident)
    return event, incident, alert


def process_detection_batch(
    features_list: list[dict[str, Any]], metadata_list: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], Any, dict[str, Any]]]:
    events = get_detection_engine().process_batch(features_list, metadata_list=metadata_list)
    results = []
    inc_mgr = get_incident_manager()
    for ev, meta in zip(events, metadata_list):
        ev["metadata"] = meta
        inc = inc_mgr.process_event(ev)
        alert = event_to_alert(ev, inc)
        results.append((ev, inc, alert))
    return results