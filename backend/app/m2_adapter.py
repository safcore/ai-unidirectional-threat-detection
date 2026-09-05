"""Normalize M2 output before handing it to the existing M4 pipeline."""
from __future__ import annotations

from typing import Any

from .m4_integration import _feature_names, process_detection


class M2AdapterError(ValueError):
    """Raised when an M2 payload cannot satisfy the canonical M4 contract."""


def normalize_m2_output(m2_output: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return canonical features and metadata without inventing or dropping fields."""
    if not isinstance(m2_output, dict):
        raise M2AdapterError("M2 output must be a JSON object")

    raw_features = m2_output.get("features")
    if not isinstance(raw_features, dict):
        raise M2AdapterError("M2 output must contain a 'features' object")

    expected = _feature_names()
    missing = sorted(expected - set(raw_features))
    extra = sorted(set(raw_features) - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing canonical features: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected features: {', '.join(extra)}")
        raise M2AdapterError("M2 output does not match the canonical 66-feature schema (" + "; ".join(details) + ")")

    metadata = m2_output.get("metadata", {})
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise M2AdapterError("M2 output 'metadata' must be an object")

    # Permit the common flat M2 transport shape while preferring explicit metadata.
    normalized_metadata = dict(metadata)
    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
        if field not in normalized_metadata and field in m2_output:
            normalized_metadata[field] = m2_output[field]

    return dict(raw_features), normalized_metadata


def process_flow(m2_output: Any) -> tuple[dict[str, Any], Any, dict[str, Any]]:
    """Run one canonical M2 output through M4, investigation, storage, and SSE."""
    features, metadata = normalize_m2_output(m2_output)
    event, incident, alert = process_detection(features, metadata)

    from . import alert_store, stream_manager

    stored = alert_store.add(alert)
    stream_manager.broadcast(stored)
    return event, incident, stored