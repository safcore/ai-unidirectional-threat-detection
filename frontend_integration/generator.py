"""
alerts/generator.py
====================

Builds the stable, structured Alert schema that the backend/dashboard
consumes (PROMPT section 19). This is the ONE place that assembles the
final JSON-able shape -- detectors and the severity/evidence engines
never construct alerts themselves.

MITRE ATT&CK mapping (PROMPT section 20): technique IDs are NOT
hallucinated. We only ship a tactic name plus an explicit note that the
exact technique ID must be verified before presentation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from itertools import count
from typing import Dict, List, Optional

from ..feature_schema import FeatureRecord
from ..rules.base import DetectionResult
from .severity import Severity, compute_severity
from .evidence import build_evidence

# Tactic-only MITRE mapping. Technique IDs deliberately omitted --
# verify exact technique IDs against the current ATT&CK matrix before
# using them in a presentation or a real alert pipeline.
_MITRE_TACTIC_BY_THREAT = {
    "DDoS": {"tactic": "Impact", "technique_id": None, "verify": True},
    "PortScan": {"tactic": "Reconnaissance", "technique_id": None, "verify": True},
}


@dataclass
class Endpoint:
    ip: str
    port: int


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    flow_id: str

    source: Endpoint
    destination: Endpoint
    protocol: str

    threat_class: str
    confidence: float
    severity: str

    detection_method: List[str]
    evidence: List[str]

    mitre: Dict[str, Optional[str] | bool]
    status: str = "NEW"

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class AlertGenerator:
    """
    Stateful only in the sense that it hands out sequential alert IDs.
    Safe to share a single instance across the whole detection engine.
    """

    def __init__(self, id_prefix: str = "ALT"):
        self._id_prefix = id_prefix
        self._counter = count(1)

    def _next_alert_id(self) -> str:
        return f"{self._id_prefix}-{next(self._counter):06d}"

    def generate(
        self,
        feature: FeatureRecord,
        result: DetectionResult,
        config: dict | None = None,
    ) -> Alert:
        if not result.detected:
            raise ValueError(
                "AlertGenerator.generate() called with a non-detection; "
                "check result.detected before calling this."
            )

        confidence = round(result.score, 4)
        severity = compute_severity(
            result.threat_class, confidence, feature, config=config
        )
        evidence = build_evidence(result)
        mitre = _MITRE_TACTIC_BY_THREAT.get(
            result.threat_class,
            {"tactic": "Unknown", "technique_id": None, "verify": True},
        )

        return Alert(
            alert_id=self._next_alert_id(),
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            flow_id=feature.flow_id,
            source=Endpoint(ip=feature.src_ip, port=feature.src_port),
            destination=Endpoint(ip=feature.dst_ip, port=feature.dst_port),
            protocol=feature.protocol,
            threat_class=result.threat_class,
            confidence=confidence,
            severity=severity.value,
            detection_method=[result.detection_method],
            evidence=evidence,
            mitre=dict(mitre),
            status="NEW",
        )
