"""
Alert Generation Module for Phase 3.

Converts normalized threat events and decision results into structured, deterministic alerts:
  - BENIGN -> INFO
  - SUSPICIOUS -> LOW
  - ANOMALOUS -> MEDIUM
  - MALICIOUS -> HIGH / CRITICAL (for severe attack vectors)
"""

import uuid
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional
from ml.config.detection_config import get_detection_config, DetectionConfig

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Structured Alert object."""
    alert_id: str
    severity: str        # INFO / LOW / MEDIUM / HIGH / CRITICAL
    title: str
    threat_class: str
    decision: str
    confidence: float
    anomaly_score: float
    timestamp: str       # ISO-8601 timestamp
    status: str          # NEW

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AlertGenerator:
    """
    Generates structured Alert objects from decision results and network metadata.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or get_detection_config()

    def generate_alert(self, decision_result: Any, metadata: Optional[Dict[str, Any]] = None) -> Alert:
        """
        Generate structured Alert object.
        """
        decision = decision_result.decision
        threat_class = decision_result.threat_class
        confidence = decision_result.confidence
        anomaly_score = decision_result.anomaly_score

        # Determine severity
        if decision == "BENIGN":
            severity = "INFO"
            title = "Benign Network Flow"
        elif decision == "SUSPICIOUS":
            severity = "LOW"
            title = f"Suspicious Activity Detected ({threat_class})"
        elif decision == "ANOMALOUS":
            severity = "MEDIUM"
            title = f"Network Traffic Anomaly Detected (Score: {anomaly_score:.2f})"
        elif decision == "MALICIOUS":
            if threat_class in self.config.critical_attack_classes:
                severity = "CRITICAL"
            else:
                severity = "HIGH"
            title = f"{threat_class.replace('_', ' ')} Attack Detected"
        else:
            severity = "MEDIUM"
            title = f"Security Alert: {threat_class}"

        alert_id = str(uuid.uuid4())
        timestamp_iso = datetime.now(timezone.utc).isoformat()

        return Alert(
            alert_id=alert_id,
            severity=severity,
            title=title,
            threat_class=threat_class,
            decision=decision,
            confidence=confidence,
            anomaly_score=anomaly_score,
            timestamp=timestamp_iso,
            status="NEW",
        )
