"""
Threat Decision Engine Module.

Applies deterministic decision logic on classifier predictions and anomaly scores:
  - BENIGN: threat_class == "BENIGN" & confidence >= benign_threshold & anomaly_score < anomaly_threshold
  - MALICIOUS: threat_class != "BENIGN" & confidence >= malicious_threshold
  - ANOMALOUS: anomaly_score >= anomaly_threshold
  - SUSPICIOUS: threat_class != "BENIGN" & confidence < malicious_threshold
"""

import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional
from ml.config.detection_config import get_detection_config, DetectionConfig

logger = logging.getLogger(__name__)


@dataclass
class DecisionResult:
    """Structured decision output."""
    decision: str  # BENIGN / MALICIOUS / SUSPICIOUS / ANOMALOUS
    threat_class: str
    confidence: float
    anomaly_score: float
    reason: str


class DecisionEngine:
    """
    Deterministic threat decision engine.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or get_detection_config()

    def evaluate(self, prediction_result: Dict[str, Any]) -> DecisionResult:
        """
        Evaluate prediction result dict against configured decision rules.
        """
        threat_class = str(prediction_result.get("threat_class", "BENIGN"))
        confidence = float(prediction_result.get("confidence", 1.0))
        anomaly_score = float(prediction_result.get("anomaly_score", 0.0))

        mal_thresh = self.config.malicious_confidence_threshold
        ben_thresh = self.config.benign_confidence_threshold
        anom_thresh = self.config.anomaly_threshold

        # 1. ANOMALOUS Check (Unsupervised Isolation Forest score trigger)
        if anomaly_score >= anom_thresh:
            if threat_class != "BENIGN" and confidence >= mal_thresh:
                decision = "MALICIOUS"
                reason = f"High confidence attack prediction '{threat_class}' ({confidence:.2f}) with high anomaly score ({anomaly_score:.2f})."
            else:
                decision = "ANOMALOUS"
                reason = f"High anomaly score ({anomaly_score:.2f} >= threshold {anom_thresh:.2f})."

        # 2. MALICIOUS Check (High confidence supervised attack prediction)
        elif threat_class != "BENIGN" and confidence >= mal_thresh:
            decision = "MALICIOUS"
            reason = f"High confidence attack prediction '{threat_class}' ({confidence:.2f} >= threshold {mal_thresh:.2f})."

        # 3. SUSPICIOUS Check (Low confidence supervised attack prediction)
        elif threat_class != "BENIGN" and confidence < mal_thresh:
            decision = "SUSPICIOUS"
            reason = f"Low confidence attack prediction '{threat_class}' ({confidence:.2f} < threshold {mal_thresh:.2f})."

        # 4. BENIGN Check
        elif threat_class == "BENIGN" and confidence >= ben_thresh and anomaly_score < anom_thresh:
            decision = "BENIGN"
            reason = f"Confirmed BENIGN flow with confidence {confidence:.2f} and low anomaly score {anomaly_score:.2f}."

        else:
            decision = "SUSPICIOUS"
            reason = f"Uncertain prediction parameters (class='{threat_class}', confidence={confidence:.2f}, anomaly={anomaly_score:.2f})."

        return DecisionResult(
            decision=decision,
            threat_class=threat_class,
            confidence=confidence,
            anomaly_score=anomaly_score,
            reason=reason,
        )
