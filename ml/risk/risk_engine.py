"""
Explainable Engineering Risk Scoring Engine Module.

Calculates a deterministic 0-100 risk score by normalizing 5 core security components:
  1. ML Classifier Confidence Score (0-100) - weight: 0.25
  2. Isolation Forest Anomaly Score (0-100) - weight: 0.20
  3. Alert Severity Score (0-100) - weight: 0.25
  4. Threat Intel Reputation Score (0-100) - weight: 0.15
  5. Event Correlation Count Score (0-100) - weight: 0.15

Documented as an explainable engineering risk score used to prioritize SOC investigations.
"""

import logging
import numpy as np
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {
    "INFO": 10.0,
    "LOW": 30.0,
    "MEDIUM": 50.0,
    "HIGH": 80.0,
    "CRITICAL": 100.0,
}

INTEL_SCORES = {
    "BENIGN": 0.0,
    "UNKNOWN": 20.0,
    "UNAVAILABLE": 20.0,
    "SUSPICIOUS": 60.0,
    "MALICIOUS": 100.0,
}


@dataclass
class RiskScoreResult:
    """Structured Risk Score Result."""
    score: float         # 0.0 to 100.0
    level: str           # LOW / MEDIUM / HIGH / CRITICAL
    components: Dict[str, float]
    weights: Dict[str, float]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RiskEngine:
    """
    Deterministic explainable risk scoring engine.
    """

    def __init__(self):
        # Weights summing strictly to 1.0
        self.weights = {
            "confidence": 0.25,
            "anomaly": 0.20,
            "severity": 0.25,
            "intel": 0.15,
            "correlation": 0.15,
        }

    def calculate_risk(
        self,
        confidence: float,
        anomaly_score: float,
        severity: str,
        intel_reputation: str = "UNKNOWN",
        correlated_event_count: int = 1,
    ) -> RiskScoreResult:
        """
        Calculate normalized risk score (0-100) and risk level.
        """
        # 1. Component normalization (0-100)
        s_conf = float(np.clip(confidence * 100.0, 0.0, 100.0))
        s_anom = float(np.clip(anomaly_score * 100.0, 0.0, 100.0))
        s_sev = SEVERITY_SCORES.get(severity.upper(), 30.0)
        s_intel = INTEL_SCORES.get(intel_reputation.upper(), 20.0)
        s_corr = float(np.clip(correlated_event_count * 25.0, 0.0, 100.0))

        components = {
            "confidence_score": round(s_conf, 2),
            "anomaly_score": round(s_anom, 2),
            "severity_score": round(s_sev, 2),
            "intel_score": round(s_intel, 2),
            "correlation_score": round(s_corr, 2),
        }

        # 2. Weighted sum computation
        raw_score = (
            self.weights["confidence"] * s_conf +
            self.weights["anomaly"] * s_anom +
            self.weights["severity"] * s_sev +
            self.weights["intel"] * s_intel +
            self.weights["correlation"] * s_corr
        )

        final_score = round(float(np.clip(raw_score, 0.0, 100.0)), 2)

        # 3. Risk level categorization
        if final_score >= 85.0:
            level = "CRITICAL"
        elif final_score >= 60.0:
            level = "HIGH"
        elif final_score >= 30.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        explanation = (
            f"Risk score {final_score:.1f}/100 ({level}) computed from ML confidence ({components['confidence_score']:.1f}), "
            f"anomaly severity ({components['anomaly_score']:.1f}), alert severity ({components['severity_score']:.1f}), "
            f"threat intel reputation ({components['intel_score']:.1f}), and event correlation depth ({components['correlation_score']:.1f})."
        )

        return RiskScoreResult(
            score=final_score,
            level=level,
            components=components,
            weights=self.weights,
            explanation=explanation,
        )
