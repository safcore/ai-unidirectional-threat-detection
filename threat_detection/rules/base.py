"""
base.py
=======

Shared result type returned by every detector (rule-based today, ML /
behavioural later). Keeping this uniform is what lets the fusion engine
(Milestone 3) treat all detectors interchangeably.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DetectionResult:
    """
    Output of a single detector for a single feature record.

    detected:      whether this detector believes a threat is present
    threat_class:  e.g. "DDoS", "PortScan"
    score:         this detector's own 0.0-1.0 score. NOT the same thing
                   as a calibrated "confidence" -- see PROMPT section 16.
                   The engine may relabel this as "confidence" only when
                   this is the sole contributing detector.
    reasons:       machine-readable trigger reasons, used to build
                   human-readable evidence strings downstream.
    contributing_features: raw feature values that drove the score, kept
                   for explainability (PROMPT section 31).
    detection_method: tag identifying the detector family, e.g. "RULE".
    """

    detected: bool
    threat_class: str
    score: float
    reasons: List[str] = field(default_factory=list)
    contributing_features: Dict[str, float] = field(default_factory=dict)
    detection_method: str = "RULE"
