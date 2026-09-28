"""
Module 3 (M3) — AI Threat Detection Engine
==========================================
Provides multi-class network threat classification for:
- BENIGN
- SYN_FLOOD
- UDP_FLOOD
- PORT_SCAN
"""

from .schema import ThreatClass, SeverityLevel, ThreatAlert
from .detector import ThreatDetector
from .features import extract_features, MODEL_FEATURE_NAMES
from .model import ThreatClassifier

__all__ = [
    "ThreatClass",
    "SeverityLevel",
    "ThreatAlert",
    "ThreatDetector",
    "ThreatClassifier",
    "extract_features",
    "MODEL_FEATURE_NAMES",
]
