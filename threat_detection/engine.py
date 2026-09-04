"""
engine.py
=========

The single stable entry point the rest of the team integrates against:

    alert = engine.detect(feature_record)   # Alert | None

Milestone 1 wiring:

    FeatureRecord -> validator -> [DDoSDetector, PortScanDetector]
                  -> pick highest-scoring detected threat
                  -> AlertGenerator -> Alert

Milestone 3 will insert an ML detector + a real fusion engine between the
rule detectors and the alert generator; this class is structured so that
swap is additive, not a rewrite (see `_run_detectors`).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from .alerts.generator import Alert, AlertGenerator
from .config_loader import load_config
from .feature_schema import FeatureRecord
from .rules.base import DetectionResult
from .rules.ddos import DDoSDetector
from .rules.port_scan import PortScanDetector
from .validator import validate_feature

logger = logging.getLogger("threat_detection.engine")


class ThreatDetectionEngine:
    def __init__(self, config: dict | None = None):
        self.config = config or load_config()
        self.ddos_detector = DDoSDetector(self.config)
        self.port_scan_detector = PortScanDetector(self.config)
        self.alert_generator = AlertGenerator()
        self.min_confidence = self.config["detection"]["minimum_confidence"]

    def _run_detectors(self, feature: FeatureRecord) -> List[DetectionResult]:
        """
        Runs every rule detector against the feature record.

        NOTE: In Milestone 1 there is no fusion step yet -- each detector
        is independent and we simply keep every result. `detect()` below
        picks the best one. When ML + behavioural detectors and real
        fusion (Milestone 3) are added, this method's return type stays
        the same (List[DetectionResult]); only what happens to that list
        afterwards changes.
        """
        return [
            self.ddos_detector.detect(feature),
            self.port_scan_detector.detect(feature),
        ]

    def detect(self, feature: FeatureRecord) -> Optional[Alert]:
        """
        Returns a structured Alert, or None if no threat was detected
        (or the input was invalid). Never raises on malformed input --
        malformed records are logged and discarded (PROMPT section 29).
        """
        validation = validate_feature(feature)
        if not validation.is_valid:
            logger.warning(
                "Discarding invalid feature record flow_id=%s errors=%s",
                getattr(feature, "flow_id", "<unknown>"),
                validation.errors,
            )
            return None

        results = self._run_detectors(feature)

        detected_results = [r for r in results if r.detected and r.score >= self.min_confidence]
        if not detected_results:
            logger.debug("No detection for flow_id=%s", feature.flow_id)
            return None

        # Milestone 1: no cross-detector fusion yet -- take the strongest
        # single detection. This is an explicit, documented simplification,
        # not an accident (see engine.py docstring / README "Limitations").
        best = max(detected_results, key=lambda r: r.score)

        alert = self.alert_generator.generate(feature, best, config=self.config)
        logger.info(
            "ALERT %s threat=%s confidence=%.2f severity=%s flow_id=%s",
            alert.alert_id, alert.threat_class, alert.confidence,
            alert.severity, alert.flow_id,
        )
        return alert
