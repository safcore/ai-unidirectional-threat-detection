"""
rules/ddos.py
=============

Rule-based DDoS / volumetric-attack detector.

Design: instead of a single hard threshold (packet_rate > X), we compute
several independent 0..1 "component scores" from different signals, then
combine them with configurable weights (PROMPT section 7). This means a
flow that is moderately high on several signals can still be flagged,
while a flow that is high on exactly one noisy signal is less likely to
dominate the result.

All thresholds live in config/thresholds.yaml under `ddos:`.
"""

from __future__ import annotations

from typing import Dict

from ..config_loader import load_config
from ..feature_schema import FeatureRecord
from .base import DetectionResult


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


class DDoSDetector:
    """Stateless, per-flow DDoS scorer."""

    def __init__(self, config: dict | None = None):
        cfg = config or load_config()
        self.cfg = cfg["ddos"]
        self.min_confidence = cfg["detection"]["minimum_confidence"]

    def _component_scores(self, f: FeatureRecord) -> Dict[str, float]:
        c = self.cfg

        # Packet rate: 0 at "warning" threshold, 1.0 at "high" threshold.
        pr_warn, pr_high = c["packet_rate_warning"], c["packet_rate_high"]
        packet_rate_score = _clamp01(
            (f.packet_rate - pr_warn) / max(pr_high - pr_warn, 1e-9)
        )

        # Byte rate: linear up to byte_rate_high.
        byte_rate_score = _clamp01(f.byte_rate / max(c["byte_rate_high"], 1e-9))

        # SYN rate (SYN packets per second).
        syn_rate = f.syn_count / max(f.flow_duration, 1e-9)
        syn_rate_score = _clamp01(syn_rate / max(c["syn_rate_high"], 1e-9))

        # SYN/ACK imbalance: many SYNs, almost no ACKs -> classic SYN flood.
        syn_ack_ratio = f.syn_count / max(f.ack_count, 1)
        syn_ack_score = _clamp01(
            syn_ack_ratio / max(c["syn_ack_imbalance_ratio"], 1e-9)
        )

        # Short-duration, high-volume shape.
        if (
            f.flow_duration <= c["short_duration_seconds"]
            and f.packet_count >= c["short_duration_packet_count"]
        ):
            short_duration_score = 1.0
        else:
            # partial credit as it approaches the shape
            duration_factor = _clamp01(
                1 - (f.flow_duration / max(c["short_duration_seconds"], 1e-9))
            )
            volume_factor = _clamp01(
                f.packet_count / max(c["short_duration_packet_count"], 1e-9)
            )
            short_duration_score = duration_factor * volume_factor

        return {
            "packet_rate": packet_rate_score,
            "byte_rate": byte_rate_score,
            "syn_rate": syn_rate_score,
            "syn_ack_imbalance": syn_ack_score,
            "short_duration_volume": short_duration_score,
        }

    def detect(self, f: FeatureRecord) -> DetectionResult:
        c = self.cfg

        # Ignore trivially small flows -- not enough evidence either way.
        if f.packet_count < c["min_packet_count"]:
            return DetectionResult(
                detected=False, threat_class="DDoS", score=0.0,
                reasons=["Flow too small to evaluate for DDoS"],
            )

        components = self._component_scores(f)
        weights = c["weights"]

        score = sum(components[name] * weights[name] for name in weights)
        score = _clamp01(score)

        reasons = []
        contributing: Dict[str, float] = {}

        if components["packet_rate"] > 0:
            reasons.append(
                f"Packet rate {f.packet_rate:.0f} pkt/s exceeds baseline "
                f"(warning={c['packet_rate_warning']}, high={c['packet_rate_high']})"
            )
            contributing["packet_rate"] = f.packet_rate

        if components["byte_rate"] > 0.3:
            reasons.append(
                f"Byte rate {f.byte_rate:.0f} B/s is elevated "
                f"(high threshold={c['byte_rate_high']})"
            )
            contributing["byte_rate"] = f.byte_rate

        if components["syn_rate"] > 0.3:
            reasons.append(
                f"High SYN activity: {f.syn_count} SYNs over "
                f"{f.flow_duration:.2f}s (~{f.syn_count / max(f.flow_duration, 1e-9):.0f}/s)"
            )
            contributing["syn_count"] = f.syn_count

        if components["syn_ack_imbalance"] > 0.3:
            reasons.append(
                f"SYN/ACK imbalance: {f.syn_count} SYN vs {f.ack_count} ACK"
            )
            contributing["syn_ack_ratio"] = f.syn_count / max(f.ack_count, 1)

        if components["short_duration_volume"] > 0.3:
            reasons.append(
                f"Large packet volume ({f.packet_count}) observed over short "
                f"duration ({f.flow_duration:.2f}s)"
            )
            contributing["flow_duration"] = f.flow_duration
            contributing["packet_count"] = f.packet_count

        detected = score >= self.min_confidence

        return DetectionResult(
            detected=detected,
            threat_class="DDoS",
            score=score,
            reasons=reasons if reasons else ["No individual signal was significant"],
            contributing_features=contributing,
            detection_method="RULE",
        )
