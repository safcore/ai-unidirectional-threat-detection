"""
rules/port_scan.py
===================

Stateful port-scan / reconnaissance detector.

A single flow can almost never prove a port scan -- you need to see one
source IP touching many distinct destination ports within a short time
window (PROMPT section 8). So this detector keeps small, bounded,
per-source-IP state (a deque of recent (timestamp, dst_port, syn_count)
events) and scores based on aggregated behaviour in a sliding window.

State is bounded by time (old events are pruned every call) so memory
does not grow unbounded in a long-running streaming process
(PROMPT section 23).
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Tuple

from ..config_loader import load_config
from ..feature_schema import FeatureRecord
from .base import DetectionResult


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


@dataclass
class _Event:
    epoch_seconds: float
    dst_ip: str
    dst_port: int
    syn_count: int


class PortScanDetector:
    """
    Maintains per-source-IP sliding-window state across multiple calls to
    `detect()`. Intended to be instantiated ONCE per detection engine and
    reused across the whole stream (it is NOT stateless like DDoSDetector).
    """

    def __init__(self, config: dict | None = None):
        cfg = config or load_config()
        self.cfg = cfg["port_scan"]
        self.min_confidence = cfg["detection"]["minimum_confidence"]
        self._state: Dict[str, Deque[_Event]] = defaultdict(deque)

    def _prune(self, src_ip: str, now: float) -> None:
        window = self.cfg["window_seconds"]
        events = self._state[src_ip]
        while events and (now - events[0].epoch_seconds) > window:
            events.popleft()

    def detect(self, f: FeatureRecord) -> DetectionResult:
        c = self.cfg
        now = f.parsed_timestamp().timestamp()

        # Record this flow's event for the source IP, then prune stale ones.
        self._state[f.src_ip].append(
            _Event(now, f.dst_ip, f.dst_port, f.syn_count)
        )
        self._prune(f.src_ip, now)

        events = list(self._state[f.src_ip])

        if len(events) < c["min_events_to_evaluate"]:
            return DetectionResult(
                detected=False, threat_class="PortScan", score=0.0,
                reasons=[
                    f"Only {len(events)} flow(s) observed for {f.src_ip} in "
                    f"window; need at least {c['min_events_to_evaluate']} to evaluate"
                ],
            )

        unique_ports = {e.dst_port for e in events}
        unique_dst_ips = {e.dst_ip for e in events}
        total_syns = sum(e.syn_count for e in events)
        window_span = now - events[0].epoch_seconds

        # Component 1: breadth of unique destination ports touched.
        port_score = _clamp01(
            len(unique_ports) / max(c["unique_ports_high"], 1)
        )

        # Component 2: SYN intensity (many SYNs with few/no full handshakes
        # is typical of a fast SYN scan).
        syn_score = _clamp01(total_syns / max(c["syn_count_high"], 1))

        # Component 3: concentration -- scanning many ports on FEW distinct
        # destination IPs (i.e. focused on one or two targets) is a
        # stronger reconnaissance signal than the same port count spread
        # across many destinations (which could just be normal client
        # behaviour, e.g. many short-lived connections to a CDN).
        concentration_score = _clamp01(
            len(unique_ports) / max(len(unique_dst_ips), 1) / max(c["unique_ports_high"], 1)
        )

        weights = c["weights"]
        score = _clamp01(
            port_score * weights["unique_ports"]
            + syn_score * weights["syn_intensity"]
            + concentration_score * weights["port_concentration"]
        )

        reasons = []
        contributing: Dict[str, float] = {}

        if len(unique_ports) >= c["unique_ports_warning"]:
            reasons.append(
                f"Source {f.src_ip} contacted {len(unique_ports)} unique "
                f"destination ports within {window_span:.1f}s"
            )
            contributing["unique_dst_ports"] = len(unique_ports)

        if total_syns >= c["syn_count_high"] * 0.3:
            reasons.append(f"High SYN activity observed: {total_syns} SYNs in window")
            contributing["syn_count_in_window"] = total_syns

        if len(unique_dst_ips) == 1 and len(unique_ports) >= c["unique_ports_warning"]:
            reasons.append(
                f"Connection pattern is consistent with reconnaissance: many "
                f"ports probed on a single destination ({next(iter(unique_dst_ips))})"
            )

        detected = score >= self.min_confidence

        return DetectionResult(
            detected=detected,
            threat_class="PortScan",
            score=score,
            reasons=reasons if reasons else ["No individual signal was significant"],
            contributing_features=contributing,
            detection_method="RULE",
        )

    def reset(self) -> None:
        """Clear all per-source state. Mainly useful for tests."""
        self._state.clear()
