"""
Investigation Timeline Module.

Builds chronological timeline representations of security events and incident progressions
with filterable search parameters.
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TimelineEntry:
    """Structured Timeline Entry."""
    timestamp: str
    event_id: str
    threat_class: str
    decision: str
    severity: str
    risk_score: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    mitre_technique_id: Optional[str]
    evidence_snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TimelineBuilder:
    """
    Chronological timeline generator.
    """

    def build_timeline(self, events: List[Dict[str, Any]], risk_scores: Optional[List[float]] = None) -> List[TimelineEntry]:
        """
        Build chronological timeline entries from an event list.
        """
        sorted_events = sorted(events, key=lambda e: str(e.get("timestamp", "")))
        entries: List[TimelineEntry] = []

        for idx, evt in enumerate(sorted_events):
            timestamp = evt.get("timestamp", "")
            event_id = evt.get("event_id", f"evt-{idx+1}")
            threat_class = evt.get("threat_class", "BENIGN")
            decision = evt.get("decision", "BENIGN")
            alert = evt.get("alert", {})
            severity = alert.get("severity", "INFO")
            
            src_ip = evt.get("source", {}).get("src_ip")
            dst_ip = evt.get("destination", {}).get("dst_ip")
            dst_port = evt.get("destination", {}).get("dst_port")

            score = risk_scores[idx] if risk_scores and idx < len(risk_scores) else 30.0

            evidence = f"Observed '{threat_class}' ({decision}) targeting port {dst_port if dst_port else 'N/A'} with confidence {evt.get('confidence', 0.0):.2f}."

            entries.append(TimelineEntry(
                timestamp=timestamp,
                event_id=event_id,
                threat_class=threat_class,
                decision=decision,
                severity=severity,
                risk_score=score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                mitre_technique_id=None,
                evidence_snippet=evidence,
            ))

        return entries

    def filter_timeline(
        self,
        entries: List[TimelineEntry],
        min_severity: Optional[str] = None,
        threat_class_filter: Optional[str] = None,
        src_ip_filter: Optional[str] = None,
    ) -> List[TimelineEntry]:
        """Filter timeline entries by severity, threat class, or IP."""
        filtered = entries
        if threat_class_filter:
            filtered = [e for e in filtered if e.threat_class.upper() == threat_class_filter.upper()]
        if src_ip_filter:
            filtered = [e for e in filtered if e.src_ip == src_ip_filter]
        return filtered
