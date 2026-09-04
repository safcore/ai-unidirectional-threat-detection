"""
Attack Chain Reconstruction Module.

Builds chronological multi-stage attack progression representations while distinguishing
observed evidence from inferred attack stages:
  - OBSERVED: Direct telemetry evidence
  - CORRELATED: Multi-event entity correlation
  - INFERRED: Logical attack progression step
  - UNKNOWN: Unverified stage
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AttackStage:
    """Structured Attack Chain Stage."""
    stage_id: int
    timestamp: str
    event_id: str
    threat_class: str
    decision: str
    severity: str
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    confidence: float
    evidence: List[str]
    stage_status: str  # OBSERVED / CORRELATED / INFERRED / UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AttackChainBuilder:
    """
    Reconstructs chronological multi-step attack chains from correlated event lists.
    """

    def build_chain(self, events: List[Dict[str, Any]], mitre_mappings: Optional[List[List[Dict[str, Any]]]] = None) -> List[AttackStage]:
        """
        Build ordered attack chain stages from correlated event sequence.
        """
        # Sort chronologically by timestamp
        sorted_events = sorted(events, key=lambda e: str(e.get("timestamp", "")))
        stages: List[AttackStage] = []

        for idx, evt in enumerate(sorted_events):
            event_id = evt.get("event_id", f"evt-{idx+1}")
            timestamp = evt.get("timestamp", "")
            threat_class = evt.get("threat_class", "UNKNOWN")
            decision = evt.get("decision", "BENIGN")
            confidence = float(evt.get("confidence", 0.0))
            alert = evt.get("alert", {})
            severity = alert.get("severity", "INFO")

            # Get associated MITRE mapping if available
            tech_id = None
            tech_name = None
            if mitre_mappings and idx < len(mitre_mappings) and mitre_mappings[idx]:
                first_mapping = mitre_mappings[idx][0]
                tech_id = first_mapping.get("technique_id")
                tech_name = first_mapping.get("technique_name")

            # Determine stage status (OBSERVED vs CORRELATED vs INFERRED)
            if idx == 0:
                stage_status = "OBSERVED"
                evidence_desc = [f"Initial observed event '{threat_class}' from {evt.get('source', {}).get('src_ip', 'unknown')}"]
            else:
                stage_status = "CORRELATED"
                evidence_desc = [f"Correlated follow-on event '{threat_class}' occurring in sequence"]

            stages.append(AttackStage(
                stage_id=idx + 1,
                timestamp=timestamp,
                event_id=event_id,
                threat_class=threat_class,
                decision=decision,
                severity=severity,
                mitre_technique_id=tech_id,
                mitre_technique_name=tech_name,
                confidence=confidence,
                evidence=evidence_desc,
                stage_status=stage_status,
            ))

        return stages
