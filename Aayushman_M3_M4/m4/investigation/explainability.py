"""
Explainability Engine Module.

Generates structured SOC investigation evidence answering:
  1. What happened?
  2. Why was it classified as malicious/suspicious?
  3. Why is the risk score high/critical?
  4. What empirical evidence supports the conclusion?

Follows strict claim discipline:
  - "Threat intelligence enrichment provides additional contextual evidence." (NOT "confirms attack")
  - "Observed behavior is mapped to a potentially relevant MITRE technique." (NOT "proves intent")
  - "Risk score is an explainable engineering score." (NOT "probability of compromise")
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class IncidentExplanation:
    """Structured Explainability Payload."""
    summary: str
    why_malicious: str
    why_risk_level: str
    evidence_list: List[str]
    mitre_context: List[str]
    intel_context: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExplainabilityEngine:
    """
    SOC Evidence & Investigation Explainability Generator.
    """

    def explain(
        self,
        incident_id: str,
        events: List[Dict[str, Any]],
        risk_result: Any,
        mitre_mappings: List[Any],
        intel_enrichment: Dict[str, Any],
    ) -> IncidentExplanation:
        """
        Generate structured explanation for an incident.
        """
        event_count = len(events)
        primary_threat = events[0].get("threat_class", "UNKNOWN") if events else "UNKNOWN"
        src_ip = events[0].get("source", {}).get("src_ip", "unknown host") if events else "unknown host"

        summary = f"Detected {event_count} correlated security event(s) originating from host '{src_ip}' with primary classification '{primary_threat}'."

        why_malicious = (
            f"Supervised ML model predicted '{primary_threat}' with confidence {events[0].get('confidence', 0.0):.2f} "
            f"and Isolation Forest anomaly severity {events[0].get('anomaly_score', 0.0):.2f}."
        )

        why_risk_level = (
            f"Assigned explainable engineering risk score {risk_result.score:.1f}/100 ({risk_result.level}) "
            f"due to {risk_result.explanation}"
        )

        evidence_list = []
        for idx, evt in enumerate(events):
            evidence_list.append(
                f"Event {idx+1}: {evt.get('threat_class')} ({evt.get('decision')}) at {evt.get('timestamp')} "
                f"[Conf: {evt.get('confidence', 0.0):.2f}, Anomaly: {evt.get('anomaly_score', 0.0):.2f}]"
            )

        mitre_context = []
        for mapping in mitre_mappings:
            m_dict = mapping if isinstance(mapping, dict) else mapping.to_dict()
            mitre_context.append(
                f"Technique {m_dict.get('technique_id')} ({m_dict.get('technique_name')} - {m_dict.get('tactic')}): "
                f"{m_dict.get('reason')} [Confidence: {m_dict.get('confidence', 0.0):.2f}]"
            )

        intel_context = []
        rep = intel_enrichment.get("overall_reputation", "UNKNOWN")
        total_iocs = intel_enrichment.get("total_iocs_extracted", 0)
        intel_context.append(
            f"Threat intelligence enrichment provides additional contextual evidence: "
            f"Extracted {total_iocs} IOC(s) with overall reputation '{rep}'."
        )

        return IncidentExplanation(
            summary=summary,
            why_malicious=why_malicious,
            why_risk_level=why_risk_level,
            evidence_list=evidence_list,
            mitre_context=mitre_context,
            intel_context=intel_context,
        )
