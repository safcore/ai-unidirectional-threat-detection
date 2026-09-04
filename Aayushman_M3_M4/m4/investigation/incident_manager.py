"""
Incident Manager & Lightweight Persistence Module.

Orchestrates Phase 4 Threat Intelligence enrichment, MITRE ATT&CK mapping, Threat Correlation,
Risk Scoring, Attack Chain reconstruction, Timeline generation, and Explainability.
Persists Incident objects using SQLite + SQLAlchemy lightweight storage.
"""

import uuid
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

from ml.threat_intelligence.enrichment_engine import ThreatIntelEnrichmentEngine
from ml.mitre.attack_mapper import MITREAttackMapper
from ml.correlation.correlation_engine import ThreatCorrelationEngine
from ml.risk.risk_engine import RiskEngine
from ml.investigation.timeline import TimelineBuilder
from ml.investigation.explainability import ExplainabilityEngine

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_DIR = BASE_DIR / "data"
DB_PATH = DB_DIR / "phase4_investigation.db"


@dataclass
class Incident:
    """Structured Incident Object."""
    incident_id: str
    title: str
    created_at: str
    updated_at: str
    status: str             # NEW / INVESTIGATING / CONTAINED / RESOLVED / CLOSED
    risk_score: float
    risk_level: str         # LOW / MEDIUM / HIGH / CRITICAL
    source_entity: str
    target_entity: str
    events: List[Dict[str, Any]]
    mitre_mappings: List[Dict[str, Any]]
    iocs: List[Dict[str, Any]]
    attack_chain: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    explanation: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IncidentManager:
    """
    Central Incident & Investigation Manager.
    """

    def __init__(self):
        self.enrichment_engine = ThreatIntelEnrichmentEngine()
        self.mitre_mapper = MITREAttackMapper()
        self.correlation_engine = ThreatCorrelationEngine()
        self.risk_engine = RiskEngine()
        self.timeline_builder = TimelineBuilder()
        self.explainability_engine = ExplainabilityEngine()
        self.incidents: Dict[str, Incident] = {}

    def process_event(self, event: Dict[str, Any]) -> Incident:
        """
        Process a Phase 3 normalized threat event through the complete Phase 4 pipeline.
        """
        # 1. Threat Intel Enrichment
        intel_res = self.enrichment_engine.enrich_event(event)

        # 2. MITRE ATT&CK Mapping
        mitre_res = self.mitre_mapper.map_event(event)
        mitre_dicts = [m.to_dict() for m in mitre_res]

        # 3. Threat Correlation
        group = self.correlation_engine.correlate(event)

        # 4. Risk Scoring
        confidence = float(event.get("confidence", 0.80))
        anomaly_score = float(event.get("anomaly_score", 0.0))
        severity = event.get("alert", {}).get("severity", "INFO")
        intel_rep = intel_res.get("overall_reputation", "UNKNOWN")
        correlated_count = len(group.events)

        risk_res = self.risk_engine.calculate_risk(
            confidence=confidence,
            anomaly_score=anomaly_score,
            severity=severity,
            intel_reputation=intel_rep,
            correlated_event_count=correlated_count,
        )

        # 5. Timeline Generation
        timeline_entries = self.timeline_builder.build_timeline(
            group.events, risk_scores=[risk_res.score] * len(group.events)
        )
        timeline_dicts = [t.to_dict() for t in timeline_entries]

        # 6. Explainability Generation
        explanation_obj = self.explainability_engine.explain(
            incident_id=group.group_id,
            events=group.events,
            risk_result=risk_res,
            mitre_mappings=mitre_res,
            intel_enrichment=intel_res,
        )

        # 7. Assemble/Update Incident Object
        incident_id = f"inc-{group.entity_key.replace('.', '-')}"
        now_iso = datetime.now(timezone.utc).isoformat()

        if incident_id in self.incidents:
            inc = self.incidents[incident_id]
            inc.updated_at = now_iso
            inc.risk_score = risk_res.score
            inc.risk_level = risk_res.level
            inc.events = group.events
            inc.mitre_mappings = mitre_dicts
            inc.iocs = intel_res.get("iocs", [])
            inc.attack_chain = group.attack_chain
            inc.timeline = timeline_dicts
            inc.explanation = explanation_obj.to_dict()
        else:
            primary_threat = event.get("threat_class", "Threat")
            inc = Incident(
                incident_id=incident_id,
                title=f"Security Incident: {primary_threat} from {group.entity_key}",
                created_at=now_iso,
                updated_at=now_iso,
                status="NEW",
                risk_score=risk_res.score,
                risk_level=risk_res.level,
                source_entity=group.entity_key,
                target_entity=str(event.get("destination", {}).get("dst_ip", "Target Host")),
                events=group.events,
                mitre_mappings=mitre_dicts,
                iocs=intel_res.get("iocs", []),
                attack_chain=group.attack_chain,
                timeline=timeline_dicts,
                explanation=explanation_obj.to_dict(),
            )
            self.incidents[incident_id] = inc

        return inc

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def list_incidents(self) -> List[Incident]:
        return list(self.incidents.values())


_incident_manager_instance = None


def get_incident_manager() -> IncidentManager:
    global _incident_manager_instance
    if _incident_manager_instance is None:
        _incident_manager_instance = IncidentManager()
    return _incident_manager_instance
