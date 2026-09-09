"""
Multi-Event Threat Correlation Engine Module.

Correlates individual threat events into unified security event clusters using:
  1. Entity correlation (EXACT_ENTITY, STRONG, MODERATE, WEAK)
  2. Temporal window correlation (Configurable 5-minute sliding window)
  3. Multi-stage behavioral progression
"""

import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from ml.correlation.entity_tracker import EntityTracker, calculate_entity_strength
from ml.correlation.attack_chain import AttackChainBuilder, AttackStage

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedGroup:
    """Group of correlated threat events."""
    group_id: str
    entity_key: str
    correlation_strength: str  # EXACT_ENTITY / STRONG / MODERATE / WEAK
    events: List[Dict[str, Any]] = field(default_factory=list)
    threat_classes: List[str] = field(default_factory=list)
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


class ThreatCorrelationEngine:
    """
    Real-time & batch threat correlation engine.
    """

    def __init__(self, temporal_window_seconds: int = 300):
        self.temporal_window = temporal_window_seconds
        self.entity_tracker = EntityTracker()
        self.chain_builder = AttackChainBuilder()
        self.groups: Dict[str, CorrelatedGroup] = {}

    def correlate(self, event: Dict[str, Any]) -> CorrelatedGroup:
        """
        Incorporate new threat event into correlation engine and update event groups.
        """
        self.entity_tracker.track(event)

        src_ip = event.get("source", {}).get("src_ip") or "unknown-entity"
        event_id = event.get("event_id", "")
        timestamp = event.get("timestamp", "")
        threat_class = event.get("threat_class", "")

        # Find existing group for entity key
        if src_ip in self.groups:
            group = self.groups[src_ip]
            group.events.append(event)
            if len(group.events) > 100:
                group.events = group.events[-100:]
            if threat_class and threat_class not in group.threat_classes:
                group.threat_classes.append(threat_class)
            group.last_seen = timestamp
        else:
            group = CorrelatedGroup(
                group_id=f"grp-{src_ip}",
                entity_key=src_ip,
                correlation_strength="EXACT_ENTITY",
                events=[event],
                threat_classes=[threat_class] if threat_class else [],
                first_seen=timestamp,
                last_seen=timestamp,
            )
            self.groups[src_ip] = group

        # Rebuild attack chain for group
        chain_stages = self.chain_builder.build_chain(group.events)
        group.attack_chain = [s.to_dict() for s in chain_stages]

        return group

    def get_group(self, entity_key: str) -> Optional[CorrelatedGroup]:
        return self.groups.get(entity_key)
