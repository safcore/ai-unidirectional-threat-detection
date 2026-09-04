"""
Entity Tracker Module for Threat Correlation.

Tracks entities (IP addresses, subnets, destination endpoints) across events and evaluates entity connection strength:
  - EXACT_ENTITY: Same exact Source IP
  - STRONG: Same Source IP + Destination IP pair
  - MODERATE: Same Source IP + Destination Port
  - WEAK: Same Subnet (/24 IPv4 prefix)
"""

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional

logger = logging.getLogger(__name__)


@dataclass
class EntityState:
    """Tracked entity state."""
    entity_key: str  # IP address or Subnet
    entity_type: str  # "IP" or "Subnet"
    event_ids: List[str] = field(default_factory=list)
    threat_classes: Set[str] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""


def get_ipv4_subnet(ip_str: str) -> Optional[str]:
    """Get /24 subnet prefix for IPv4 address."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if ip.is_private or ip.is_global:
            network = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
            return str(network)
    except ValueError:
        pass
    return None


def calculate_entity_strength(event1: Dict[str, Any], event2: Dict[str, Any]) -> str:
    """
    Calculate entity correlation strength between two events.
    """
    src1 = event1.get("source", {}).get("src_ip")
    src2 = event2.get("source", {}).get("src_ip")

    dst1 = event1.get("destination", {}).get("dst_ip")
    dst2 = event2.get("destination", {}).get("dst_ip")

    port1 = event1.get("destination", {}).get("dst_port")
    port2 = event2.get("destination", {}).get("dst_port")

    if src1 and src2 and src1 == src2:
        if dst1 and dst2 and dst1 == dst2:
            return "STRONG"
        if port1 and port2 and port1 == port2:
            return "MODERATE"
        return "EXACT_ENTITY"

    # Subnet check
    if src1 and src2:
        sub1 = get_ipv4_subnet(src1)
        sub2 = get_ipv4_subnet(src2)
        if sub1 and sub2 and sub1 == sub2:
            return "WEAK"

    return "NONE"


class EntityTracker:
    """
    Tracks and catalogs active network entities across event streams.
    """

    def __init__(self):
        self.entities: Dict[str, EntityState] = {}

    def track(self, event: Dict[str, Any]):
        """Register event details against entity tracking store."""
        event_id = event.get("event_id", "")
        timestamp = event.get("timestamp", "")
        threat_class = event.get("threat_class", "")

        src_ip = event.get("source", {}).get("src_ip")
        if src_ip:
            if src_ip not in self.entities:
                self.entities[src_ip] = EntityState(
                    entity_key=src_ip,
                    entity_type="IP",
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            ent = self.entities[src_ip]
            ent.event_ids.append(event_id)
            if threat_class:
                ent.threat_classes.add(threat_class)
            ent.last_seen = timestamp
