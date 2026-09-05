"""
Evidence-Based MITRE ATT&CK Mapper Module.

Maps threat classification events and flow features to MITRE ATT&CK enterprise techniques
only when empirical evidence supports the mapping basis.
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from ml.mitre.technique_store import get_technique_store, TechniqueStore

logger = logging.getLogger(__name__)


@dataclass
class MITREMapping:
    """Structured MITRE ATT&CK Mapping."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    reason: str
    evidence: List[str]
    mapping_basis: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MITREAttackMapper:
    """
    Evidence-based MITRE ATT&CK technique mapper.
    """

    def __init__(self, store: Optional[TechniqueStore] = None):
        self.store = store or get_technique_store()

    def map_event(self, event: Dict[str, Any]) -> List[MITREMapping]:
        """
        Map normalized threat event to applicable MITRE ATT&CK techniques based on evidence.
        """
        mappings: List[MITREMapping] = []
        threat_class = str(event.get("threat_class", "BENIGN")).upper()
        decision = str(event.get("decision", "BENIGN")).upper()
        confidence = float(event.get("confidence", 0.0))

        dest_info = event.get("destination", {})
        dst_port = dest_info.get("dst_port")

        if decision == "BENIGN":
            return mappings

        # 1. PORT_SCAN -> T1046 (Network Service Scanning)
        if "PORT_SCAN" in threat_class or threat_class == "PORT_SCAN":
            tech = self.store.get_technique("T1046")
            if tech:
                mappings.append(MITREMapping(
                    technique_id="T1046",
                    technique_name=tech["technique_name"],
                    tactic=tech["tactic"],
                    confidence=round(confidence * 0.95, 4),
                    reason="Observed network flow pattern characteristic of multi-port discovery scanning.",
                    evidence=["threat_class: PORT_SCAN", f"dst_port: {dst_port}"],
                    mapping_basis="Flow-level port scanning behavior classification",
                ))

        # 2. BRUTE_FORCE -> T1110 (Brute Force)
        elif "BRUTE" in threat_class or threat_class == "BRUTE_FORCE":
            tech = self.store.get_technique("T1110")
            if tech:
                mappings.append(MITREMapping(
                    technique_id="T1110",
                    technique_name=tech["technique_name"],
                    tactic=tech["tactic"],
                    confidence=round(confidence * 0.95, 4),
                    reason="Repeated authentication credential attempts over network transport.",
                    evidence=["threat_class: BRUTE_FORCE", f"dst_port: {dst_port}"],
                    mapping_basis="High-frequency authentication connection pattern",
                ))

        # 3. WEB_ATTACK -> T1190 (Exploitation of Public-Facing Application)
        elif "WEB" in threat_class or threat_class == "WEB_ATTACK":
            tech = self.store.get_technique("T1190")
            if tech:
                mappings.append(MITREMapping(
                    technique_id="T1190",
                    technique_name=tech["technique_name"],
                    tactic=tech["tactic"],
                    confidence=round(confidence * 0.95, 4),
                    reason="HTTP/HTTPS request patterns targeting public web application endpoints.",
                    evidence=["threat_class: WEB_ATTACK", f"dst_port: {dst_port}"],
                    mapping_basis="Application-layer web exploit flow metrics",
                ))

        # 4. DDOS / DOS -> T1498 (Network Denial of Service)
        elif "DOS" in threat_class or "DDOS" in threat_class:
            tech = self.store.get_technique("T1498")
            if tech:
                mappings.append(MITREMapping(
                    technique_id="T1498",
                    technique_name=tech["technique_name"],
                    tactic=tech["tactic"],
                    confidence=round(confidence * 0.95, 4),
                    reason="Volumetric or state-exhaustion network flow traffic designed to disrupt service.",
                    evidence=["threat_class: " + threat_class, f"dst_port: {dst_port}"],
                    mapping_basis="High-volume packet flood flow measurements",
                ))

        # 5. BOTNET / INFILTRATION -> Require explicit port/protocol evidence
        elif "BOTNET" in threat_class:
            if dst_port in [80, 443, 8080, 6667]:  # Specific HTTP/C2 protocol evidence
                tech = self.store.get_technique("T1071")
                if tech:
                    mappings.append(MITREMapping(
                        technique_id="T1071",
                        technique_name=tech["technique_name"],
                        tactic=tech["tactic"],
                        confidence=round(confidence * 0.85, 4),
                        reason="Botnet command & control communication over standard web ports.",
                        evidence=["threat_class: BOTNET", f"dst_port: {dst_port}"],
                        mapping_basis="Application layer protocol C2 flow pattern",
                    ))
            else:
                # Insufficient evidence for confident mapping
                mappings.append(MITREMapping(
                    technique_id="NO_CONFIDENT_MAPPING",
                    technique_name="Unspecified Botnet Activity",
                    tactic="Command and Control",
                    confidence=0.40,
                    reason="Insufficient protocol evidence to map to specific ATT&CK technique.",
                    evidence=["threat_class: BOTNET"],
                    mapping_basis="Unverified botnet flow label",
                ))

        elif "INFILTRATION" in threat_class:
            mappings.append(MITREMapping(
                technique_id="NO_CONFIDENT_MAPPING",
                technique_name="Unspecified Network Infiltration",
                tactic="Lateral Movement",
                confidence=0.30,
                reason="Insufficient payload evidence to confirm specific ATT&CK technique.",
                evidence=["threat_class: INFILTRATION"],
                mapping_basis="Unverified infiltration flow label",
            ))

        return mappings
