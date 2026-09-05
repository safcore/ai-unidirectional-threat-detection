"""
MITRE ATT&CK Technique Database Store (v14.1 Enterprise ATT&CK).
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Enterprise ATT&CK v14.1 Technique Knowledge Base
ATTACK_TECHNIQUES = {
    "T1046": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
    },
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts.",
    },
    "T1190": {
        "technique_id": "T1190",
        "technique_name": "Exploitation of Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to take advantage of a weakness in a Internet-facing application.",
    },
    "T1498": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Network DoS attacks to degrade or disrupt service availability.",
    },
    "T1071": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection.",
    },
    "T1090": {
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may construct and use a proxy system to route malicious network connections.",
    },
}


class TechniqueStore:
    """Local store for MITRE ATT&CK enterprise techniques."""

    def __init__(self):
        self.techniques = ATTACK_TECHNIQUES

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        return self.techniques.get(technique_id)


_store_instance = None


def get_technique_store() -> TechniqueStore:
    global _store_instance
    if _store_instance is None:
        _store_instance = TechniqueStore()
    return _store_instance
