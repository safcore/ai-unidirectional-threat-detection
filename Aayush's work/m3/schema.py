"""
Module 3 (M3) — Schema & Alert Data Contracts
=============================================
Defines threat classes, severity levels, and structured alert schemas
for the AI Threat Detection Engine.
"""

from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime


class ThreatClass(str, Enum):
    """Threat classes supported by M3."""
    BENIGN = "BENIGN"
    SYN_FLOOD = "SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    PORT_SCAN = "PORT_SCAN"


class SeverityLevel(str, Enum):
    """Severity ratings conforming to standard SOC/SIEM triage."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatAlert:
    """
    Structured alert object emitted by M3 for consumption by M4/M5/M6.
    Retains flow identity and metadata alongside the threat classification,
    confidence score, severity, and driving evidence.
    """
    timestamp: str
    window_id: str
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    threat_class: str
    confidence: float
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to standard JSON-serializable dictionary."""
        return asdict(self)
