"""
M5 — Alert Schema (Pydantic)
=============================
Standardized alert record per NTRO problem spec:
  timestamp, flow_id, threat_class, confidence, severity, evidence

MITRE ATT&CK mapping is handled by mitre_mapper.py.
"""

import uuid
import time
from typing import Any, Dict, Optional
from enum import Enum
from dataclasses import dataclass, field, asdict
import json


class ThreatClass(str, Enum):
    DDOS    = "DDOS"
    RECON   = "RECON"
    BEACON  = "BEACON"
    DGA     = "DGA"
    TLS     = "TLS_ANOMALY"
    EXFIL   = "EXFIL"
    DNS_TUN = "DNS_TUNNEL"


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    """
    Structured alert record — the final output of the NetWatch pipeline.
    All fields are JSON-serializable.
    """
    alert_id:      str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:     float = field(default_factory=time.time)
    timestamp_iso: str = ""

    # Flow identifier
    flow_id:   str = ""
    src_ip:    str = ""
    dst_ip:    str = ""
    src_port:  int = 0
    dst_port:  int = 0
    protocol:  str = ""

    # Classification
    threat_class:   str = ""
    threat_subtype: str = ""
    severity:       str = Severity.MEDIUM
    confidence:     float = 0.0

    # Supporting evidence (feature values that triggered the alert)
    evidence: Dict[str, Any] = field(default_factory=dict)

    # MITRE ATT&CK context (populated by MitreMapper)
    mitre_tactic:     str = ""
    mitre_technique:  str = ""
    mitre_technique_id: str = ""

    def __post_init__(self):
        if not self.timestamp_iso:
            import datetime
            self.timestamp_iso = datetime.datetime.utcfromtimestamp(
                self.timestamp
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_detector_dict(cls, d: dict) -> "Alert":
        """
        Construct an Alert from the raw dict emitted by a detector module.
        """
        return cls(
            flow_id        = d.get("flow_id", ""),
            src_ip         = d.get("src_ip", ""),
            dst_ip         = d.get("dst_ip", ""),
            src_port       = d.get("src_port", 0),
            dst_port       = d.get("dst_port", 0),
            protocol       = d.get("protocol", ""),
            threat_class   = d.get("threat_class", ""),
            threat_subtype = d.get("threat_subtype", ""),
            severity       = d.get("severity", Severity.MEDIUM),
            confidence     = d.get("confidence", 0.0),
            evidence       = d.get("evidence", {}),
        )
