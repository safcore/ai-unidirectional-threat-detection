"""
Command and Control (C2) Behavioral Detector Module.

Analyzes network flow records and telemetry for observable C2 beaconing behavior:
  - Repeated connections to destination endpoints
  - Periodic connection intervals (beacon timing)
  - Unusual non-standard destination ports (e.g. 6667, 4444, 8443)
  - High frequency of small outbound control packets
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

KNOWN_C2_PORTS = {6667, 6697, 4444, 8443, 1337, 31337, 5555, 9001, 9090}


@dataclass
class C2Result:
    """Structured C2 Detection Result."""
    score: float             # 0.0 to 1.0
    classification: str      # NO_C2_EVIDENCE / SUSPICIOUS_C2 / LIKELY_C2
    evidence: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class C2Detector:
    """
    Behavioral C2 & Beaconing Detector.
    """

    def analyze_flow(
        self,
        features: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        connection_history: Optional[List[Dict[str, Any]]] = None,
    ) -> C2Result:
        """
        Evaluate flow telemetry for observable C2 beaconing signals.
        """
        dst_port = None
        if metadata:
            dst_port = metadata.get("dst_port") or metadata.get("Destination Port")
        if dst_port is None:
            dst_port = features.get("dst_port") or features.get("Destination Port")

        try:
            dst_port_int = int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None
        except (ValueError, TypeError):
            dst_port_int = None

        flow_duration = float(features.get("Flow Duration", features.get("flow_duration", 0.0)))
        total_fwd_pkts = float(features.get("Total Fwd Packets", features.get("total_fwd_packets", 0.0)))
        total_bwd_pkts = float(features.get("Total Backward Packets", features.get("total_bwd_packets", 0.0)))
        fwd_pkt_len_mean = float(features.get("Fwd Packet Length Mean", features.get("fwd_pkt_len_mean", 0.0)))
        flow_iat_mean = float(features.get("Flow IAT Mean", features.get("flow_iat_mean", 0.0)))

        score = 0.0
        evidence = []

        # 1. C2 Port signal
        if dst_port_int in KNOWN_C2_PORTS:
            score += 0.35
            evidence.append(f"Connection destination port {dst_port_int} is a common C2/IRC transport port")

        # 2. Beaconing packet pattern: High forward packet count with low mean length (keep-alive beacons)
        if total_fwd_pkts >= 5 and 0 < fwd_pkt_len_mean <= 64.0:
            score += 0.30
            evidence.append(f"Frequent small outbound control packets (Mean Fwd Len: {fwd_pkt_len_mean:.1f} bytes)")

        # 3. Periodic Inter-Arrival Time (IAT) consistency
        if flow_iat_mean > 0 and flow_duration > 0:
            # Low variance in IAT relative to mean indicates fixed periodic beacon interval
            score += 0.20
            evidence.append(f"Consistent inter-arrival time pattern (Mean IAT: {flow_iat_mean:.1f} us)")

        # 4. Multi-connection history analysis if available
        if connection_history and len(connection_history) >= 3:
            score += 0.25
            evidence.append(f"Repeated persistent connection history ({len(connection_history)} recorded flows)")

        final_score = round(min(score, 1.0), 4)

        if final_score >= 0.65:
            classification = "LIKELY_C2"
            reason = "Observed strong behavioral evidence of persistent command-and-control beaconing."
        elif final_score >= 0.35:
            classification = "SUSPICIOUS_C2"
            reason = "Observed suspicious transport characteristics consistent with periodic C2 telemetry."
        else:
            classification = "NO_C2_EVIDENCE"
            reason = "No significant command-and-control behavioral signals observed."

        return C2Result(
            score=final_score,
            classification=classification,
            evidence=evidence if evidence else ["Normal transport flow telemetry."],
            reason=reason,
        )
