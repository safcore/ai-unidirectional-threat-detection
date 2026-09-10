"""
Data Exfiltration Behavioral Detector Module.

Analyzes network flow telemetry for observable data exfiltration signals:
  - Unusually high outbound byte volume
  - High outbound-to-inbound byte ratio
  - Large payload sizes and sustained outbound data transfer
  - DNS tunneling indicators (large DNS query payloads or high TXT record volume)
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExfiltrationResult:
    """Structured Data Exfiltration Detection Result."""
    classification: str       # NORMAL / SUSPICIOUS_EXFILTRATION / LIKELY_EXFILTRATION
    score: float              # 0.0 to 1.0
    evidence: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExfiltrationDetector:
    """
    Behavioral Data Exfiltration & DNS Tunneling Detector.
    """

    def analyze_flow(self, features: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> ExfiltrationResult:
        """
        Evaluate flow telemetry for observable data exfiltration behavior.
        """
        fwd_bytes = float(features.get("Total Length of Fwd Packets", features.get("total_fwd_bytes", 0.0)))
        bwd_bytes = float(features.get("Total Length of Bwd Packets", features.get("total_bwd_bytes", 0.0)))
        fwd_pkt_max = float(features.get("Fwd Packet Length Max", features.get("fwd_pkt_len_max", 0.0)))
        fwd_pkts = float(features.get("Total Fwd Packets", features.get("total_fwd_packets", 0.0)))

        dst_port = None
        if metadata:
            dst_port = metadata.get("dst_port") or metadata.get("Destination Port")
        if dst_port is None:
            dst_port = features.get("dst_port") or features.get("Destination Port")

        try:
            dst_port_int = int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None
        except (ValueError, TypeError):
            dst_port_int = None

        score = 0.0
        evidence = []

        # 1. High outbound-to-inbound ratio (Asymmetric data transfer)
        if fwd_bytes > 5000 and bwd_bytes > 0:
            byte_ratio = fwd_bytes / bwd_bytes
            if byte_ratio >= 10.0:
                score += 0.35
                evidence.append(f"High outbound-to-inbound byte ratio ({byte_ratio:.1f}:1)")
            elif byte_ratio >= 4.0:
                score += 0.20
                evidence.append(f"Elevated outbound byte ratio ({byte_ratio:.1f}:1)")
        elif fwd_bytes > 50000 and bwd_bytes == 0:
            score += 0.40
            evidence.append(f"Unidirectional outbound byte transfer ({fwd_bytes/1024:.1f} KB with 0 inbound bytes)")

        # 2. Large individual payload size
        if fwd_pkt_max >= 1400:
            score += 0.20
            evidence.append(f"Large maximum payload size ({fwd_pkt_max:.0f} bytes)")

        # 3. Absolute high volume threshold
        if fwd_bytes >= 1_000_000:  # > 1 MB
            score += 0.30
            evidence.append(f"High total outbound volume ({fwd_bytes / (1024*1024):.2f} MB)")
        elif fwd_bytes >= 100_000:  # > 100 KB
            score += 0.20
            evidence.append(f"Elevated outbound volume ({fwd_bytes / 1024:.1f} KB)")

        # 4. DNS Tunneling signal: High outbound byte ratio over DNS port 53 or encapsulated query metrics
        if dst_port_int == 53:
            if fwd_bytes > 2000:
                score += 0.35
                evidence.append(f"High outbound payload volume over DNS port 53 ({fwd_bytes/1024:.1f} KB - DNS Tunneling indicator)")
            elif fwd_bytes > 500:
                score += 0.20
                evidence.append(f"Elevated outbound DNS payload volume ({fwd_bytes} bytes)")

            # Check query domain characteristics if available in metadata
            query_domain = str((metadata or {}).get("domain") or (metadata or {}).get("query_name") or "")
            if query_domain:
                labels = query_domain.split(".")
                max_label_len = max(len(l) for l in labels) if labels else 0
                if len(query_domain) >= 45 or max_label_len >= 30:
                    score += 0.30
                    evidence.append(f"Anomalously long DNS query hostname ({len(query_domain)} chars, max label: {max_label_len})")
                if len(labels) >= 4:
                    score += 0.15
                    evidence.append(f"Excessive subdomain nesting depth ({len(labels)} labels)")

        final_score = round(min(score, 1.0), 4)

        if final_score >= 0.65:
            classification = "LIKELY_EXFILTRATION"
            reason = "Observed strong telemetry indicators of sustained large-scale outbound data transfer."
        elif final_score >= 0.35:
            classification = "SUSPICIOUS_EXFILTRATION"
            reason = "Observed asymmetric outbound byte ratios consistent with potential data exfiltration."
        else:
            classification = "NORMAL"
            reason = "Outbound traffic volume and byte ratios within normal baseline parameters."

        return ExfiltrationResult(
            classification=classification,
            score=final_score,
            evidence=evidence if evidence else ["Normal data transfer metrics."],
            reason=reason,
        )
