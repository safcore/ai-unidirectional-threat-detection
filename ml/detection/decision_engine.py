"""
Threat Decision Engine Module.

Applies deterministic decision logic on classifier predictions and anomaly scores:
  - BENIGN: threat_class == "BENIGN" & confidence >= benign_threshold & anomaly_score < anomaly_threshold
  - MALICIOUS: threat_class != "BENIGN" & confidence >= malicious_threshold
  - ANOMALOUS: anomaly_score >= anomaly_threshold
  - SUSPICIOUS: threat_class != "BENIGN" & confidence < malicious_threshold
"""

import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, Union
from ml.config.detection_config import get_detection_config, DetectionConfig
from m4_threat_classifier.detection.c2_detector import C2Detector
from m4_threat_classifier.detection.dga_detector import DGADetector
from m4_threat_classifier.detection.exfiltration_detector import ExfiltrationDetector
from ml.detection.tls_metadata_detector import get_tls_metadata_detector

logger = logging.getLogger(__name__)


@dataclass
class DecisionResult:
    """Structured decision output."""
    decision: str  # BENIGN / MALICIOUS / SUSPICIOUS / ANOMALOUS
    threat_class: str
    confidence: float
    anomaly_score: float
    reason: str


class DecisionEngine:
    """
    Deterministic threat decision engine.
    Combines supervised ML classifiers, unsupervised anomaly scores, and
    passive behavioral detectors for PS-26145 multi-threat coverage.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or get_detection_config()
        self.c2_detector = C2Detector()
        self.dga_detector = DGADetector()
        self.exfil_detector = ExfiltrationDetector()
        self.tls_detector = get_tls_metadata_detector()

    def evaluate(
        self,
        prediction_result: Dict[str, Any],
        features: Optional[Union[Dict[str, Any], Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DecisionResult:
        """
        Evaluate prediction result dict against configured decision rules and
        behavioral passive telemetry for PS-26145 threat classes.
        """
        threat_class = str(prediction_result.get("threat_class", "BENIGN"))
        confidence = float(prediction_result.get("confidence", 1.0))
        anomaly_score = float(prediction_result.get("anomaly_score", 0.0))

        mal_thresh = self.config.malicious_confidence_threshold
        ben_thresh = self.config.benign_confidence_threshold
        anom_thresh = self.config.anomaly_threshold

        # 1. ANOMALOUS Check (Unsupervised Isolation Forest score trigger)
        if anomaly_score >= anom_thresh:
            if threat_class != "BENIGN" and confidence >= mal_thresh:
                decision = "MALICIOUS"
                reason = f"High confidence attack prediction '{threat_class}' ({confidence:.2f}) with high anomaly score ({anomaly_score:.2f})."
            else:
                decision = "ANOMALOUS"
                reason = f"High anomaly score ({anomaly_score:.2f} >= threshold {anom_thresh:.2f})."

        # 2. MALICIOUS Check (High confidence supervised attack prediction)
        elif threat_class != "BENIGN" and confidence >= mal_thresh:
            decision = "MALICIOUS"
            reason = f"High confidence attack prediction '{threat_class}' ({confidence:.2f} >= threshold {mal_thresh:.2f})."

        # 3. SUSPICIOUS Check (Low confidence supervised attack prediction)
        elif threat_class != "BENIGN" and confidence < mal_thresh:
            decision = "SUSPICIOUS"
            reason = f"Low confidence attack prediction '{threat_class}' ({confidence:.2f} < threshold {mal_thresh:.2f})."

        # 4. BENIGN Check
        elif threat_class == "BENIGN" and confidence >= ben_thresh and anomaly_score < anom_thresh:
            decision = "BENIGN"
            reason = f"Confirmed BENIGN flow with confidence {confidence:.2f} and low anomaly score {anomaly_score:.2f}."

        else:
            decision = "SUSPICIOUS"
            reason = f"Uncertain prediction parameters (class='{threat_class}', confidence={confidence:.2f}, anomaly={anomaly_score:.2f})."

        # 5. Passive Behavioral Multi-Threat Detection (PS-26145 Coverage)
        # Evaluates C2 beaconing, DGA, DNS tunneling, encrypted session anomalies, and data exfiltration
        if features is not None:
            feat_dict = features.iloc[0].to_dict() if hasattr(features, "iloc") else features

            # A. Botnet C2 Beaconing Detector
            if decision in ("BENIGN", "ANOMALOUS", "SUSPICIOUS") or threat_class in ("BENIGN", "OTHER_ATTACK"):
                c2_res = self.c2_detector.analyze_flow(feat_dict, metadata)
                if c2_res.score >= 0.60:
                    decision = "MALICIOUS"
                    threat_class = "C2_COMMUNICATION"
                    confidence = max(confidence, c2_res.score)
                    reason = f"C2 Beaconing Detected: {c2_res.reason} Signals: {'; '.join(c2_res.evidence) if c2_res.evidence else 'Periodic beacon interval matching C2 pattern'}"

            # B. Data Exfiltration & DNS Tunneling Detector
            if decision in ("BENIGN", "ANOMALOUS", "SUSPICIOUS") or threat_class in ("BENIGN", "OTHER_ATTACK"):
                exfil_res = self.exfil_detector.analyze_flow(feat_dict, metadata)
                if exfil_res.score >= 0.60:
                    decision = "MALICIOUS"
                    dst_p = (metadata or {}).get("dst_port") or feat_dict.get("Destination Port")
                    if str(dst_p) == "53":
                        threat_class = "DNS_TUNNEL"
                        reason = f"DNS Tunneling Detected: High outbound payload volume over DNS port 53. Signals: {'; '.join(exfil_res.evidence) if exfil_res.evidence else 'Encapsulated high-entropy domain queries'}"
                    else:
                        threat_class = "DATA_EXFILTRATION"
                        reason = f"Data Exfiltration Detected: {exfil_res.reason} Signals: {'; '.join(exfil_res.evidence) if exfil_res.evidence else 'High outbound payload transfer'}"
                    confidence = max(confidence, exfil_res.score)

            # C. Domain Generation Algorithm (DGA) Detector
            if decision in ("BENIGN", "ANOMALOUS", "SUSPICIOUS") or threat_class in ("BENIGN", "OTHER_ATTACK"):
                domain = (metadata or {}).get("domain") or (metadata or {}).get("query_name")
                if domain:
                    dga_res = self.dga_detector.analyze_domain(str(domain))
                    if dga_res.dga_score >= 0.60:
                        decision = "MALICIOUS"
                        threat_class = "DGA"
                        confidence = max(confidence, dga_res.dga_score)
                        reason = f"DGA Domain Detected: {dga_res.reason} (Domain: {dga_res.domain})"

            # D. Malware in Encrypted Sessions (TLS/QUIC Passive Metadata Anomaly - No Decryption)
            # Evaluated if exfiltration detector has not already classified as high-volume data exfiltration
            if (decision in ("BENIGN", "ANOMALOUS", "SUSPICIOUS") or threat_class in ("BENIGN", "OTHER_ATTACK")) and threat_class != "DATA_EXFILTRATION":
                tls_res = self.tls_detector.analyze_flow(feat_dict, metadata)
                if tls_res.is_anomalous:
                    decision = "MALICIOUS"
                    threat_class = "ENCRYPTED_MALWARE_METADATA"
                    confidence = max(confidence, tls_res.score)
                    reason = f"Encrypted Session Anomaly: {tls_res.reason} Evidence: {'; '.join(tls_res.evidence)}"

            # E. Volumetric Flood / SYN Flood Check vs Reconnaissance Port Scan (PS-26145 Threat 1 & 4)
            if decision in ("BENIGN", "ANOMALOUS", "SUSPICIOUS") or threat_class in ("BENIGN", "OTHER_ATTACK", "PORT_SCAN", "DDOS"):
                syn_flags = float(feat_dict.get("SYN Flag Count", 0.0))
                flow_pkts_s = float(feat_dict.get("Flow Packets/s", 0.0))
                total_fwd_pkts = float(feat_dict.get("Total Fwd Packets", 0.0))
                bwd_pkts = float(feat_dict.get("Total Backward Packets", 0.0))
                dst_p = str((metadata or {}).get("dst_port") or feat_dict.get("Destination Port", 80))

                # If destination port is SSH / non-web admin or low packet scan (< 500 packets) with high rate SYN probes
                is_scan = (threat_class == "PORT_SCAN") or (
                    syn_flags >= 10 and bwd_pkts == 0 and (dst_p in ("22", "21", "23", "3389") or total_fwd_pkts < 300)
                )

                if is_scan:
                    decision = "MALICIOUS"
                    threat_class = "PORT_SCAN"
                    confidence = max(confidence, 0.94)
                    reason = f"Reconnaissance Port Scan Detected: High-frequency SYN probes ({syn_flags:.0f} SYN flags) targeting port {dst_p} without completed handshake."
                elif syn_flags >= 50 or (flow_pkts_s >= 5000 and total_fwd_pkts >= 50) or (total_fwd_pkts >= 100 and bwd_pkts == 0):
                    decision = "MALICIOUS"
                    threat_class = "DDOS"
                    confidence = max(confidence, 0.98)
                    reason = f"Volumetric SYN Flood Detected: High SYN rate ({syn_flags:.0f} SYN flags, {flow_pkts_s:.1f} pkts/s) targeting port {dst_p} with zero ACK response."

        return DecisionResult(
            decision=decision,
            threat_class=threat_class,
            confidence=confidence,
            anomaly_score=anomaly_score,
            reason=reason,
        )
