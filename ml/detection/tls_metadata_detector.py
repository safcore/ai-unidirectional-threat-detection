"""
ml/detection/tls_metadata_detector.py
======================================
Passive TLS/QUIC Metadata Anomaly Detector for PS-26145.

STRICT COMPLIANCE WITH PS-26145:
  1. PASSIVE METADATA ONLY: Inspects packet sizes, timing, flow duration, packet counts,
     byte counts, and observable handshake headers.
  2. NO PAYLOAD DECRYPTION: Never attempts to decrypt ciphertext, strip encryption,
     or break TLS/QUIC security.
  3. NO ACTIVE PROBING: Strictly read-only / unidirectional. Never transmits packets
     or contacts endpoints.
  4. OBSERVABLE FINGERPRINTING: Evaluates packet length variance, inter-arrival consistency,
     and optional JA3 / JA4 handshake metadata if observable in the initial client hello.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Standard ports associated with TLS/QUIC encrypted transport
ENCRYPTED_PORTS = {443, 8443, 9443, 4433, 2083, 2087, 2096}


@dataclass
class TLSMetadataResult:
    """Structured result of passive TLS/QUIC metadata inspection."""
    is_anomalous: bool
    score: float                # 0.0 to 1.0 confidence score
    classification: str         # NORMAL_TLS / SUSPICIOUS_ENCRYPTED / LIKELY_MALICIOUS_ENCRYPTED
    threat_category: str        # e.g., "Encrypted Session Anomaly" or "BENIGN"
    evidence: List[str]
    reason: str
    ja3_fingerprint: Optional[str] = None
    ja4_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TLSMetadataDetector:
    """
    Passive TLS & QUIC Metadata Anomaly Detector.
    Evaluates encrypted sessions using only flow metadata and observable transport headers.
    """

    def __init__(self):
        # Known malicious / C2 beacon JA3 MD5 hashes (e.g. Cobalt Strike, Metasploit, standard malware defaults)
        self.known_malicious_ja3 = {
            "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike default TLS beacon",
            "72a589da586844d7f0818ce684948eea": "TrickBot TLS C2 profile",
            "b32309a26951912be7dba376398abc3b": "Emotet HTTPS staging",
            "51c64c77e60f3980eea90869b68c58a8": "Qakbot TLS beacon",
        }

    @staticmethod
    def compute_ja3_fingerprint(
        ssl_version: int,
        ciphers: List[int],
        extensions: List[int],
        curves: List[int],
        point_formats: List[int],
    ) -> Tuple[str, str]:
        """
        Compute JA3 string and MD5 hash strictly from observable handshake fields.
        Does NOT decrypt application data.
        """
        ciphers_str = "-".join(str(c) for c in ciphers)
        extensions_str = "-".join(str(e) for e in extensions)
        curves_str = "-".join(str(c) for c in curves)
        point_formats_str = "-".join(str(p) for p in point_formats)

        ja3_string = f"{ssl_version},{ciphers_str},{extensions_str},{curves_str},{point_formats_str}"
        ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()
        return ja3_string, ja3_hash

    def analyze_flow(
        self,
        features: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TLSMetadataResult:
        """
        Evaluate flow telemetry for encrypted session anomalies using passive metadata only.
        """
        metadata = metadata or {}
        dst_port = metadata.get("dst_port") or metadata.get("Destination Port")
        if dst_port is None:
            dst_port = features.get("dst_port") or features.get("Destination Port")

        try:
            dst_port_int = int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None
        except (ValueError, TypeError):
            dst_port_int = None

        protocol = str(metadata.get("protocol") or features.get("protocol_name") or "TCP").upper()
        fwd_bytes = float(features.get("Total Length of Fwd Packets", features.get("total_fwd_bytes", 0.0)))
        bwd_bytes = float(features.get("Total Length of Bwd Packets", features.get("total_bwd_bytes", 0.0)))
        pkt_len_mean = float(features.get("Packet Length Mean", features.get("packet_length_mean", 0.0)))
        pkt_len_std = float(features.get("Packet Length Std", features.get("packet_length_std", 0.0)))
        pkt_len_var = float(features.get("Packet Length Variance", 0.0))
        flow_duration = float(features.get("Flow Duration", 0.0))
        flow_iat_mean = float(features.get("Flow IAT Mean", 0.0))
        flow_iat_std = float(features.get("Flow IAT Std", 0.0))
        total_fwd_pkts = float(features.get("Total Fwd Packets", 0.0))
        total_bwd_pkts = float(features.get("Total Backward Packets", 0.0))

        score = 0.0
        evidence: List[str] = []
        ja3_hash: Optional[str] = None
        ja4_str: Optional[str] = None

        # Check if flow target is an encrypted service port or protocol
        is_encrypted_transport = (dst_port_int in ENCRYPTED_PORTS) or (protocol in ("TLS", "HTTPS", "QUIC"))

        if not is_encrypted_transport:
            return TLSMetadataResult(
                is_anomalous=False,
                score=0.0,
                classification="NORMAL_TLS",
                threat_category="BENIGN",
                evidence=["Unencrypted or standard non-TLS transport."],
                reason="Traffic is not targeting an encrypted service port.",
            )

        evidence.append(f"Encrypted session transport (Port: {dst_port_int}, Protocol: {protocol})")

        # 1. JA3 / Handshake Metadata Evaluation (if observable in metadata)
        observable_ja3 = metadata.get("ja3") or metadata.get("ja3_hash")
        if not observable_ja3 and "tls_handshake" in metadata:
            hs = metadata["tls_handshake"]
            _, ja3_hash = self.compute_ja3_fingerprint(
                ssl_version=hs.get("version", 771),
                ciphers=hs.get("ciphers", []),
                extensions=hs.get("extensions", []),
                curves=hs.get("curves", []),
                point_formats=hs.get("point_formats", []),
            )
        elif observable_ja3:
            ja3_hash = str(observable_ja3).lower()

        if ja3_hash:
            evidence.append(f"Passive JA3 client fingerprint: {ja3_hash}")
            if ja3_hash in self.known_malicious_ja3:
                score += 0.50
                threat_desc = self.known_malicious_ja3[ja3_hash]
                evidence.append(f"JA3 hash matches known malware profile ({threat_desc})")
            else:
                score += 0.10

        # Optional JA4 fingerprint representation
        observable_ja4 = metadata.get("ja4")
        if observable_ja4:
            ja4_str = str(observable_ja4)
            evidence.append(f"Passive JA4 fingerprint: {ja4_str}")

        # 2. Automated C2 Beaconing in Encrypted Session (Low Packet Variance + Regular Timing)
        # Normal web traffic has high packet variance (HTML, CSS, images, API calls).
        # Automated beacons over TLS have uniform packet sizes and near-zero variance.
        if total_fwd_pkts >= 6:
            if 0.0 < pkt_len_std < 15.0 and 40.0 <= pkt_len_mean <= 300.0:
                score += 0.35
                evidence.append(
                    f"Anomalous uniform packet size distribution in TLS session (Mean: {pkt_len_mean:.1f}B, Std: {pkt_len_std:.1f}B)"
                )

            # Highly consistent inter-arrival timing (beaconing over HTTPS)
            if flow_iat_mean > 100_000 and (flow_iat_std / flow_iat_mean) < 0.25:
                score += 0.30
                evidence.append(
                    f"Periodic inter-arrival consistency over encrypted session (Mean IAT: {flow_iat_mean/1000:.1f}ms, Jitter: {flow_iat_std/flow_iat_mean:.2f})"
                )

        # 3. Asymmetric Encrypted Exfiltration (Large Outbound Over TLS with Minimal Inbound)
        if fwd_bytes >= 100_000:
            if bwd_bytes == 0.0 or (fwd_bytes / max(1.0, bwd_bytes)) >= 10.0:
                score += 0.40
                evidence.append(
                    f"Heavily asymmetric encrypted transfer ({fwd_bytes/1024:.1f} KB outbound vs {bwd_bytes/1024:.1f} KB inbound)"
                )

        # 4. Small Burst Heartbeat Anomaly (Long duration, low volume, continuous keep-alives)
        if flow_duration > 60_000_000 and total_fwd_pkts >= 10 and (fwd_bytes / total_fwd_pkts) < 100:
            score += 0.25
            evidence.append(
                f"Long-lived low-volume encrypted heartbeat channel (Duration: {flow_duration/1_000_000:.1f}s)"
            )

        final_score = round(min(score, 1.0), 4)

        if final_score >= 0.60:
            is_anom = True
            classification = "LIKELY_MALICIOUS_ENCRYPTED"
            threat_category = "Encrypted Session Anomaly"
            reason = (
                "Observed passive metadata anomalies in encrypted session (uniform packet variance, "
                "beaconing periodicity, or asymmetric transfer) without payload decryption."
            )
        elif final_score >= 0.35:
            is_anom = True
            classification = "SUSPICIOUS_ENCRYPTED"
            threat_category = "Encrypted Session Anomaly"
            reason = "Observed suspicious transport characteristics in encrypted flow metadata."
        else:
            is_anom = False
            classification = "NORMAL_TLS"
            threat_category = "BENIGN"
            reason = "Encrypted flow conforms to standard interactive TLS/QUIC session parameters."

        return TLSMetadataResult(
            is_anomalous=is_anom,
            score=final_score,
            classification=classification,
            threat_category=threat_category,
            evidence=evidence,
            reason=reason,
            ja3_fingerprint=ja3_hash,
            ja4_fingerprint=ja4_str,
        )


_detector_instance: Optional[TLSMetadataDetector] = None


def get_tls_metadata_detector() -> TLSMetadataDetector:
    """Singleton getter for TLSMetadataDetector."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = TLSMetadataDetector()
    return _detector_instance
