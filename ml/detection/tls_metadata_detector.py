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


# GREASE values defined in RFC 8701
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def parse_tls_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Passively parse a TLS ClientHello record from raw mirrored packet payload.
    Does NOT decrypt or modify traffic; operates purely on observable cleartext headers.
    
    Returns None if payload is not a valid TLS ClientHello or contains insufficient bytes.
    """
    if not payload or len(payload) < 42:
        return None

    try:
        # TLS Record layer: Content Type (1 byte: 0x16 = Handshake), Version (2 bytes), Length (2 bytes)
        content_type = payload[0]
        if content_type != 0x16:
            return None

        record_len = (payload[3] << 8) | payload[4]
        if len(payload) < 5 + record_len:
            # Fragmented packet; evaluate available slice
            payload_slice = payload[5:]
        else:
            payload_slice = payload[5 : 5 + record_len]

        # Handshake Type (1 byte: 0x01 = ClientHello)
        if len(payload_slice) < 38 or payload_slice[0] != 0x01:
            return None

        # Handshake Length (3 bytes)
        # hs_len = (payload_slice[1] << 16) | (payload_slice[2] << 8) | payload_slice[3]

        # Client Version (2 bytes)
        client_version = (payload_slice[4] << 8) | payload_slice[5]

        # Skip Random (32 bytes: 6..38)
        offset = 38
        if len(payload_slice) <= offset:
            return None

        # Session ID Length (1 byte)
        session_id_len = payload_slice[offset]
        offset += 1 + session_id_len
        if len(payload_slice) <= offset + 2:
            return None

        # Cipher Suites Length (2 bytes)
        cipher_len = (payload_slice[offset] << 8) | payload_slice[offset + 1]
        offset += 2
        if len(payload_slice) < offset + cipher_len:
            return None

        ciphers: List[int] = []
        for i in range(0, cipher_len, 2):
            c = (payload_slice[offset + i] << 8) | payload_slice[offset + i + 1]
            if c not in GREASE_VALUES:
                ciphers.append(c)
        offset += cipher_len

        # Compression Methods
        if len(payload_slice) <= offset:
            return None
        comp_len = payload_slice[offset]
        offset += 1 + comp_len

        # Extensions
        extensions: List[int] = []
        curves: List[int] = []
        point_formats: List[int] = []
        sni: Optional[str] = None
        has_supported_versions_13 = False

        if len(payload_slice) > offset + 2:
            ext_total_len = (payload_slice[offset] << 8) | payload_slice[offset + 1]
            offset += 2
            ext_end = min(offset + ext_total_len, len(payload_slice))

            while offset + 4 <= ext_end:
                ext_type = (payload_slice[offset] << 8) | payload_slice[offset + 1]
                ext_len = (payload_slice[offset + 2] << 8) | payload_slice[offset + 3]
                offset += 4

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                ext_data = payload_slice[offset : offset + ext_len]
                offset += ext_len

                # SNI (Extension 0)
                if ext_type == 0 and len(ext_data) >= 5:
                    sni_name_len = (ext_data[3] << 8) | ext_data[4]
                    if len(ext_data) >= 5 + sni_name_len:
                        try:
                            sni = ext_data[5 : 5 + sni_name_len].decode("utf-8", errors="ignore")
                        except Exception:
                            pass

                # Supported Groups / Elliptic Curves (Extension 10)
                elif ext_type == 10 and len(ext_data) >= 2:
                    groups_len = (ext_data[0] << 8) | ext_data[1]
                    for g_idx in range(2, min(2 + groups_len, len(ext_data)), 2):
                        group = (ext_data[g_idx] << 8) | ext_data[g_idx + 1]
                        if group not in GREASE_VALUES:
                            curves.append(group)

                # EC Point Formats (Extension 11)
                elif ext_type == 11 and len(ext_data) >= 1:
                    ec_len = ext_data[0]
                    for p_idx in range(1, min(1 + ec_len, len(ext_data))):
                        point_formats.append(ext_data[p_idx])

                # Supported Versions (Extension 43 / 0x002b)
                elif ext_type == 43 and len(ext_data) >= 1:
                    sv_len = ext_data[0]
                    for v_idx in range(1, min(1 + sv_len, len(ext_data)), 2):
                        if v_idx + 1 < len(ext_data):
                            ver = (ext_data[v_idx] << 8) | ext_data[v_idx + 1]
                            if ver == 0x0304:  # TLS 1.3
                                has_supported_versions_13 = True

        return {
            "version": client_version,
            "has_tls13": has_supported_versions_13,
            "ciphers": ciphers,
            "extensions": extensions,
            "curves": curves,
            "point_formats": point_formats,
            "sni": sni,
        }
    except Exception as exc:
        logger.debug("Passive TLS parse exception: %s", exc)
        return None


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
        Compute standard JA3 string and MD5 hash strictly from observable handshake fields.
        Filters GREASE values in conformance with Salesforce JA3 specification.
        Does NOT decrypt application data.
        """
        filtered_ciphers = [c for c in ciphers if c not in GREASE_VALUES]
        filtered_exts = [e for e in extensions if e not in GREASE_VALUES]
        filtered_curves = [c for c in curves if c not in GREASE_VALUES]

        ciphers_str = "-".join(str(c) for c in filtered_ciphers)
        extensions_str = "-".join(str(e) for e in filtered_exts)
        curves_str = "-".join(str(c) for c in filtered_curves)
        point_formats_str = "-".join(str(p) for p in point_formats)

        ja3_string = f"{ssl_version},{ciphers_str},{extensions_str},{curves_str},{point_formats_str}"
        ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()
        return ja3_string, ja3_hash

    @staticmethod
    def compute_ja4_fingerprint(
        protocol: str,
        tls_version: int,
        has_sni: bool,
        ciphers: List[int],
        extensions: List[int],
        alpn: str = "00",
        has_tls13: bool = False,
    ) -> str:
        """
        Compute observable JA4 Client fingerprint:
          Format: {protocol}{version}{sni}{ciphers_count}{ext_count}{alpn}_{ciphers_hash}_{ext_hash}
          e.g. t13d151100_...
        Calculated purely on observed client handshake fields. Does not fabricate hashes.
        """
        proto_char = "t" if "TCP" in protocol.upper() else ("q" if "QUIC" in protocol.upper() else "t")
        ver_str = "13" if (has_tls13 or tls_version == 0x0304) else ("12" if tls_version == 0x0303 else "10")
        sni_char = "d" if has_sni else "i"
        
        filtered_ciphers = sorted([c for c in ciphers if c not in GREASE_VALUES])
        filtered_exts = sorted([e for e in extensions if e not in GREASE_VALUES])

        cipher_count = f"{min(len(filtered_ciphers), 99):02d}"
        ext_count = f"{min(len(filtered_exts), 99):02d}"
        part_a = f"{proto_char}{ver_str}{sni_char}{cipher_count}{ext_count}{alpn}"

        ciphers_hex = ",".join(f"{c:04x}" for c in filtered_ciphers)
        part_b = hashlib.sha256(ciphers_hex.encode("utf-8")).hexdigest()[:12] if filtered_ciphers else "000000000000"

        exts_hex = ",".join(f"{e:04x}" for e in filtered_exts)
        part_c = hashlib.sha256(exts_hex.encode("utf-8")).hexdigest()[:12] if filtered_exts else "000000000000"

        return f"{part_a}_{part_b}_{part_c}"

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

        # 1. JA3 / JA4 Handshake Metadata Evaluation (if observable in metadata or raw payload)
        observable_ja3 = metadata.get("ja3") or metadata.get("ja3_hash")
        raw_payload = metadata.get("raw_payload") or metadata.get("raw_frame")
        parsed_hello = None

        if isinstance(raw_payload, (bytes, bytearray)) and len(raw_payload) >= 42:
            parsed_hello = parse_tls_client_hello(bytes(raw_payload))

        if parsed_hello:
            _, ja3_hash = self.compute_ja3_fingerprint(
                ssl_version=parsed_hello["version"],
                ciphers=parsed_hello["ciphers"],
                extensions=parsed_hello["extensions"],
                curves=parsed_hello["curves"],
                point_formats=parsed_hello["point_formats"],
            )
            ja4_str = self.compute_ja4_fingerprint(
                protocol=protocol,
                tls_version=parsed_hello["version"],
                has_sni=bool(parsed_hello["sni"]),
                ciphers=parsed_hello["ciphers"],
                extensions=parsed_hello["extensions"],
                has_tls13=parsed_hello.get("has_tls13", False),
            )
            if parsed_hello.get("sni"):
                evidence.append(f"Passive TLS SNI: {parsed_hello['sni']}")

        elif not observable_ja3 and "tls_handshake" in metadata:
            hs = metadata["tls_handshake"]
            _, ja3_hash = self.compute_ja3_fingerprint(
                ssl_version=hs.get("version", 771),
                ciphers=hs.get("ciphers", []),
                extensions=hs.get("extensions", []),
                curves=hs.get("curves", []),
                point_formats=hs.get("point_formats", []),
            )
            ja4_str = self.compute_ja4_fingerprint(
                protocol=protocol,
                tls_version=hs.get("version", 771),
                has_sni=bool(hs.get("sni")),
                ciphers=hs.get("ciphers", []),
                extensions=hs.get("extensions", []),
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
        observable_ja4 = metadata.get("ja4") or ja4_str
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
