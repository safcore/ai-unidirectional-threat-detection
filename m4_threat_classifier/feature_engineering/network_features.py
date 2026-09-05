"""
Network Behavioral Feature Extractor Module.

Converts structured pre-aggregated network flow records into standardized behavioral feature vectors
for C2 communication and Data Exfiltration detection.

EXPECTED INPUT FLOW SCHEMA (dict):
----------------------------------
{
    "flow_id": str,               # Unique flow identifier
    "src_ip": str,                # Source IP address
    "dst_ip": str,                # Destination IP address
    "src_port": int,              # Source port
    "dst_port": int,              # Destination port
    "protocol": str,              # TCP / UDP / ICMP
    "flow_duration": float,       # Total flow duration in seconds
    "packets_out": int,           # Forward/Outbound packet count
    "packets_in": int,            # Backward/Inbound packet count
    "bytes_out": int,             # Outbound payload bytes
    "bytes_in": int,              # Inbound payload bytes
    "packet_lengths": List[int],  # List of individual packet sizes (optional)
    "inter_arrival_times": List[float], # Flow inter-arrival timestamps (optional)
    "connection_count_10s": int,  # Connections to destination in last 10s window (optional)
    "dst_frequency": int          # Number of distinct connections to target destination (optional)
}
"""

import math
from typing import Dict, Any, List, Union


class NetworkBehavioralFeatureExtractor:
    """
    Extracts statistical and behavioral features from structured network flow records.
    Does NOT ingest raw PCAP files directly; relies on upstream M1/M2 flow extractors.
    """

    def extract_features(self, flow_record: Dict[str, Any]) -> Dict[str, Union[int, float]]:
        """
        Extract numerical behavioral features from a structured flow record dictionary.

        Args:
            flow_record: Dictionary adhering to EXPECTED INPUT FLOW SCHEMA.

        Returns:
            Dict[str, Union[int, float]]: Extracted behavioral features dictionary.
        """
        if not flow_record or not isinstance(flow_record, dict):
            return self._empty_features()

        flow_duration = float(flow_record.get("flow_duration", 0.0))
        packets_out = int(flow_record.get("packets_out", 0))
        packets_in = int(flow_record.get("packets_in", 0))
        total_packets = packets_out + packets_in

        bytes_out = int(flow_record.get("bytes_out", 0))
        bytes_in = int(flow_record.get("bytes_in", 0))
        total_bytes = bytes_out + bytes_in

        # Upload / Download Byte Ratio (critical for Exfiltration)
        upload_download_ratio = (bytes_out / bytes_in) if bytes_in > 0 else float(bytes_out)

        # Flow throughput metrics
        bytes_per_second = (total_bytes / flow_duration) if flow_duration > 0 else 0.0
        packets_per_second = (total_packets / flow_duration) if flow_duration > 0 else 0.0

        # Packet size statistics
        packet_lengths: List[int] = flow_record.get("packet_lengths", [])
        if packet_lengths:
            pkt_mean = sum(packet_lengths) / len(packet_lengths)
            variance = sum((x - pkt_mean) ** 2 for x in packet_lengths) / len(packet_lengths)
            pkt_std = math.sqrt(variance)
            pkt_min = min(packet_lengths)
            pkt_max = max(packet_lengths)
        else:
            pkt_mean = (total_bytes / total_packets) if total_packets > 0 else 0.0
            pkt_std = 0.0
            pkt_min = 0
            pkt_max = 0

        # Periodicity / Inter-arrival Time (IAT) statistics (critical for C2 Beaconing)
        iats: List[float] = flow_record.get("inter_arrival_times", [])
        if len(iats) > 1:
            iat_mean = sum(iats) / len(iats)
            iat_variance = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
            iat_std = math.sqrt(iat_variance)
            # Coefficient of Variation (CoV) for periodicity (lower CoV indicates rigid periodic C2 beacon)
            periodicity_cov = (iat_std / iat_mean) if iat_mean > 0 else 999.0
        else:
            iat_mean = 0.0
            iat_std = 0.0
            periodicity_cov = 999.0

        # Connection & Destination Frequency
        connection_count_10s = int(flow_record.get("connection_count_10s", 1))
        dst_frequency = int(flow_record.get("dst_frequency", 1))

        return {
            "flow_duration": round(flow_duration, 4),
            "total_packets": total_packets,
            "packets_out": packets_out,
            "packets_in": packets_in,
            "total_bytes": total_bytes,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "upload_download_ratio": round(float(upload_download_ratio), 4),
            "bytes_per_second": round(float(bytes_per_second), 4),
            "packets_per_second": round(float(packets_per_second), 4),
            "packet_length_mean": round(float(pkt_mean), 4),
            "packet_length_std": round(float(pkt_std), 4),
            "packet_length_min": pkt_min,
            "packet_length_max": pkt_max,
            "iat_mean": round(float(iat_mean), 4),
            "iat_std": round(float(iat_std), 4),
            "periodicity_cov": round(float(periodicity_cov), 4),
            "connection_count_10s": connection_count_10s,
            "dst_frequency": dst_frequency,
        }

    def _empty_features(self) -> Dict[str, Union[int, float]]:
        """Return zeroed features dictionary when empty flow record is provided."""
        return {
            "flow_duration": 0.0,
            "total_packets": 0,
            "packets_out": 0,
            "packets_in": 0,
            "total_bytes": 0,
            "bytes_out": 0,
            "bytes_in": 0,
            "upload_download_ratio": 0.0,
            "bytes_per_second": 0.0,
            "packets_per_second": 0.0,
            "packet_length_mean": 0.0,
            "packet_length_std": 0.0,
            "packet_length_min": 0,
            "packet_length_max": 0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "periodicity_cov": 999.0,
            "connection_count_10s": 0,
            "dst_frequency": 0,
        }
