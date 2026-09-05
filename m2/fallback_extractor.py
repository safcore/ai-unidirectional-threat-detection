"""
m2_features/fallback_extractor.py
==================================
Pure-Python Flow Aggregator and Feature Extractor fallback when NFStream / Npcap
is unavailable on Windows or when running in lightweight demonstration environments.
Guarantees compatibility with canonical 66-feature schema without native C dependencies.
"""

from __future__ import annotations

import math
import time
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from m1_ingest.pcap_stream_reader import RawPacket
from .canonical_adapter import adapt_to_canonical_66


@dataclass
class FallbackFlowRecord:
    """Flow tracking container for pure-Python fallback."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    pkt_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    iats: List[float] = field(default_factory=list)
    packet_sizes: List[int] = field(default_factory=list)
    ttls: List[int] = field(default_factory=list)

    def add_packet(self, pkt: RawPacket):
        now = pkt.timestamp
        if self.pkt_count > 0:
            self.iats.append(max(0.0, now - self.last_seen))
        self.last_seen = now
        self.pkt_count += 1
        self.byte_count += pkt.payload_len + 40
        self.packet_sizes.append(pkt.payload_len + 40)
        self.ttls.append(pkt.ttl)

        flags = pkt.flags
        if flags & 0x02: self.syn_count += 1
        if flags & 0x10: self.ack_count += 1
        if flags & 0x01: self.fin_count += 1
        if flags & 0x04: self.rst_count += 1
        if flags & 0x08: self.psh_count += 1
        if flags & 0x20: self.urg_count += 1

    def to_raw_features(self) -> Dict[str, Any]:
        dur = max(1e-6, self.last_seen - self.start_time)
        dur_us = dur * 1_000_000.0

        sizes = self.packet_sizes or [0]
        iats = self.iats or [0.0]
        ttls = self.ttls or [64]

        return {
            "extractor_mode": "fallback_pure_python",
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol_name": self.protocol,
            "Flow Duration": dur_us,
            "Total Fwd Packets": float(self.pkt_count),
            "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": float(self.byte_count),
            "Total Length of Bwd Packets": 0.0,
            "Fwd Packet Length Max": float(max(sizes)),
            "Fwd Packet Length Min": float(min(sizes)),
            "Fwd Packet Length Mean": float(sum(sizes) / len(sizes)),
            "Fwd Packet Length Std": float(math.sqrt(sum((x - sum(sizes)/len(sizes))**2 for x in sizes) / len(sizes))) if len(sizes) > 1 else 0.0,
            "Bwd Packet Length Max": 0.0,
            "Bwd Packet Length Min": 0.0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Min Packet Length": float(min(sizes)),
            "Max Packet Length": float(max(sizes)),
            "Packet Length Mean": float(sum(sizes) / len(sizes)),
            "Packet Length Std": float(math.sqrt(sum((x - sum(sizes)/len(sizes))**2 for x in sizes) / len(sizes))) if len(sizes) > 1 else 0.0,
            "Packet Length Variance": float(sum((x - sum(sizes)/len(sizes))**2 for x in sizes) / len(sizes)) if len(sizes) > 1 else 0.0,
            "Average Packet Size": float(sum(sizes) / len(sizes)),
            "Avg Fwd Segment Size": float(sum(sizes) / len(sizes)),
            "Avg Bwd Segment Size": 0.0,
            "Flow Bytes/s": float(self.byte_count / dur),
            "Flow Packets/s": float(self.pkt_count / dur),
            "Fwd Packets/s": float(self.pkt_count / dur),
            "Bwd Packets/s": 0.0,
            "Flow IAT Mean": float(sum(iats) / len(iats)) * 1_000_000.0,
            "Flow IAT Std": float(math.sqrt(sum((x - sum(iats)/len(iats))**2 for x in iats) / len(iats)) * 1_000_000.0) if len(iats) > 1 else 0.0,
            "Flow IAT Max": float(max(iats)) * 1_000_000.0,
            "Flow IAT Min": float(min(iats)) * 1_000_000.0,
            "Fwd IAT Total": float(sum(iats)) * 1_000_000.0,
            "Fwd IAT Mean": float(sum(iats) / len(iats)) * 1_000_000.0,
            "Fwd IAT Std": float(math.sqrt(sum((x - sum(iats)/len(iats))**2 for x in iats) / len(iats)) * 1_000_000.0) if len(iats) > 1 else 0.0,
            "Fwd IAT Max": float(max(iats)) * 1_000_000.0,
            "Fwd IAT Min": float(min(iats)) * 1_000_000.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "FIN Flag Count": float(self.fin_count),
            "SYN Flag Count": float(self.syn_count),
            "RST Flag Count": float(self.rst_count),
            "PSH Flag Count": float(self.psh_count),
            "ACK Flag Count": float(self.ack_count),
            "URG Flag Count": float(self.urg_count),
            "Fwd PSH Flags": float(self.psh_count),
            "Bwd PSH Flags": 0.0,
            "Fwd URG Flags": float(self.urg_count),
            "Bwd URG Flags": 0.0,
            "Down/Up Ratio": 0.0,
            "TTL Mean": float(sum(ttls) / len(ttls)),
            "TCP Window Size Init": 65535.0 if self.protocol == "TCP" else 0.0,
            "TCP Window Size Mean": 65535.0 if self.protocol == "TCP" else 0.0,
        }


class FallbackPurePythonAggregator:
    """Aggregates packets into flows and extracts canonical 66 features."""

    def __init__(self, flow_timeout_sec: float = 10.0):
        self.timeout = flow_timeout_sec
        self.flows: Dict[Tuple, FallbackFlowRecord] = {}

    def ingest_packet(self, pkt: RawPacket) -> Optional[Tuple[Dict[str, float], Dict[str, Any]]]:
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        now = pkt.timestamp

        # Check existing flow
        flow = self.flows.get(key)
        emitted = None

        if flow and (now - flow.last_seen > self.timeout):
            # Emit completed flow
            raw = flow.to_raw_features()
            emitted = adapt_to_canonical_66(raw)
            flow = None

        if flow is None:
            flow_id = f"flow_{len(self.flows)}_{int(now)}"
            flow = FallbackFlowRecord(
                flow_id=flow_id,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                start_time=now,
                last_seen=now,
            )
            self.flows[key] = flow

        flow.add_packet(pkt)
        return emitted

    def flush_flows(self) -> List[Tuple[Dict[str, float], Dict[str, Any]]]:
        """Flush all active flows."""
        results = []
        for flow in self.flows.values():
            raw = flow.to_raw_features()
            results.append(adapt_to_canonical_66(raw))
        self.flows.clear()
        return results
