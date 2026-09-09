"""
flow_store.py — Thread-safe In-Memory Store for Observed Network Flows.

Stores genuine flows ingested via PCAP upload, PCAP replay, live interface capture,
or streaming telemetry. Enables IP-based filtering and genuine ML evaluation.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ObservedFlow:
    """Represents a genuine network flow observed by the ingress pipeline."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration_ms: float
    timestamp: float
    features: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    attack_type: Optional[str] = None
    detection: Optional[Dict[str, Any]] = None
    alert_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "attack_type": self.attack_type,
            "alert_id": self.alert_id,
        }


class FlowStore:
    """Thread-safe store for observed network flows."""

    def __init__(self, max_flows: int = 10000):
        self._flows: List[ObservedFlow] = []
        self._flows_by_src: Dict[str, List[ObservedFlow]] = {}
        self._lock = threading.Lock()
        self._max_flows = max_flows
        self._counter = 0

    def record_flow(
        self,
        features: Dict[str, float],
        metadata: Dict[str, Any],
        raw_stats: Optional[Dict[str, Any]] = None,
        detection: Optional[Dict[str, Any]] = None,
        alert_id: Optional[str] = None,
    ) -> ObservedFlow:
        """Record an observed flow into the store."""
        raw_stats = raw_stats or {}
        with self._lock:
            self._counter += 1
            flow_id = str(metadata.get("flow_id") or f"FLW-{self._counter:05d}")
            src_ip = str(metadata.get("src_ip") or "0.0.0.0").strip()
            dst_ip = str(metadata.get("dst_ip") or "0.0.0.0").strip()
            src_port = int(metadata.get("src_port") or 0)
            dst_port = int(metadata.get("dst_port") or 0)
            protocol = str(metadata.get("protocol") or metadata.get("protocol_name") or "TCP").upper()

            # Packet and byte metrics from raw stats or canonical features
            pkt_count = int(
                raw_stats.get("packet_count")
                or features.get("Total Fwd Packets", 0) + features.get("Total Backward Packets", 0)
                or 1
            )
            byte_count = int(
                raw_stats.get("byte_count")
                or features.get("Total Length of Fwd Packets", 0) + features.get("Total Length of Bwd Packets", 0)
                or 64
            )
            duration_us = float(
                raw_stats.get("duration_us")
                or features.get("Flow Duration", 1000.0)
            )
            duration_ms = max(0.1, round(duration_us / 1000.0, 2))

            flow = ObservedFlow(
                flow_id=flow_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_count=pkt_count,
                byte_count=byte_count,
                duration_ms=duration_ms,
                timestamp=time.time(),
                features=dict(features),
                metadata=dict(metadata),
                attack_type=metadata.get("attack_type"),
                detection=detection,
                alert_id=alert_id,
            )

            # Evict oldest if full
            if len(self._flows) >= self._max_flows:
                removed = self._flows.pop(0)
                src_list = self._flows_by_src.get(removed.src_ip, [])
                if removed in src_list:
                    src_list.remove(removed)

            self._flows.append(flow)
            if src_ip not in self._flows_by_src:
                self._flows_by_src[src_ip] = []
            self._flows_by_src[src_ip].append(flow)
            return flow

    def get_flows_by_ip(self, ip: str) -> List[ObservedFlow]:
        """Find all observed flows where src_ip matches ip."""
        ip = str(ip).strip()
        with self._lock:
            return list(self._flows_by_src.get(ip, []))

    def has_ip(self, ip: str) -> bool:
        """Check if any flows have been observed for this IP."""
        ip = str(ip).strip()
        with self._lock:
            return ip in self._flows_by_src and len(self._flows_by_src[ip]) > 0

    def total_flows(self) -> int:
        with self._lock:
            return len(self._flows)

    def total_packets(self) -> int:
        with self._lock:
            return sum(f.packet_count for f in self._flows)

    def total_bytes(self) -> int:
        with self._lock:
            return sum(f.byte_count for f in self._flows)

    def observed_ips(self) -> List[str]:
        with self._lock:
            return sorted(self._flows_by_src.keys())

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_flows": len(self._flows),
                "total_packets": sum(f.packet_count for f in self._flows),
                "total_bytes": sum(f.byte_count for f in self._flows),
                "unique_ips": len(self._flows_by_src),
                "active_ips": sorted(self._flows_by_src.keys()),
            }

    def clear(self):
        with self._lock:
            self._flows.clear()
            self._flows_by_src.clear()
            self._counter = 0


# Global singleton instance
flow_store = FlowStore()
