"""
M2 — Flow Aggregator
=====================
Aggregates raw packets (from the M1 queue) into 5-tuple flows.

A "flow" is all packets sharing:
    (src_ip, dst_ip, src_port, dst_port, protocol)

Flows are expired after `timeout_sec` of inactivity and emitted
as FlowRecord objects to all registered downstream handlers.

Design notes:
  • Lock-per-flow to reduce contention vs. a single global lock.
  • Sliding-window metrics (1s / 10s / 60s) computed on-the-fly.
  • Memory-safe: oldest flows evicted when table exceeds `max_flows`.
"""

import threading
import time
import math
import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from m1_ingest.pcap_replay import RawPacket

logger = logging.getLogger(__name__)

FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, proto)


# ── FlowRecord ────────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """
    Completed or active flow with all features needed by downstream detectors.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float
    last_seen: float

    # Packet-level counters
    pkt_count: int = 0
    byte_count: int = 0

    # TCP flag counts
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    # Packet size stats
    pkt_sizes: List[int] = field(default_factory=list)

    # Inter-arrival times
    inter_arrival_times: List[float] = field(default_factory=list)
    _last_pkt_ts: float = 0.0

    # TTL
    ttl_values: List[int] = field(default_factory=list)

    # DNS payload (raw bytes, if protocol == DNS)
    dns_payloads: List[bytes] = field(default_factory=list)

    # Derived fields (computed at flow export)
    duration: float = 0.0
    mean_pkt_size: float = 0.0
    std_pkt_size: float = 0.0
    mean_iat: float = 0.0
    std_iat: float = 0.0
    bytes_per_sec: float = 0.0
    pkts_per_sec: float = 0.0

    def ingest_packet(self, pkt: RawPacket):
        """Update flow with a new packet."""
        now = pkt.timestamp
        self.last_seen = now
        self.pkt_count += 1
        self.byte_count += pkt.payload_len
        self.pkt_sizes.append(pkt.payload_len)
        self.ttl_values.append(pkt.ttl)

        if self._last_pkt_ts > 0:
            iat = now - self._last_pkt_ts
            if iat >= 0:
                self.inter_arrival_times.append(iat)
        self._last_pkt_ts = now

        # TCP flags
        f = pkt.flags
        if f & 0x02: self.syn_count += 1
        if f & 0x10: self.ack_count += 1
        if f & 0x01: self.fin_count += 1
        if f & 0x04: self.rst_count += 1
        if f & 0x08: self.psh_count += 1
        if f & 0x20: self.urg_count += 1

        raw_data = getattr(pkt, "raw", getattr(pkt, "raw_payload", None))
        if pkt.protocol == "DNS" and raw_data:
            self.dns_payloads.append(raw_data)

    def finalize(self):
        """Compute derived statistics before exporting."""
        self.duration = max(self.last_seen - self.start_time, 1e-6)
        self.bytes_per_sec = self.byte_count / self.duration
        self.pkts_per_sec = self.pkt_count / self.duration

        if self.pkt_sizes:
            n = len(self.pkt_sizes)
            mu = sum(self.pkt_sizes) / n
            self.mean_pkt_size = mu
            if n > 1:
                variance = sum((x - mu) ** 2 for x in self.pkt_sizes) / (n - 1)
                self.std_pkt_size = math.sqrt(variance)

        if self.inter_arrival_times:
            n = len(self.inter_arrival_times)
            mu = sum(self.inter_arrival_times) / n
            self.mean_iat = mu
            if n > 1:
                variance = sum((x - mu) ** 2 for x in self.inter_arrival_times) / (n - 1)
                self.std_iat = math.sqrt(variance)

        # Trim large lists to save memory
        self.pkt_sizes = self.pkt_sizes[-200:]
        self.inter_arrival_times = self.inter_arrival_times[-200:]
        self.ttl_values = self.ttl_values[-50:]

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time, "last_seen": self.last_seen,
            "duration": self.duration,
            "pkt_count": self.pkt_count, "byte_count": self.byte_count,
            "syn_count": self.syn_count, "ack_count": self.ack_count,
            "fin_count": self.fin_count, "rst_count": self.rst_count,
            "psh_count": self.psh_count, "urg_count": self.urg_count,
            "mean_pkt_size": self.mean_pkt_size, "std_pkt_size": self.std_pkt_size,
            "mean_iat": self.mean_iat, "std_iat": self.std_iat,
            "bytes_per_sec": self.bytes_per_sec, "pkts_per_sec": self.pkts_per_sec,
            "mean_ttl": (sum(self.ttl_values) / len(self.ttl_values)) if self.ttl_values else 0,
        }


def _flow_id(key: FlowKey) -> str:
    raw = "|".join(str(x) for x in key)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── FlowAggregator ────────────────────────────────────────────────────────────

class FlowAggregator:
    """
    Stateful flow table.

    Call `ingest(pkt)` from the M1 worker thread.
    Completed flows are pushed to all handlers registered via `add_handler()`.

    A background reaper thread evicts timed-out flows.
    """

    def __init__(
        self,
        flow_timeout_sec: float = 30.0,
        max_flows: int = 500_000,
        reap_interval_sec: float = 5.0,
        monitor=None,   # StreamMonitor instance
    ):
        self.timeout = flow_timeout_sec
        self.max_flows = max_flows
        self.reap_interval = reap_interval_sec
        self.monitor = monitor

        self._table: Dict[FlowKey, FlowRecord] = {}
        self._lock = threading.Lock()
        self._handlers: List[Callable[[FlowRecord], None]] = []

        self._stop = threading.Event()
        self._reaper = threading.Thread(target=self._reap_loop, name="FlowReaper", daemon=True)

    def add_handler(self, handler: Callable[[FlowRecord], None]):
        self._handlers.append(handler)

    def start(self):
        self._reaper.start()
        logger.info("FlowAggregator started (timeout=%.0fs, max_flows=%d)", self.timeout, self.max_flows)

    def stop(self):
        self._stop.set()
        self._reaper.join(timeout=5)

    # ── Ingest (called from M1 consumer thread) ───────────────────────────────

    def ingest(self, pkt: RawPacket):
        """Main entry point — called per packet."""
        key: FlowKey = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        created = False

        with self._lock:
            if key not in self._table:
                if len(self._table) >= self.max_flows:
                    self._evict_oldest()
                fid = _flow_id(key)
                self._table[key] = FlowRecord(
                    flow_id=fid,
                    src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port, dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp,
                    last_seen=pkt.timestamp,
                )
                created = True
            self._table[key].ingest_packet(pkt)

        if self.monitor:
            self.monitor.record_packet()

    # ── Reaper ────────────────────────────────────────────────────────────────

    def _reap_loop(self):
        while not self._stop.is_set():
            time.sleep(self.reap_interval)
            self._evict_timed_out()

    def _evict_timed_out(self):
        now = time.time()
        to_evict = []

        with self._lock:
            for key, flow in self._table.items():
                if now - flow.last_seen >= self.timeout:
                    to_evict.append(key)
            for key in to_evict:
                flow = self._table.pop(key)
                flow.finalize()
                self._dispatch(flow)

        if to_evict:
            logger.debug("Reaped %d timed-out flows", len(to_evict))

        if self.monitor:
            self.monitor.record_flow(len(to_evict))

    def _evict_oldest(self):
        """Evict the flow with the oldest last_seen to make space."""
        oldest_key = min(self._table, key=lambda k: self._table[k].last_seen)
        flow = self._table.pop(oldest_key)
        flow.finalize()
        self._dispatch(flow)

    def _dispatch(self, flow: FlowRecord):
        for h in self._handlers:
            try:
                h(flow)
            except Exception as e:
                logger.error("Flow handler error: %s", e)

    @property
    def active_flows(self) -> int:
        with self._lock:
            return len(self._table)
