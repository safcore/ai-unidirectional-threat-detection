"""
M2 — Feature Extractor
========================
Converts FlowRecord objects into pandas-compatible feature dicts / DataFrames
for consumption by M3 and M4 classifiers.

Features extracted:
  • Flow volume: pkt_count, byte_count, duration, bps, pps
  • TCP flag ratios: syn_ratio, ack_ratio, rst_ratio
  • Size statistics: mean_pkt_size, std_pkt_size, coeff_of_variation
  • IAT statistics: mean_iat, std_iat, iat_entropy
  • TTL info: mean_ttl
  • Source-IP entropy across destination (per 5-sec window)
  • Destination port fan-out per source IP (per 10-sec window)
  • Outbound/inbound byte ratio (per host pair in window)
  • DNS features: query_entropy, query_length (if DNS flow)
"""

import math
import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional

from m2_features.flow_aggregator import FlowRecord

logger = logging.getLogger(__name__)


# ── Utility: Shannon Entropy ──────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    n = len(data)
    entropy = -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)
    return entropy


def iat_entropy(iats: List[float], bins: int = 10) -> float:
    """Discretize IATs into bins and compute entropy."""
    if len(iats) < 2:
        return 0.0
    min_v, max_v = min(iats), max(iats)
    if max_v == min_v:
        return 0.0
    width = (max_v - min_v) / bins
    counts = defaultdict(int)
    for v in iats:
        b = min(int((v - min_v) / width), bins - 1)
        counts[b] += 1
    n = len(iats)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def domain_ngram_score(domain: str, n: int = 3) -> float:
    """
    Simple n-gram score: fraction of n-grams NOT in a rough English bigram/trigram set.
    Higher score → more random (DGA-like).
    """
    COMMON_BIGRAMS = {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
        "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
        "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    }
    if len(domain) < n:
        return 1.0
    grams = {domain[i:i+n] for i in range(len(domain) - n + 1)}
    if n == 2:
        unknown = sum(1 for g in grams if g not in COMMON_BIGRAMS)
        return unknown / max(len(grams), 1)
    return 0.5  # default for trigram (simplified)


def extract_dns_domain(raw: bytes) -> Optional[str]:
    """
    Extract domain name from a raw DNS payload (question section).
    Returns None if not parseable.
    """
    if not raw or len(raw) < 12:
        return None
    try:
        # Skip DNS header (12 bytes)
        pos = 12
        labels = []
        while pos < len(raw):
            length = raw[pos]
            if length == 0:
                break
            pos += 1
            labels.append(raw[pos:pos+length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else None
    except Exception:
        return None


# ── Per-Window Source IP Entropy Tracker ─────────────────────────────────────

class WindowedEntropyTracker:
    """
    Tracks source IP diversity per destination in a sliding time window.
    Used for DDoS detection (spoofed-source floods have high src_ip entropy).
    """

    def __init__(self, window_sec: float = 5.0):
        self.window = window_sec
        self._lock = threading.Lock()
        # dst_ip → deque of (timestamp, src_ip)
        self._buckets: Dict[str, deque] = defaultdict(deque)

    def record(self, src_ip: str, dst_ip: str, ts: float):
        with self._lock:
            self._buckets[dst_ip].append((ts, src_ip))

    def src_ip_entropy(self, dst_ip: str) -> float:
        """Shannon entropy of source IPs seen for this destination in window."""
        now = time.time()
        with self._lock:
            dq = self._buckets.get(dst_ip, deque())
            # Trim stale
            while dq and now - dq[0][0] > self.window:
                dq.popleft()
            srcs = [ip for _, ip in dq]

        if len(srcs) < 2:
            return 0.0
        return shannon_entropy(" ".join(srcs))

    def pkt_rate(self, dst_ip: str) -> float:
        """Packets/sec arriving at dst_ip in window."""
        now = time.time()
        with self._lock:
            dq = self._buckets.get(dst_ip, deque())
            count = sum(1 for ts, _ in dq if now - ts <= self.window)
        return count / self.window


# ── Per-Source Port Fan-Out Tracker ──────────────────────────────────────────

class PortFanoutTracker:
    """
    Tracks how many unique destination ports a source IP contacts per window.
    Used for port scan detection.
    """

    def __init__(self, window_sec: float = 10.0):
        self.window = window_sec
        self._lock = threading.Lock()
        # src_ip → deque of (timestamp, dst_port)
        self._buckets: Dict[str, deque] = defaultdict(deque)

    def record(self, src_ip: str, dst_port: int, ts: float):
        with self._lock:
            self._buckets[src_ip].append((ts, dst_port))

    def unique_ports(self, src_ip: str) -> int:
        now = time.time()
        with self._lock:
            dq = self._buckets.get(src_ip, deque())
            while dq and now - dq[0][0] > self.window:
                dq.popleft()
            return len({port for _, port in dq})


# ── Outbound Byte Ratio Tracker ───────────────────────────────────────────────

class ByteRatioTracker:
    """
    Tracks outbound vs inbound bytes per host pair.
    High outbound ratio → potential data exfiltration.
    """

    def __init__(self, window_sec: float = 60.0):
        self.window = window_sec
        self._lock = threading.Lock()
        # host_pair → deque of (ts, direction, bytes)  direction: 'out'|'in'
        self._buckets: Dict[tuple, deque] = defaultdict(deque)

    def record(self, src_ip: str, dst_ip: str, byte_count: int, ts: float):
        pair = (src_ip, dst_ip)
        with self._lock:
            self._buckets[pair].append((ts, byte_count))

    def outbound_ratio(self, src_ip: str, dst_ip: str) -> float:
        """Ratio of outbound bytes from src_ip to total bytes in window."""
        out_pair = (src_ip, dst_ip)
        in_pair  = (dst_ip, src_ip)
        now = time.time()
        with self._lock:
            def _sum(pair):
                dq = self._buckets.get(pair, deque())
                return sum(b for ts, b in dq if now - ts <= self.window)
            out_bytes = _sum(out_pair)
            in_bytes  = _sum(in_pair)
        total = out_bytes + in_bytes
        return out_bytes / total if total > 0 else 0.5


# ── Main Feature Extractor ────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Converts a FlowRecord into a flat feature dict ready for ML classifiers.

    Usage:
        extractor = FeatureExtractor()
        extractor.add_handler(my_classifier.predict)
        extractor.extract(flow_record)   # called from M2 flow handler
    """

    def __init__(self):
        self.entropy_tracker  = WindowedEntropyTracker(window_sec=5.0)
        self.fanout_tracker   = PortFanoutTracker(window_sec=10.0)
        self.ratio_tracker    = ByteRatioTracker(window_sec=60.0)
        self._handlers = []

    def add_handler(self, handler):
        self._handlers.append(handler)

    def extract(self, flow: FlowRecord) -> dict:
        """Extract all features from a flow and dispatch to handlers."""
        ts = flow.last_seen

        # Update contextual trackers
        self.entropy_tracker.record(flow.src_ip, flow.dst_ip, ts)
        self.fanout_tracker.record(flow.src_ip, flow.dst_port, ts)
        self.ratio_tracker.record(flow.src_ip, flow.dst_ip, flow.byte_count, ts)

        # ── Core flow features ────────────────────────────────────────────────
        feats = flow.to_dict()

        # ── TCP flag ratios ───────────────────────────────────────────────────
        pc = max(flow.pkt_count, 1)
        feats["syn_ratio"] = flow.syn_count / pc
        feats["ack_ratio"] = flow.ack_count / pc
        feats["rst_ratio"] = flow.rst_count / pc
        feats["fin_ratio"] = flow.fin_count / pc
        feats["psh_ratio"] = flow.psh_count / pc
        feats["syn_no_ack"] = int(flow.syn_count > 0 and flow.ack_count == 0)

        # ── Packet size coefficient of variation ──────────────────────────────
        feats["pkt_size_cv"] = (
            flow.std_pkt_size / flow.mean_pkt_size
            if flow.mean_pkt_size > 0 else 0.0
        )

        # ── IAT entropy ───────────────────────────────────────────────────────
        feats["iat_entropy"] = iat_entropy(flow.inter_arrival_times)

        # ── Contextual network features ───────────────────────────────────────
        feats["src_ip_entropy"] = self.entropy_tracker.src_ip_entropy(flow.dst_ip)
        feats["dst_pkt_rate"]   = self.entropy_tracker.pkt_rate(flow.dst_ip)
        feats["unique_dst_ports"] = self.fanout_tracker.unique_ports(flow.src_ip)
        feats["outbound_ratio"] = self.ratio_tracker.outbound_ratio(flow.src_ip, flow.dst_ip)

        # ── DNS features (if DNS flow) ─────────────────────────────────────────
        feats["is_dns"] = int(flow.protocol == "DNS")
        feats["dns_entropy"]    = 0.0
        feats["dns_query_len"]  = 0
        feats["dns_ngram_score"] = 0.0

        if flow.protocol == "DNS" and flow.dns_payloads:
            domain = extract_dns_domain(flow.dns_payloads[-1])
            if domain:
                name = domain.split(".")[0] if "." in domain else domain
                feats["dns_entropy"]    = shannon_entropy(name)
                feats["dns_query_len"]  = len(name)
                feats["dns_ngram_score"] = domain_ngram_score(name, n=2)

        # Dispatch to downstream classifiers
        for h in self._handlers:
            try:
                h(feats)
            except Exception as e:
                logger.error("Feature handler error: %s", e)

        return feats
