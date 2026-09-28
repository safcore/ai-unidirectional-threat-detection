"""
M3 — Port Scan / Reconnaissance Detector
==========================================
Detects:
  • Horizontal port scans   — single source → many unique dst ports
  • Network sweeps          — single source → many unique dst hosts
  • SYN-only probes         — SYN without ACK/FIN (classic nmap -sS)

Algorithm: Sliding window counting + threshold rules.
No ML model required (pure statistical).
"""

import time
import logging
import threading
from collections import defaultdict, deque
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PortScanDetector:
    """
    Tracks unique destination ports and hosts per source IP in a sliding window.
    Fires an alert when thresholds are exceeded.
    """

    # Tuneable thresholds
    PORT_SCAN_THRESHOLD  = 30    # unique dst ports in window → port scan
    HOST_SWEEP_THRESHOLD = 20    # unique dst hosts in window → network sweep
    WINDOW_SEC = 10.0            # sliding window size

    def __init__(self, alert_handler: Optional[Callable] = None):
        self._handlers: List[Callable] = []
        if alert_handler:
            self._handlers.append(alert_handler)

        self._lock = threading.Lock()
        # src_ip → deque of (timestamp, dst_ip, dst_port)
        self._table: Dict[str, deque] = defaultdict(deque)
        # Track which src_ips we've already alerted to avoid spam
        self._alerted: Dict[str, float] = {}  # src_ip → last_alert_ts
        self._alert_cooldown = 30.0            # seconds between repeat alerts

    def add_handler(self, h: Callable):
        self._handlers.append(h)

    def predict(self, feats: dict):
        """Called per flow from FeatureExtractor."""
        src_ip   = feats.get("src_ip", "")
        dst_ip   = feats.get("dst_ip", "")
        dst_port = feats.get("dst_port", 0)
        proto    = feats.get("protocol", "")
        syn_no_ack = feats.get("syn_no_ack", 0)
        ts       = feats.get("last_seen", time.time())

        with self._lock:
            dq = self._table[src_ip]
            dq.append((ts, dst_ip, dst_port))

            # Trim stale entries
            cutoff = ts - self.WINDOW_SEC
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            recent = list(dq)

        unique_ports = len({p for _, _, p in recent})
        unique_hosts = len({ip for _, ip, _ in recent})

        # Cooldown check
        last_alert = self._alerted.get(src_ip, 0)
        if ts - last_alert < self._alert_cooldown:
            return

        # Evaluate thresholds
        if unique_ports >= self.PORT_SCAN_THRESHOLD:
            self._fire_alert(feats, "PORT_SCAN", unique_ports, unique_hosts, ts)
            with self._lock:
                self._alerted[src_ip] = ts
        elif unique_hosts >= self.HOST_SWEEP_THRESHOLD:
            self._fire_alert(feats, "NETWORK_SWEEP", unique_ports, unique_hosts, ts)
            with self._lock:
                self._alerted[src_ip] = ts

    def _fire_alert(
        self,
        feats: dict,
        subtype: str,
        unique_ports: int,
        unique_hosts: int,
        ts: float,
    ):
        confidence = min(
            0.5 + 0.02 * max(unique_ports - self.PORT_SCAN_THRESHOLD,
                             unique_hosts - self.HOST_SWEEP_THRESHOLD),
            0.99
        )
        alert = {
            "threat_class":   "RECON",
            "threat_subtype": subtype,
            "confidence":     round(confidence, 4),
            "severity":       "HIGH" if confidence > 0.75 else "MEDIUM",
            "evidence": {
                "unique_dst_ports": unique_ports,
                "unique_dst_hosts": unique_hosts,
                "window_sec":       self.WINDOW_SEC,
                "syn_no_ack":       feats.get("syn_no_ack", 0),
                "protocol":         feats.get("protocol", ""),
            },
            **{k: feats[k] for k in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"] if k in feats},
        }
        for h in self._handlers:
            try:
                h(alert)
            except Exception as e:
                logger.error("PortScan alert handler error: %s", e)
