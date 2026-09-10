"""
attack_gen/data_exfiltration.py
================================
Data Exfiltration Simulator for PS-26145 demonstration.
Simulates high-volume asymmetric outbound data transfer.

TEST-ONLY MODULE / SIMULATION HARNESS:
This generator is strictly for offline testing, dataset generation, and pipeline
benchmarking in controlled lab environments. It is never active in production ingress.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class DataExfiltrationGenerator:
    """
    Simulates high-volume outbound data exfiltration over TCP/HTTPS or DNS.
    """

    def __init__(
        self,
        target_ip: str = "198.51.100.23",
        target_port: int = 443,
        rate_kbps: int = 500,
        duration_sec: float = 5.0,
        chunk_size: int = 8192,
        stop_event: Optional[threading.Event] = None,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.rate_kbps = rate_kbps
        self.duration = duration_sec
        self.chunk_size = chunk_size
        self.stop_event = stop_event or threading.Event()
        self.bytes_sent = 0
        self.chunks_sent = 0

    def run(self):
        start = time.time()
        logger.info("Data Exfiltration simulator started -> %s:%d (%d KB/s)",
                    self.target_ip, self.target_port, self.rate_kbps)

        while not self.stop_event.is_set() and (time.time() - start) < self.duration:
            self.bytes_sent += self.chunk_size
            self.chunks_sent += 1
            # Sleep appropriate interval to match rate
            time.sleep(max(0.01, self.chunk_size / (self.rate_kbps * 1024)))

        logger.info("Data Exfiltration simulator completed (%d KB transferred)",
                    self.bytes_sent // 1024)
        return self.bytes_sent
