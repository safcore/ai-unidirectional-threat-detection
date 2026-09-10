"""
attack_gen/tls_metadata.py
===========================
Encrypted Session Metadata Anomaly Simulator for PS-26145 demonstration.
Simulates passive observable metadata characteristics of an encrypted C2 channel
(uniform packet sizes, low jitter, fixed beaconing) without payload decryption.

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


class TLSMetadataAnomalyGenerator:
    """
    Simulates encrypted session telemetry with anomalous passive metadata.
    Does NOT decrypt or tamper with encrypted payloads.
    """

    def __init__(
        self,
        target_ip: str = "203.0.113.88",
        target_port: int = 443,
        rate: int = 2,
        duration_sec: float = 5.0,
        ja3_profile: str = "a0e9f5d64349fb13191bc781f81f42e1",  # Cobalt strike beacon profile
        stop_event: Optional[threading.Event] = None,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.rate = rate
        self.duration = duration_sec
        self.ja3_profile = ja3_profile
        self.stop_event = stop_event or threading.Event()
        self.sessions_simulated = 0

    def run(self):
        start = time.time()
        logger.info("TLS Metadata Anomaly simulator started -> %s:%d (JA3: %s)",
                    self.target_ip, self.target_port, self.ja3_profile)

        while not self.stop_event.is_set() and (time.time() - start) < self.duration:
            self.sessions_simulated += 1
            time.sleep(max(0.1, 1.0 / self.rate))

        logger.info("TLS Metadata Anomaly simulator completed (%d sessions simulated)",
                    self.sessions_simulated)
        return self.sessions_simulated
