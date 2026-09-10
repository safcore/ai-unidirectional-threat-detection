"""
attack_gen/c2_beacon.py
========================
Command & Control (C2) Beaconing Simulator for PS-26145 demonstration.
Simulates periodic keep-alive telemetry with low jitter to common C2/IRC ports.

TEST-ONLY MODULE / SIMULATION HARNESS:
This generator is strictly for offline testing, dataset generation, and pipeline
benchmarking in controlled lab environments. It is never active in production ingress.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class C2BeaconGenerator:
    """
    Simulates periodic C2 beaconing over TCP.
    """

    def __init__(
        self,
        target_ip: str = "192.168.1.100",
        target_port: int = 8443,
        interval_sec: float = 1.0,
        duration_sec: float = 10.0,
        payload_size: int = 48,
        stop_event: Optional[threading.Event] = None,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.interval = interval_sec
        self.duration = duration_sec
        self.payload_size = payload_size
        self.stop_event = stop_event or threading.Event()
        self.beacons_sent = 0

    def run(self):
        start = time.time()
        logger.info("C2 Beacon simulator started -> %s:%d", self.target_ip, self.target_port)

        while not self.stop_event.is_set() and (time.time() - start) < self.duration:
            self.beacons_sent += 1
            # Add small realistic jitter (0.01 - 0.05s) to mimic real malware beacon profiles
            jitter = random.uniform(0.01, 0.05)
            time.sleep(max(0.05, self.interval + jitter))

        logger.info("C2 Beacon simulator completed (%d beacons sent)", self.beacons_sent)
        return self.beacons_sent
