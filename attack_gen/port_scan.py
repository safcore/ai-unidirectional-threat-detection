"""
TCP Port Scan generator for triggering discovery detections.

TEST-ONLY MODULE / SIMULATION HARNESS:
This generator is strictly for offline testing, dataset generation, and pipeline
benchmarking in controlled lab environments. It is never active in production ingress.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import List, Optional

logger = logging.getLogger(__name__)


class PortScanGenerator:
    """
    Performs TCP connect scan or simulation across a specified port range.
    """

    def __init__(
        self,
        target: str = "127.0.0.1",
        port_start: int = 1,
        port_end: int = 100,
        timeout: float = 0.05,
        threads: int = 20,
        force_simulation: bool = False,
        stop_event: Optional[threading.Event] = None,
    ):
        self.target = target
        self.ports = list(range(port_start, port_end + 1))
        self.timeout = timeout
        self.threads = min(threads, 50)
        self.force_simulation = force_simulation
        self.stop_event = stop_event or threading.Event()
        self.open_ports: List[int] = []
        self.scanned = 0
        self._lock = threading.Lock()

    def _scan_port(self, port: int) -> None:
        if self.stop_event.is_set():
            return
        if self.force_simulation:
            time.sleep(0.001)
            with self._lock:
                self.scanned += 1
                if port in (80, 443, 5000, 8000, 8080):
                    self.open_ports.append(port)
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            s.close()
            with self._lock:
                self.scanned += 1
                if result == 0:
                    self.open_ports.append(port)
        except Exception:
            with self._lock:
                self.scanned += 1

    def run(self) -> List[int]:
        logger.info(
            "Port scan started: %s ports %d-%d (threads=%d, sim=%s)",
            self.target, self.ports[0] if self.ports else 0,
            self.ports[-1] if self.ports else 0,
            self.threads, self.force_simulation,
        )
        active: List[threading.Thread] = []
        for port in self.ports:
            if self.stop_event.is_set():
                break
            while len([t for t in active if t.is_alive()]) >= self.threads:
                if self.stop_event.is_set():
                    break
                time.sleep(0.005)
            if self.stop_event.is_set():
                break
            t = threading.Thread(target=self._scan_port, args=(port,), daemon=True)
            t.start()
            active.append(t)

        for t in active:
            t.join(timeout=1.0)

        return self.open_ports
