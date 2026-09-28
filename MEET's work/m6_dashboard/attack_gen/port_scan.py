"""
M6 — Port Scanner (nmap -sS equivalent for demo)
=================================================
Sends TCP SYN packets to sequential ports on a target host.
Uses stdlib — no raw sockets needed (TCP connect scan fallback).
"""

import socket
import time
import threading
import logging
import argparse
from typing import List

logger = logging.getLogger(__name__)


class PortScanGenerator:
    """
    Performs a TCP connect scan across a port range.
    Suitable for triggering the M3 PortScanDetector in demo mode.
    """

    def __init__(
        self,
        target: str = "127.0.0.1",
        port_start: int = 1,
        port_end: int = 1024,
        timeout: float = 0.05,
        threads: int = 50,
    ):
        self.target     = target
        self.ports      = list(range(port_start, port_end + 1))
        self.timeout    = timeout
        self.threads    = threads
        self._open      = []
        self._lock      = threading.Lock()
        self._scanned   = 0

    def _scan_port(self, port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            s.close()
            with self._lock:
                self._scanned += 1
                if result == 0:
                    self._open.append(port)
                    logger.debug("OPEN: %s:%d", self.target, port)
        except Exception:
            pass

    def run(self) -> List[int]:
        logger.info(
            "Port scan: %s ports %d-%d (%d threads, timeout=%.2fs)",
            self.target, self.ports[0], self.ports[-1], self.threads, self.timeout
        )
        start = time.time()
        active = []
        for port in self.ports:
            # Keep thread pool bounded
            while len([t for t in active if t.is_alive()]) >= self.threads:
                time.sleep(0.005)
            t = threading.Thread(target=self._scan_port, args=(port,), daemon=True)
            t.start()
            active.append(t)

        for t in active:
            t.join()

        elapsed = time.time() - start
        logger.info(
            "Scan complete: %d ports in %.1fs — %d open: %s",
            self._scanned, elapsed, len(self._open), self._open[:20]
        )
        return self._open


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Port Scanner (demo trigger for NetWatch)")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--start",  type=int, default=1)
    parser.add_argument("--end",    type=int, default=1024)
    parser.add_argument("--threads",type=int, default=50)
    args = parser.parse_args()
    scanner = PortScanGenerator(args.target, args.start, args.end, threads=args.threads)
    open_ports = scanner.run()
    print(f"Open ports: {open_ports}")
