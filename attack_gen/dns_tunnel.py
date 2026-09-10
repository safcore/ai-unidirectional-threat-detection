"""
DNS Tunnel Traffic Generator for simulating high-entropy DNS exfiltration.

TEST-ONLY MODULE / SIMULATION HARNESS:
This generator is strictly for offline testing, dataset generation, and pipeline
benchmarking in controlled lab environments. It is never active in production ingress.
"""
from __future__ import annotations

import logging
import random
import socket
import struct
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


def _encode_dns_name(domain: str) -> bytes:
    result = b""
    for label in domain.split("."):
        result += bytes([len(label)]) + label.encode()
    return result + b"\x00"


def _build_dns_query(domain: str, qtype: int = 16) -> bytes:
    txid = random.randint(0, 65535)
    flags = 0x0100
    qdcount = 1
    header = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)
    qname = _encode_dns_name(domain)
    qclass = 1
    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question


def _make_dga_label(length: int = 40) -> str:
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choices(chars, k=length))


class DnsTunnelGenerator:
    """
    Sends high-entropy DNS queries or simulates them safely.
    """

    def __init__(
        self,
        nameserver: str = "8.8.8.8",
        base_domain: str = "tunnel.example.com",
        rate_qps: int = 5,
        duration_sec: float = 10.0,
        label_len: int = 50,
        qtype: int = 16,
        force_simulation: bool = False,
        stop_event: Optional[threading.Event] = None,
    ):
        self.ns = nameserver
        self.domain = base_domain
        self.rate = rate_qps
        self.duration = duration_sec
        self.label_len = label_len
        self.qtype = qtype
        self.force_simulation = force_simulation
        self.stop_event = stop_event or threading.Event()
        self.sent = 0

    def run(self) -> int:
        interval = 1.0 / self.rate if self.rate > 0 else 0.1
        end_time = time.time() + self.duration
        sock = None
        if not self.force_simulation:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
            except Exception:
                sock = None

        logger.info(
            "DNS Tunnel started: target=%s domain=%s rate=%d qps sim=%s",
            self.ns, self.domain, self.rate, self.force_simulation or (sock is None),
        )

        try:
            while time.time() < end_time and not self.stop_event.is_set():
                label = _make_dga_label(self.label_len)
                fqdn = f"{label}.{self.domain}"
                pkt = _build_dns_query(fqdn, qtype=self.qtype)

                if sock and not self.force_simulation:
                    try:
                        sock.sendto(pkt, (self.ns, 53))
                    except OSError:
                        pass
                self.sent += 1
                if interval > 0:
                    time.sleep(interval)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return self.sent
