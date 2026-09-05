"""
M1 — PCAP Replay & Synthetic Traffic Generator
================================================
Reads a real PCAP file (or generates synthetic packets) and pushes them
into the shared threading.Queue at a configurable rate.

This module is the ONLY data source — it emulates a hardware data-diode:
  • No packets are ever transmitted back.
  • No handshakes are initiated.
  • No probes are sent.
"""

import threading
import time
import random
import struct
import socket
import queue
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)


# ── Packet data container ────────────────────────────────────────────────────
from .pcap_stream_reader import RawPacket


# ── PCAP parser (pure-Python, no libpcap required for demo) ─────────────────

PCAP_GLOBAL_HEADER = 24
PCAP_PKT_HEADER = 16

def _parse_pcap(path: str):
    """
    PCAP / PCAPNG parser. Uses dpkt when available (supports .pcap and .pcapng).
    Falls back to stdlib parser for standard libpcap files.
    """
    from .pcap_stream_reader import _dpkt_parse, HAS_DPKT, _stdlib_parse
    if HAS_DPKT:
        yield from _dpkt_parse(path)
    else:
        yield from _stdlib_parse(path)


def _parse_ethernet(raw: bytes, ts: float) -> Optional[RawPacket]:
    """Parse Ethernet frame → IP → TCP/UDP."""
    if len(raw) < 14:
        return None
    ether_type = struct.unpack("!H", raw[12:14])[0]
    if ether_type != 0x0800:  # only IPv4
        return None
    return _parse_ip(raw[14:], ts)


def _parse_ip(raw: bytes, ts: float) -> Optional[RawPacket]:
    if len(raw) < 20:
        return None
    ver_ihl = raw[0]
    ihl = (ver_ihl & 0x0F) * 4
    proto = raw[9]
    ttl = raw[8]
    src_ip = socket.inet_ntoa(raw[12:16])
    dst_ip = socket.inet_ntoa(raw[16:20])
    payload = raw[ihl:]

    if proto == 6:    # TCP
        return _parse_tcp(payload, src_ip, dst_ip, ttl, ts)
    elif proto == 17: # UDP
        return _parse_udp(payload, src_ip, dst_ip, ttl, ts)
    elif proto == 1:  # ICMP
        return RawPacket(ts, src_ip, dst_ip, 0, 0, "ICMP", 0, len(payload), ttl)
    return None


def _parse_tcp(raw: bytes, src_ip, dst_ip, ttl, ts) -> Optional[RawPacket]:
    if len(raw) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", raw[0:4])
    flags = raw[13]
    data_off = (raw[12] >> 4) * 4
    payload_len = max(0, len(raw) - data_off)
    return RawPacket(ts, src_ip, dst_ip, src_port, dst_port, "TCP", flags, payload_len, ttl)


def _parse_udp(raw: bytes, src_ip, dst_ip, ttl, ts) -> Optional[RawPacket]:
    if len(raw) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", raw[0:6])
    proto = "DNS" if dst_port == 53 or src_port == 53 else "UDP"
    return RawPacket(ts, src_ip, dst_ip, src_port, dst_port, proto, 0, length - 8, ttl)


# ── Synthetic traffic generator ──────────────────────────────────────────────

def _random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _random_port(low=1024, high=65535):
    return random.randint(low, high)


ATTACK_SCENARIOS = [
    "benign", "syn_flood", "udp_flood", "port_scan",
    "dns_tunnel", "beacon", "dga", "exfil"
]


class SyntheticTrafficGenerator:
    """
    Generates realistic synthetic network traffic covering all 6 threat classes.
    Runs in a background thread and puts RawPacket objects into the shared queue.
    """

    def __init__(
        self,
        pkt_queue: queue.Queue,
        packets_per_sec: int = 5000,
        attack_mix: float = 0.3,   # fraction of traffic that is attack
        stop_event: threading.Event = None,
    ):
        self.q = pkt_queue
        self.pps = packets_per_sec
        self.attack_mix = attack_mix
        self.stop_event = stop_event or threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="SyntheticGen", daemon=True
        )

    def start(self):
        self._thread.start()
        logger.info("SyntheticTrafficGenerator started at %d pps", self.pps)

    def stop(self):
        self.stop_event.set()
        self._thread.join(timeout=3)

    def _run(self):
        interval = 1.0 / self.pps if self.pps > 0 else 0
        # Pre-generate a pool of "attacker" IPs to keep beacon source stable
        beacon_src = _random_ip()
        beacon_dst = _random_ip()
        beacon_next = time.time() + 30  # beacon every 30s

        while not self.stop_event.is_set():
            now = time.time()
            pkt = self._make_packet(now, beacon_src, beacon_dst, beacon_next)
            if pkt:
                if time.time() >= beacon_next - 30:
                    beacon_next = now + 30  # reschedule

                try:
                    self.q.put_nowait(pkt)
                except queue.Full:
                    pass  # drop if consumer is too slow

            if interval > 0:
                time.sleep(interval)

    def _make_packet(self, now, beacon_src, beacon_dst, beacon_next) -> Optional[RawPacket]:
        roll = random.random()

        if roll < 0.60:
            return self._benign(now)
        elif roll < 0.70:
            return self._syn_flood(now)
        elif roll < 0.78:
            return self._udp_flood(now)
        elif roll < 0.84:
            return self._port_scan(now)
        elif roll < 0.88:
            return self._dns_tunnel(now)
        elif roll < 0.92:
            return self._beacon(now, beacon_src, beacon_dst)
        elif roll < 0.96:
            return self._dga_query(now)
        else:
            return self._exfil(now)

    # ── Individual scenario generators ──────────────────────────────────────

    def _benign(self, ts) -> RawPacket:
        common_ports = [80, 443, 22, 25, 110, 143, 8080, 3306]
        return RawPacket(
            timestamp=ts,
            src_ip=_random_ip(), dst_ip=_random_ip(),
            src_port=_random_port(), dst_port=random.choice(common_ports),
            protocol="TCP", flags=0x02 | 0x10,  # SYN-ACK or ACK
            payload_len=random.randint(64, 1460),
            ttl=random.randint(48, 128),
        )

    def _syn_flood(self, ts) -> RawPacket:
        """SYN flood: many sources, single destination, SYN flag only, small payload."""
        victim = "192.168.100.1"
        return RawPacket(
            timestamp=ts,
            src_ip=_random_ip(),       # spoofed sources
            dst_ip=victim,
            src_port=_random_port(),
            dst_port=80,
            protocol="TCP",
            flags=0x02,                # SYN only
            payload_len=random.randint(0, 20),
            ttl=random.randint(32, 64),
        )

    def _udp_flood(self, ts) -> RawPacket:
        """UDP amplification: large responses from port 19/123/53."""
        amplifiers = [19, 53, 123, 1900]
        victim = "10.0.0.1"
        return RawPacket(
            timestamp=ts,
            src_ip=_random_ip(),
            dst_ip=victim,
            src_port=random.choice(amplifiers),
            dst_port=_random_port(),
            protocol="UDP",
            flags=0,
            payload_len=random.randint(512, 4096),  # amplified response
            ttl=random.randint(48, 120),
        )

    def _port_scan(self, ts) -> RawPacket:
        """Port scan: single source, sequential destination ports, SYN only."""
        scanner = "172.16.0.99"
        target = "10.0.0.50"
        return RawPacket(
            timestamp=ts,
            src_ip=scanner,
            dst_ip=target,
            src_port=_random_port(),
            dst_port=random.randint(1, 65535),
            protocol="TCP",
            flags=0x02,   # SYN
            payload_len=0,
            ttl=64,
        )

    def _dns_tunnel(self, ts) -> RawPacket:
        """DNS tunneling: long subdomain labels, TXT/NULL record types."""
        return RawPacket(
            timestamp=ts,
            src_ip=_random_ip(),
            dst_ip="8.8.8.8",
            src_port=_random_port(1024, 60000),
            dst_port=53,
            protocol="DNS",
            flags=0,
            payload_len=random.randint(200, 512),   # long DNS query = tunnel
            ttl=64,
            raw_payload=self._make_dns_tunnel_payload(),
        )

    def _beacon(self, ts, src, dst) -> RawPacket:
        """C2 beacon: fixed src/dst, regular interval, small payload."""
        return RawPacket(
            timestamp=ts,
            src_ip=src,
            dst_ip=dst,
            src_port=_random_port(49000, 65000),
            dst_port=443,
            protocol="TCP",
            flags=0x18,   # PSH+ACK
            payload_len=random.randint(64, 256),
            ttl=128,
        )

    def _dga_query(self, ts) -> RawPacket:
        """DGA domain query: high-entropy domain name in DNS."""
        return RawPacket(
            timestamp=ts,
            src_ip=_random_ip(),
            dst_ip="8.8.8.8",
            src_port=_random_port(),
            dst_port=53,
            protocol="DNS",
            flags=0,
            payload_len=random.randint(60, 120),
            ttl=64,
            raw_payload=self._make_dga_payload(),
        )

    def _exfil(self, ts) -> RawPacket:
        """Data exfiltration: large outbound payload, tiny inbound."""
        return RawPacket(
            timestamp=ts,
            src_ip="192.168.1.50",      # internal host exfiltrating
            dst_ip=_random_ip(),
            src_port=_random_port(),
            dst_port=443,
            protocol="TCP",
            flags=0x18,
            payload_len=random.randint(8000, 65000),  # huge outbound
            ttl=64,
        )

    # ── Payload helpers ──────────────────────────────────────────────────────

    def _make_dns_tunnel_payload(self) -> bytes:
        """Fake DNS query with long subdomain (simulates tunnel)."""
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        label = "".join(random.choices(chars, k=random.randint(40, 60)))
        domain = f"{label}.tunnel.example.com"
        encoded = domain.encode() + b"\x00" * 20
        return encoded

    def _make_dga_payload(self) -> bytes:
        """Fake DNS query with DGA-style domain (high entropy)."""
        chars = "abcdefghijklmnopqrstuvwxyz"
        domain_len = random.randint(12, 22)
        domain = "".join(random.choices(chars, k=domain_len)) + ".com"
        return domain.encode()


# ── PCAP Replay ───────────────────────────────────────────────────────────────

class PcapReplayer:
    """
    Replays packets from a PCAP file at a configurable speed multiplier.
    Preserves original packet timing when speed=1.0.
    """

    def __init__(
        self,
        pcap_path: str,
        pkt_queue: queue.Queue,
        speed: float = 1.0,
        loop: bool = True,
        stop_event: threading.Event = None,
    ):
        self.path = pcap_path
        self.q = pkt_queue
        self.speed = speed
        self.loop = loop
        self.stop_event = stop_event or threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="PcapReplayer", daemon=True
        )

    def start(self):
        self._thread.start()
        logger.info("PcapReplayer started: %s (speed=%.1fx)", self.path, self.speed)

    def stop(self):
        self.stop_event.set()
        self._thread.join(timeout=3)

    def _run(self):
        while not self.stop_event.is_set():
            prev_pkt_ts = None
            replay_start = time.time()
            first_pkt_ts = None

            try:
                for pkt in _parse_pcap(self.path):
                    if self.stop_event.is_set():
                        return

                    if first_pkt_ts is None:
                        first_pkt_ts = pkt.timestamp

                    # Compute when this packet should be emitted in wall-clock time
                    relative_ts = (pkt.timestamp - first_pkt_ts) / self.speed
                    target_wall = replay_start + relative_ts
                    sleep_for = target_wall - time.time()
                    if sleep_for > 0:
                        time.sleep(min(sleep_for, 0.01))

                    # Stamp with current wall time
                    pkt.timestamp = time.time()
                    try:
                        self.q.put_nowait(pkt)
                    except queue.Full:
                        pass

            except FileNotFoundError:
                logger.error("PCAP file not found: %s — falling back to synthetic", self.path)
                break
            except Exception as e:
                logger.error("PCAP parse error: %s", e)
                break

            if not self.loop:
                break

        logger.info("PcapReplayer finished")
