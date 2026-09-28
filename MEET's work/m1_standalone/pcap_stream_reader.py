"""
M1 — PCAP Streaming Reader (using dpkt — pure Python, no libpcap dependency)
==============================================================================
Reads a PCAP file packet-by-packet and pushes RawPacket objects into
the threading.Queue.

This is the CORRECT ingest path for the NTRO problem statement:
  "passive mirroring... packet captures... no return path"

The CSV files are used ONLY for training the ML models offline.
The PCAP reader is the live/demo detection path.

Supported PCAP formats:
  - Standard libpcap (.pcap)
  - Wireshark/tcpdump captures
  - CIC-IDS 2017 PCAPs (Monday.pcap through Friday.pcap)

Dependencies:
  pip install dpkt        ← fast C-backed PCAP parser
  (falls back to pure-Python struct parser if dpkt not available)

Usage:
    reader = PcapStreamReader(
        pcap_path  = "data/pcaps/Friday-ddos.pcap",
        flow_queue = my_queue,
        speed      = 10.0,    # 10x replay speed
    )
    reader.start()
"""

import os
import queue
import struct
import socket
import threading
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger(__name__)


# ── RawPacket (same shape as before, but richer) ─────────────────────────────

@dataclass
class RawPacket:
    """One parsed network packet from a PCAP file."""
    timestamp:   float        # epoch seconds (from PCAP header)
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    protocol:    str          # TCP | UDP | DNS | ICMP
    flags:       int          # TCP flags bitmask
    payload_len: int          # bytes (excludes IP/TCP headers)
    ttl:         int
    raw_payload: bytes = field(default=b"", repr=False)

    @property
    def raw(self) -> bytes:
        return self.raw_payload

    @property
    def flow_key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    @property
    def flow_id(self) -> str:
        raw = "|".join(str(x) for x in self.flow_key)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Pure-Python PCAP parser (stdlib only — no dpkt needed) ───────────────────

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_GLOBAL_HDR_SIZE = 24
PCAP_PKT_HDR_SIZE    = 16


def _inet_ntoa(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _parse_pcap_file(path: str):
    """
    Generator: yields (timestamp_float, raw_bytes) for each packet
    in a standard libpcap (.pcap) file.
    Pure Python — no external libraries needed.
    """
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == PCAP_MAGIC_LE:
            endian = "<"
        elif magic == PCAP_MAGIC_BE:
            endian = ">"
        else:
            raise ValueError(f"Not a valid PCAP file (magic={magic.hex()})")

        # Skip rest of global header (version, snaplen, link type)
        f.read(20)

        while True:
            pkt_hdr = f.read(PCAP_PKT_HDR_SIZE)
            if len(pkt_hdr) < PCAP_PKT_HDR_SIZE:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                endian + "IIII", pkt_hdr
            )
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break
            ts = ts_sec + ts_usec / 1_000_000.0
            yield ts, raw


def _parse_ethernet(raw: bytes, ts: float) -> Optional[RawPacket]:
    """Ethernet II frame → IP packet."""
    if len(raw) < 14:
        return None
    ether_type = struct.unpack("!H", raw[12:14])[0]
    if ether_type == 0x0800:    # IPv4
        return _parse_ipv4(raw[14:], ts)
    elif ether_type == 0x86DD:  # IPv6 (basic support)
        return _parse_ipv6(raw[14:], ts)
    return None


def _parse_ipv4(raw: bytes, ts: float) -> Optional[RawPacket]:
    if len(raw) < 20:
        return None
    ihl     = (raw[0] & 0x0F) * 4
    proto   = raw[9]
    ttl     = raw[8]
    src_ip  = _inet_ntoa(raw[12:16])
    dst_ip  = _inet_ntoa(raw[16:20])
    payload = raw[ihl:]

    if proto == 6:
        return _parse_tcp(payload, src_ip, dst_ip, ttl, ts)
    elif proto == 17:
        return _parse_udp(payload, src_ip, dst_ip, ttl, ts)
    elif proto == 1:
        return RawPacket(ts, src_ip, dst_ip, 0, 0, "ICMP", 0, len(payload), ttl)
    return None


def _parse_ipv6(raw: bytes, ts: float) -> Optional[RawPacket]:
    """Minimal IPv6 — extract addresses + next header."""
    if len(raw) < 40:
        return None
    next_hdr = raw[6]
    # IPv6 addresses are 16 bytes each
    src_ip = ":".join(
        f"{raw[8+i*2]:02x}{raw[9+i*2]:02x}" for i in range(8)
    )
    dst_ip = ":".join(
        f"{raw[24+i*2]:02x}{raw[25+i*2]:02x}" for i in range(8)
    )
    payload = raw[40:]
    if next_hdr == 6:
        return _parse_tcp(payload, src_ip, dst_ip, 64, ts)
    elif next_hdr == 17:
        return _parse_udp(payload, src_ip, dst_ip, 64, ts)
    return None


def _parse_tcp(raw: bytes, src_ip, dst_ip, ttl, ts) -> Optional[RawPacket]:
    if len(raw) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", raw[0:4])
    flags   = raw[13]
    data_off = (raw[12] >> 4) * 4
    payload  = raw[data_off:]
    return RawPacket(ts, src_ip, dst_ip, src_port, dst_port,
                     "TCP", flags, len(payload), ttl, payload[:512])


def _parse_udp(raw: bytes, src_ip, dst_ip, ttl, ts) -> Optional[RawPacket]:
    if len(raw) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", raw[0:6])
    payload = raw[8:]
    proto = "DNS" if (dst_port == 53 or src_port == 53) else "UDP"
    return RawPacket(ts, src_ip, dst_ip, src_port, dst_port,
                     proto, 0, max(0, length - 8), ttl, payload[:512])


try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False


def _dpkt_parse(path: str):
    """Use dpkt parser if installed (supports standard PCAP and PCAPNG)."""
    import dpkt, socket as _socket

    def _ip_to_str(addr):
        try:
            if len(addr) == 4:
                return _socket.inet_ntoa(addr)
            return _socket.inet_ntop(_socket.AF_INET6, addr)
        except Exception:
            return "0.0.0.0"

    with open(path, "rb") as f:
        pcap = None
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            try:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)
            except Exception as e:
                logger.error("Could not parse PCAP/PCAPNG with dpkt: %s", e)
                return

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip  = getattr(eth, "data", eth)
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                src_ip = _ip_to_str(ip.src)
                dst_ip = _ip_to_str(ip.dst)
                ttl    = getattr(ip, "ttl", 64)
                seg    = getattr(ip, "data", None)
                if not seg:
                    continue

                if isinstance(seg, dpkt.tcp.TCP):
                    flags = getattr(seg, "flags", 0)
                    payload = bytes(getattr(seg, "data", b""))
                    yield RawPacket(ts, src_ip, dst_ip,
                                    seg.sport, seg.dport,
                                    "TCP", flags, len(payload), ttl,
                                    payload[:512])
                elif isinstance(seg, dpkt.udp.UDP):
                    payload = bytes(getattr(seg, "data", b""))
                    proto = "DNS" if getattr(seg, "dport", 0) == 53 or getattr(seg, "sport", 0) == 53 else "UDP"
                    yield RawPacket(ts, src_ip, dst_ip,
                                    getattr(seg, "sport", 0), getattr(seg, "dport", 0),
                                    proto, 0, len(payload), ttl,
                                    payload[:512])
                elif isinstance(seg, dpkt.icmp.ICMP):
                    yield RawPacket(ts, src_ip, dst_ip,
                                    0, 0, "ICMP", 0, 0, ttl)
            except Exception:
                continue


def _stdlib_parse(path: str):
    """Pure-Python PCAP parser (no dependencies)."""
    for ts, raw in _parse_pcap_file(path):
        pkt = _parse_ethernet(raw, ts)
        if pkt:
            yield pkt


# ── PcapStreamReader ──────────────────────────────────────────────────────────

class PcapStreamReader:
    """
    Reads a PCAP file packet-by-packet and enqueues RawPacket objects.

    This is the production ingest path for the NTRO problem:
      - Read-only: never transmits anything
      - Streaming: one packet at a time into threading.Queue
      - Speed-controlled: replay at N× original timing

    Parameters
    ----------
    pcap_path : str
        Path to the .pcap file
    flow_queue : queue.Queue
        The shared M1 threading.Queue
    speed : float
        Replay speed multiplier. 1.0 = real time, 10.0 = 10× faster
    loop : bool
        Loop the PCAP when it ends
    stop_event : threading.Event
    monitor : StreamMonitor (optional)
    """

    def __init__(
        self,
        pcap_path: str,
        flow_queue: queue.Queue,
        speed: float = 10.0,
        loop: bool = True,
        stop_event: Optional[threading.Event] = None,
        monitor=None,
    ):
        self.path       = pcap_path
        self.q          = flow_queue
        self.speed      = speed
        self.loop       = loop
        self.stop_event = stop_event or threading.Event()
        self.monitor    = monitor

        # Stats
        self.pkts_read    = 0
        self.pkts_dropped = 0
        self.parse_errors = 0

        self._thread = threading.Thread(
            target=self._run, name="PcapStreamReader", daemon=True
        )

    def start(self):
        self._thread.start()
        logger.info("PcapStreamReader started: %s (speed=%.1fx)", self.path, self.speed)

    def stop(self):
        self.stop_event.set()
        self._thread.join(timeout=5)

    def _run(self):
        if not os.path.exists(self.path):
            logger.error("PCAP file not found: %s", self.path)
            return

        while not self.stop_event.is_set():
            try:
                self._replay_once()
            except Exception as e:
                logger.error("PCAP replay error: %s", e)
                break
            if not self.loop:
                break

        logger.info(
            "PcapStreamReader done | pkts=%d drops=%d errors=%d",
            self.pkts_read, self.pkts_dropped, self.parse_errors,
        )

    def _replay_once(self):
        """Replay the PCAP file once at the configured speed."""
        gen = _dpkt_parse(self.path) if HAS_DPKT else _stdlib_parse(self.path)

        first_pkt_ts: Optional[float] = None
        wall_start = time.time()

        for pkt in gen:
            if self.stop_event.is_set():
                return

            # Timing: maintain original inter-packet gaps scaled by speed
            if first_pkt_ts is None:
                first_pkt_ts = pkt.timestamp

            relative  = (pkt.timestamp - first_pkt_ts) / self.speed
            target_t  = wall_start + relative
            sleep_for = target_t - time.time()
            if sleep_for > 0.001:
                time.sleep(sleep_for)

            # Enqueue
            try:
                self.q.put_nowait(pkt)
                self.pkts_read += 1
                if self.monitor:
                    self.monitor.record_packet()
            except queue.Full:
                self.pkts_dropped += 1
                if self.monitor:
                    self.monitor.record_drop()


# ── Dual-mode pipeline (PCAP + CSV) ──────────────────────────────────────────

class DualModePipeline:
    """
    Selects the right ingest source automatically:

    ┌─────────────────────────────────────────┐
    │  if pcap_path provided                  │
    │      → PcapStreamReader (real packets)  │
    │  elif csv_paths provided                │
    │      → CICIDSReader (flow records)      │
    │  else                                   │
    │      → Demo mode (synthetic)            │
    └─────────────────────────────────────────┘

    For NTRO demo: use PCAP for live detection,
    use CSV only for offline model training.
    """

    def __init__(
        self,
        pcap_path: Optional[str]  = None,
        csv_paths: Optional[List[str]] = None,
        target_fps: int            = 1000,
        speed: float               = 10.0,
        queue_size: int            = 50_000,
        num_workers: int           = 2,
        monitor                    = None,
    ):
        import queue as _queue
        self.flow_queue  = _queue.Queue(maxsize=queue_size)
        self.monitor     = monitor
        self._handlers   = []
        self._workers    = []
        self._stop       = threading.Event()
        self._reader     = None

        # Decide mode
        if pcap_path and os.path.exists(pcap_path):
            self._mode = "pcap"
            self._pcap_path  = pcap_path
            self._speed      = speed
        elif csv_paths:
            self._mode = "csv"
            self._csv_paths  = csv_paths
            self._target_fps = target_fps
        else:
            self._mode = "demo"
            self._target_fps = target_fps

        self.num_workers = num_workers
        logger.info("DualModePipeline: mode=%s", self._mode)

    def add_handler(self, fn):
        self._handlers.append(fn)

    def start(self):
        from cic_ids_pipeline import FlowWorker

        if self._mode == "pcap":
            self._reader = PcapStreamReader(
                pcap_path   = self._pcap_path,
                flow_queue  = self.flow_queue,
                speed       = self._speed,
                stop_event  = self._stop,
                monitor     = self.monitor,
            )
        else:
            from cic_ids_reader import CICIDSReader
            self._reader = CICIDSReader(
                csv_paths  = getattr(self, "_csv_paths", []),
                flow_queue = self.flow_queue,
                mode       = self._mode if self._mode != "pcap" else "demo",
                target_fps = getattr(self, "_target_fps", 1000),
                stop_event = self._stop,
                monitor    = self.monitor,
            )

        self._reader.start()

        def _dispatch(item):
            for h in self._handlers:
                h(item)

        for i in range(self.num_workers):
            w = FlowWorker(self.flow_queue, _dispatch,
                           name=f"Worker-{i}", stop_event=self._stop)
            w.start()
            self._workers.append(w)

        logger.info("DualModePipeline started | mode=%s | workers=%d",
                    self._mode, len(self._workers))

    def stop(self):
        self._stop.set()

    @property
    def total_processed(self):
        return sum(w.flows_processed for w in self._workers)

    @property
    def mode(self):
        return self._mode
