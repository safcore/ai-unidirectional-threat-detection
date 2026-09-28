"""
Module 2 (M2) — Packet Adapter & Micro-PCAP Serializer
======================================================
Bridges M1's in-memory RawPacket stream with NFStream's C-engine.
Serializes batches of RawPackets into transient temporary libpcap 2.4 capture files
for NFStream C-engine dissection. Files are strictly ephemeral and cleaned up immediately
after feature extraction.
"""

import struct
import socket
import tempfile
import os
import time
import logging
from typing import List, Any, Optional, BinaryIO

logger = logging.getLogger("m2.packet_adapter")

# Standard libpcap 2.4 global header: 24 bytes, little-endian, linktype 1 (Ethernet)
PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,   # magic number (microseconds)
    2,            # major version
    4,            # minor version
    0,            # thiszone (GMT offset)
    0,            # sigfigs
    65535,        # snaplen
    1,            # network link type (1 = DLT_EN10MB / Ethernet)
)

DUMMY_ETH_SRC = b"\xaa\xbb\xcc\xdd\xee\xff"
DUMMY_ETH_DST = b"\x11\x22\x33\x44\x55\x66"
ETH_TYPE_IPV4 = b"\x08\x00"
ETH_HEADER_IPV4 = DUMMY_ETH_DST + DUMMY_ETH_SRC + ETH_TYPE_IPV4

PROTO_NUMBERS = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "DNS": 17,
    "HOPOPT": 0,
    "ICMPV6": 58,
}


def _ip_to_bytes(ip_str: str) -> bytes:
    """Convert IPv4 string to 4 bytes. Falls back to 0.0.0.0 on malformed input."""
    try:
        return socket.inet_aton(ip_str)
    except Exception:
        return b"\x00\x00\x00\x00"


def raw_packet_to_ethernet_frame(pkt: Any) -> bytes:
    """
    Converts an M1 RawPacket into a complete wire-format Ethernet frame.
    Prioritizes genuine captured wire bytes (raw_frame/raw). Falls back to
    synthesizing minimal headers only when wire bytes are unavailable.
    """
    raw_data = (
        getattr(pkt, "raw_frame", None)
        or getattr(pkt, "raw", None)
        or getattr(pkt, "raw_payload", None)
        or b""
    )

    # Case 1: Raw data is already a complete Ethernet frame (>=14B with IPv4/IPv6)
    if len(raw_data) >= 14 and raw_data[12:14] in (b"\x08\x00", b"\x86\xdd"):
        return raw_data

    # Case 2: Raw data is an IP packet (IPv4 header version nibble == 4, >=20B)
    if len(raw_data) >= 20 and (raw_data[0] >> 4) == 4:
        return ETH_HEADER_IPV4 + raw_data

    # Case 3: Need to synthesize Ethernet + IP + L4 header from packet fields
    src_ip = getattr(pkt, "src_ip", "10.0.0.1")
    dst_ip = getattr(pkt, "dst_ip", "10.0.0.2")
    src_port = int(getattr(pkt, "src_port", 0) or 0)
    dst_port = int(getattr(pkt, "dst_port", 0) or 0)
    protocol_raw = getattr(pkt, "protocol", "TCP")
    flags = int(getattr(pkt, "flags", 0) or 0)
    ttl = int(getattr(pkt, "ttl", 64) or 64)

    # Determine protocol number
    if isinstance(protocol_raw, int):
        proto_num = protocol_raw
    else:
        proto_num = PROTO_NUMBERS.get(str(protocol_raw).upper(), 6)

    payload = raw_data if isinstance(raw_data, bytes) else b""

    # Build L4 header
    if proto_num == 6:  # TCP
        l4_hdr = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            1000,       # sequence number
            0,          # ack number
            0x50,       # data offset = 5 (20 bytes)
            flags,      # TCP control flags
            8192,       # window size
            0,          # checksum (0 is accepted by pcap parsers)
            0,          # urgent pointer
        )
    elif proto_num == 17:  # UDP
        udp_len = 8 + len(payload)
        l4_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    elif proto_num == 1:  # ICMP
        l4_hdr = struct.pack("!BBHI", 8, 0, 0, 0)  # Echo request
    else:
        l4_hdr = b""

    ip_total_len = 20 + len(l4_hdr) + len(payload)
    src_bytes = _ip_to_bytes(src_ip)
    dst_bytes = _ip_to_bytes(dst_ip)

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,           # Version 4, IHL 5 (20 bytes)
        0x00,           # Type of service
        ip_total_len,   # Total length
        1234,           # Identification
        0x0000,         # Flags + Fragment offset
        ttl,            # Time to live
        proto_num,      # Protocol (TCP/UDP/ICMP)
        0,              # Header checksum
        src_bytes,
        dst_bytes,
    )

    return ETH_HEADER_IPV4 + ip_hdr + l4_hdr + payload


def write_packets_to_pcap_file(packets: List[Any], file_obj: BinaryIO) -> int:
    """
    Writes a list of packets into an open binary file in libpcap format.
    Returns the number of packets written.
    """
    file_obj.write(PCAP_GLOBAL_HEADER)
    count = 0
    now = time.time()

    for pkt in packets:
        try:
            ts = float(getattr(pkt, "timestamp", now) or now)
            frame = raw_packet_to_ethernet_frame(pkt)
            frame_len = len(frame)

            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            if ts_usec < 0:
                ts_usec = 0

            # Packet header: ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, frame_len, frame_len)
            file_obj.write(pkt_hdr)
            file_obj.write(frame)
            count += 1
        except Exception as e:
            logger.warning("Skipping unparseable packet in window: %s", e)
            continue

    file_obj.flush()
    return count


def packets_to_temp_pcap(packets: List[Any], prefix: str = "m2_window_") -> str:
    """
    Writes packets to a temporary .pcap file on disk and returns the filepath.
    The caller is responsible for removing the file after NFStream processing.
    """
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix=prefix)
    with os.fdopen(fd, "wb") as f:
        write_packets_to_pcap_file(packets, f)
    return path
