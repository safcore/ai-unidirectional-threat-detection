"""
tests/generators.py
====================

Synthetic FeatureRecord generators (PROMPT section 25). Not everything
is identical between calls -- a bit of controlled variation via `variant`
so tests exercise more than one exact input.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from threat_detection.feature_schema import FeatureRecord

_flow_ids = itertools.count(1)


def _next_flow_id() -> str:
    return f"flow-{next(_flow_ids):06d}"


def _ts(offset_seconds: float = 0.0) -> str:
    base = datetime(2026, 9, 2, 12, 30, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_normal(
    src_ip: str = "10.0.0.15",
    dst_ip: str = "10.0.0.20",
    dst_port: int = 443,
    variant: int = 0,
) -> FeatureRecord:
    """Ordinary, unremarkable client traffic."""
    packet_count = 40 + variant * 3
    duration = 1.5 + variant * 0.1
    return FeatureRecord(
        flow_id=_next_flow_id(),
        timestamp=_ts(variant),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=40000 + variant,
        dst_port=dst_port,
        protocol="TCP",
        packet_count=packet_count,
        byte_count=packet_count * 800,
        flow_duration=duration,
        packet_rate=packet_count / duration,
        byte_rate=(packet_count * 800) / duration,
        syn_count=1,
        ack_count=packet_count - 2,
        rst_count=0,
        fin_count=1,
    )


def generate_ddos(
    packet_rate: float = 10000,
    syn_rate: float = 7000,
    duration: float = 2.0,
    src_ip: str = "203.0.113.5",
    dst_ip: str = "10.0.0.20",
    variant: int = 0,
) -> FeatureRecord:
    """High-volume, SYN-heavy short flow -- classic volumetric shape."""
    packet_count = int(packet_rate * duration)
    syn_count = int(syn_rate * duration)
    byte_rate = packet_rate * (1400 + variant * 10)
    return FeatureRecord(
        flow_id=_next_flow_id(),
        timestamp=_ts(variant),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=4000 + variant,
        dst_port=80,
        protocol="TCP",
        packet_count=packet_count,
        byte_count=int(byte_rate * duration),
        flow_duration=duration,
        packet_rate=packet_rate,
        byte_rate=byte_rate,
        syn_count=syn_count,
        ack_count=max(1, int(syn_count * 0.01)),
        rst_count=int(syn_count * 0.02),
        fin_count=0,
    )


def generate_port_scan_events(
    src_ip: str = "10.0.0.50",
    dst_ip: str = "10.0.0.99",
    num_ports: int = 40,
    start_port: int = 20,
    window_seconds: float = 4.0,
):
    """
    Yields a sequence of FeatureRecords representing one source IP probing
    many destination ports on the same destination IP in a short window --
    used to exercise the STATEFUL PortScanDetector across multiple calls.
    """
    for i in range(num_ports):
        offset = (window_seconds / max(num_ports, 1)) * i
        yield FeatureRecord(
            flow_id=_next_flow_id(),
            timestamp=_ts(offset),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000 + i,
            dst_port=start_port + i,
            protocol="TCP",
            packet_count=2,
            byte_count=120,
            flow_duration=0.05,
            packet_rate=40.0,
            byte_rate=2400.0,
            syn_count=1,
            ack_count=0,
            rst_count=1,
            fin_count=0,
        )
