"""Tests for M1 Ingestion Layer."""
import pytest
from m1_ingest import RawPacket, SyntheticTrafficGenerator, IngestPipeline, StreamMonitor
import queue
import time


def test_synthetic_traffic_generation():
    q = queue.Queue(maxsize=100)
    gen = SyntheticTrafficGenerator(pkt_queue=q, packets_per_sec=500, attack_mix=0.5)
    now = time.time()
    pkt = gen._make_packet(now, "10.0.0.1", "10.0.0.2", now + 30)
    assert isinstance(pkt, RawPacket)
    assert pkt.src_ip
    assert pkt.dst_ip
    assert pkt.protocol in ("TCP", "UDP", "DNS")


def test_stream_monitor():
    mon = StreamMonitor(interval_sec=0.1, print_stats=False)
    mon.record_packet(10)
    mon.record_flow(5)
    assert mon._pkt_count == 10
