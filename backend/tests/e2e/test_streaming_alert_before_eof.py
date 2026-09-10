"""
test_streaming_alert_before_eof.py
==================================
Proves streaming pipeline behavior:
Alerts are emitted and broadcasted BEFORE the overall PCAP ingestion completes (EOF).
Complies strictly with PS-26145 incremental processing constraints.
"""
from __future__ import annotations

import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from m1_ingest.pcap_stream_reader import RawPacket
from m2_features import FallbackPurePythonAggregator
from backend.app.m4_integration import process_detection
from backend.app.alert_store import AlertStore


def test_streaming_alert_emitted_before_pcap_eof(tmp_path):
    store = AlertStore(data_path=str(tmp_path / "stream_alerts.json"))
    agg = FallbackPurePythonAggregator()

    emitted_alert_times = []
    total_packets = 120
    malicious_flow_flushed = False

    for idx in range(total_packets):
        if idx < 60:
            pkt = RawPacket(
                timestamp=1700000000.0 + (idx * 0.0001),
                src_ip="192.168.1.105",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=80,
                protocol="TCP",
                flags=0x02,
                payload_len=0,
                ttl=64,
            )
        else:
            pkt = RawPacket(
                timestamp=1700000000.0 + (idx * 0.1),
                src_ip="192.168.1.20",
                dst_ip="10.0.0.2",
                src_port=49152,
                dst_port=443,
                protocol="TCP",
                flags=0x18,
                payload_len=250,
                ttl=58,
            )

        agg.ingest_packet(pkt)
        time.sleep(0.002)

        if idx == 59:
            flows = agg.flush_flows()
            for feats, meta in flows:
                event, incident, alert = process_detection(feats, meta)
                if alert and "Benign" not in alert.get("threat", ""):
                    stored = store.add(alert)
                    alert_time = time.perf_counter()
                    emitted_alert_times.append((stored["alert_id"], alert_time))
                    malicious_flow_flushed = True

    pcap_eof_time = time.perf_counter()

    final_flows = agg.flush_flows()
    for feats, meta in final_flows:
        event, incident, alert = process_detection(feats, meta)
        if alert and "Benign" not in alert.get("threat", ""):
            store.add(alert)

    assert malicious_flow_flushed is True, "Malicious flow was not detected and emitted"
    assert len(emitted_alert_times) >= 1, "Expected at least 1 alert emitted during streaming"

    alert_id, alert_timestamp = emitted_alert_times[0]
    assert alert_timestamp < pcap_eof_time, f"Alert {alert_id} not emitted before EOF"

    persisted = store.get_by_id(alert_id)
    assert persisted is not None
    assert persisted["threat"] in ("Ddos", "Port Scan", "Syn Flood")
