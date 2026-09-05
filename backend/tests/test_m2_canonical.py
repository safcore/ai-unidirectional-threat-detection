"""Tests for M2 Canonical Adapter and Fallback Engine."""
import pytest
import json
from pathlib import Path

from m2_features import (
    adapt_to_canonical_66,
    get_canonical_feature_names,
    FallbackPurePythonAggregator,
    extract_features,
    is_nfstream_available,
)
from m1_ingest import RawPacket
import app.m2_adapter as m2_adapter


def test_canonical_feature_names_count():
    names = get_canonical_feature_names()
    assert len(names) == 66
    assert "Destination Port" in names
    assert "Flow Duration" in names
    assert "SYN Flag Count" in names


def test_adapt_raw_flow_to_66_features():
    raw_flow = {
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "Flow Duration": 500000.0,
        "Total Fwd Packets": 10.0,
        "SYN Flag Count": 10.0,
    }
    features, metadata = adapt_to_canonical_66(raw_flow)
    assert len(features) == 66
    assert features["Destination Port"] == 80.0
    assert features["Flow Duration"] == 500000.0
    assert features["Total Fwd Packets"] == 10.0
    assert features["SYN Flag Count"] == 10.0
    assert metadata["src_ip"] == "192.168.1.10"
    assert metadata["dst_ip"] == "10.0.0.5"


def test_m2_output_satisfies_backend_m2_adapter():
    raw_flow = {
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "Total Fwd Packets": 5.0,
    }
    features, metadata = adapt_to_canonical_66(raw_flow)
    # Validate with Anika's backend m2_adapter
    norm_features, norm_metadata = m2_adapter.normalize_m2_output({
        "features": features,
        "metadata": metadata,
    })
    assert len(norm_features) == 66
    assert norm_metadata["src_ip"] == "192.168.1.10"


def test_fallback_pure_python_aggregator():
    agg = FallbackPurePythonAggregator(flow_timeout_sec=5.0)
    pkt1 = RawPacket(
        timestamp=1000.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        flags=2,  # SYN
        payload_len=0,
        ttl=64,
    )
    pkt2 = RawPacket(
        timestamp=1001.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        flags=16,  # ACK
        payload_len=100,
        ttl=64,
    )
    agg.ingest_packet(pkt1)
    agg.ingest_packet(pkt2)

    flows = agg.flush_flows()
    assert len(flows) == 1
    features, metadata = flows[0]
    assert len(features) == 66
    assert features["Total Fwd Packets"] == 2.0
    assert features["SYN Flag Count"] == 1.0
    assert features["ACK Flag Count"] == 1.0
    assert metadata["src_ip"] == "10.0.0.1"
    assert metadata["dst_ip"] == "10.0.0.2"
    assert metadata["dst_port"] == 80
    assert metadata["mode"] == "fallback_pure_python"


def test_extract_features_with_fallback():
    pkt = RawPacket(
        timestamp=1000.0,
        src_ip="172.16.0.5",
        dst_ip="8.8.8.8",
        src_port=5353,
        dst_port=53,
        protocol="UDP",
        flags=0,
        payload_len=60,
        ttl=128,
    )
    features, metadata = extract_features([pkt])
    assert len(features) == 66
    assert metadata["dst_ip"] == "8.8.8.8"
    assert metadata["dst_port"] == 53
