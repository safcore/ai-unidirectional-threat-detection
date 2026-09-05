"""
m2_features/canonical_adapter.py
================================
Maps M2 82-column DataFrame or flow dictionary into the canonical 66-feature schema
strictly required by M3 (Krisha) and M4 (Aayushman) models.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pandas as pd
import numpy as np

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "ml" / "models" / "feature_schema.json"


def get_canonical_feature_names() -> List[str]:
    """Load canonical 66 feature names from the authoritative schema."""
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["ml_feature_names"]


def adapt_to_canonical_66(flow_record: Dict[str, Any]) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """
    Convert a flow dictionary (from NFStream 82-columns or Pure-Python Fallback)
    into:
      1. features: Dict[str, float] containing exactly the 66 canonical features
      2. metadata: Dict[str, Any] containing src_ip, dst_ip, src_port, dst_port, protocol
    """
    canonical_names = get_canonical_feature_names()

    # Extract metadata
    src_ip = str(flow_record.get("src_ip") or flow_record.get("Source IP") or "0.0.0.0")
    dst_ip = str(flow_record.get("dst_ip") or flow_record.get("Destination IP") or "0.0.0.0")
    src_port = int(flow_record.get("src_port") or flow_record.get("Source Port") or 0)
    dst_port = int(flow_record.get("dst_port") or flow_record.get("Destination Port") or 0)
    protocol = str(flow_record.get("protocol_name") or flow_record.get("protocol") or "TCP").upper()

    metadata = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "window_id": str(flow_record.get("window_id", "w_0")),
        "mode": flow_record.get("extractor_mode", "nfstream"),
    }

    # Map features
    fwd_pkts = float(flow_record.get("Total Fwd Packets", 0.0) or flow_record.get("src2dst_packets", 0.0) or flow_record.get("pkt_count", 0.0))
    bwd_pkts = float(flow_record.get("Total Backward Packets", 0.0) or flow_record.get("dst2src_packets", 0.0))
    fwd_bytes = float(flow_record.get("Total Length of Fwd Packets", 0.0) or flow_record.get("src2dst_bytes", 0.0) or flow_record.get("byte_count", 0.0))
    bwd_bytes = float(flow_record.get("Total Length of Bwd Packets", 0.0) or flow_record.get("dst2src_bytes", 0.0))

    duration = float(flow_record.get("Flow Duration", 0.0))
    if duration == 0.0 and "duration" in flow_record:
        duration = float(flow_record["duration"]) * 1_000_000.0  # seconds -> microseconds

    features: Dict[str, float] = {}

    for name in canonical_names:
        if name in flow_record and flow_record[name] is not None:
            val = flow_record[name]
            try:
                features[name] = float(val) if not np.isnan(float(val)) else 0.0
            except (ValueError, TypeError):
                features[name] = 0.0
            continue

        # Canonical aliases & derivations
        if name == "Destination Port":
            features[name] = float(dst_port)
        elif name == "Flow Duration":
            features[name] = duration
        elif name == "Total Fwd Packets":
            features[name] = fwd_pkts
        elif name == "Total Backward Packets":
            features[name] = bwd_pkts
        elif name == "Total Length of Fwd Packets":
            features[name] = fwd_bytes
        elif name == "Total Length of Bwd Packets":
            features[name] = bwd_bytes
        elif name in ("Subflow Fwd Packets",):
            features[name] = fwd_pkts
        elif name in ("Subflow Fwd Bytes",):
            features[name] = fwd_bytes
        elif name in ("Subflow Bwd Packets",):
            features[name] = bwd_pkts
        elif name in ("Subflow Bwd Bytes",):
            features[name] = bwd_bytes
        elif name in ("Fwd Header Length", "Fwd Header Length.1", "min_seg_size_forward"):
            features[name] = 32.0 if protocol == "TCP" else 20.0
        elif name == "Bwd Header Length":
            features[name] = 32.0 if protocol == "TCP" else 20.0
        elif name == "act_data_pkt_fwd":
            features[name] = fwd_pkts
        elif name in ("Init_Win_bytes_forward", "TCP Window Size Init"):
            features[name] = float(flow_record.get("TCP Window Size Init", 65535.0 if protocol == "TCP" else 0.0))
        elif name in ("Init_Win_bytes_backward",):
            features[name] = float(flow_record.get("TCP Window Size Mean", 65535.0 if protocol == "TCP" else 0.0))
        elif name.startswith("Active") or name.startswith("Idle"):
            features[name] = 0.0
        elif name == "Down/Up Ratio":
            features[name] = (bwd_pkts / fwd_pkts) if fwd_pkts > 0 else 0.0
        elif name == "Average Packet Size":
            total_pkts = fwd_pkts + bwd_pkts
            features[name] = ((fwd_bytes + bwd_bytes) / total_pkts) if total_pkts > 0 else 0.0
        elif name == "Avg Fwd Segment Size":
            features[name] = (fwd_bytes / fwd_pkts) if fwd_pkts > 0 else 0.0
        elif name == "Avg Bwd Segment Size":
            features[name] = (bwd_bytes / bwd_pkts) if bwd_pkts > 0 else 0.0
        elif name == "Flow Bytes/s":
            features[name] = ((fwd_bytes + bwd_bytes) / (duration / 1_000_000.0)) if duration > 0 else 0.0
        elif name == "Flow Packets/s":
            total_pkts = fwd_pkts + bwd_pkts
            features[name] = (total_pkts / (duration / 1_000_000.0)) if duration > 0 else 0.0
        elif name == "Fwd Packets/s":
            features[name] = (fwd_pkts / (duration / 1_000_000.0)) if duration > 0 else 0.0
        elif name == "Bwd Packets/s":
            features[name] = (bwd_pkts / (duration / 1_000_000.0)) if duration > 0 else 0.0
        else:
            # Default zero for missing statistical features
            features[name] = 0.0

    return features, metadata
