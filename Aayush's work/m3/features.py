"""
Module 3 (M3) — Feature Extractor & Encoder
===========================================
Prepares feature matrices for ML training and streaming inference from M2 DataFrames.
- Strictly excludes raw network identifiers (IPs, ports, window IDs).
- One-hot encodes categorical 'Port Access Type' (SINGLE, SEQUENTIAL, RANDOM).
- Replaces NaNs / Infs with 0.0 and enforces float64 dtypes.
- Guarantees deterministic column order between training and inference.
"""

from typing import List
import numpy as np
import pandas as pd
import logging

logger = logging.getLogger("m3.features")

# Metadata / identifiers preserved for SOC alerting and evidence, but excluded from ML model
EXCLUDED_IDENTIFIERS = [
    "window_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol_name",
    "application_name",
    "application_category_name",
    "Port Access Type",  # One-hot encoded into separate binary features
    "threat_class",
    "label",
]

# Core numeric features from M2 82-column contract
BASE_NUMERIC_FEATURES: List[str] = [
    # Duration
    "Flow Duration",
    # Volume
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    # Packet length stats
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    # Rates
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    # IAT stats
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    # TCP Flags
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    # Cumulative TCP Flag Bitmask & Ratio
    "tcp_flag_bitmask",
    "Down/Up Ratio",
    # TTL Features
    "TTL Mean",
    "TTL Std",
    "TTL Variance",
    "TTL Min",
    "TTL Max",
    # TCP Window Features
    "TCP Window Size Init",
    "TCP Window Size Mean",
    # IP Fragment Flags
    "IP Flags DF Count",
    "IP Flags MF Count",
    # Retransmission
    "Retransmission Count",
    # Port Access Pattern numeric score
    "Port Sequentiality Score",
    # Protocol & Enriched Volume/Confidence
    "protocol",
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    "application_confidence",
]

# One-hot encoded Port Access Type categories
PORT_ACCESS_CATEGORIES: List[str] = ["SINGLE", "SEQUENTIAL", "RANDOM"]
ONE_HOT_PORT_ACCESS: List[str] = [f"port_access_{cat}" for cat in PORT_ACCESS_CATEGORIES]

# Canonical ML Feature List (76 features)
MODEL_FEATURE_NAMES: List[str] = BASE_NUMERIC_FEATURES + ONE_HOT_PORT_ACCESS


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transforms an M2 DataFrame into a sanitized, numeric feature matrix.
    
    1. Extracts base numeric features, supplying 0.0 for any missing columns.
    2. Performs one-hot encoding for 'Port Access Type' across ['SINGLE', 'SEQUENTIAL', 'RANDOM'].
    3. Handles NaN and infinite values cleanly.
    4. Enforces float64 dtype and exact canonical column order.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=MODEL_FEATURE_NAMES, dtype="float64")

    out = pd.DataFrame(index=df.index)

    # 1. Base numeric columns
    for col in BASE_NUMERIC_FEATURES:
        if col in df.columns:
            out[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
        else:
            out[col] = 0.0

    # 2. One-hot encoding of Port Access Type
    raw_pat = df["Port Access Type"].astype(str).str.upper().str.strip() if "Port Access Type" in df.columns else pd.Series("SINGLE", index=df.index)
    for cat in PORT_ACCESS_CATEGORIES:
        col_name = f"port_access_{cat}"
        out[col_name] = (raw_pat == cat).astype("float64")

    # 3. Handle inf / nan
    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    # 4. Strict deterministic column ordering & dtype
    out = out[MODEL_FEATURE_NAMES].astype("float64")
    return out
