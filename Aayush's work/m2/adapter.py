"""
Module 2 (M2) — Feature Adapter
===============================
Transforms raw NFStream flow statistics into the standardized CIC-IDS 2017 / Project
feature schema. Enforces deterministic column ordering, type casting, safe derivations,
and robust handling of NaN/infinite values. Integrates deep packet-level metrics
(TTL variance, TCP window, retransmissions, port access patterns).
"""

import pandas as pd
import numpy as np
import logging
from typing import Optional, Dict, Tuple, Any

from .schema import (
    DIRECT_FEATURE_MAP,
    DETERMINISTIC_COLUMN_ORDER,
    SCHEMA_DTYPES,
)

logger = logging.getLogger("m2.adapter")

PROTO_NUM_TO_NAME = {
    0: "HOPOPT",
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def _col_or_zero(df: pd.DataFrame, col: str, scale: float = 1.0) -> pd.Series:
    """Helper to safely extract a column multiplied by scale, or a zero Series if missing."""
    if col in df.columns:
        return df[col].astype(float) * scale
    return pd.Series(0.0, index=df.index, dtype="float64")


class FeatureAdapter:
    """
    Adapts raw NFStream DataFrames to standard project schema with CIC-IDS 2017 names.
    Merges window packet analysis metrics (TTL, TCP window, retransmissions, port scans).
    """

    def __init__(self, replace_inf_nan: bool = True):
        self.replace_inf_nan = replace_inf_nan

    def adapt(
        self,
        raw_df: pd.DataFrame,
        window_id: str = "w_0",
        flow_metrics: Optional[Dict[Tuple, Dict[str, Any]]] = None,
        host_patterns: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> pd.DataFrame:
        """
        Main adaptation entrypoint.
        Converts a raw NFStream DataFrame into a strictly-typed, deterministically-ordered
        project DataFrame.
        """
        if raw_df is None or raw_df.empty:
            return self.create_empty_dataframe(window_id=window_id)

        df = raw_df.copy()

        # ── 1. Window ID & Metadata ───────────────────────────────────────────
        df["window_id"] = window_id

        # Protocol Name
        if "protocol" in df.columns:
            df["protocol_name"] = df["protocol"].map(
                lambda p: PROTO_NUM_TO_NAME.get(int(p), str(p)) if pd.notnull(p) else "UNKNOWN"
            )
        else:
            df["protocol"] = 0
            df["protocol_name"] = "UNKNOWN"

        # ── 2. Direct Feature Renames ─────────────────────────────────────────
        for src_col, dst_col in DIRECT_FEATURE_MAP.items():
            if src_col in df.columns:
                df[dst_col] = df[src_col]
            else:
                df[dst_col] = 0

        # ── 3. Flow Duration (ms -> µs for CIC-IDS 2017 compatibility) ────────
        df["Flow Duration"] = _col_or_zero(df, "bidirectional_duration_ms", 1000.0)

        # ── 4. Packet Length Aggregates ───────────────────────────────────────
        if "Packet Length Std" in df.columns:
            df["Packet Length Variance"] = df["Packet Length Std"].astype(float) ** 2
        else:
            df["Packet Length Variance"] = 0.0

        df["Average Packet Size"] = df["Packet Length Mean"] if "Packet Length Mean" in df.columns else 0.0
        df["Avg Fwd Segment Size"] = df["Fwd Packet Length Mean"] if "Fwd Packet Length Mean" in df.columns else 0.0
        df["Avg Bwd Segment Size"] = df["Bwd Packet Length Mean"] if "Bwd Packet Length Mean" in df.columns else 0.0

        # ── 5. Rates (Flow Bytes/s, Packets/s) ────────────────────────────────
        duration_sec = (_col_or_zero(df, "bidirectional_duration_ms") / 1000.0).clip(lower=0.001)

        bidi_bytes = _col_or_zero(df, "bidirectional_bytes")
        bidi_pkts = _col_or_zero(df, "bidirectional_packets")
        fwd_pkts = _col_or_zero(df, "Total Fwd Packets")
        bwd_pkts = _col_or_zero(df, "Total Backward Packets")

        df["Flow Bytes/s"] = bidi_bytes / duration_sec
        df["Flow Packets/s"] = bidi_pkts / duration_sec
        df["Fwd Packets/s"] = fwd_pkts / duration_sec
        df["Bwd Packets/s"] = bwd_pkts / duration_sec

        # ── 6. Inter-Arrival Times (ms -> µs) ─────────────────────────────────
        df["Flow IAT Mean"] = _col_or_zero(df, "bidirectional_mean_piat_ms", 1000.0)
        df["Flow IAT Std"] = _col_or_zero(df, "bidirectional_stddev_piat_ms", 1000.0)
        df["Flow IAT Max"] = _col_or_zero(df, "bidirectional_max_piat_ms", 1000.0)
        df["Flow IAT Min"] = _col_or_zero(df, "bidirectional_min_piat_ms", 1000.0)

        df["Fwd IAT Total"] = _col_or_zero(df, "src2dst_duration_ms", 1000.0)
        df["Fwd IAT Mean"] = _col_or_zero(df, "src2dst_mean_piat_ms", 1000.0)
        df["Fwd IAT Std"] = _col_or_zero(df, "src2dst_stddev_piat_ms", 1000.0)
        df["Fwd IAT Max"] = _col_or_zero(df, "src2dst_max_piat_ms", 1000.0)
        df["Fwd IAT Min"] = _col_or_zero(df, "src2dst_min_piat_ms", 1000.0)

        df["Bwd IAT Total"] = _col_or_zero(df, "dst2src_duration_ms", 1000.0)
        df["Bwd IAT Mean"] = _col_or_zero(df, "dst2src_mean_piat_ms", 1000.0)
        df["Bwd IAT Std"] = _col_or_zero(df, "dst2src_stddev_piat_ms", 1000.0)
        df["Bwd IAT Max"] = _col_or_zero(df, "dst2src_max_piat_ms", 1000.0)
        df["Bwd IAT Min"] = _col_or_zero(df, "dst2src_min_piat_ms", 1000.0)

        # ── 7. Ratios ─────────────────────────────────────────────────────────
        df["Down/Up Ratio"] = bwd_pkts / fwd_pkts.clip(lower=1.0)

        # ── 8. Merge Deep Packet Analysis Metrics ──────────────────────────────
        # Initialize defaults
        df["TTL Mean"] = 64.0
        df["TTL Std"] = 0.0
        df["TTL Variance"] = 0.0
        df["TTL Min"] = 64.0
        df["TTL Max"] = 64.0
        df["TCP Window Size Init"] = 0.0
        df["TCP Window Size Mean"] = 0.0
        df["IP Flags DF Count"] = 0
        df["IP Flags MF Count"] = 0
        df["Retransmission Count"] = 0
        df["Port Sequentiality Score"] = 0.0
        df["Port Access Type"] = "SINGLE"

        # Derived flag bitmask fallback
        syn_bit = (df.get("SYN Flag Count", 0) > 0).astype(int) * 2
        ack_bit = (df.get("ACK Flag Count", 0) > 0).astype(int) * 16
        fin_bit = (df.get("FIN Flag Count", 0) > 0).astype(int) * 1
        rst_bit = (df.get("RST Flag Count", 0) > 0).astype(int) * 4
        psh_bit = (df.get("PSH Flag Count", 0) > 0).astype(int) * 8
        urg_bit = (df.get("URG Flag Count", 0) > 0).astype(int) * 32
        ece_bit = (df.get("ECE Flag Count", 0) > 0).astype(int) * 64
        cwr_bit = (df.get("CWE Flag Count", 0) > 0).astype(int) * 128
        df["tcp_flag_bitmask"] = syn_bit | ack_bit | fin_bit | rst_bit | psh_bit | urg_bit | ece_bit | cwr_bit

        if flow_metrics:
            for idx, row in df.iterrows():
                src_ip = str(row.get("src_ip", ""))
                dst_ip = str(row.get("dst_ip", ""))
                sport = int(row.get("src_port", 0))
                dport = int(row.get("dst_port", 0))
                proto = int(row.get("protocol", 6))

                # Lookup by forward, reverse, or bidirectional key
                key_fwd = (src_ip, dst_ip, sport, dport, proto)
                key_rev = (dst_ip, src_ip, dport, sport, proto)
                bidi_key = (tuple(sorted([src_ip, dst_ip])), min(sport, dport), max(sport, dport), proto)

                metrics = flow_metrics.get(key_fwd) or flow_metrics.get(bidi_key) or flow_metrics.get(key_rev)
                if metrics:
                    df.at[idx, "TTL Mean"] = metrics["ttl_mean"]
                    df.at[idx, "TTL Std"] = metrics["ttl_std"]
                    df.at[idx, "TTL Variance"] = metrics["ttl_var"]
                    df.at[idx, "TTL Min"] = metrics["ttl_min"]
                    df.at[idx, "TTL Max"] = metrics["ttl_max"]
                    df.at[idx, "tcp_flag_bitmask"] = metrics["tcp_flag_bitmask"]
                    df.at[idx, "TCP Window Size Init"] = metrics["tcp_win_init"]
                    df.at[idx, "TCP Window Size Mean"] = metrics["tcp_win_mean"]
                    df.at[idx, "IP Flags DF Count"] = metrics["ip_df_count"]
                    df.at[idx, "IP Flags MF Count"] = metrics["ip_mf_count"]
                    df.at[idx, "Retransmission Count"] = metrics["retransmission_count"]

        if host_patterns:
            for idx, row in df.iterrows():
                src_ip = str(row.get("src_ip", ""))
                if src_ip in host_patterns:
                    df.at[idx, "Port Sequentiality Score"] = host_patterns[src_ip]["port_sequentiality_score"]
                    df.at[idx, "Port Access Type"] = host_patterns[src_ip]["port_access_type"]

        # ── 9. Ensure All Target Columns Exist ─────────────────────────────────
        for col in DETERMINISTIC_COLUMN_ORDER:
            if col not in df.columns:
                target_dtype = SCHEMA_DTYPES.get(col, "float64")
                if target_dtype in ("int64", "float64"):
                    df[col] = 0
                else:
                    df[col] = ""

        # ── 10. Filter and Order Columns Deterministically ─────────────────────
        out_df = df[DETERMINISTIC_COLUMN_ORDER].copy()

        # ── 11. Replace Inf and NaN ───────────────────────────────────────────
        if self.replace_inf_nan:
            numeric_cols = [c for c, d in SCHEMA_DTYPES.items() if d in ("float64", "int64") and c in out_df.columns]
            for col in numeric_cols:
                out_df[col] = out_df[col].replace([np.inf, -np.inf], np.nan).fillna(0.0)

        # ── 12. Strict Dtype Enforcement ──────────────────────────────────────
        for col, dtype_str in SCHEMA_DTYPES.items():
            if col in out_df.columns:
                try:
                    if dtype_str == "int64":
                        out_df[col] = out_df[col].fillna(0).astype("int64")
                    elif dtype_str == "float64":
                        out_df[col] = out_df[col].fillna(0.0).astype("float64")
                    elif dtype_str == "string":
                        out_df[col] = out_df[col].fillna("").astype("string")
                except Exception as e:
                    logger.warning("Could not cast column %s to %s: %s", col, dtype_str, e)

        return out_df

    def create_empty_dataframe(self, window_id: str = "w_empty") -> pd.DataFrame:
        """
        Creates an empty DataFrame with exact deterministic column ordering and schema dtypes.
        Ensures downstream modules never encounter schema shape errors on empty windows.
        """
        data = {}
        for col in DETERMINISTIC_COLUMN_ORDER:
            dtype_str = SCHEMA_DTYPES.get(col, "float64")
            if dtype_str == "int64":
                data[col] = pd.Series([], dtype="int64")
            elif dtype_str == "float64":
                data[col] = pd.Series([], dtype="float64")
            else:
                data[col] = pd.Series([], dtype="string")
        return pd.DataFrame(data)
