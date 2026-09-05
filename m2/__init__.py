"""
Module 2 (M2) — Streaming Feature Extraction Layer
===================================================
High-speed feature extraction with dual-mode support:
  1. Primary: NFStream 6.6.0 C-Engine + Deep Packet Analyzer (when Npcap is available)
  2. Fallback: Pure-Python Flow Aggregator & Canonical Adapter (when Npcap/NFStream is absent)
Guarantees deterministic output mapping directly to the canonical 66-feature schema for M3/M4.
"""

import logging
from typing import Optional, Dict, Any, Tuple, List

from .canonical_adapter import adapt_to_canonical_66, get_canonical_feature_names
from .fallback_extractor import FallbackPurePythonAggregator, FallbackFlowRecord

logger = logging.getLogger("m2")

_NFSTREAM_AVAILABLE: Optional[bool] = None


def is_nfstream_available() -> bool:
    """Check whether NFStream and required native libraries can be loaded."""
    global _NFSTREAM_AVAILABLE
    if _NFSTREAM_AVAILABLE is not None:
        return _NFSTREAM_AVAILABLE
    try:
        from .bootstrap import bootstrap_environment
        bootstrap_environment()
        import nfstream
        _ = nfstream.NFStreamer
        _NFSTREAM_AVAILABLE = True
    except Exception as e:
        logger.info("NFStream native engine not available (will use pure-Python fallback): %s", e)
        _NFSTREAM_AVAILABLE = False
    return _NFSTREAM_AVAILABLE


def extract_features(pkt_or_window: Any) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """
    Extract canonical 66-feature vector from a packet or window.
    Uses NFStream when available, otherwise falls back to pure-Python aggregator.
    """
    if is_nfstream_available():
        try:
            from .engine import NFStreamEngine
            engine = NFStreamEngine()
            # If window:
            df = engine.extract_from_window(pkt_or_window)
            if not df.empty:
                return adapt_to_canonical_66(df.iloc[0].to_dict())
        except Exception as e:
            logger.warning("NFStream extraction failed, using fallback: %s", e)

    # Fallback mode
    if hasattr(pkt_or_window, "packets"):
        packets = pkt_or_window.packets
    elif isinstance(pkt_or_window, list):
        packets = pkt_or_window
    else:
        packets = [pkt_or_window]

    agg = FallbackPurePythonAggregator()
    for p in packets:
        agg.ingest_packet(p)
    flushed = agg.flush_flows()
    if flushed:
        return flushed[0]

    # Return clean empty feature vector if no packets
    canonical_names = get_canonical_feature_names()
    features = {name: 0.0 for name in canonical_names}
    metadata = {
        "src_ip": "0.0.0.0", "dst_ip": "0.0.0.0",
        "src_port": 0, "dst_port": 0,
        "protocol": "TCP", "mode": "fallback_empty",
    }
    return features, metadata


__all__ = [
    "is_nfstream_available",
    "adapt_to_canonical_66",
    "get_canonical_feature_names",
    "FallbackPurePythonAggregator",
    "FallbackFlowRecord",
    "extract_features",
]
