"""
Module 2 (M2) — Feature Extraction Package
==========================================
PS 26145: Unidirectional Threat Detector
High-speed streaming network feature extractor powered by NFStream and Npcap.
Bridges M1 RawPacket streams into 30-second sliding windows and yields
clean, typed pandas DataFrames mapped to the project / CIC-IDS 2017 schema for M3/M4.
"""

# 1. Bootstrap Windows DLL environment immediately on import
from .bootstrap import bootstrap_environment, ensure_nfstream_ready
bootstrap_environment()

from .config import M2Config
from .flow_types import FlowWindow, WindowMetadata
from .schema import (
    DETERMINISTIC_COLUMN_ORDER,
    SCHEMA_DTYPES,
    DIRECT_FEATURE_MAP,
    FEATURE_DOCUMENTATION,
)
from .packet_adapter import (
    raw_packet_to_ethernet_frame,
    write_packets_to_pcap_file,
    packets_to_temp_pcap,
)
from .adapter import FeatureAdapter
from .engine import NFStreamEngine
from .window_aggregator import StreamWindowAggregator
from .packet_analyzer import WindowPacketAnalyzer
from .pipeline import M2Pipeline, M1WindowBridge

__version__ = "1.0.0"
__author__ = "Aayush (SIH 2026 Team - Module 2 Lead)"

__all__ = [
    "M2Config",
    "FlowWindow",
    "WindowMetadata",
    "DETERMINISTIC_COLUMN_ORDER",
    "SCHEMA_DTYPES",
    "DIRECT_FEATURE_MAP",
    "FEATURE_DOCUMENTATION",
    "raw_packet_to_ethernet_frame",
    "write_packets_to_pcap_file",
    "packets_to_temp_pcap",
    "FeatureAdapter",
    "NFStreamEngine",
    "WindowPacketAnalyzer",
    "StreamWindowAggregator",
    "M1WindowBridge",
    "M2Pipeline",
    "extract_features_from_window",
    "extract_features_from_packets",
    "extract_features_from_pcap",
    "batch_extract_pcap",
    "bootstrap_environment",
    "ensure_nfstream_ready",
]


def batch_extract_pcap(pcap_path: str, config: M2Config = None, window_id: str = "w_eval"):
    """Evaluation / offline test helper to extract features from a full PCAP file."""
    engine = NFStreamEngine(config=config)
    return engine.extract_from_pcap(pcap_path, window_id=window_id)


def extract_features_from_window(window: FlowWindow, config: M2Config = None):
    """Functional convenience entry point to extract features from a FlowWindow."""
    engine = NFStreamEngine(config=config)
    return engine.extract_from_window(window)


def extract_features_from_packets(packets, config: M2Config = None, window_id: str = "w_batch"):
    """Functional convenience entry point to extract features from a list of RawPackets."""
    engine = NFStreamEngine(config=config)
    return engine.extract_from_packets(packets, window_id=window_id)


def extract_features_from_pcap(pcap_path: str, config: M2Config = None, window_id: str = "w_pcap"):
    """Functional convenience entry point to extract features from a PCAP file."""
    engine = NFStreamEngine(config=config)
    return engine.extract_from_pcap(pcap_path, window_id=window_id)
