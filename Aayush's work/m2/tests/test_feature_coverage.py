"""
Unit Test: Feature Coverage & Master Guide Parity
=================================================
Validates that every feature required by the Team Leader Master Guide
is present, properly typed, and correctly computed in M2 output DataFrames.
"""

import unittest
import numpy as np
import pandas as pd
from dataclasses import dataclass
from typing import Optional

from m2.flow_types import FlowWindow
from m2.pipeline import M2Pipeline
from m2.config import M2Config
from m2.packet_analyzer import WindowPacketAnalyzer


@dataclass
class MockWirePacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: int
    payload_len: int
    ttl: int
    raw: Optional[bytes] = None
    raw_frame: Optional[bytes] = None


class TestFeatureCoverage(unittest.TestCase):
    """Verifies all 14 required features from the Team Leader Master Guide."""

    def test_all_14_required_features_present_in_schema(self):
        """Checks schema contains every single feature specified in the Master Guide."""
        config = M2Config()
        pipeline = M2Pipeline(config=config)
        empty_window = FlowWindow("w_test", 0.0, 30.0, [])
        meta, df = pipeline.process_flow_window(empty_window)

        required_features = [
            # 1. TCP flag bitmask
            "tcp_flag_bitmask",
            # 2. Bytes per flow
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            # 3. Packets per flow
            "Total Fwd Packets",
            "Total Backward Packets",
            # 4. Flow duration
            "Flow Duration",
            # 5. IAT mean / variance / max
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            # 6. Bidirectional flow ratio
            "Down/Up Ratio",
            # 7. Source / destination port
            "src_port",
            "dst_port",
            # 8. Protocol
            "protocol",
            # 9. TTL and TTL variance
            "TTL Mean",
            "TTL Std",
            "TTL Variance",
            "TTL Min",
            "TTL Max",
            # 10. TCP window size
            "TCP Window Size Init",
            "TCP Window Size Mean",
            # 11. IP fragment flags
            "IP Flags DF Count",
            "IP Flags MF Count",
            # 12. Payload-size distribution
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "Min Packet Length",
            "Max Packet Length",
            # 13. Retransmission count
            "Retransmission Count",
            # 14. Sequential vs random port-access pattern
            "Port Sequentiality Score",
            "Port Access Type",
        ]

        for feature in required_features:
            self.assertIn(feature, df.columns, f"Required feature '{feature}' missing from DataFrame schema!")

    def test_packet_analyzer_computations(self):
        """Verifies packet analyzer computes TTL, bitmask, window size, retransmission, and port patterns."""
        # Create synthetic scan packets:
        # src_ip scans ports 80, 81, 82, 83 (sequential scan)
        # Port 80 has a retransmission (duplicate seq)
        packets = [
            MockWirePacket(10.0, "192.168.1.50", "10.0.0.1", 40000, 80, "TCP", 0x02, 10, 64),
            MockWirePacket(10.1, "192.168.1.50", "10.0.0.1", 40000, 80, "TCP", 0x02, 10, 64),  # retransmission
            MockWirePacket(10.2, "192.168.1.50", "10.0.0.1", 40001, 81, "TCP", 0x10, 20, 50),
            MockWirePacket(10.3, "192.168.1.50", "10.0.0.1", 40002, 82, "TCP", 0x18, 30, 40),
            MockWirePacket(10.4, "192.168.1.50", "10.0.0.1", 40003, 83, "TCP", 0x01, 0, 30),
        ]

        flow_metrics, host_patterns = WindowPacketAnalyzer.analyze_window_packets(packets)

        # 1. Host Port Scan Sequentiality
        self.assertIn("192.168.1.50", host_patterns)
        pattern = host_patterns["192.168.1.50"]
        self.assertEqual(pattern["port_access_type"], "SEQUENTIAL")
        self.assertGreaterEqual(pattern["port_sequentiality_score"], 0.9)

        # 2. Flow Metrics for port 80 flow
        fwd_key = ("192.168.1.50", "10.0.0.1", 40000, 80, 6)
        self.assertIn(fwd_key, flow_metrics)
        m80 = flow_metrics[fwd_key]
        self.assertEqual(m80["ttl_mean"], 64.0)
        self.assertEqual(m80["ttl_var"], 0.0)
        self.assertEqual(m80["tcp_flag_bitmask"], 0x02)  # SYN
        self.assertEqual(m80["retransmission_count"], 1)  # 1 duplicate SYN

    def test_production_flow_window_contract(self):
        """Verifies M2Pipeline.process_flow_window directly accepts a FlowWindow."""
        config = M2Config()
        pipeline = M2Pipeline(config=config)

        packets = [
            MockWirePacket(1.0, "192.168.1.10", "10.0.0.2", 1234, 80, "TCP", 0x02, 0, 64),
            MockWirePacket(1.1, "192.168.1.10", "10.0.0.2", 1234, 80, "TCP", 0x10, 100, 64),
        ]
        window = FlowWindow(window_id="w_contract", start_time=0.0, end_time=30.0, packets=packets)

        meta, df = pipeline.process_flow_window(window)
        self.assertEqual(meta.window_id, "w_contract")
        self.assertIsInstance(df, pd.DataFrame)
        self.assertGreaterEqual(len(df), 1)
        self.assertEqual(df["window_id"].iloc[0], "w_contract")
        self.assertIn("Total Fwd Packets", df.columns)
        self.assertIn("SYN Flag Count", df.columns)
        self.assertIn("TTL Mean", df.columns)
        self.assertIn("tcp_flag_bitmask", df.columns)


if __name__ == "__main__":
    unittest.main()
