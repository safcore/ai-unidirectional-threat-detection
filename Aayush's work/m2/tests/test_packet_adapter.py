"""
Unit tests for M2 Packet Adapter & PCAP Serializer (m2/packet_adapter.py)
"""

import unittest
import os
from m2.packet_adapter import (
    raw_packet_to_ethernet_frame,
    packets_to_temp_pcap,
    PCAP_GLOBAL_HEADER,
)
from m1_standalone.pcap_replay import RawPacket
from m2.engine import NFStreamEngine


class TestPacketAdapter(unittest.TestCase):
    def test_raw_packet_to_ethernet_frame_tcp(self):
        """TCP RawPacket generates a valid 54-byte minimum Ethernet/IP/TCP frame."""
        pkt = RawPacket(
            timestamp=1700000000.0,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            flags=0x02,  # SYN
            payload_len=0,
            ttl=64,
            raw=b"",
        )
        frame = raw_packet_to_ethernet_frame(pkt)
        self.assertGreaterEqual(len(frame), 54)  # 14 (Eth) + 20 (IP) + 20 (TCP)
        # Ethernet type must be IPv4 (0x0800)
        self.assertEqual(frame[12:14], b"\x08\x00")
        # IP version must be 4
        self.assertEqual((frame[14] >> 4), 4)

    def test_raw_packet_to_ethernet_frame_udp(self):
        """UDP RawPacket generates a valid Ethernet/IP/UDP frame."""
        payload = b"test payload"
        pkt = RawPacket(
            timestamp=1700000000.0,
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=5353,
            dst_port=53,
            protocol="UDP",
            flags=0,
            payload_len=len(payload),
            ttl=64,
            raw=payload,
        )
        frame = raw_packet_to_ethernet_frame(pkt)
        # 14 (Eth) + 20 (IP) + 8 (UDP) + len(payload)
        self.assertEqual(len(frame), 14 + 20 + 8 + len(payload))

    def test_packets_to_temp_pcap_and_nfstream_extraction(self):
        """Packets serialized to temp PCAP can be dissected by NFStream."""
        packets = [
            RawPacket(
                timestamp=1700000000.0 + i * 0.05,
                src_ip="192.168.1.100",
                dst_ip="10.0.0.5",
                src_port=40000 + i,
                dst_port=80,
                protocol="TCP",
                flags=0x02,
                payload_len=0,
                ttl=64,
                raw=b"",
            )
            for i in range(10)
        ]

        temp_pcap = packets_to_temp_pcap(packets)
        self.assertTrue(os.path.exists(temp_pcap))
        try:
            # Check global header
            with open(temp_pcap, "rb") as f:
                header = f.read(24)
            self.assertEqual(header, PCAP_GLOBAL_HEADER)

            # Test NFStream engine extraction from this temp pcap
            engine = NFStreamEngine()
            df = engine.extract_from_pcap(temp_pcap, window_id="w_test_pcap")
            self.assertEqual(len(df), 10)
            self.assertEqual(df["SYN Flag Count"].sum(), 10)
        finally:
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)

    def test_raw_wire_bytes_preserved(self):
        """Verify that genuine captured wire bytes (raw_frame) are preserved intact."""
        # Simulated full Ethernet frame with custom MACs
        custom_eth_frame = (
            b"\xde\xad\xbe\xef\x00\x01"  # custom dst MAC
            b"\xde\xad\xbe\xef\x00\x02"  # custom src MAC
            b"\x08\x00"                  # EtherType IPv4
            + b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\xae\xbe\xc0\xa8\x01\x64\x0a\x00\x00\x05"
            + b"\x30\x39\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
        )
        pkt = RawPacket(
            timestamp=1700000000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            flags=0x02,
            payload_len=0,
            ttl=64,
            raw=custom_eth_frame,
        )
        frame = raw_packet_to_ethernet_frame(pkt)
        # Must match the exact original wire bytes without modification
        self.assertEqual(frame, custom_eth_frame)
        self.assertEqual(frame[:6], b"\xde\xad\xbe\xef\x00\x01")


if __name__ == "__main__":
    unittest.main()
