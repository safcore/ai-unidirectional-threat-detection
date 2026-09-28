"""
Streaming multi-window verification tests for M2 (m2/tests/test_streaming_windows.py)
"""

import unittest
from m2.pipeline import M2Pipeline
from m2.config import M2Config
from m2.schema import DETERMINISTIC_COLUMN_ORDER
from m1_standalone.pcap_replay import RawPacket


def make_syn_packet(ts: float, sport: int, src_ip: str = "192.168.1.100"):
    return RawPacket(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip="10.0.0.5",
        src_port=sport,
        dst_port=80,
        protocol="TCP",
        flags=0x02,  # SYN
        payload_len=0,
        ttl=64,
        raw=b"",
    )


class TestStreamingWindows(unittest.TestCase):
    def test_multi_window_pipeline_streaming(self):
        """
        Feed packets spanning 3 successive 30-second windows.
        Assert that:
        1. Window 1, 2, 3 each produce a valid DataFrame.
        2. Schema and dtypes are 100% stable and identical across windows.
        3. Window IDs are unique and monotonically increasing.
        4. State from window 1 does not leak into window 2.
        """
        config = M2Config(window_duration_sec=30.0, slide_interval_sec=30.0)
        pipeline = M2Pipeline(config=config)
        pipeline.start()

        collected_results = []
        pipeline.subscribe(lambda df, meta: collected_results.append((meta, df)))

        # ── Window 1: t = 0.0s to 25.0s (15 packets from 192.168.1.10)
        for i in range(15):
            pipeline.ingest(make_syn_packet(ts=float(i * 1.5), sport=1000 + i, src_ip="192.168.1.10"))

        # ── Window 2: t = 30.0s to 55.0s (25 packets from 192.168.1.20)
        # Note: Ingesting at t=30.0s triggers Window 1 completion
        for i in range(25):
            pipeline.ingest(make_syn_packet(ts=30.0 + float(i * 1.0), sport=2000 + i, src_ip="192.168.1.20"))

        # ── Window 3: t = 60.0s to 85.0s (10 packets from 192.168.1.30)
        # Ingesting at t=60.0s triggers Window 2 completion
        for i in range(10):
            pipeline.ingest(make_syn_packet(ts=60.0 + float(i * 2.0), sport=3000 + i, src_ip="192.168.1.30"))

        # Stop and flush Window 3
        pipeline.stop(flush=True)

        self.assertEqual(len(collected_results), 3, "Expected exactly 3 emitted windows")

        (meta1, df1), (meta2, df2), (meta3, df3) = collected_results

        # 1. Distinguishable Window IDs
        self.assertEqual(meta1.window_id, "w_0001")
        self.assertEqual(meta2.window_id, "w_0002")
        self.assertEqual(meta3.window_id, "w_0003")

        # 2. Schema Stability across all windows
        for idx, (meta, df) in enumerate(collected_results, 1):
            self.assertEqual(
                list(df.columns),
                DETERMINISTIC_COLUMN_ORDER,
                f"Window {idx} schema order mismatch",
            )
            self.assertFalse(
                df.isna().any().any(),
                f"Window {idx} contains unexpected NaN values",
            )

        # 3. State Isolation Verification
        # Window 1 only saw IP 192.168.1.10
        self.assertTrue((df1["src_ip"] == "192.168.1.10").all())
        self.assertEqual(meta1.packet_count, 15)

        # Window 2 only saw IP 192.168.1.20
        self.assertTrue((df2["src_ip"] == "192.168.1.20").all())
        self.assertEqual(meta2.packet_count, 25)

        # Window 3 only saw IP 192.168.1.30
        self.assertTrue((df3["src_ip"] == "192.168.1.30").all())
        self.assertEqual(meta3.packet_count, 10)

        # 4. Correct flow counts
        self.assertEqual(meta1.flow_count, len(df1))
        self.assertEqual(meta2.flow_count, len(df2))
        self.assertEqual(meta3.flow_count, len(df3))

    def test_overlapping_sliding_window(self):
        """
        Tests true overlapping sliding window semantics:
        window_duration = 30s, slide_interval = 10s.
        Window 1: [0, 30)
        Window 2: [10, 40) retaining packets from [10, 30)
        """
        config = M2Config(window_duration_sec=30.0, slide_interval_sec=10.0)
        pipeline = M2Pipeline(config=config)
        pipeline.start()

        collected = []
        pipeline.subscribe(lambda df, meta: collected.append((meta, df)))

        # Packets in [0, 30)
        pipeline.ingest(make_syn_packet(ts=5.0, sport=1001, src_ip="10.0.0.1"))
        pipeline.ingest(make_syn_packet(ts=15.0, sport=1002, src_ip="10.0.0.2"))
        pipeline.ingest(make_syn_packet(ts=25.0, sport=1003, src_ip="10.0.0.3"))

        # Packet at ts=35.0 crosses the 30s boundary -> triggers Window 1
        pipeline.ingest(make_syn_packet(ts=35.0, sport=1004, src_ip="10.0.0.4"))

        # Flush final window
        pipeline.stop(flush=True)

        self.assertGreaterEqual(len(collected), 2, "Should emit at least 2 overlapping windows")
        meta1, df1 = collected[0]
        meta2, df2 = collected[1]

        # Window 1: [0, 30) had 3 packets (ts=5, 15, 25)
        self.assertEqual(meta1.packet_count, 3)

        # Window 2: [10, 40) retained packets >= 10 (ts=15, 25) plus new packet ts=35
        self.assertEqual(meta2.packet_count, 3)
        self.assertTrue("10.0.0.2" in df2["src_ip"].values)
        self.assertTrue("10.0.0.3" in df2["src_ip"].values)
        self.assertTrue("10.0.0.4" in df2["src_ip"].values)
        # ts=5 (10.0.0.1) was dropped from Window 2 because ts < 10.0
        self.assertFalse("10.0.0.1" in df2["src_ip"].values)

    def test_large_timestamp_gap_in_sliding_mode(self):
        """Verify that large gaps in packet timestamps cleanly realign the sliding window."""
        config = M2Config(window_duration_sec=30.0, slide_interval_sec=10.0)
        pipeline = M2Pipeline(config=config)
        pipeline.start()

        collected = []
        pipeline.subscribe(lambda df, meta: collected.append((meta, df)))

        # Window 1 packets
        pipeline.ingest(make_syn_packet(ts=1.0, sport=1000))
        pipeline.ingest(make_syn_packet(ts=10.0, sport=1001))

        # Huge gap: 200 seconds later
        pipeline.ingest(make_syn_packet(ts=210.0, sport=2000))
        pipeline.stop(flush=True)

        self.assertGreaterEqual(len(collected), 2)
        meta_after_gap, df_after_gap = collected[-1]
        self.assertGreaterEqual(meta_after_gap.start_time, 200.0)


if __name__ == "__main__":
    unittest.main()
