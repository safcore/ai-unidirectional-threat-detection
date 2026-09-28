"""
End-to-End M1 -> M2 Integration Tests (m2/tests/test_m1_m2_integration.py)
========================================================================
Proves that Meet's M1 Ingest Pipeline (threading.Queue, workers, StreamMonitor)
seamlessly feeds Aayush's M2 Feature Extractor (NFStream Engine, Feature Adapter)
and produces production-grade DataFrames for Aayushman's M3/M4 models.
"""

import unittest
import time
import os
import sys

# Ensure SIH root and m1_standalone are on path
SIH_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if SIH_ROOT not in sys.path:
    sys.path.insert(0, SIH_ROOT)
M1_DIR = os.path.join(SIH_ROOT, "m1_standalone")
if M1_DIR not in sys.path:
    sys.path.insert(0, M1_DIR)

from m1_standalone.packet_queue import IngestPipeline, make_packet_queue, PacketWorker
from m1_standalone.pcap_stream_reader import PcapStreamReader
from m2.pipeline import M2Pipeline
from m2.config import M2Config
from m2.schema import DETERMINISTIC_COLUMN_ORDER


class TestM1M2Integration(unittest.TestCase):
    def test_m1_synthetic_pipeline_to_m2(self):
        """
        Tests M1 IngestPipeline with synthetic traffic generator feeding M2.
        Data flow:
        M1 Synthetic Generator -> M1 Queue -> M1 Workers -> M2 Ingest -> NFStream -> DataFrame
        """
        # Configure M2 with 1.0 second windows for fast test turnaround
        m2_config = M2Config(
            window_duration_sec=1.0,
            slide_interval_sec=1.0,
            time_source="wall_clock",
        )
        m2_pipeline = M2Pipeline(config=m2_config)
        m2_pipeline.start()

        # Create Meet's M1 Ingest Pipeline
        m1_pipeline = IngestPipeline(
            pps=2000,
            queue_size=10_000,
            num_workers=2,
            attack_mix=0.5,
        )

        # Wire M1 -> M2 using Meet's public API
        m2_pipeline.attach_to_m1(m1_pipeline)

        # Start M1 streaming
        m1_pipeline.start()
        time.sleep(2.5)  # Stream for 2.5 seconds (spans multiple 1.0s windows)

        # Stop M1 and flush M2
        m1_pipeline.stop()
        final_meta, final_df = m2_pipeline.flush()
        m2_pipeline.stop(flush=False)

        # Collect all windows delivered to M2's output queue
        windows = []
        while not m2_pipeline.output_queue.empty():
            windows.append(m2_pipeline.output_queue.get_nowait())

        self.assertGreater(len(windows), 0, "M2 should have produced at least one flow window")
        meta, df = windows[0]

        # Verify DataFrame properties
        self.assertFalse(df.empty, "DataFrame should contain extracted flows")
        self.assertEqual(list(df.columns), DETERMINISTIC_COLUMN_ORDER)
        self.assertIn("Total Fwd Packets", df.columns)
        self.assertIn("SYN Flag Count", df.columns)
        self.assertIn("Flow Duration", df.columns)
        self.assertGreater(df["Total Fwd Packets"].sum(), 0)

    def test_m1_pcap_reader_to_m2(self):
        """
        Tests M1 PcapStreamReader replaying demo_traffic.pcap into M2.
        """
        pcap_path = os.path.join(SIH_ROOT, "demo_traffic.pcap")
        self.assertTrue(os.path.exists(pcap_path), f"demo_traffic.pcap must exist at {pcap_path}")

        m2_config = M2Config(
            window_duration_sec=30.0,
            slide_interval_sec=30.0,
            time_source="packet",
        )
        m2_pipeline = M2Pipeline(config=m2_config)
        pkt_queue = make_packet_queue(maxsize=10_000)

        # Wire M2 directly to queue before starting
        m2_pipeline.attach_to_queue(pkt_queue)
        m2_pipeline.start()

        reader = PcapStreamReader(
            pcap_path=pcap_path,
            flow_queue=pkt_queue,
            speed=50.0,
            loop=False,
        )
        reader.start()

        # Wait for reader to finish
        reader._thread.join(timeout=5.0)
        # Allow M2 queue worker to drain packets from the queue
        while not pkt_queue.empty():
            time.sleep(0.05)
        time.sleep(0.3)

        # Flush final window
        res = m2_pipeline.flush()
        m2_pipeline.stop(flush=False)

        self.assertIsNotNone(res, "Flush should emit a window from the PCAP traffic")
        meta, df = res

        self.assertEqual(len(df), 1, "demo_traffic.pcap has 1 flow")
        self.assertEqual(df["SYN Flag Count"].iloc[0], 100)
        self.assertEqual(df["src_ip"].iloc[0], "192.168.1.100")
        self.assertEqual(df["dst_ip"].iloc[0], "10.0.0.5")


if __name__ == "__main__":
    unittest.main()
