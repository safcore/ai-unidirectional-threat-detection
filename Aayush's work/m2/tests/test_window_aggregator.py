"""
Unit tests for M2 Streaming Window Aggregator (m2/window_aggregator.py)
"""

import unittest
import threading
from m2.window_aggregator import StreamWindowAggregator
from m2.config import M2Config
from m1_standalone.pcap_replay import RawPacket


def make_test_packet(ts: float, sport: int = 1000):
    return RawPacket(
        timestamp=ts,
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=sport,
        dst_port=80,
        protocol="TCP",
        flags=0x02,
        payload_len=0,
        ttl=64,
        raw=b"",
    )


class TestWindowAggregator(unittest.TestCase):
    def test_30_second_window_boundary(self):
        """Packets within 30s are held; crossing 30s boundary emits window 1."""
        emitted_windows = []
        config = M2Config(window_duration_sec=30.0, slide_interval_sec=30.0)
        agg = StreamWindowAggregator(config=config, on_window_ready=emitted_windows.append)

        # Ingest packets from t=100.0 to t=129.9 (20 packets)
        for i in range(20):
            ts = 100.0 + i * 1.5  # up to 128.5
            w = agg.ingest(make_test_packet(ts, sport=1000 + i))
            self.assertIsNone(w, "Window should not be emitted before 30 seconds")

        self.assertEqual(len(emitted_windows), 0)

        # Ingest packet at t=130.5 (boundary crossed!)
        w1 = agg.ingest(make_test_packet(130.5, sport=9999))
        self.assertIsNotNone(w1, "Crossing 30s boundary must emit completed window")
        self.assertEqual(len(emitted_windows), 1)
        self.assertEqual(w1.window_id, "w_0001")
        self.assertEqual(w1.packet_count, 20)
        self.assertEqual(w1.start_time, 100.0)
        self.assertEqual(w1.end_time, 130.0)

        # The packet at 130.5 belongs to window 2
        self.assertEqual(agg._current_packets[0].src_port, 9999)

    def test_tumbling_window_state_isolation(self):
        """Packets in Window 1 do not contaminate Window 2."""
        emitted = []
        config = M2Config(window_duration_sec=30.0, slide_interval_sec=30.0)
        agg = StreamWindowAggregator(config=config, on_window_ready=emitted.append)

        # Window 1: t = 0s to 29s
        for i in range(5):
            agg.ingest(make_test_packet(float(i * 5), sport=100 + i))

        # Window 2: t = 30s to 59s
        for i in range(7):
            agg.ingest(make_test_packet(30.0 + float(i * 4), sport=200 + i))

        # Window 3 trigger: t = 60s
        agg.ingest(make_test_packet(60.0, sport=300))

        self.assertGreaterEqual(len(emitted), 2)
        w1, w2 = emitted[0], emitted[1]

        self.assertEqual(w1.packet_count, 5)
        self.assertEqual(w2.packet_count, 7)

        w1_sports = {p.src_port for p in w1.packets}
        w2_sports = {p.src_port for p in w2.packets}
        self.assertTrue(w1_sports.isdisjoint(w2_sports), "Window 1 and 2 must not share packet state")

    def test_flush_emits_partial_window(self):
        """flush() finalizes and emits any remaining buffered packets."""
        emitted = []
        config = M2Config(window_duration_sec=30.0)
        agg = StreamWindowAggregator(config=config, on_window_ready=emitted.append)

        agg.ingest(make_test_packet(10.0))
        agg.ingest(make_test_packet(15.0))

        self.assertEqual(len(emitted), 0)
        final_w = agg.flush()

        self.assertIsNotNone(final_w)
        self.assertEqual(final_w.packet_count, 2)
        self.assertTrue(final_w.is_final)
        self.assertEqual(len(emitted), 1)

        # Second flush on empty should return None
        self.assertIsNone(agg.flush())

    def test_concurrent_ingest_thread_safety(self):
        """Multi-threaded ingest does not corrupt window state or drop counts."""
        config = M2Config(window_duration_sec=30.0, slide_interval_sec=30.0)
        agg = StreamWindowAggregator(config=config)

        def worker(thread_id: int):
            for i in range(100):
                agg.ingest(make_test_packet(float(i * 0.2), sport=1000 * thread_id + i))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(agg.total_packets_received, 400)


if __name__ == "__main__":
    unittest.main()
