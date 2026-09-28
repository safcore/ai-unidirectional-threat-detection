"""
M1 Smoke Test — verifies the streaming queue prints
"Processed X flows in last second" continuously.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m1_ingest.packet_queue import IngestPipeline
from m1_ingest.stream_monitor import StreamMonitor
from m2_features.flow_aggregator import FlowAggregator

print("=" * 60)
print("M1 SMOKE TEST — Streaming Queue Health Check")
print("=" * 60)

monitor    = StreamMonitor(interval_sec=1.0, print_stats=True)
aggregator = FlowAggregator(flow_timeout_sec=2.0, monitor=monitor)
pipeline   = IngestPipeline(pps=5_000, attack_mix=0.30, num_workers=2)

aggregator.start()
monitor.start()
pipeline.add_consumer(aggregator.ingest)
pipeline.start()

print("[M1] Pipeline started. Watching for 10 seconds...")
time.sleep(10)

fps = monitor.avg_flows_per_sec(last_n=8)
print(f"\n[RESULT] Average flows/sec (last 8s): {fps:.0f}")
print(f"[RESULT] Total packets processed: {pipeline.total_processed}")
print(f"[RESULT] Queue depth: {pipeline.queue_depth}")

if fps > 0:
    print("[PASS] M1 streaming queue is working correctly")
else:
    print("[FAIL] No flows detected -- check pipeline wiring")

pipeline.stop()
aggregator.stop()
monitor.stop()
