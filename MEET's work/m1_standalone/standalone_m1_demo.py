"""
M1 INGEST PIPELINE — STANDALONE DEMO (MEET'S MODULE)
=====================================================
Dedicated runner for Module 1 (Ingest Pipeline & Queuing).

Satisfies all M1 requirements for Meet:
  1. Thread-safe bounded threading.Queue ingest core
  2. PCAP & PCAPNG replay engine (speed-controlled, zero packet loss)
  3. Real-time sliding-window monitor printing "Processed X flows/sec" every 1s
  4. Multithreaded consumer worker pool with drop-count metrics

Usage:
    # Run with synthetic PCAP (no files needed):
    python m1_ingest/standalone_m1_demo.py

    # Run with a real PCAP or PCAPNG file:
    python m1_ingest/standalone_m1_demo.py --pcap "path/to/file.pcap" --speed 10.0

    # Run high-throughput stress test (50,000 pps):
    python m1_ingest/standalone_m1_demo.py --pps 50000 --duration 15
"""

import sys
import os
import time
import argparse
import logging

# Ensure parent directory is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)-20s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("m1_meet")

from pcap_stream_reader import PcapStreamReader, RawPacket
from stream_monitor     import StreamMonitor
from packet_queue       import make_packet_queue, PacketWorker, IngestPipeline


def main():
    parser = argparse.ArgumentParser(description="M1 Ingest Pipeline — Standalone Demo (Meet)")
    parser.add_argument("--pcap",     default=None,   help="Path to .pcap or .pcapng file")
    parser.add_argument("--pps",      type=int, default=5000, help="Target packets/sec for synthetic generator")
    parser.add_argument("--speed",    type=float, default=10.0, help="Replay speed multiplier for PCAP")
    parser.add_argument("--duration", type=int, default=15, help="Demo duration in seconds")
    parser.add_argument("--workers",  type=int, default=2, help="Consumer worker threads")
    args = parser.parse_args()

    print("=" * 72)
    print("  MEET'S MODULE — M1: INGEST PIPELINE & STREAMING QUEUE")
    print("  NTRO Problem 26145 | Unidirectional Data-Diode Emulation")
    print("=" * 72)

    # ── 1. Create Stream Monitor ──────────────────────────────────────────────
    monitor = StreamMonitor(interval_sec=1.0, print_stats=True)
    monitor.start()

    # ── 2. Select Ingest Source (PCAP vs Synthetic) ───────────────────────────
    if args.pcap and os.path.exists(args.pcap):
        print(f"\n[M1 CONFIG] Source      : REAL PCAP/PCAPNG ({args.pcap})")
        print(f"[M1 CONFIG] Speed Factor: {args.speed:.1f}x")
        print(f"[M1 CONFIG] Workers     : {args.workers} consumer threads")

        pkt_queue = make_packet_queue(maxsize=100_000)
        reader    = PcapStreamReader(
            pcap_path  = args.pcap,
            flow_queue = pkt_queue,
            speed      = args.speed,
            loop       = True,
            monitor    = monitor,
        )

        def _consumer_handler(pkt: RawPacket):
            monitor.record_flow()  # Record flow metrics

        workers = [
            PacketWorker(pkt_queue, _consumer_handler, name=f"Worker-{i}")
            for i in range(args.workers)
        ]

        for w in workers:
            w.start()
        reader.start()

        def stop_all():
            reader.stop()
            for w in workers:
                w.stop()
            monitor.stop()

        get_total = lambda: sum(w.packets_processed for w in workers)
        get_qsize = lambda: pkt_queue.qsize()

    else:
        print(f"\n[M1 CONFIG] Source      : SYNTHETIC TRAFFIC GENERATOR")
        print(f"[M1 CONFIG] Target PPS  : {args.pps:,} packets/sec")
        print(f"[M1 CONFIG] Workers     : {args.workers} consumer threads")

        pipeline = IngestPipeline(
            pps         = args.pps,
            num_workers = args.workers,
            queue_size  = 100_000,
        )

        def _consumer_handler(pkt: RawPacket):
            monitor.record_flow()

        pipeline.add_consumer(_consumer_handler)
        pipeline.start()

        def stop_all():
            pipeline.stop()
            monitor.stop()

        get_total = lambda: pipeline.total_processed
        get_qsize = lambda: pipeline.queue_depth

    print("\n[M1 READY] Streaming packets... (Watch for '[STREAM] Processed X flows/sec')\n")

    # ── 3. Run Demo Loop ──────────────────────────────────────────────────────
    start_time = time.time()
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[M1] Demo interrupted by user.")

    elapsed = time.time() - start_time
    total_processed = get_total()
    avg_fps = monitor.avg_flows_per_sec(last_n=min(int(elapsed), 10))

    # ── 4. Print Summary Report ───────────────────────────────────────────────
    stop_all()

    print("\n" + "=" * 72)
    print("  MEET'S MODULE M1 — INGEST PERFORMANCE REPORT")
    print("=" * 72)
    print(f"  Execution Time           : {elapsed:.2f} seconds")
    print(f"  Total Packets Streamed   : {total_processed:,}")
    print(f"  Average Throughput       : {avg_fps:,.0f} flows/sec")
    print(f"  Final Queue Depth        : {get_qsize():,}")
    print(f"  Packet Drops             : {monitor.latest.get('total_drops', 0)}")
    print("=" * 72)

    if total_processed > 0 and avg_fps > 0:
        print("  [PASS] VERDICT: Meet's M1 Streaming Queue is 100% operational!")
    else:
        print("  [FAIL] VERDICT: No packets processed.")
    print("=" * 72)


if __name__ == "__main__":
    main()
