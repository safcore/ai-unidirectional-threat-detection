"""
NetWatch — Unified Entry Point
================================
Wires all modules together and starts the full pipeline:

  M1 (Ingest) → M2 (Features) → M3+M4 (Detectors) → M5 (Alerts) → M6 (Dashboard)

Usage:
    python run.py                        # synthetic traffic, dashboard on :5000
    python run.py --pcap traffic.pcap   # replay a PCAP file
    python run.py --pps 10000           # 10k packets/sec synthetic load
    python run.py --no-dashboard        # pipeline only, no web UI
    python run.py --train               # train ML models first, then run
"""

import sys
import os
import time
import logging
import argparse
import threading

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)-20s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("netwatch")


def parse_args():
    p = argparse.ArgumentParser(description="NetWatch — AI Cyber Threat Detection Pipeline")
    p.add_argument("--pcap",         default=None,  help="Path to live PCAP file to replay (real-time detection)")
    p.add_argument("--csv",          nargs="+", default=[], help="Path(s) to CIC-IDS 2017 CSV file(s)")
    p.add_argument("--pps",          type=int, default=5_000, help="Synthetic packets/sec (default 5000)")
    p.add_argument("--attack-mix",   type=float, default=0.30, help="Fraction of synthetic attack traffic")
    p.add_argument("--flow-timeout", type=float, default=30.0, help="Flow inactivity timeout (sec)")
    p.add_argument("--workers",      type=int, default=2, help="Packet consumer threads")
    p.add_argument("--port",         type=int, default=5000, help="Dashboard port")
    p.add_argument("--no-dashboard", action="store_true", help="Disable the web dashboard")
    p.add_argument("--train",        action="store_true", help="Train ML models before starting")
    p.add_argument("--debug",        action="store_true", help="Enable debug logging")
    return p.parse_args()


def train_models():
    logger.info("═══ Training ML models ═══")
    from m3_classifiers.train import train_ddos_model
    train_ddos_model()
    logger.info("═══ Training complete ═══")


def main():
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("╔══════════════════════════════════════════╗")
    logger.info("║   NETWATCH — AI Cyber Threat Detection   ║")
    logger.info("║   Unidirectional Traffic Analysis        ║")
    logger.info("╚══════════════════════════════════════════╝")

    # ── Optional: train models first ─────────────────────────────────────────
    if args.train:
        train_models()

    # ── M1 & M2: Pipeline Wiring ──────────────────────────────────────────────
    from m1_ingest.stream_monitor import StreamMonitor
    from m2_features.flow_aggregator import FlowAggregator
    from m2_features.feature_extractor import FeatureExtractor
    from m5_alerts.alert_engine import AlertEngine

    monitor = StreamMonitor(interval_sec=1.0, print_stats=True)
    monitor.start()

    alert_engine = AlertEngine(monitor=monitor)
    alert_engine.start()

    extractor = FeatureExtractor()

    # ── Detectors (M3 + M4) ───────────────────────────────────────────────────
    from m3_classifiers.ddos_detector import DDoSDetector
    from m3_classifiers.portscan_detector import PortScanDetector
    from m4_advanced.dga_detector import DGADetector
    from m4_advanced.beacon_detector import BeaconDetector
    from m4_advanced.exfil_detector import ExfilDetector

    ddos_det     = DDoSDetector(alert_handler=alert_engine.ingest)
    portscan_det = PortScanDetector(alert_handler=alert_engine.ingest)
    dga_det      = DGADetector(alert_handler=alert_engine.ingest)
    beacon_det   = BeaconDetector(alert_handler=alert_engine.ingest)
    exfil_det    = ExfilDetector(alert_handler=alert_engine.ingest)

    extractor.add_handler(ddos_det.predict)
    extractor.add_handler(portscan_det.predict)
    extractor.add_handler(dga_det.predict)
    extractor.add_handler(beacon_det.predict)
    extractor.add_handler(exfil_det.predict)

    # ── Ingest Selection (PCAP vs CSV vs Synthetic) ──────────────────────────
    if args.csv:
        logger.info("Ingest mode: CSV dataset replay (%d files)", len(args.csv))
        from m1_ingest.cic_ids_pipeline import CICIDSPipeline
        pipeline = CICIDSPipeline(
            csv_paths   = args.csv,
            target_fps  = args.pps,
            num_workers = args.workers,
            monitor     = monitor,
        )
        # For CSV flows, adapt CICFlowRecord -> extractor
        def _handle_cic_flow(cic_flow):
            feats = cic_flow.to_feature_dict()
            extractor.extract_feats_dict(feats) if hasattr(extractor, "extract_feats_dict") else None
            # Dispatch directly to feature handlers
            for h in extractor._handlers:
                try:
                    h(feats)
                except Exception:
                    pass

        pipeline.add_handler(_handle_cic_flow)

    elif args.pcap:
        logger.info("Ingest mode: Live PCAP replay (%s)", args.pcap)
        from m1_ingest.pcap_stream_reader import PcapStreamReader
        from m1_ingest.packet_queue import make_packet_queue, PacketWorker

        aggregator = FlowAggregator(flow_timeout_sec=args.flow_timeout, monitor=monitor)
        aggregator.add_handler(extractor.extract)
        aggregator.start()

        pkt_queue = make_packet_queue(50_000)
        reader = PcapStreamReader(args.pcap, pkt_queue, speed=10.0, monitor=monitor)

        def _dispatch(pkt):
            aggregator.ingest(pkt)

        workers = [PacketWorker(pkt_queue, _dispatch, name=f"Worker-{i}") for i in range(args.workers)]
        for w in workers: w.start()
        reader.start()

        class _PcapPipelineWrapper:
            def stop(self):
                reader.stop()
                for w in workers: w.stop()
                aggregator.stop()
            @property
            def total_processed(self):
                return sum(w.packets_processed for w in workers)
        pipeline = _PcapPipelineWrapper()

    else:
        logger.info("Ingest mode: Synthetic live traffic generator (%d pps)", args.pps)
        from m1_ingest.packet_queue import IngestPipeline
        aggregator = FlowAggregator(flow_timeout_sec=args.flow_timeout, monitor=monitor)
        aggregator.add_handler(extractor.extract)
        aggregator.start()

        pipeline = IngestPipeline(
            pps=args.pps,
            attack_mix=args.attack_mix,
            num_workers=args.workers,
        )
        pipeline.add_consumer(aggregator.ingest)
        pipeline.start()

    logger.info("Pipeline started — Processed X flows in last second printing every 1s")
    logger.info("Throughput target: %d pps / ~%.0f Mbps equivalent", args.pps, args.pps * 800 / 1e6)

    # ── M6: Dashboard ─────────────────────────────────────────────────────────
    if not args.no_dashboard:
        from m6_dashboard.app import run_dashboard, register_with_engine, register_monitor
        register_with_engine(alert_engine)
        register_monitor(monitor)

        dash_thread = threading.Thread(
            target=run_dashboard,
            kwargs={"host": "0.0.0.0", "port": args.port, "debug": False},
            name="Dashboard",
            daemon=True,
        )
        dash_thread.start()
        logger.info("Dashboard → http://localhost:%d", args.port)

    # ── Main loop ─────────────────────────────────────────────────────────────
    logger.info("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(10)
            fps = monitor.avg_flows_per_sec(last_n=10)
            logger.info(
                "[HEALTH] avg 10s flows/sec=%.0f | active_flows=%d | total_alerts=%d",
                fps, aggregator.active_flows, alert_engine.total_alerts,
            )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        pipeline.stop()
        aggregator.stop()
        monitor.stop()
        logger.info("NetWatch stopped. Total alerts: %d", alert_engine.total_alerts)


if __name__ == "__main__":
    main()
