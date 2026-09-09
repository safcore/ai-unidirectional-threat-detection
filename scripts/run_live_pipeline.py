"""
run_live_pipeline.py — Master End-to-End Pipeline Orchestrator for PS-145 SOC.

Data Flow:
  M1 (Ingest: PCAP / CSV Dataset / Synthetic Live)
    -> M2 (Feature Extraction: NFStream or pure-Python fallback -> 66 canonical features)
    -> M3/M4 (Threat Classifier + Anomaly Model + Investigation)
    -> M5 (Alert Normalizer -> canonical shared/alert_schema.json)
    -> Flask Backend (POST /api/detect or local store + SSE broadcast)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pipeline")

# Ensure project root and backend are in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Imports from project modules
from m2_features import (
    adapt_to_canonical_66,
    extract_features,
    get_canonical_feature_names,
    FallbackPurePythonAggregator,
)
from backend.app.alert_normalizer import normalize_alert


def send_to_backend(
    target_url: str,
    features: Dict[str, float],
    metadata: Dict[str, Any],
    timeout: float = 5.0,
) -> Optional[Dict[str, Any]]:
    """Post detection payload to running backend API."""
    payload = json.dumps({"features": features, "metadata": metadata}).encode("utf-8")
    req = urllib.request.Request(
        target_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        logger.warning("Could not reach backend at %s: %s", target_url, e)
    except Exception as e:
        logger.warning("Error posting to %s: %s", target_url, e)
    return None


def run_pipeline(
    mode: str = "synthetic",
    input_path: Optional[str] = None,
    target_url: str = "http://localhost:8000/api/detect",
    direct: bool = False,
    dry_run: bool = False,
    rate: float = 10.0,
    max_events: int = 20,
) -> Dict[str, Any]:
    """Execute end-to-end pipeline."""
    logger.info("=" * 60)
    logger.info("Starting PS-145 Pipeline Orchestrator")
    logger.info("Mode: %s | Direct: %s | DryRun: %s | MaxEvents: %d", mode, direct, dry_run, max_events)
    logger.info("=" * 60)

    stats = {
        "flows_processed": 0,
        "alerts_generated": 0,
        "threat_counts": {},
        "start_time": time.time(),
        "end_time": None,
    }

    # Lazy-import backend components for direct mode
    m4_process_detection = None
    direct_store = None
    direct_stream = None
    if direct or dry_run:
        try:
            from backend.app.m4_integration import process_detection as m4_process_detection
            from backend.app import alert_store as direct_store
            from backend.app import stream_manager as direct_stream
        except Exception as e:
            logger.warning("Could not load direct backend components: %s", e)

    flow_generator = None

    if mode == "dataset":
        if not input_path or not os.path.exists(input_path):
            raise FileNotFoundError(f"Dataset file not found: {input_path}")
        from m1_ingest.cicids_reader import CICIDSReader
        reader = CICIDSReader(csv_paths=[input_path], target_fps=int(rate))

        def _dataset_gen():
            for record in reader.records():
                # Convert CICFlowRecord to canonical 66 features
                features, metadata = adapt_to_canonical_66(record.to_dict())
                yield features, metadata

        flow_generator = _dataset_gen()

    elif mode == "pcap":
        if not input_path or not os.path.exists(input_path):
            raise FileNotFoundError(f"PCAP file not found: {input_path}")
        from m1_ingest.pcap_replay import _parse_pcap
        agg = FallbackPurePythonAggregator()

        def _pcap_gen():
            for pkt in _parse_pcap(input_path):
                agg.ingest_packet(pkt)
                flushed = agg.flush_flows()
                for feat, meta in flushed:
                    yield feat, meta
            # Final flush
            for feat, meta in agg.flush_flows():
                yield feat, meta

        flow_generator = _pcap_gen()

    else:  # mode in ("synthetic", "live")
        from m1_ingest.pcap_replay import SyntheticTrafficGenerator
        import queue
        q = queue.Queue()
        synth = SyntheticTrafficGenerator(
            pkt_queue=q,
            packets_per_sec=max(10, int(rate * 10)),
            attack_mix=0.5,
        )

        def _synth_gen():
            beacon_src = "192.168.1.100"
            beacon_dst = "10.0.0.1"
            beacon_next = time.time() + 30
            agg = FallbackPurePythonAggregator()
            while True:
                now = time.time()
                for _ in range(5):
                    pkt = synth._make_packet(now, beacon_src, beacon_dst, beacon_next)
                    if pkt:
                        agg.ingest_packet(pkt)
                for feat, meta in agg.flush_flows():
                    yield feat, meta

        flow_generator = _synth_gen()

    # Process flows through pipeline
    delay = 1.0 / rate if rate > 0 else 0.0
    for features, metadata in flow_generator:
        stats["flows_processed"] += 1
        alert = None

        if not direct and not dry_run:
            # POST to backend /api/detect
            resp = send_to_backend(target_url, features, metadata)
            if resp and resp.get("status") == "success":
                alert = resp.get("alert")
            elif resp is None:
                # If backend is unreachable, fallback to direct detection
                logger.info("Backend offline, evaluating flow locally...")
                if m4_process_detection:
                    try:
                        _, _, alert = m4_process_detection(features, metadata)
                    except Exception as exc:
                        logger.error("Local detection failed: %s", exc)
        else:
            # Direct or dry-run evaluation
            if m4_process_detection:
                try:
                    _, _, alert = m4_process_detection(features, metadata)
                except Exception as exc:
                    logger.error("Local detection failed: %s", exc)

        if alert:
            normalized = normalize_alert(alert)
            threat = normalized.get("threat", "Unknown")
            stats["alerts_generated"] += 1
            stats["threat_counts"][threat] = stats["threat_counts"].get(threat, 0) + 1

            if direct and not dry_run and direct_store:
                try:
                    direct_store.add(normalized)
                except ValueError:
                    pass  # Skip duplicates
                if direct_stream:
                    direct_stream.broadcast(normalized)

            logger.info(
                "ALERT [%s] Threat: %s | Severity: %s | Confidence: %.2f | %s:%s -> %s:%s",
                normalized.get("alert_id"),
                threat,
                normalized.get("severity"),
                normalized.get("confidence", 0.0),
                normalized.get("source_ip"),
                normalized.get("source_port"),
                normalized.get("destination_ip"),
                normalized.get("destination_port"),
            )

        if max_events > 0 and stats["flows_processed"] >= max_events:
            break

        if delay > 0:
            time.sleep(delay)

    stats["end_time"] = time.time()
    elapsed = stats["end_time"] - stats["start_time"]
    logger.info("=" * 60)
    logger.info(
        "Pipeline finished in %.2fs | Flows: %d | Alerts: %d",
        elapsed, stats["flows_processed"], stats["alerts_generated"],
    )
    logger.info("Threat Summary: %s", json.dumps(stats["threat_counts"], indent=2))
    logger.info("=" * 60)
    return stats


def main():
    parser = argparse.ArgumentParser(description="PS-145 Master Pipeline Orchestrator")
    parser.add_argument("--mode", choices=["synthetic", "live", "pcap", "dataset"], default="synthetic",
                        help="Ingest source mode (default: synthetic)")
    parser.add_argument("--input", dest="input_path", default=None,
                        help="Input file path for pcap or dataset mode")
    parser.add_argument("--target-url", default="http://localhost:8000/api/detect",
                        help="Backend detection API URL")
    parser.add_argument("--direct", action="store_true",
                        help="Evaluate directly using local models without HTTP")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run detections without storing alerts")
    parser.add_argument("--rate", type=float, default=10.0,
                        help="Processing rate in flows/sec (default: 10)")
    parser.add_argument("--max-events", type=int, default=10,
                        help="Maximum events to process (default: 10, 0 for infinite)")

    args = parser.parse_args()
    run_pipeline(
        mode=args.mode,
        input_path=args.input_path,
        target_url=args.target_url,
        direct=args.direct,
        dry_run=args.dry_run,
        rate=args.rate,
        max_events=args.max_events,
    )


if __name__ == "__main__":
    main()
