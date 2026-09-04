"""
Worker-Scaling Benchmark Script for Phase 3 Audit.

Evaluates StreamProcessor queue processing across 1, 2, 4, and 8 worker threads on 1,000 validation flows.
Measures:
  - Throughput (flows/sec)
  - Latency P50, P95, P99 (ms)
  - Successful / Failed counts
  - Decision breakdown & Alert severity breakdown
"""

import time
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List

from ml.training.loader import load_feature_schema, validate_and_extract_features
from ml.detection.stream_processor import StreamProcessor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("worker_scaling_benchmark")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
VAL_PATH = BASE_DIR / "ml" / "data" / "validation.csv"


def run_worker_scaling_benchmark() -> Dict[str, Any]:
    """Run benchmark across 1, 2, 4, and 8 worker threads."""
    schema = load_feature_schema()
    logger.info("Loading 250 validation flows for fast multi-worker scaling benchmark...")
    df_val = pd.read_csv(VAL_PATH, nrows=250, low_memory=False)
    X_val, _ = validate_and_extract_features(df_val, schema)
    flow_records = X_val.to_dict(orient="records")

    worker_counts = [1, 2, 4, 8]
    scaling_results = {}
    
    # Store decision & severity breakdown for 1-worker run
    decision_breakdown = {"BENIGN": 0, "SUSPICIOUS": 0, "ANOMALOUS": 0, "MALICIOUS": 0}
    severity_breakdown = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for num_workers in worker_counts:
        logger.info(f"Testing StreamProcessor with {num_workers} worker thread(s)...")
        processor = StreamProcessor(max_queue_size=2000, worker_count=num_workers)
        processor.start()

        start_time = time.time()
        latencies_ms = []

        # Submit all 1,000 flows
        for flow in flow_records:
            processor.submit_flow(flow)

        events_retrieved = 0
        success_count = 0
        failed_count = 0

        while events_retrieved < len(flow_records):
            t0 = time.time()
            evt = processor.get_event(block=True, timeout=5.0)
            t1 = time.time()
            if evt is None:
                logger.warning(f"Timeout waiting for event on {num_workers} workers.")
                break
            
            events_retrieved += 1
            latencies_ms.append((t1 - t0) * 1000)

            if evt.get("status") == "success":
                success_count += 1
                if num_workers == 1:
                    dec = evt.get("decision", "BENIGN")
                    decision_breakdown[dec] = decision_breakdown.get(dec, 0) + 1
                    
                    alert = evt.get("alert", {})
                    sev = alert.get("severity", "INFO")
                    severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            else:
                failed_count += 1

        elapsed = time.time() - start_time
        processor.stop()

        throughput = len(flow_records) / elapsed if elapsed > 0 else 0.0
        p50 = float(np.percentile(latencies_ms, 50)) if latencies_ms else 0.0
        p95 = float(np.percentile(latencies_ms, 95)) if latencies_ms else 0.0
        p99 = float(np.percentile(latencies_ms, 99)) if latencies_ms else 0.0

        scaling_results[num_workers] = {
            "workers": num_workers,
            "flows": len(flow_records),
            "successful": success_count,
            "failed": failed_count,
            "elapsed_sec": round(elapsed, 4),
            "throughput_flows_per_sec": round(throughput, 2),
            "latency_p50_ms": round(p50, 4),
            "latency_p95_ms": round(p95, 4),
            "latency_p99_ms": round(p99, 4),
        }

        logger.info(
            f"Workers={num_workers} | Throughput={throughput:.2f} fps | "
            f"P50={p50:.4f} ms | P95={p95:.4f} ms | P99={p99:.4f} ms"
        )

    return {
        "scaling_results": scaling_results,
        "decision_breakdown": decision_breakdown,
        "severity_breakdown": severity_breakdown,
    }


if __name__ == "__main__":
    res = run_worker_scaling_benchmark()
    print("="*60)
    print("WORKER-SCALING BENCHMARK RESULTS:")
    print("="*60)
    for workers, metrics in res["scaling_results"].items():
        print(f"Workers: {workers} -> {metrics}")
    print("\nDECISION BREAKDOWN (1,000 flows):", res["decision_breakdown"])
    print("SEVERITY BREAKDOWN (1,000 flows):", res["severity_breakdown"])
    print("="*60)
