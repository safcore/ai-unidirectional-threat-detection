"""
benchmark/throughput_benchmark.py
==================================
PS-26145 Throughput and Latency Benchmark Suite.
Measures real performance across 1,000, 5,000, and 10,000 flow batches:
  - Pipeline: Raw Flow Record -> adapt_to_canonical_66 -> process_detection
  - Metrics: Throughput (flows/sec), Latency (mean, p50, p95, p99 ms),
             Alerts generated, Threat breakdown, Error/drop rate.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from m2_features import adapt_to_canonical_66
from backend.app.m4_integration import process_detection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("benchmark")


def load_test_flows(csv_path: Optional[str] = None, max_needed: int = 10000) -> List[Dict[str, Any]]:
    """
    Load realistic flows from test dataset or generate realistic synthetic flows.
    """
    default_csv = PROJECT_ROOT / "teamwork" / "_inspection" / "SIH PS145" / "AaYuushman's work" / "ml" / "data" / "test.csv"
    target_path = Path(csv_path) if csv_path else default_csv

    flows: List[Dict[str, Any]] = []

    if target_path.exists():
        logger.info("Loading %d flow records from dataset: %s", max_needed, target_path)
        # Read in nrows
        df = pd.read_csv(target_path, nrows=max_needed)
        records = df.to_dict(orient="records")
        for i, row in enumerate(records):
            row["src_ip"] = f"192.168.1.{10 + (i % 250)}"
            row["dst_ip"] = f"10.0.0.{1 + (i % 20)}"
            row["src_port"] = 1024 + (i % 60000)
            row["dst_port"] = int(row.get("Destination Port", 80))
            row["protocol"] = "TCP"
        flows = records
        logger.info("Successfully loaded %d records from CSV.", len(flows))
    else:
        logger.info("Dataset CSV not found at %s. Generating %d synthetic flow records...", target_path, max_needed)
        # Generate varied synthetic flows (DDoS, benign, port scan, etc.)
        np.random.seed(42)
        for i in range(max_needed):
            is_attack = (i % 3 == 0)
            flows.append({
                "Destination Port": 80 if is_attack else np.random.choice([80, 443, 22, 53, 8080]),
                "Flow Duration": np.random.uniform(100, 100000) if is_attack else np.random.uniform(10000, 5000000),
                "Total Fwd Packets": np.random.randint(50, 500) if is_attack else np.random.randint(1, 20),
                "Total Backward Packets": np.random.randint(0, 5) if is_attack else np.random.randint(1, 20),
                "Total Length of Fwd Packets": np.random.uniform(5000, 50000),
                "Total Length of Bwd Packets": np.random.uniform(0, 5000),
                "Fwd Packet Length Max": np.random.uniform(100, 1500),
                "Fwd Packet Length Min": 0,
                "Fwd Packet Length Mean": np.random.uniform(40, 500),
                "Fwd Packet Length Std": np.random.uniform(10, 200),
                "Bwd Packet Length Max": np.random.uniform(0, 1500),
                "Bwd Packet Length Min": 0,
                "Bwd Packet Length Mean": np.random.uniform(0, 500),
                "Bwd Packet Length Std": np.random.uniform(0, 200),
                "Flow Bytes/s": np.random.uniform(10000, 1000000),
                "Flow Packets/s": np.random.uniform(100, 10000),
                "Flow IAT Mean": np.random.uniform(10, 1000),
                "Flow IAT Std": np.random.uniform(5, 500),
                "Flow IAT Max": np.random.uniform(50, 5000),
                "Flow IAT Min": np.random.uniform(1, 50),
                "src_ip": f"192.168.1.{10 + (i % 200)}",
                "dst_ip": f"10.0.0.{1 + (i % 10)}",
                "src_port": 1024 + (i % 60000),
                "dst_port": 80 if is_attack else 443,
                "protocol": "TCP",
            })

    # If we need more rows than loaded, repeat cyclically
    if len(flows) < max_needed:
        multiplier = (max_needed // len(flows)) + 1
        flows = (flows * multiplier)[:max_needed]

    return flows[:max_needed]


from backend.app.m4_integration import process_detection, process_detection_batch


def benchmark_batch(flows: List[Dict[str, Any]], batch_size: int, chunk_size: int = 500) -> Dict[str, Any]:
    """
    Run benchmark for a given batch size of flows through the end-to-end pipeline:
      adapt_to_canonical_66 -> process_detection_batch
    """
    batch = flows[:batch_size]
    latencies_ms: List[float] = []
    alerts_generated = 0
    threat_counts: Dict[str, int] = {}
    errors = 0

    logger.info("=== Running Benchmark Batch: %d flows (chunk_size=%d) ===", batch_size, chunk_size)

    # Warm-up with 5 flows
    for warmup_flow in batch[:5]:
        try:
            feat, meta = adapt_to_canonical_66(warmup_flow)
            process_detection(feat, meta)
        except Exception:
            pass

    batch_start = time.perf_counter()

    for offset in range(0, len(batch), chunk_size):
        chunk = batch[offset : offset + chunk_size]
        t0 = time.perf_counter()
        try:
            feats = []
            metas = []
            for flow in chunk:
                feat, meta = adapt_to_canonical_66(flow)
                feats.append(feat)
                metas.append(meta)

            results = process_detection_batch(feats, metas)
            t1 = time.perf_counter()
            per_flow_lat = ((t1 - t0) * 1000.0) / len(chunk)
            latencies_ms.extend([per_flow_lat] * len(chunk))

            for event, incident, alert in results:
                threat = alert.get("threat", "BENIGN")
                if threat and threat.upper() != "BENIGN":
                    alerts_generated += 1
                    threat_counts[threat] = threat_counts.get(threat, 0) + 1

        except Exception as exc:
            t1 = time.perf_counter()
            per_flow_lat = ((t1 - t0) * 1000.0) / max(1, len(chunk))
            latencies_ms.extend([per_flow_lat] * len(chunk))
            errors += len(chunk)
            logger.warning("Error processing flow chunk at %d: %s", offset, exc)

    batch_elapsed = time.perf_counter() - batch_start
    throughput = len(batch) / batch_elapsed if batch_elapsed > 0 else 0.0

    lat_arr = np.array(latencies_ms)
    p50 = float(np.percentile(lat_arr, 50))
    p90 = float(np.percentile(lat_arr, 90))
    p95 = float(np.percentile(lat_arr, 95))
    p99 = float(np.percentile(lat_arr, 99))
    mean_lat = float(np.mean(lat_arr))
    min_lat = float(np.min(lat_arr))
    max_lat = float(np.max(lat_arr))

    result = {
        "flows_processed": len(batch),
        "elapsed_sec": round(batch_elapsed, 4),
        "throughput_fps": round(throughput, 2),
        "latency_ms": {
            "mean": round(mean_lat, 4),
            "p50": round(p50, 4),
            "p90": round(p90, 4),
            "p95": round(p95, 4),
            "p99": round(p99, 4),
            "min": round(min_lat, 4),
            "max": round(max_lat, 4),
        },
        "alerts_generated": alerts_generated,
        "threat_counts": threat_counts,
        "errors": errors,
        "error_rate_pct": round((errors / len(batch)) * 100, 2),
    }

    logger.info(
        "Batch %d complete: %.2f flows/sec | Latency p50: %.4f ms, p95: %.4f ms | Alerts: %d | Errors: %d",
        batch_size, throughput, p50, p95, alerts_generated, errors,
    )
    return result


def run_full_benchmark(
    batch_sizes: Optional[List[int]] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    if batch_sizes is None:
        batch_sizes = [1000, 5000, 10000]

    max_needed = max(batch_sizes)
    flows = load_test_flows(max_needed=max_needed)

    results: Dict[str, Any] = {
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hardware_environment": {
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
        },
        "pipeline_stages": [
            "M1/M2: Ingestion & Feature Normalization (adapt_to_canonical_66)",
            "M3: Supervised Classification (Random Forest / DDoS / PortScan)",
            "M4: Behavioral Anomaly Detection & Investigation (Isolation Forest, C2, DGA, Exfil, TLS)",
            "M5: Canonical Alert Normalization (shared/alert_schema.json)",
        ],
        "batches": {},
    }

    for size in batch_sizes:
        batch_res = benchmark_batch(flows, size)
        results["batches"][str(size)] = batch_res

    # Overall summary metrics
    results["summary"] = {
        "tested_scales": batch_sizes,
        "peak_throughput_fps": max(b["throughput_fps"] for b in results["batches"].values()),
        "average_p50_latency_ms": round(float(np.mean([b["latency_ms"]["p50"] for b in results["batches"].values()])), 4),
        "average_p95_latency_ms": round(float(np.mean([b["latency_ms"]["p95"] for b in results["batches"].values()])), 4),
        "total_flows_evaluated": sum(b["flows_processed"] for b in results["batches"].values()),
        "total_alerts_generated": sum(b["alerts_generated"] for b in results["batches"].values()),
        "total_errors": sum(b["errors"] for b in results["batches"].values()),
    }

    out_file = Path(output_path) if output_path else PROJECT_ROOT / "benchmark" / "benchmark_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info("Benchmark results saved to: %s", out_file)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run PS-26145 Throughput Benchmark")
    parser.add_argument("--sizes", nargs="+", type=int, default=[1000, 5000, 10000],
                        help="Batch sizes to evaluate (default: 1000 5000 10000)")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    res = run_full_benchmark(batch_sizes=args.sizes, output_path=args.output)
    print("\n" + "=" * 60)
    print("PS-26145 BENCHMARK RESULTS SUMMARY")
    print("=" * 60)
    for size, b in res["batches"].items():
        print(f"Scale: {size:>5} flows | Throughput: {b['throughput_fps']:>8.2f} flows/sec | "
              f"P50 Latency: {b['latency_ms']['p50']:>6.4f} ms | P95 Latency: {b['latency_ms']['p95']:>6.4f} ms | "
              f"Alerts: {b['alerts_generated']:>5} | Errors: {b['errors']}")
    print("=" * 60)
    print(f"Peak Throughput: {res['summary']['peak_throughput_fps']:.2f} flows/sec")
    print("=" * 60)
