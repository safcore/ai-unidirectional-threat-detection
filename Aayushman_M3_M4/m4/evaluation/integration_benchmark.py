"""
Integration Benchmark Module for Phase 3.

Measures real-time integrated detection pipeline performance:
  - Throughput (flows/sec)
  - Latency percentiles: P50 (median), P95 (95th percentile), P99 (99th percentile) in milliseconds
  - Queue depth & validation failure rates
"""

import time
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from ml.detection.detection_engine import get_detection_engine

logger = logging.getLogger(__name__)


def run_integration_benchmark(X_val_sample: pd.DataFrame, num_samples: int = 2000) -> Dict[str, Any]:
    """
    Benchmark integrated DetectionEngine.process() latency and throughput.
    """
    logger.info(f"Running Integrated System Benchmark on {min(len(X_val_sample), num_samples):,} validation flow vectors...")
    engine = get_detection_engine()

    sample_rows = X_val_sample.head(num_samples).to_dict(orient="records")
    
    latencies_ms: List[float] = []
    success_count = 0
    validation_err_count = 0
    alerts_count = 0

    # Warmup
    for row in sample_rows[:10]:
        _ = engine.process(row)

    total_start = time.time()
    for row in sample_rows:
        t0 = time.time()
        event = engine.process(row)
        t1 = time.time()
        
        latencies_ms.append((t1 - t0) * 1000)

        if event.get("status") == "success":
            success_count += 1
            if event.get("decision") != "BENIGN":
                alerts_count += 1
        else:
            validation_err_count += 1

    total_time_sec = time.time() - total_start

    p50_latency = float(np.percentile(latencies_ms, 50))
    p95_latency = float(np.percentile(latencies_ms, 95))
    p99_latency = float(np.percentile(latencies_ms, 99))
    throughput_fps = len(sample_rows) / total_time_sec if total_time_sec > 0 else 0.0

    logger.info(f"Benchmark Complete -> Throughput: {throughput_fps:.2f} flows/sec | P50: {p50_latency:.4f} ms | P95: {p95_latency:.4f} ms | P99: {p99_latency:.4f} ms")

    return {
        "flows_benchmarked": len(sample_rows),
        "total_time_sec": round(total_time_sec, 4),
        "throughput_flows_per_sec": round(throughput_fps, 2),
        "latency_p50_ms": round(p50_latency, 4),
        "latency_p95_ms": round(p95_latency, 4),
        "latency_p99_ms": round(p99_latency, 4),
        "successful_inferences": success_count,
        "validation_failures": validation_err_count,
        "alerts_generated": alerts_count,
    }
