"""
CLI Benchmark Runner Script.

Loads validation.csv with nrows=1000 and runs integrated system performance benchmarking.
"""

import time
import logging
import pandas as pd
from pathlib import Path
from ml.training.loader import load_feature_schema, validate_and_extract_features
from ml.evaluation.integration_benchmark import run_integration_benchmark

logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
VAL_PATH = BASE_DIR / "ml" / "data" / "validation.csv"

def main():
    schema = load_feature_schema()
    df_val = pd.read_csv(VAL_PATH, nrows=1000, low_memory=False)
    X_val, _ = validate_and_extract_features(df_val, schema)
    
    results = run_integration_benchmark(X_val, num_samples=1000)
    print("="*60)
    print("INTEGRATED REAL-TIME DETECTION PIPELINE BENCHMARK RESULTS:")
    print("="*60)
    for k, v in results.items():
        print(f"  {k}: {v}")
    print("="*60)

if __name__ == "__main__":
    main()
