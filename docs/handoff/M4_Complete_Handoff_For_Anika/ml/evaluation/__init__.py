"""
Evaluation utilities package for Phase 2.
"""

from .metrics import evaluate_classification, benchmark_inference_speed

__all__ = ["evaluate_classification", "benchmark_inference_speed"]
