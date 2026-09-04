"""
Detection and Threshold Settings Configuration Module.

Stores configurable decision thresholds and alert mapping parameters.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DetectionConfig:
    """Configurable thresholds and settings for the detection engine."""

    # Decision Thresholds
    malicious_confidence_threshold: float = 0.80
    benign_confidence_threshold: float = 0.80
    anomaly_threshold: float = 0.70

    # High Severity Attack Classes (Assigned CRITICAL / HIGH severity)
    critical_attack_classes: List[str] = field(
        default_factory=lambda: ["DDOS", "DOS", "BOTNET", "BRUTE_FORCE", "INFILTRATION"]
    )

    # Queue Configs for Stream Processing
    max_queue_size: int = 10000
    worker_threads: int = 2


_config_instance = None


def get_detection_config() -> DetectionConfig:
    """Get singleton DetectionConfig instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = DetectionConfig()
    return _config_instance
