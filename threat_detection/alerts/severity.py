"""
alerts/severity.py
===================

Severity is deliberately a SEPARATE concept from confidence
(PROMPT section 17): confidence says "how sure are we this detection is
real", severity says "how bad would it be if it's real". A very-high-
confidence, low-intensity port scan is still less severe than a
very-high-confidence, massive-volume DDoS.

This module is intentionally simple in Milestone 1 (confidence bands +
a couple of threat-specific "force critical" overrides). It can grow
richer intensity modelling later without changing its public interface.
"""

from __future__ import annotations

from enum import Enum

from ..config_loader import load_config
from ..feature_schema import FeatureRecord


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def compute_severity(
    threat_class: str,
    confidence: float,
    feature: FeatureRecord,
    config: dict | None = None,
) -> Severity:
    cfg = (config or load_config())["severity"]

    # Threat-specific overrides: extreme intensity forces CRITICAL
    # regardless of confidence banding, because the operational impact
    # is severe even if we're not maximally certain.
    if threat_class == "DDoS" and feature.packet_rate >= cfg["ddos_critical_packet_rate"]:
        return Severity.CRITICAL

    if (
        threat_class == "PortScan"
        and feature.unique_dst_ports is not None
        and feature.unique_dst_ports >= cfg["port_scan_critical_unique_ports"]
    ):
        return Severity.CRITICAL

    # Default: confidence-banded severity.
    if confidence >= cfg["confidence_critical"]:
        return Severity.CRITICAL
    if confidence >= cfg["confidence_high"]:
        return Severity.HIGH
    if confidence >= cfg["confidence_medium"]:
        return Severity.MEDIUM
    if confidence > 0:
        return Severity.LOW
    return Severity.INFO
