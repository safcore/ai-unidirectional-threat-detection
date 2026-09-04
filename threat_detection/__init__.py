"""
threat_detection
=================

Passive, read-only network threat detection engine for SIH PS 26145
(AI-Based Detection of Cyber Threats in Unidirectional IP Traffic).

This package NEVER sends, injects, modifies, or blocks traffic. It only
consumes flow/feature metadata and produces structured alerts.

Milestone 1 scope:
    - Feature schema (feature_schema.py)
    - Input validation (validator.py)
    - DDoS rule detector (rules/ddos.py)
    - Port scan rule detector (rules/port_scan.py)
    - Severity engine (alerts/severity.py)
    - Evidence engine (alerts/evidence.py)
    - Alert generator (alerts/generator.py)
    - Orchestration engine (engine.py)
"""

from .engine import ThreatDetectionEngine

__all__ = ["ThreatDetectionEngine"]
__version__ = "0.1.0"
