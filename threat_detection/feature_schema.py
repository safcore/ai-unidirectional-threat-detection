"""
feature_schema.py
==================

Defines the stable contract between upstream Feature Extraction and this
Threat Detection module. Milestone 1 covers the flow-level + TCP fields
needed for DDoS and Port Scan detection. DNS/TLS/behavioural fields will
be added in later milestones (see README "Extending the schema").

NOTE: Field names and types here are a CONTRACT other teammates depend on.
Do not rename fields casually once the backend integrates against them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP"}


@dataclass(frozen=True)
class FeatureRecord:
    """
    A single flow-level feature record.

    All fields are required unless a default is given. Fields with
    defaults are optional in Milestone 1 because not every upstream
    extractor will populate them yet (e.g. unique_dst_ports is only
    meaningful once per-source aggregation exists).
    """

    flow_id: str
    timestamp: str  # ISO-8601, e.g. "2026-09-02T12:30:00Z"

    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: str  # one of SUPPORTED_PROTOCOLS

    packet_count: int
    byte_count: int

    flow_duration: float  # seconds

    packet_rate: float  # packets/sec
    byte_rate: float  # bytes/sec

    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    # Optional: only meaningful if the extractor tracks it per-flow.
    # The Port Scan detector primarily derives this itself from
    # per-source state, but if upstream already computed it, we use it
    # as an additional signal.
    unique_dst_ports: Optional[int] = None

    def parsed_timestamp(self) -> datetime:
        """Parse the ISO-8601 timestamp into a timezone-aware datetime."""
        ts = self.timestamp
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    @staticmethod
    def from_dict(data: dict) -> "FeatureRecord":
        """
        Build a FeatureRecord from a raw dict (e.g. JSON from the queue).
        Does NOT validate semantics -- use validator.validate_feature()
        for that. This only maps known keys and ignores unknown ones so
        that upstream schema growth doesn't break Milestone 1.
        """
        known_fields = {f for f in FeatureRecord.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return FeatureRecord(**filtered)
