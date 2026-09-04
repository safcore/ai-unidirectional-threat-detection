"""
validator.py
============

Treats every incoming FeatureRecord as untrusted input. Validates types,
ranges, and sanity constraints BEFORE it reaches any detector.

Design goal (see PROMPT section 29/30): one malformed record must never
crash the streaming pipeline. Callers should always check `.is_valid`
and log/discard/quarantine invalid records rather than raising.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from typing import List

from .feature_schema import FeatureRecord, SUPPORTED_PROTOCOLS


@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[str] = field(default_factory=list)


def _is_finite_number(value) -> bool:
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _valid_port(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def validate_feature(record: FeatureRecord) -> ValidationResult:
    """
    Validate a FeatureRecord. Returns ValidationResult with all errors
    found (not just the first) so logs are useful for debugging bad
    upstream data.
    """
    errors: List[str] = []

    # --- identifiers ---
    if not record.flow_id or not isinstance(record.flow_id, str):
        errors.append("flow_id must be a non-empty string")

    try:
        record.parsed_timestamp()
    except Exception:
        errors.append(f"timestamp is not valid ISO-8601: {record.timestamp!r}")

    # --- IP addresses ---
    if not _valid_ip(record.src_ip):
        errors.append(f"src_ip is not a valid IP address: {record.src_ip!r}")
    if not _valid_ip(record.dst_ip):
        errors.append(f"dst_ip is not a valid IP address: {record.dst_ip!r}")

    # --- ports ---
    if not _valid_port(record.src_port):
        errors.append(f"src_port out of range 0-65535: {record.src_port!r}")
    if not _valid_port(record.dst_port):
        errors.append(f"dst_port out of range 0-65535: {record.dst_port!r}")

    # --- protocol ---
    if record.protocol not in SUPPORTED_PROTOCOLS:
        errors.append(
            f"protocol {record.protocol!r} not in supported set {SUPPORTED_PROTOCOLS}"
        )

    # --- numeric sanity: non-negative, finite (no NaN/Inf) ---
    numeric_fields = {
        "packet_count": record.packet_count,
        "byte_count": record.byte_count,
        "flow_duration": record.flow_duration,
        "packet_rate": record.packet_rate,
        "byte_rate": record.byte_rate,
        "syn_count": record.syn_count,
        "ack_count": record.ack_count,
        "rst_count": record.rst_count,
        "fin_count": record.fin_count,
    }
    for name, value in numeric_fields.items():
        if not _is_finite_number(value):
            errors.append(f"{name} must be a finite number, got {value!r}")
        elif value < 0:
            errors.append(f"{name} must be >= 0, got {value!r}")

    if record.unique_dst_ports is not None:
        if not isinstance(record.unique_dst_ports, int) or record.unique_dst_ports < 0:
            errors.append(
                f"unique_dst_ports must be a non-negative int, got {record.unique_dst_ports!r}"
            )

    # --- cross-field sanity ---
    if _is_finite_number(record.flow_duration) and record.flow_duration == 0:
        # zero-duration flows make rate-based math meaningless; not fatal,
        # but flag so the engine can treat rates cautiously.
        if record.packet_count > 0 and record.packet_rate == 0:
            errors.append(
                "flow_duration is 0 but packet_count > 0 and packet_rate is 0; "
                "rate fields look uninitialized"
            )

    return ValidationResult(is_valid=(len(errors) == 0), errors=errors)
