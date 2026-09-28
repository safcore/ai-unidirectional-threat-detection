"""
M4 — Data Exfiltration Detector
=================================
Detects anomalous outbound data transfers using:
  1. Outbound/inbound byte ratio anomaly per host pair (window-based)
  2. Session-level byte count vs. typical profile
  3. Large single-flow byte count to unusual destinations
  4. Isolation Forest on flow volume features (optional model)

Features used:
  • outbound_ratio    (from M2 ByteRatioTracker)
  • byte_count        (total bytes in flow)
  • bytes_per_sec     (data rate)
  • duration          (session length)
  • dst_port          (unusual ports = suspicious)
  • dst_ip            (private vs. public)
"""

import os
import math
import pickle
import logging
from typing import Callable, List, Optional
import ipaddress

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "exfil_iforest.pkl")

EXFIL_FEATURES = [
    "outbound_ratio", "byte_count", "bytes_per_sec",
    "duration", "pkt_count", "mean_pkt_size",
]

# Ports commonly used for exfiltration (non-standard)
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888, 9999,   # reverse shells
    1337, 31337,                            # hacker classics
    6667, 6697,                             # IRC
    53, 80, 443, 8080,                      # covert channels (included for high-vol)
}

LARGE_FLOW_BYTES = 500_000   # 500 KB in a single flow → flag


def _is_private(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except Exception:
        return False


def _rule_score(feats: dict) -> float:
    score = 0.0
    out_ratio  = feats.get("outbound_ratio", 0.5)
    byte_count = feats.get("byte_count", 0)
    bps        = feats.get("bytes_per_sec", 0)
    dst_port   = feats.get("dst_port", 0)
    dst_ip     = feats.get("dst_ip", "")
    src_ip     = feats.get("src_ip", "")

    # Internal → external direction is suspicious for exfil
    is_internal_to_external = _is_private(src_ip) and not _is_private(dst_ip)

    if out_ratio > 0.9 and is_internal_to_external:
        score += 0.4
    elif out_ratio > 0.8:
        score += 0.2

    if byte_count > LARGE_FLOW_BYTES:
        score += 0.3
    if byte_count > 5_000_000:  # 5MB
        score += 0.2

    if bps > 1_000_000 and is_internal_to_external:  # 1 MB/s sustained
        score += 0.2

    if dst_port in SUSPICIOUS_PORTS and byte_count > 10_000:
        score += 0.15

    return min(score, 1.0)


class ExfilDetector:
    """
    Data exfiltration detector combining Isolation Forest + heuristic rules.
    """

    THRESHOLD = 0.55

    def __init__(self, alert_handler: Optional[Callable] = None):
        self._handlers: List[Callable] = []
        if alert_handler:
            self._handlers.append(alert_handler)
        self._model = None
        self._load_model()

    def add_handler(self, h: Callable):
        self._handlers.append(h)

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    self._model = pickle.load(f)
                logger.info("Exfil IForest model loaded")
            except Exception as e:
                logger.warning("Could not load exfil model: %s — rules only", e)

    def predict(self, feats: dict):
        """Called per flow."""
        rule_score = _rule_score(feats)

        model_score = 0.0
        if self._model is not None:
            try:
                vec = [[feats.get(k, 0.0) for k in EXFIL_FEATURES]]
                # IsolationForest: decision_function returns negative = anomaly
                raw = self._model.decision_function(vec)[0]
                # Map to 0-1: lower raw score = more anomalous
                model_score = max(0.0, min(1.0, 0.5 - raw))
            except Exception:
                pass

        confidence = (0.6 * model_score + 0.4 * rule_score) if self._model else rule_score

        if confidence >= self.THRESHOLD:
            src_ip = feats.get("src_ip", "")
            dst_ip = feats.get("dst_ip", "")
            direction = (
                "INTERNAL_TO_EXTERNAL"
                if _is_private(src_ip) and not _is_private(dst_ip)
                else "INTERNAL_TO_INTERNAL" if _is_private(dst_ip)
                else "UNKNOWN"
            )
            alert = {
                "threat_class":   "EXFIL",
                "threat_subtype": "DATA_EXFILTRATION",
                "confidence":     round(confidence, 4),
                "severity":       "CRITICAL" if confidence > 0.85 else "HIGH",
                "evidence": {
                    "outbound_ratio":  round(feats.get("outbound_ratio", 0), 3),
                    "byte_count":      feats.get("byte_count", 0),
                    "bytes_per_sec":   round(feats.get("bytes_per_sec", 0), 1),
                    "direction":       direction,
                    "dst_port":        feats.get("dst_port", 0),
                },
                **{k: feats[k] for k in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"] if k in feats},
            }
            for h in self._handlers:
                try:
                    h(alert)
                except Exception as e:
                    logger.error("Exfil handler error: %s", e)
