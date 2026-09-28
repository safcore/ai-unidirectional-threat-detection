"""
M3 — DDoS Detector (Random Forest + Threshold Rules)
======================================================
Detects:
  • SYN floods      — high SYN ratio + high src_ip entropy + high pkt_rate
  • UDP floods      — large UDP payload + high dst_pkt_rate
  • ICMP floods     — high pps to single destination
  • Spoofed floods  — high source-IP entropy (many unique /24 subnets)

Model: Random Forest trained on synthetic + CIC-IDS2017 features.
Fallback: Pure threshold rules when model not loaded.
"""

import os
import math
import pickle
import logging
import threading
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "ddos_rf.pkl")

# ── Feature set used by the Random Forest ─────────────────────────────────────
DDOS_FEATURES = [
    "syn_ratio", "ack_ratio", "rst_ratio", "pkt_count", "pkts_per_sec",
    "bytes_per_sec", "mean_pkt_size", "src_ip_entropy", "dst_pkt_rate",
    "mean_iat", "std_iat", "duration", "syn_no_ack",
]


def _feature_vector(feats: dict) -> List[float]:
    return [float(feats.get(k, 0.0)) for k in DDOS_FEATURES]


# ── Threshold rules (always active, model is additive) ───────────────────────

def _rule_based_score(feats: dict) -> float:
    """
    Returns a threat score 0–1 based on threshold rules.
    Combined with model confidence for final score.
    """
    score = 0.0

    syn_ratio     = feats.get("syn_ratio", 0)
    pkt_rate      = feats.get("pkts_per_sec", 0)
    src_entropy   = feats.get("src_ip_entropy", 0)
    dst_pkt_rate  = feats.get("dst_pkt_rate", 0)
    mean_pkt_size = feats.get("mean_pkt_size", 0)
    proto         = feats.get("protocol", "")
    byte_rate     = feats.get("bytes_per_sec", 0)
    syn_no_ack    = feats.get("syn_no_ack", 0)

    # SYN flood heuristics
    if syn_ratio > 0.85 and pkt_rate > 500:
        score += 0.4
    if syn_no_ack and pkt_rate > 200:
        score += 0.3
    if src_entropy > 3.5:   # high source diversity = spoofed
        score += 0.2
    if dst_pkt_rate > 1000:
        score += 0.2

    # UDP amplification
    if proto == "UDP" and mean_pkt_size > 400 and byte_rate > 50_000:
        score += 0.5

    return min(score, 1.0)


class DDoSDetector:
    """
    DDoS detector combining Random Forest model + threshold rules.
    Emits Alert dicts via registered handler callbacks.
    """

    THRESHOLD = 0.55   # confidence threshold to fire an alert

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
                logger.info("DDoS RF model loaded from %s", MODEL_PATH)
            except Exception as e:
                logger.warning("Could not load DDoS model: %s — using rules only", e)

    def predict(self, feats: dict):
        """Called per flow from FeatureExtractor."""
        rule_score = _rule_based_score(feats)

        model_score = 0.0
        if self._model is not None:
            try:
                vec = [_feature_vector(feats)]
                proba = self._model.predict_proba(vec)[0]
                # Class index 1 = attack (convention from training)
                model_score = float(proba[1]) if len(proba) > 1 else 0.0
            except Exception as e:
                logger.debug("DDoS model predict error: %s", e)

        # Combine: if model loaded, weight 60/40; else rule only
        if self._model:
            confidence = 0.6 * model_score + 0.4 * rule_score
        else:
            confidence = rule_score

        if confidence >= self.THRESHOLD:
            # Determine sub-type
            if feats.get("protocol") == "UDP" and feats.get("mean_pkt_size", 0) > 400:
                threat_subtype = "UDP_AMPLIFICATION"
            elif feats.get("syn_ratio", 0) > 0.7:
                threat_subtype = "SYN_FLOOD"
            else:
                threat_subtype = "VOLUMETRIC_DDOS"

            alert = {
                "threat_class": "DDOS",
                "threat_subtype": threat_subtype,
                "confidence": round(confidence, 4),
                "severity": "CRITICAL" if confidence > 0.85 else "HIGH",
                "evidence": {
                    "syn_ratio":      round(feats.get("syn_ratio", 0), 3),
                    "pkts_per_sec":   round(feats.get("pkts_per_sec", 0), 1),
                    "src_ip_entropy": round(feats.get("src_ip_entropy", 0), 3),
                    "dst_pkt_rate":   round(feats.get("dst_pkt_rate", 0), 1),
                    "mean_pkt_size":  round(feats.get("mean_pkt_size", 0), 1),
                    "protocol":       feats.get("protocol", ""),
                },
                **{k: feats[k] for k in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"] if k in feats},
            }
            self._dispatch(alert)

    def _dispatch(self, alert: dict):
        for h in self._handlers:
            try:
                h(alert)
            except Exception as e:
                logger.error("DDoS alert handler error: %s", e)
