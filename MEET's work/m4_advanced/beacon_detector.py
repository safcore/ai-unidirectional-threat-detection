"""
M4 — C2 Beacon Detector (FFT Periodicity Analysis)
====================================================
Detects Command & Control beaconing by analysing the inter-flow
arrival times of repeated connections from the same source to
the same destination.

Algorithm:
  1. Track inter-flow gaps (seconds) per (src_ip, dst_ip) pair.
  2. When >= MIN_SAMPLES gaps collected, run FFT on the gap series.
  3. If the dominant frequency has power significantly above the mean
     → periodic signal detected → C2 beacon alert.
  4. Also check coefficient of variation: very regular gaps (low CoV)
     are suspicious even without a clear FFT peak.

No model file needed — pure signal processing.
"""

import math
import time
import logging
import threading
from collections import defaultdict, deque
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _fft_dominant_power_ratio(series: List[float]) -> float:
    """
    Compute the ratio of the dominant FFT bin power to the mean power.
    A ratio >> 1 indicates periodicity.
    Uses a simplified Goertzel / manual DFT for stdlib-only operation.
    """
    n = len(series)
    if n < 4:
        return 0.0

    # Subtract mean (DC component)
    mean = sum(series) / n
    x = [v - mean for v in series]

    # Compute DFT magnitudes for frequencies 1..n//2
    max_mag = 0.0
    total_power = 0.0
    for k in range(1, n // 2 + 1):
        re = sum(x[i] * math.cos(2 * math.pi * k * i / n) for i in range(n))
        im = sum(x[i] * math.sin(2 * math.pi * k * i / n) for i in range(n))
        mag = math.sqrt(re * re + im * im)
        total_power += mag
        if mag > max_mag:
            max_mag = mag

    mean_power = total_power / (n // 2) if n > 2 else 1.0
    return max_mag / mean_power if mean_power > 0 else 0.0


def _coeff_of_variation(series: List[float]) -> float:
    """CoV = std/mean. Low CoV → regular → beacon-like."""
    n = len(series)
    if n < 2:
        return 1.0
    mu = sum(series) / n
    if mu == 0:
        return 0.0
    variance = sum((v - mu) ** 2 for v in series) / (n - 1)
    return math.sqrt(variance) / mu


class BeaconDetector:
    """
    Tracks inter-flow timing for each (src_ip, dst_ip) pair.
    Fires an alert when periodicity is detected via FFT or low CoV.
    """

    # Tuneable parameters
    MIN_SAMPLES      = 6      # minimum flows before analysis
    MAX_SAMPLES      = 60     # rolling window size
    FFT_RATIO_THRESH = 5.0    # dominant/mean power ratio threshold
    COV_THRESH       = 0.25   # CoV below this → very regular → beacon
    MAX_IAT_SEC      = 600.0  # ignore gaps > 10 min (likely session end)
    ALERT_COOLDOWN   = 60.0   # seconds between repeat alerts per pair

    def __init__(self, alert_handler: Optional[Callable] = None):
        self._handlers: List[Callable] = []
        if alert_handler:
            self._handlers.append(alert_handler)

        self._lock = threading.Lock()
        # (src_ip, dst_ip) → deque of (timestamp_of_flow_start, duration)
        self._flow_times: Dict[Tuple[str,str], deque] = defaultdict(
            lambda: deque(maxlen=self.MAX_SAMPLES)
        )
        self._alerted: Dict[Tuple[str,str], float] = {}

    def add_handler(self, h: Callable):
        self._handlers.append(h)

    def predict(self, feats: dict):
        """Called per completed flow from FeatureExtractor."""
        src_ip = feats.get("src_ip", "")
        dst_ip = feats.get("dst_ip", "")
        ts     = feats.get("start_time", time.time())
        pair   = (src_ip, dst_ip)

        with self._lock:
            dq = self._flow_times[pair]
            dq.append(ts)
            timestamps = list(dq)

        if len(timestamps) < self.MIN_SAMPLES:
            return

        # Compute inter-flow arrival times (gaps between successive flows)
        gaps = [
            timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps) - 1)
            if 0 < timestamps[i+1] - timestamps[i] <= self.MAX_IAT_SEC
        ]

        if len(gaps) < self.MIN_SAMPLES - 1:
            return

        cov         = _coeff_of_variation(gaps)
        fft_ratio   = _fft_dominant_power_ratio(gaps)
        mean_gap    = sum(gaps) / len(gaps)

        # Scoring
        score = 0.0
        if fft_ratio >= self.FFT_RATIO_THRESH:
            score += 0.5 + min((fft_ratio - self.FFT_RATIO_THRESH) / 10, 0.3)
        if cov <= self.COV_THRESH:
            score += 0.4 + (self.COV_THRESH - cov) / self.COV_THRESH * 0.2
        score = min(score, 1.0)

        if score < 0.5:
            return

        # Cooldown
        now = time.time()
        last_alert = self._alerted.get(pair, 0)
        if now - last_alert < self.ALERT_COOLDOWN:
            return

        with self._lock:
            self._alerted[pair] = now

        confidence = round(score, 4)
        alert = {
            "threat_class":   "BEACON",
            "threat_subtype": "C2_BEACONING",
            "confidence":     confidence,
            "severity":       "CRITICAL" if confidence > 0.85 else "HIGH",
            "evidence": {
                "mean_interval_sec": round(mean_gap, 2),
                "coeff_of_variation": round(cov, 3),
                "fft_power_ratio":   round(fft_ratio, 2),
                "sample_count":      len(gaps),
                "dst_port":          feats.get("dst_port", 0),
            },
            **{k: feats[k] for k in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"] if k in feats},
        }
        for h in self._handlers:
            try:
                h(alert)
            except Exception as e:
                logger.error("Beacon handler error: %s", e)
