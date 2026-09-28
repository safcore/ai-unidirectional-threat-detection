"""
M4 — DGA Domain Detector
=========================
Detects algorithmically generated domains (DGA) using:
  1. Shannon entropy of the domain name
  2. Bigram n-gram perplexity (vs. English language model)
  3. Vowel/consonant ratio
  4. Numeric character ratio
  5. Domain length
  6. Random Forest classifier (trained on DGArchive + Alexa Top-1M)

Fallback: pure statistical scoring if model not loaded.
"""

import os
import math
import pickle
import logging
import random
from collections import defaultdict
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "dga_rf.pkl")

# ── English bigram log-probabilities (simplified approximation) ──────────────
# Built from letter frequency analysis of English text.
# Higher = more natural; lower = more random/DGA-like.
ENGLISH_BIGRAMS = {
    "th": -2.7, "he": -2.9, "in": -3.0, "er": -3.1, "an": -3.2,
    "re": -3.3, "on": -3.4, "at": -3.5, "en": -3.5, "nd": -3.6,
    "ti": -3.7, "es": -3.7, "or": -3.8, "te": -3.9, "of": -4.0,
    "ed": -4.0, "is": -4.1, "it": -4.2, "al": -4.2, "ar": -4.3,
    "st": -4.3, "to": -4.4, "nt": -4.5, "ng": -4.5, "se": -4.6,
    "ha": -4.6, "as": -4.7, "ou": -4.7, "io": -4.8, "le": -4.8,
    "ve": -4.9, "co": -5.0, "me": -5.0, "de": -5.1, "hi": -5.1,
    "ri": -5.2, "ro": -5.2, "ic": -5.3, "ne": -5.3, "ea": -5.4,
}
DEFAULT_BIGRAM_LOGPROB = -8.0   # unknown bigram → very unlikely English


def _bigram_perplexity(domain: str) -> float:
    """
    Compute perplexity of a domain name under an English bigram model.
    Lower perplexity = more English-like. Higher = more DGA-like.
    """
    domain = domain.lower()
    if len(domain) < 2:
        return 0.0
    log_prob = 0.0
    n = 0
    for i in range(len(domain) - 1):
        bg = domain[i:i+2]
        if bg.isalpha():
            log_prob += ENGLISH_BIGRAMS.get(bg, DEFAULT_BIGRAM_LOGPROB)
            n += 1
    if n == 0:
        return 999.0
    avg_log_prob = log_prob / n
    perplexity = math.exp(-avg_log_prob)
    return perplexity


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_domain_features(domain: str) -> dict:
    """Extract lexical features from a domain name for DGA detection."""
    name = domain.split(".")[0] if "." in domain else domain
    name_lower = name.lower()
    length = len(name_lower)

    vowels = sum(1 for c in name_lower if c in "aeiou")
    consonants = sum(1 for c in name_lower if c.isalpha() and c not in "aeiou")
    digits = sum(1 for c in name_lower if c.isdigit())

    return {
        "length":         length,
        "entropy":        _shannon_entropy(name_lower),
        "perplexity":     _bigram_perplexity(name_lower),
        "vowel_ratio":    vowels / max(length, 1),
        "digit_ratio":    digits / max(length, 1),
        "hyphen_count":   name_lower.count("-"),
        "unique_chars":   len(set(name_lower)),
        "longest_consonant_run": _longest_consonant_run(name_lower),
    }


def _longest_consonant_run(s: str) -> int:
    """Length of the longest run of consecutive consonants."""
    CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
    max_run = cur_run = 0
    for c in s:
        if c in CONSONANTS:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 0
    return max_run


DGA_FEATURE_KEYS = ["length", "entropy", "perplexity", "vowel_ratio", "digit_ratio",
                    "hyphen_count", "unique_chars", "longest_consonant_run"]


class DGADetector:
    """
    DGA domain detector using statistical features + optional Random Forest.
    Called per DNS flow from FeatureExtractor.
    """

    THRESHOLD = 0.60

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
                logger.info("DGA RF model loaded from %s", MODEL_PATH)
            except Exception as e:
                logger.warning("Could not load DGA model: %s — rules only", e)

    def predict(self, feats: dict):
        """Called per flow. Only processes DNS flows."""
        if not feats.get("is_dns"):
            return

        # Get DNS features
        dns_entropy   = feats.get("dns_entropy", 0.0)
        dns_query_len = feats.get("dns_query_len", 0)
        ngram_score   = feats.get("dns_ngram_score", 0.0)

        if dns_query_len < 4:
            return  # Too short to be meaningful

        # Rule-based score
        rule_score = 0.0
        if dns_entropy > 3.5:
            rule_score += 0.35
        if dns_entropy > 4.0:
            rule_score += 0.20
        if ngram_score > 0.6:
            rule_score += 0.25
        if dns_query_len > 16:
            rule_score += 0.15
        rule_score = min(rule_score, 1.0)

        # Model score (from raw flow features vector)
        model_score = 0.0
        if self._model is not None:
            try:
                vec = [[feats.get(k, 0.0) for k in DGA_FEATURE_KEYS]]
                proba = self._model.predict_proba(vec)[0]
                model_score = float(proba[1]) if len(proba) > 1 else 0.0
            except Exception:
                pass

        confidence = (0.5 * model_score + 0.5 * rule_score) if self._model else rule_score

        if confidence >= self.THRESHOLD:
            alert = {
                "threat_class":   "DGA",
                "threat_subtype": "DGA_DOMAIN",
                "confidence":     round(confidence, 4),
                "severity":       "HIGH" if confidence > 0.8 else "MEDIUM",
                "evidence": {
                    "dns_entropy":    round(dns_entropy, 3),
                    "dns_query_len":  dns_query_len,
                    "ngram_score":    round(ngram_score, 3),
                },
                **{k: feats[k] for k in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"] if k in feats},
            }
            for h in self._handlers:
                try:
                    h(alert)
                except Exception as e:
                    logger.error("DGA handler error: %s", e)
