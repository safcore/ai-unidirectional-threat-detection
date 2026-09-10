"""
Domain Generation Algorithm (DGA) Detector Module.

Analyzes domain strings for algorithmic lexical randomness, high Shannon entropy,
unusual character distributions, digit ratios, and suspicious TLD patterns.
"""

import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

from m4_threat_classifier.feature_engineering.domain_features import DomainFeatureExtractor

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {".ru", ".xyz", ".top", ".tk", ".biz", ".info", ".cn", ".work", ".click"}


@dataclass
class DGAResult:
    """Structured DGA Detection Result."""
    domain: str
    dga_score: float        # 0.0 to 1.0
    classification: str     # NORMAL / SUSPICIOUS / LIKELY_DGA
    features: Dict[str, Any]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DGADetector:
    """
    Modular Lexical & Structural DGA Detector.
    """

    def __init__(self):
        self.feature_extractor = DomainFeatureExtractor()

    def analyze_domain(self, domain: str) -> DGAResult:
        """
        Analyze input domain string and return DGA classification result.
        """
        if not domain or not isinstance(domain, str) or not domain.strip():
            return DGAResult(
                domain=str(domain) if domain else "",
                dga_score=0.0,
                classification="NORMAL",
                features={},
                reason="Empty or invalid domain input.",
            )

        cleaned_domain = domain.lower().strip()
        raw_feats = self.feature_extractor.extract_features(cleaned_domain)

        domain_len = int(raw_feats.get("domain_length", 0))
        label_len = int(raw_feats.get("main_label_length", 0))
        entropy = float(raw_feats.get("domain_entropy", 0.0))
        unique_char_ratio = float(raw_feats.get("unique_char_ratio", 0.0))
        num_digits = int(raw_feats.get("num_digits", 0))
        digit_ratio = round(num_digits / domain_len, 4) if domain_len > 0 else 0.0
        vowel_consonant_ratio = float(raw_feats.get("vowel_consonant_ratio", 0.0))

        # Check suspicious TLD
        has_suspicious_tld = any(cleaned_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

        # Calculate heuristic DGA score [0.0 - 1.0]
        score = 0.0
        reasons = []

        # 1. Entropy weighting
        if entropy >= 4.2:
            score += 0.40
            reasons.append(f"High Shannon entropy ({entropy:.2f})")
        elif entropy >= 3.7:
            score += 0.20
            reasons.append(f"Elevated Shannon entropy ({entropy:.2f})")

        # 2. Unique character ratio
        if unique_char_ratio >= 0.75 and label_len >= 10:
            score += 0.25
            reasons.append(f"High unique character ratio ({unique_char_ratio:.2f})")

        # 3. Digit ratio
        if digit_ratio >= 0.20:
            score += 0.20
            reasons.append(f"High digit ratio ({digit_ratio:.2f})")

        # 4. Low vowel ratio
        if vowel_consonant_ratio < 0.25 and label_len >= 8:
            score += 0.15
            reasons.append(f"Unusual vowel-consonant ratio ({vowel_consonant_ratio:.2f})")

        # 5. Character N-gram Distribution (Bi-gram & Tri-gram uniqueness)
        ngram_2_unique = float(raw_feats.get("ngram_2_unique_ratio", 0.0))
        ngram_3_unique = float(raw_feats.get("ngram_3_unique_ratio", 0.0))
        if label_len >= 10 and ngram_2_unique >= 0.85:
            score += 0.20
            reasons.append(f"High bi-gram uniqueness ratio ({ngram_2_unique:.2f})")
        if label_len >= 12 and ngram_3_unique >= 0.90:
            score += 0.15
            reasons.append(f"High tri-gram diversity ({ngram_3_unique:.2f})")

        # 6. TLD bonus
        if has_suspicious_tld:
            score += 0.15
            reasons.append("Suspicious Top-Level Domain (TLD)")

        final_score = round(min(score, 1.0), 4)

        if final_score >= 0.65:
            classification = "LIKELY_DGA"
        elif final_score >= 0.35:
            classification = "SUSPICIOUS"
        else:
            classification = "NORMAL"

        reason_str = "; ".join(reasons) if reasons else "Normal lexical domain features."

        compact_features = {
            "entropy": entropy,
            "length": domain_len,
            "digit_ratio": digit_ratio,
            "unique_char_ratio": unique_char_ratio,
            "vowel_consonant_ratio": vowel_consonant_ratio,
            "ngram_2_unique_ratio": ngram_2_unique,
            "ngram_3_unique_ratio": ngram_3_unique,
        }

        return DGAResult(
            domain=cleaned_domain,
            dga_score=final_score,
            classification=classification,
            features=compact_features,
            reason=reason_str,
        )
