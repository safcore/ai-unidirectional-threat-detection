"""
Domain Lexical Feature Extractor Module.

Extracts lexical, structural, and information-theoretic features from domain strings
for DGA detection.
"""

import string
from typing import Dict, Union
from .entropy import calculate_shannon_entropy
from .ngrams import CharacterNGramExtractor


class DomainFeatureExtractor:
    """
    Extracts lexical features from domain strings (e.g. FQDNs or second-level domains).
    """

    VOWELS = set("aeiou")
    CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

    def __init__(self, ngram_sizes=(2, 3, 4)):
        """
        Initialize domain feature extractor.
        """
        self.ngram_extractor = CharacterNGramExtractor(n_values=ngram_sizes)

    def extract_features(self, domain: str) -> Dict[str, Union[int, float]]:
        """
        Extract complete domain lexical feature vector.

        Args:
            domain: Input domain string (e.g., 'facebook.com', 'a8f9x11z.ru').

        Returns:
            Dict[str, Union[int, float]]: Dictionary of numerical feature names and values.
        """
        if not domain or not isinstance(domain, str):
            return self._empty_features()

        cleaned_domain = domain.lower().strip()
        length = len(cleaned_domain)

        # Separate main body from TLD if available (e.g., 'example.com' -> 'example')
        domain_parts = cleaned_domain.split(".")
        main_label = domain_parts[0] if domain_parts else cleaned_domain
        main_length = len(main_label)

        # Character counts
        num_digits = sum(1 for c in cleaned_domain if c.isdigit())
        num_letters = sum(1 for c in cleaned_domain if c.isalpha())
        num_special = sum(1 for c in cleaned_domain if not c.isalnum() and c != ".")
        
        # Vowels & Consonants (evaluated on main label)
        num_vowels = sum(1 for c in main_label if c in self.VOWELS)
        num_consonants = sum(1 for c in main_label if c in self.CONSONANTS)
        vowel_consonant_ratio = (num_vowels / num_consonants) if num_consonants > 0 else float(num_vowels)

        # Unique character ratio
        unique_chars = len(set(cleaned_domain))
        unique_char_ratio = (unique_chars / length) if length > 0 else 0.0

        # Shannon Entropy
        domain_entropy = calculate_shannon_entropy(cleaned_domain)
        label_entropy = calculate_shannon_entropy(main_label)

        # N-gram statistical features
        ngram_feats = self.ngram_extractor.extract_ngram_features(cleaned_domain)

        # Base features dictionary
        features: Dict[str, Union[int, float]] = {
            "domain_length": length,
            "main_label_length": main_length,
            "num_digits": num_digits,
            "num_special_chars": num_special,
            "num_subdomains": max(0, len(domain_parts) - 2) if len(domain_parts) > 1 else 0,
            "vowel_count": num_vowels,
            "consonant_count": num_consonants,
            "vowel_consonant_ratio": round(float(vowel_consonant_ratio), 4),
            "unique_char_ratio": round(float(unique_char_ratio), 4),
            "domain_entropy": round(float(domain_entropy), 4),
            "main_label_entropy": round(float(label_entropy), 4),
        }

        # Merge n-gram features
        features.update(ngram_feats)

        return features

    def _empty_features(self) -> Dict[str, Union[int, float]]:
        """Return zeroed features for invalid or empty domain inputs."""
        empty: Dict[str, Union[int, float]] = {
            "domain_length": 0,
            "main_label_length": 0,
            "num_digits": 0,
            "num_special_chars": 0,
            "num_subdomains": 0,
            "vowel_count": 0,
            "consonant_count": 0,
            "vowel_consonant_ratio": 0.0,
            "unique_char_ratio": 0.0,
            "domain_entropy": 0.0,
            "main_label_entropy": 0.0,
        }
        empty.update(self.ngram_extractor.extract_ngram_features(""))
        return empty
