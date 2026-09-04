"""
Character-Level N-Gram Extractor Module.

Extracts character-level n-grams (2-grams, 3-grams, 4-grams) from domain strings,
URLs, or other text-like security indicators.
"""

from collections import Counter
from typing import List, Dict, Union, Set, Tuple


class CharacterNGramExtractor:
    """
    Extracts character-level N-grams and summary statistics for specified N values.
    """

    def __init__(self, n_values: Tuple[int, ...] = (2, 3, 4)):
        """
        Initialize the N-gram extractor with targeted N values.

        Args:
            n_values: Tuple of integers indicating N-gram sizes (default: 2, 3, 4).
        """
        self.n_values = sorted(n_values)

    def extract_ngrams(self, text: str, n: int) -> List[str]:
        """
        Extract character-level n-grams of size n from input text.

        Args:
            text: Input string (e.g. domain name, hostname, URL).
            n: Size of n-gram window.

        Returns:
            List[str]: Extracted n-gram substrings.
        """
        if not text or len(text) < n or n <= 0:
            return []
        
        cleaned_text = text.lower().strip()
        return [cleaned_text[i : i + n] for i in range(len(cleaned_text) - n + 1)]

    def get_ngram_counts(self, text: str, n: int) -> Dict[str, int]:
        """
        Get frequency distribution count of n-grams of size n.

        Args:
            text: Input string.
            n: Size of n-gram.

        Returns:
            Dict[str, int]: Mapping from n-gram substring to count.
        """
        ngrams = self.extract_ngrams(text, n)
        return dict(Counter(ngrams))

    def extract_ngram_features(self, text: str) -> Dict[str, Union[int, float]]:
        """
        Extract structured numerical n-gram statistical features for ML models.

        Args:
            text: Input string (e.g. 'google.com', 'x189zkqa91.biz').

        Returns:
            Dict[str, Union[int, float]]: Extracted statistical features per N value.
        """
        features: Dict[str, Union[int, float]] = {}
        cleaned_text = text.lower().strip() if text else ""

        for n in self.n_values:
            ngrams = self.extract_ngrams(cleaned_text, n)
            total_ngrams = len(ngrams)
            unique_ngrams = len(set(ngrams))
            unique_ratio = (unique_ngrams / total_ngrams) if total_ngrams > 0 else 0.0

            features[f"ngram_{n}_total_count"] = total_ngrams
            features[f"ngram_{n}_unique_count"] = unique_ngrams
            features[f"ngram_{n}_unique_ratio"] = round(float(unique_ratio), 4)

        return features
