"""
Shannon Entropy Feature Extraction Module.

Calculates Shannon Entropy over string sequences (domain names, subdomains)
or byte/byte-frequency data.
"""

import math
from collections import Counter
from typing import Union, Sequence


def calculate_shannon_entropy(data: Union[str, bytes, Sequence[int]]) -> float:
    r"""
    Calculate the Shannon Entropy of a given string, byte sequence, or integer sequence.

    Formula:
        H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)

    Args:
        data: Input text, byte string, or sequence of values.

    Returns:
        float: Shannon entropy value (0.0 if empty data or single unique character).
    """
    if not data:
        return 0.0

    length = len(data)
    if length <= 1:
        return 0.0

    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return float(entropy)
