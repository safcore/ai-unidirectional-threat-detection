"""
Unit tests for M4 Feature Engineering Modules:
- Shannon Entropy
- Character-level N-Grams
- Domain Lexical Features
- Network Behavioral Features
"""

import math
import pytest
from m4_threat_classifier.feature_engineering import (
    calculate_shannon_entropy,
    CharacterNGramExtractor,
    DomainFeatureExtractor,
    NetworkBehavioralFeatureExtractor,
)


def test_shannon_entropy_basic():
    """Test basic Shannon entropy calculations."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("a") == 0.0
    assert calculate_shannon_entropy("aaaaa") == 0.0
    
    # 2 symbols with equal probability -> H = -2*(0.5 * log2(0.5)) = 1.0
    assert pytest.approx(calculate_shannon_entropy("abababab"), 0.001) == 1.0
    
    # Random DGA string should have higher entropy than repetitive word
    low_entropy = calculate_shannon_entropy("google")
    high_entropy = calculate_shannon_entropy("zx918qka741mzn")
    assert high_entropy > low_entropy


def test_ngram_extractor_basic():
    """Test character N-gram extraction for 2-grams, 3-grams, 4-grams."""
    extractor = CharacterNGramExtractor(n_values=(2, 3, 4))

    # Test 2-gram extraction
    two_grams = extractor.extract_ngrams("test", n=2)
    assert two_grams == ["te", "es", "st"]

    # Test 3-gram extraction
    three_grams = extractor.extract_ngrams("test", n=3)
    assert three_grams == ["tes", "est"]

    # Test N-gram statistical feature vector
    feats = extractor.extract_ngram_features("example")
    assert feats["ngram_2_total_count"] == 6
    assert feats["ngram_3_total_count"] == 5
    assert feats["ngram_4_total_count"] == 4
    assert feats["ngram_2_unique_count"] == 6

    # Test empty string
    empty_feats = extractor.extract_ngram_features("")
    assert empty_feats["ngram_2_total_count"] == 0


def test_domain_feature_extractor():
    """Test domain lexical feature extraction."""
    extractor = DomainFeatureExtractor()

    domain = "v189zkqa.biz"
    feats = extractor.extract_features(domain)

    assert feats["domain_length"] == len(domain)
    assert feats["main_label_length"] == 8
    assert feats["num_digits"] == 3
    assert feats["domain_entropy"] > 3.0
    assert "ngram_2_total_count" in feats
    assert "vowel_consonant_ratio" in feats

    # Test invalid / empty domain
    empty_feats = extractor.extract_features("")
    assert empty_feats["domain_length"] == 0


def test_network_behavioral_feature_extractor():
    """Test pre-aggregated network flow feature extraction."""
    extractor = NetworkBehavioralFeatureExtractor()

    sample_flow = {
        "flow_id": "test-flow-001",
        "src_ip": "192.168.1.50",
        "dst_ip": "45.33.32.156",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "flow_duration": 100.0,
        "packets_out": 50,
        "packets_in": 10,
        "bytes_out": 500000,
        "bytes_in": 10000,
        "packet_lengths": [1000, 1000, 1000, 1000, 1000],
        "inter_arrival_times": [2.0, 2.0, 2.0, 2.0, 2.0],  # Constant IAT -> CoV = 0.0
        "connection_count_10s": 15,
        "dst_frequency": 5,
    }

    feats = extractor.extract_features(sample_flow)

    assert feats["flow_duration"] == 100.0
    assert feats["total_packets"] == 60
    assert feats["bytes_out"] == 500000
    assert feats["upload_download_ratio"] == 50.0  # High upload ratio
    assert feats["periodicity_cov"] == 0.0          # Rigid periodic C2 beaconing CoV
    assert feats["packet_length_mean"] == 1000.0

    # Test empty flow record
    empty_feats = extractor.extract_features({})
    assert empty_feats["total_packets"] == 0
    assert empty_feats["periodicity_cov"] == 999.0
