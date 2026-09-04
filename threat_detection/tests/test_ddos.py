import pytest

from threat_detection.rules.ddos import DDoSDetector
from threat_detection.tests.generators import generate_normal, generate_ddos


@pytest.fixture
def detector():
    return DDoSDetector()


def test_normal_traffic_does_not_trigger(detector):
    for variant in range(5):
        feature = generate_normal(variant=variant)
        result = detector.detect(feature)
        assert result.detected is False, f"False positive on normal traffic variant {variant}"


def test_ddos_traffic_triggers(detector):
    feature = generate_ddos(packet_rate=10000, syn_rate=7000, duration=2.0)
    result = detector.detect(feature)
    assert result.detected is True
    assert result.threat_class == "DDoS"
    assert result.score >= 0.60
    assert len(result.reasons) > 0


def test_ddos_score_increases_with_intensity(detector):
    mild = generate_ddos(packet_rate=1500, syn_rate=800, duration=2.0)
    severe = generate_ddos(packet_rate=25000, syn_rate=20000, duration=1.0)

    mild_result = detector.detect(mild)
    severe_result = detector.detect(severe)

    assert severe_result.score > mild_result.score


def test_tiny_flow_is_ignored(detector):
    feature = generate_normal(variant=0)
    # Force it below min_packet_count regardless of generator defaults.
    import dataclasses
    tiny = dataclasses.replace(feature, packet_count=5, byte_count=500)
    result = detector.detect(tiny)
    assert result.detected is False
    assert "too small" in result.reasons[0].lower()


def test_borderline_traffic_does_not_immediately_hit_critical_confidence(detector):
    # Elevated but not extreme -- should not score as if it were a
    # massive flood.
    borderline = generate_ddos(packet_rate=1200, syn_rate=600, duration=3.0)
    result = detector.detect(borderline)
    assert result.score < 0.90
