import pytest

from threat_detection.rules.port_scan import PortScanDetector
from threat_detection.tests.generators import generate_normal, generate_port_scan_events


@pytest.fixture
def detector():
    return PortScanDetector()


def test_normal_single_connection_does_not_trigger(detector):
    feature = generate_normal()
    result = detector.detect(feature)
    assert result.detected is False


def test_few_normal_connections_do_not_trigger(detector):
    # A handful of connections to different everyday ports from the same
    # client should not look like a scan.
    for variant, port in enumerate([443, 443, 80]):
        feature = generate_normal(dst_port=port, variant=variant)
        result = detector.detect(feature)
    assert result.detected is False


def test_port_scan_sequence_triggers(detector):
    events = list(generate_port_scan_events(num_ports=40))
    last_result = None
    for event in events:
        last_result = detector.detect(event)

    assert last_result.detected is True
    assert last_result.threat_class == "PortScan"
    assert any("unique destination ports" in r for r in last_result.reasons)


def test_port_scan_state_is_per_source_ip(detector):
    scan_events = list(
        generate_port_scan_events(src_ip="10.0.0.50", num_ports=30)
    )
    other_host_normal = generate_normal(src_ip="10.0.0.51", variant=0)

    for e in scan_events:
        detector.detect(e)

    # A different, well-behaved source IP must not be affected by another
    # host's scan state.
    result = detector.detect(other_host_normal)
    assert result.detected is False


def test_reset_clears_state(detector):
    events = list(generate_port_scan_events(num_ports=40))
    for e in events:
        detector.detect(e)

    detector.reset()

    # Immediately after reset, a single new flow should not trigger.
    fresh = list(generate_port_scan_events(num_ports=1))[0]
    result = detector.detect(fresh)
    assert result.detected is False
