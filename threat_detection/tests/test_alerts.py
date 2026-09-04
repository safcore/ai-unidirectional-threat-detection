import dataclasses
import math

import pytest

from threat_detection.engine import ThreatDetectionEngine
from threat_detection.tests.generators import (
    generate_normal,
    generate_ddos,
    generate_port_scan_events,
)


@pytest.fixture
def engine():
    return ThreatDetectionEngine()


def test_normal_traffic_produces_no_alert(engine):
    feature = generate_normal()
    alert = engine.detect(feature)
    assert alert is None


def test_ddos_produces_well_formed_alert(engine):
    feature = generate_ddos(packet_rate=15000, syn_rate=10000, duration=1.5)
    alert = engine.detect(feature)

    assert alert is not None
    assert alert.threat_class == "DDoS"
    assert alert.alert_id.startswith("ALT-")
    assert 0.0 <= alert.confidence <= 1.0
    assert alert.severity in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert alert.detection_method == ["RULE"]
    assert len(alert.evidence) > 0
    assert alert.status == "NEW"
    assert alert.source.ip == feature.src_ip
    assert alert.destination.ip == feature.dst_ip
    assert alert.mitre["tactic"] == "Impact"
    # We deliberately never invent technique IDs.
    assert alert.mitre["technique_id"] is None


def test_extreme_ddos_is_critical_severity(engine):
    feature = generate_ddos(packet_rate=25000, syn_rate=22000, duration=1.0)
    alert = engine.detect(feature)
    assert alert is not None
    assert alert.severity == "CRITICAL"


def test_port_scan_produces_alert_via_engine(engine):
    events = list(generate_port_scan_events(num_ports=40))
    last_alert = None
    for event in events:
        last_alert = engine.detect(event)

    assert last_alert is not None
    assert last_alert.threat_class == "PortScan"
    assert last_alert.mitre["tactic"] == "Reconnaissance"


def test_missing_required_field_fails_safely(engine):
    feature = generate_normal()
    # Simulate a malformed record: invalid protocol value.
    bad = dataclasses.replace(feature, protocol="NOT_A_PROTOCOL")
    alert = engine.detect(bad)
    assert alert is None  # discarded, not raised


def test_invalid_negative_values_fail_safely(engine):
    feature = generate_normal()
    bad = dataclasses.replace(feature, packet_count=-100)
    alert = engine.detect(bad)
    assert alert is None


def test_nan_values_fail_safely(engine):
    feature = generate_normal()
    bad = dataclasses.replace(feature, byte_rate=math.nan)
    alert = engine.detect(bad)
    assert alert is None


def test_alert_ids_increment(engine):
    f1 = generate_ddos(packet_rate=12000, syn_rate=9000, duration=1.0)
    f2 = generate_ddos(packet_rate=13000, syn_rate=9500, duration=1.0)

    a1 = engine.detect(f1)
    a2 = engine.detect(f2)

    assert a1 is not None and a2 is not None
    assert a1.alert_id != a2.alert_id


def test_multiple_detectors_can_each_fire_independently(engine):
    # Not simultaneously on the same flow, but the engine should handle a
    # DDoS flow followed by an unrelated port scan sequence without state
    # leaking between detector types.
    ddos_alert = engine.detect(generate_ddos(packet_rate=15000, syn_rate=11000, duration=1.0))
    assert ddos_alert is not None and ddos_alert.threat_class == "DDoS"

    scan_events = list(generate_port_scan_events(num_ports=40, src_ip="10.0.0.77"))
    scan_alert = None
    for e in scan_events:
        scan_alert = engine.detect(e)
    assert scan_alert is not None and scan_alert.threat_class == "PortScan"
