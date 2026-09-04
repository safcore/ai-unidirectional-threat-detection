import json

from threat_detection.engine import ThreatDetectionEngine
from threat_detection.feature_schema import FeatureRecord


def main():
    engine = ThreatDetectionEngine()

    ddos_feature = FeatureRecord(
        flow_id="demo-ddos-001",
        timestamp="2026-09-02T12:30:00Z",
        src_ip="203.0.113.5",
        dst_ip="10.0.0.20",
        src_port=4000,
        dst_port=80,
        protocol="TCP",
        packet_count=20000,
        byte_count=30000000,
        flow_duration=2.0,
        packet_rate=10000,
        byte_rate=15000000,
        syn_count=7000,
        ack_count=100,
        rst_count=20,
    )

    alert = engine.detect(ddos_feature)

    if alert:
        print("\n🚨 THREAT DETECTED")
        print("=" * 50)
        print(json.dumps(alert.to_dict(), indent=2))
    else:
        print("\n✅ No threat detected.")


if __name__ == "__main__":
    main()