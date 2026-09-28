"""
Module 3 (M3) — Fallback Smoke-Test Dataset Generator
=====================================================
WARNING: THIS IS STRICTLY A FALLBACK SMOKE-TEST UTILITY.
DO NOT USE THIS AS THE PRIMARY TRAINING SOURCE FOR PRODUCTION.
The real training pipeline requires labelled traffic passed through M1 -> M2.
"""

import random
from typing import Dict, Any, List
import pandas as pd
import numpy as np

from .schema import ThreatClass


def generate_fallback_smoke_dataset(
    n_benign: int = 200,
    n_syn_flood: int = 100,
    n_udp_flood: int = 100,
    n_port_scan: int = 100,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Generates a deterministic synthetic dataset matching M2's 82-column contract
    strictly for pipeline validation, smoke-testing, and automated unit tests.
    
    Exact class distribution:
      BENIGN: n_benign (default 200)
      SYN_FLOOD: n_syn_flood (default 100)
      UDP_FLOOD: n_udp_flood (default 100)
      PORT_SCAN: n_port_scan (default 100)
      Total: 500 samples
    """
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)

    records: List[Dict[str, Any]] = []

    def rand_ip(prefix: str = "192.168.1"):
        return f"{prefix}.{rng.randint(10, 250)}"

    # 1. BENIGN Samples
    for i in range(n_benign):
        fwd_pkts = rng.randint(5, 120)
        bwd_pkts = rng.randint(4, 110)
        duration_ms = rng.uniform(500.0, 15000.0)
        dur_us = duration_ms * 1000.0
        dur_sec = max(duration_ms / 1000.0, 0.001)

        fwd_bytes = fwd_pkts * rng.uniform(60.0, 800.0)
        bwd_bytes = bwd_pkts * rng.uniform(100.0, 1200.0)
        tot_bytes = fwd_bytes + bwd_bytes

        rec = {
            "window_id": f"w_smoke_{i % 5}",
            "src_ip": rand_ip("192.168.1"),
            "dst_ip": rand_ip("10.0.0"),
            "src_port": rng.randint(1025, 65000),
            "dst_port": rng.choice([80, 443, 8080, 53, 22]),
            "protocol": 6 if rng.random() > 0.15 else 17,
            "protocol_name": "TCP" if rng.random() > 0.15 else "UDP",
            "Flow Duration": dur_us,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": bwd_bytes,
            "Fwd Packet Length Max": rng.uniform(400.0, 1460.0),
            "Fwd Packet Length Min": 40.0,
            "Fwd Packet Length Mean": fwd_bytes / fwd_pkts,
            "Fwd Packet Length Std": rng.uniform(10.0, 200.0),
            "Bwd Packet Length Max": rng.uniform(500.0, 1460.0),
            "Bwd Packet Length Min": 40.0,
            "Bwd Packet Length Mean": bwd_bytes / bwd_pkts,
            "Bwd Packet Length Std": rng.uniform(20.0, 300.0),
            "Min Packet Length": 40.0,
            "Max Packet Length": 1460.0,
            "Packet Length Mean": tot_bytes / (fwd_pkts + bwd_pkts),
            "Packet Length Std": rng.uniform(30.0, 250.0),
            "Packet Length Variance": rng.uniform(900.0, 62500.0),
            "Average Packet Size": tot_bytes / (fwd_pkts + bwd_pkts),
            "Avg Fwd Segment Size": fwd_bytes / fwd_pkts,
            "Avg Bwd Segment Size": bwd_bytes / bwd_pkts,
            "Flow Bytes/s": tot_bytes / dur_sec,
            "Flow Packets/s": (fwd_pkts + bwd_pkts) / dur_sec,
            "Fwd Packets/s": fwd_pkts / dur_sec,
            "Bwd Packets/s": bwd_pkts / dur_sec,
            "Flow IAT Mean": rng.uniform(1000.0, 50000.0),
            "Flow IAT Std": rng.uniform(500.0, 20000.0),
            "Flow IAT Max": rng.uniform(50000.0, 500000.0),
            "Flow IAT Min": rng.uniform(10.0, 200.0),
            "Fwd IAT Total": dur_us * 0.9,
            "Fwd IAT Mean": rng.uniform(1500.0, 60000.0),
            "Fwd IAT Std": rng.uniform(800.0, 30000.0),
            "Fwd IAT Max": rng.uniform(60000.0, 600000.0),
            "Fwd IAT Min": rng.uniform(20.0, 300.0),
            "Bwd IAT Total": dur_us * 0.85,
            "Bwd IAT Mean": rng.uniform(1500.0, 60000.0),
            "Bwd IAT Std": rng.uniform(800.0, 30000.0),
            "Bwd IAT Max": rng.uniform(60000.0, 600000.0),
            "Bwd IAT Min": rng.uniform(20.0, 300.0),
            "FIN Flag Count": rng.choice([0, 1, 2]),
            "SYN Flag Count": rng.choice([1, 2]),
            "RST Flag Count": 0,
            "PSH Flag Count": rng.randint(1, 15),
            "ACK Flag Count": max(fwd_pkts, bwd_pkts) - 1,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Fwd PSH Flags": rng.randint(0, 5),
            "Bwd PSH Flags": rng.randint(0, 5),
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "tcp_flag_bitmask": 24,  # PSH + ACK typical
            "Down/Up Ratio": bwd_pkts / max(fwd_pkts, 1),
            "TTL Mean": 64.0,
            "TTL Std": 0.0,
            "TTL Variance": 0.0,
            "TTL Min": 64.0,
            "TTL Max": 64.0,
            "TCP Window Size Init": 65535.0,
            "TCP Window Size Mean": 32768.0,
            "IP Flags DF Count": fwd_pkts,
            "IP Flags MF Count": 0,
            "Retransmission Count": rng.randint(0, 2),
            "Port Sequentiality Score": 0.0,
            "Port Access Type": "SINGLE",
            "bidirectional_duration_ms": int(duration_ms),
            "bidirectional_packets": fwd_pkts + bwd_pkts,
            "bidirectional_bytes": int(tot_bytes),
            "src2dst_packets": fwd_pkts,
            "src2dst_bytes": int(fwd_bytes),
            "dst2src_packets": bwd_pkts,
            "dst2src_bytes": int(bwd_bytes),
            "application_name": "HTTP",
            "application_category_name": "Web",
            "application_confidence": 1,
            "threat_class": ThreatClass.BENIGN.value,
        }
        records.append(rec)

    # 2. SYN_FLOOD Samples
    for i in range(n_syn_flood):
        fwd_pkts = rng.randint(50, 600)
        bwd_pkts = 0  # Zero backward packets in unidirectional flood
        duration_ms = rng.uniform(5.0, 50.0)
        dur_us = duration_ms * 1000.0
        dur_sec = max(duration_ms / 1000.0, 0.001)

        fwd_bytes = fwd_pkts * 40.0  # TCP header only
        bwd_bytes = 0.0
        tot_bytes = fwd_bytes

        rec = {
            "window_id": f"w_smoke_syn_{i % 3}",
            "src_ip": rand_ip("192.168.100"),
            "dst_ip": "10.0.0.5",
            "src_port": rng.randint(1025, 65000),
            "dst_port": rng.choice([80, 443, 8080]),
            "protocol": 6,
            "protocol_name": "TCP",
            "Flow Duration": dur_us,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": 0.0,
            "Fwd Packet Length Max": 40.0,
            "Fwd Packet Length Min": 40.0,
            "Fwd Packet Length Mean": 40.0,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0.0,
            "Bwd Packet Length Min": 0.0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Min Packet Length": 40.0,
            "Max Packet Length": 40.0,
            "Packet Length Mean": 40.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "Average Packet Size": 40.0,
            "Avg Fwd Segment Size": 40.0,
            "Avg Bwd Segment Size": 0.0,
            "Flow Bytes/s": tot_bytes / dur_sec,
            "Flow Packets/s": fwd_pkts / dur_sec,
            "Fwd Packets/s": fwd_pkts / dur_sec,
            "Bwd Packets/s": 0.0,
            "Flow IAT Mean": rng.uniform(10.0, 200.0),
            "Flow IAT Std": rng.uniform(5.0, 100.0),
            "Flow IAT Max": rng.uniform(100.0, 500.0),
            "Flow IAT Min": 0.0,
            "Fwd IAT Total": dur_us,
            "Fwd IAT Mean": rng.uniform(10.0, 200.0),
            "Fwd IAT Std": rng.uniform(5.0, 100.0),
            "Fwd IAT Max": rng.uniform(100.0, 500.0),
            "Fwd IAT Min": 0.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": fwd_pkts,  # Massive SYN count
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,  # Zero ACK
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "tcp_flag_bitmask": 2,  # SYN only (0x02)
            "Down/Up Ratio": 0.0,
            "TTL Mean": 64.0,
            "TTL Std": 0.0,
            "TTL Variance": 0.0,
            "TTL Min": 64.0,
            "TTL Max": 64.0,
            "TCP Window Size Init": 1024.0,
            "TCP Window Size Mean": 1024.0,
            "IP Flags DF Count": 0,
            "IP Flags MF Count": 0,
            "Retransmission Count": rng.randint(0, 10),
            "Port Sequentiality Score": 0.0,
            "Port Access Type": "SINGLE",
            "bidirectional_duration_ms": int(duration_ms),
            "bidirectional_packets": fwd_pkts,
            "bidirectional_bytes": int(tot_bytes),
            "src2dst_packets": fwd_pkts,
            "src2dst_bytes": int(fwd_bytes),
            "dst2src_packets": 0,
            "dst2src_bytes": 0,
            "application_name": "HTTP",
            "application_category_name": "Web",
            "application_confidence": 0,
            "threat_class": ThreatClass.SYN_FLOOD.value,
        }
        records.append(rec)

    # 3. UDP_FLOOD Samples
    for i in range(n_udp_flood):
        fwd_pkts = rng.randint(50, 600)
        bwd_pkts = 0
        duration_ms = rng.uniform(5.0, 50.0)
        dur_us = duration_ms * 1000.0
        dur_sec = max(duration_ms / 1000.0, 0.001)

        pkt_len = rng.choice([64.0, 128.0, 512.0, 1024.0])
        fwd_bytes = fwd_pkts * pkt_len
        tot_bytes = fwd_bytes

        rec = {
            "window_id": f"w_smoke_udp_{i % 3}",
            "src_ip": rand_ip("192.168.200"),
            "dst_ip": "10.0.0.10",
            "src_port": rng.randint(1025, 65000),
            "dst_port": rng.choice([53, 123, 161, 500, 30000]),
            "protocol": 17,
            "protocol_name": "UDP",
            "Flow Duration": dur_us,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": 0.0,
            "Fwd Packet Length Max": pkt_len,
            "Fwd Packet Length Min": pkt_len,
            "Fwd Packet Length Mean": pkt_len,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0.0,
            "Bwd Packet Length Min": 0.0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Min Packet Length": pkt_len,
            "Max Packet Length": pkt_len,
            "Packet Length Mean": pkt_len,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "Average Packet Size": pkt_len,
            "Avg Fwd Segment Size": pkt_len,
            "Avg Bwd Segment Size": 0.0,
            "Flow Bytes/s": tot_bytes / dur_sec,
            "Flow Packets/s": fwd_pkts / dur_sec,
            "Fwd Packets/s": fwd_pkts / dur_sec,
            "Bwd Packets/s": 0.0,
            "Flow IAT Mean": rng.uniform(10.0, 200.0),
            "Flow IAT Std": rng.uniform(5.0, 100.0),
            "Flow IAT Max": rng.uniform(100.0, 500.0),
            "Flow IAT Min": 0.0,
            "Fwd IAT Total": dur_us,
            "Fwd IAT Mean": rng.uniform(10.0, 200.0),
            "Fwd IAT Std": rng.uniform(5.0, 100.0),
            "Fwd IAT Max": rng.uniform(100.0, 500.0),
            "Fwd IAT Min": 0.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "tcp_flag_bitmask": 0,
            "Down/Up Ratio": 0.0,
            "TTL Mean": 64.0,
            "TTL Std": 0.0,
            "TTL Variance": 0.0,
            "TTL Min": 64.0,
            "TTL Max": 64.0,
            "TCP Window Size Init": 0.0,
            "TCP Window Size Mean": 0.0,
            "IP Flags DF Count": 0,
            "IP Flags MF Count": 0,
            "Retransmission Count": 0,
            "Port Sequentiality Score": 0.0,
            "Port Access Type": "SINGLE",
            "bidirectional_duration_ms": int(duration_ms),
            "bidirectional_packets": fwd_pkts,
            "bidirectional_bytes": int(tot_bytes),
            "src2dst_packets": fwd_pkts,
            "src2dst_bytes": int(fwd_bytes),
            "dst2src_packets": 0,
            "dst2src_bytes": 0,
            "application_name": "DNS" if pkt_len < 100 else "Unknown",
            "application_category_name": "Network",
            "application_confidence": 0,
            "threat_class": ThreatClass.UDP_FLOOD.value,
        }
        records.append(rec)

    # 4. PORT_SCAN Samples
    for i in range(n_port_scan):
        fwd_pkts = rng.choice([1, 2])
        bwd_pkts = rng.choice([0, 1])
        duration_ms = rng.uniform(0.1, 5.0)
        dur_us = duration_ms * 1000.0
        dur_sec = max(duration_ms / 1000.0, 0.001)

        fwd_bytes = fwd_pkts * 40.0
        bwd_bytes = bwd_pkts * 40.0
        tot_bytes = fwd_bytes + bwd_bytes

        seq_score = rng.uniform(0.65, 1.0) if i % 2 == 0 else rng.uniform(0.0, 0.3)
        access_type = "SEQUENTIAL" if seq_score >= 0.5 else "RANDOM"

        rec = {
            "window_id": f"w_smoke_scan_{i % 3}",
            "src_ip": rand_ip("192.168.50"),
            "dst_ip": "10.0.0.1",
            "src_port": rng.randint(30000, 60000),
            "dst_port": rng.randint(1, 1024),
            "protocol": 6,
            "protocol_name": "TCP",
            "Flow Duration": dur_us,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": bwd_bytes,
            "Fwd Packet Length Max": 40.0,
            "Fwd Packet Length Min": 40.0,
            "Fwd Packet Length Mean": 40.0,
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 40.0 if bwd_pkts else 0.0,
            "Bwd Packet Length Min": 40.0 if bwd_pkts else 0.0,
            "Bwd Packet Length Mean": 40.0 if bwd_pkts else 0.0,
            "Bwd Packet Length Std": 0.0,
            "Min Packet Length": 40.0,
            "Max Packet Length": 40.0,
            "Packet Length Mean": 40.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "Average Packet Size": 40.0,
            "Avg Fwd Segment Size": 40.0,
            "Avg Bwd Segment Size": 40.0 if bwd_pkts else 0.0,
            "Flow Bytes/s": tot_bytes / dur_sec,
            "Flow Packets/s": (fwd_pkts + bwd_pkts) / dur_sec,
            "Fwd Packets/s": fwd_pkts / dur_sec,
            "Bwd Packets/s": bwd_pkts / dur_sec,
            "Flow IAT Mean": 0.0,
            "Flow IAT Std": 0.0,
            "Flow IAT Max": 0.0,
            "Flow IAT Min": 0.0,
            "Fwd IAT Total": 0.0,
            "Fwd IAT Mean": 0.0,
            "Fwd IAT Std": 0.0,
            "Fwd IAT Max": 0.0,
            "Fwd IAT Min": 0.0,
            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 1,
            "RST Flag Count": bwd_pkts,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "tcp_flag_bitmask": 2,  # SYN probe
            "Down/Up Ratio": bwd_pkts / fwd_pkts,
            "TTL Mean": 64.0,
            "TTL Std": 0.0,
            "TTL Variance": 0.0,
            "TTL Min": 64.0,
            "TTL Max": 64.0,
            "TCP Window Size Init": 1024.0,
            "TCP Window Size Mean": 1024.0,
            "IP Flags DF Count": 0,
            "IP Flags MF Count": 0,
            "Retransmission Count": 0,
            "Port Sequentiality Score": seq_score,
            "Port Access Type": access_type,
            "bidirectional_duration_ms": int(duration_ms),
            "bidirectional_packets": fwd_pkts + bwd_pkts,
            "bidirectional_bytes": int(tot_bytes),
            "src2dst_packets": fwd_pkts,
            "src2dst_bytes": int(fwd_bytes),
            "dst2src_packets": bwd_pkts,
            "dst2src_bytes": int(bwd_bytes),
            "application_name": "Unknown",
            "application_category_name": "Unspecified",
            "application_confidence": 0,
            "threat_class": ThreatClass.PORT_SCAN.value,
        }
        records.append(rec)

    df = pd.DataFrame(records)
    return df
