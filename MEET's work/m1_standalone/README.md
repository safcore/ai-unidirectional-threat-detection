# Module 1 (M1) — Ingest Pipeline & PCAP Replay (Meet's Module)

> **NTRO Problem Statement 26145** | Category: Software | Theme: Cybersecurity
> **Owner**: Meet (Role: Ingest Pipeline, PCAP Replay & Queuing)

---

## Overview

This directory contains the **complete, self-contained standalone package for Module 1 (M1)**. 

It satisfies all M1 requirements:
- [x] **Unidirectional Ingest**: Read-only stream (data-diode compliant — zero return path, no probes, no handshakes).
- [x] **Threading Queue**: Thread-safe `threading.Queue` preventing memory overflow during live stream.
- [x] **PCAP & PCAPNG Replay**: High-speed packet-by-packet streaming reader (`.pcap` & Wireshark `.pcapng` format).
- [x] **Zero Packet Drops**: Thread-pool worker architecture benchmarked at **33,000–55,000+ packets/sec**.
- [x] **Health Indicator**: Real-time sliding window monitor printing `[STREAM] Processed X flows in last second` every 1 second.

---

## Directory Structure

```
m1_standalone/
├── standalone_m1_demo.py    ← Meet's main demonstration runner
├── pcap_stream_reader.py    ← PCAP & PCAPNG streaming reader (dpkt / stdlib)
├── packet_queue.py          ← Core threading.Queue & PacketWorker threads
├── stream_monitor.py        ← Real-time "Processed X flows/sec" monitor
├── pcap_replay.py           ← Synthetic packet generator for all attack types
├── flow_record.py           ← RawPacket & CICFlowRecord dataclass definitions
├── cic_ids_reader.py        ← Streaming CSV reader for dataset evaluation
├── cic_ids_pipeline.py      ← Queue pipeline for dataset flows
├── test_m1_pcap.py          ← PCAP streaming smoke test
├── test_m1_cic_ids.py       ← Dataset streaming smoke test
└── requirements.txt         ← Dependency: dpkt
```

---

## Quick Start Commands for Meet

### 1. Install Dependency
```bash
pip install -r requirements.txt
```

### 2. Run Meet's Standalone M1 Ingest Demo
```bash
# Load test with synthetic generator (10,000 pps):
python standalone_m1_demo.py --pps 10000 --duration 10

# Replay a real PCAP or PCAPNG file (e.g., Friday-WorkingHours.pcap):
python standalone_m1_demo.py --pcap "path/to/file.pcap" --speed 10.0
```

### 3. Run PCAP Streaming Verification Test (33,000+ pkts/s)
```bash
python test_m1_pcap.py --speed 500
```

### 4. Run Dataset CSV Evaluation Test
```bash
python test_m1_cic_ids.py
```

---

## Hand-off Contract: How M1 Connects to M2 (Feature Extractor)

Meet's M1 module exposes the `add_consumer()` method to register M2's flow aggregator:

```python
from m1_standalone.packet_queue import IngestPipeline
from m1_standalone.pcap_stream_reader import PcapStreamReader

# Create pipeline
pipeline = IngestPipeline(pps=5000, num_workers=2)

# Wire M1 -> M2 (pass M2's ingest callback):
pipeline.add_consumer(m2_flow_aggregator.ingest)

# Start streaming
pipeline.start()
```

Each packet passed to M2 is a `RawPacket` object:
```python
pkt.timestamp    # Float: epoch timestamp
pkt.src_ip       # String: source IP address
pkt.dst_ip       # String: destination IP address
pkt.src_port     # Integer: source port
pkt.dst_port     # Integer: destination port
pkt.protocol     # String: "TCP" | "UDP" | "DNS" | "ICMP"
pkt.flags        # Integer: TCP flags bitmask (SYN=0x02, ACK=0x10)
pkt.payload_len  # Integer: payload length in bytes
pkt.raw          # Bytes: raw packet payload bytes
pkt.flow_key     # Tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
```
