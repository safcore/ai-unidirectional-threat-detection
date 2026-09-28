# NetWatch — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

> **NTRO Problem Statement 26145** | Category: Software | Theme: Cybersecurity

---

## Architectural Principle: CSV vs. PCAP

> **Why PCAP is the Real-Time Ingest Source, and CSV is for Training Only:**
> - **CSV (CIC-IDS 2017)** contains offline, pre-aggregated flow features. It is used **exclusively to train and evaluate the Machine Learning models** (`m3_classifiers/train.py`).
> - **PCAP (Raw Packet Captures)** represents live, un-aggregated network traffic mirrored across a hardware data diode. It is processed in **real-time packet-by-packet via `threading.Queue`** (`m1_ingest/pcap_stream_reader.py`).

```
                    ┌──────────────────────────────────────────────┐
                    │            OFFLINE TRAINING PHASE            │
                    │                                              │
  CIC-IDS CSV ────► │  Pre-labeled flow features (78 cols)         │
  (Dataset)         │  Train Random Forest & Isolation Forest      │
                    │  Save to models/ddos_rf.pkl                  │
                    └──────────────────────────────────────────────┘

                    ┌──────────────────────────────────────────────┐
                    │           LIVE REAL-TIME PIPELINE            │
                    │                                              │
  PCAP / Hardware ──► M1: Packet Stream Ingest (dpkt / libpcap)    │
  Mirroring Link    │  M2: Real-time Feature Extraction            │
  (Unidirectional)  │  M3/M4: ML Model Inference & Heuristics      │
                    │  M5/M6: Structured Alert Engine & Dashboard  │
                    └──────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train ML models on CSV features
python -m m3_classifiers.train

# 3. Test PCAP real-time streaming (synthetic or real file)
python tests/test_m1_pcap.py --speed 100

# 4. Test CIC-IDS CSV dataset streaming
python tests/test_m1_cic_ids.py

# 5. Run full pipeline with live dashboard
python run.py
# Dashboard → http://localhost:5000
```

### Ingest Modes

```bash
# Live PCAP replay mode (real-time packet ingest)
python run.py --pcap path/to/traffic.pcap --speed 10

# CSV replay mode (dataset simulation)
python run.py --csv data/cic-ids-2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

# Synthetic live load mode (5,000 packets/sec default)
python run.py --pps 10000
```

---

## Ingest Layer (`m1_ingest/`)

| File | Input | Role |
|------|-------|------|
| `pcap_stream_reader.py` | `.pcap` files / Live NIC | Real-time packet-by-packet streaming ingest (`dpkt` / stdlib) |
| `cic_ids_reader.py` | CIC-IDS 2017 `.csv` | Row-by-row streaming CSV reader for dataset evaluation |
| `pcap_replay.py` | Synthetic generator | Packet generator for all 6 attack scenarios |
| `packet_queue.py` | Shared state | Thread-safe `threading.Queue` core with worker threads |
| `stream_monitor.py` | Metrics | Prints `Processed X flows/sec` health line every 1 second |

---

## Threat Classes Detected

| Threat | Live PCAP Feature | ML Model |
|--------|------------------|----------|
| **DDoS** (SYN/UDP flood) | SYN ratio, src_ip entropy, pkt_rate | Random Forest (trained on CIC-IDS) |
| **Port Scan / Recon** | Unique dst_ports per src in 10s window | Sliding-window statistical rule |
| **C2 Beaconing** | Inter-flow arrival times periodicity | FFT Dominant Frequency Ratio + CoV |
| **DGA Domains** | Domain Shannon entropy, bigram perplexity | Lexical RF + English Bigram Model |
| **Data Exfiltration** | Outbound/inbound byte ratio | Isolation Forest + Anomaly rules |
| **DNS Tunneling** | Subdomain label length & entropy | Heuristic rule |

---

## Alert Schema

```json
{
  "alert_id": "uuid-v4",
  "timestamp": 1725272106.3,
  "timestamp_iso": "2026-09-02T09:15:06Z",
  "flow_id": "sha256[:16]",
  "src_ip": "172.16.0.99",
  "dst_ip": "10.0.0.50",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "threat_class": "RECON",
  "threat_subtype": "PORT_SCAN",
  "severity": "HIGH",
  "confidence": 0.82,
  "evidence": {
    "unique_dst_ports": 52,
    "window_sec": 10,
    "syn_no_ack": 1
  },
  "mitre_tactic": "Discovery",
  "mitre_technique": "Network Service Discovery",
  "mitre_technique_id": "T1046"
}
```

---

## Attack Generators (Live Demo)

```bash
# Trigger SYN flood detection
python -m m6_dashboard.attack_gen.syn_flood --target 127.0.0.1 --rate 500

# Trigger DNS tunnel detection  
python -m m6_dashboard.attack_gen.dns_tunnel --ns 8.8.8.8 --rate 10

# Trigger port scan detection
python -m m6_dashboard.attack_gen.port_scan --target 127.0.0.1 --end 1024
```
