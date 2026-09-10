# NETRION — AI-Based Cyber Threat Detection in Unidirectional IP Traffic

[![SIH 2026](https://img.shields.io/badge/SIH-2026-blue.svg)](https://www.sih.gov.in/)
[![Problem Statement](https://img.shields.io/badge/PS--ID-26145-brightgreen.svg)]()
[![Hardware Constraint](https://img.shields.io/badge/Hardware-Unidirectional%20Data%20Diode%20(RX--Only)-orange.svg)]()
[![Model Schema](https://img.shields.io/badge/Contract-66%20Features%20(Frozen)-purple.svg)]()
[![Backend Tests](https://img.shields.io/badge/Tests-129%20Passed-success.svg)]()

**NETRION** is an industrial-grade, AI/ML-driven Cyber Threat Detection and Autonomous SOC Investigation platform designed specifically for **physically unidirectional IP networks** (optical data diodes). Built for **Smart India Hackathon 2026 (PS-26145)**, NETRION monitors high-security OT, SCADA, defense, and nuclear control environments by processing mirrored ingress network streams with zero possibility of egress leakage or physical back-channel tampering.

---

## 1. Unidirectional Physical Data Diode Reality

In strict unidirectional network architectures:
1. **Physical RX-Only Tap (Zero Transmit Frames)**: The ingestion interface operates via a single strand of fiber-optic cable connected to the photodiode receiver (RX) of the network interface card (NIC). The transmit (TX) laser is physically absent or disconnected. Not a single bit or TCP ACK can ever be injected back onto the monitored network segment.
2. **Passive TLS JA3 vs JA4 & JA3S Physical Availability**:
   - **JA3 (ClientHello Fingerprinting)**: Observable passively from the client-to-server direction. NETRION extracts client TLS version, cipher suites, extensions, elliptic curves, and point formats directly from mirrored frames without decryption.
   - **JA3S (ServerHello Fingerprinting)**: **Physically unavailable** on unidirectional RX-only diode taps monitoring ingress traffic, because server responses traverse an isolated internal segment or separate return path with no reverse diode path. NETRION explicitly documents and respects this physical reality.
   - **Observable JA4**: JA4 client hashes (`{proto}{ver}{sni}{ciphers}{exts}_{cipher_hash}_{ext_hash}`) are computed genuinely from observed client parameters without fabricating or synthetically hashing non-existent server responses.
3. **Purely Advisory / Defensive Security Posture**: Because an optical diode physically prevents packet transmission, NETRION **does not perform active network mitigation** (such as sending TCP RSTs, modifying inline firewall ACLs, or performing active vulnerability probes). All verdicts generate real-time alerts, automated SOC workflows, and enriched forensic recommendations for external network orchestration.

---

## 2. End-to-End Pipeline Architecture

NETRION adheres to a strict linear, single-pass pipeline preserving the canonical 66-feature vector:

```
Production / Mirrored Traffic (RX-Only Tap)
                   │
                   ▼
       [M1 Ingest / Packet Stream]
                   │
                   ▼
             [Flow Assembly]
                   │
                   ▼
   [M2 Feature Extraction (Canonical 66)]
                   │
                   ▼
       [M3/M4 ML + Specialized Detectors]
         ├── Isolation Forest (Anomaly)
         ├── Random Forest (Supervised)
         ├── Botnet C2 Detector (Interval Analysis)
         ├── DGA Detector (Entropy + N-Grams)
         ├── DNS Tunneling & Exfiltration Detector
         └── Passive TLS / JA3 / JA4 Metadata Detector
                   │
                   ▼
            [Decision Engine]
                   │
                   ▼
          [M5 MITRE Enrichment]
                   │
                   ▼
          [Alert Normalization]
                   │
                   ▼
     [Backend Persistence & SQLite Store]
                   │
                   ▼
        [Server-Sent Events (SSE)]
                   │
                   ▼
     [React SOC Live Console + NVIDIA NIM Copilot]
```

---

## 3. Threat Coverage (PS-26145 Compliance)

| Threat Category | Detection Mechanism | Passive Observable Signals |
|---|---|---|
| **Volumetric Flood / DDoS** | Flow rate analytics & Random Forest | High SYN rate, extreme packets/sec, zero ACK responses |
| **Port Scan / Reconnaissance** | TCP flag heuristics & Supervised RF | Rapid SYN probes targeting standard service ports without completed handshakes |
| **DNS Tunneling** | Exfiltration heuristics & DNS entropy | Elevated payload volume on UDP port 53, high character entropy, deep subdomain nesting |
| **Domain Generation Algorithms (DGA)**| Statistical & Character N-Grams | Shannon entropy, vowel-to-consonant ratios, bi-gram & tri-gram frequency anomalies |
| **Command & Control (C2) Beaconing** | Inter-arrival timing & Jitter analysis | Low coefficient of variation in flow inter-arrival times, uniform packet sizes |
| **Data Exfiltration** | Outbound payload asymmetry | High forward-to-backward byte ratios (>=10:1), large packet sizes (>=1400 bytes) |
| **Encrypted Malware Sessions** | Passive TLS metadata & JA3/JA4 | Matching known malicious JA3 profiles (e.g. Cobalt Strike), abnormal extension lengths, non-standard cipher profiles (no decryption) |

---

## 4. Benchmark & Performance Metrics

Benchmarked offline across stored canonical feature vectors (batch inference) on Python 3.13:
- **Peak Batch Pipeline Throughput**: `605.24 flows/second` (Offline batch inference across stored flow vectors; not live network interface throughput)
- **Median Flow Ingestion Latency (P50)**: `2.11 ms`
- **95th Percentile Latency (P95)**: `2.30 ms`
- **Error Rate**: `0.00%` across 16,000+ benchmarked flows
- **Full Backend Test Suite**: **129/129 tests passing** (`pytest backend/tests/`)

---

## 5. Quickstart

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Node.js 18+ and npm

### Backend Setup
```bash
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python -m flask --app app.main run --port 5000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:5173` to open the SOC Dashboard.

### Running Test Suite
```bash
pytest backend/tests/
```
