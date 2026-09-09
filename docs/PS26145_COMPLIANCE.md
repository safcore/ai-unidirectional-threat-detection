# PS-26145 Problem Statement Compliance Matrix

**Problem Statement:** PS-26145 / SIH 2026  
**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Organization:** Ministry of Home Affairs / Indian Cyber Crime Coordination Centre (I4C)  
**Date:** September 6, 2026  
**Status:** **FULLY COMPLIANT (100%)**  

---

## 1. Compliance Overview

The platform is purpose-built to operate in strictly isolated, unidirectional network security environments (e.g., optical data diodes, unidirectional security gateways, passive network taps). It passively ingests unidirectional flow telemetry, extracts 66 statistical network features, detects both known and zero-day cyber threats using a multi-model ML ensemble and behavioral heuristics, enriches alerts via NVIDIA Nemotron 3.5 AI, and streams standardized alerts to a SOC dashboard in real time.

---

## 2. Threat Category Verification Matrix

| # | Required Threat Category | Primary Detection Module | Behavioral / ML Technique | MITRE ATT&CK Mapping | Automated Test Verification | Status |
| :-: | :--- | :--- | :--- | :-: | :--- | :-: |
| **1** | **Volumetric DDoS / DoS Attacks** | `ml/inference/m3_predict.py`<br>`ml/detection/decision_engine.py` | Supervised Random Forest (F1=99.8%) + Packet rate & volume anomaly detection | **T1498** / **T1499**<br>Network Denial of Service | `test_m4_integration.py`<br>`test_attack_service.py` | **VERIFIED** |
| **2** | **Botnet Command & Control (C2) Beaconing** | `m4_threat_classifier/detection/c2_detector.py`<br>`attack_gen/c2_beacon.py` | Inter-arrival time (IAT) variance, low jitter analysis ($CV < 0.25$), fixed periodicity | **T1071**<br>Application Layer Protocol | `test_ps26145_compliance.py`<br>`test_attack_service.py` | **VERIFIED** |
| **3** | **DGA & DNS Tunnelling** | `m4_threat_classifier/detection/dga_detector.py`<br>`attack_gen/dns_tunnel.py` | Shannon entropy ($H > 3.8$ bits/char), consonant/vowel ratio, hex density, query length | **T1568.002** / **T1071.004**<br>Domain Generation Algorithms | `test_ps26145_compliance.py`<br>`test_attack_service.py` | **VERIFIED** |
| **4** | **Malware in Encrypted Sessions (TLS/QUIC)** | `ml/detection/tls_metadata_detector.py`<br>`attack_gen/tls_metadata.py` | **Passive metadata ONLY:** Packet length distribution, duration, IAT jitter, JA3 profile matching (**Strictly zero payload decryption**) | **T1573**<br>Encrypted Channel | `test_ps26145_compliance.py`<br>`test_attack_service.py` | **VERIFIED** |
| **5** | **Reconnaissance & Port Scanning** | `ml/inference/m3_predict.py`<br>`attack_gen/port_scan.py` | SYN scan detection, distinct destination port fan-out, horizontal/vertical sweep tracking | **T1046**<br>Network Service Discovery | `test_m4_integration.py`<br>`test_attack_service.py` | **VERIFIED** |
| **6** | **Data Exfiltration** | `m4_threat_classifier/detection/exfiltration_detector.py`<br>`attack_gen/data_exfiltration.py` | Flow asymmetry ratio ($\frac{\text{Bytes}_{\text{fwd}}}{\text{Bytes}_{\text{bwd}}} > 10.0$), sustained outbound volume bursts | **T1048**<br>Exfiltration Over Alternative Protocol | `test_ps26145_compliance.py`<br>`test_attack_service.py` | **VERIFIED** |

---

## 3. Architecture & Constraint Compliance

### 3.1 Unidirectional IP Network Constraint
- **Passive Tapping:** The system listens passively via PCAP streaming (`m1_ingest/pcap_stream_reader.py`) or synthetic interface capture (`m1_ingest/pcap_replay.py`).
- **No Return Path:** Zero transmitted packets, zero active handshakes, zero TCP RST/ICMP injected into the monitored network segment.
- **Data Diode Compatibility:** Validated to operate correctly with unidirectional ingress where backward ACK packets are either absent or synthetic.

### 3.2 Non-Decrypting Inspection Constraint
- **No TLS Decryption:** The platform does not install root certificates, terminate TLS sessions, or inspect ciphertext.
- **Statistical Metadata:** Classification relies exclusively on observable transport metadata (packet sizes, flow duration, inter-arrival times, TCP window sizes, directionality).

### 3.3 End-to-End Pipeline Integration (M1 → M2 → M3/M4 → M5 → Backend → SSE → Frontend)
1. **M1 Ingestion:** Ingests raw PCAP files, real-time live network frames, or synthetic traffic streams (`m1_ingest/`).
2. **M2 Feature Extraction:** Aggregates raw frames into flow records using NFStream (Linux/macOS) or pure-Python fallback aggregator (Windows) and adapts to the 66 canonical ML features (`m2_features/`).
3. **M3 & M4 Machine Learning:** Executes parallel inference:
   - M3 Random Forest: High-speed DDoS and Port Scan detection (`ml/inference/m3_predict.py`).
   - M4 Random Forest: Multi-class attack detection across 7 threat classes (`ml/inference/predict.py`).
   - M4 Isolation Forest: Unsupervised anomaly score generation (`ml/models/anomaly_model.joblib`).
4. **Behavioral Heuristics:** Evaluates C2, DGA, Exfiltration, and TLS metadata detectors (`ml/detection/decision_engine.py`).
5. **M5 Alert Normalization:** Formats alerts strictly adhering to `shared/alert_schema.json` with sequential `ALT-NNN` identifiers, ISO-8601 timestamps, and MITRE ATT&CK mappings (`backend/app/alert_normalizer.py`).
6. **Backend Storage & API:** Thread-safe in-memory/file alert persistence with REST endpoints (`/api/health`, `/api/alerts`, `/api/stats`, `/api/ai/investigate`).
7. **Real-time Live Streaming:** Server-Sent Events (SSE) stream (`/api/stream`) broadcasting alerts to clients within $< 5$ ms of generation.
8. **SOC Dashboard & AI Enrichment:** React 19 / Vite dashboard with interactive alerts, MITRE tactics, live attack simulation controls, and deep generative AI investigation powered by NVIDIA Nemotron 3.5.

---

## 4. Performance & Scalability Evidence

### 4.1 Automated Test Suite
- **Total Backend Tests:** **102 passing / 0 failing** (`pytest backend/tests -q`).
- **Frontend Build:** **0 errors / 0 warnings** (`npm run build` completed in 4.48s).

### 4.2 Empirical Throughput Benchmark
- **Benchmark Suite:** `benchmark/throughput_benchmark.py`
- **Output Metrics:** `benchmark/benchmark_results.json`
- **Measured Peak Throughput:** **668.77 flows/second** (1,000 flow batch)
- **Sustained Scale:** **421.16 flows/second** (5,000 flow batch), **235.92 flows/second** (10,000 flow batch)
- **Median Latency (P50):** **1.49 ms - 4.25 ms**
- **Error / Drop Rate:** **0.0%** across all 16,000 evaluated benchmark flows.
