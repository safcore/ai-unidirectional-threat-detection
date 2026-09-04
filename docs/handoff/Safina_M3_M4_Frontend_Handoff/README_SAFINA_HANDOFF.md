# README_SAFINA_HANDOFF.md — Frontend Integration Handoff Guide

**Target Audience:** Safina (M6 Frontend UI Lead)  
**Author:** Aayushman Parab (M4 Lead ML & Security Investigation Engineer)  
**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Package:** `docs/handoff/Safina_M3_M4_Frontend_Handoff.zip`  

---

## 1. Executive Overview

This handoff package provides all API response schemas, classification contracts, realistic JSON sample payloads, and endpoint documentation required to build the **Frontend SOC Dashboard UI**.

The threat detection pipeline runs **M3 (Krisha)** and **M4 (Aayushman)** in parallel over canonical 66-feature flow records extracted by **M2 (Aayush)** from packets ingested by **M1 (Meet)**. Results are served via REST API endpoints built by **Anika (M6 Backend)**.

---

## 2. End-to-End System Architecture

```text
M1 Packet Ingestion Pipeline (Meet)
        ↓
M2 66-Feature Extraction (Aayush)
        ↓
Canonical 66-Feature Flow Record
        ↓
 ┌───────────────┐
 │               │
 ▼               ▼
M3              M4
 │               │
 │               ├── Random Forest Classifier
 │               ├── Isolation Forest Anomaly Detector
 │               ├── DGA Detector
 │               ├── C2 Behavioral Detector
 │               └── Exfiltration Detector
 │               │
 └───────┬───────┘
         ↓
 Unified Threat Event
         ↓
 Phase 3 Decision & Precedence Engine
         ↓
 Phase 4 SOC Incident Investigation
 (Risk 0-100 + IOCs + MITRE + Timeline)
         ↓
 NVIDIA Nemotron 3.5 Lightning AI
         ↓
 Flask REST API (Anika / M6 Backend)
         ↓
 Safina Frontend SOC Dashboard
```

---

## 3. Module Responsibilities Matrix

| Team Member | Module | System Responsibilities |
| :--- | :--- | :--- |
| **Meet** | **M1** | Packet streaming, `threading.Queue`, PCAP replay, zero packet drop. |
| **Aayush** | **M2** | Real-time Scapy/Pandas 66-feature DataFrame extraction. |
| **Aayushman** | **M4** | Random Forest, Isolation Forest, DGA/C2/Exfiltration detectors, Phase 4 Investigation (Risk, MITRE, Timeline), Nemotron AI layer. |
| **Krisha** | **M3 + M5** | DDoS & PortScan classifier, MITRE ATT&CK technique mapper, standardized alert JSON. |
| **Anika** | **M6 Backend** | Flask REST API, SSE streaming, attack generator endpoints. |
| **Safina** | **M6 Frontend** | Interactive SOC Dashboard UI, alert feeds, live threat visualization, Nemotron briefing widget. |

---

## 4. Phase 4 Investigation Field Availability Check

Safina specifically inquired about the presence of investigation fields in the backend response. Here is the authoritative status:

- **`risk_score`:** **PRESENT** (`incident["risk_score"]`: 0.0 to 100.0 numerical engineering score; `incident["risk_level"]`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **`IOC`:** **PRESENT** (`incident["iocs"]`: List of extracted IP/domain IOC dictionaries with reputation and hit counts).
- **`correlation`:** **PRESENT** (`incident["attack_chain"]` & `incident["timeline"]`: Chronological multi-event entity correlation).
- **`AI analysis status`:** **PRESENT** (`incident["explanation"]` / `POST /api/v1/ai/analyze` response: `status`: `SUCCESS` / `AI_UNAVAILABLE`).

---

## 5. Verified Test Suite Baseline

- **`pytest`:** **`49 passed` in 11.21s**
- **`python test_nemotron.py`:** **`PASS — HTTP 200 — NEMOTRON_OK`**
- **`python run_all_tests.py`:** **`ALL TESTS EXECUTED CLEANLY`**
