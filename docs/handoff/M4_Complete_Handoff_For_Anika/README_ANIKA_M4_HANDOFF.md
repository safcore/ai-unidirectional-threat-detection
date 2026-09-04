# README_ANIKA_M4_HANDOFF.md — M4 Backend Integration Guide for Anika

**Target Lead:** Anika (M6 Backend & SSE Lead)  
**Author:** Aayushman Parab (M4 Lead ML & Security Investigation Engineer)  
**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Package:** `M4_Complete_Handoff_For_Anika.zip`  

---

## 1. Executive Summary & Purpose

This handoff package contains the complete, production-ready source code, serialized model artifacts, detection engines, Phase 4 investigation pipelines, test suites, and API contracts for **M4 — Advanced Threat Classifier B / SOC Investigation Layer**.

This package is prepared specifically for **Anika** to integrate the M4 core engine with the Flask REST API and SSE (Server-Sent Events) live streaming backend.

---

## 2. System Capability & Ownership Boundaries

### What M4 OWNS (Aayushman):
- **Parallel M3 + M4 ML Inference:** Random Forest Classifier + Isolation Forest Anomaly Detector + M3 DDoS/PortScan adapter.
- **Advanced Behavioral Detectors:** DGA (Domain Generation Algorithm) Detector, C2 (Command & Control) Detector, Data Exfiltration Detector.
- **Phase 3 Real-time Decision Engine:** Schema validation, decision precedence, alert object generation.
- **Phase 4 SOC Investigation Engine:** IOC extraction & threat intel enrichment, MITRE ATT&CK mapping (`T1046`, `T1498`, etc.), threat correlation & attack chain reconstruction, 0–100 risk scoring engine, timeline generation, explainability engine.
- **NVIDIA Nemotron 3.5 Lightning AI Layer:** Hosted NIM API client (`https://integrate.api.nvidia.com/v1`) generating qualitative LLM SOC briefings with fail-safe fallback (`status: "AI_UNAVAILABLE"`).

### What Other Team Members OWN:
- **Meet (M1):** Network packet streaming, `threading.Queue`, PCAP replay, packet ingestion.
- **Aayush (M2):** Scapy/Pandas real-time 66-feature vector extraction.
- **Krisha (M3 + M5):** `m3_ddos_portscan_classifier.joblib` artifact (DDoS/PortScan model), M5 MITRE mapper & alert schema.
- **Anika (M6 Backend):** Flask application wrapper, SSE live event streaming, API routing, attack generator integration.
- **Safina (M6 Frontend):** Dashboard UI, alert feeds, live network flow visualization.

---

## 3. How Anika Integrates M4 in Flask / SSE

Anika should call M4 functions directly in Flask route handlers or SSE generator functions.

### Option A: Standard Real-Time Detection Flow
```python
from ml.detection.detection_engine import get_detection_engine

# Single instance initialized at app startup
engine = get_detection_engine()

# Process incoming M2 feature dict (66 features) + network metadata
event = engine.process(features_dict, metadata={"src_ip": "10.0.0.5", "dst_ip": "10.0.0.20"})

# event contains: status, event_id, timestamp, threat_class, decision, confidence,
# anomaly_score, probabilities, classifications (m3 & m4), source, destination, alert
```

### Option B: Full Phase 4 Incident Investigation Flow
```python
from ml.investigation.incident_manager import get_incident_manager

mgr = get_incident_manager()

# Process Phase 3 event through Phase 4 pipeline
incident = mgr.process_event(event)

# incident.to_dict() contains: incident_id, title, status, risk_score (0-100), risk_level,
# mitre_mappings, iocs, attack_chain, timeline, explanation
```

### Option C: NVIDIA Nemotron AI SOC Analysis
```python
from m4_threat_classifier.ai.nemotron_client import get_nemotron_client

nemotron = get_nemotron_client()
ai_result = nemotron.analyze_incident(incident.to_dict())
```

---

## 4. Shared Input & Parallel Classification Contract

M4 expects the **canonical M2 66-feature record** defined in `ml/models/feature_schema.json`.

```text
                             M2 66-Feature Vector
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
          M3 Classifier (Krisha)                M4 Pipeline (Aayushman)
        (DDOS / PORT_SCAN Focus)               (Random Forest + Isolation Forest)
                    │                                     │
                    ▼                                     ▼
             classifications.m3                   classifications.m4
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                          Unified Orchestrated Event
                                       │
                       ┌───────────────┼───────────────┐
                       ▼               ▼               ▼
                      DGA             C2          Exfiltration
                                       │
                                       ▼
                          Phase 3 Decision Precedence
                                       │
                                       ▼
                          Phase 4 SOC Investigation
                                       │
                                       ▼
                       NVIDIA Nemotron 3.5 Lightning NIM
```

### Classification Output Structure:
```json
{
  "status": "success",
  "threat_class": "DDOS",
  "confidence": 0.994,
  "anomaly_score": 0.05,
  "classifications": {
    "m3": {
      "threat_class": "DDOS",
      "confidence": 0.994,
      "probabilities": { "BENIGN": 0.006, "DDOS": 0.994, "PORT_SCAN": 0.0 },
      "anomaly_score": 0.0
    },
    "m4": {
      "threat_class": "BENIGN",
      "confidence": 0.85,
      "probabilities": { "BENIGN": 0.85, "DDOS": 0.05, "PORT_SCAN": 0.02 },
      "anomaly_score": 0.05
    }
  }
}
```

---

## 5. Serialized Model Artifact Checksums (SHA-256)

All model binaries are 100% byte-for-byte identical to original production artifacts:

| Artifact Name | Location | Size (MB) | SHA-256 Checksum | Status |
| :--- | :--- | :--- | :--- | :--- |
| **M4 Classifier** | `ml/models/classifier.joblib` | 10.94 MB | `5a18b5b9a46bb0ba16f335edcc5c7be494b6ecadfe2f4afa24ef8ad67d0f3626` | **UNCHANGED** |
| **M4 Anomaly Model** | `ml/models/anomaly_model.joblib` | 0.78 MB | `5541b4515d6758481207e846bf608d30fdc8e24528e9e32f90b4f2f25d9e9df8` | **UNCHANGED** |
| **M4 Preprocessor** | `ml/models/preprocessing_pipeline.joblib` | 0.00 MB | `9c298d589a2158eb513cb52191144518a2acab2cb0c04f1df14fca0f712fa4a1` | **UNCHANGED** |
| **M4 Feature Schema** | `ml/models/feature_schema.json` | 0.02 MB | `c41b032e71921bd8d862e7ea947d58d4de6c9311f39214b5f618b2c97ed6a6b2` | **UNCHANGED** |
| **M3 Classifier** | `ml/models/m3_ddos_portscan_classifier.joblib` | 10.77 MB | `2df5c02f749cf14d988ba3366940bd11ed5bc66dbab5e707a057c031075a8b2d` | **UNCHANGED** |

---

## 6. Test Baseline Results

- **`pytest`:** **`49 passed` in 17.59s** (41 baseline + 8 integration tests)
- **`python run_all_tests.py`:** **`ALL TESTS EXECUTED CLEANLY`**
- **`python test_nemotron.py`:** **`PASS — HTTP 200 — NEMOTRON_OK`**
