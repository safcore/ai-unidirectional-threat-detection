# README_KRISHA_M3_M5_TASK.md — Krisha's Assigned Responsibility & Task Guide

**Assigned Engineer:** Krisha  
**Modules Owned:** **M3 — Threat Classifier A** + **M5 — MITRE Mapper & Alert Schema Engine**  
**Upstream System:** M4 (Advanced Threat Classifier B / Investigation Layer - Aayushman)  

---

# KRISHA — YOUR RESPONSIBILITY

Welcome! You are responsible for:
1. **M3 — Threat Classifier A:** Building/integrating real-time classification models focusing specifically on **DDoS** and **Port Scanning** attack vectors.
2. **M5 — MITRE Mapper & Alert Schema Engine:** Taking normalized threat classification outputs and generating standardized JSON alert payloads enriched with MITRE ATT&CK technique IDs and telemetry evidence.

You should **BUILD ON TOP OF** the M4 system rather than creating duplicate or conflicting implementations.

---

## 1. M3 — Threat Classifier A Implementation Guide

### A. Interface with M4
M3 receives clean 66-feature vector DataFrames from M2 (Aayush) and produces threat predictions.

You must consume the canonical feature schema contract defined in:
`ml/models/feature_schema.json`

### B. Output Format
Normalize your M3 classification output into the standard M4 prediction format:
```python
{
    "threat_class": "DDoS",             # e.g., DDoS, PortScan, DoS, BENIGN
    "confidence": 0.994,
    "probabilities": {
        "DDoS": 0.994,
        "BENIGN": 0.006
    },
    "anomaly_score": 0.05,
    "is_anomalous": False
}
```

### C. M3 Classifier Requirements
- Prepare your train/validation/test dataset splits.
- Evaluate precision, recall, F1-score, and confusion matrices for DDoS and PortScan classes.
- Save trained model artifacts alongside M4 in `ml/models/`.
- **Do NOT modify M4's existing `classifier.joblib` artifact.**

---

## 2. M5 — MITRE Mapper & Alert Schema Engine

### A. ATT&CK Mapping Integration
Import and utilize M4's evidence-based mapper (`ml/mitre/attack_mapper.py`):
```python
from ml.mitre.attack_mapper import MITREAttackMapper

mapper = MITREAttackMapper()
mappings = mapper.map_event(threat_event)
```

Supported Mappings:
- **`T1046`** (Network Service Scanning) $\rightarrow$ `PORT_SCAN`
- **`T1110`** (Brute Force) $\rightarrow$ `FTP_PATATOR`, `SSH_PATATOR`
- **`T1190`** (Exploit Public-Facing Application) $\rightarrow$ `WEB_ATTACK`
- **`T1498`** (Network Denial of Service) $\rightarrow$ `DDoS`, `DoS`
- **`T1071`** (Application Layer Protocol) $\rightarrow$ `LIKELY_C2`
- **`T1090`** (Proxy/Anonymization) $\rightarrow$ `SUSPICIOUS_EXFILTRATION`

### B. Standardized Alert JSON Schema Contract

Every generated alert payload must conform to this schema contract:

```json
{
  "alert_id": "alt-550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-09-03T21:35:00.000Z",
  "source_ip": "10.0.0.5",
  "destination_ip": "10.0.0.20",
  "source_port": 54321,
  "destination_port": 80,
  "protocol": "TCP",
  "threat_class": "DDoS",
  "confidence": 0.994,
  "severity": "HIGH",
  "risk_score": 78.5,
  "evidence": [
    "High forward packet rate (12,000 pps)",
    "Asymmetric byte transfer ratio"
  ],
  "mitre_mapping": {
    "technique_id": "T1498",
    "technique_name": "Network Denial of Service",
    "tactic": "Impact",
    "confidence": 0.95
  },
  "ioc_data": {
    "extracted_iocs": ["10.0.0.5"],
    "intel_hits": []
  },
  "correlation_data": {
    "entity_id": "ent-10-0-0-5",
    "correlated_event_count": 4
  },
  "ai_analysis": {
    "status": "SUCCESS",
    "model": "nvidia/nemotron-3.5-lightning-30b-a3b"
  }
}
```

---

## 3. M3 / M4 / M5 INTEGRATION CONTRACT

```text
                 M2 Real-Time Packets/Flows
                             │
                             ▼
                   Common 66-Feature Vector
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
       M3 Classifier (Krisha)        M4 Classifier (Aayushman)
      (DDoS / PortScan focus)      (DGA / C2 / Exfiltration)
              │                             │
              └──────────────┬──────────────┘
                             ▼
                   Normalized Threat Event
                             │
                             ▼
                  M5 MITRE Mapper (Krisha)
                             │
                             ▼
                   Phase 4 SOC Investigation
                             │
                             ▼
                NVIDIA Nemotron AI Briefing
```

---

## 4. WHAT KRISHA MUST NOT MODIFY

```text
DO NOT MODIFY WITHOUT EXPLICIT COORDINATION:

- ml/models/classifier.joblib (M4 Baseline Random Forest)
- ml/models/anomaly_model.joblib (M4 Isolation Forest)
- ml/models/preprocessing_pipeline.joblib (StandardScaler)
- ml/models/feature_schema.json (Canonical 66-Feature Vector Schema)
- ml/detection/decision_engine.py (Phase 3 Decision Precedence)
- ml/investigation/incident_manager.py (Phase 4 Risk & Correlation Engine)
- m4_threat_classifier/detection/dga_detector.py
- m4_threat_classifier/detection/c2_detector.py
- m4_threat_classifier/detection/exfiltration_detector.py
- m4_threat_classifier/ai/nemotron_client.py
```

---

## 5. KRISHA'S TEST PLAN

Run this verification sequence on your machine after extracting the handoff package:

### Step 1: Run Full Automated Unit Test Suite
```powershell
pytest
```
*Expected Result:* `41 passed`

### Step 2: Test M4 Integrated System Script
```powershell
python run_all_tests.py
```
*Expected Result:* All component tests PASS with Nemotron AI client reporting `SUCCESS`.

### Step 3: Run Direct Nemotron CLI Test
```powershell
python test_nemotron.py
```
*Expected Result:* `DIRECT NIM TEST: PASS — HTTP 200 — NEMOTRON_OK`.

---

## 6. DEAD-END / ENGINEERING RULE

> **DO NOT blindly follow implementation docs if something differs.**  
>  
> If an interface mismatch occurs:  
> 1. Inspect the live code in `ml/detection/` and `ml/mitre/`.  
> 2. Adapt your new code to fit the existing architecture.  
> 3. Do not duplicate existing functionality.  
> 4. Do not overwrite frozen M4 model files.  
> 5. Document any architectural adjustments clearly.
