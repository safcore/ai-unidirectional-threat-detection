# M3 (Threat Classifier A) + M4 (Advanced Threat Classifier B) Integration Architecture

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Modules:** M3 (DDoS / PortScan Random Forest - Krisha) + M4 (Advanced Threat Classifier B / Phase 4 - Aayushman)  
**Primary Artifact:** `ml/models/m3_ddos_portscan_classifier.joblib`  

---

## 1. Executive Summary & Integration Architecture

Krisha's independent `m3_ddos_portscan_classifier.joblib` model has been integrated in parallel with Aayushman's M4 classification pipeline. Both classifiers operate concurrently over the exact same canonical M2 66-feature vector record, preserving both predictions under `classifications["m3"]` and `classifications["m4"]`.

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

---

## 2. Artifact SHA-256 Checksum Verification Table

| Artifact Name | Status | Size (MB) | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **`m3_ddos_portscan_classifier.joblib`** | **UNCHANGED** | 10.77 MB | `2df5c02f749cf14d988ba3366940bd11ed5bc66dbab5e707a057c031075a8b2d` |
| **`classifier.joblib`** | **UNCHANGED** | 10.94 MB | `5a18b5b9a46bb0ba16f335edcc5c7be494b6ecadfe2f4afa24ef8ad67d0f3626` |
| **`anomaly_model.joblib`** | **UNCHANGED** | 0.78 MB | `5541b4515d6758481207e846bf608d30fdc8e24528e9e32f90b4f2f25d9e9df8` |
| **`preprocessing_pipeline.joblib`** | **UNCHANGED** | 0.00 MB | `9c298d589a2158eb513cb52191144518a2acab2cb0c04f1df14fca0f712fa4a1` |
| **`feature_schema.json`** | **UNCHANGED** | 0.02 MB | `c41b032e71921bd8d862e7ea947d58d4de6c9311f39214b5f618b2c97ed6a6b2` |

---

## 3. Shared 66-Feature Input Contract

Both M3 and M4 receive the exact same 66 numerical feature column vector defined in `ml/models/feature_schema.json`.

Features passed to `predict(features)` or `DetectionEngine.process(features)` are formatted and passed in parallel without modifying feature values or column ordering.

- **M3 Preprocessing:** Handled internally by Krisha's `M3Predictor` adapter (`ml/inference/m3_predict.py`), formatting the canonical 66 features into DataFrame columns matching `feature_schema.json`.
- **M4 Preprocessor:** Uses `preprocessing_pipeline.joblib` (`StandardScaler`) to scale features for M4's Random Forest classifier.

---

## 4. Output Structure & Non-Overwrite Guarantee

The normalized output retains both model predictions independently:

```json
{
  "status": "success",
  "event_id": "8f3b2a1c-...",
  "threat_class": "DDOS",
  "confidence": 0.994,
  "anomaly_score": 0.05,
  "classifications": {
    "m3": {
      "threat_class": "DDOS",
      "confidence": 0.994,
      "probabilities": {
        "BENIGN": 0.006,
        "DDOS": 0.994,
        "PORT_SCAN": 0.0
      },
      "anomaly_score": 0.0
    },
    "m4": {
      "threat_class": "BENIGN",
      "confidence": 0.85,
      "probabilities": {
        "BENIGN": 0.85,
        "DDOS": 0.05,
        "PORT_SCAN": 0.02,
        "DOS": 0.08
      },
      "anomaly_score": 0.05
    }
  }
}
```

---

## 5. Deterministic Conflict Resolution Rules

1. **Independent Retention:** `classifications.m3` and `classifications.m4` are always preserved independently in raw prediction format.
2. **Unified Threat Precedence:**
   - **Rule A (M3 DDOS / PORT_SCAN):** If M3 predicts `DDOS` or `PORT_SCAN` with high confidence ($\ge 0.70$) and M4 predicts `BENIGN`, the primary `threat_class` prioritizes M3's primary threat detection (`DDOS`/`PORT_SCAN`).
   - **Rule B (M4 Advanced Threats):** If M4's advanced detector detects `DGA`, `C2`, or `EXFILTRATION`, M4's advanced detection result drives the unified decision according to existing M4 precedence rules.
   - **Rule C (BENIGN Agreement):** If both predict `BENIGN`, the primary `threat_class` is `BENIGN`.

---

## 6. API Compatibility & Endpoints

Updated endpoints:
- `POST /api/v1/detect`
- `POST /api/v1/investigations/events`

Both endpoints expose:
```json
"classifications": {
    "m3": { ... },
    "m4": { ... }
}
```
Existing fields, headers, and HTTP contracts are 100% backward compatible.

---

## 7. Files Added & Modified

### Files Added:
1. `ml/models/m3_ddos_portscan_classifier.joblib`
2. `ml/config/m3_config.py`
3. `ml/inference/m3_predict.py`
4. `tests/test_m3_m4_integration.py`
5. `docs/integration/M3_M4_INTEGRATION.md`

### Files Modified:
1. `ml/inference/predict.py`
2. `ml/detection/detection_engine.py`

### Frozen Files Verified Unchanged:
1. `ml/models/classifier.joblib`
2. `ml/models/anomaly_model.joblib`
3. `ml/models/preprocessing_pipeline.joblib`
4. `ml/models/feature_schema.json`
5. `m4_threat_classifier/detection/dga_detector.py`
6. `m4_threat_classifier/detection/c2_detector.py`
7. `m4_threat_classifier/detection/exfiltration_detector.py`
8. `ml/detection/decision_engine.py`
9. `ml/investigation/incident_manager.py`
10. `m4_threat_classifier/ai/nemotron_client.py`

---

## 8. Final Testing & Validation Results

```text
M3 + M4 Parallel Integration Results
=====================================
BENIGN Flow Scenario            : PASS
DDOS Flow Scenario              : PASS
PORT_SCAN Flow Scenario         : PASS
M4-Specific Attack (DGA/C2/Exf) : PASS

M3 Result Preserved             : PASS (classifications.m3)
M4 Result Preserved             : PASS (classifications.m4)
Shared 66 Features              : PASS (Canonical Schema)
Phase 4 Pipeline Preserved      : PASS (IncidentManager & Timeline)
Nemotron AI Preserved           : PASS (SUCCESS)

Pytest Baseline Tests           : 41/41 PASS
New Integration Tests           : 8/8 PASS
Total Pytest Suite              : 49/49 PASS in 9.72s
```
