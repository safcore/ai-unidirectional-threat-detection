# INTEGRATION_QUICK_REFERENCE.md — 1-Page Quick Reference Guide

**M4 Owner:** Aayushman Parab  
**Recipient:** Krisha (M3 + M5 Lead)  
**Project:** SIH 2026 — AI Cyber Threat Detection  

---

## 1. Quick Technical Summary

- **M4 Input:** Dictionary of 66 numerical features (`ml/models/feature_schema.json`).
- **M4 Output:** Normalized ISO-8601 Threat Event JSON with `threat_class`, `confidence`, `risk_score`, `severity`, `mitre`, and `alert`.
- **M3 Task:** Classify M2 flow vectors into DDoS, PortScan, or DoS threat classes.
- **M5 Task:** Map predictions to MITRE ATT&CK techniques (`T1046`, `T1498`, etc.) and emit standard JSON alert payloads.

---

## 2. Key File Paths

```text
ml/models/classifier.joblib              # Trained Baseline Random Forest (FROZEN)
ml/models/feature_schema.json            # 66-Feature Vector Contract (FROZEN)
ml/inference/predict.py                  # Predict interface: predict(features)
ml/detection/detection_engine.py         # Main Orchestrator: engine.process(features)
ml/mitre/attack_mapper.py                # MITRE ATT&CK Enterprise v14.1 Mapper
ml/risk/risk_engine.py                   # 0-100 Risk Score Engine
ml/investigation/incident_manager.py     # Incident Builder & Timeline Engine
m4_threat_classifier/ai/nemotron_client.py # NVIDIA Nemotron 3.5 Lightning AI Client
```

---

## 3. Execution & Verification Commands

```powershell
# 1. Run direct Nemotron NIM API inference test
python test_nemotron.py

# 2. Run integrated component test script
python run_all_tests.py

# 3. Run full automated test suite (41 tests)
pytest
```

---

## 4. Frozen Components (DO NOT MODIFY)

- `ml/models/*` (`classifier.joblib`, `anomaly_model.joblib`, `preprocessing_pipeline.joblib`, `feature_schema.json`)
- `ml/detection/decision_engine.py` (Phase 3 Decision Rules)
- `ml/investigation/incident_manager.py` (Phase 4 Incident Engine)
- `m4_threat_classifier/detection/*` (DGA, C2, Exfiltration Detectors)
