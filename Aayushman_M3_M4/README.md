# Aayushman_M3_M4 — Consolidated M3 + M4 Threat Detection & Investigation Package

**Lead Engineer:** Aayushman Parab  
**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Location:** `Aayushman_M3_M4/`  

---

## 1. Overview

This folder contains the consolidated source code, model artifacts, detection engines, Phase 4 investigation pipelines, test suites, and documentation representing the complete **M3 + M4 Threat Detection Contribution**.

```text
M2 66 Features
       |
       +--------> M3 (Krisha)
       |           |
       |           +--> DDOS / PORT_SCAN Focus
       |
       +--------> M4 (Aayushman)
                   |
                   +--> Advanced Threat Detection (DGA / C2 / Exfil)
                   +--> Phase 3 Decision Engine
                   +--> Phase 4 Investigation & Risk Scoring (0-100)
                   +--> NVIDIA Nemotron 3.5 Lightning AI Analysis

Final Event Payload
    |
    +--> classifications["m3"]
    +--> classifications["m4"]
```

---

## 2. Directory Structure

```text
Aayushman_M3_M4/
├── m3/                                 # Krisha's M3 DDoS & PortScan Classifier
│   ├── model/
│   │   └── m3_ddos_portscan_classifier.joblib
│   ├── inference/
│   │   └── m3_predict.py
│   ├── config/
│   │   └── m3_config.py
│   └── tests/
│       └── test_m3_m4_integration.py
│
├── m4/                                 # Aayushman's M4 Advanced Classifier & Investigation
│   ├── models/
│   │   ├── classifier.joblib
│   │   ├── anomaly_model.joblib
│   │   ├── preprocessing_pipeline.joblib
│   │   └── feature_schema.json
│   ├── inference/
│   │   └── predict.py
│   ├── detection/
│   │   ├── feature_validator.py
│   │   ├── decision_engine.py
│   │   ├── alert_generator.py
│   │   ├── detection_engine.py
│   │   ├── stream_processor.py
│   │   ├── dga_detector.py
│   │   ├── c2_detector.py
│   │   └── exfiltration_detector.py
│   ├── threat_intelligence/
│   │   ├── ioc_extractor.py
│   │   ├── intel_provider.py
│   │   ├── cache.py
│   │   └── enrichment_engine.py
│   ├── mitre/
│   │   ├── technique_store.py
│   │   └── attack_mapper.py
│   ├── correlation/
│   │   ├── entity_tracker.py
│   │   ├── attack_chain.py
│   │   └── correlation_engine.py
│   ├── risk/
│   │   └── risk_engine.py
│   ├── investigation/
│   │   ├── timeline.py
│   │   ├── explainability.py
│   │   └── incident_manager.py
│   ├── ai/
│   │   └── nemotron_client.py
│   ├── api/
│   │   └── routes.py
│   ├── config/
│   │   └── detection_config.py
│   └── evaluation/
│       ├── integration_benchmark.py
│       ├── run_benchmark_cli.py
│       └── phase4_evaluation.py
│
├── data/                               # Threat Intel Indicators
│   └── threat_intel/
│       ├── malicious_ips.json
│       ├── malicious_domains.json
│       └── known_iocs.json
│
├── tests/                              # Automated Pytest Suite
│   ├── test_detection_pipeline.py
│   ├── test_feature_engineering.py
│   ├── test_leftover_m4_nemotron.py
│   ├── test_model_pipeline.py
│   ├── test_phase4_investigation.py
│   ├── test_preprocessing.py
│   └── test_m3_m4_integration.py
│
├── examples/                           # Real JSON Output Samples
│   ├── FINAL_M3_M4_OUTPUT.json
│   ├── FINAL_M3_M4_OUTPUT_EXPLAINED.md
│   ├── BENIGN.json
│   ├── DDOS.json
│   ├── PORT_SCAN.json
│   └── M4_ATTACK.json
│
├── reports/                            # Implementation & Evaluation Reports
│   ├── phase3_integration_report.md
│   ├── phase4_investigation_report.md
│   ├── m4_leftover_audit.md
│   └── m4_leftover_implementation_report.md
│
├── requirements.txt                    # Production Python dependencies
├── .env.example                        # Safe template environment file
├── .gitignore                          # Git exclusion rules
└── README.md                           # Master package documentation
```

---

## 3. Serialized Model Artifact Checksums (SHA-256)

| Artifact Name | Location | Size (MB) | SHA-256 Checksum | Status |
| :--- | :--- | :--- | :--- | :--- |
| **M3 Classifier** | `m3/model/m3_ddos_portscan_classifier.joblib` | 10.77 MB | `2df5c02f749cf14d988ba3366940bd11ed5bc66dbab5e707a057c031075a8b2d` | **UNCHANGED** |
| **M4 Classifier** | `m4/models/classifier.joblib` | 10.94 MB | `5a18b5b9a46bb0ba16f335edcc5c7be494b6ecadfe2f4afa24ef8ad67d0f3626` | **UNCHANGED** |
| **M4 Anomaly Model** | `m4/models/anomaly_model.joblib` | 0.78 MB | `5541b4515d6758481207e846bf608d30fdc8e24528e9e32f90b4f2f25d9e9df8` | **UNCHANGED** |
| **M4 Preprocessor** | `m4/models/preprocessing_pipeline.joblib` | 0.00 MB | `9c298d589a2158eb513cb52191144518a2acab2cb0c04f1df14fca0f712fa4a1` | **UNCHANGED** |
| **M4 Feature Schema** | `m4/models/feature_schema.json` | 0.02 MB | `c41b032e71921bd8d862e7ea947d58d4de6c9311f39214b5f618b2c97ed6a6b2` | **UNCHANGED** |
