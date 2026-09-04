# AI Unidirectional Threat Detection Platform

Near-real-time AI/ML pipeline for detecting and classifying cyber threats from unidirectional IP traffic using passive network telemetry (SIH 2026 PS145).

---

## 1. System Overview & Architecture

The platform orchestrates real-time packet ingestion (M1), 66-feature extraction (M2), parallel ML classification (M3 & M4), advanced behavioral threat detection (DGA, C2, Exfiltration), deterministic decision precedence (Phase 3), SOC incident investigation (Phase 4), and qualitative AI briefing generation via NVIDIA Nemotron 3.5 Lightning NIM API.

```text
               M1 Packet Ingestion Pipeline (Meet)
                                │
                                ▼
             M2 Real-Time Feature Extractor (Aayush)
                                │
                                ▼
                   Canonical 66-Feature Vector
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
                  (Risk 0-100 + IOCs + MITRE + Timeline)
                                │
                                ▼
                NVIDIA Nemotron 3.5 Lightning NIM
                                │
                                ▼
               Flask REST API & SSE Stream (Anika)
                                │
                                ▼
                 Safina Frontend SOC Dashboard
```

---

## 2. Directory Structure

```text
ai-unidirectional-threat-detection/
│
├── backend/                            # Anika's Flask backend & SSE service
├── shared/                             # Standardized alert schema (M5)
│
├── .env.example                        # Template environment configuration (Public)
├── .gitignore                          # Git exclusion rules
├── pytest.ini                          # Pytest configuration
├── requirements.txt                    # Production Python dependencies
├── run_all_tests.py                    # Integrated system component test runner
├── test_nemotron.py                    # Standalone NVIDIA Nemotron NIM direct CLI test runner
├── README.md                           # Master repository documentation
├── DATASETS.md                         # Dataset storage policies and PCAP exclusion rules
│
├── config/                             # Central settings & parameters
│   └── settings.py
│
├── data/                               # Threat intel & local dataset descriptors
│   ├── README.md
│   ├── threat_intel/
│   │   ├── known_iocs.json
│   │   ├── malicious_domains.json
│   │   └── malicious_ips.json
│   └── processed/
│       └── data_validation_report.md
│
├── docs/                               # System documentation & handoff packages
│   ├── handoff/                        # Handoff documentation & ZIP packages
│   │   ├── M4_Complete_Handoff_For_Anika/
│   │   ├── M4_Complete_Handoff_For_Anika.zip
│   │   ├── Safina_M3_M4_Frontend_Handoff/
│   │   └── Safina_M3_M4_Frontend_Handoff.zip
│   ├── integration/                    # M3 + M4 integration documentation
│   │   └── M3_M4_INTEGRATION.md
│   └── reports/                        # Milestone implementation reports
│       ├── m4_leftover_audit.md
│       ├── m4_leftover_implementation_report.md
│       ├── phase1_dataset_report.md
│       ├── phase2_model_evaluation.md
│       ├── phase3_integration_report.md
│       └── phase4_investigation_report.md
│
├── m4_threat_classifier/              # Advanced M4 detector modules & API routes
│   ├── ai/
│   │   └── nemotron_client.py          # Hosted NVIDIA Nemotron 3.5 Lightning client
│   ├── api/
│   │   └── routes.py                   # Flask REST API blueprint
│   └── detection/
│       ├── dga_detector.py             # Domain Generation Algorithm detector
│       ├── c2_detector.py              # Command & Control beaconing detector
│       └── exfiltration_detector.py    # Data exfiltration detector
│
├── ml/                                 # Machine Learning core library
│   ├── config/                         # Detection & M3 configs
│   │   ├── detection_config.py
│   │   └── m3_config.py
│   ├── correlation/
│   │   └── correlation_engine.py       # Entity correlation & attack chain engine
│   ├── detection/                      # Phase 3 detection engine
│   │   ├── alert_generator.py
│   │   ├── decision_engine.py
│   │   ├── detection_engine.py
│   │   ├── feature_validator.py
│   │   └── stream_processor.py
│   ├── evaluation/                     # Model evaluation metrics
│   ├── inference/                      # Parallel M3 + M4 inference engine
│   │   ├── m3_predict.py
│   │   └── predict.py
│   ├── investigation/                  # Phase 4 SOC investigation & timeline
│   │   ├── explainability.py
│   │   ├── incident_manager.py
│   │   └── timeline.py
│   ├── mitre/
│   │   └── attack_mapper.py            # MITRE ATT&CK mapper (T1046, T1498, etc.)
│   ├── models/                         # Serialized joblib artifacts & schema
│   │   ├── README.md
│   │   ├── classifier.joblib
│   │   ├── anomaly_model.joblib
│   │   ├── preprocessing_pipeline.joblib
│   │   ├── feature_schema.json
│   │   └── m3_ddos_portscan_classifier.joblib
│   ├── preprocessing/                  # Data cleaning & standardization
│   │   ├── clean.py
│   │   └── schema.py
│   ├── risk/
│   │   └── risk_engine.py              # Deterministic 0-100 risk scoring engine
│   ├── threat_intelligence/
│   │   └── enrichment_engine.py        # Threat intel IOC lookup provider
│   └── training/
│       └── loader.py                   # Dataform & schema loader
│
└── tests/                              # Automated pytest suite
    ├── test_detection_pipeline.py
    ├── test_feature_engineering.py
    ├── test_leftover_m4_nemotron.py
    ├── test_m3_m4_integration.py
    ├── test_model_pipeline.py
    ├── test_phase4_investigation.py
    └── test_preprocessing.py
```

---

## 3. Team Responsibility Matrix

| Team Member | Module | System Responsibilities | Handoff Package |
| :--- | :--- | :--- | :--- |
| **Meet** | **M1** | Packet streaming, `threading.Queue`, PCAP replay, zero drop. | `M1_Ingest_Pipeline` |
| **Aayush** | **M2** | Real-time Scapy/Pandas 66-feature vector extraction. | `M2_Feature_Extractor` |
| **Aayushman** | **M4** | Random Forest, Isolation Forest, DGA/C2/Exfil detectors, Phase 4 Investigation, Nemotron AI layer. | `M4_Complete_Handoff_For_Anika.zip` |
| **Krisha** | **M3 + M5** | DDoS & PortScan classifier (`m3_ddos_portscan_classifier.joblib`), MITRE mapper. | `M3_M5_Krisha_Work.zip` |
| **Anika** | **M6 Backend** | Flask REST API, SSE live event streaming, API routing, attack generator. | `M4_Complete_Handoff_For_Anika.zip` |
| **Safina** | **M6 Frontend** | Dashboard UI, alert feeds, live network flow visualization. | `Safina_M3_M4_Frontend_Handoff.zip` |

---

## 4. Execution & Testing Instructions

### Direct NIM API Test
```powershell
python test_nemotron.py
```

### Integrated Component Test
```powershell
python run_all_tests.py
```

### Full Automated Pytest Suite
```powershell
pytest
```
*(Expected Result: `49 passed in ~11s`)*
