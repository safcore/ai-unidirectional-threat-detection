# Data Directory & Dataset Storage Policy

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Module:** M4 — Advanced Threat Classifier B  

---

## 1. Overview & Storage Rules

The `data/` directory contains runtime threat intelligence JSON files, data schema validation outputs, and guidelines for placing raw datasets.

> [!CAUTION]
> **Git Tracking Policy:** Large raw datasets (e.g., CICIDS2017 CSV files) and PCAP network trace files ($> 100$ MB) are explicitly **EXCLUDED** from Git tracking via `.gitignore` to prevent repository bloating.

---

## 2. Directory Breakdown

```text
data/
├── README.md                   # Data storage policy & dataset instructions (This file)
├── threat_intel/               # Offline threat intelligence JSON stores (Committed)
│   ├── known_iocs.json         # High-confidence IP/domain indicator store
│   ├── malicious_ips.json      # Known malicious IPv4 addresses
│   └── malicious_domains.json  # Known malicious DGA/C2 domains
├── processed/                  # Small processed metrics & validation reports
│   └── data_validation_report.md
└── raw/                        # Local raw dataset storage (Ignored by Git)
    └── cicids2017/             # Expected location for raw CICIDS2017 CSVs
```

---

## 3. Required Local Datasets

To run full model retraining or dataset cleaning routines locally, download the **CICIDS2017** dataset from the official Canadian Institute for Cybersecurity repository and place the raw CSV files into `data/raw/cicids2017/`:

- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
- `Tuesday-WorkingHours.pcap_ISCX.csv`
- `Wednesday-workingHours.pcap_ISCX.csv`

---

## 4. Runtime Requirements

For inference and real-time detection (`predict.py`, `detection_engine.py`, `incident_manager.py`), **raw datasets are not required**. The pre-trained model artifacts are stored in `ml/models/`.
