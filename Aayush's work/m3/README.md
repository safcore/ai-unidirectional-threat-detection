# Module 3 (M3) — AI Threat Detection Engine

> **NTRO Problem Statement 26145 — Unidirectional Threat Detector**  
> **Module**: M3 (AI Threat Classifier)  
> **Scope**: DDoS (SYN_FLOOD, UDP_FLOOD) & Reconnaissance (PORT_SCAN) Detection  
> **Engine**: scikit-learn RandomForestClassifier (CPU-efficient, Offline)  

---

## 1. Overview & Architecture

Module 3 sits directly downstream of Module 2 (M2) in the PS 26145 pipeline:
```text
  [M1: Ingestion & 30s Windowing]
                 │
                 ▼ (FlowWindow: 30-second packet window)
  [M2: NFStream Feature Extraction]
                 │
                 ▼ (pandas.DataFrame: 82 columns)
  [M3: AI Threat Detection Engine]
                 │
                 ▼ (ThreatAlert dict / latest_alert.json)
  [M4 / M5: Alert Correlator & SOC Triage]
```

### Supported Threat Classes
- `BENIGN`
- `SYN_FLOOD`
- `UDP_FLOOD`
- `PORT_SCAN`

---

## 2. Directory Structure

```text
c:\Aayush\SIH\m3\
├── __init__.py               # Public API exports
├── schema.py                 # ThreatClass, SeverityLevel, ThreatAlert dataclass
├── features.py               # 82-column -> 76 ML feature extraction & one-hot encoding
├── model.py                  # ThreatClassifier wrapper with joblib persistence
├── fallback_data.py          # Synthetic fallback smoke-test dataset (smoke-test ONLY)
├── train.py                  # Offline training CLI with strict fail-safe rules
├── detector.py               # Streaming runtime threat inference engine
├── runner.py                 # Standalone demo runner (consumes m2_output_for_ai.csv)
├── README.md                 # Module documentation
├── models/
│   ├── threat_detector.joblib       # Serialized scikit-learn model
│   └── threat_detector_metadata.json# Training data provenance & metrics
└── tests/
    ├── __init__.py
    ├── test_features.py       # One-hot encoding & identifier exclusion tests
    ├── test_train_fail_safe.py# Training fail-safe & metadata tests
    ├── test_detector.py       # Inference, alert schema & severity tests
    └── test_runner.py         # End-to-end runner test
```

---

## 3. Data Handoff & ML Features

### Identifiers Excluded from ML Training
To prevent spurious correlation and preserve generalization, the following columns are strictly excluded from the ML feature matrix and preserved only for alert reporting:
`window_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol_name`, `application_name`, `application_category_name`.

### Categorical Encoding for `Port Access Type`
M2's `Port Access Type` is one-hot encoded into three binary columns (avoiding arbitrary ordinal ordering):
- `port_access_SINGLE` (1.0 or 0.0)
- `port_access_SEQUENTIAL` (1.0 or 0.0)
- `port_access_RANDOM` (1.0 or 0.0)

**Total Model Features**: Exactly **76 numeric features** derived from M2's 82-column schema.

---

## 4. How to Run

### Run Unit Tests (10 Tests)
```powershell
python -m unittest discover -s c:\Aayush\SIH\m3\tests -p "test_*.py" -v
```

### Run Standalone Demo Runner (Consumes `m2_output_for_ai.csv`)
```powershell
python -m m3.runner --csv c:\Aayush\SIH\m2_output_for_ai.csv
```

### Train Offline Model
#### A. Using Real Labelled CSV (Primary Production Path):
```powershell
python -m m3.train --data path/to/labelled_m2_traffic.csv
```

#### B. Using Labelled PCAP Directory (via M2 Batch Extractor):
```powershell
python -m m3.train --pcap-dir path/to/labelled_pcaps/
```

#### C. Running Internal Smoke-Test (Explicit Fallback Only):
```powershell
python -m m3.train --smoke-test
```
> [!NOTE]
> If neither `--data` nor `--pcap-dir` is provided and `--smoke-test` is omitted, `train.py` fails immediately.

---

## 5. Downstream Handoff Output (`latest_alert.json`)

When an attack flow is detected, M3 outputs a structured alert for M4/M5/M6:
```json
{
    "timestamp": "2026-09-03T04:58:54.565809+00:00",
    "window_id": "w_demo",
    "flow_id": "192.168.1.100:12345->10.0.0.5:80/TCP",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.5",
    "src_port": 12345,
    "dst_port": 80,
    "protocol": "TCP",
    "threat_class": "SYN_FLOOD",
    "confidence": 0.66,
    "severity": "CRITICAL",
    "evidence": {
        "syn_flag_count": 100,
        "ack_flag_count": 0,
        "total_fwd_packets": 100,
        "total_bwd_packets": 0,
        "flow_packets_per_sec": 16666.67,
        "down_up_ratio": 0.0,
        "tcp_flag_bitmask": 2
    }
}
```
