# README_M4_COMPLETE.md — Complete M4 Implementation Documentation

**Module Owner:** Aayushman Parab (M4 — Advanced Threat Classifier B / Lead ML & Security Investigation Engineer)  
**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Repository Path:** `C:\PROJECTS\SIH PS145\AaYuushman's work\`  

---

## A. M4 Responsibility

Aayushman is responsible for **M4 — Advanced Threat Classifier B**.

Key Capabilities Implemented:
1. **CICIDS2017 Random Forest Classifier:** 99.4% F1-score baseline threat classifier trained on 1.6M flow records across 66 numerical network features.
2. **Isolation Forest Anomaly Detector:** Unsupervised outlier detector calculating flow anomaly scores.
3. **Advanced Heuristic & Behavioral Detectors:**
   - **DGA Detector:** Lexical analysis, Shannon entropy, character distribution, and TLD reputation.
   - **C2 Behavioral Detector:** Keep-alive beacon timing, inter-arrival time (IAT) variance, small control payload analysis, and target port verification (6667, 4444, 8443, etc.).
   - **Data Exfiltration Detector:** Asymmetric outbound-to-inbound byte ratios ($\ge 10:1$), unidirectional data streams, and DNS tunneling indicators (port 53).
4. **Phase 4 SOC Security Investigation Engine:** Threat intelligence enrichment, offline IOC caching, MITRE ATT&CK Enterprise v14.1 mapping, multi-event correlation, attack-chain construction, and 0–100 normalized risk scoring.
5. **NVIDIA Nemotron 3.5 Lightning AI Investigation Layer:** Hosted OpenAI-compatible NIM API client (`https://integrate.api.nvidia.com/v1`) providing qualitative LLM SOC briefings with fail-safe fallback.

---

## B. M4 Architecture

```text
               M1 Packet Ingestion (Meet - Network/PCAP)
                                 │
                                 ▼
           M2 Real-Time Feature Extractor (Aayush - Scapy/Pandas)
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ M4 Feature Validator    │ (ml/detection/feature_validator.py)
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ M4 Predict Interface    │ (ml/inference/predict.py)
                    └────────────┬────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  DGA Detector    │   │   C2 Detector    │   │ Exfil Detector   │
│  (Lexical/TLD)   │   │  (Beacon/Ports)  │   │ (Ratios/Tunnel)  │
└─────────┬────────┘   └─────────┬────────┘   └─────────┬────────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Phase 3 Decision Engine │ (ml/detection/decision_engine.py)
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Normalized Threat Event │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Phase 4 Investigation   │ (ml/investigation/incident_manager.py)
                    │ - IOC Enrichment        │
                    │ - MITRE Mapping (M5)    │
                    │ - Entity Correlation    │
                    │ - Risk Engine (0-100)   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ NVIDIA Nemotron NIM AI  │ (m4_threat_classifier/ai/nemotron_client.py)
                    │ (Model: 3.5 Lightning)  │
                    └────────────┬────────────┘
                                 │
                                 ▼
               Final Standardized Incident / Alert Payload
```

---

## C. Machine Learning Pipeline

- **Dataset Source:** CICIDS2017 (Canadian Institute for Cybersecurity).
- **Preprocessing Pipeline (`ml/preprocessing/clean.py`):** Standardizes 66 numeric features, cleans infinite/missing values, removes exact duplicates, and applies `StandardScaler` (`preprocessing_pipeline.joblib`).
- **Supervised Classifier (`classifier.joblib`):** Trained Random Forest (100 estimators, max depth 20).
- **Anomaly Model (`anomaly_model.joblib`):** Isolation Forest (contamination 0.05).
- **Canonical Schema (`ml/models/feature_schema.json`):** 66 feature column vectors.

> [!IMPORTANT]
> **Real-World Prevalence Disclaimer:** Model performance metrics on CICIDS2017 benchmarks reflect synthetic distribution evaluations and must NOT be cited as guaranteed real-world prevalence claims in operational deployment.

---

## D. M4 Inference (`ml/inference/predict.py`)

Inference Interface:
```python
from ml.inference.predict import predict

features = {f: 10.0 for f in range(66)} # 66 feature dictionary
result = predict(features)

# Output structure:
# {
#     "threat_class": "BENIGN",
#     "confidence": 0.985,
#     "probabilities": {"BENIGN": 0.985, "DDoS": 0.015, ...},
#     "anomaly_score": 0.12,
#     "is_anomalous": False
# }
```

---

## E. Advanced Detectors

### 1. DGA Detector (`m4_threat_classifier/detection/dga_detector.py`)
- **Shannon Entropy:** $\ge 4.2$ flags randomized domain labels.
- **Unique Char Ratio:** $\ge 0.75$ indicates high alphabet diversity.
- **Digit Ratio:** $\ge 0.20$ flags numeric insertion patterns.
- **Vowel-Consonant Ratio:** $< 0.25$ detects unpronounceable character strings.
- **Suspicious TLDs:** `.ru`, `.xyz`, `.top`, `.tk`, `.biz`, `.info`, `.cn`, `.work`, `.click`.
- **Classification:** `NORMAL`, `SUSPICIOUS`, `LIKELY_DGA`.

### 2. C2 Behavioral Detector (`m4_threat_classifier/detection/c2_detector.py`)
- **Target C2 Ports:** 6667, 6697, 4444, 8443, 1337, 31337, 5555, 9001, 9090.
- **Control Packets:** Small forward packet lengths ($\le 64$ bytes).
- **Periodicity:** Low Inter-Arrival Time (IAT) variance relative to mean flow duration.
- **Classification:** `NO_C2_EVIDENCE`, `SUSPICIOUS_C2`, `LIKELY_C2`.

### 3. Exfiltration Detector (`m4_threat_classifier/detection/exfiltration_detector.py`)
- **Asymmetric Byte Ratio:** Outbound-to-inbound byte ratio $\ge 10:1$.
- **Unidirectional Transfers:** $> 50$ KB outbound with 0 inbound bytes.
- **Payload Max:** $\ge 1,400$ bytes max packet length.
- **DNS Tunneling:** $> 2.0$ KB outbound data over DNS port 53.
- **Classification:** `NORMAL`, `SUSPICIOUS_EXFILTRATION`, `LIKELY_EXFILTRATION`.

---

## F. Phase 3 & Phase 4 Architecture

- **Phase 3 Decision Precedence:** `ANOMALOUS -> MALICIOUS -> SUSPICIOUS -> BENIGN`.
- **Phase 4 Risk Scoring Engine (`ml/risk/risk_engine.py`):** Deterministic 0–100 score calculated from:
  $$\text{Risk Score} = 0.25 \times \text{Confidence} + 0.25 \times \text{Anomaly} + 0.20 \times \text{Severity} + 0.15 \times \text{Intel} + 0.15 \times \text{Correlation}$$
- **MITRE Mapper (`ml/mitre/attack_mapper.py`):** Maps threat classes and evidence to ATT&CK techniques:
  - `T1046` (Network Service Scanning - PortScan)
  - `T1110` (Brute Force)
  - `T1190` (Exploit Public-Facing Application)
  - `T1498` (Network Denial of Service - DDoS/DoS)
  - `T1071` (Application Layer Protocol - C2)
  - `T1090` (Proxy/Anonymization - Infiltration)

---

## G. NVIDIA Nemotron AI Integration

- **API Base URL:** `https://integrate.api.nvidia.com/v1`
- **Active Model:** `nvidia/nemotron-3.5-lightning-30b-a3b`
- **Role:** Qualitative LLM SOC investigation briefing generator.
- **Fail-Safe Design:** If API call fails or key is missing, client returns `status: "AI_UNAVAILABLE"`, `deterministic_detection_available: True`. Deterministic detection never breaks.

---

## H. Repository File Map

| Component | File / Directory Path | Purpose |
| :--- | :--- | :--- |
| **Model Artifacts** | `ml/models/` | Trained joblib files & feature schema JSON |
| **Preprocessing** | `ml/preprocessing/clean.py` | Data cleaning & scaling |
| **Inference Interface** | `ml/inference/predict.py` | Single-line prediction interface |
| **DGA Detector** | `m4_threat_classifier/detection/dga_detector.py` | Lexical & Shannon entropy DGA classifier |
| **C2 Detector** | `m4_threat_classifier/detection/c2_detector.py` | Behavioral beacon & C2 port detector |
| **Exfiltration Detector** | `m4_threat_classifier/detection/exfiltration_detector.py` | Asymmetric ratio & DNS tunneling detector |
| **Phase 3 Decision Engine** | `ml/detection/decision_engine.py` | Deterministic threat decision precedence |
| **Alert Generator** | `ml/detection/alert_generator.py` | Structured JSON alert schema generator |
| **MITRE ATT&CK Mapper** | `ml/mitre/attack_mapper.py` | Evidence-based MITRE technique mapper |
| **Risk Scoring Engine** | `ml/risk/risk_engine.py` | 0-100 normalized risk score calculator |
| **Incident Manager** | `ml/investigation/incident_manager.py` | Multi-event correlation & SOC incident builder |
| **Nemotron AI Client** | `m4_threat_classifier/ai/nemotron_client.py` | NVIDIA NIM OpenAI-compatible API client |
| **API Blueprint** | `m4_threat_classifier/api/routes.py` | Flask REST API routes (`/api/v1/...`) |
| **Test Runner** | `run_all_tests.py` | Integrated system component test runner |
| **Nemotron Direct Test** | `test_nemotron.py` | Standalone NVIDIA NIM direct API test script |
