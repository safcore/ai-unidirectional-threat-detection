# M4 Leftover Audit & Capability Assessment Report

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Module:** M4 — Advanced Threat Classifier B  
**Timestamp:** 2026-09-03  

---

## 1. Executive Capability Matrix

| Capability / Component | Status | Existing Implementation Location | Missing / Required Leftover Action |
| :--- | :--- | :--- | :--- |
| **Supervised Network Flow Classifier** | `IMPLEMENTED` | `ml/models/classifier.joblib`, `ml/inference/predict.py` | None (Phase 2 model frozen). |
| **Unsupervised Anomaly Detector** | `IMPLEMENTED` | `ml/models/anomaly_model.joblib`, `ml/inference/predict.py` | None (Phase 2 model frozen). |
| **Domain Lexical & Entropy Features** | `IMPLEMENTED` | `m4_threat_classifier/feature_engineering/domain_features.py` | Extracted lexical features exist. |
| **Structured DGA Detector** | `PARTIALLY IMPLEMENTED` | `domain_features.py` | Need `m4_threat_classifier/detection/dga_detector.py` to evaluate DGA score, classification (NORMAL/SUSPICIOUS/LIKELY_DGA), and explanations. |
| **C2 Behavioral Detector** | `PARTIALLY IMPLEMENTED` | Flow features & `ml/mitre/attack_mapper.py` | Need `m4_threat_classifier/detection/c2_detector.py` for beaconing, periodicity, destination consistency, and C2 scoring. |
| **Data Exfiltration Detector** | `PARTIALLY IMPLEMENTED` | Outbound flow features | Need `m4_threat_classifier/detection/exfiltration_detector.py` for outbound/inbound ratios, payload sizes, DNS tunneling indicators. |
| **Threat Intelligence & Cache** | `IMPLEMENTED` | `ml/threat_intelligence/` | None (Phase 4 implementation complete). |
| **Evidence-based MITRE Mapping** | `IMPLEMENTED` | `ml/mitre/` | None (Phase 4 implementation complete). |
| **Multi-Event Threat Correlation** | `IMPLEMENTED` | `ml/correlation/` | None (Phase 4 implementation complete). |
| **Explainable Risk Engine** | `IMPLEMENTED` | `ml/risk/` | None (Phase 4 implementation complete). |
| **Incident & Timeline Manager** | `IMPLEMENTED` | `ml/investigation/` | None (Phase 4 implementation complete). |
| **NVIDIA Nemotron LLM Client** | `PARTIALLY IMPLEMENTED` | `m4_threat_classifier/reasoning/nemotron_layer.py` (Mock stub) | Need real OpenAI-compatible NIM client (`m4_threat_classifier/ai/nemotron_client.py`) connecting to NVIDIA NIM API with environment key loading & strict guardrails. |

---

## 2. Genuinely Missing M4 Leftover Actions Identified
1. **`m4_threat_classifier/detection/dga_detector.py`**: Modular DGA detector using lexical features & Shannon entropy.
2. **`m4_threat_classifier/detection/c2_detector.py`**: Behavioral C2 detector using connection periodicity, destination consistency, small packet frequency, and port signals.
3. **`m4_threat_classifier/detection/exfiltration_detector.py`**: Behavioral Data Exfiltration detector using outbound byte volume, outbound/inbound ratio, payload size, and DNS tunneling signals.
4. **`m4_threat_classifier/ai/nemotron_client.py`**: Live OpenAI-compatible client for NVIDIA NIM API using `NVIDIA_NIM_API_KEY` from `.env`, with strict AI guardrails and fail-safe fallback behavior.
5. **`.env` & `.env.example`**: Secure environment configuration for `NVIDIA_NIM_API_KEY`.
6. **`POST /api/v1/ai/analyze`**: Extended API endpoint for Nemotron SOC investigation analysis.
