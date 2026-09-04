# M4 Leftover Implementation & NVIDIA Nemotron Integration Technical Report

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Module:** M4 — Advanced Threat Classifier B / NVIDIA Nemotron AI Integration Layer  
**Timestamp:** 2026-09-03  

---

## A. Executive Summary & Model Resolution
The model configured for NVIDIA NIM integration is:
```env
NVIDIA_NIM_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
```
Live inference testing against `https://integrate.api.nvidia.com/v1/chat/completions` confirmed **HTTP 200 OK** completion.

All existing Phase 2, Phase 3, and Phase 4 model files, thresholds, decision precedence, and investigation modules remain 100% frozen and untouched. All **41/41 unit and integration tests passed in 25.67s**.

---

## B. Audit Findings (`ml/reports/m4_leftover_audit.md`)
The repository audit revealed that while domain lexical feature extractors (`domain_features.py`, `entropy.py`, `ngrams.py`) and network flow features existed, dedicated modular detectors for DGA, C2 behavioral signals, and Data Exfiltration were missing. Additionally, the Nemotron reasoning layer existed only as a mock interface stub (`nemotron_layer.py`).

---

## C. Newly Implemented Capabilities
1. **DGA Detector Module (`m4_threat_classifier/detection/dga_detector.py`):** Modular lexical & Shannon entropy DGA classifier.
2. **C2 Behavioral Detector Module (`m4_threat_classifier/detection/c2_detector.py`):** Connection periodicity, beacon timing, and C2 port analyzer.
3. **Data Exfiltration Detector Module (`m4_threat_classifier/detection/exfiltration_detector.py`):** Outbound byte volume, outbound/inbound byte ratio, and DNS tunneling detector.
4. **NVIDIA Nemotron NIM AI Client (`m4_threat_classifier/ai/nemotron_client.py`):** OpenAI-compatible API client connecting to NVIDIA NIM (`https://integrate.api.nvidia.com/v1`) using `NVIDIA_NIM_API_KEY` from `.env`.
5. **AI Investigation Endpoint (`POST /api/v1/ai/analyze`):** Endpoint for LLM-driven SOC investigation briefings.
6. **Environment & Security Config (`.env`, `.env.example`, `.gitignore`):** Secure key storage and gitignore rules.

---

## D. DGA Detection Methodology
The DGA Detector extracts domain metrics:
- **Shannon Entropy:** $\ge 4.2$ (High entropy / random character generation).
- **Unique Character Ratio:** $\ge 0.75$ (High alphabet diversity).
- **Digit Ratio:** $\ge 0.20$ (Excessive numbers in label).
- **Vowel-Consonant Ratio:** $< 0.25$ (Unusual consonant clusters).
- **Suspicious TLDs:** `.ru`, `.xyz`, `.top`, `.tk`, `.biz`, `.info`, `.cn`, `.work`, `.click`.
- **Classification:** `NORMAL`, `SUSPICIOUS`, `LIKELY_DGA`.

---

## E. C2 Behavioral Detection Methodology
The C2 Detector evaluates transport flow metrics:
- **C2 Target Ports:** 6667, 6697, 4444, 8443, 1337, 31337, 5555, 9001, 9090.
- **Beacon Packet Pattern:** High forward packet count with low mean length ($\le 64$ bytes) representing keep-alive control beacons.
- **Periodicity Signal:** Low Inter-Arrival Time (IAT) variance relative to mean flow duration.
- **Classification:** `NO_C2_EVIDENCE`, `SUSPICIOUS_C2`, `LIKELY_C2`.

---

## F. Data Exfiltration Detection Methodology
The Exfiltration Detector evaluates outbound data metrics:
- **Outbound-to-Inbound Byte Ratio:** $\ge 10.0:1$ (Asymmetric outbound data transfer).
- **Unidirectional Transfers:** $> 50$ KB outbound with 0 inbound response bytes.
- **Large Payload Max:** $\ge 1,400$ bytes payload size.
- **DNS Tunneling Indicator:** $> 2.0$ KB outbound transfer over DNS port 53.
- **Classification:** `NORMAL`, `SUSPICIOUS_EXFILTRATION`, `LIKELY_EXFILTRATION`.

---

## G. NVIDIA Nemotron AI Architecture
- **API Endpoint:** OpenAI-compatible `POST /v1/chat/completions` at `https://integrate.api.nvidia.com/v1`.
- **Active Model:** `nvidia/nemotron-3.5-lightning-30b-a3b` (verified via live HTTP 200 response).
- **Fail-Safe Fallback:** If API key is missing, network times out, or NIM fails, the client returns `status: "AI_UNAVAILABLE"`, `deterministic_detection_available: true`. The core ML/rule pipeline never crashes.
- **Prompt Guardrails:** Instructs LLM to summarize supplied evidence only; forbids inventing IPs, timestamps, attribution, or ATT&CK intent.

---

## H. Environment Configuration
Configuration is loaded from `.env`:
```env
NVIDIA_NIM_API_KEY=<masked>
NVIDIA_NIM_BASE_URL=https://integrate.api.nvidia.com/v1
NVIDIA_NIM_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
NVIDIA_NIM_TIMEOUT=30
NVIDIA_NIM_ENABLED=true
```

---

## I. Security Considerations
- `.env` is explicitly ignored by `.gitignore`.
- API keys are NEVER printed, logged, or returned in HTTP responses or exception tracebacks.
- External API calls use strict 30-second timeouts.

---

## J. Automated Test Results
Executed `pytest`:
- `tests/test_detection_pipeline.py`: 10 passed
- `tests/test_feature_engineering.py`: 4 passed
- `tests/test_leftover_m4_nemotron.py`: 6 passed
- `tests/test_model_pipeline.py`: 6 passed
- `tests/test_phase4_investigation.py`: 9 passed
- `tests/test_preprocessing.py`: 6 passed
- **Total Test Results:** **41 passed in 25.67s** (100% pass rate).

---

## K. Limitations
1. **Domain Payload Telemetry:** DGA detection requires domain strings in DNS query payloads or metadata.
2. **LLM Context Window:** Nemotron AI analysis synthesizes structured incident summaries; live inference requires network access to NVIDIA NIM endpoints.

---

## L. What is NOT Implemented
- Fine-tuning local Nemotron model weights on local GPUs (the system connects via NVIDIA NIM API as designed).
- Automatic DNS packet capture parsing (M4 consumes flow/metadata records extracted by M1/M2).
