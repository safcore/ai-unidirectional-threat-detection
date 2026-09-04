# ARCHITECTURE_M4_FOR_BACKEND.md — Backend Architecture Flow

```text
M1 Packet Ingestion Pipeline (Meet)
        ↓
M2 66-Feature Extraction (Aayush)
        ↓
Canonical 66-Feature Flow Record
        ↓
 ┌───────────────┐
 │               │
 ▼               ▼
M3              M4
 │               │
 │               ├── Random Forest Classifier
 │               ├── Isolation Forest Anomaly Detector
 │               ├── DGA Detector
 │               ├── C2 Behavioral Detector
 │               └── Exfiltration Detector
 │               │
 └───────┬───────┘
         ↓
 Unified Threat Event
         ↓
 Phase 3 Decision Engine
         ↓
 Phase 4 Investigation
 (Risk 0-100 + IOCs + MITRE + Timeline)
         ↓
 Flask REST API (Anika / M6 Backend)
         ↓
 SSE Live Event Stream
         ↓
 Safina Frontend Dashboard UI
```

### Key Technical Properties:
1. **Parallel Execution:** M3 (`m3_predict.py`) and M4 (`predict.py`) execute in parallel over the canonical 66-feature vector record. Both raw outputs are preserved in `classifications.m3` and `classifications.m4`.
2. **Deterministic Precedence:** M3 handles `DDOS` and `PORT_SCAN` primary predictions ($\ge 0.70$ confidence), while M4 handles advanced threat vectors (`DGA`, `C2`, `EXFILTRATION`, `DoS`, `Brute Force`).
3. **Fail-Safe AI Integration:** If NVIDIA Nemotron NIM is unavailable or key is omitted, `status: "AI_UNAVAILABLE"` is returned safely while deterministic ML detection and risk scoring continue without interruption.
