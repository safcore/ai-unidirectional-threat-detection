# PS-145 Threat Detection Platform — Technical Integration Guide

## 1. System Architecture & Data Flow

The Smart India Hackathon (SIH) 2026 Problem Statement PS-145 platform implements an end-to-end, unidirectional network threat detection architecture:

```
[M1 Ingest Layer] (PCAP Replay / CIC-IDS CSV / Synthetic Generator)
       │
       ▼ (RawPacket / CICFlowRecord)
[M2 Feature Extraction] (NFStream C-Engine or Pure-Python Fallback)
       │
       ▼ (Canonical 66-Feature Vector)
[M3/M4 Detection Engine] (Krisha PortScan/DDoS + Aayushman 6-Class RF + Isolation Forest Anomaly)
       │
       ▼ (Detection Event + Incident Investigation)
[M5 Alert Normalizer] (Strict shared/alert_schema.json Enforcement)
       │
       ▼ (Canonical Alert: ALT-NNN, [0, 65535] ports, clamped conf/sev, dict evidence)
[Anika Flask Backend] (/api/detect, /api/alerts, /api/stats, /api/attack/*)
       │
       ├──────────────────────────────┬──────────────────────────────┐
       ▼                              ▼                              ▼
[SSE Live Stream]             [Persistent Store]             [NVIDIA Nemotron AI]
(/api/stream -> React SOC)    (data/alerts.json)             (Nemotron 3.5 NIM)
```

### Unidirectional Diode Emulation
As mandated by the NTRO specification for passive monitoring:
- Ingestion operates strictly read-only on mirrored wire packets.
- No network packets, handshakes, or probes are transmitted back onto monitored interfaces.
- The attack generators (`attack_gen/`) are decoupled and isolated for local lab demonstrations.

---

## 2. Integrated Modules & Contributions

| Module | Primary Contributor | Integrated Path | Key Capabilities |
| :--- | :--- | :--- | :--- |
| **M1 Ingest** | Aayush | `m1_ingest/` | `PcapStreamReader`, `SyntheticTrafficGenerator`, `CICIDSReader`, `RawPacket` with wire-bytes `raw_frame` & `raw_payload`. |
| **M2 Features** | Aayush | `m2_features/` | Dual-mode feature extraction: NFStream C-Engine when Npcap is present; deterministic pure-Python fallback (`FallbackPurePythonAggregator`) mapping 82/arbitrary features to canonical 66 features via `canonical_adapter.py`. |
| **M3 Detection** | Krisha | `ml/models/` | `m3_ddos_portscan_classifier.joblib` (10.8 MB) specialized Random Forest for DDoS and Port Scanning. |
| **M4 Threat Detection** | Aayushman | `ml/`, `m4_threat_classifier/` | 6-Class classifier (`classifier.joblib`, 10.9 MB), Anomaly detector (`anomaly_model.joblib`, 802 KB), MITRE ATT&CK mapper, timeline builder, and incident manager. |
| **M5 Normalizer** | Controlled Integration | `backend/app/alert_normalizer.py` | Validates against `shared/alert_schema.json`, assigns sequential `ALT-NNN`, normalizes severity, clamps confidence, validates MITRE technique format (`^T[0-9]+(\.[0-9]+)?$`), and wraps indicators as dict evidence. |
| **Attack Generator** | Meet | `attack_gen/`, `backend/app/attack_service.py` | SYN Flood, Port Scan, and DNS Tunnel simulation and raw-socket generators with thread-safe management and cancellation. |
| **Backend & AI** | Anika | `backend/app/` | Source-of-truth Flask REST API, thread-safe `alert_store`, real-time SSE `/api/stream`, and NVIDIA Nemotron 3.5 LLM enrichment (`/api/ai/*`). |
| **Orchestrator** | Controlled Integration | `run_live_pipeline.py` | Master CLI tool executing M1 -> M2 -> M3/M4 -> M5 -> Backend across PCAP, Dataset, and Live/Synthetic modes. |

---

## 3. Configuration & Environment Harmonization

Environment variables are managed dynamically via `backend/app/env_loader.py`.
To support both Anika's backend AI service and Aayushman's M4 NIM client without credential duplication or leakage:

- `NVIDIA_API_KEY` $\longleftrightarrow$ `NVIDIA_NIM_API_KEY` (Bidirectionally synced)
- `NVIDIA_MODEL` $\longleftrightarrow$ `NVIDIA_NIM_MODEL` (Defaults to `nvidia/nemotron-3.5-lightning-30b-a3b`)
- `NVIDIA_BASE_URL` $\longleftrightarrow$ `NVIDIA_NIM_BASE_URL` (Defaults to `https://integrate.api.nvidia.com/v1`)
- `AI_TIMEOUT_SECS` $\longleftrightarrow$ `NVIDIA_NIM_TIMEOUT` (Defaults to `120s` / `60s`)

No secrets or raw keys are ever logged or exposed in health endpoints.

---

## 4. Operational Instructions

### A. Running the Backend Server
Activate the virtual environment and start the Flask backend:
```powershell
backend\.venv\Scripts\python.exe -m flask --app backend.app run --port 8000
```
API endpoints available:
- `GET /` & `GET /api/health`
- `GET /api/alerts` & `POST /api/alerts`
- `GET /api/stats`
- `GET /api/stream` (SSE Live EventSource)
- `POST /api/detect` (Feature detection ingestion)
- `POST /api/attack/start`, `POST /api/attack/stop`, `GET /api/attack/status`
- `GET /api/ai/health`, `POST /api/ai/analyze/<alert_id>`, `POST /api/ai/correlate`

### B. Running the Master Pipeline Orchestrator
Execute live synthetic traffic detection:
```powershell
backend\.venv\Scripts\python.exe run_live_pipeline.py --mode synthetic --rate 10 --max-events 20
```

Replay a real PCAP file:
```powershell
backend\.venv\Scripts\python.exe run_live_pipeline.py --mode pcap --input path/to/capture.pcap --direct
```

Stream CIC-IDS2017 flow dataset:
```powershell
backend\.venv\Scripts\python.exe run_live_pipeline.py --mode dataset --input path/to/dataset.csv --rate 25
```

### C. Triggering Attack Demonstrations
From HTTP client or frontend:
```bash
# Start a SYN flood simulation
curl -X POST http://localhost:8000/api/attack/start \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "syn_flood", "params": {"duration": 10, "simulation": true}}'

# Query status
curl http://localhost:8000/api/attack/status

# Stop active attacks
curl -X POST http://localhost:8000/api/attack/stop -H "Content-Type: application/json" -d '{}'
```

### D. Running the Test Suite
Execute the full test suite (102 tests):
```powershell
backend\.venv\Scripts\python.exe -m pytest backend/tests -v
```
