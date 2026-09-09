# NETRION Architecture & Data Diode Pipeline

NETRION is an AI-powered Unidirectional Threat Detection & Investigation Platform built for Smart India Hackathon 2026 (Problem Statement PS-145).

```
Unidirectional Optical Data Diode (Hardware / Simulation)
                      │ (Rx Only — Zero Tx Back-channel)
                      ▼
[M1 Ingestion] ──► PCAP Stream / Packet Queue / Flow Replay
                      │
                      ▼
[M2 Features]  ──► 66 Canonical Network & Behavioral Features
                      │
                      ▼
[M3/M4 ML Engine] ─► Isolation Forest (Anomaly) + XGBoost / Random Forest (Multi-Class)
                      │
                      ▼
[M5 Correlation] ─► MITRE ATT&CK Mapping + Explainable Risk Engine (0-100)
                      │
                      ▼
[Backend SOC]  ──► Flask REST API + Server-Sent Events (SSE) Live Stream
                      │
                      ▼
[Frontend Console]─► React + Vite SOC Investigation Dashboard + NVIDIA Nemotron LLM
```

## Core Components
- **M1 Ingestion (`m1_ingest/`)**: Real-time packet parsing, PCAP replay, flow record extraction.
- **M2 Feature Engine (`m2_features/`)**: 66-feature canonical schema vector extraction.
- **M3/M4 Detection Engine (`ml/`)**: Supervised classifier, unsupervised Isolation Forest, C2/DGA/Exfiltration detectors, and TLS metadata analysis.
- **M5 Risk & Correlation (`ml/risk/`, `ml/correlation/`)**: Multi-factor 0-100 risk scoring and MITRE ATT&CK enterprise technique mapping.
- **Backend Service (`backend/app/`)**: High-performance Flask REST API and SSE broadcaster.
- **AI Investigation Assistant (`backend/app/ai/`)**: NVIDIA Nemotron LLM security copilot with deterministic fallback.
- **SOC Console (`frontend/`)**: Real-time SOC dashboard, interactive IP investigation dossier, and drawer inspector.
