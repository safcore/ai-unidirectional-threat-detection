# API_ENDPOINTS.md — Frontend API Endpoint Documentation

**Base API Path:** `http://127.0.0.1:5000` (or configured Flask host)  
**Blueprint Prefix:** `/api/v1`  

---

## 1. Summary of Frontend-Facing Endpoints

| Method | Endpoint Path | Description | Frontend Use Case |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/detect` | Runs Phase 3 threat detection over flow features. | Live flow inspection & alert card rendering. |
| `POST` | `/api/v1/investigations/events` | Runs Phase 3 detection & Phase 4 investigation. | Main alert ingestion & incident building. |
| `GET` | `/api/v1/incidents` | Lists all active Phase 4 Incidents. | Incident Table view / SOC dashboard feed. |
| `GET` | `/api/v1/incidents/<incident_id>` | Returns full details for a single Incident ID. | Incident Detail Modal / Drilldown view. |
| `GET` | `/api/v1/incidents/<incident_id>/timeline` | Returns chronological event timeline. | Incident Timeline widget. |
| `GET` | `/api/v1/incidents/<incident_id>/attack-chain` | Returns multi-stage attack chain progression. | Attack Chain graph / progression view. |
| `GET` | `/api/v1/incidents/<incident_id>/mitre` | Returns MITRE ATT&CK technique mappings. | MITRE ATT&CK Matrix badge overlay. |
| `POST` | `/api/v1/ai/analyze` | Generates NVIDIA Nemotron 3.5 Lightning AI SOC briefing. | "Analyze with Nemotron AI" button action. |
| `GET` | `/api/v1/health` | Service health check & model configuration status. | System Health status indicator in header. |

---

## 2. Detailed Endpoint Specs

### A. `POST /api/v1/detect`
- **Request Body:**
  ```json
  {
    "features": { "Destination Port": 80, "Flow Duration": 500.0, ... },
    "metadata": { "src_ip": "10.0.0.5", "dst_ip": "10.0.0.20" }
  }
  ```
- **Response (200 OK):**
  Returns normalized `event` JSON containing `threat_class`, `decision`, `confidence`, `probabilities`, `classifications.m3`, `classifications.m4`, and `alert` object.

---

### B. `POST /api/v1/investigations/events`
- **Request Body:** Flow feature payload or normalized event dict.
- **Response (200 OK):**
  Returns `{"status": "success", "event": {...}, "incident": {...}}`.

---

### C. `POST /api/v1/ai/analyze`
- **Request Body:** Incident dictionary or structured telemetry payload.
- **Response (200 OK):**
  ```json
  {
    "status": "SUCCESS",
    "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
    "analysis": "Here's a SOC briefing analysis...",
    "key_findings": ["Structured evidence analyzed by NVIDIA NIM LLM."],
    "recommended_actions": ["Review socket telemetry", "Inspect target network logs"],
    "deterministic_detection_available": true
  }
  ```
