# API_QUICK_REFERENCE.md — Backend Quick Reference Guide for Anika

**Target Developer:** Anika  

---

## 1. Quick Integration Matrix for Anika

| Question | Answer / Implementation Code |
| :--- | :--- |
| **What do I call for detection?** | `from ml.detection.detection_engine import get_detection_engine`<br>`engine = get_detection_engine()`<br>`event = engine.process(features, metadata=metadata)` |
| **What do I call for investigation?** | `from ml.investigation.incident_manager import get_incident_manager`<br>`mgr = get_incident_manager()`<br>`incident = mgr.process_event(event)` |
| **What do I call for Nemotron AI?** | `from m4_threat_classifier.ai.nemotron_client import get_nemotron_client`<br>`nemotron = get_nemotron_client()`<br>`result = nemotron.analyze_incident(incident_data)` |
| **What input do I send?** | Canonical 66-feature dictionary + optional metadata dict (`src_ip`, `dst_ip`, `src_port`, `dst_port`). |
| **Where are M3 / M4 results?** | `event["classifications"]["m3"]` and `event["classifications"]["m4"]` |
| **Where is risk_score?** | `incident.to_dict()["risk_score"]` (0.0 to 100.0) & `incident.to_dict()["risk_level"]` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| **Where are IOCs?** | `incident.to_dict()["iocs"]` (List of IP/domain reputation dicts) |
| **Where is MITRE mapping?** | `incident.to_dict()["mitre_mappings"]` (List of ATT&CK technique dicts) |
| **Where is correlation?** | `incident.to_dict()["attack_chain"]` & `incident.to_dict()["timeline"]` |
| **Where is AI analysis status?** | `incident.to_dict()["explanation"]` or `/api/v1/ai/analyze` response (`status`: `SUCCESS` / `AI_UNAVAILABLE`) |

---

## 2. Standard Endpoint Implementations (`routes.py`)

- `POST /api/v1/detect` $\rightarrow$ Phase 3 detection event
- `POST /api/v1/investigations/events` $\rightarrow$ Phase 3 detection + Phase 4 SOC incident
- `GET /api/v1/incidents` $\rightarrow$ List of active Phase 4 incidents
- `GET /api/v1/incidents/<incident_id>` $\rightarrow$ Specific incident details
- `POST /api/v1/ai/analyze` $\rightarrow$ NVIDIA Nemotron 3.5 Lightning AI analysis
- `GET /api/v1/health` $\rightarrow$ Health check
