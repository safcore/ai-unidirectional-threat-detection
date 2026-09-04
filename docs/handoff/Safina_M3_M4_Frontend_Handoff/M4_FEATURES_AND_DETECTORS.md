# M4_FEATURES_AND_DETECTORS.md — M4 Capabilities & Detector Guide for Frontend Display

**Author:** Aayushman Parab  
**Target Audience:** Safina (Frontend Developer)  

---

## 1. Overview of M4 Capabilities

Module M4 produces threat telemetry across five distinct detection and investigation categories. The frontend UI should render these indicators on alert cards and incident detail views.

---

## 2. Advanced Heuristic Detectors

### A. DGA Detector (Domain Generation Algorithm)
- **What It Detects:** Malware generating pseudo-random domain names to evade DNS blocklists.
- **Frontend Display Fields:**
  - `threat_class`: `LIKELY_DGA` or `SUSPICIOUS`
  - `dga_score`: `0.0` to `1.0`
  - `evidence`: Lexical metrics (Shannon entropy $\ge 4.2$, digit ratio $\ge 0.20$, suspicious TLDs like `.ru`, `.xyz`).

### B. C2 Behavioral Detector (Command & Control)
- **What It Detects:** Compromised hosts communicating with external attacker control servers via periodic keep-alive beacons.
- **Frontend Display Fields:**
  - `threat_class`: `LIKELY_C2` or `SUSPICIOUS_C2`
  - `c2_score`: `0.0` to `1.0`
  - `evidence`: Target C2 ports (6667, 4444, 8443, etc.), small control payload sizes ($\le 64$ bytes), low inter-arrival time (IAT) variance.

### C. Data Exfiltration Detector
- **What It Detects:** Unauthorized data transfers from internal network hosts to external destinations.
- **Frontend Display Fields:**
  - `threat_class`: `SUSPICIOUS_EXFILTRATION` or `LIKELY_EXFILTRATION`
  - `exfiltration_score`: `0.0` to `1.0`
  - `evidence`: Asymmetric outbound/inbound byte ratio ($\ge 10:1$), unidirectional data streams ($> 50$ KB), large payload sizes ($\ge 1460$ bytes), or DNS tunneling ($> 2.0$ KB over port 53).

---

## 3. Phase 4 SOC Investigation Fields

### A. Risk Scoring Engine (0–100 Score)
Render as a prominent gauge or colored badge on the UI:
- **`0.0 - 29.9` (LOW):** Green badge
- **`30.0 - 59.9` (MEDIUM):** Yellow badge
- **`60.0 - 84.9` (HIGH):** Orange badge
- **`85.0 - 100.0` (CRITICAL):** Red badge

### B. MITRE ATT&CK Technique Badge
Display mapped ATT&CK technique IDs alongside threat alerts:
- `T1046` (Network Service Scanning)
- `T1110` (Brute Force)
- `T1190` (Exploit Public-Facing Application)
- `T1498` (Network Denial of Service)
- `T1071` (Application Layer Protocol)
- `T1090` (Proxy/Anonymization)

### C. NVIDIA Nemotron AI SOC Briefing Widget
Render the qualitative LLM summary output (`incident["explanation"]["summary"]` or `/api/v1/ai/analyze` response) inside a dedicated "AI Threat Analyst Insights" panel on the incident view.
