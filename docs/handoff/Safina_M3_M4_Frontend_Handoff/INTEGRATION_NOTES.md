# INTEGRATION_NOTES.md — Frontend Integration Guidelines for Safina

**Target Developer:** Safina  
**Module:** M6 Frontend SOC Dashboard  

---

## 1. Key Integration Rules for Frontend UI

1. **Consume REST API & Event Streams:** Do NOT load Python `.joblib` model binaries or run Python scripts directly in the browser or frontend process. All ML inference and SOC investigation logic is handled by the backend API.
2. **Display Parallel Classifications Independently:**
   - Render `classifications.m3.threat_class` as Krisha's M3 primary prediction (e.g. `DDOS`, `PORT_SCAN`).
   - Render `classifications.m4.threat_class` as Aayushman's M4 prediction.
   - Render top-level `threat_class` as the unified system decision.
   - **Never overwrite M3 with M4 or M4 with M3.**
3. **Render Phase 4 Investigation Widgets:**
   - **Risk Gauge:** Render `incident.risk_score` (0.0 to 100.0) with corresponding badge colors (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - **IOC Table:** Render `incident.iocs` extracted indicators.
   - **Timeline View:** Render `incident.timeline` chronological events.
   - **MITRE Matrix Overlay:** Render `incident.mitre_mappings` technique badges (`T1046`, `T1498`, etc.).
4. **Nemotron AI Insights Panel:** Render the LLM analysis string (`incident.explanation.summary` or `/api/v1/ai/analyze` response) in a qualitative "AI SOC Briefing" tab or drawer.
5. **Fail-Safe UI Design:** If the AI analysis status returns `AI_UNAVAILABLE`, display a clean info banner stating *"AI Assistant Unavailable — Deterministic Detection Active"*. The primary threat score, alerts, and detection badges must remain fully visible.
