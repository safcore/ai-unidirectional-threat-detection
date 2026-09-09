# NETRION REST & SSE API Reference

## Health & Status
- `GET /api/health` — Returns system status, diode mode (`ONLINE (RX DIODE)`), and component readiness.

## Alerts API
- `GET /api/alerts` — Retrieves all generated security alerts with multi-factor risk scores and MITRE mappings.
- `GET /api/alerts/<id>` — Returns full alert payload including flow metadata, trigger features, and IOCs.
- `POST /api/alerts` — Ingestion endpoint for detection engine to push new alerts.

## Real-Time SSE Stream
- `GET /api/stream` — Server-Sent Events endpoint streaming live alert notifications to the SOC frontend.

## Traffic Analysis & PCAP Replay
- `POST /api/traffic/upload-pcap` — Uploads `.pcap`/`.pcapng` file for processing.
- `POST /api/traffic/replay-pcap` — Replays PCAP through M1->M2->M3/M4 pipeline.
- `GET /api/traffic/analyze-ip/<ip>` — Comprehensive IP investigation dossier with flow evidence, protocol distribution, and risk breakdown.

## Attack Simulation & Safe Demonstration
- `POST /api/attack/start` — Triggers safe attack demonstration scenarios (`syn_flood`, `port_scan`, `dns_tunnel`, `c2_beacon`, `data_exfiltration`, `tls_metadata`).
- `POST /api/attack/stop` — Halts running attack simulations.

## AI Investigation Assistant
- `POST /api/ai/analyze/<alert_id>` — Triggers NVIDIA Nemotron security copilot analysis with explainable reasoning.
- `GET /api/ai/health` — Checks Nemotron API connectivity and fallback status.
