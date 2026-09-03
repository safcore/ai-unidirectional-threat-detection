# PS-145 Threat Detection Backend

Flask-based backend for the PS-145 cybersecurity threat-detection system.
Provides REST API + SSE real-time streaming for the React SOC dashboard.

---

## Architecture

```
PCAP / Traffic
  → Flow Extraction (Meet)
  → Feature Engineering (Aayush)
  → ML + Rule Detection (Aayushman + Krisha)
  → Alert JSON  ──POST /api/alerts──►  Flask Backend (Anika)
                                              │
                                        SSE /api/stream
                                              │
                                     React SOC Dashboard (Safina)
```

**Integration contract:** All detection modules POST to `/api/alerts`.
The backend is **completely independent** of the ML/PCAP modules.

---

## Setup

### 1. Create virtual environment

```bash
python -m venv .venv
```

### 2. Activate (Windows)

```bash
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Run the server

From the `backend/` directory:

```bash
python -m app.main
```

Server starts at: `http://127.0.0.1:8000`

Mock alerts are loaded automatically on first run (if the store is empty).

---

## API Reference

| Method | Endpoint              | Description                          |
|--------|-----------------------|--------------------------------------|
| GET    | `/`                   | Service info + endpoint list         |
| GET    | `/api/health`         | Health check                         |
| GET    | `/api/alerts`         | List all alerts (newest first)       |
| GET    | `/api/alerts?severity=HIGH` | Filter by severity            |
| GET    | `/api/alerts/<id>`    | Get single alert by ID               |
| POST   | `/api/alerts`         | Ingest a new alert                   |
| GET    | `/api/stats`          | SOC statistics (counts by severity)  |
| GET    | `/api/stream`         | SSE real-time alert stream           |

### GET /api/health

```json
{ "status": "healthy", "service": "threat-detection-backend", "sse_clients": 0 }
```

### POST /api/alerts — Request body

```json
{
  "alert_id": "ALT-101",
  "timestamp": "2026-09-02T14:00:00Z",
  "threat": "DDoS",
  "severity": "CRITICAL",
  "confidence": 0.98,
  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.20",
  "source_port": 4000,
  "destination_port": 80,
  "protocol": "TCP",
  "mitre": {
    "tactic": "Impact",
    "technique": "T1498",
    "technique_name": "Network Denial of Service"
  },
  "evidence": { "packets": 50000, "connections": 1000, "ports_scanned": 0 }
}
```

**Status codes:** `201` Created · `400` Bad JSON · `409` Duplicate ID · `422` Validation error

### GET /api/stats

```json
{
  "total_alerts": 8,
  "critical": 3,
  "high": 3,
  "medium": 2,
  "low": 0,
  "threat_types": { "Port Scan": 2, "DDoS": 1, "C2 Communication": 1 }
}
```

### GET /api/stream (SSE)

JavaScript usage in React:

```js
const es = new EventSource("http://localhost:8000/api/stream");

es.addEventListener("connected", () => console.log("SSE live"));

es.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  // update your SOC dashboard state here
};
```

---

## Testing

Run all tests from `backend/`:

```bash
pytest
```

Or with verbose output:

```bash
pytest -v
```

---

## Demo flow

1. **Start Flask:**
   ```bash
   python -m app.main
   ```

2. **Start React frontend** (Safina — separate terminal):
   ```bash
   cd ../frontend
   npm run dev
   ```

3. **Open dashboard** in browser at `http://localhost:5173`

4. **Stream test alerts** (in a third terminal):
   ```bash
   python test_client.py
   ```

   For continuous SSE demo:
   ```bash
   python test_client.py --loop --delay 2
   ```

5. Alerts appear in the dashboard in real time via SSE.

---

## File structure

```
backend/
├── app/
│   ├── __init__.py      # Application factory + module singletons
│   ├── main.py          # Entry point + mock data loader
│   ├── routes.py        # All API endpoints (Blueprint)
│   ├── models.py        # Alert validation (no Pydantic dependency)
│   ├── alert_store.py   # Thread-safe JSON persistence layer
│   └── stream.py        # SSE StreamManager (per-client queues)
├── data/
│   └── alerts.json      # Persisted alerts (auto-created)
├── tests/
│   ├── conftest.py      # Pytest fixtures (isolated tmp store)
│   ├── test_health.py   # / and /api/health tests
│   ├── test_alerts.py   # CRUD + validation + stats tests
│   └── test_stream.py   # SSE endpoint tests
├── test_client.py       # Synthetic alert sender (for SSE demo)
└── requirements.txt
```

```
shared/
└── alert_schema.json    # JSON Schema contract (for all team modules)
```

---

## Integration guide for other modules

**Krisha / Aayushman — sending an alert:**

```python
import requests

alert = {
    "alert_id": "ALT-200",
    "timestamp": "2026-09-02T14:00:00Z",
    "threat": "Port Scan",
    "severity": "HIGH",
    "confidence": 0.94,
    "source_ip": "10.0.0.5",
    "destination_ip": "192.168.1.1",
    "source_port": 12345,
    "destination_port": 22,
    "protocol": "TCP",
    "mitre": {
        "tactic": "Discovery",
        "technique": "T1046",
        "technique_name": "Network Service Scanning"
    },
    "evidence": {"packets": 100, "connections": 50, "ports_scanned": 20}
}

resp = requests.post("http://127.0.0.1:8000/api/alerts", json=alert)
print(resp.status_code, resp.json())
```

See `shared/alert_schema.json` for the full contract.
