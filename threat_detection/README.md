# Threat Detection Engine — Milestone 1

**SIH PS 26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**
**Module: Person 4 — Threat Detection**

Passive, read-only detection engine. This module never sends, injects,
modifies, or blocks packets — it only consumes flow-level feature
records and produces structured alerts.

## 1. Scope of Milestone 1

```
Feature Schema → Validator → DDoS Detector + Port Scan Detector
   → Severity Engine → Evidence Engine → Alert Generator → Tests
```

Not yet included (later milestones): streaming queue architecture, ML
detector, rule/ML fusion, DGA, DNS tunnelling, C2 beaconing, encrypted
traffic metadata, exfiltration, cross-flow correlation, deduplication.

## 2. Project structure

```
threat_detection/
├── __init__.py
├── engine.py            # ThreatDetectionEngine — the stable public API
├── feature_schema.py    # FeatureRecord contract
├── validator.py         # untrusted-input validation
├── config_loader.py     # loads config/thresholds.yaml (cached)
├── config/
│   └── thresholds.yaml  # ALL tunable thresholds — no magic numbers in code
├── rules/
│   ├── base.py           # DetectionResult shared type
│   ├── ddos.py            # weighted-scoring DDoS detector
│   └── port_scan.py       # stateful, sliding-window port scan detector
├── alerts/
│   ├── severity.py        # severity != confidence
│   ├── evidence.py        # human-readable evidence assembly
│   └── generator.py       # builds the stable Alert schema
├── tests/
│   ├── generators.py       # synthetic FeatureRecord generators
│   ├── test_ddos.py
│   ├── test_port_scan.py
│   └── test_alerts.py
└── requirements.txt
```

One deliberate structural addition vs. the originally sketched layout:
`rules/base.py` holds a shared `DetectionResult` dataclass used by every
detector (rule-based now, ML/behavioural later). This is what lets
`engine.py` treat all detectors uniformly and makes the Milestone 3
fusion step an additive change rather than a rewrite. `config_loader.py`
was added as a small shared utility so no module re-implements YAML
loading/caching.

## 3. Install

```bash
cd threat_detection
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 4. Run the tests

```bash
# from the directory that CONTAINS threat_detection/
python3 -m pytest threat_detection/tests -v
```

## 5. Example: using the engine directly

```python
from threat_detection.engine import ThreatDetectionEngine
from threat_detection.feature_schema import FeatureRecord

engine = ThreatDetectionEngine()

feature = FeatureRecord(
    flow_id="flow-001",
    timestamp="2026-09-02T12:30:00Z",
    src_ip="203.0.113.5",
    dst_ip="10.0.0.20",
    src_port=4000,
    dst_port=80,
    protocol="TCP",
    packet_count=20000,
    byte_count=30000000,
    flow_duration=2.0,
    packet_rate=10000,
    byte_rate=15000000,
    syn_count=7000,
    ack_count=100,
    rst_count=20,
)

alert = engine.detect(feature)
if alert:
    print(alert.to_dict())
```

Expected output (fields will vary slightly — timestamps, alert_id
counter):

```json
{
  "alert_id": "ALT-000001",
  "timestamp": "2026-09-02T...Z",
  "flow_id": "flow-001",
  "source": {"ip": "203.0.113.5", "port": 4000},
  "destination": {"ip": "10.0.0.20", "port": 80},
  "protocol": "TCP",
  "threat_class": "DDoS",
  "confidence": 0.9...,
  "severity": "CRITICAL",
  "detection_method": ["RULE"],
  "evidence": [
    "Packet rate 10000 pkt/s exceeds baseline (warning=1000, high=5000)",
    "High SYN activity: 7000 SYNs over 2.00s (~3500/s)",
    "SYN/ACK imbalance: 7000 SYN vs 100 ACK",
    "Large packet volume (20000) observed over short duration (2.00s)"
  ],
  "mitre": {"tactic": "Impact", "technique_id": null, "verify": true},
  "status": "NEW"
}
```

Note `mitre.technique_id` is `null` and `verify: true` — we deliberately
do not guess an ATT&CK technique ID (see §10).

## 6. How the DDoS detector works

Five independent 0–1 component scores (packet rate, byte rate, SYN
rate, SYN/ACK imbalance, short-duration-high-volume shape) are combined
with configurable weights from `config/thresholds.yaml`. A flow is
flagged only if the weighted sum clears `detection.minimum_confidence`.
Tiny flows (`packet_count < min_packet_count`) are skipped entirely —
there isn't enough evidence either way.

## 7. How the port scan detector works

Port scanning cannot be judged from one flow. `PortScanDetector` keeps
a **bounded, per-source-IP, time-windowed** deque of recent
`(timestamp, dst_ip, dst_port, syn_count)` events. On every call it
prunes events older than `port_scan.window_seconds`, then scores based
on: how many unique destination ports were touched, SYN intensity, and
concentration (many ports against few destination IPs = more scan-like
than the same port count spread across many hosts, which looks more
like ordinary client behaviour).

**Important:** this detector is stateful. Instantiate it once per
engine/process and keep feeding it flows — do not create a new
`PortScanDetector()` per flow, or it will never see enough history to
evaluate anything.

## 8. Confidence vs. severity vs. score

- **score** — a detector's own raw 0–1 rule-scoring output.
- **confidence** — currently, we treat the winning detector's score as
  the alert's confidence. This is a **rule-based detection score**, not
  a statistically calibrated probability. It will become an actual
  calibrated confidence once ML models and real fusion (Milestone 3)
  are in place.
- **severity** — computed separately in `alerts/severity.py` from
  confidence bands *plus* threat-specific intensity overrides (e.g. an
  extreme packet rate forces `CRITICAL` regardless of exact confidence
  value). Severity is never simply set equal to confidence.

## 9. Evidence & explainability

Every alert's `evidence` list is built directly from the specific
feature values that triggered each detector component (e.g. exact
packet rate, SYN count, unique port count) — not a generic "threat
detected" string. This is what a judge, SOC analyst, or teammate needs
to answer "why did the system flag this?"

## 10. MITRE ATT&CK mapping

Milestone 1 maps `DDoS → Impact` and `PortScan → Reconnaissance` at the
**tactic** level only. We do **not** invent technique IDs (e.g.
T1595-style identifiers) — `mitre.technique_id` is `null` with
`verify: true` until someone on the team looks up and confirms the
correct current technique ID against the live ATT&CK matrix before any
presentation.

## 11. False-positive handling in Milestone 1

- Weighted multi-signal scoring instead of single hard thresholds.
- Minimum evidence requirements (`min_packet_count` for DDoS,
  `min_events_to_evaluate` for port scan) before a detector will even
  render a verdict.
- All thresholds are configurable in `config/thresholds.yaml`, marked
  explicitly as **prototype/lab values that must be recalibrated
  against real traffic** — nothing here is claimed to be validated
  against a real baseline.
- Alert deduplication / incident aggregation is **not yet implemented**
  — that's Milestone 2, alongside the streaming queue architecture.

## 12. Error handling

`validator.py` treats every `FeatureRecord` as untrusted: invalid IPs,
out-of-range ports, unsupported protocol strings, negative numbers, and
non-finite values (NaN/Infinity) are all rejected. `engine.detect()`
never raises on a malformed record — it logs a warning and returns
`None`, so one bad record can never take down a streaming loop.

## 13. Connecting to real PCAP-derived features later

Nothing in this module depends on how a `FeatureRecord` was produced.
Once the Feature Extraction module (upstream) emits dicts/JSON matching
the schema in `feature_schema.py`, they can be converted via
`FeatureRecord.from_dict(raw_dict)` and passed straight into
`engine.detect()`. Unknown extra keys in the upstream dict are silently
ignored, so upstream schema growth (DNS/TLS/behavioural fields for
later milestones) won't break this module.

## 14. Known limitations (Milestone 1)

- No fusion across detectors yet — if both DDoS and PortScan somehow
  fired on the same flow, the engine currently keeps only the
  higher-scoring one, not a combined verdict. Milestone 3 replaces this
  with a real fusion engine.
- No alert deduplication/incident aggregation — a sustained attack
  currently produces one alert per matching flow. Milestone 2.
- No streaming queue wiring yet — `engine.detect()` is called
  synchronously per record. Milestone 2 adds the `Queue`-based worker
  architecture.
- Thresholds are unvalidated placeholders, explicitly marked as such
  everywhere they appear.
- No performance benchmarking has been run yet; no throughput/latency
  numbers are claimed anywhere in this repo (see PROMPT §23/§38 — we do
  not invent benchmark numbers).

## 15. What's next — Milestone 2

```
Queue-based streaming detection worker
+ bounded state management across the stream
+ alert deduplication / incident aggregation
```

This wraps `ThreatDetectionEngine.detect()` in a `feature_queue` →
worker → `alert_queue` loop and adds incident tracking
(`first_seen`, `last_seen`, `event_count`, `peak_packet_rate`) so a
5,000-packet flood produces one evolving incident instead of 5,000
identical alerts.
