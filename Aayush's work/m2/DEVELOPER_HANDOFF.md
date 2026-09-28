# Module 2 (M2) — Developer Handoff Guide

> **Target Audience**: Team Members (Meet [M1], Aayushman [M3/M4], Anika [M5/M6], Evaluators)  
> **Module**: M2 — High-Speed Streaming Feature Extractor  
> **Lead**: Aayush  
> **Engine**: NFStream 6.6.0 C-Engine + Deep Packet Analyzer  

---

### Quick Summary

```text
       M1 (Ingest & 30s Window Manager)
            │
            ▼ (FlowWindow: 30-second packet window)
       M2 (NFStream C-Engine + Deep Packet Analyzer)
            │
            ▼ (pandas.DataFrame: 82 columns, CIC-IDS 2017 + DPI + Packet Features)
       M3 / M4 (AI Threat Detection Engine)
```

---

### 1. What Goes In?

#### A. Production Ingestion: `FlowWindow`
The canonical input defined in the Team Leader Master Guide is a `FlowWindow` object:
```python
window = FlowWindow(
    window_id="w_0001",
    start_time=1700000000.0,
    end_time=1700000030.0,
    packets=[...],  # list of RawPacket objects
)
```

#### B. Streaming Compatibility Bridge: `RawPacket`
When running with M1's `IngestPipeline`, M2 provides `M1WindowBridge` / `pipeline.ingest(pkt)`:
- Attributes: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `flags`, `payload_len`, `ttl`, `raw_frame`.

---

### 2. What Happens Inside M2?

1. **Production Path (`process_flow_window`)**:
   - Takes `FlowWindow`.
   - Runs `m2.packet_analyzer`: extracts TTL mean/variance, cumulative TCP flag bitmasks, TCP advertised window sizes, IP fragment flags, retransmissions, and sequential vs. random port scanning patterns.
   - Preserves original wire bytes (`raw_frame`) and serializes the window into an ephemeral temporary PCAP.
   - Invokes NFStream's compiled C-engine (`_lib_engine.pyd`) for high-speed bidirectional flow analysis.
   - Cleans up the temporary PCAP file immediately in a `finally:` block.
   - Merges statistics via `FeatureAdapter` into 82 strictly-typed columns.
2. **Compatibility Path (`M1WindowBridge`)**:
   - Buffers streaming `RawPacket` objects into 30-second windows using `StreamWindowAggregator` and triggers `process_flow_window` on window completion.

---

### 3. What Comes Out?

A `pandas.DataFrame` containing **82 strictly-typed columns** in deterministic order:
- **Flow Identity**: `window_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `protocol_name`.
- **Volume & Rates**: `Flow Duration` (µs), `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd/Bwd Packets`, `Flow Bytes/s`, `Flow Packets/s`.
- **Packet Length Distributions**: Max, Min, Mean, Std, `Packet Length Variance`, `Average Packet Size`.
- **TCP Control Flags & Bitmask**: `SYN Flag Count`, `ACK Flag Count`, `FIN Flag Count`, `RST Flag Count`, `tcp_flag_bitmask`.
- **Deep Packet Features**:
  - `TTL Mean`, `TTL Std`, `TTL Variance`, `TTL Min`, `TTL Max`
  - `TCP Window Size Init`, `TCP Window Size Mean`
  - `IP Flags DF Count`, `IP Flags MF Count`
  - `Retransmission Count`
  - `Port Sequentiality Score`, `Port Access Type`
- **Application Context**: `application_name`, `application_category_name`, `application_confidence`.

---

### 4. How Do I Run It?

#### Run Standalone Replay Demo
```powershell
python c:\Aayush\SIH\m2_processor.py demo_traffic.pcap
```

#### Run M3 AI Threat Detector on Output
```powershell
$env:PYTHONIOENCODING="utf-8"; python c:\Aayush\SIH\m3_dummy_ai.py
```

#### Run Full Test Suite (21 Tests)
```powershell
$env:PYTHONPATH="c:\Aayush\SIH;c:\Aayush\SIH\m1_standalone"; python -m unittest discover -s c:\Aayush\SIH\m2\tests -p "test_*.py" -v
```

---

### 5. How Do I Integrate with It?

#### A. For Meet (M1 Ingest Lead):
```python
# Option 1: Hand off completed 30-second FlowWindow (Production Contract)
import m2
pipeline = m2.M2Pipeline()
meta, df = pipeline.process_flow_window(flow_window)

# Option 2: Stream raw packets into M2 compatibility bridge
from m1_standalone.packet_queue import IngestPipeline
pipeline = m2.M2Pipeline()
m1_pipeline = IngestPipeline(pps=5000, num_workers=2)
pipeline.attach_to_m1(m1_pipeline)
pipeline.start()
m1_pipeline.start()
```

#### B. For Aayushman (M3/M4 AI Lead):
```python
import m2

pipeline = m2.M2Pipeline()

# Subscribe to receive DataFrames as each 30s window completes:
def ai_detector(df, meta):
    print(f"Window {meta.window_id}: {len(df)} flows")
    predictions = model.predict(df)

pipeline.subscribe(ai_detector)
```

---

### 6. What Can Go Wrong?

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| `ImportError: DLL load failed: _lib_engine` | Windows cannot find `wpcap.dll` | Install Npcap in WinPcap-compatible mode. `m2` auto-registers `C:\Windows\System32\Npcap`. |
| Zero flows from PCAP replay | Capture uses raw IPv4 datalink (linktype 228) | Fixed in `m1_standalone.pcap_stream_reader` and `m2.packet_adapter` to support linktypes 12, 101, 228. |
| Unicode error on Windows console | CP1252 terminal without UTF-8 output | Run with `$env:PYTHONIOENCODING="utf-8"`. |
