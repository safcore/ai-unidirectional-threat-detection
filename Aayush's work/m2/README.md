# Module 2 (M2) — High-Speed Streaming Feature Extraction

> **NTRO Problem Statement 26145 — Unidirectional Threat Detector**  
> **Module**: M2 (Feature Extractor & Flow Statistics Engine)  
> **Lead / Owner**: Aayush  
> **Engine**: NFStream 6.6.0 C-Engine + Deep Packet Analyzer + Npcap  

---

## 1. Purpose

Module 2 (M2) is the real-time feature-extraction engine for the **PS 26145 Unidirectional Threat Detector**.
Operating on a passive hardware data diode (optical tap), raw network traffic is parsed and grouped into bidirectional communication flows, accumulated into temporal sliding windows, and converted into strictly typed, high-dimensional statistical feature vectors for consumption by AI/ML threat detection models (M3/M4).

M2 provides:
- **Production Contract**: Consumes discrete `FlowWindow` objects produced by M1's 30-second sliding window aggregator.
- **Deep Flow Analysis**: Executes high-speed C-engine flow tracking via **NFStream 6.6.0**, extracting 86 native flow features per flow.
- **Deep Packet Analysis**: Extracts IP Time-To-Live (TTL), TTL variance, cumulative TCP flag bitmasks, TCP advertised window sizes, IP fragment flags, TCP retransmissions, and sequential vs. random port scanning patterns.
- **Feature Adaptation**: Maps raw statistics into the project's canonical **CIC-IDS 2017** feature schema, outputting deterministic pandas DataFrames (82 columns).
- **M1 Compatibility Bridge**: Provides `M1WindowBridge` to ingest raw packet streams when running with M1 standalone pipelines.

---

## 2. Architecture & Module Boundaries

### Production Architecture (Team Leader Master Guide)

```text
  Passive Hardware Data Diode (Optical Tap)
                    │
                    ▼
  [Module 1: Ingest Pipeline & PCAP Replay (Meet)]
  ├─ Network Tap / PCAP Reader
  ├─ Bounded Ingestion Queue (threading.Queue)
  └─ 30-Second Sliding Window Manager
                    │
                    ▼
               FlowWindow (30-second slice of network traffic)
                    │
                    ▼ [M2 Production Entry Point: process_flow_window()]
  [Module 2: Feature Extraction (Aayush)]
  ├─ 1. Deep Packet Analyzer (m2.packet_analyzer)
  │     ├─ Computes TTL distributions & TTL variance
  │     ├─ Computes cumulative TCP flag bitmask
  │     ├─ Parses TCP advertised window sizes (init, mean)
  │     ├─ Tracks IP fragment flags (DF, MF)
  │     ├─ Detects TCP retransmissions
  │     └─ Evaluates sequential vs. random port-access patterns
  │
  ├─ 2. Packet Adapter & Transient PCAP Bridge (m2.packet_adapter)
  │     ├─ Preserves original wire bytes (pkt.raw_frame / pkt.raw)
  │     └─ Generates ephemeral temporary libpcap 2.4 buffer
  │
  ├─ 3. NFStream C-Dissection Engine (m2.engine)
  │     ├─ Multithreaded C-speed flow tracking (_lib_engine.pyd)
  │     ├─ Bidirectional statistical analysis (IAT, sizes, rates)
  │     └─ nDPI application protocol identification
  │
  └─ 4. Feature Adapter (m2.adapter)
        ├─ Maps NFStream attributes to canonical CIC-IDS 2017 schema
        ├─ Merges deep packet metrics (TTL, flags, window, retransmission)
        ├─ Converts units (ms → µs, rates, ratios)
        ├─ Sanitizes NaN / Inf to 0.0
        └─ Enforces deterministic column ordering and strict dtypes
                    │
                    ▼
          pandas.DataFrame (82 columns)
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
  [Output Queue / Callback]   [Optional CSV Sink]
         │                     │
         ▼                     ▼
  Module 3 / Module 4         m2_output_for_ai.csv
  (AI Threat Detector)        (Offline Evaluation)
```

### Compatibility Bridge for M1 (`M1WindowBridge`)
In environments where M1 emits `RawPacket` streams directly rather than completed `FlowWindow` objects, M2's `M1WindowBridge` encapsulates `StreamWindowAggregator` to slice raw packets into 30-second windows and deliver them cleanly to `process_flow_window()`.

---

## 3. Responsibilities

### What M2 Owns
- The production feature extraction pipeline consuming `FlowWindow` instances.
- Deep packet inspection for TTL variance, TCP window sizes, IP fragment flags, retransmissions, and port access patterns.
- Serializing packets into transient libpcap buffers for NFStream C-engine dissection.
- Managing the NFStream C-engine lifecycle and safe cleanup of transient PCAP files.
- Adapting flow statistics to the canonical CIC-IDS 2017 schema with deterministic column ordering and strict dtypes.
- Providing `M1WindowBridge` as a compatibility adapter for M1 `RawPacket` streams.

### What M2 Does NOT Own
- Hardware network tap ingestion and NIC promiscuous packet capture (owned by M1).
- Hardware backpressure and ingestion queue depth regulation (owned by M1).
- Threat classification and anomaly scoring (owned by M3).
- MITRE ATT&CK mapping and alerting (owned by M4 / M5).
- Web dashboard and UI visualization (owned by M6).

---

## 4. Input Contracts

### Primary Production Contract (`FlowWindow`)
The production entry point is `M2Pipeline.process_flow_window(window: FlowWindow)`:

```python
@dataclass
class FlowWindow:
    window_id: str           # Unique identifier (e.g. "w_0001", "w_0002")
    start_time: float        # Window start epoch timestamp (seconds)
    end_time: float          # Window end epoch timestamp (seconds)
    packets: List[Any]       # List of RawPacket objects in this window
```

### Raw Packet Contract (`RawPacket`)
Each packet within a `FlowWindow` (or ingested via `M1WindowBridge`) conforms to:

```python
@dataclass
class RawPacket:
    timestamp: float          # Epoch seconds (from PCAP header or wall-clock)
    src_ip: str               # Source IPv4 address (e.g. "192.168.1.100")
    dst_ip: str               # Destination IPv4 address (e.g. "10.0.0.5")
    src_port: int             # Source transport port (0-65535)
    dst_port: int             # Destination transport port (0-65535)
    protocol: str             # "TCP" | "UDP" | "DNS" | "ICMP"
    flags: int                # TCP flags bitmask (SYN=0x02, ACK=0x10, etc.)
    payload_len: int          # Payload length in bytes
    ttl: int                  # IP Time-To-Live
    raw_payload: bytes        # Raw payload bytes
    raw_frame: bytes          # Genuine captured wire frame (Ethernet / IP)
```

---

## 5. Output Contract

M2 outputs a `pandas.DataFrame` containing exactly **82 columns** in deterministic order, with strict dtypes and zero unhandled `NaN`/`inf` values.

### Column Categories
1. **Metadata**: `window_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `protocol_name`
2. **Flow Volume**: `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd Packets`, `Total Length of Bwd Packets`
3. **Packet Length Distributions**: Forward/Backward Max, Min, Mean, Std, Min/Max Packet Length, Mean, Std, Variance, Average Packet Size, Segment Sizes
4. **Traffic Rates**: `Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`, `Bwd Packets/s`
5. **Inter-Arrival Times (IAT)**: Flow IAT (Mean, Std, Max, Min), Fwd IAT (Total, Mean, Std, Max, Min), Bwd IAT (Total, Mean, Std, Max, Min)
6. **TCP Control Flags**: `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`, `PSH Flag Count`, `ACK Flag Count`, `URG Flag Count`, `CWE Flag Count`, `ECE Flag Count`, `Fwd PSH Flags`, `Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags`
7. **Flag Bitmask & Ratios**: `tcp_flag_bitmask`, `Down/Up Ratio`
8. **TTL Features**: `TTL Mean`, `TTL Std`, `TTL Variance`, `TTL Min`, `TTL Max`
9. **TCP Window Features**: `TCP Window Size Init`, `TCP Window Size Mean`
10. **IP Fragment Flags**: `IP Flags DF Count`, `IP Flags MF Count`
11. **Retransmission**: `Retransmission Count`
12. **Port Access Pattern**: `Port Sequentiality Score`, `Port Access Type`
13. **Enriched DPI Context**: `bidirectional_duration_ms`, `bidirectional_packets`, `bidirectional_bytes`, `src2dst_packets`, `src2dst_bytes`, `dst2src_packets`, `dst2src_bytes`, `application_name`, `application_category_name`, `application_confidence`

---

## 6. NFStream Integration & Transient PCAP Handling

### C-Engine Integration
- **Engine**: NFStream 6.6.0 C-engine (`_lib_engine.pyd`) with compiled packet dissection and flow expiration.
- **Why NFStream**: Eliminates Java subprocess overhead of CICFlowMeter, avoids Python GIL contention, and achieves 60,000+ packets/sec throughput.

### Transient PCAP Storage (Accurate Description)
NFStream's underlying C-engine requires a filesystem path to open offline captures (`pcap_open_offline`).
`m2.packet_adapter` writes packets to an ephemeral temporary `.pcap` file using `tempfile.mkstemp()`. The temporary file is opened, processed by NFStream, and **deleted immediately in a `finally:` block** after feature extraction. This transient file approach ensures minimal disk footprint and avoids accumulating temp files.

---

## 7. Master Guide Feature Coverage Table

Every feature required by the Team Leader Master Guide is audited and classified below:

| Required Feature | Project / Schema Name | Category | Extraction / Derivation Source | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **TCP flag bitmask** | `tcp_flag_bitmask` | **C** | `m2.packet_analyzer` (bitwise OR across packets) | Cumulative bitmask (SYN=0x02, ACK=0x10, etc.) |
| **Bytes per flow** | `Total Length of Fwd Packets`, `Total Length of Bwd Packets` | **A** | NFStream (`src2dst_bytes`, `dst2src_bytes`) | Direct 1:1 forward and backward payload bytes |
| **Packets per flow** | `Total Fwd Packets`, `Total Backward Packets` | **A** | NFStream (`src2dst_packets`, `dst2src_packets`) | Direct 1:1 forward and backward packet counts |
| **Flow duration** | `Flow Duration` | **B** | NFStream (`bidirectional_duration_ms` * 1000.0) | Converted from milliseconds to microseconds |
| **IAT mean/variance/max** | `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max` | **A / B** | NFStream (`bidirectional_mean/stddev/max_piat_ms`) | Scaled to µs; variance derived as `std ** 2` |
| **Bidirectional flow ratio** | `Down/Up Ratio` | **B** | Derived: `dst2src_packets / max(src2dst_packets, 1)` | Packet ratio; byte ratio available via volumes |
| **Source / Destination port** | `src_port`, `dst_port` | **A** | NFStream (`src_port`, `dst_port`) | Direct 1:1 transport endpoints |
| **Protocol** | `protocol`, `protocol_name` | **A / B** | NFStream (`protocol`) | Protocol number (6=TCP, 17=UDP) and mapped string |
| **TTL and TTL variance** | `TTL Mean`, `TTL Std`, `TTL Variance`, `TTL Min`, `TTL Max` | **C** | `m2.packet_analyzer` (`pkt.ttl` / IP header byte 8) | Extracted across all packets in the flow |
| **TCP window size** | `TCP Window Size Init`, `TCP Window Size Mean` | **C** | `m2.packet_analyzer` (TCP header bytes 14-15) | Initial forward advertised window and mean window |
| **IP fragment flags** | `IP Flags DF Count`, `IP Flags MF Count` | **C** | `m2.packet_analyzer` (IPv4 header byte 6 flags) | Don't Fragment (DF) and More Fragments (MF) counts |
| **Payload-size distribution** | `Packet Length Mean`, `Std`, `Variance`, `Min`, `Max` | **A / B** | NFStream (`bidirectional_mean/stddev/min/max_ps`) | Complete payload length distribution and variance |
| **Retransmission count** | `Retransmission Count` | **C** | `m2.packet_analyzer` (duplicate seq/SYN tracking) | Number of repeated TCP transmissions in the flow |
| **Sequential vs random port access** | `Port Sequentiality Score`, `Port Access Type` | **C** | `m2.packet_analyzer` (per `src_ip` port delta tracking) | Detects sequential vs. random reconnaissance scans |

> **Classification Legend**:  
> - **A**: Genuinely extracted directly from NFStream native flow records.  
> - **B**: Correctly derived mathematically from NFStream statistics.  
> - **C**: Extracted via deep packet analysis (`m2.packet_analyzer`) to complement NFStream.  
> - **D**: Genuinely unsupported / limitation (e.g. proprietary CICFlowMeter bulk heuristics).

---

## 8. Sliding Window Semantics & Gap Handling

`StreamWindowAggregator` supports two 30-second window modes:
1. **Tumbling Mode** (`window_duration_sec = 30.0, slide_interval_sec = 30.0`):
   - Disjoint windows: `[0s, 30s)`, `[30s, 60s)`, `[60s, 90s)`.
   - Complete state isolation: packet buffers are cleared between intervals.
2. **Overlapping Sliding Mode** (`slide_interval_sec < window_duration_sec`):
   - Configurable slide (e.g., 30s window sliding every 10s).
   - Window 1: `[0s, 30s)`, Window 2: `[10s, 40s)`, Window 3: `[20s, 50s)`.
   - Automatically retains packets falling inside `[start + slide, end + slide)`.
3. **Large Timestamp Gap Handling**:
   - When traffic experiences long idle gaps (`ts >= window_end + duration`), the window state realigns directly to the new packet's arrival time, preventing spurious empty window loops.
4. **Flush on Termination**:
   - Calling `stop(flush=True)` or `flush()` finalizes and emits any remaining buffered packets.

---

## 9. Installation & Windows Npcap Setup

### System Requirements
- **OS**: Windows 10/11 (AMD64) or Linux (x86_64)
- **Python**: 3.10 to 3.12 (Python 3.12 verified)
- **Npcap Driver**: Required on Windows for `wpcap.dll` (https://npcap.com/#download). Install in **"WinPcap API-compatible Mode"**.

### Python Dependencies
```bash
pip install nfstream==6.6.0 pandas numpy rich scapy dpkt
```

### Windows DLL Bootstrap
Importing `m2` automatically executes `m2.bootstrap.bootstrap_environment()`, which registers `C:\Windows\System32\Npcap` via `os.add_dll_directory()`. Multiprocessing workers also find `wpcap.dll` through `sitecustomize.py`.

---

## 10. Usage Examples

### A. Production FlowWindow Ingestion (Team Contract)
```python
import m2

pipeline = m2.M2Pipeline()
# Ingest completed 30-second FlowWindow from M1
meta, df = pipeline.process_flow_window(flow_window)
print(f"Extracted {len(df)} flows with {len(df.columns)} features")
```

### B. Streaming via M1 Compatibility Bridge
```python
from m1_standalone.packet_queue import IngestPipeline
import m2

pipeline = m2.M2Pipeline(config=m2.M2Config(window_duration_sec=30.0))

def on_features(df, meta):
    print(f"Window {meta.window_id}: {len(df)} flows -> M3 AI model")

pipeline.subscribe(on_features)
m1 = IngestPipeline(pps=5000, num_workers=2)
pipeline.attach_to_m1(m1)

pipeline.start()
m1.start()
```

### C. Offline / Evaluation Benchmark (Batch API)
```python
import m2

# Offline evaluation utility only (not used in production streaming)
df = m2.batch_extract_pcap("demo_traffic.pcap")
print(df[["src_ip", "dst_ip", "SYN Flag Count", "TTL Mean", "tcp_flag_bitmask"]].head())
```

---

## 11. Testing

M2 includes 21 automated unit and integration tests:

```powershell
$env:PYTHONPATH="c:\Aayush\SIH;c:\Aayush\SIH\m1_standalone"; python -m unittest discover -s c:\Aayush\SIH\m2\tests -p "test_*.py" -v
```

### Test Coverage Breakdown
- `test_feature_coverage.py`: All 14 Master Guide features present, TTL/bitmask/retransmissions/port scan logic, production `FlowWindow` contract.
- `test_feature_adapter.py`: Direct mapping, derived features, empty DataFrame shape, NaN/inf sanitization, deterministic column order.
- `test_packet_adapter.py`: TCP/UDP frame synthesis, transient PCAP serialization, raw wire byte preservation.
- `test_window_aggregator.py`: 30-second boundaries, state isolation, flush on stop, multi-threaded ingest concurrency.
- `test_streaming_windows.py`: Multi-window streaming, overlapping sliding windows, large timestamp gap recovery.
- `test_m1_m2_integration.py`: M1 queue and synthetic/PCAP replay integration.

**Results: 21 of 21 tests pass.**

---

## 12. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| `ImportError: DLL load failed: _lib_engine` | Windows cannot locate `wpcap.dll` | Install Npcap in WinPcap-compatible mode. `m2` auto-registers `C:\Windows\System32\Npcap`. |
| Dropped packets on PCAP replay | PCAP uses raw IPv4 datalink (linktype 228) | Fixed in `m1_standalone.pcap_stream_reader` and `m2.packet_adapter` to support linktypes 12, 101, 228. |
| Missing features in old test runners | Output DataFrame updated from 69 to 82 columns | All new columns are deterministically placed; downstream models reading subset of columns continue unaffected. |

---

## 13. Project Constraints

- **100% Offline**: Operates with zero network calls, zero cloud dependencies, and zero telemetry.
- **Data-Diode Compliant**: Passive consumer only. Transmits no packets and opens no outbound sockets.
- **Streaming Pipeline**: Slices packets into 30-second windows without accumulating multi-gigabyte captures in memory.

---

## 14. Remaining Limitations

1. **Java CICFlowMeter Subflow Bulk Heuristics**: Heuristics such as `Fwd Avg Bytes/Bulk` or `Subflow Fwd Packets` are specific to CICFlowMeter's legacy implementation and are not emitted by NFStream. The 82 features extracted by M2 provide superior statistical coverage.
2. **Transient Disk Buffer for NFStream**: Because NFStream's C-engine requires a filesystem path string (`pcap_open_offline`), transient temporary PCAP files on disk are required during window processing. These files are deleted immediately in `finally:` blocks.

---

## 15. Downstream Integration (M3 / M4)

Aayushman's AI threat detection models can consume M2 in three ways:
1. **Push Callback**: `pipeline.subscribe(my_ai_handler)`
2. **Pull Queue**: `meta, df = pipeline.get_next_window(timeout=1.0)`
3. **CSV Poller**: `m2_output_for_ai.csv`
