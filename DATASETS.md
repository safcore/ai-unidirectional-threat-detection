# M4 — Dataset Architecture & Specification Documentation

## Architectural Note on Dataset Selection

> **CRITICAL SEPARATION OF DATA SOURCES:**
> Standard network flow datasets like **CIC-IDS2017** are optimized for packet-level flow statistics (e.g., flow duration, byte counts, TCP flags), making them suitable for detecting **Command & Control (C2)** channels and **Data Exfiltration** anomalies.
> 
> However, **CIC-IDS2017 alone is NOT sufficient for DGA (Domain Generation Algorithm) detection.** DGA classification relies on lexical, character-level, and information-theoretic properties of domain names (such as domain length, sub-label entropy, character n-gram perplexity, and consonant-to-vowel ratios). Therefore, M4 uses a multi-source dataset strategy combining lexical domain corpora with network flow captures.

---

## Targeted Dataset Specifications

### 1. DGA (Domain Generation Algorithm) Dataset
- **Dataset Name**: UMDA DGA Dataset / Majestic Million vs. DGA Feed (BAM / Cryptolocker / Suppobox / Pyda)
- **Source**: University of Maryland / Malware Domain List / Majestic Top 1M
- **URL**: `https://github.com/dga-dataset` / `https://majestic.com/reports/majestic-million`
- **Threat Category**: `DGA` (Benign vs. DGA-generated domain names)
- **File Format**: CSV / Text (`domain`, `subdomain`, `family`, `label`)
- **Available Features**: Raw FQDN strings, TLD, timestamp, algorithm family tag.
- **Label Format**: Binary (`0` = Benign, `1` = DGA) and Multiclass (`Cryptolocker`, `Conficker`, `Gameover`, `Benign`).
- **License / Usage Restrictions**: Open Academic / Research Use.
- **Why Appropriate**: Provides thousands of algorithmically generated domain strings from active malware families alongside top legitimate domains, enabling precise lexical feature extraction (entropy, n-grams).

---

### 2. C2 (Command and Control) Communication Dataset
- **Dataset Name**: Stratosphere Linux IPS Dataset (CTU-13) & Malware Capture Facility Project
- **Source**: CTU University Prague / Stratosphere Laboratory
- **URL**: `https://www.stratosphereips.org/datasets-ctu13`
- **Threat Category**: `C2` (Botnet / C2 beaconing communication)
- **File Format**: NetFlow / CSV / PCAP (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `bytes`, `packets`, `duration`, `periodicity`)
- **Available Features**: Inter-arrival time (IAT), flow duration, periodicity metrics, byte ratio, connection frequency.
- **Label Format**: Multiclass (`Botnet-C2`, `Normal`, `Background`).
- **License / Usage Restrictions**: Creative Commons Attribution 4.0 International (CC BY 4.0).
- **Why Appropriate**: CTU-13 contains real malware execution captures with distinct periodic beaconing behavior, allowing extraction of frequency-domain and timing periodicity features.

---

### 3. Data Exfiltration Dataset
- **Dataset Name**: CIC-IDS2017 / Canadian Institute for Cybersecurity Exfiltration Captures
- **Source**: UNB Canadian Institute for Cybersecurity
- **URL**: `https://www.unb.ca/cic/datasets/ids-2017.html`
- **Threat Category**: `DATA_EXFILTRATION` & `BENIGN`
- **File Format**: CSV (78 extracted flow features) / PCAP
- **Available Features**: Flow Duration, Total Fwd Packets, Total Backward Packets, Fwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Outbound/Inbound Byte Ratio.
- **Label Format**: Binary/Categorical (`BENIGN`, `Infiltration`, `Data_Exfiltration`).
- **License / Usage Restrictions**: Open for Academic & Non-commercial Cybersecurity Research.
- **Why Appropriate**: High volume of background normal traffic combined with distinct asymmetric outbound data transfer flows, ideal for evaluation of flow imbalance and volume-based exfiltration.

---

## Directory Architecture

```
data/
├── raw/
│   ├── dga/           # Raw DGA and legitimate domain CSVs
│   ├── c2/            # NetFlow/PCAP extractions for C2 channels
│   └── exfiltration/  # Flow records for data exfiltration
├── processed/         # Cleaned, unified tabular records ready for pipeline
└── features/          # Extracted feature vectors (entropy, n-grams, flow metrics)
```
