# M2 Data & Feature Validation Report for M4 Threat Classifier B

> **Module Evaluated:** M2 Feature Extractor Output (`m2_output_for_ai.csv`)  
> **Evaluator:** M4 Lead ML Engineer  
> **Source File Path:** `C:\PROJECTS\SIH PS189\Aayush's work\m2_feature_extractor\m2_feature_extractor\m2_output_for_ai.csv`  
> **Evaluation Timestamp:** 2026-09-02

---

## 1. Data Profile & Statistical Summary

| Metric | Value | Audit Finding |
| :--- | :--- | :--- |
| **Row Count** | 1 | Single synthetic/test flow sample |
| **Column Count** | 14 | Pre-aggregated IP flow layer metrics |
| **Missing / Null Values** | 0 | No missing values present |
| **Infinite Values** | 0 | No infinity or NaN entries found |
| **Duplicate Rows** | 0 | No duplicate rows |
| **Label / Target Column** | **NONE** | Ground truth label column is absent |

### Column Schema & Data Types

```
1.  src_ip                       (string  - '192.168.1.100')
2.  dst_ip                       (string  - '10.0.0.5')
3.  src_port                     (int64   - 12345)
4.  dst_port                     (int64   - 80)
5.  protocol                     (int64   - 6 / TCP)
6.  Flow Duration                (int64   - 6 seconds)
7.  Total Fwd Packets            (int64   - 100)
8.  Total Backward Packets       (int64   - 0)
9.  Total Length of Fwd Packets   (int64   - 4000 bytes)
10. Total Length of Bwd Packets   (int64   - 0 bytes)
11. SYN Flag Count               (int64   - 100)
12. ACK Flag Count               (int64   - 0)
13. Fwd IAT Mean                 (float64 - 0.060606)
14. Bwd IAT Mean                 (float64 - 0.0)
```

---

## 2. Feature Mapping & Gap Analysis vs. M4 Requirements

M4 is required to detect four primary threat categories: **BENIGN**, **DGA**, **C2**, and **DATA_EXFILTRATION**.

### A. DGA (Domain Generation Algorithm) Detection Analysis
- **M4 Feature Requirements:** Domain strings (FQDN), domain length, subdomain count, vowel/consonant ratio, Shannon entropy, character 2-gram, 3-gram, and 4-gram frequency statistics.
- **M2 Availability:** **NONE**. `m2_output_for_ai.csv` provides layer 3/4 IP address headers (`src_ip`, `dst_ip`) and TCP flags, but contains **no DNS query name, host header, or domain string**.
- **Calculations Possible:** **Shannon entropy and character N-gram features CANNOT be calculated** from `m2_output_for_ai.csv` because no domain or payload text string is included.

### B. C2 (Command and Control) Communication Analysis
- **M4 Feature Requirements:** Flow duration, forward/backward packet counts, inter-arrival time (IAT) mean and standard deviation, periodicity coefficient of variation (CoV), and connection frequency.
- **M2 Availability:** **PARTIAL**. M2 provides `Flow Duration`, `Fwd IAT Mean`, `Bwd IAT Mean`, `SYN Flag Count`, and `ACK Flag Count`.
- **Calculations Possible:** Basic flow timing can be mapped; however, detailed inter-arrival variance and periodicity CoV require per-packet IAT arrays.

### C. Data Exfiltration Activity Analysis
- **M4 Feature Requirements:** Outbound vs. inbound byte totals, upload/download byte ratio, flow duration, and throughput (bytes/sec).
- **M2 Availability:** **WELL SUPPORTED**. `Total Length of Fwd Packets` (4000 bytes) vs. `Total Length of Bwd Packets` (0 bytes) allows direct calculation of outbound upload volume and upload/download ratio ($4000 / 0 \rightarrow \infty$).

---

## 3. Evaluation of CSV Suitability

1. **Suitability for Model Training: UNSUITABLE**
   - **Reason 1:** The file contains only **1 single sample**, which is insufficient for statistical model fitting or cross-validation.
   - **Reason 2:** There are **no ground-truth threat labels** (`BENIGN`, `DGA`, `C2`, `DATA_EXFILTRATION`).
   - **Reason 3:** Crucial DGA domain attributes are entirely missing.

2. **Suitability for Runtime Inference: SUITABLE FOR FLOWS ONLY (WITH GAPS)**
   - Suitable as an input format for runtime network flow inference (C2 and Exfiltration models) once baseline models are trained offline on labeled datasets.
   - **Unsuitable for runtime DGA inference** unless extended to include domain/DNS query string fields.

---

## 4. Required Action Items & Recommendations

### Action Item A: Request to M2 Engineering Team
Request the M2 team to update their runtime feature output schema to include a `domain` / `dns_query` string field whenever DNS or HTTP packets are processed, e.g.:
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.5",
  "dns_query": "zx199qka.biz"  <-- REQUIRED FOR M4 DGA EXTRACTION
}
```

### Action Item B: Phase 3 Offline Dataset Strategy
Because `m2_output_for_ai.csv` cannot be used for model training, M4 requires offline labeled benchmark datasets:
1. **DGA Training:** UMDA DGA Dataset / Majestic 1M (Lexical domain labels).
2. **C2 Training:** CTU-13 / Stratosphere Malware Captures (NetFlow C2 beaconing).
3. **Exfiltration Training:** CIC-IDS2017 flow subset (Infiltration/Exfiltration flows).

---

## 5. Next Steps

1. Present findings and validation results to project lead.
2. Obtain approval for Phase 3 (Offline Dataset Acquisition & Baseline Model Training).
