# Phase 2 — ML Model Development & Evaluation Technical Report

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Role:** Person 3 (Senior Machine Learning Engineer)  
**Evaluation Timestamp:** 2026-09-03  

---

## 1. Dataset & Schema Overview
- **Training Set (`train.csv`):** 1,124,461 rows
- **Validation Set (`validation.csv`):** 240,956 rows
- **Test Set (`test.csv` - Isolated):** 240,957 rows
- **Active ML Features:** 66 numerical network flow features

---

## 2. Supervised Model Candidate Comparison (Validation Set)

| Model Candidate | Accuracy | Macro F1 | Weighted F1 | Attack Recall | FNR (Missed) | FPR (False Alarm) | Throughput (fps) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression Baseline** | 0.9357 | 0.628 | 0.9486 | 0.9962 | 0.0038 | 0.0777 | 1058864.46 |
| **Random Forest Primary** | 0.9992 | 0.9932 | 0.9992 | 0.9991 | 0.0009 | 0.0007 | 332430.11 |


---

## 3. Selected Model & Justification
- **Selected Primary Classifier:** `Random Forest Primary`
- **Validation Macro F1:** 0.9932
- **Validation Attack Recall:** 0.9991
- **Validation Missed Attack Rate (FNR):** 0.0009
- **Validation False Alarm Rate (FPR):** 0.0007
- **Inference Throughput:** 332,430.11 flows/sec
- **Selection Rationale:** Selected due to superior Macro F1 performance, high minority attack recall, low false negative rates on malicious network flows, and real-time inference throughput.

### Selected Model Per-Class Validation Breakdown
| Threat Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| `BENIGN` | 0.9997 | 0.9993 | 0.9995 | 177,373 |
| `BRUTE_FORCE` | 0.9985 | 0.9993 | 0.9989 | 1,373 |
| `DDOS` | 0.9996 | 0.9992 | 0.9994 | 19,202 |
| `DOS` | 0.9958 | 0.9993 | 0.9975 | 29,062 |
| `OTHER_ATTACK` | 1.0 | 1.0 | 1.0 | 2 |
| `PORT_SCAN` | 1.0 | 0.9995 | 0.9997 | 13,623 |
| `WEB_ATTACK` | 0.9773 | 0.9377 | 0.9571 | 321 |

---

## 4. Isolation Forest Anomaly Detection Summary
- **Validation Anomalies Flagged:** 23,953 (9.94%)
- **Mean Normalized Anomaly Score:** 0.1597
- **Usage:** Provides an unsupervised complementary `anomaly_score` $[0.0, 1.0]$ alongside supervised predictions.

---

## 5. Top 15 Important Features (Gini Importance)
1. `Destination Port` (0.0775)
2. `Init_Win_bytes_backward` (0.0444)
3. `Bwd Header Length` (0.0419)
4. `Fwd Packet Length Max` (0.0404)
5. `Total Length of Fwd Packets` (0.0387)
6. `Fwd Packet Length Mean` (0.0358)
7. `Max Packet Length` (0.0351)
8. `Bwd Packet Length Max` (0.0344)
9. `Avg Fwd Segment Size` (0.0334)
10. `Subflow Fwd Bytes` (0.0329)
11. `Fwd Header Length.1` (0.0319)
12. `Average Packet Size` (0.0315)
13. `Subflow Bwd Bytes` (0.0277)
14. `Packet Length Mean` (0.0262)
15. `Bwd Packet Length Min` (0.0255)

---

## 6. FINAL UNSEEN TEST RESULTS

> **Evaluation Protocol:** Evaluated ONCE on `ml/data/test.csv` (240,957 rows) after freezing model architecture and preprocessing pipeline.

- **Test Accuracy:** 0.9991
- **Test Macro F1:** 0.9945
- **Test Macro Precision:** 0.9984
- **Test Macro Recall:** 0.9909
- **Test Weighted F1:** 0.9991
- **Test Attack Recall:** 0.9993
- **Test False Negative Rate (Missed Attacks):** 0.0007
- **Test False Positive Rate (False Alarms):** 0.0009

### Final Test Set Per-Class Metrics
| Threat Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| `BENIGN` | 0.9997 | 0.9991 | 0.9994 | 177,373 |
| `BRUTE_FORCE` | 0.9978 | 0.9985 | 0.9982 | 1,373 |
| `DDOS` | 0.9997 | 0.9997 | 0.9997 | 19,203 |
| `DOS` | 0.9946 | 0.9994 | 0.997 | 29,062 |
| `OTHER_ATTACK` | 1.0 | 1.0 | 1.0 | 2 |
| `PORT_SCAN` | 0.9999 | 0.999 | 0.9994 | 13,623 |
| `WEB_ATTACK` | 0.9967 | 0.9408 | 0.9679 | 321 |

---

## 7. Model Artifacts & Handoff for Person 4
- **Classifier Artifact:** `ml/models/classifier.joblib`
- **Preprocessor Artifact:** `ml/models/preprocessing_pipeline.joblib`
- **Anomaly Detector Artifact:** `ml/models/anomaly_model.joblib`
- **Feature Schema Specification:** `ml/models/feature_schema.json`
- **Inference Interface Module:** `ml/inference/predict.py`

---

## 8. Person 4 Handoff Contract
Person 4 will invoke `predict(features)` in `ml/inference/predict.py` to get structured predictions:
```json
{
  "threat_class": "DDOS",
  "confidence": 0.98,
  "probabilities": {
    "BENIGN": 0.01,
    "DDOS": 0.98,
    "PORT_SCAN": 0.01
  },
  "anomaly_score": 0.89
}
```

---

## 9. Phase 3 Readiness

```
READY FOR PERSON 4 RULE ENGINE & ALERTS FUSION (PHASE 3 / M5)
```
