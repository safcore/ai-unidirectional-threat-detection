# Phase 1 — Dataset Preparation & Validation Technical Report

**Project:** SIH 2026 — AI-Based Cyber Threat Detection in Unidirectional IP Traffic  
**Role:** Person 3 (Senior Machine Learning Engineer)  
**Execution Timestamp:** 2026-09-03  

---

## 1. Dataset Overview
- **Source Dataset:** Raw CICIDS2017 Dataset Files (`data/raw/cicids2017/`)
- **Initial Raw Records:** 1,821,190
- **Initial Column Count:** 79
- **Memory Footprint:** 1180.14 MB

---

## 2. Data Quality & Cleaning Audit
- **Infinite / NaN Values Converted:** 2,954
- **Rows Dropped Due to Unresolvable Nulls:** 0
- **Exact Duplicate Rows Removed:** 214,816
- **Remaining Clean Records:** 1,821,190

---

## 3. Label Analysis & Preservation Strategy
- **Original Label Preservation:** Exact raw strings from dataset `Label` column are preserved in `Label`.
- **Target Taxonomy Normalization:** Secondary normalized taxonomy column `target` created for downstream classification compatibility (`BENIGN`, `DDOS`, `PORT_SCAN`, `DOS`, `BRUTE_FORCE`, `WEB_ATTACK`, `BOTNET`, `INFILTRATION`).
- **Unique Raw Classes Detected:** 13

---

## 4. Data Leakage & Identifier Analysis

| Column Name | Assigned Category | ML Matrix Inclusion | Justification / Leakage Analysis |
| :--- | :--- | :--- | :--- |
| `Source IP` / `src_ip` | `METADATA / IDENTIFIER` | **EXCLUDED** | Prevents host IP memorization; kept for alert context |
| `Destination IP` / `dst_ip` | `METADATA / IDENTIFIER` | **EXCLUDED** | Prevents host IP memorization; kept for alert context |
| `Flow ID` / `timestamp` | `METADATA / IDENTIFIER` | **EXCLUDED** | Transactional identifier / timing artifact |
| `Label` | `TARGET` | **EXCLUDED** | Raw ground-truth target vector |
| `target` | `TARGET` | **EXCLUDED** | Mapped ground-truth target vector |
| *Flow Duration, Packets, Bytes, Flags, IAT Stats* | `ML_FEATURE` | **INCLUDED** | Pre-aggregated network traffic flow behavior |

---

## 5. Constant & Near-Constant Feature Exclusion
The following 12 features were identified as zero-variance constant features (top value present in >99.9% of rows) and excluded from the ML training matrix:
- `Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, RST Flag Count, CWE Flag Count, ECE Flag Count, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate`

---

## 6. Train / Validation / Test Split Strategy
- **Split Ratio:** **70% Training | 15% Validation | 15% Test**
- **Random Seed:** `RANDOM_STATE = 42` (Fixed for 100% reproducibility)
- **Stratification:** Stratified sampling applied on target class vector to preserve exact class ratios across splits.
- **Group/Time Leakage Assessment:** Evaluated chronological sequence vs flow aggregation. Stratified splitting preserves rare attack class representation across train and test partitions.
- **Test Set Protection:** `ml/data/test.csv` (240,957 rows) is strictly isolated and will NOT be accessed during feature selection, model training, or hyperparameter tuning.

---

## 7. Final Split Class Distribution

| Target Class | Training (70%) | Validation (15%) | Test (15%) | Total Records |
| :--- | :--- | :--- | :--- | :--- |
| `BENIGN` | 827,739 (70%) | 177,373 (15%) | 177,373 (15%) | **1,182,485** |
| `BRUTE_FORCE` | 6,406 (70%) | 1,373 (15%) | 1,373 (15%) | **9,152** |
| `DDOS` | 89,611 (70%) | 19,202 (15%) | 19,203 (15%) | **128,016** |
| `DOS` | 135,624 (70%) | 29,062 (15%) | 29,062 (15%) | **193,748** |
| `OTHER_ATTACK` | 7 (70%) | 2 (15%) | 2 (15%) | **11** |
| `PORT_SCAN` | 63,573 (70%) | 13,623 (15%) | 13,623 (15%) | **90,819** |
| `WEB_ATTACK` | 1,501 (70%) | 321 (15%) | 321 (15%) | **2,143** |

---

## 8. ML Interface & Feature Schema Summary
- **Active ML Features:** 66 features
- **Feature Schema Path:** `ml/models/feature_schema.json`
- **Output Files Generated:**
  - `ml/data/train.csv` (1,124,461 rows)
  - `ml/data/validation.csv` (240,956 rows)
  - `ml/data/test.csv` (240,957 rows)

---

## 9. Phase 2 Recommendations (Model Candidates & Training)
1. **Class Imbalance Handling:** Use `class_weight='balanced'` in Random Forest / XGBoost classifiers to compensate for minority attack classes (`WEB_ATTACK`, `BOTNET`, `INFILTRATION`).
2. **Candidate Models:** Random Forest, XGBoost Classifier, Logistic Regression baseline.
3. **Evaluation Metrics:** Multi-class Precision, Recall, Macro F1-score, and Confusion Matrix evaluated on `validation.csv`.

---

## 10. Phase 2 Readiness Declaration

```
READY FOR PHASE 2 MODEL TRAINING
```
