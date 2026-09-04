# Machine Learning Model Artifacts & Feature Schema

**Module:** M4 — Advanced Threat Classifier B / Phase 2 Model Store  
**Location:** `ml/models/`  

---

## 1. Overview of Artifacts

This directory contains the serialized binary model artifacts and canonical feature schema JSON file required for real-time inference, anomaly detection, and feature validation.

```text
ml/models/
├── README.md                          # Model store documentation (This file)
├── classifier.joblib                  # Trained Baseline Random Forest Model
├── anomaly_model.joblib               # Trained Isolation Forest Anomaly Detector
├── preprocessing_pipeline.joblib      # Trained StandardScaler Data Preprocessor
└── feature_schema.json                # Canonical 66-Feature Vector Contract
```

---

## 2. Artifact Details

| Artifact Name | Generating Script | Loading Module | Purpose |
| :--- | :--- | :--- | :--- |
| **`classifier.joblib`** | `ml/training/train_classifier.py` | `ml/inference/predict.py` | Supervised Random Forest Classifier (100 estimators, max depth 20) trained on 1.6M CICIDS2017 flow records (99.4% F1-score). |
| **`anomaly_model.joblib`** | `ml/training/train_anomaly.py` | `ml/inference/predict.py` | Unsupervised Isolation Forest model (contamination 0.05) evaluating flow outlier anomaly scores. |
| **`preprocessing_pipeline.joblib`** | `ml/preprocessing/clean.py` | `ml/inference/predict.py` | Standardized `StandardScaler` pipeline fitting feature scaling transformations. |
| **`feature_schema.json`** | `ml/training/loader.py` | `ml/detection/feature_validator.py` | JSON contract specifying the exact 66 numerical feature column names, data types, and ordering expected by the models. |

---

## 3. Canonical 66-Feature Vector Schema Contract

Incoming feature dictionaries passed to `predict(features)` or `engine.process(features)` must match the 66 numerical column vector schema defined in `feature_schema.json`.

Sample features include:
- `Destination Port`
- `Flow Duration`
- `Total Fwd Packets`, `Total Backward Packets`
- `Total Length of Fwd Packets`, `Total Length of Bwd Packets`
- `Fwd Packet Length Max`, `Fwd Packet Length Min`, `Fwd Packet Length Mean`, `Fwd Packet Length Std`
- `Flow Bytes/s`, `Flow Packets/s`
- `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max`, `Flow IAT Min`
- `Bwd IAT Mean`, `Fwd IAT Mean`, `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`, `ACK Flag Count`, etc.
