"""
Module 3 (M3) — Offline Threat Classifier Training Pipeline
===========================================================
Trains the scikit-learn RandomForestClassifier model offline for M3.
- Primarily consumes real labelled network traffic features passed through M1 -> M2.
- STABLE FAIL-SAFE: Real training data will NEVER silently fall back to synthetic data.
- The '--smoke-test' flag is the ONLY mechanism allowing fallback synthetic data.
- Records rigorous provenance metadata (source, sample count, class distribution,
  feature count, evaluation metrics) alongside the serialized joblib artifact.
"""

import os
import sys
import argparse
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from .schema import ThreatClass
from .features import extract_features, MODEL_FEATURE_NAMES
from .model import ThreatClassifier
from .fallback_data import generate_fallback_smoke_dataset


DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "threat_detector.joblib")


def load_labeled_csv(data_path: str) -> Tuple[pd.DataFrame, str]:
    """Loads CSV and detects target label column ('threat_class' or 'label')."""
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Training data file not found: {data_path}")

    df = pd.read_csv(data_path)
    label_col = None
    for candidate in ["threat_class", "label", "Label", "Target"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if not label_col:
        raise ValueError(
            f"Input dataset at {data_path} must contain a target label column "
            "('threat_class' or 'label'). Columns found: {list(df.columns)}"
        )

    # Standardize label values to ThreatClass
    valid_classes = {cls.value for cls in ThreatClass}
    
    # Map common variations
    label_mapping = {
        "BENIGN": ThreatClass.BENIGN.value,
        "Benign": ThreatClass.BENIGN.value,
        "0": ThreatClass.BENIGN.value,
        "DDoS": ThreatClass.SYN_FLOOD.value,
        "DoS": ThreatClass.SYN_FLOOD.value,
        "SYN_FLOOD": ThreatClass.SYN_FLOOD.value,
        "SYN Flood": ThreatClass.SYN_FLOOD.value,
        "UDP_FLOOD": ThreatClass.UDP_FLOOD.value,
        "UDP Flood": ThreatClass.UDP_FLOOD.value,
        "PortScan": ThreatClass.PORT_SCAN.value,
        "PORT_SCAN": ThreatClass.PORT_SCAN.value,
        "Port Scan": ThreatClass.PORT_SCAN.value,
    }

    df[label_col] = df[label_col].map(lambda x: label_mapping.get(str(x), str(x)))
    # Filter to supported scope
    df = df[df[label_col].isin(valid_classes)].copy()
    if df.empty:
        raise ValueError(f"No samples matching supported M3 classes {valid_classes} found in {data_path}")

    return df, label_col


def load_pcap_directory(pcap_dir: str) -> Tuple[pd.DataFrame, str]:
    """
    Extracts features from PCAP files in subdirectories using M2's batch extractor.
    Directory structure expected:
      pcap_dir/BENIGN/*.pcap
      pcap_dir/SYN_FLOOD/*.pcap
      pcap_dir/UDP_FLOOD/*.pcap
      pcap_dir/PORT_SCAN/*.pcap
    """
    if not os.path.exists(pcap_dir):
        raise FileNotFoundError(f"PCAP directory not found: {pcap_dir}")

    # Safely import M2 pipeline without modifying M2
    try:
        from m2.pipeline import M2Pipeline
    except ImportError:
        raise ImportError("Could not import m2.pipeline. Ensure the repository root is on PYTHONPATH.")

    pipeline = M2Pipeline()
    records = []

    for cls in ThreatClass:
        cls_dir = os.path.join(pcap_dir, cls.value)
        if not os.path.isdir(cls_dir):
            continue

        for fname in os.listdir(cls_dir):
            if fname.lower().endswith((".pcap", ".pcapng")):
                fpath = os.path.join(cls_dir, fname)
                df_extracted = pipeline.batch_extract_pcap(fpath)
                df_extracted["threat_class"] = cls.value
                records.append(df_extracted)

    if not records:
        raise ValueError(
            f"No valid PCAP files found in subdirectories of {pcap_dir}. "
            f"Expected subdirectories for {list(ThreatClass.__members__.keys())}."
        )

    full_df = pd.concat(records, ignore_index=True)
    return full_df, "threat_class"


def train_model(
    data_path: Optional[str] = None,
    pcap_dir: Optional[str] = None,
    smoke_test: bool = False,
    output_path: str = DEFAULT_MODEL_PATH,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Core offline training entrypoint.
    
    STABLE FAIL-SAFE:
    Fails immediately if no real data is provided and smoke_test=False.
    """
    # ── Strict Fail-Safe Validation ───────────────────────────────────────────
    if not data_path and not pcap_dir and not smoke_test:
        error_msg = (
            "\n" + "=" * 78 + "\n"
            "[ERROR] Real training data source is missing!\n"
            "-" * 78 + "\n"
            "M3 requires labelled feature data generated from network traffic passed\n"
            "through M1 -> M2.\n\n"
            "Options:\n"
            "  1. Supply a labelled CSV of M2 features:\n"
            "     python -m m3.train --data <path/to/m2_labelled.csv>\n\n"
            "  2. Supply a directory of labelled PCAPs:\n"
            "     python -m m3.train --pcap-dir <path/to/pcap_dir>\n\n"
            "  3. Explicitly request an internal smoke-test with fallback synthetic data:\n"
            "     python -m m3.train --smoke-test\n"
            "=" * 78 + "\n"
        )
        raise RuntimeError(error_msg)

    # ── 1. Acquire Dataset ────────────────────────────────────────────────────
    if data_path:
        data_source = os.path.abspath(data_path)
        is_smoke_test = False
        print(f"[DATA] Loading real training data from CSV: {data_source}")
        df, target_col = load_labeled_csv(data_path)
    elif pcap_dir:
        data_source = os.path.abspath(pcap_dir)
        is_smoke_test = False
        print(f"[DATA] Extracting features from PCAP directory via M2: {data_source}")
        df, target_col = load_pcap_directory(pcap_dir)
    else:
        data_source = "FALLBACK_SYNTHETIC_SMOKE_TEST"
        is_smoke_test = True
        print("\n" + "!" * 78)
        print("[WARNING] Model is being trained on FALLBACK SYNTHETIC SMOKE-TEST data.")
        print("   This is strictly for testing M3 pipeline mechanics and unit test validation.")
        print("   Do NOT report these metrics as genuine real-world model accuracy.")
        print("!" * 78 + "\n")
        df = generate_fallback_smoke_dataset(seed=random_state)
        target_col = "threat_class"

    # ── 2. Feature Extraction & Alignment ─────────────────────────────────────
    print("[PREP] Extracting sanitized feature matrix (excluding identifiers)...")
    X = extract_features(df)
    y = df[target_col].astype(str)

    class_dist = {str(k): int(v) for k, v in y.value_counts().to_dict().items()}
    print(f"[DISTRIBUTION] Class distribution ({len(df)} total samples): {class_dist}")

    # Check minimum classes
    if len(class_dist) < 2:
        raise ValueError(f"Training requires at least 2 distinct classes. Found: {list(class_dist.keys())}")

    # ── 3. Train/Test Split ───────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=random_state,
        stratify=y,
    )

    # ── 4. Train RandomForest Classifier ──────────────────────────────────────
    print(f"[TRAIN] Training RandomForestClassifier on {len(X_train)} samples across {X.shape[1]} features...")
    clf = ThreatClassifier(n_estimators=50, max_depth=12, random_state=random_state)
    clf.fit(X_train, y_train)

    # ── 5. Evaluation ─────────────────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    accuracy = float(accuracy_score(y_test, y_pred))
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    report_text = classification_report(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_).tolist()

    print("\n" + "=" * 55)
    print("[EVALUATION] Model Evaluation Results:")
    print("=" * 55)
    print(f"Overall Accuracy: {accuracy * 100:.2f}%\n")
    print(report_text)
    print(f"Classes evaluated: {clf.classes_}")

    top_features = list(clf.get_feature_importances().items())[:8]
    print(f"\n[FEATURES] Top Driving Features: {top_features}")

    # ── 6. Save Artifact & Provenance Metadata ─────────────────────────────────
    metadata = {
        "training_data_source": data_source,
        "is_smoke_test": is_smoke_test,
        "samples_count": int(len(df)),
        "train_samples_count": int(len(X_train)),
        "test_samples_count": int(len(X_test)),
        "class_distribution": class_dist,
        "feature_count": int(len(clf.feature_names)),
        "feature_names": clf.feature_names,
        "evaluation_metrics": {
            "accuracy": round(accuracy, 4),
            "classification_report": report_dict,
            "confusion_matrix": cm,
            "evaluated_classes": clf.classes_,
        },
        "top_features": top_features,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    clf.save(output_path, metadata=metadata)
    meta_path = os.path.splitext(output_path)[0] + "_metadata.json"
    print(f"\n[SAVE] Model successfully saved to: {output_path}")
    print(f"[SAVE] Provenance metadata saved to: {meta_path}")

    return metadata


def main():
    parser = argparse.ArgumentParser(description="M3 Threat Classifier Offline Training Pipeline")
    parser.add_argument("--data", type=str, default=None, help="Path to labelled M2 feature CSV")
    parser.add_argument("--pcap-dir", type=str, default=None, help="Path to directory of labelled PCAPs")
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Explicitly permit training on synthetic fallback data for pipeline validation",
    )
    parser.add_argument(
        "--output-model",
        type=str,
        default=DEFAULT_MODEL_PATH,
        help="Destination path for serialized threat_detector.joblib",
    )

    args = parser.parse_args()

    try:
        train_model(
            data_path=args.data,
            pcap_dir=args.pcap_dir,
            smoke_test=args.smoke_test,
            output_path=args.output_model,
        )
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Training failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
