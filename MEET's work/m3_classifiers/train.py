"""
M3 — Model Training Script
============================
Generates synthetic training data and trains:
  1. Random Forest for DDoS detection
  2. (Port scan uses rule-based, no training needed)

Saves models to models/ directory.

Run:
    python -m m3_classifiers.train
"""

import os
import random
import pickle
import math
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

DDOS_FEATURES = [
    "syn_ratio", "ack_ratio", "rst_ratio", "pkt_count", "pkts_per_sec",
    "bytes_per_sec", "mean_pkt_size", "src_ip_entropy", "dst_pkt_rate",
    "mean_iat", "std_iat", "duration", "syn_no_ack",
]


def _rand_entropy(low, high):
    return random.uniform(low, high)


def generate_ddos_dataset(n_benign=3000, n_attack=3000):
    """Generate synthetic labeled feature vectors for DDoS training."""
    X, y = [], []

    # Benign traffic
    for _ in range(n_benign):
        row = [
            random.uniform(0.0, 0.15),   # syn_ratio
            random.uniform(0.3, 0.9),    # ack_ratio
            random.uniform(0.0, 0.05),   # rst_ratio
            random.randint(3, 200),       # pkt_count
            random.uniform(1, 150),      # pkts_per_sec
            random.uniform(100, 50000),  # bytes_per_sec
            random.uniform(200, 1400),   # mean_pkt_size
            random.uniform(0.0, 2.0),    # src_ip_entropy (low = few sources)
            random.uniform(1, 100),      # dst_pkt_rate
            random.uniform(0.001, 0.5),  # mean_iat
            random.uniform(0.0, 0.3),    # std_iat
            random.uniform(0.1, 300),    # duration
            0,                           # syn_no_ack
        ]
        X.append(row)
        y.append(0)  # benign

    # SYN Flood
    for _ in range(n_attack // 2):
        row = [
            random.uniform(0.85, 1.0),   # syn_ratio HIGH
            random.uniform(0.0, 0.1),    # ack_ratio LOW
            random.uniform(0.0, 0.05),   # rst_ratio
            random.randint(500, 10000),  # pkt_count HIGH
            random.uniform(500, 5000),   # pkts_per_sec HIGH
            random.uniform(5000, 50000), # bytes_per_sec
            random.uniform(0, 60),       # mean_pkt_size SMALL (no data)
            random.uniform(3.0, 5.0),    # src_ip_entropy HIGH (spoofed)
            random.uniform(500, 5000),   # dst_pkt_rate HIGH
            random.uniform(0.0001, 0.001),# mean_iat TINY
            random.uniform(0.0, 0.001),  # std_iat
            random.uniform(0.1, 30),     # duration
            1,                           # syn_no_ack
        ]
        X.append(row)
        y.append(1)  # attack

    # UDP Amplification
    for _ in range(n_attack // 2):
        row = [
            random.uniform(0.0, 0.05),   # syn_ratio LOW (UDP)
            random.uniform(0.0, 0.05),   # ack_ratio LOW (UDP)
            random.uniform(0.0, 0.02),   # rst_ratio
            random.randint(100, 5000),   # pkt_count
            random.uniform(200, 2000),   # pkts_per_sec
            random.uniform(200000, 1e7), # bytes_per_sec VERY HIGH
            random.uniform(500, 4096),   # mean_pkt_size LARGE (amplified)
            random.uniform(2.5, 4.5),    # src_ip_entropy
            random.uniform(200, 2000),   # dst_pkt_rate
            random.uniform(0.0001, 0.005),# mean_iat
            random.uniform(0.0, 0.01),   # std_iat
            random.uniform(0.1, 30),     # duration
            0,                           # syn_no_ack
        ]
        X.append(row)
        y.append(1)

    return X, y


def train_ddos_model():
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
    except ImportError:
        logger.error("scikit-learn not installed. Run: pip install scikit-learn")
        return

    logger.info("Generating DDoS training data...")
    X, y = generate_ddos_dataset(n_benign=4000, n_attack=4000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    logger.info("Training Random Forest (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["benign", "ddos"])
    logger.info("DDoS Model Performance:\n%s", report)

    # Feature importance
    importances = sorted(zip(DDOS_FEATURES, clf.feature_importances_), key=lambda x: -x[1])
    logger.info("Top features: %s", importances[:5])

    model_path = os.path.join(MODEL_DIR, "ddos_rf.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    logger.info("Saved DDoS model → %s", model_path)


if __name__ == "__main__":
    train_ddos_model()
    logger.info("Training complete. Model saved to models/")
