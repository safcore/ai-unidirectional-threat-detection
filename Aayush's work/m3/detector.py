"""
Module 3 (M3) — Runtime Threat Detection Engine
================================================
Consumes 82-column DataFrames emitted by M2 in real-time or from file.
Extracts ML features, executes local RandomForest inference, assigns SOC severities,
gathers supporting diagnostic evidence, and emits structured ThreatAlerts.
"""

import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd
import logging

from .schema import ThreatClass, SeverityLevel, ThreatAlert
from .features import extract_features
from .model import ThreatClassifier

logger = logging.getLogger("m3.detector")

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "models", "threat_detector.joblib"
)


class ThreatDetector:
    """
    Streaming AI threat detector for M3.
    Consumes M2 82-column DataFrames, performs local inference, and outputs ThreatAlerts.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.classifier: Optional[ThreatClassifier] = None
        self._load_model()

    def _load_model(self) -> None:
        """Loads the pre-trained ThreatClassifier."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model file not found at '{self.model_path}'. "
                "Please run offline training first (python -m m3.train)."
            )
        self.classifier = ThreatClassifier.load(self.model_path)
        logger.info("ThreatDetector loaded model from %s", self.model_path)

    def predict(self, df: pd.DataFrame) -> List[ThreatAlert]:
        """
        Infers threats for each flow record in the M2 DataFrame.
        Returns a list of structured ThreatAlert objects.
        """
        if df is None or df.empty:
            return []

        if self.classifier is None:
            raise RuntimeError("ThreatClassifier is not loaded.")

        # 1. Extract sanitized ML features
        X = extract_features(df)

        # 2. Model inference
        prob_matrix = self.classifier.predict_proba(X)
        classes = self.classifier.classes_

        alerts: List[ThreatAlert] = []
        now_ts = datetime.now(timezone.utc).isoformat()

        for idx, (_, row) in enumerate(df.iterrows()):
            probs = prob_matrix[idx]
            best_idx = int(np.argmax(probs))
            threat_class = classes[best_idx]
            confidence = float(probs[best_idx])

            # Extract flow identifiers for alert context
            window_id = str(row.get("window_id", "w_unknown"))
            src_ip = str(row.get("src_ip", "0.0.0.0"))
            dst_ip = str(row.get("dst_ip", "0.0.0.0"))
            src_port = int(row.get("src_port", 0))
            dst_port = int(row.get("dst_port", 0))
            proto_name = str(row.get("protocol_name", row.get("protocol", "TCP"))).upper()

            flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto_name}"

            # 3. Severity & Evidence extraction
            severity, evidence = self._evaluate_severity_and_evidence(threat_class, confidence, row)

            alert = ThreatAlert(
                timestamp=now_ts,
                window_id=window_id,
                flow_id=flow_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_name,
                threat_class=threat_class,
                confidence=round(confidence, 4),
                severity=severity,
                evidence=evidence,
            )
            alerts.append(alert)

        return alerts

    def _evaluate_severity_and_evidence(
        self,
        threat_class: str,
        confidence: float,
        row: pd.Series,
    ) -> Tuple[str, Dict[str, Any]]:
        """Computes triage severity and extracts driving evidentiary metrics."""
        evidence: Dict[str, Any] = {}

        if threat_class == ThreatClass.SYN_FLOOD.value:
            severity = SeverityLevel.CRITICAL.value
            evidence = {
                "syn_flag_count": int(row.get("SYN Flag Count", 0)),
                "ack_flag_count": int(row.get("ACK Flag Count", 0)),
                "total_fwd_packets": int(row.get("Total Fwd Packets", 0)),
                "total_bwd_packets": int(row.get("Total Backward Packets", 0)),
                "flow_packets_per_sec": round(float(row.get("Flow Packets/s", 0.0)), 2),
                "down_up_ratio": round(float(row.get("Down/Up Ratio", 0.0)), 4),
                "tcp_flag_bitmask": int(row.get("tcp_flag_bitmask", 0)),
            }

        elif threat_class == ThreatClass.UDP_FLOOD.value:
            severity = SeverityLevel.HIGH.value
            evidence = {
                "protocol": int(row.get("protocol", 17)),
                "total_fwd_packets": int(row.get("Total Fwd Packets", 0)),
                "total_bwd_packets": int(row.get("Total Backward Packets", 0)),
                "flow_packets_per_sec": round(float(row.get("Flow Packets/s", 0.0)), 2),
                "down_up_ratio": round(float(row.get("Down/Up Ratio", 0.0)), 4),
                "packet_length_mean": round(float(row.get("Packet Length Mean", 0.0)), 2),
            }

        elif threat_class == ThreatClass.PORT_SCAN.value:
            seq_score = float(row.get("Port Sequentiality Score", 0.0))
            if confidence >= 0.9 and seq_score >= 0.8:
                severity = SeverityLevel.HIGH.value
            else:
                severity = SeverityLevel.MEDIUM.value

            evidence = {
                "port_sequentiality_score": round(seq_score, 4),
                "port_access_type": str(row.get("Port Access Type", "UNKNOWN")),
                "dst_port": int(row.get("dst_port", 0)),
                "total_fwd_packets": int(row.get("Total Fwd Packets", 0)),
                "total_bwd_packets": int(row.get("Total Backward Packets", 0)),
                "syn_flag_count": int(row.get("SYN Flag Count", 0)),
            }

        else:  # BENIGN
            severity = SeverityLevel.INFO.value
            evidence = {
                "flow_duration_us": round(float(row.get("Flow Duration", 0.0)), 2),
                "total_fwd_packets": int(row.get("Total Fwd Packets", 0)),
                "total_bwd_packets": int(row.get("Total Backward Packets", 0)),
                "down_up_ratio": round(float(row.get("Down/Up Ratio", 0.0)), 4),
            }

        return severity, evidence
