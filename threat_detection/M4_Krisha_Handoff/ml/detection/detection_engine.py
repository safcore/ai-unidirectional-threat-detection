"""
Main Detection Engine Orchestrator for Phase 3.

Integrates:
  1. Feature Schema Validation (feature_validator.py)
  2. Phase 2 ML Model Inference (ml/inference/predict.py)
  3. Decision Engine Logic (decision_engine.py)
  4. Alert Generator (alert_generator.py)

Produces normalized ISO-8601 Threat Events and Alerts.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
import pandas as pd

from ml.detection.feature_validator import validate_feature_schema
from ml.detection.decision_engine import DecisionEngine
from ml.detection.alert_generator import AlertGenerator
from ml.detection.standardized_alert import build_standardized_alert
from ml.inference.predict import predict
from ml.inference.m3_predict import M3Predictor

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Central real-time detection engine. Loaded once at application startup.
    """

    def __init__(self):
        logger.info("Initializing Phase 3 Detection Engine (loading models & decision rules)...")
        self.decision_engine = DecisionEngine()
        self.alert_generator = AlertGenerator()
        self.m3_predictor = M3Predictor()
        logger.info("Phase 3 Detection Engine initialized successfully.")

    def process(
        self, features: Union[Dict[str, Any], pd.DataFrame], metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Process incoming feature vector or DataFrame flow record.

        Returns normalized Threat Event dictionary.
        """
        try:
            # 1. Validate Feature Schema
            is_valid, validation_err, cleaned_features = validate_feature_schema(features)
            if not is_valid:
                logger.warning(f"Feature schema validation failed: {validation_err['error_type']}")
                return validation_err

            # Extract network metadata (src_ip, dst_ip, ports) if present in payload or metadata
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None

            if metadata:
                src_ip = metadata.get("src_ip") or metadata.get("Source IP")
                dst_ip = metadata.get("dst_ip") or metadata.get("Destination IP")
                src_port = metadata.get("src_port") or metadata.get("Source Port")
                dst_port = metadata.get("dst_port") or metadata.get("Destination Port")
            
            if isinstance(features, dict):
                src_ip = src_ip or features.get("src_ip") or features.get("Source IP")
                dst_ip = dst_ip or features.get("dst_ip") or features.get("Destination IP")
                src_port = src_port or features.get("src_port") or features.get("Source Port")
                dst_port = dst_port or features.get("dst_port") or features.get("Destination Port")

            # 2. Invoke Phase 2 ML Inference
            m4_inference_result = predict(cleaned_features)
            m3_inference_result = self.m3_predictor.predict(cleaned_features)
            inference_result = m4_inference_result
            if (
                m3_inference_result
                and m3_inference_result.get("threat_class") in {"DDOS", "PORT_SCAN"}
            ):
                inference_result = m3_inference_result

            # 3. Threat Decision Engine Evaluation
            decision_result = self.decision_engine.evaluate(inference_result)

            # 4. Alert Generation
            alert_obj = self.alert_generator.generate_alert(decision_result, metadata=metadata)

            # 5. Assemble Normalized Threat Event
            event_id = str(uuid.uuid4())
            timestamp_iso = datetime.now(timezone.utc).isoformat()

            event = {
                "status": "success",
                "event_id": event_id,
                "timestamp": timestamp_iso,
                "threat_class": decision_result.threat_class,
                "decision": decision_result.decision,
                "confidence": decision_result.confidence,
                "anomaly_score": decision_result.anomaly_score,
                "decision_reason": decision_result.reason,
                "probabilities": inference_result.get("probabilities", {}),
                "telemetry": cleaned_features,
                "classifications": {
                    "m3": m3_inference_result,
                    "m4": m4_inference_result,
                },
                "source": {
                    "src_ip": src_ip if src_ip else None,
                    "src_port": int(src_port) if src_port is not None and str(src_port).isdigit() else None,
                },
                "destination": {
                    "dst_ip": dst_ip if dst_ip else None,
                    "dst_port": int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None,
                },
                "model": {
                    "classifier": "RandomForest",
                    "model_version": "phase2",
                },
                "alert": alert_obj.to_dict(),
            }
            event["standardized_alert"] = build_standardized_alert(event)

            return event

        except Exception as e:
            logger.exception("Unexpected error in DetectionEngine.process()")
            return {
                "status": "error",
                "error_type": "INFERENCE_PROCESSING_EXCEPTION",
                "message": str(e),
            }


# Singleton instance
_engine_instance = None


def get_detection_engine() -> DetectionEngine:
    """Get singleton DetectionEngine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DetectionEngine()
    return _engine_instance
