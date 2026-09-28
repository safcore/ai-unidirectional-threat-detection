"""
Unit tests for m3.detector — Streaming inference, alert schemas, severity, and evidence.
"""

import unittest
import os
import tempfile
import pandas as pd

from m3.schema import ThreatClass, SeverityLevel, ThreatAlert
from m3.train import train_model
from m3.detector import ThreatDetector
from m3.fallback_data import generate_fallback_smoke_dataset


class TestM3Detector(unittest.TestCase):
    """Verifies runtime inference contracts."""

    @classmethod
    def setUpClass(cls):
        """Train a temporary smoke model for testing detector functionality."""
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.model_path = os.path.join(cls.temp_dir.name, "test_threat_detector.joblib")
        train_model(smoke_test=True, output_path=cls.model_path)
        cls.detector = ThreatDetector(model_path=cls.model_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_predict_returns_valid_threat_alerts(self):
        """Inference should return ThreatAlert objects conforming to schema."""
        df = generate_fallback_smoke_dataset(n_benign=5, n_syn_flood=5, n_udp_flood=5, n_port_scan=5)
        alerts = self.detector.predict(df)

        self.assertEqual(len(alerts), len(df))
        for alert in alerts:
            self.assertIsInstance(alert, ThreatAlert)
            self.assertIn(alert.threat_class, [tc.value for tc in ThreatClass])
            self.assertIn(alert.severity, [s.value for s in SeverityLevel])
            self.assertGreaterEqual(alert.confidence, 0.0)
            self.assertLessEqual(alert.confidence, 1.0)
            self.assertTrue("+00:00" in alert.timestamp or alert.timestamp.endswith("Z"))
            self.assertIn("->", alert.flow_id)
            self.assertIsInstance(alert.evidence, dict)

    def test_syn_flood_critical_severity_and_evidence(self):
        """SYN flood alerts must be assigned CRITICAL severity with SYN-related evidence."""
        syn_df = generate_fallback_smoke_dataset(
            n_benign=0, n_syn_flood=1, n_udp_flood=0, n_port_scan=0, seed=123
        )

        alerts = self.detector.predict(syn_df)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]

        self.assertEqual(alert.threat_class, ThreatClass.SYN_FLOOD.value)
        self.assertEqual(alert.severity, SeverityLevel.CRITICAL.value)
        self.assertGreaterEqual(alert.evidence["syn_flag_count"], 50)
        self.assertEqual(alert.evidence["total_bwd_packets"], 0)

    def test_empty_dataframe_returns_empty_list(self):
        """Empty input must cleanly produce empty list without raising exceptions."""
        self.assertEqual(self.detector.predict(pd.DataFrame()), [])


if __name__ == "__main__":
    unittest.main()
