"""
Unit tests for m3.runner — Standalone runner and downstream alert handoff.
"""

import unittest
import os
import json
import tempfile
import pandas as pd

from m3.train import train_model
from m3.runner import run_m3_on_csv
from m3.fallback_data import generate_fallback_smoke_dataset


class TestM3Runner(unittest.TestCase):
    """Verifies end-to-end execution of runner.py."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.model_path = os.path.join(cls.temp_dir.name, "runner_test_model.joblib")
        train_model(smoke_test=True, output_path=cls.model_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_runner_on_sample_csv(self):
        """Runner must process input CSV, print output, and export latest_alert.json."""
        csv_path = os.path.join(self.temp_dir.name, "test_input.csv")
        alert_path = os.path.join(self.temp_dir.name, "latest_alert.json")

        df = generate_fallback_smoke_dataset(n_benign=1, n_syn_flood=1, n_udp_flood=0, n_port_scan=0)
        df.to_csv(csv_path, index=False)

        alerts = run_m3_on_csv(
            csv_path=csv_path,
            model_path=self.model_path,
            output_alert_path=alert_path,
        )

        self.assertEqual(len(alerts), 2)
        self.assertTrue(os.path.exists(alert_path))

        with open(alert_path, "r") as f:
            dispatched_alert = json.load(f)

        self.assertIn("threat_class", dispatched_alert)
        self.assertIn("severity", dispatched_alert)
        self.assertIn("confidence", dispatched_alert)
        self.assertIn("evidence", dispatched_alert)


if __name__ == "__main__":
    unittest.main()
