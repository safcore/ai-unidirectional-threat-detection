"""
Unit tests for m3.train — Verifies fail-safe behavior and metadata provenance.
"""

import unittest
import os
import tempfile
import json

from m3.train import train_model


class TestTrainFailSafe(unittest.TestCase):
    """Verifies that M3 offline training adheres strictly to user fail-safe rules."""

    def test_fails_without_real_data_or_smoke_flag(self):
        """Must raise RuntimeError when no real data is provided and smoke_test is False."""
        with self.assertRaises(RuntimeError) as ctx:
            train_model(data_path=None, pcap_dir=None, smoke_test=False)
        self.assertIn("Real training data source is missing", str(ctx.exception))

    def test_smoke_test_metadata_provenance(self):
        """Smoke test training must produce valid model artifact and accurate metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_out = os.path.join(tmpdir, "test_model.joblib")
            meta_out = os.path.join(tmpdir, "test_model_metadata.json")

            metadata = train_model(smoke_test=True, output_path=model_out)

            # Check files exist
            self.assertTrue(os.path.exists(model_out))
            self.assertTrue(os.path.exists(meta_out))

            # Inspect written metadata
            with open(meta_out, "r") as f:
                saved_meta = json.load(f)

            self.assertTrue(saved_meta["is_smoke_test"])
            self.assertEqual(saved_meta["training_data_source"], "FALLBACK_SYNTHETIC_SMOKE_TEST")
            self.assertEqual(saved_meta["samples_count"], 500)
            self.assertIn("BENIGN", saved_meta["class_distribution"])
            self.assertIn("SYN_FLOOD", saved_meta["class_distribution"])
            self.assertIn("UDP_FLOOD", saved_meta["class_distribution"])
            self.assertIn("PORT_SCAN", saved_meta["class_distribution"])
            self.assertGreater(saved_meta["feature_count"], 50)
            self.assertIn("accuracy", saved_meta["evaluation_metrics"])


if __name__ == "__main__":
    unittest.main()
