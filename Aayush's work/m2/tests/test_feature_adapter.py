"""
Unit tests for M2 Feature Adapter (m2/adapter.py)
"""

import unittest
import pandas as pd
import numpy as np

from m2.adapter import FeatureAdapter
from m2.schema import DETERMINISTIC_COLUMN_ORDER, SCHEMA_DTYPES


class TestFeatureAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = FeatureAdapter(replace_inf_nan=True)

    def test_empty_dataframe_has_deterministic_schema(self):
        """Empty input produces empty DataFrame with full deterministic columns and correct dtypes."""
        empty_df = self.adapter.adapt(pd.DataFrame(), window_id="w_test")
        self.assertTrue(empty_df.empty)
        self.assertEqual(list(empty_df.columns), DETERMINISTIC_COLUMN_ORDER)
        for col, expected_dtype in SCHEMA_DTYPES.items():
            actual_dtype = str(empty_df[col].dtype)
            self.assertIn(expected_dtype, actual_dtype)

    def test_direct_feature_mapping(self):
        """Direct 1:1 mapped features are properly renamed."""
        raw_df = pd.DataFrame([{
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": 6,
            "bidirectional_duration_ms": 100,
            "src2dst_packets": 10,
            "dst2src_packets": 5,
            "src2dst_bytes": 1000,
            "dst2src_bytes": 500,
            "bidirectional_syn_packets": 2,
            "bidirectional_ack_packets": 14,
            "src2dst_max_ps": 1460,
            "src2dst_min_ps": 40,
            "src2dst_mean_ps": 100.0,
            "src2dst_stddev_ps": 15.0,
        }])

        df = self.adapter.adapt(raw_df, window_id="w_0001")
        self.assertEqual(len(df), 1)
        self.assertEqual(df["window_id"].iloc[0], "w_0001")
        self.assertEqual(df["Total Fwd Packets"].iloc[0], 10)
        self.assertEqual(df["Total Backward Packets"].iloc[0], 5)
        self.assertEqual(df["Total Length of Fwd Packets"].iloc[0], 1000.0)
        self.assertEqual(df["Total Length of Bwd Packets"].iloc[0], 500.0)
        self.assertEqual(df["SYN Flag Count"].iloc[0], 2)
        self.assertEqual(df["ACK Flag Count"].iloc[0], 14)
        self.assertEqual(df["Fwd Packet Length Max"].iloc[0], 1460.0)
        self.assertEqual(df["Fwd Packet Length Min"].iloc[0], 40.0)
        self.assertEqual(df["protocol_name"].iloc[0], "TCP")

    def test_derived_features(self):
        """Derived features (Flow Duration, Variance, Rates, Down/Up Ratio) compute correctly."""
        raw_df = pd.DataFrame([{
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": 6,
            "bidirectional_duration_ms": 2000,  # 2 seconds
            "bidirectional_packets": 20,
            "bidirectional_bytes": 4000,
            "src2dst_packets": 10,
            "dst2src_packets": 10,
            "src2dst_bytes": 2000,
            "dst2src_bytes": 2000,
            "bidirectional_stddev_ps": 5.0,
            "bidirectional_mean_ps": 200.0,
            "bidirectional_mean_piat_ms": 100.0,
        }])

        df = self.adapter.adapt(raw_df, window_id="w_0002")
        # Duration: ms * 1000 -> µs
        self.assertAlmostEqual(df["Flow Duration"].iloc[0], 2_000_000.0)
        # Variance = stddev^2 = 25.0
        self.assertAlmostEqual(df["Packet Length Variance"].iloc[0], 25.0)
        # Rates = 4000 bytes / 2.0s = 2000.0 B/s; 20 pkts / 2.0s = 10.0 pkts/s
        self.assertAlmostEqual(df["Flow Bytes/s"].iloc[0], 2000.0)
        self.assertAlmostEqual(df["Flow Packets/s"].iloc[0], 10.0)
        # Down/Up Ratio = 10 / 10 = 1.0
        self.assertAlmostEqual(df["Down/Up Ratio"].iloc[0], 1.0)
        # Flow IAT Mean: 100 ms * 1000 = 100,000 µs
        self.assertAlmostEqual(df["Flow IAT Mean"].iloc[0], 100_000.0)

    def test_nan_and_infinite_handling(self):
        """NaN and inf values in raw input are sanitized to 0.0."""
        raw_df = pd.DataFrame([{
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 80,
            "dst_port": 80,
            "protocol": 6,
            "bidirectional_duration_ms": 0,  # Could trigger divide-by-zero
            "src2dst_packets": 0,
            "dst2src_packets": 0,
            "bidirectional_mean_piat_ms": np.nan,
            "bidirectional_stddev_piat_ms": np.inf,
        }])

        df = self.adapter.adapt(raw_df, window_id="w_sanitize")
        self.assertFalse(df.isna().any().any(), "DataFrame should not contain any NaN values")
        self.assertFalse(np.isinf(df["Flow Bytes/s"].iloc[0]), "Flow Bytes/s should not be inf")
        self.assertEqual(df["Flow IAT Mean"].iloc[0], 0.0)
        self.assertEqual(df["Flow IAT Std"].iloc[0], 0.0)

    def test_deterministic_column_order(self):
        """Output columns strictly follow DETERMINISTIC_COLUMN_ORDER."""
        raw_df = pd.DataFrame([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
        df = self.adapter.adapt(raw_df, window_id="w_cols")
        self.assertEqual(list(df.columns), DETERMINISTIC_COLUMN_ORDER)


if __name__ == "__main__":
    unittest.main()
