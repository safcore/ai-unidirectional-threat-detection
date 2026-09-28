"""
Unit tests for m3.features — Feature extraction, encoding, and sanitization.
"""

import unittest
import pandas as pd
import numpy as np

from m3.features import (
    extract_features,
    MODEL_FEATURE_NAMES,
    PORT_ACCESS_CATEGORIES,
    EXCLUDED_IDENTIFIERS,
)


class TestM3Features(unittest.TestCase):
    """Verifies feature extraction guarantees for M3."""

    def test_feature_names_exclude_identifiers(self):
        """Identifiers such as IPs and ports must NEVER appear in MODEL_FEATURE_NAMES."""
        for ident in EXCLUDED_IDENTIFIERS:
            self.assertNotIn(ident, MODEL_FEATURE_NAMES)

    def test_port_access_type_one_hot_encoding(self):
        """Port Access Type must be cleanly one-hot encoded into 3 binary columns."""
        df = pd.DataFrame([
            {"Port Access Type": "SINGLE", "protocol": 6},
            {"Port Access Type": "SEQUENTIAL", "protocol": 6},
            {"Port Access Type": "RANDOM", "protocol": 17},
            {"Port Access Type": "UNKNOWN_VAL", "protocol": 6},
        ])

        X = extract_features(df)
        self.assertIn("port_access_SINGLE", X.columns)
        self.assertIn("port_access_SEQUENTIAL", X.columns)
        self.assertIn("port_access_RANDOM", X.columns)

        # Row 0: SINGLE
        self.assertEqual(X.loc[0, "port_access_SINGLE"], 1.0)
        self.assertEqual(X.loc[0, "port_access_SEQUENTIAL"], 0.0)
        self.assertEqual(X.loc[0, "port_access_RANDOM"], 0.0)

        # Row 1: SEQUENTIAL
        self.assertEqual(X.loc[1, "port_access_SINGLE"], 0.0)
        self.assertEqual(X.loc[1, "port_access_SEQUENTIAL"], 1.0)
        self.assertEqual(X.loc[1, "port_access_RANDOM"], 0.0)

        # Row 2: RANDOM
        self.assertEqual(X.loc[2, "port_access_SINGLE"], 0.0)
        self.assertEqual(X.loc[2, "port_access_SEQUENTIAL"], 0.0)
        self.assertEqual(X.loc[2, "port_access_RANDOM"], 1.0)

        # Row 3: UNKNOWN -> all 0s
        self.assertEqual(X.loc[3, "port_access_SINGLE"], 0.0)
        self.assertEqual(X.loc[3, "port_access_SEQUENTIAL"], 0.0)
        self.assertEqual(X.loc[3, "port_access_RANDOM"], 0.0)

    def test_nan_and_inf_handling(self):
        """NaN and inf values in input must be safely replaced with 0.0."""
        df = pd.DataFrame([{
            "Flow Bytes/s": np.nan,
            "Flow Packets/s": np.inf,
            "Down/Up Ratio": -np.inf,
            "Total Fwd Packets": 10,
        }])

        X = extract_features(df)
        self.assertFalse(X.isna().any().any())
        self.assertFalse(np.isinf(X.values).any())
        self.assertEqual(X.loc[0, "Flow Bytes/s"], 0.0)
        self.assertEqual(X.loc[0, "Flow Packets/s"], 0.0)
        self.assertEqual(X.loc[0, "Down/Up Ratio"], 0.0)
        self.assertEqual(X.loc[0, "Total Fwd Packets"], 10.0)

    def test_empty_dataframe(self):
        """Empty input DataFrame should return empty DataFrame with exact feature columns."""
        df = pd.DataFrame()
        X = extract_features(df)
        self.assertEqual(list(X.columns), MODEL_FEATURE_NAMES)
        self.assertEqual(len(X), 0)


if __name__ == "__main__":
    unittest.main()
