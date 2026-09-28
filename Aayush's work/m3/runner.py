"""
Module 3 (M3) — Standalone Runner & Handoff Verification
========================================================
Proves the M2 -> M3 handoff by loading M2 output (e.g. m2_output_for_ai.csv),
executing ThreatDetector inference, reporting structured alerts, and writing
'latest_alert.json' for downstream M4/M5/M6 consumption.
"""

import os
import sys
import json
import argparse
import pandas as pd
from typing import Optional, List

from .schema import ThreatAlert
from .detector import ThreatDetector

DEFAULT_CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "m2_output_for_ai.csv")
ALERT_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "latest_alert.json")


def run_m3_on_csv(
    csv_path: str = DEFAULT_CSV_PATH,
    model_path: Optional[str] = None,
    output_alert_path: str = ALERT_OUTPUT_PATH,
) -> List[ThreatAlert]:
    """
    Executes M3 Threat Detection on a given M2 output CSV.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"M2 input CSV not found at: {csv_path}")

    print("=" * 70)
    print("Module 3 (M3) AI Threat Detector -- Runtime Handoff")
    print("=" * 70)
    print(f"[INPUT] Reading M2 Feature Extractor Output: {csv_path}")

    df = pd.read_csv(csv_path)
    print(f"[DATA] Loaded {len(df)} flow records with {len(df.columns)} columns.")

    detector = ThreatDetector(model_path=model_path)
    alerts = detector.predict(df)

    print(f"\n[INFERENCE] Inferred {len(alerts)} flows:")
    print("-" * 70)

    attack_alerts = []

    for idx, alert in enumerate(alerts, 1):
        alert_dict = alert.to_dict()
        print(f"Flow #{idx}: [{alert.severity}] {alert.threat_class} "
              f"(Confidence: {alert.confidence * 100:.1f}%) | {alert.flow_id}")
        print(f"   Window: {alert.window_id}")
        print(f"   Evidence: {json.dumps(alert.evidence, indent=6)}")

        if alert.threat_class != "BENIGN":
            attack_alerts.append(alert_dict)

    # Downstream handoff: write latest attack alert to latest_alert.json
    if attack_alerts:
        # Write the first/highest priority attack alert
        primary_alert = attack_alerts[0]
        with open(output_alert_path, "w", encoding="utf-8") as f:
            json.dump(primary_alert, f, indent=4)
        print("\n" + "=" * 70)
        print(f"[ALERT] THREAT IDENTIFIED: {primary_alert['threat_class']} [{primary_alert['severity']}]")
        print(f"[DISPATCH] Alert written to downstream sink: {output_alert_path}")
        print("=" * 70)
    else:
        print("\n[OK] All flows classified as BENIGN. No critical threat alerts dispatched.")

    return alerts


def main():
    parser = argparse.ArgumentParser(description="M3 Standalone Runner")
    parser.add_argument(
        "--csv",
        type=str,
        default=DEFAULT_CSV_PATH,
        help=f"Path to M2 output CSV (default: {DEFAULT_CSV_PATH})",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Path to trained threat_detector.joblib",
    )
    parser.add_argument(
        "--out-alert",
        type=str,
        default=ALERT_OUTPUT_PATH,
        help=f"Destination for latest_alert.json (default: {ALERT_OUTPUT_PATH})",
    )

    args = parser.parse_args()

    try:
        run_m3_on_csv(
            csv_path=args.csv,
            model_path=args.model,
            output_alert_path=args.out_alert,
        )
    except Exception as e:
        print(f"[ERROR] During M3 execution: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
