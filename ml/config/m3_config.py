"""Configuration for the independent M3 DDoS and PortScan classifier."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_PATH = BASE_DIR / "models" / "feature_schema.json"
MODEL_PATH = BASE_DIR / "models" / "m3_ddos_portscan_classifier.joblib"


@dataclass(frozen=True)
class M3Config:
    feature_schema_path: Path
    feature_names: tuple[str, ...]
    target_column: str
    model_path: Path
    classes: tuple[str, ...] = ("BENIGN", "DDOS", "PORT_SCAN")
    random_state: int = 42
    n_estimators: int = 100
    max_depth: int | None = 18
    class_weight: str = "balanced"
    n_jobs: int = -1


def load_m3_config(schema_path: Path = SCHEMA_PATH) -> M3Config:
    with schema_path.open("r", encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    feature_names = tuple(schema["ml_feature_names"])
    if schema.get("total_ml_features") != len(feature_names):
        raise ValueError("feature_schema.json feature count does not match ml_feature_names")

    return M3Config(
        feature_schema_path=schema_path,
        feature_names=feature_names,
        target_column=schema["target_column"],
        model_path=MODEL_PATH,
    )


_m3_config: M3Config | None = None


def get_m3_config() -> M3Config:
    global _m3_config
    if _m3_config is None:
        _m3_config = load_m3_config()
    return _m3_config
