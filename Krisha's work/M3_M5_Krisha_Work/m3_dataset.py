"""Dataset preparation for the independent M3 classifier."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from ml.config.m3_config import SCHEMA_PATH, M3Config, load_m3_config
from ml.preprocessing.clean import clean_headers_and_strings, handle_missing_and_inf
from ml.training.loader import validate_and_extract_features


DATA_DIR = SCHEMA_PATH.parent.parent / "data"


class M3DatasetError(ValueError):
    """Raised when an M3 dataset cannot satisfy its preparation contract."""


@dataclass(frozen=True)
class M3DatasetSplit:
    features: pd.DataFrame
    labels: pd.Series


@dataclass(frozen=True)
class M3DatasetBundle:
    train: M3DatasetSplit
    validation: M3DatasetSplit
    test: M3DatasetSplit
    config: M3Config


def _prepare_split(path: Path, config: M3Config) -> M3DatasetSplit:
    if not path.exists():
        raise M3DatasetError(f"M3 dataset file not found: {path}")

    dataframe = pd.read_csv(path, low_memory=False)
    dataframe = clean_headers_and_strings(dataframe)

    required_columns = set(config.feature_names) | {config.target_column}
    missing_columns = sorted(required_columns - set(dataframe.columns))
    if missing_columns:
        raise M3DatasetError(
            f"{path.name}: missing required columns: {missing_columns}"
        )

    dataframe, _ = handle_missing_and_inf(dataframe)
    schema = {
        "ml_feature_names": list(config.feature_names),
        "target_column": config.target_column,
    }
    try:
        features, labels = validate_and_extract_features(dataframe, schema)
    except ValueError as error:
        raise M3DatasetError(f"{path.name}: schema validation failed: {error}") from error

    labels = labels.astype("string").str.strip().str.upper()
    selected = labels.isin(config.classes)
    if not selected.any():
        raise M3DatasetError(
            f"{path.name}: no rows contain the required M3 classes {config.classes}"
        )

    return M3DatasetSplit(
        features=features.loc[selected].reset_index(drop=True),
        labels=labels.loc[selected].reset_index(drop=True),
    )


def load_m3_datasets(
    data_dir: Path = DATA_DIR,
    schema_path: Path = SCHEMA_PATH,
) -> M3DatasetBundle:
    """Load and prepare the existing train, validation, and test splits."""
    config = load_m3_config(schema_path)
    return M3DatasetBundle(
        train=_prepare_split(data_dir / "train.csv", config),
        validation=_prepare_split(data_dir / "validation.csv", config),
        test=_prepare_split(data_dir / "test.csv", config),
        config=config,
    )


def load_m3_train_and_validation(
    data_dir: Path = DATA_DIR,
    schema_path: Path = SCHEMA_PATH,
) -> tuple[M3DatasetSplit, M3DatasetSplit, M3Config]:
    """Load only the official training and validation splits."""
    config = load_m3_config(schema_path)
    return (
        _prepare_split(data_dir / "train.csv", config),
        _prepare_split(data_dir / "validation.csv", config),
        config,
    )