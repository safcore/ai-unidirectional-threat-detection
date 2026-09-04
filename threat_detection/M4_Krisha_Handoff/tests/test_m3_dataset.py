import json

import pandas as pd
import pytest

from ml.config.m3_config import SCHEMA_PATH
from ml.training.m3_dataset import M3DatasetError, load_m3_datasets


def _write_schema(path):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    path.write_text(json.dumps(schema), encoding="utf-8")
    return schema


def _write_splits(directory, schema, rows):
    columns = list(reversed(schema["ml_feature_names"])) + ["target"]
    dataframe = pd.DataFrame(rows, columns=columns)
    for split in ("train", "validation", "test"):
        dataframe.to_csv(directory / f"{split}.csv", index=False)


def test_load_m3_datasets_selects_canonical_features_and_preserves_order(tmp_path):
    schema = _write_schema(tmp_path / "feature_schema.json")
    values = [float(index) for index in range(len(schema["ml_feature_names"]))]
    reversed_columns = list(reversed(schema["ml_feature_names"]))
    reversed_values = [values[schema["ml_feature_names"].index(column)] for column in reversed_columns]
    rows = [reversed_values + ["BENIGN"], reversed_values + ["DDOS"], reversed_values + ["DOS"], reversed_values + ["PORT_SCAN"]]
    _write_splits(tmp_path, schema, rows)

    datasets = load_m3_datasets(data_dir=tmp_path, schema_path=tmp_path / "feature_schema.json")

    assert list(datasets.train.features.columns) == schema["ml_feature_names"]
    assert datasets.train.labels.tolist() == ["BENIGN", "DDOS", "PORT_SCAN"]
    assert datasets.validation.labels.tolist() == datasets.train.labels.tolist()
    assert datasets.test.labels.tolist() == datasets.train.labels.tolist()
    assert datasets.train.features.iloc[0].tolist() == values


def test_non_finite_values_use_existing_cleaning_behavior(tmp_path):
    schema = _write_schema(tmp_path / "feature_schema.json")
    values = [1.0] * len(schema["ml_feature_names"])
    rows = [values + ["BENIGN"] for _ in range(200)]
    rows[0][schema["ml_feature_names"].index("Flow Duration")] = float("inf")
    _write_splits(tmp_path, schema, rows)

    datasets = load_m3_datasets(data_dir=tmp_path, schema_path=tmp_path / "feature_schema.json")

    assert len(datasets.train.features) == 200
    assert not datasets.train.features.isna().any().any()
    assert not datasets.train.features.map(lambda value: value in (float("inf"), float("-inf"))).any().any()


def test_missing_required_feature_has_clear_error(tmp_path):
    schema = _write_schema(tmp_path / "feature_schema.json")
    columns = schema["ml_feature_names"][:-1] + ["target"]
    dataframe = pd.DataFrame([[1.0] * len(schema["ml_feature_names"])], columns=columns)
    for split in ("train", "validation", "test"):
        dataframe.to_csv(tmp_path / f"{split}.csv", index=False)

    with pytest.raises(M3DatasetError, match="missing required columns.*Idle Min"):
        load_m3_datasets(data_dir=tmp_path, schema_path=tmp_path / "feature_schema.json")