"""
ML contract tests: feature ordering, invalid-input rejection and determinism.

These exercise the *service* layer directly (no HTTP) because this is where the
"never run a different preprocessing pipeline at inference" rule is enforced.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from app.services.ml_service import model_service
from app.services.preprocessing_service import (
    DatasetError,
    load_schema,
    prepare_features,
    read_traffic_file,
)
from tests.conftest import SAMPLE_CSV


@pytest.fixture(scope="module")
def raw_frame() -> pd.DataFrame:
    return pd.read_csv(SAMPLE_CSV, nrows=60)


@pytest.fixture(scope="module")
def schema():
    return load_schema()


def test_prepared_matrix_uses_the_trained_feature_order(raw_frame, schema):
    prepared = prepare_features(raw_frame, schema)
    expected = model_service.feature_names()

    assert list(prepared.features.columns) == expected
    assert len(expected) == 70
    # the model itself must accept this matrix as-is
    result = model_service.predict(prepared.features)
    assert len(result["labels"]) == len(raw_frame)
    assert all(label in model_service.classes_ for label in result["labels"])


def test_columns_are_reordered_deterministically_not_randomly(raw_frame, schema):
    """Same rows, different column order in the file → identical feature matrix."""
    shuffled = raw_frame.sample(frac=1, axis=1, random_state=11)
    assert list(shuffled.columns) != list(raw_frame.columns)

    first = prepare_features(raw_frame, schema)
    second = prepare_features(shuffled, schema)

    assert list(first.features.columns) == list(second.features.columns)
    assert np.array_equal(first.features.to_numpy(), second.features.to_numpy())

    a = model_service.predict(first.features)
    b = model_service.predict(second.features)
    assert a["labels"] == b["labels"]
    assert np.allclose(a["confidences"], b["confidences"])


def test_model_refuses_to_predict_on_a_misordered_matrix(raw_frame, schema):
    prepared = prepare_features(raw_frame, schema)
    scrambled = prepared.features[list(reversed(prepared.features.columns))]

    with pytest.raises(ValueError, match="feature order"):
        model_service.predict(scrambled)


def test_probabilities_are_normalised(raw_frame, schema):
    prepared = prepare_features(raw_frame, schema)
    result = model_service.predict(prepared.features)

    matrix = np.asarray(result["probabilities"])
    assert matrix.shape == (len(raw_frame), len(result["classes"]))
    assert np.allclose(matrix.sum(axis=1), 1.0, atol=1e-4)
    confidence = np.asarray(result["confidences"])
    assert np.allclose(confidence, matrix.max(axis=1), atol=1e-6)
    assert ((confidence >= 0) & (confidence <= 1)).all()


def test_missing_features_are_rejected_with_a_structured_error():
    frame = pd.DataFrame({"port": [80, 443], "custom_metric": [1.5, 2.5]})
    with pytest.raises(DatasetError) as excinfo:
        prepare_features(frame, load_schema())

    error = excinfo.value
    assert error.status_code == 400
    assert "incompatible" in error.message.lower()
    assert error.detail["matched_features"] == 0
    assert error.detail["expected_features"] == 70
    assert error.detail["missing_features"]
    assert error.detail["hint"]


def test_low_feature_coverage_is_rejected(raw_frame, schema, feature_columns):
    """A file with only half of the expected columns must not be silently scored."""
    partial: pd.DataFrame = raw_frame[feature_columns[:30]].copy()
    with pytest.raises(DatasetError) as excinfo:
        prepare_features(partial, schema)
    assert "incompatible" in excinfo.value.message.lower()
    assert excinfo.value.detail["coverage"] < schema.min_feature_coverage


def test_extra_unknown_columns_are_ignored(raw_frame, schema):
    enriched = raw_frame.copy()
    enriched["vendor_custom_field"] = "x"
    prepared = prepare_features(enriched, schema)

    assert prepared.diagnostics["feature_coverage"] == 1.0
    assert "vendor_custom_field" in prepared.diagnostics["extra_columns_ignored"]
    assert len(prepared.features.columns) == 70


def test_infinite_values_are_cleaned_not_crashed(raw_frame, schema):
    """inf -> NaN -> the affected rows are dropped (same cleaning as training)."""
    broken = raw_frame.copy()
    column = broken.columns[0]
    broken[column] = broken[column].astype("float64")
    broken.loc[broken.index[:3], column] = np.inf

    prepared = prepare_features(broken, schema)
    assert prepared.diagnostics["infinite_values_replaced"] >= 3
    assert np.isfinite(prepared.features.to_numpy()).all()
    assert prepared.diagnostics["rows_dropped_missing_values"] >= 3

    result = model_service.predict(prepared.features)
    assert len(result["labels"]) == len(prepared.features) == len(broken) - 3


def test_non_flow_file_is_rejected(tmp_path):
    target = tmp_path / "notes.csv"
    target.write_text("subject,body\nhello,world\n")
    frame = read_traffic_file(target)
    with pytest.raises(DatasetError):
        prepare_features(frame, load_schema())


def test_ground_truth_is_extracted_but_never_used_as_a_feature(raw_frame, schema):
    prepared = prepare_features(raw_frame, schema)
    assert prepared.ground_truth and any(value for value in prepared.ground_truth)
    assert "Label" not in prepared.features.columns
    assert all("label" not in column.lower() for column in prepared.features.columns)
