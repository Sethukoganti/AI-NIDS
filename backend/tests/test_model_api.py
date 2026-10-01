"""The AI Model API: every number must come from the exported artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from app.core.config import settings

ML_DIR = Path(settings.MODEL_PATH).parent


def _artifact(name: str) -> dict:
    return json.loads((ML_DIR / name).read_text())


def test_model_info_reports_the_loaded_artifact(client, auth):
    response = client.get("/api/model/info", headers=auth)
    assert response.status_code == 200
    body = response.json()

    assert body["loaded"] is True, f"model failed to load: {body.get('load_error')}"
    assert body["algorithm"] == "Random Forest"
    assert body["n_estimators"] == 100
    assert len(body["classes"]) == 9
    assert "Normal Traffic" in body["classes"]
    assert body["n_features"] == 70
    assert body["normal_class"] == "Normal Traffic"


def test_reported_accuracy_equals_the_evaluation_artifact(client, auth):
    response = client.get("/api/model/info", headers=auth).json()
    evaluation = _artifact("evaluation.json")
    assert response["evaluation"]["accuracy"] == evaluation["accuracy"]
    assert response["evaluation"]["macro_f1"] == evaluation["macro_f1"]
    assert response["evaluation"]["n_test"] == evaluation["n_test"]
    assert 0.0 < response["evaluation"]["accuracy"] <= 1.0
    # never presented without its provenance
    assert response["evaluation"]["disclaimer"]


def test_feature_importances_sum_to_one_and_are_ordered(client, auth):
    response = client.get("/api/model/features?top=200", headers=auth)
    assert response.status_code == 200
    body = response.json()
    importances = body["importances"]

    assert len(importances) == 70
    values = [item["importance"] for item in importances]
    assert values == sorted(values, reverse=True)
    assert abs(sum(values) - 1.0) < 0.01  # real model.feature_importances_


def test_evaluation_exposes_per_class_report_and_confusion_matrix(client, auth):
    response = client.get("/api/model/evaluation", headers=auth)
    assert response.status_code == 200
    body = response.json()

    assert set(body["per_class"]) == set(_artifact("evaluation.json")["per_class"])
    labels = body["confusion_matrix"]["labels"]
    matrix = body["confusion_matrix"]["matrix"]
    assert len(labels) == len(matrix) == 9
    assert all(len(row) == 9 for row in matrix)
    assert sum(sum(row) for row in matrix) == body["n_test"]


def test_architecture_stages_carry_real_hyperparameters(client, auth):
    response = client.get("/api/model/architecture", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert len(body["stages"]) >= 8

    forest = next(stage for stage in body["stages"] if stage["id"] == "forest")
    assert forest["metrics"]["n_estimators"] == 100
    assert forest["metrics"]["min_samples_leaf"] == 2  # the documented size guard
    assert body["algorithm"] == "Random Forest"


def test_class_profiles_are_available(client, auth):
    response = client.get("/api/model/class-profiles", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert len(body["profiles"]) == 9
    assert len(body["features_ranked"]) >= 10
    profile = body["profiles"]["DDoS"]["features"]
    sample = next(iter(profile.values()))
    assert {"median", "mean", "p95", "max", "normal_median"} <= set(sample)


def test_health_reports_model_and_services(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["database"]["ok"] is True
    assert body["checks"]["model"]["ok"] is True
    assert body["model"]["test_accuracy"] > 0.9


def test_system_endpoint_is_admin_only(client, auth, admin_auth):
    assert client.get("/api/health/system", headers=auth).status_code == 403
    response = client.get("/api/health/system", headers=admin_auth)
    assert response.status_code == 200
    body = response.json()
    assert body["database"]["ok"] is True
    assert body["rate_limiter"]["enabled"] in (True, False)
    assert body["uploads"]["upload_dir"]
