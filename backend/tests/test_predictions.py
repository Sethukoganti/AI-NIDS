"""Analysis jobs, prediction browsing and per-record inspection."""

from __future__ import annotations

import pytest

ALLOWED_RISK = {"low", "medium", "high", "critical"}


def test_analysis_summary_is_complete(analysed_sample):
    summary = analysed_sample["summary"]
    job = analysed_sample["job"]

    assert job["status"] == "completed"
    assert job["progress"] == 100
    assert summary["total_records"] == 60
    assert summary["normal_records"] + summary["suspicious_records"] == summary["total_records"]
    assert set(summary["risk_distribution"]) <= ALLOWED_RISK
    assert summary["preprocessing"]["rows_in_file"] == 60
    assert summary["preprocessing"]["matched_features"] == summary["preprocessing"]["expected_features"]
    assert summary["model"]["algorithm"] == "Random Forest"


def test_analysis_compares_against_ground_truth_when_present(analysed_sample):
    ground_truth = analysed_sample["summary"].get("ground_truth")
    assert ground_truth is not None, "the sample file carries a Label column"
    assert ground_truth["labelled_rows"] == 60
    assert 0.0 <= ground_truth["match_rate"] <= 1.0
    binary = ground_truth["binary"]
    assert binary["precision"] >= 0.5 and binary["recall"] >= 0.5
    assert binary["true_positive"] + binary["false_negative"] >= 0


def test_job_detail_matches_creation(client, auth, analysed_sample):
    job_id = analysed_sample["job"]["id"]
    detail = client.get(f"/api/predictions/jobs/{job_id}", headers=auth)
    assert detail.status_code == 200
    assert detail.json()["id"] == job_id
    assert detail.json()["status"] == "completed"

    listing = client.get("/api/predictions/jobs?page_size=5", headers=auth)
    assert listing.status_code == 200
    assert any(item["id"] == job_id for item in listing.json()["items"])


def test_prediction_filters_are_applied_server_side(client, auth, analysed_sample):
    job_id = analysed_sample["job"]["id"]

    attacks = client.get(
        f"/api/predictions?job_id={job_id}&verdict=attack&page_size=100", headers=auth
    )
    assert attacks.status_code == 200
    assert all(item["is_attack"] for item in attacks.json()["items"])

    normal = client.get(f"/api/predictions?job_id={job_id}&verdict=normal&page_size=100", headers=auth)
    assert all(not item["is_attack"] for item in normal.json()["items"])

    high = client.get(f"/api/predictions?job_id={job_id}&risk_level=medium&page_size=100", headers=auth)
    assert all(item["risk_level"] in {"medium", "high", "critical"} for item in high.json()["items"])

    confident = client.get(f"/api/predictions?job_id={job_id}&min_confidence=0.99&page_size=100", headers=auth)
    assert all(item["confidence"] >= 0.99 for item in confident.json()["items"])


def test_prediction_sorting_and_pagination(client, auth, analysed_sample):
    job_id = analysed_sample["job"]["id"]
    response = client.get(
        f"/api/predictions?job_id={job_id}&sort_by=confidence&sort_dir=desc&page=1&page_size=10",
        headers=auth,
    )
    assert response.status_code == 200
    body = response.json()
    scores = [item["confidence"] for item in body["items"]]
    assert scores == sorted(scores, reverse=True)
    assert body["page"] == 1 and body["page_size"] == 10 and body["pages"] >= 1


def test_prediction_detail_explains_the_record(client, auth, analysed_sample):
    first = client.get(
        f"/api/predictions?job_id={analysed_sample['job']['id']}&page_size=1", headers=auth
    ).json()["items"][0]

    detail = client.get(f"/api/predictions/{first['id']}?with_shap=true", headers=auth)
    assert detail.status_code == 200
    body = detail.json()

    assert body["id"] == first["id"]
    assert body["features"], "the stored feature vector should be returned"
    assert isinstance(body["features"], dict) and body["features"]

    method = body.get("explanation_method")
    assert method in {"tree_shap", "global_feature_importance"}
    if method == "tree_shap":
        explanation = body["explanation"]
        assert explanation["method"] == "tree_shap"
        assert explanation["contributions"], "SHAP contributions must be present"
        contribution = explanation["contributions"][0]
        assert {"feature", "shap_value", "impact_pct"} <= set(contribution)
        assert 0 <= contribution["impact_pct"] <= 100
    else:  # the honest fallback must be labelled as such
        assert body.get("explanation_label")


def test_unknown_prediction_returns_404(client, auth):
    assert client.get("/api/predictions/does-not-exist", headers=auth).status_code == 404
    assert client.get("/api/predictions/does-not-exist/explain", headers=auth).status_code == 404


def test_ai_explanation_uses_real_evidence(client, auth, analysed_sample):
    first = client.get(
        f"/api/predictions?job_id={analysed_sample['job']['id']}&page_size=1", headers=auth
    ).json()["items"][0]

    response = client.get(f"/api/predictions/{first['id']}/explain?force_local=true", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert body["provider"] in {"local", "local-fallback"} or body["provider"]
    assert body["explanation"].strip()
    assert body["grounded_on"]


def test_simulate_persists_only_when_asked(client, auth):
    dry_run = client.post(
        "/api/predictions/simulate",
        json={"rows": 15, "sample": "simulation_stream", "persist": False},
        headers=auth,
    )
    assert dry_run.status_code == 200
    assert dry_run.json()["processed"] == 15

    persisted = client.post(
        "/api/predictions/simulate",
        json={"rows": 15, "sample": "simulation_stream", "persist": True},
        headers=auth,
    )
    assert persisted.status_code == 200
    assert persisted.json()["persisted"] is True
    assert persisted.json()["job"]["status"] == "completed"
