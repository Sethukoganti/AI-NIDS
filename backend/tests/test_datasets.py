"""Upload validation, schema enforcement, dataset profiling and the explorer API."""

from __future__ import annotations

from tests.conftest import build_csv_bytes


def test_upload_accepts_a_cicids_compatible_csv(client, auth):
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("valid_flows.csv", build_csv_bytes(rows=30), "text/csv")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["rows"] == 30
    assert body["columns"] >= 70
    assert body["source"] == "upload"
    assert body["feature_coverage"] >= 0.8
    assert body["filename"] == "valid_flows.csv"


def test_upload_rejects_non_csv_extension(client, auth):
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("payload.exe", b"MZ\x90\x00not-a-csv", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "file format" in response.text.lower() or "csv" in response.text.lower()


def test_upload_rejects_empty_file(client, auth):
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("empty.csv", b"", "text/csv")},
    )
    assert response.status_code == 400


def test_upload_rejects_unparseable_csv(client, auth):
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("junk.csv", b"\x00\x01\x02\x03\x04binary-garbage", "text/csv")},
    )
    assert response.status_code == 400


def test_upload_rejects_incompatible_columns_and_explains_why(client, auth):
    """A file that is not network-flow data must fail loudly, with detail."""
    csv = b"name,age,city\nalice,30,hyderabad\nbob,41,delhi\n"
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("people.csv", csv, "text/csv")},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert detail["matched_features"] == 0
    assert detail["expected_features"] == 70
    assert isinstance(detail["missing_features"], list) and detail["missing_features"]
    assert "hint" in detail


def test_upload_accepts_reordered_columns(client, auth):
    """Column order in the file is irrelevant - the contract is by name."""
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("shuffled_columns.csv", build_csv_bytes(rows=25, shuffle_columns=True), "text/csv")},
    )
    assert response.status_code == 200, response.text
    assert response.json()["feature_coverage"] >= 0.8


def test_upload_accepts_a_file_with_missing_features_via_imputation(client, auth):
    """Up to 20% of the expected features may be absent - they are imputed, and reported."""
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("fewer_columns.csv", build_csv_bytes(rows=25, drop_leading=10), "text/csv")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    coverage = body["feature_coverage"]
    assert 0.8 <= coverage < 1.0


def test_list_datasets_includes_the_uploaded_one(client, auth, sample_dataset):
    response = client.get("/api/datasets", headers=auth)
    assert response.status_code == 200
    ids = {d["id"] for d in response.json()["items"]}
    assert sample_dataset["id"] in ids


def test_dataset_profile_and_paginated_rows(client, auth, sample_dataset):
    dataset_id = sample_dataset["id"]

    profile = client.get(f"/api/datasets/{dataset_id}", headers=auth)
    assert profile.status_code == 200
    body = profile.json()
    assert body["rows"] == 60
    assert len(body["columns_meta"]) >= 70
    assert isinstance(body["columns_meta"][0], dict)

    first = client.get(f"/api/datasets/{dataset_id}/rows?page=1&page_size=10", headers=auth)
    assert first.status_code == 200
    payload = first.json()
    assert len(payload["items"]) == 10
    assert payload["total"] == 60
    assert payload["pages"] == 6
    assert payload["page_size"] == 10

    second = client.get(f"/api/datasets/{dataset_id}/rows?page=2&page_size=10", headers=auth)
    assert second.json()["items"] != payload["items"]


def test_unknown_dataset_returns_404(client, auth):
    assert client.get("/api/datasets/does-not-exist", headers=auth).status_code == 404
    assert client.get("/api/datasets/does-not-exist/rows", headers=auth).status_code == 404


def test_reference_dataset_is_available(client, auth):
    response = client.get("/api/datasets/reference", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is True
    full = body["full_dataset"]
    assert full["rows"] > 2_000_000          # the real 2.83 M-row capture, not a mock
    assert full["columns"] >= 79
    assert body["training_table"]["rows"] == 217_731
    assert body["training_table"]["columns"] - 2 >= 70      # features + Label/Attack Type
    assert body["target_column"] == "Attack Type"
    assert len(body["model"]["classes"]) == 9
    assert body["model"]["algorithm"] == "Random Forest"


def test_sample_datasets_can_be_registered(client, auth):
    response = client.post(
        "/api/datasets/sample",
        headers=auth,
        json={"sample": "simulation_stream", "name": "pytest stream"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["rows"] == 800
    assert body["source"] == "sample"
    assert body["feature_coverage"] >= 0.8


def test_delete_requires_admin(client, auth, admin_auth):
    created = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("to_delete.csv", build_csv_bytes(rows=20), "text/csv")},
    )
    dataset_id = created.json()["id"]

    assert client.delete(f"/api/datasets/{dataset_id}", headers=auth).status_code == 403
    assert client.delete(f"/api/datasets/{dataset_id}", headers=admin_auth).status_code == 200
    assert client.get(f"/api/datasets/{dataset_id}", headers=auth).status_code == 404


def test_reference_dataset_rows_fall_back_to_the_bundled_sample(client, auth):
    """
    The full 2.83 M-row capture is not stored locally, so the explorer must serve the
    bundled held-out sample for it - and say so instead of failing with a 409.
    """
    datasets = client.get("/api/datasets", headers=auth).json()["items"]
    reference = next((d for d in datasets if d["source"] == "reference"), None)
    assert reference is not None, "the seeded reference dataset is missing"

    response = client.get(f"/api/datasets/{reference['id']}/rows?page=1&page_size=5", headers=auth)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert len(payload["items"]) == 5
    assert payload["source"] == "reference_sample"
    assert payload["note"] and "not stored locally" in payload["note"]
    assert payload["preview_truncated"] is True      # the statistics describe far more rows
