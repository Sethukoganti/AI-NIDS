"""User-uploaded datasets can be analyzed in Attack Simulation."""


def test_live_simulation_streams_an_owned_uploaded_dataset(client, auth, sample_dataset):
    response = client.get(
        "/api/live/stream",
        headers=auth,
        params={"rows": 2, "dataset_id": sample_dataset["id"]},
    )

    assert response.status_code == 200, response.text
    assert response.text.count("event: flow") == 2
    assert "pytest_sample.csv" in response.text


def test_live_simulation_hides_another_users_dataset(client, admin_auth, sample_dataset):
    response = client.get(
        "/api/live/stream",
        headers=admin_auth,
        params={"rows": 2, "dataset_id": sample_dataset["id"]},
    )

    assert response.status_code == 404
