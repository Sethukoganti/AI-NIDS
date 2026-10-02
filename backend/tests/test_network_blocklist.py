"""Admin-managed IP/CIDR analysis policies."""

from ipaddress import ip_network

import pytest

from app.db.session import SessionLocal
from app.models.database_models import Alert
from app.services.network_blocklist_service import matching_network, normalize_network


def test_ip_and_cidr_values_are_normalized():
    assert normalize_network("203.0.113.17") == "203.0.113.17/32"
    assert normalize_network("203.0.113.17/24") == "203.0.113.0/24"
    assert normalize_network("2001:db8::1") == "2001:db8::1/128"

    with pytest.raises(ValueError, match="valid IPv4/IPv6"):
        normalize_network("not-an-ip")
    with pytest.raises(ValueError, match="default route"):
        normalize_network("0.0.0.0/0")


def test_policy_matches_only_same_family_addresses_inside_network():
    rules = [("203.0.113.0/24", ip_network(normalize_network("203.0.113.0/24")))]
    assert matching_network("203.0.113.42", rules) == "203.0.113.0/24"
    assert matching_network("203.0.114.42", rules) is None
    assert matching_network("2001:db8::1", rules) is None
    assert matching_network("not-an-ip", rules) is None


def test_admin_can_add_release_and_list_policy(client, admin_auth, auth):
    response = client.post(
        "/api/admin/network/blocks",
        headers=admin_auth,
        json={"network": "198.51.100.9/24", "reason": "Repeated malicious scan"},
    )
    assert response.status_code == 200, response.text
    rule = response.json()["rule"]
    assert rule["network"] == "198.51.100.0/24"
    assert rule["active"] is True
    assert response.json()["enforcement"] == "analysis_label_only"

    listed = client.get("/api/admin/network/blocks", headers=admin_auth)
    assert listed.status_code == 200
    assert any(item["id"] == rule["id"] for item in listed.json()["items"])

    assert client.get("/api/admin/network/blocks", headers=auth).status_code == 403
    assert (
        client.post(
            "/api/admin/network/blocks",
            headers=auth,
            json={"network": "192.0.2.1", "reason": "Analyst cannot manage policy"},
        ).status_code
        == 403
    )

    duplicate = client.post(
        "/api/admin/network/blocks",
        headers=admin_auth,
        json={"network": "198.51.100.0/24", "reason": "Duplicate"},
    )
    assert duplicate.status_code == 409

    released = client.delete(f"/api/admin/network/blocks/{rule['id']}", headers=admin_auth)
    assert released.status_code == 200, released.text
    assert released.json()["rule"]["active"] is False
    assert released.json()["rule"]["released_at"]

    invalid = client.post(
        "/api/admin/network/blocks",
        headers=admin_auth,
        json={"network": "0.0.0.0/0", "reason": "Too broad"},
    )
    assert invalid.status_code == 422


def test_blocking_an_alert_resolves_it_and_labels_matching_alerts(client, admin_auth, auth):
    with SessionLocal() as db:
        alert = Alert(
            alert_type="Port scan detected",
            attack_type="Port Scan",
            severity="high",
            status="new",
            message="Test source address",
            confidence=0.99,
            risk_score=0.9,
            source_ip="203.0.113.19",
        )
        db.add(alert)
        db.commit()
        alert_id = alert.id

    response = client.post(
        "/api/admin/network/blocks",
        headers=admin_auth,
        json={
            "network": "203.0.113.0/24",
            "reason": "Confirmed hostile source",
            "alert_id": alert_id,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["alert"]["status"] == "resolved"
    assert body["rule"]["source_alert_id"] == alert_id

    listed = client.get("/api/alerts?status=all&page_size=200", headers=auth).json()
    matched = next(item for item in listed["items"] if item["id"] == alert_id)
    assert matched["blocklist_network"] == "203.0.113.0/24"

    released = client.delete(
        f"/api/admin/network/blocks/{body['rule']['id']}", headers=admin_auth
    )
    assert released.status_code == 200
    listed = client.get("/api/alerts?status=all&page_size=200", headers=auth).json()
    released_match = next(item for item in listed["items"] if item["id"] == alert_id)
    assert released_match["blocklist_network"] is None


def test_active_policy_is_recorded_on_subsequent_flow_analysis(client, admin_auth, auth):
    import pandas as pd
    from pathlib import Path

    sample_path = Path(__file__).resolve().parents[2] / "frontend" / "public" / "samples" / "sample_traffic.csv"
    frame = pd.read_csv(sample_path, nrows=20)
    frame["Source IP"] = "192.0.2.17"
    upload = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("blocklist_sample.csv", frame.to_csv(index=False).encode(), "text/csv")},
    )
    assert upload.status_code == 200, upload.text

    policy = client.post(
        "/api/admin/network/blocks",
        headers=admin_auth,
        json={"network": "192.0.2.0/24", "reason": "Test analysis policy"},
    )
    assert policy.status_code == 200, policy.text
    rule_id = policy.json()["rule"]["id"]

    analysis = client.post(
        "/api/predictions/analyze",
        headers=auth,
        json={"dataset_id": upload.json()["id"], "force_sync": True},
    )
    assert analysis.status_code == 200, analysis.text
    job_id = analysis.json()["job"]["id"]
    predictions = client.get(
        f"/api/predictions?job_id={job_id}&page_size=100", headers=auth
    )
    assert predictions.status_code == 200, predictions.text
    rows = predictions.json()["items"]
    assert rows
    assert all(row["source_ip"] == "192.0.2.17" for row in rows)
    assert all(row["blocklist_network"] == "192.0.2.0/24" for row in rows)

    release = client.delete(f"/api/admin/network/blocks/{rule_id}", headers=admin_auth)
    assert release.status_code == 200, release.text
