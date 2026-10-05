from __future__ import annotations

import pytest


def test_demo_rules_persist_allow_block_change_and_removal(client, admin_auth):
    path = "/api/admin/network/blocked-ips"
    status = client.get(path, headers=admin_auth)
    assert status.status_code == 200
    assert status.json()["mode"] == "simulation"

    payload = {
        "ip": "198.51.100.23",
        "reason": "College project demo",
        "confirm": True,
    }
    blocked = client.post(path, headers=admin_auth, json=payload)
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["policy"] == "deny"
    assert blocked.json()["changed"] is True
    assert blocked.json()["message"].startswith("Simulated")

    listed = client.get(path, headers=admin_auth).json()["items"]
    assert len([rule for rule in listed if rule["ip"] == payload["ip"]]) == 1
    assert next(rule for rule in listed if rule["ip"] == payload["ip"])["policy"] == "deny"

    allowed = client.post(
        "/api/admin/network/allowed-ips",
        headers=admin_auth,
        json=payload,
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["policy"] == "allow"

    listed = client.get(path, headers=admin_auth).json()["items"]
    assert next(rule for rule in listed if rule["ip"] == payload["ip"])["policy"] == "allow"

    removed = client.post(
        "/api/admin/network/allowed-ips/remove",
        headers=admin_auth,
        json=payload,
    )
    assert removed.status_code == 200, removed.text
    assert removed.json()["changed"] is True
    assert payload["ip"] not in {
        rule["ip"] for rule in client.get(path, headers=admin_auth).json()["items"]
    }


def test_demo_clear_removes_all_rules(client, admin_auth):
    for ip, route in (
        ("198.51.100.24", "/api/admin/network/blocked-ips"),
        ("198.51.100.25", "/api/admin/network/allowed-ips"),
    ):
        response = client.post(
            route,
            headers=admin_auth,
            json={"ip": ip, "reason": "Demo fixture", "confirm": True},
        )
        assert response.status_code == 200, response.text

    cleared = client.post(
        "/api/admin/network/blocked-ips/clear",
        headers=admin_auth,
        json={"reason": "Reset the project demonstration.", "confirm": True},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["removed"] >= 2
    assert client.get("/api/admin/network/blocked-ips", headers=admin_auth).json()["items"] == []


def test_demo_rules_need_admin_and_explicit_confirmation(client, auth, admin_auth):
    payload = {"ip": "198.51.100.26", "reason": "Demo fixture", "confirm": False}
    assert client.post(
        "/api/admin/network/blocked-ips",
        headers=admin_auth,
        json=payload,
    ).status_code == 428

    payload["confirm"] = True
    assert client.post(
        "/api/admin/network/blocked-ips",
        headers=auth,
        json=payload,
    ).status_code == 403


@pytest.mark.parametrize("ip", ["198.51.100.0/24", "not-an-ip", "::1"])
def test_demo_rules_accept_only_individual_ipv4(client, admin_auth, ip):
    response = client.post(
        "/api/admin/network/blocked-ips",
        headers=admin_auth,
        json={"ip": ip, "reason": "Demo fixture", "confirm": True},
    )
    assert response.status_code == 422
