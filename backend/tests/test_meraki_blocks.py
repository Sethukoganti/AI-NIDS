from __future__ import annotations

import copy

import pytest

from app.services import meraki_service


class FakeResponse:
    def __init__(self, payload=None):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return copy.deepcopy(self.payload)


class FakeMerakiClient:
    def __init__(self, policy):
        self.policy = copy.deepcopy(policy)
        self.updates = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, _path):
        return FakeResponse(self.policy)

    def put(self, _path, *, json):
        self.updates.append(copy.deepcopy(json))
        self.policy.update(copy.deepcopy(json))
        return FakeResponse({})


def test_block_prepends_exact_host_rule_and_preserves_existing_policy(monkeypatch):
    existing_rule = {
        "comment": "Existing staff access",
        "policy": "allow",
        "protocol": "tcp",
        "srcPort": "Any",
        "srcCidr": "Any",
        "destPort": "443",
        "destCidr": "10.0.0.0/8",
    }
    client = FakeMerakiClient(
        {"rules": [existing_rule], "syslogDefaultRule": True}
    )
    monkeypatch.setattr(meraki_service, "_client", lambda: client)

    result = meraki_service.block_ip("198.51.100.23")

    assert result == {"ip": "198.51.100.23", "changed": True}
    payload = client.updates[0]
    assert payload["rules"][0] == {
        "comment": f"{meraki_service.MANAGED_COMMENT_PREFIX}198.51.100.23",
        "policy": "deny",
        "protocol": "any",
        "srcPort": "Any",
        "srcCidr": "198.51.100.23/32",
        "destPort": "Any",
        "destCidr": "Any",
    }
    assert payload["rules"][1] == existing_rule
    assert payload["syslogDefaultRule"] is True


def test_unblock_and_clear_preserve_unmanaged_firewall_rules(monkeypatch):
    managed_one = {
        "comment": f"{meraki_service.MANAGED_COMMENT_PREFIX}198.51.100.23",
        "policy": "deny",
    }
    managed_two = {
        "comment": f"{meraki_service.MANAGED_COMMENT_PREFIX}203.0.113.8",
        "policy": "deny",
    }
    operator_rule = {"comment": "Operator deny", "policy": "deny", "srcCidr": "192.0.2.0/24"}
    client = FakeMerakiClient({"rules": [managed_one, operator_rule, managed_two]})
    monkeypatch.setattr(meraki_service, "_client", lambda: client)

    assert meraki_service.unblock_ip("198.51.100.23") == {
        "ip": "198.51.100.23",
        "changed": True,
    }
    assert client.policy["rules"] == [operator_rule, managed_two]
    assert meraki_service.clear_managed_blocks() == {"removed": 1}
    assert client.policy["rules"] == [operator_rule]


def test_blocking_is_idempotent(monkeypatch):
    rule = {
        "comment": f"{meraki_service.MANAGED_COMMENT_PREFIX}198.51.100.23",
        "policy": "deny",
    }
    client = FakeMerakiClient({"rules": [rule]})
    monkeypatch.setattr(meraki_service, "_client", lambda: client)

    assert meraki_service.block_ip("198.51.100.23") == {
        "ip": "198.51.100.23",
        "changed": False,
    }
    assert client.updates == []


def test_admin_confirmation_and_role_are_required(client, admin_auth, auth, monkeypatch):
    monkeypatch.setattr(meraki_service, "is_configured", lambda: True)
    monkeypatch.setattr(
        meraki_service,
        "block_ip",
        lambda _ip: pytest.fail("must not change the firewall without confirmation"),
    )
    body = {"ip": "198.51.100.23", "reason": "Confirmed intrusion", "confirm": False}

    assert client.post("/api/admin/network/blocked-ips", headers=admin_auth, json=body).status_code == 428
    body["confirm"] = True
    assert client.post("/api/admin/network/blocked-ips", headers=auth, json=body).status_code == 403


def test_admin_block_route_records_confirmed_change(client, admin_auth, monkeypatch):
    monkeypatch.setattr(meraki_service, "is_configured", lambda: True)
    monkeypatch.setattr(
        meraki_service,
        "block_ip",
        lambda ip: {"ip": ip, "changed": True},
    )

    response = client.post(
        "/api/admin/network/blocked-ips",
        headers=admin_auth,
        json={"ip": "198.51.100.23", "reason": "Verified malicious source", "confirm": True},
    )

    assert response.status_code == 200, response.text
    assert response.json()["changed"] is True


@pytest.mark.parametrize("ip", ["198.51.100.0/24", "not-an-ip", "::1"])
def test_block_endpoint_rejects_ranges_and_non_ipv4(client, admin_auth, ip):
    response = client.post(
        "/api/admin/network/blocked-ips",
        headers=admin_auth,
        json={"ip": ip, "reason": "Verified malicious source", "confirm": True},
    )
    assert response.status_code == 422
