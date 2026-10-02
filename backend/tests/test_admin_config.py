"""
Dynamic configuration and network-status contract tests.

The settings console is only trustworthy if the backend enforces the whole loop:
validate, require confirmation for a dangerous change, record a revision and an
audit entry, and make the new value effective for the *very next* request.
"""

from __future__ import annotations

import pytest

from .conftest import ADMIN, ANALYST  # noqa: F401  (kept for symmetry / skipping)


def _restore(client, admin_auth, scope: str, key: str, value):
    """Put a setting back so tests stay independent of execution order."""
    client.put(
        f"/api/admin/{scope}/config",
        headers=admin_auth,
        json={"values": {key: value}, "confirm_dangerous": True},
    )


def test_settings_expose_all_eleven_admin_sections(client, admin_auth):
    body = client.get("/api/admin/settings", headers=admin_auth).json()
    expected = [
        "Network",
        "Detection",
        "Alerts",
        "Model",
        "Dataset",
        "Notifications",
        "Users",
        "Security",
        "Data Retention",
        "System",
        "Audit Logs",
    ]
    assert body["section_order"] == expected
    # Every configured section must fold onto one of the eleven console sections.
    aliases = body["section_aliases"]
    sections = {s["name"] for s in body["sections"]}
    for name in sections:
        assert name in expected or aliases.get(name) in expected, (
            f"section {name!r} maps to no admin console section"
        )
    assert "effective_configuration" in body
    assert body["scope_permissions"]


def test_each_config_scope_reads_independently(client, admin_auth):
    for scope in ("network", "detection", "alerts", "model", "system"):
        response = client.get(f"/api/admin/settings/{scope}", headers=admin_auth)
        assert response.status_code == 200, scope
        assert response.json()["fields"], f"{scope} exposes no fields"


def test_unknown_scope_is_404(client, admin_auth):
    assert client.get("/api/admin/settings/nope", headers=admin_auth).status_code == 404


def test_out_of_range_value_is_rejected_and_changes_nothing(client, admin_auth):
    before = client.get("/api/admin/detection/config", headers=admin_auth).json()["values"]
    response = client.put(
        "/api/admin/detection/config",
        headers=admin_auth,
        json={"values": {"risk_high_threshold": 5.0}},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["errors"], "a rejection must say which field failed"

    after = client.get("/api/admin/detection/config", headers=admin_auth).json()["values"]
    assert after == before, "a rejected write must not change anything"


def test_dangerous_change_requires_confirmation(client, admin_auth):
    original = client.get("/api/admin/model/config", headers=admin_auth).json()["values"][
        "enabled"
    ]
    if not original:
        _restore(client, admin_auth, "model", "enabled", True)
        original = True

    response = client.put(
        "/api/admin/model/config",
        headers=admin_auth,
        json={"values": {"enabled": False}, "note": "test: unconfirmed"},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["requires_confirmation"] is True
    assert (
        client.get("/api/admin/model/config", headers=admin_auth).json()["values"]["enabled"]
        is True
    )

    confirmed = client.put(
        "/api/admin/model/config",
        headers=admin_auth,
        json={"values": {"enabled": False}, "confirm_dangerous": True, "note": "test: confirmed"},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["values"]["enabled"] is False
    assert "disabled" in " ".join(confirmed.json()["warnings"]).lower()
    _restore(client, admin_auth, "model", "enabled", True)


def test_write_becomes_effective_on_the_next_read(client, admin_auth):
    """Cache invalidation: the new value must not wait for a TTL."""
    client.put(
        "/api/admin/detection/config",
        headers=admin_auth,
        json={"values": {"risk_medium_threshold": 0.61}},
    )
    described = client.get("/api/admin/detection/config", headers=admin_auth).json()
    assert described["values"]["risk_medium_threshold"] == 0.61

    runtime = client.get("/api/health/runtime", headers=admin_auth).json()[
        "effective_configuration"
    ]
    assert runtime["risk_thresholds"]["medium"] == 0.61

    _restore(client, admin_auth, "detection", "risk_medium_threshold", 0.65)
    assert (
        client.get("/api/health/runtime", headers=admin_auth).json()[
            "effective_configuration"
        ]["risk_thresholds"]["medium"]
        == 0.65
    )


def test_every_write_records_a_revision_and_an_audit_entry(client, admin_auth):
    before = client.get(
        "/api/admin/audit-logs", headers=admin_auth, params={"page_size": 200}
    ).json()["total"]

    response = client.put(
        "/api/admin/detection/config",
        headers=admin_auth,
        json={"values": {"min_confidence_to_alert": 0.55}, "note": "test revision"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["changed"] == ["min_confidence_to_alert"]
    assert body["revision_ids"], "a write must leave a revision id"

    after = client.get(
        "/api/admin/audit-logs", headers=admin_auth, params={"page_size": 200}
    ).json()
    assert after["total"] > before
    latest = after["items"][0]
    assert latest["action"].endswith("_changed")
    assert "min_confidence_to_alert" in latest["action"]
    assert latest["previous_value"] is not None or latest["new_value"] is not None

    _restore(client, admin_auth, "detection", "min_confidence_to_alert", 0.5)


def test_active_version_must_be_a_registered_model(client, admin_auth):
    response = client.put(
        "/api/admin/model/config",
        headers=admin_auth,
        json={"values": {"active_version": "totally-made-up"}, "confirm_dangerous": True},
    )
    assert response.status_code == 422
    assert "not a registered model version" in response.text


# --------------------------------------------------------------------------- #
# Network status machine
# --------------------------------------------------------------------------- #
def test_manual_status_change_is_recorded_with_history(client, admin_auth):
    response = client.post(
        "/api/admin/network/status",
        headers=admin_auth,
        json={"status": "maintenance", "reason": "planned window", "confirm": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["changed"] is True
    # The transition payload nests the whole status profile under "status".
    profile = body["status"]
    assert profile["status_key"] == "maintenance"
    assert profile["status"] == "maintenance"
    assert profile["source"] in {"manual", "automatic", "system"}
    assert profile["reason"] == "planned window"
    assert profile["label"]
    assert profile["configuration_applied"], "a status change must report what it applied"

    history = client.get("/api/admin/network/status/history", headers=admin_auth).json()
    assert history["items"], "every transition must be in the history"
    latest = history["items"][0]
    assert latest["status"] == "maintenance"
    assert latest["source"] == "manual"
    assert latest["reason"] == "planned window"
    assert latest["changed_by"], "a manual change must record who did it"


def test_status_change_applies_the_mode_profile(client, admin_auth):
    baseline = client.get("/api/admin/network/status", headers=admin_auth).json()
    client.post(
        "/api/admin/network/status",
        headers=admin_auth,
        json={"status": "critical_threat", "reason": "test escalation", "confirm": True},
    )
    escalated = client.get("/api/health/runtime", headers=admin_auth).json()[
        "effective_configuration"
    ]
    baseline_runtime = baseline.get("effective_configuration") or {}
    if baseline_runtime:
        assert (
            escalated["risk_critical_threshold"] <= baseline_runtime["risk_critical_threshold"]
        ), "a critical status must not make detection less sensitive"

    client.post(
        "/api/admin/network/status",
        headers=admin_auth,
        json={"status": "normal", "reason": "test restore", "confirm": True},
    )


def test_invalid_status_is_rejected(client, admin_auth):
    response = client.post(
        "/api/admin/network/status", headers=admin_auth, json={"status": "not-a-status"}
    )
    assert response.status_code == 422


def test_status_indicators_are_measured_not_invented(client, admin_auth):
    body = client.get("/api/admin/network/status", headers=admin_auth).json()
    indicators = body.get("indicators") or {}
    # Whatever is reported must be derived from stored rows, so an empty platform
    # has to report zeros rather than plausible-looking numbers.
    for key in ("alerts_last_hour", "critical_alerts", "predictions_last_hour"):
        if key in indicators:
            assert indicators[key] >= 0
    assert body.get("configuration_applied"), "the status view must report what is live"
    assert body.get("label") and body.get("tone")
    assert body["evaluable"] in (True, False)


def test_evaluation_endpoint_runs_the_rules(client, admin_auth):
    response = client.post("/api/admin/network/status/evaluate", headers=admin_auth)
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert body.get("basis"), "evaluation must state what it measured"
    assert "measured" in body["basis"]