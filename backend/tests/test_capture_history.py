"""Authenticated ownership and persistence of live capture history."""


def test_capture_history_is_owned_and_flow_records_are_visible(client, auth, admin_auth, monkeypatch):
    from app.api import capture as capture_api

    monkeypatch.setattr(capture_api.capture_service, "is_active", lambda: False)
    monkeypatch.setattr(
        capture_api.capture_service,
        "start_capture",
        lambda iface=None: {"started": True, "interface": iface or "test0"},
    )
    monkeypatch.setattr(
        capture_api.capture_service,
        "status",
        lambda: {
            "agent_running": True,
            "interface": "test0",
            "packet_count": 11,
            "flow_count": 1,
            "queue_depth": 0,
            "error": None,
        },
    )

    started = client.post("/api/capture/start", headers=auth, json={"iface": "test0"})
    assert started.status_code == 200, started.text
    assert started.json()["started"] is True

    owner_listing = client.get("/api/capture/history", headers=auth)
    assert owner_listing.status_code == 200
    assert owner_listing.json()["total"] >= 1
    session_id = owner_listing.json()["items"][0]["id"]

    flow_index, suspicious_count = capture_api._persist_scored_flow(
        session_id,
        {
            "prediction": "Port Scan",
            "confidence": 0.91,
            "is_attack": True,
            "risk_level": "high",
            "risk_score": 0.83,
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_port": 41234,
            "destination_port": 22,
            "protocol": "TCP",
            "flow_duration": 12.5,
            "packet_rate": 4.0,
        },
    )
    assert (flow_index, suspicious_count) == (1, 1)

    detail = client.get(f"/api/capture/history/{session_id}", headers=auth)
    assert detail.status_code == 200
    assert detail.json()["id"] == session_id
    assert detail.json()["interface"] == "test0"
    assert detail.json()["flow_count"] == 1
    assert detail.json()["flows"][0]["prediction"] == "Port Scan"
    assert detail.json()["flows"][0]["source_ip"] == "192.0.2.10"

    unauthenticated = client.get("/api/capture/history")
    assert unauthenticated.status_code == 401

    not_owner = client.get(f"/api/capture/history/{session_id}", headers=admin_auth)
    assert not_owner.status_code == 404

    stopped = client.post("/api/capture/stop", headers=auth)
    assert stopped.status_code == 200
    assert stopped.json()["packet_count"] == 11
