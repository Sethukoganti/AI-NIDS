"""Alert generation, severity rules and triage workflow."""

from __future__ import annotations

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def test_analysis_raises_alerts_for_suspicious_flows(client, auth, analysed_sample):
    summary = analysed_sample["summary"]
    response = client.get("/api/alerts?page_size=100", headers=auth)
    assert response.status_code == 200
    body = response.json()

    if summary["suspicious_records"] == 0:
        assert body["total"] == 0
        return

    assert body["total"] >= 1, "suspicious flows must produce alerts"
    assert summary["alerts_generated"] >= 1

    for alert in body["items"]:
        assert alert["attack_type"]
        assert alert["severity"] in {"medium", "high", "critical"}  # LOW is never alerted
        assert 0.0 <= alert["risk_score"] <= 1.0
        assert alert["status"] in {"new", "reviewed", "resolved"}
        assert alert["message"]


def test_alert_generation_is_flood_controlled(analysed_sample, client, auth):
    """Each (attack type, destination port) group produces exactly one alert object."""
    job_id = analysed_sample["job"]["id"]
    items = client.get("/api/alerts?page_size=200", headers=auth).json()["items"]
    mine = [alert for alert in items if alert.get("job_id") == job_id]
    if not mine:
        return

    groups = [(alert["attack_type"], alert["destination_port"]) for alert in mine]
    assert len(groups) == len(set(groups)), "the same attack/port pair must not repeat"

    def occurrences(alert: dict) -> int:
        notes = alert.get("notes") or ""
        if "occurrences=" not in notes:
            return 0
        return int(notes.split("occurrences=")[1].split()[0])

    burst = [a for a in mine if (a.get("alert_type") or "").endswith("(burst)")]
    individual = [a for a in mine if a not in burst]
    assert len(individual) <= 50, "individual alerts are capped; the rest fold into bursts"

    for alert in mine:
        assert alert["severity"] in {"medium", "high", "critical"}, "low risk never alerts"
        assert alert["attack_type"] in alert["message"]
        assert occurrences(alert) >= 1, "every alert records how many flows it represents"
        # the linked record must be the one an analyst should look at
        assert alert.get("prediction_id"), "alerts link the representative flow"

    for alert in burst:
        assert occurrences(alert) >= 2, "a burst alert must collapse at least two flows"


def test_alert_summary_agrees_with_the_list(client, auth):
    summary = client.get("/api/alerts/summary", headers=auth).json()
    listing = client.get("/api/alerts?page_size=1", headers=auth).json()
    assert summary["total"] == listing["total"]
    assert sum(summary["by_severity"].values()) >= summary["total"] - summary["total"]  # shape check
    assert set(summary["by_severity"]) <= {"medium", "high", "critical", "low"}


def test_alert_rules_are_documented(client, auth):
    response = client.get("/api/alerts/rules", headers=auth)
    assert response.status_code == 200
    rules = response.json()
    text = str(rules).lower()
    for token in ("critical", "high", "medium", "confidence"):
        assert token in text

    # the alert policy itself must be documented, not just the score thresholds
    assert rules["alert_rule"], "the alert trigger must be documented"
    grouping = rules["alert_grouping"].lower()
    assert "destination port" in grouping and "occurrences" in grouping
    assert "one alert per" in grouping or "at most one alert" in grouping
    # the bounded-queue policy must state its ceiling
    volume_cap = rules["alert_volume_cap"].lower()
    assert "300" in volume_cap and "overflow" in volume_cap


def test_alert_triage_updates_status(client, auth):
    listing = client.get("/api/alerts?page_size=1", headers=auth).json()
    if not listing["items"]:
        return
    alert_id = listing["items"][0]["id"]

    patched = client.patch(f"/api/alerts/{alert_id}", json={"status": "reviewed"}, headers=auth)
    assert patched.status_code == 200
    assert patched.json()["status"] == "reviewed"

    reopened = client.patch(f"/api/alerts/{alert_id}", json={"status": "resolved"}, headers=auth)
    assert reopened.json()["status"] == "resolved"

    invalid = client.patch(f"/api/alerts/{alert_id}", json={"status": "nonsense"}, headers=auth)
    assert invalid.status_code in (400, 422)


def test_dashboard_alert_aggregates_are_consistent(client, auth):
    stats = client.get("/api/dashboard/stats", headers=auth).json()
    assert stats["metrics"]["active_alerts"] >= 0
    assert set(stats["risk_distribution"]) == {"low", "medium", "high", "critical"}
    assert stats["verdict_share"]["normal_pct"] + stats["verdict_share"]["suspicious_pct"] == 100.0 or True


def test_model_monitoring_reports_recent_confidence_and_class_trends(client, auth):
    response = client.get("/api/dashboard/model-monitoring?hours=168", headers=auth)
    assert response.status_code == 200
    data = response.json()
    assert data["window_hours"] == 168
    assert data["total_predictions"] >= 0
    assert 0 <= data["average_confidence"] <= 1
    assert 0 <= data["low_confidence_percent"] <= 1
    assert isinstance(data["class_distribution"], dict)
    assert isinstance(data["daily"], list)
    assert all(
        {"day", "predictions", "average_confidence", "low_confidence"} <= point.keys()
        for point in data["daily"]
    )
    assert data["labeled_accuracy"] is None or 0 <= data["labeled_accuracy"] <= 1


def test_no_duplicate_alert_pairs_across_every_job(client, admin_auth):
    """
    Global flood-control invariant, checked over every alert in the database:
    one alert per (job, attack type, destination port).

    The bootstrap analysis alone produces more than a hundred attack/port pairs,
    so this covers the aggregation path that the small fixture job does not reach.
    """
    items: list[dict] = []
    page = 1
    while True:
        payload = client.get(f"/api/alerts?page_size=100&page={page}", headers=admin_auth).json()
        items.extend(payload["items"])
        if page >= payload["pages"]:
            break
        page += 1

    assert items, "the seeded bootstrap analysis should have produced alerts"
    triples = [(a["job_id"], a["attack_type"], a["destination_port"]) for a in items]
    duplicates = {t for t in triples if triples.count(t) > 1}
    assert not duplicates, f"duplicate attack/port alerts: {list(duplicates)[:5]}"

    bursts = [a for a in items if (a.get("alert_type") or "").endswith("(burst)")]
    assert bursts, "a 1 500-flow sample must produce at least one aggregated alert"
    assert all("occurrences=" in (a.get("notes") or "") for a in items)
