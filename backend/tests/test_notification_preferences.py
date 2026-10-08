"""Per-user in-app notification delivery preferences."""


DEFAULT_CATEGORIES = {"alert", "network", "model", "system", "user", "dataset"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def test_notification_preferences_persist_and_filter_the_feed(client, auth, admin_auth):
    analyst_default = client.get("/api/analyst/notification-preferences", headers=auth)
    assert analyst_default.status_code == 200
    assert set(analyst_default.json()["categories"]) == DEFAULT_CATEGORIES
    assert analyst_default.json()["minimum_severity"] == "info"

    updated = client.put(
        "/api/analyst/notification-preferences",
        headers=auth,
        json={"categories": ["alert", "system"], "minimum_severity": "high"},
    )
    assert updated.status_code == 200
    assert updated.json() == {"categories": ["alert", "system"], "minimum_severity": "high"}

    persisted = client.get("/api/analyst/notification-preferences", headers=auth)
    assert persisted.json() == updated.json()

    listing = client.get("/api/analyst/notifications?page_size=200", headers=auth)
    assert listing.status_code == 200
    assert all(item["category"] in {"alert", "system"} for item in listing.json()["items"])
    assert all(SEVERITY_RANK[item["severity"]] >= SEVERITY_RANK["high"] for item in listing.json()["items"])

    admin_default = client.get("/api/analyst/notification-preferences", headers=admin_auth)
    assert set(admin_default.json()["categories"]) == DEFAULT_CATEGORIES
    assert admin_default.json()["minimum_severity"] == "info"


def test_notification_preferences_reject_unknown_categories(client, auth):
    response = client.put(
        "/api/analyst/notification-preferences",
        headers=auth,
        json={"categories": ["alert", "external"], "minimum_severity": "high"},
    )
    assert response.status_code == 422
