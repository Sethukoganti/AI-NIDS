"""
RBAC contract tests.

These assert the *backend* is authoritative: a token that says ``analyst`` is
refused with ``403`` on every admin route, regardless of what the client asked
for, and a revoked permission takes effect on the very next request even though
the JWT itself is still valid and unexpired.
"""

from __future__ import annotations

import pytest

ADMIN_ROUTES = [
    ("GET", "/api/admin/settings"),
    ("GET", "/api/admin/settings/network"),
    ("GET", "/api/admin/users"),
    ("GET", "/api/admin/roles"),
    ("GET", "/api/admin/audit-logs"),
    ("GET", "/api/admin/system/health"),
    ("GET", "/api/admin/datasets"),
    ("GET", "/api/admin/network/config"),
    ("GET", "/api/admin/network/status"),
    ("GET", "/api/admin/network/status/history"),
    ("GET", "/api/admin/detection/config"),
    ("GET", "/api/admin/alerts/config"),
    ("GET", "/api/admin/model/config"),
    ("GET", "/api/admin/notifications"),
]

ANALYST_ROUTES = [
    ("GET", "/api/analyst/alerts"),
    ("GET", "/api/analyst/predictions"),
    ("GET", "/api/analyst/investigations"),
    ("GET", "/api/analyst/investigations/stats"),
]


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_analyst_is_forbidden_on_admin_routes(client, auth, method, path):
    response = client.request(method, path, headers=auth)
    assert response.status_code == 403, f"{path} returned {response.status_code}: {response.text[:200]}"


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_is_allowed_on_admin_routes(client, admin_auth, method, path):
    response = client.request(method, path, headers=admin_auth)
    assert response.status_code == 200, f"{path} returned {response.status_code}: {response.text[:300]}"


@pytest.mark.parametrize("method,path", ANALYST_ROUTES)
def test_analyst_reaches_analyst_routes(client, auth, method, path):
    response = client.request(method, path, headers=auth)
    assert response.status_code == 200, f"{path} returned {response.status_code}: {response.text[:300]}"


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_unauthenticated_gets_401_not_403(client, method, path):
    """No token is a different failure from a wrong role; do not leak 403 vs 401."""
    response = client.request(method, path)
    assert response.status_code == 401, f"{path} returned {response.status_code}"


def test_admin_route_with_a_forged_role_claim_is_still_forbidden(client, auth):
    """
    The JWT may carry whatever the client likes - role is re-read from the
    database on every request, so a token claiming ``admin`` cannot be produced
    without the server having signed it for a real admin.
    """
    from app.core.security import create_access_token

    analyst = client.get("/api/auth/me", headers=auth).json()
    assert analyst["role"] == "analyst"

    forged = create_access_token(
        subject=analyst["id"], role="admin", extra={"email": analyst["email"]}
    )
    response = client.get(
        "/api/admin/users", headers={"Authorization": f"Bearer {forged}"}
    )
    assert response.status_code == 403


def test_analyst_cannot_delete_a_dataset(client, auth, sample_dataset):
    """Dataset deletion is a destructive admin action, not part of the analyst flow."""
    response = client.delete(f"/api/datasets/{sample_dataset['id']}", headers=auth)
    assert response.status_code == 403


def test_analyst_cannot_write_global_configuration(client, auth):
    for scope in ("network", "detection", "alerts", "model"):
        response = client.put(
            f"/api/admin/{scope}/config", headers=auth, json={"values": {}}
        )
        assert response.status_code == 403, f"{scope}: {response.status_code}"


def test_analyst_cannot_change_network_status(client, auth):
    response = client.post(
        "/api/admin/network/status",
        headers=auth,
        json={"status": "maintenance", "reason": "analyst attempt"},
    )
    assert response.status_code == 403


def test_live_stream_requires_authentication(client):
    """The SSE endpoint used to have no dependency at all."""
    assert client.get("/api/live/stream").status_code == 401
    assert client.get("/api/live/samples").status_code == 401


def test_denied_access_is_audited(client, auth, admin_auth):
    client.get("/api/admin/users", headers=auth)
    response = client.get(
        "/api/admin/audit-logs",
        headers=admin_auth,
        params={"action": "access.denied", "page_size": 50},
    )
    assert response.status_code == 200
    entries = response.json()["items"]
    assert entries, "a denied admin request must leave an audit trail"
    latest = entries[0]
    assert latest["action"] == "access.denied"
    assert latest["result"] == "denied"
    assert latest["user_role"] == "analyst"
    assert latest["resource"] == "/api/admin/users"
    assert latest["detail"]["method"] == "GET"
    assert latest["detail"]["status_code"] == 403
    assert "users.manage" in latest["detail"]["permission"]


def test_role_change_takes_effect_on_the_next_request(client, admin_auth):
    """
    Revoking the analyst role on the account must invalidate an *already issued*
    token, because authorisation is resolved from the database per request.
    """
    from app.db.session import SessionLocal
    from app.models.database_models import User

    from .conftest import ANALYST

    login = client.post(
        "/api/auth/login", json={"email": ANALYST[0], "password": ANALYST[1]}
    )
    if login.status_code != 200:
        pytest.skip("demo analyst account not seeded")
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    session = SessionLocal()
    try:
        user = session.query(User).filter(User.email == ANALYST[0]).one()
        user.role = "viewer"
        session.commit()
        user_id = user.id
    finally:
        session.close()

    try:
        # The JWT is still valid and unexpired; the database says otherwise.
        denied = client.get("/api/analyst/alerts", headers=headers)
        assert denied.status_code == 403
    finally:
        session = SessionLocal()
        try:
            session.query(User).filter(User.id == user_id).one().role = "analyst"
            session.commit()
        finally:
            session.close()

    assert client.get("/api/analyst/alerts", headers=headers).status_code == 200


def test_disabled_account_cannot_use_an_existing_token(client, admin_auth):
    from app.db.session import SessionLocal
    from app.models.database_models import User

    from .conftest import ANALYST

    login = client.post(
        "/api/auth/login", json={"email": ANALYST[0], "password": ANALYST[1]}
    )
    if login.status_code != 200:
        pytest.skip("demo analyst account not seeded")
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    session = SessionLocal()
    try:
        session.query(User).filter(User.email == ANALYST[0]).one().is_active = False
        session.commit()
    finally:
        session.close()

    try:
        assert client.get("/api/analyst/alerts", headers=headers).status_code == 403
    finally:
        session = SessionLocal()
        try:
            session.query(User).filter(User.email == ANALYST[0]).one().is_active = True
            session.commit()
        finally:
            session.close()


def test_password_reset_invalidates_existing_sessions(client, admin_auth):
    """
    Resetting a password must end the sessions that were open with the old one,
    otherwise a stolen token outlives the credential the admin just rotated.
    """
    import time
    from datetime import datetime, timedelta, timezone

    from app.db.session import SessionLocal
    from app.models.database_models import User

    login = client.post(
        "/api/auth/login",
        json={"email": "reset-probe@ainids.dev", "password": "ResetMe123!"},
    )
    if login.status_code == 409:  # already created by an earlier run
        pytest.skip("probe account already exists")
    if login.status_code != 200:
        pytest.skip(f"probe account not seeded: {login.status_code}")
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.get("/api/analyst/alerts", headers=headers).status_code == 200

    session = SessionLocal()
    try:
        session.query(User).filter(User.email == "reset-probe@ainids.dev").one().access_reset_at = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        session.commit()
    finally:
        session.close()

    stale = client.get("/api/analyst/alerts", headers=headers)
    assert stale.status_code == 403
    assert "password reset" in stale.json()["detail"].lower()


def test_permissions_are_reported_and_role_scoped(client, auth, admin_auth):
    mine = client.get("/api/auth/me", headers=auth).json()
    assert mine["role"] == "analyst"
    granted = set(mine["permissions"])
    assert "traffic.analyze" in granted
    # An analyst must never hold an administration permission.
    assert granted.isdisjoint(
        {
            "users.manage",
            "roles.manage",
            "network.configure",
            "detection.configure",
            "alerts.configure",
            "model.configure",
            "settings.system",
            "audit.view",
            "datasets.delete",
        }
    )

    roles = client.get("/api/admin/roles", headers=admin_auth).json()["roles"]
    analyst_role = next(r for r in roles if r["name"] == "analyst")
    admin_role = next(r for r in roles if r["name"] == "admin")
    assert analyst_role["permissions"], "the analyst role must grant something"
    assert analyst_role["protected"], "an analyst keeps at least its core permissions"
    assert analyst_role["is_system"] is True
    assert admin_role["is_system"] is True
    assert set(admin_role["permissions"]).issuperset(
        set(analyst_role["permissions"])
    ), "admin must be a superset of analyst"