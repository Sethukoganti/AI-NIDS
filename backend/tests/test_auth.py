"""Authentication, authorisation and password-handling tests."""

from __future__ import annotations

from app.core.config import settings


def test_login_returns_token_and_user(client, analyst_token):
    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@ainids.dev", "password": "Analyst@123"},
    )
    assert response.status_code == 200
    body = response.json()
    token = body["access_token"]
    assert token.count(".") == 2 and len(token) > 60      # a signed JWT
    assert token != "none"
    assert body["token_type"].lower() == "bearer"
    assert body["expires_in"] > 0
    assert body["user"]["email"] == "analyst@ainids.dev"
    assert body["user"]["role"] == "analyst"
    # the password hash must never leave the server
    assert "password_hash" not in response.text


def test_login_rejects_wrong_password(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@ainids.dev", "password": "definitely-wrong"},
    )
    assert response.status_code == 401
    assert "incorrect" in response.text.lower() or "invalid" in response.text.lower()


def test_login_rejects_unknown_email(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "nobody@ainids.dev", "password": "Analyst@123"},
    )
    assert response.status_code == 401


def test_protected_endpoint_requires_token(client):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/predictions").status_code == 401
    assert client.get("/api/alerts").status_code == 401


def test_garbage_token_is_rejected(client):
    response = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


def test_me_returns_current_user(client, auth):
    response = client.get("/api/auth/me", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "analyst@ainids.dev"
    assert body["role"] == "analyst"
    assert body["is_active"] is True


def test_analyst_cannot_list_users(client, auth):
    """Role separation: only admins manage accounts."""
    response = client.get("/api/auth/users", headers=auth)
    assert response.status_code == 403


def test_admin_can_list_users(client, admin_auth):
    response = client.get("/api/auth/users", headers=admin_auth)
    assert response.status_code == 200
    items = response.json()["items"]
    emails = {u["email"] for u in items}
    assert {"analyst@ainids.dev", "admin@ainids.dev"} <= emails


def test_created_user_cannot_be_created_with_weak_password(client, admin_auth):
    response = client.post(
        "/api/auth/users",
        headers=admin_auth,
        json={"name": "Weak", "email": "weak@ainids.dev", "password": "short", "role": "analyst"},
    )
    # 422 from the password policy, and it must serialise as clean JSON
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_error"
    assert any("password" in str(err.get("loc")) for err in body["errors"])


def test_admin_can_create_and_login_a_new_user(client, admin_auth):
    created = client.post(
        "/api/auth/users",
        headers=admin_auth,
        json={
            "name": "Pytest Analyst",
            "email": "pytest.analyst@ainids.dev",
            "password": "Str0ng-Passw0rd!",
            "role": "analyst",
        },
    )
    assert created.status_code in (200, 201), created.text
    assert "password_hash" not in created.text

    login = client.post(
        "/api/auth/login",
        json={"email": "pytest.analyst@ainids.dev", "password": "Str0ng-Passw0rd!"},
    )
    assert login.status_code == 200


def test_logout_invalidates_the_session_token(client, fresh_login):
    headers = fresh_login()
    assert client.get("/api/auth/me", headers=headers).status_code == 200

    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_auth_config_is_public_and_safe(client):
    response = client.get("/api/auth/config")
    assert response.status_code == 200
    body = response.json()
    assert body["password_min_length"] >= 8
    assert body["demo_accounts_enabled"] is False or isinstance(body["demo_accounts"], list)
    assert "jwt" not in response.text.lower()
    assert settings.JWT_SECRET not in response.text


def test_schema_upgrade_adds_user_columns_without_losing_accounts(tmp_path):
    from sqlalchemy import create_engine, inspect, text

    from app.db.session import _add_missing_columns

    legacy_engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with legacy_engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE users ("
            "id VARCHAR(36) PRIMARY KEY, name VARCHAR(120) NOT NULL, "
            "email VARCHAR(255) NOT NULL, password_hash VARCHAR(255) NOT NULL, "
            "role VARCHAR(20) NOT NULL, is_active BOOLEAN NOT NULL, "
            "last_login_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
        )
        connection.execute(
            text(
                "INSERT INTO users (id, name, email, password_hash, role, is_active, created_at, updated_at) "
                "VALUES ('legacy-id', 'Legacy Analyst', 'legacy@ainids.dev', 'preserved-hash', "
                "'analyst', 1, '2025-01-01', '2025-01-01')"
            )
        )

    _add_missing_columns(legacy_engine)

    with legacy_engine.connect() as connection:
        columns = {column["name"] for column in inspect(connection).get_columns("users")}
        account = connection.execute(
            text("SELECT email, password_hash, disabled_at, disabled_by, access_reset_at, notes FROM users")
        ).one()
    legacy_engine.dispose()

    assert {"disabled_at", "disabled_by", "access_reset_at", "notes"} <= columns
    assert account == ("legacy@ainids.dev", "preserved-hash", None, None, None, None)
