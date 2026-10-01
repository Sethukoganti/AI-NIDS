"""Rate limiting, security headers, request logging and the upload guard."""

from __future__ import annotations

from app.middleware.rate_limit_middleware import SlidingWindowLimiter, parse_limit


def test_parse_limit_supports_the_configured_grammar():
    assert parse_limit("10/minute") == (10, 60)
    assert parse_limit("30/minute") == (30, 60)
    assert parse_limit("2/second") == (2, 1)
    assert parse_limit("5/hour") == (5, 3600)


def test_limiter_blocks_once_the_window_is_exhausted():
    limiter = SlidingWindowLimiter()
    allowed, remaining, retry_after = limiter.check("client-a", limit=3, window=60)
    assert allowed is True and remaining == 2 and retry_after == 0

    limiter.check("client-a", limit=3, window=60)
    allowed, remaining, _ = limiter.check("client-a", limit=3, window=60)
    assert allowed is True and remaining == 0

    allowed, remaining, retry_after = limiter.check("client-a", limit=3, window=60)
    assert allowed is False
    assert remaining == 0
    assert retry_after >= 1

    # a different client is unaffected
    assert limiter.check("client-b", limit=3, window=60)[0] is True


def test_health_route_is_public_and_carries_instrumentation_headers(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID")
    assert response.headers.get("X-Process-Time-Ms")


def test_security_headers_are_present(client):
    headers = client.get("/api/health").headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert "Permissions-Policy" in headers


def test_unknown_api_routes_are_authenticated_before_404(client):
    """Middleware runs before routing, so anonymous callers never probe routes."""
    assert client.get("/api/definitely-not-a-route").status_code == 401
    assert client.get("/api/definitely-not-a-route", headers={"Authorization": "Bearer nonsense"}).status_code == 401


def test_login_rate_limit_headers_are_exposed(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "nobody@ainids.dev", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.headers.get("X-RateLimit-Limit")


def test_error_responses_do_not_leak_internals(client, auth):
    response = client.get("/api/predictions/00000000-0000-0000-0000-000000000000", headers=auth)
    assert response.status_code == 404
    text = response.text.lower()
    for leak in ("traceback", "sqlalchemy", "file \"/home", "password"):
        assert leak not in text
