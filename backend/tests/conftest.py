"""
Shared fixtures for the AI-NIDS backend test suite.

The environment is configured *before* the application is imported so the tests
never touch the development database, never need an AI provider key and never
depend on state left behind by a previous run.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# --------------------------------------------------------------------------- #
# Test environment (must happen before `app` is imported)
# --------------------------------------------------------------------------- #
TEST_DB = Path(tempfile.gettempdir()) / "ainids_pytest.db"
for _suffix in ("", "-wal", "-shm"):
    _stale = Path(str(TEST_DB) + _suffix)
    if _stale.exists():
        _stale.unlink()

os.environ.update(
    {
        "DATABASE_URL": f"sqlite:///{TEST_DB}",
        "JWT_SECRET": "pytest-secret-value-not-used-outside-the-test-suite",
        "ENVIRONMENT": "test",
        "LOG_LEVEL": "WARNING",
        "SEED_DEMO_DATA": "true",
        "RATE_LIMIT_ENABLED": "true",
        "AI_PROVIDER": "none",
    }
)

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.main import app  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_CSV = REPO_ROOT / "frontend" / "public" / "samples" / "sample_traffic.csv"

ANALYST = (settings.DEMO_USER_EMAIL, settings.DEMO_USER_PASSWORD)
ADMIN = (settings.DEMO_ADMIN_EMAIL, settings.DEMO_ADMIN_PASSWORD)


# --------------------------------------------------------------------------- #
# client / auth
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def client() -> TestClient:
    """A single TestClient for the whole session (lifespan runs once)."""
    with TestClient(app) as test_client:
        yield test_client


def _token(client: TestClient, credentials: tuple[str, str]) -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": credentials[0], "password": credentials[1]},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture(scope="session")
def analyst_token(client: TestClient) -> str:
    return _token(client, ANALYST)


@pytest.fixture(scope="session")
def admin_token(client: TestClient) -> str:
    return _token(client, ADMIN)


@pytest.fixture(scope="session")
def auth(analyst_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture(scope="session")
def admin_auth(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def fresh_login(client: TestClient):
    """Factory for throw-away logins (used by tests that mutate session state)."""

    def _login(email: str = ANALYST[0], password: str = ANALYST[1]) -> dict[str, str]:
        return {"Authorization": f"Bearer {_token(client, (email, password))}"}

    return _login


# --------------------------------------------------------------------------- #
# CSV builders
# --------------------------------------------------------------------------- #
def build_csv_bytes(
    rows: int = 40,
    *,
    drop_leading: int = 0,
    shuffle_columns: bool = False,
    seed: int = 7,
) -> bytes:
    """
    Slice the bundled held-out sample.

    ``drop_leading`` removes the first N feature columns (used to prove that
    missing-but-expected features are imputed instead of crashing) and
    ``shuffle_columns`` reorders every column, which must not change a single
    prediction.
    """
    import pandas as pd

    frame = pd.read_csv(SAMPLE_CSV, nrows=rows)
    if drop_leading:
        frame = frame.drop(columns=list(frame.columns[:drop_leading]))
    if shuffle_columns:
        frame = frame.sample(frac=1.0, axis=1, random_state=seed)
    return frame.to_csv(index=False).encode()


@pytest.fixture(scope="session")
def sample_csv_bytes() -> bytes:
    return build_csv_bytes(rows=60)


@pytest.fixture(scope="session")
def sample_dataset(client: TestClient, auth: dict[str, str]) -> dict:
    """Upload the 60-row held-out sample once and reuse it across tests."""
    response = client.post(
        "/api/datasets/upload",
        headers=auth,
        files={"file": ("pytest_sample.csv", build_csv_bytes(rows=60), "text/csv")},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture(scope="module")
def feature_columns() -> list[str]:
    """The 70 expected feature names, in training order (module-scoped on purpose:
    test modules may define their own `schema` fixture and scopes must not clash)."""
    from app.services.preprocessing_service import load_schema

    return list(load_schema().feature_columns)


@pytest.fixture(scope="session")
def analysed_job(client: TestClient, auth: dict[str, str], sample_dataset: dict) -> dict:
    """Run one synchronous analysis and return the job payload (with summary)."""
    response = client.post(
        "/api/predictions/analyze",
        headers=auth,
        json={"dataset_id": sample_dataset["id"], "force_sync": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "sync"
    return body["job"]


@pytest.fixture(scope="session")
def analysed_sample(client: TestClient, auth: dict[str, str], sample_dataset: dict) -> dict:
    """
    Full synchronous analysis result for the 60-row sample:
    ``{"mode", "job", "summary"}`` plus ``dataset_id``.

    Shared by the alerts/prediction test modules so the model runs once per session.
    """
    response = client.post(
        "/api/predictions/analyze",
        headers=auth,
        json={"dataset_id": sample_dataset["id"], "force_sync": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "sync"
    body["dataset_id"] = sample_dataset["id"]
    return body
