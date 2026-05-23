"""
Shared pytest fixtures for security regression tests.

Each test function gets a fresh in-memory SQLite database so there is
no state bleed between cases. The FastAPI get_db dependency is overridden
to route all requests through the test session factory. The in-process
search result cache is flushed at fixture setup time so cached rows from
one test cannot pollute the next.

The background worker (started via the lifespan hook) is never launched
here — TestClient is used outside a context manager so the lifespan is
not triggered. Tests that need run_scheduled_report behaviour call the
route directly via the TestClient.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.search as search_module
from app.db import Base, get_db
from app.main import app


@pytest.fixture()
def test_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def client(test_engine):
    # Clear the in-process result cache so tests don't inherit each
    # other's cached rows — the module-level dict persists across calls.
    search_module._cache.clear()

    TestSession = sessionmaker(
        bind=test_engine, autoflush=False, expire_on_commit=False
    )

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    # TestClient without `with` skips the lifespan hook, so the
    # background worker never starts — no interference with test state.
    yield TestClient(app, raise_server_exceptions=True)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _signup_and_login(client: TestClient, email: str, password: str = "testpass99!") -> tuple[str, int]:
    """Register a customer and return (bearer_token, user_id)."""
    r = client.post(
        "/auth/signup",
        json={"email": email, "password": password, "full_name": "Test User"},
    )
    assert r.status_code == 201, r.text
    user_id = r.json()["id"]
    r = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"], user_id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_ticket(client: TestClient, token: str, subject: str) -> int:
    r = client.post(
        "/tickets",
        json={"subject": subject, "description": "desc", "priority": "normal"},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _create_search(client: TestClient, token: str, filter_: dict) -> int:
    r = client.post(
        "/searches",
        json={"name": "test-search", "filter": filter_},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]
