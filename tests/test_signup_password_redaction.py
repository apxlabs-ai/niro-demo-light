"""Regression tests: POST /auth/signup must never echo the submitted password.

Invariant under test:
    A user's submitted password must NEVER appear in any API response body,
    even when the password fails validation (too short / too long).

Background:
    FastAPI/Pydantic's default RequestValidationError handler serializes the
    full validation error, including the raw `input` value, into the 422
    response body. Because the signup password is a plain `str`, a too-short
    or too-long password is reflected verbatim in `detail[*].input`, leaking
    it to reverse-proxy logs, APM agents, and error monitors that capture
    4xx bodies.

These tests promote the proof-of-concept bundles (TC-632E86B8 / TC-1A80B8DD,
same root cause) into the project's native pytest suite. They follow the same
TestClient + in-memory SQLite pattern used by tests/test_mtls.py.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app


@pytest.fixture()
def db():
    # StaticPool keeps a single in-memory connection shared across the test
    # thread (where the schema is created) and the TestClient's request
    # thread (where signup writes/reads), so the `users` table is visible to
    # rows inserted through the route under test.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Positive controls — the environment is healthy and behaves normally
# ---------------------------------------------------------------------------

def test_legitimate_signup_still_succeeds(client):
    """A valid signup must still work (201) and must not echo the password."""
    pw = "Sentinel-Valid!Aa1"  # >= 8, <= 128
    resp = client.post(
        "/auth/signup",
        json={"email": "valid@example.com", "password": pw, "full_name": "Valid User"},
    )
    assert resp.status_code == 201, resp.text
    assert pw not in resp.text, "password must never appear in a success response"


def test_missing_email_still_returns_422(client):
    """A non-sensitive validation error (missing email) must still 422.

    Positive control proving the custom handler does not swallow ordinary
    validation failures and still reports the offending non-sensitive field.
    """
    resp = client.post(
        "/auth/signup",
        json={"password": "Sentinel-Valid!Aa1", "full_name": "No Email"},
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    # The email error is still surfaced so clients can fix their request.
    assert any("email" in str(err.get("loc", "")) for err in body["detail"])


# ---------------------------------------------------------------------------
# The invariant — submitted password must never be echoed in a 422 body
# ---------------------------------------------------------------------------

def test_too_short_password_not_echoed_in_422(client):
    """Too-short password → 422, but the submitted value must NOT appear."""
    short_pw = "Sh0rt!"  # < 8 chars, distinctive marker
    resp = client.post(
        "/auth/signup",
        json={"email": "short@example.com", "password": short_pw, "full_name": "Short PW"},
    )
    assert resp.status_code == 422, resp.text
    assert short_pw not in resp.text, (
        "INVARIANT VIOLATED: too-short password echoed verbatim in 422 body"
    )


def test_too_long_password_not_echoed_in_422(client):
    """Too-long password → 422, but the submitted value must NOT appear."""
    long_marker = "ZmarkerZ"
    long_pw = long_marker + "B" * (130 - len(long_marker))  # > 128 chars
    resp = client.post(
        "/auth/signup",
        json={"email": "long@example.com", "password": long_pw, "full_name": "Long PW"},
    )
    assert resp.status_code == 422, resp.text
    assert long_marker not in resp.text and long_pw not in resp.text, (
        "INVARIANT VIOLATED: too-long password echoed verbatim in 422 body"
    )
