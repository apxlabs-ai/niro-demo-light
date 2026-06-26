"""Regression tests for input-length bounds on signup password and ticket
description.

These guard two invariants:

  1. POST /auth/signup must reject or safely handle over-length passwords
     WITHOUT returning an HTTP 500. bcrypt raises ValueError for inputs longer
     than 72 bytes; an unguarded hash turns that into an uncaught 500.
       - A 73-character password must be rejected by schema validation (422).
       - A password that is <= 72 characters but > 72 BYTES (multibyte) passes
         schema validation and reaches the hash, so the hashing helper itself
         must never raise — the request must not 500.

  2. POST /tickets must enforce a maximum size on `description` so a single
     ticket cannot persist an arbitrarily large payload (DB bloat / resource
     exhaustion). An oversized description must be rejected (422) before it is
     written to the database.

Each invariant is paired with a positive control (a legitimate request that
stays green) so a red result isolates to the missing bound, not a broken setup.

Driven entirely through the app's real routes via TestClient with an isolated
in-memory database, mirroring tests/test_mtls.py.
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
    # StaticPool keeps a single shared connection so the in-memory schema is
    # visible to the request handler thread driven by TestClient.
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
    # raise_server_exceptions=False so an uncaught handler error surfaces as the
    # real HTTP 500 a client would see (rather than re-raising into the test),
    # which is exactly the behaviour these tests must prove is gone.
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()
    # Reset the built middleware stack so other test modules that call
    # app.add_middleware (e.g. tests/test_mtls.py) on this shared app instance
    # are not rejected with "Cannot add middleware after an application has
    # started". Mirrors that module's own teardown.
    app.middleware_stack = None


def _signup(client, email, password, full_name="Test User"):
    return client.post(
        "/auth/signup",
        json={"email": email, "password": password, "full_name": full_name},
    )


# ---------------------------------------------------------------------------
# Signup password length / byte bound
# ---------------------------------------------------------------------------

def test_signup_72_char_password_succeeds(client):
    """Positive control: a legitimate 72-char password registers cleanly."""
    resp = _signup(client, "control72@example.com", "a" * 72)
    assert resp.status_code == 201, resp.text


def test_signup_73_char_password_returns_422_not_500(client):
    """A 73-char password must be rejected by validation, never produce a 500.

    On unfixed code the schema allows up to 128 chars, so this reaches bcrypt,
    which raises on >72 bytes, and the route returns HTTP 500.
    """
    resp = _signup(client, "long73@example.com", "a" * 73)
    assert resp.status_code != 500, f"over-length password produced a 500: {resp.text}"
    assert resp.status_code == 422, resp.text


def test_signup_multibyte_password_over_72_bytes_does_not_500(client):
    """A <=72-char but >72-BYTE password must not crash the hasher.

    "e" with combining/precomposed accent 'é' is 2 bytes in UTF-8. 40 of them is
    40 characters (within any sane char cap) but 80 bytes — over bcrypt's 72-byte
    limit. The hashing helper must handle this safely so signup never 500s.
    """
    pw = "é" * 40  # 40 chars, 80 bytes UTF-8
    assert len(pw) <= 72 and len(pw.encode("utf-8")) > 72
    resp = _signup(client, "multibyte@example.com", pw)
    assert resp.status_code != 500, f"multibyte password produced a 500: {resp.text}"
    assert resp.status_code == 201, resp.text


# ---------------------------------------------------------------------------
# Ticket description length bound
# ---------------------------------------------------------------------------

def _customer_token(client, email="ticketuser@example.com", password="customer-pass-1234"):
    r = _signup(client, email, password)
    assert r.status_code == 201, r.text
    r = client.post("/auth/login", data={"username": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_create_ticket_normal_description_succeeds(client):
    """Positive control: a normal-sized ticket description is accepted."""
    token = _customer_token(client, email="ticketok@example.com")
    resp = client.post(
        "/tickets",
        headers={"Authorization": f"Bearer {token}"},
        json={"subject": "control", "description": "a reasonable description", "priority": "low"},
    )
    assert resp.status_code == 201, resp.text


def test_create_ticket_oversized_description_returns_422(client):
    """An oversized ticket description must be rejected (422) before persistence.

    On unfixed code TicketCreate.description has no max_length, so a huge payload
    is accepted (201) and stored.
    """
    token = _customer_token(client, email="ticketbig@example.com")
    big = "A" * 20_000  # well past the 10_000 cap
    resp = client.post(
        "/tickets",
        headers={"Authorization": f"Bearer {token}"},
        json={"subject": "oversized", "description": big, "priority": "low"},
    )
    assert resp.status_code == 422, f"oversized description was not rejected: {resp.status_code}"
