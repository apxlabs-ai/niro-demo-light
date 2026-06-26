"""Regression tests for unvalidated input on ticket routes.

Two invariants are pinned here:

  1. PATCH /tickets/{id} must NOT accept an assignee_id that does not
     correspond to an existing user. assignee_id is a ForeignKey to
     users.id, so storing an orphaned value corrupts ticket state.
     (SQLite does not enforce the FK, so the route must.)

  2. A ticket_id path parameter that exceeds the maximum signed 64-bit
     integer must yield a client error (422), not an unhandled 500.
     SQLite/SQLAlchemy cannot bind a value larger than int64, so an
     unbounded path parameter reaches the driver and explodes. This
     applies to BOTH GET /tickets/{ticket_id} (Bearer auth, :8000) and
     GET /mtls/tickets/{ticket_id} (client-cert auth, :8443).

Each invariant is asserted against a healthy positive control so a red
is provably the invariant, not a broken environment.
"""

import pytest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, Ticket, User

MAX_INT64 = 9223372036854775807          # largest signed 64-bit int
OVER_INT64 = 9223372036854775808         # max int64 + 1 (overflows the driver)


# ---------------------------------------------------------------------------
# Cert-injection helper (mirrors tests/test_mtls.py) for the mTLS route.
# ---------------------------------------------------------------------------

def _make_ssl_object(cn: str | None) -> MagicMock:
    obj = MagicMock()
    obj.getpeercert.return_value = {"subject": ((("commonName", cn),),)}
    return obj


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # share one connection so the TestClient worker
        # thread sees rows committed by the request handler (PATCH commits then
        # refreshes; a re-checked-out per-thread connection would be empty).
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def seeded(db):
    """One agent and one customer, with one ticket owned by the customer."""
    agent = User(
        email="agent@helpdesk.example.com",
        full_name="Helpdesk Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    customer = User(
        email="alex@customer.example.com",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    db.add_all([agent, customer])
    db.commit()
    db.refresh(agent)
    db.refresh(customer)

    ticket = Ticket(
        customer_id=customer.id,
        subject="integrity-check",
        description="owned by customer",
        status="open",
        priority="low",
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return agent, customer, ticket


@pytest.fixture()
def client(db):
    """TestClient over the in-memory DB.

    raise_server_exceptions=False so an unhandled exception surfaces as a
    real HTTP 500 response (what a deployed server would return) instead
    of re-raising into the test — that lets the int64 regression go red
    cleanly on the unfixed code.

    A cert-injector middleware (same mechanism as tests/test_mtls.py)
    lets the mTLS route resolve identity without a live TLS handshake.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as StarletteRequest

    class _CertInjector(BaseHTTPMiddleware):
        async def dispatch(self, request: StarletteRequest, call_next):
            cn = request.headers.get("X-Test-Cert-CN")
            if cn is not None:
                request.scope["ssl_object"] = _make_ssl_object(cn or None)
            return await call_next(request)

    app.add_middleware(_CertInjector)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()
    app.middleware_stack = None
    app.user_middleware.clear()


def _bearer(user: User) -> dict:
    return {"Authorization": f"Bearer {issue_token(user)}"}


# ---------------------------------------------------------------------------
# Invariant 1 — PATCH /tickets/{id} rejects a non-existent assignee_id
# ---------------------------------------------------------------------------

def test_patch_ticket_rejects_nonexistent_assignee(client, seeded):
    """An agent setting assignee_id to a non-existent user must be rejected
    (4xx) and the orphaned value must NOT persist."""
    agent, customer, ticket = seeded
    bogus = 99999  # no user with this id exists

    resp = client.patch(
        f"/tickets/{ticket.id}",
        headers=_bearer(agent),
        json={"assignee_id": bogus},
    )
    assert 400 <= resp.status_code < 500, (
        f"assigning a non-existent user must be a client error, got "
        f"{resp.status_code}"
    )

    # And it must not have persisted.
    got = client.get(f"/tickets/{ticket.id}", headers=_bearer(agent))
    assert got.status_code == 200
    assert got.json()["assignee_id"] != bogus, (
        "orphaned assignee_id was persisted despite the rejection"
    )


def test_patch_ticket_accepts_existing_assignee(client, seeded):
    """Positive control: assigning a real, existing user still succeeds."""
    agent, customer, ticket = seeded

    resp = client.patch(
        f"/tickets/{ticket.id}",
        headers=_bearer(agent),
        json={"assignee_id": customer.id},
    )
    assert resp.status_code == 200
    assert resp.json()["assignee_id"] == customer.id


# ---------------------------------------------------------------------------
# Invariant 2 — out-of-range ticket_id -> 422, not 500 (both routes)
# ---------------------------------------------------------------------------

def test_get_ticket_overflow_id_returns_422(client, seeded):
    """GET /tickets/{id} (Bearer): id > max int64 must be 422, not 500."""
    agent, _, _ = seeded
    resp = client.get(f"/tickets/{OVER_INT64}", headers=_bearer(agent))
    assert resp.status_code == 422, (
        f"overflow ticket_id must be a 422 client error, got {resp.status_code}"
    )


def test_get_ticket_max_int64_returns_404(client, seeded):
    """Positive control: an in-range, non-existent id still cleanly 404s."""
    agent, _, _ = seeded
    resp = client.get(f"/tickets/{MAX_INT64}", headers=_bearer(agent))
    assert resp.status_code == 404


def test_mtls_get_ticket_overflow_id_returns_422(client, seeded):
    """GET /mtls/tickets/{id} (cert): id > max int64 must be 422, not 500."""
    resp = client.get(
        f"/mtls/tickets/{OVER_INT64}",
        headers={"X-Test-Cert-CN": "alex@customer.example.com"},
    )
    assert resp.status_code == 422, (
        f"overflow ticket_id must be a 422 client error, got {resp.status_code}"
    )


def test_mtls_get_ticket_max_int64_returns_404(client, seeded):
    """Positive control: an in-range, non-existent id still cleanly 404s."""
    resp = client.get(
        f"/mtls/tickets/{MAX_INT64}",
        headers={"X-Test-Cert-CN": "alex@customer.example.com"},
    )
    assert resp.status_code == 404
