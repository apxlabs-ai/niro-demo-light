"""mTLS acceptance tests for niro-demo-light.

Written BEFORE implementation (TDD). Every test here must FAIL on
unmodified code and PASS after the feature is complete — except
AC-BUG-1, which fails before implementation AND after intentional-bug
implementation, and only passes once the BOLA is fixed.

Acceptance criteria covered:
  AC-1:     GET /mtls/me with valid cert → 200 + cert owner's user object
  AC-2:     GET /mtls/me without cert → 401
  AC-3:     GET /mtls/me with cert CN not matching any user → 401
  AC-4:     GET /mtls/tickets with valid cert → 200 + only owner's tickets
  AC-5:     GET /mtls/tickets without cert → 401
  AC-6:     current_user_mtls: cert with no CN → 401
  AC-BUG-1: GET /mtls/tickets/{id} authenticated as alex, fetching
            blair's ticket id → must 403. INTENTIONALLY FAILS until
            the BOLA is discovered and fixed.

Test strategy:
  current_user_mtls is tested directly with a mock Request whose
  scope["ssl_object"] mimics what stdlib ssl.SSLObject.getpeercert()
  returns. Route-level tests use a TestClient with app-level dependency
  overrides for the DB, plus a conftest middleware that reads the
  test-only header X-Test-Cert-CN and injects a matching mock
  ssl_object into the ASGI scope — keeping TLS out of unit tests while
  still exercising the real auth dependency and real route handlers.
"""

import pytest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, Ticket, User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ssl_object(cn: str | None) -> MagicMock:
    """Return a mock that mimics ssl.SSLObject for a cert with the given CN.

    Passing cn=None simulates a cert where the subject carries no
    commonName field (e.g. a cert with only SAN entries and no CN).
    """
    obj = MagicMock()
    if cn is not None:
        obj.getpeercert.return_value = {
            "subject": ((("commonName", cn),),)
        }
    else:
        obj.getpeercert.return_value = {"subject": ()}
    return obj


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def demo_users(db):
    """Seed two customers and one agent with one ticket each."""
    alex = User(
        email="alex@customer.test",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    blair = User(
        email="blair@customer.test",
        full_name="Blair Customer",
        role=Role.customer,
        password_hash=hash_password("x"),
    )
    agent = User(
        email="agent@helpdesk.test",
        full_name="Helpdesk Agent",
        role=Role.agent,
        password_hash=hash_password("x"),
    )
    db.add_all([alex, blair, agent])
    db.commit()
    db.refresh(alex)
    db.refresh(blair)
    db.refresh(agent)

    ticket_alex = Ticket(
        customer_id=alex.id,
        subject="Alex-secret-ticket",
        description="owned by alex",
        status="open",
        priority="low",
    )
    ticket_blair = Ticket(
        customer_id=blair.id,
        subject="Blair-secret-ticket",
        description="owned by blair",
        status="open",
        priority="low",
    )
    db.add_all([ticket_alex, ticket_blair])
    db.commit()
    db.refresh(ticket_alex)
    db.refresh(ticket_blair)

    return alex, blair, agent, ticket_alex, ticket_blair


@pytest.fixture()
def client(db):
    """TestClient with in-memory DB override.

    A lightweight ASGI middleware is installed for this fixture only.
    It reads the test-only header X-Test-Cert-CN and injects a mock
    ssl_object into the ASGI scope before the request reaches the app,
    making the real current_user_mtls dependency exercise its full
    code path without a live TLS connection.

    Requests sent without X-Test-Cert-CN have no ssl_object in scope,
    which is the correct simulation of a plain HTTP request.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as StarletteRequest

    class _CertInjector(BaseHTTPMiddleware):
        async def dispatch(self, request: StarletteRequest, call_next):
            cn_header = request.headers.get("X-Test-Cert-CN")
            if cn_header is not None:
                # Empty string header = cert present but CN absent
                cn = cn_header if cn_header else None
                request.scope["ssl_object"] = _make_ssl_object(cn)
            return await call_next(request)

    app.add_middleware(_CertInjector)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    # Remove the injected middleware layer so it doesn't bleed into
    # other test fixtures.
    app.middleware_stack = None  # forces rebuild on next request
    app.user_middleware.clear()


# ---------------------------------------------------------------------------
# Unit tests for current_user_mtls
# ---------------------------------------------------------------------------

def test_current_user_mtls_maps_cn_to_user(db, demo_users):
    """AC-5 (unit): cert CN matching a user's email authenticates as that user."""
    from app.auth import current_user_mtls
    from starlette.requests import Request

    alex, *_ = demo_users
    mock_req = MagicMock(spec=Request)
    mock_req.scope = {"ssl_object": _make_ssl_object(cn="alex@customer.test")}

    user = current_user_mtls(request=mock_req, db=db)

    assert user.id == alex.id
    assert user.email == "alex@customer.test"


def test_current_user_mtls_raises_401_no_ssl_object(db, demo_users):
    """AC-2/AC-6 (unit): plain HTTP request (no ssl_object in scope) → 401."""
    from app.auth import current_user_mtls
    from fastapi import HTTPException
    from starlette.requests import Request

    mock_req = MagicMock(spec=Request)
    mock_req.scope = {}  # no ssl_object — simulates plain HTTP

    with pytest.raises(HTTPException) as exc:
        current_user_mtls(request=mock_req, db=db)
    assert exc.value.status_code == 401


def test_current_user_mtls_raises_401_no_cn(db, demo_users):
    """AC-6 (unit): cert present but no CN field → 401."""
    from app.auth import current_user_mtls
    from fastapi import HTTPException
    from starlette.requests import Request

    mock_req = MagicMock(spec=Request)
    mock_req.scope = {"ssl_object": _make_ssl_object(cn=None)}

    with pytest.raises(HTTPException) as exc:
        current_user_mtls(request=mock_req, db=db)
    assert exc.value.status_code == 401


def test_current_user_mtls_raises_401_unknown_cn(db, demo_users):
    """AC-3 (unit): cert CN not matching any user email → 401."""
    from app.auth import current_user_mtls
    from fastapi import HTTPException
    from starlette.requests import Request

    mock_req = MagicMock(spec=Request)
    mock_req.scope = {"ssl_object": _make_ssl_object(cn="nobody@unknown.test")}

    with pytest.raises(HTTPException) as exc:
        current_user_mtls(request=mock_req, db=db)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# Route tests: GET /mtls/me
# ---------------------------------------------------------------------------

def test_mtls_me_with_valid_cert_returns_owner(client, demo_users):
    """AC-1: valid cert → 200 + the cert owner's user object."""
    alex, *_ = demo_users
    resp = client.get("/mtls/me", headers={"X-Test-Cert-CN": "alex@customer.test"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "alex@customer.test"


def test_mtls_me_without_cert_returns_401(client, demo_users):
    """AC-2: no cert → 401."""
    resp = client.get("/mtls/me")
    assert resp.status_code == 401


def test_mtls_me_unknown_cn_returns_401(client, demo_users):
    """AC-3: cert CN not matching any user → 401."""
    resp = client.get("/mtls/me", headers={"X-Test-Cert-CN": "nobody@unknown.test"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Route tests: GET /mtls/tickets (list)
# ---------------------------------------------------------------------------

def test_mtls_tickets_returns_only_owner_tickets(client, demo_users):
    """AC-4: cert-authenticated list must be scoped to the cert owner."""
    alex, blair, _, ticket_alex, ticket_blair = demo_users
    resp = client.get("/mtls/tickets", headers={"X-Test-Cert-CN": "alex@customer.test"})
    assert resp.status_code == 200
    ids = {t["id"] for t in resp.json()}
    assert ticket_alex.id in ids, "alex's own ticket must appear"
    assert ticket_blair.id not in ids, "blair's ticket must NOT appear in alex's list"


def test_mtls_tickets_without_cert_returns_401(client, demo_users):
    """AC-5: no cert → 401."""
    resp = client.get("/mtls/tickets")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Route tests: GET /mtls/tickets/{id}
# ---------------------------------------------------------------------------

def test_mtls_ticket_by_id_owner_can_access_own(client, demo_users):
    """Sanity: cert owner can fetch their own ticket by ID → 200."""
    alex, _, _, ticket_alex, _ = demo_users
    resp = client.get(
        f"/mtls/tickets/{ticket_alex.id}",
        headers={"X-Test-Cert-CN": "alex@customer.test"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == ticket_alex.id


def test_mtls_ticket_by_id_without_cert_returns_401(client, demo_users):
    """No cert → 401 regardless of ticket id."""
    _, _, _, ticket_alex, _ = demo_users
    resp = client.get(f"/mtls/tickets/{ticket_alex.id}")
    assert resp.status_code == 401


def test_mtls_ticket_by_id_cross_user_returns_403(client, demo_users):
    """AC-BUG-1 (intentional failure): cert-authenticated as alex, accessing
    blair's ticket by ID must return 403.

    This test FAILS on the intentional implementation (which returns 200)
    and only passes once the BOLA is discovered and the ownership check
    is added. Do NOT fix this test — fix the route.
    """
    _, _, _, _, ticket_blair = demo_users
    resp = client.get(
        f"/mtls/tickets/{ticket_blair.id}",
        headers={"X-Test-Cert-CN": "alex@customer.test"},
    )
    assert resp.status_code == 403, (
        "AC-BUG-1: cross-user ticket access must be 403. "
        "If this returns 200 the BOLA is still present."
    )
