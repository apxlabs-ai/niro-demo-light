"""Regression tests for POST /auth/login hardening.

Two security invariants are exercised here:

1. Brute-force / credential-stuffing throttle
   The login endpoint must limit the number of failed attempts from a single
   source. After a small number of rapid wrong-password attempts the endpoint
   must stop returning 401 for every try and start returning HTTP 429.
   On the unfixed code every attempt returns 401 (no throttle) -> RED.

2. Account-enumeration timing oracle
   The login endpoint must take comparable time whether or not the submitted
   email belongs to a registered user, so response latency cannot be used to
   enumerate accounts. The deterministic proxy for "constant time" is that the
   password-verification (bcrypt) routine is invoked even when no user matches
   the submitted email -- i.e. the absent-user branch no longer short-circuits.
   On the unfixed code verify_password is never called for an unknown email
   (`if not user or not verify_password(...)` short-circuits) -> RED.

A wall-clock timing assertion would be flaky on shared CI hosts; this file uses
the deterministic "was bcrypt invoked?" proxy instead. See PR body for the
tradeoff.
"""

import pytest
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """Clear any in-process login-failure state between tests.

    Defensive: on the unfixed code the throttle store does not exist yet, so
    this is a no-op there and the tests still collect/run cleanly (RED).
    """
    import app.routes.auth as auth_mod

    def _clear():
        store = getattr(auth_mod, "_LOGIN_FAILURES", None)
        if store is not None:
            store.clear()

    _clear()
    yield
    _clear()


@pytest.fixture()
def existing_user(db):
    user = User(
        email="alex@customer.example.com",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("customer-pass-1234"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    # Entering the TestClient builds the app middleware stack; reset it so other
    # fixtures (e.g. test_mtls's client) can still add middleware afterwards.
    app.middleware_stack = None


# ---------------------------------------------------------------------------
# Invariant 1: brute-force throttle  (TC-78036180)
# ---------------------------------------------------------------------------

def test_correct_login_succeeds_baseline(client, existing_user):
    """Healthy baseline: a single correct login returns 200 + a token.

    Pairs with the throttle test so a RED there is provably the missing
    throttle, not a broken environment.
    """
    resp = client.post(
        "/auth/login",
        data={"username": "alex@customer.example.com", "password": "customer-pass-1234"},
    )
    assert resp.status_code == 200
    assert resp.json().get("access_token")


def test_repeated_failed_logins_are_throttled_with_429(client, existing_user):
    """After several rapid wrong-password attempts the endpoint must return 429.

    Unfixed code returns 401 for every attempt (no throttle) -> this fails RED.
    """
    statuses = []
    for _ in range(15):
        resp = client.post(
            "/auth/login",
            data={
                "username": "alex@customer.example.com",
                "password": "deliberately-wrong-password",
            },
        )
        statuses.append(resp.status_code)

    assert 429 in statuses, (
        "expected at least one HTTP 429 after repeated failed logins; "
        f"got statuses={statuses!r} (no throttle present)"
    )
    # Early attempts must still be evaluated normally (401), proving the 429 is a
    # rate-limit response and not a blanket rejection of all logins.
    assert statuses[0] == 401


def test_throttle_also_blocks_unknown_accounts(client, existing_user):
    """Credential stuffing rotates emails from one source; the per-source
    throttle must also kick in for attempts against unknown emails."""
    statuses = []
    for i in range(15):
        resp = client.post(
            "/auth/login",
            data={
                "username": f"ghost-{i}@nonexistent.invalid",
                "password": "deliberately-wrong-password",
            },
        )
        statuses.append(resp.status_code)

    assert 429 in statuses, (
        "expected HTTP 429 after repeated failed logins against unknown emails; "
        f"got statuses={statuses!r}"
    )


# ---------------------------------------------------------------------------
# Invariant 2: timing oracle / account enumeration  (TC-156956BD)
# ---------------------------------------------------------------------------

def test_login_runs_password_verify_for_unknown_email(client):
    """The absent-user branch must still perform a bcrypt verification.

    Deterministic proxy for constant-time behaviour: if verify_password is
    invoked even when no user matches, the fast short-circuit that leaks
    account existence via response latency is gone.

    Unfixed code never calls verify_password for an unknown email
    (`if not user or not verify_password(...)`) -> this fails RED.
    """
    with patch("app.routes.auth.verify_password", return_value=False) as spy:
        resp = client.post(
            "/auth/login",
            data={
                "username": "definitely-not-registered@nowhere.invalid",
                "password": "any-password",
            },
        )
    assert resp.status_code == 401
    assert spy.called, (
        "verify_password (bcrypt) was not invoked for an unknown email; the "
        "absent-user path short-circuits and leaks account existence via timing"
    )


def test_login_runs_password_verify_for_existing_email(client, existing_user):
    """Control: the existing-user wrong-password path obviously invokes bcrypt.

    Pairs with the unknown-email test so the asymmetry (the actual oracle) is
    what the RED demonstrates, not a broken spy.
    """
    with patch("app.routes.auth.verify_password", return_value=False) as spy:
        resp = client.post(
            "/auth/login",
            data={
                "username": "alex@customer.example.com",
                "password": "deliberately-wrong-password",
            },
        )
    assert resp.status_code == 401
    assert spy.called
