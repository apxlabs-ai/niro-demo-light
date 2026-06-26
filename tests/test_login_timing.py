"""Regression tests for the login timing side-channel / username enumeration.

Invariant under test:
  POST /auth/login must NOT reveal whether an email address is registered.
  The observable difference exploited in the wild is response time: on the
  vulnerable code, Python's `or` short-circuits in

      if not user or not verify_password(form.password, user.password_hash):

  so when the email is unknown (`user is None`) bcrypt.checkpw is never run,
  making the "no such user" path (~3ms) trivially distinguishable from the
  "user exists, wrong password" path (~190ms) and enabling silent enumeration
  of every registered account email.

Why a behavioral test instead of a wall-clock timing test:
  A pure timing assertion is inherently flaky in CI (GC pauses, shared
  runners, scheduler jitter) and would either be too tight (false reds) or
  too loose (false greens). Instead we assert the *mechanism* that closes the
  channel: that the password-verification work (verify_password / bcrypt) is
  invoked even when the user does not exist. That is the deterministic
  invariant — "bcrypt runs regardless of user existence" — and it captures the
  fix without depending on real wall-clock measurements.

  The known-user path is the positive control: it must also invoke
  verify_password, proving the spy is wired correctly and that the unknown-user
  red is the invariant being violated, not a broken harness.
"""

import app.routes.auth as auth_routes
from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, User

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


# ---------------------------------------------------------------------------
# Fixtures (mirrors the project's test_mtls.py conventions)
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
def known_user(db):
    """A single registered account whose password we know."""
    user = User(
        email="alex@customer.example.com",
        full_name="Alex Customer",
        role=Role.customer,
        password_hash=hash_password("correct-horse-battery-staple"),
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
    # Entering the TestClient context builds app.middleware_stack, marking the
    # app as "started". Reset it so a later test (e.g. test_mtls) that calls
    # app.add_middleware(...) doesn't hit "Cannot add middleware after an
    # application has started". Mirrors test_mtls.py's own cleanup.
    app.middleware_stack = None


@pytest.fixture()
def verify_spy(monkeypatch):
    """Spy that wraps the real verify_password and records each invocation.

    Patches the name bound inside app.routes.auth (the login handler calls the
    symbol imported into that module's namespace), delegating to the real
    implementation so the endpoint behaves identically.
    """
    real_verify = auth_routes.verify_password
    calls = []

    def spy(plain, hashed):
        calls.append((plain, hashed))
        return real_verify(plain, hashed)

    monkeypatch.setattr(auth_routes, "verify_password", spy)
    return calls


# ---------------------------------------------------------------------------
# The invariant: password verification runs regardless of user existence.
# ---------------------------------------------------------------------------

def test_login_runs_password_verification_for_unknown_email(
    client, known_user, verify_spy
):
    """RED on the vulnerable `or` short-circuit, GREEN after the dummy-hash fix.

    An unknown email + wrong password must still invoke verify_password, so the
    unknown-user path performs the same bcrypt work as the known-user path and
    the timing side channel is closed.
    """
    resp = client.post(
        "/auth/login",
        data={"username": "nobody-xyz999@no-such-domain.invalid", "password": "wrong"},
    )

    # Same opaque 401 an attacker sees in both equivalence classes.
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid credentials"

    # The invariant: bcrypt work happened even though the user does not exist.
    assert verify_spy, (
        "verify_password was NOT invoked for an unknown email — the login "
        "handler short-circuits before bcrypt, leaking via response time whether "
        "the email is registered (username enumeration)."
    )


def test_login_runs_password_verification_for_known_email(
    client, known_user, verify_spy
):
    """Positive control: a registered email + wrong password invokes
    verify_password (and 401s). Proves the spy is wired correctly, so the
    unknown-email assertion is meaningful."""
    resp = client.post(
        "/auth/login",
        data={"username": known_user.email, "password": "wrong"},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid credentials"
    assert verify_spy, "verify_password must be invoked for a registered email"


def test_login_succeeds_with_correct_credentials(client, known_user):
    """Sanity: the fix must not break legitimate login."""
    resp = client.post(
        "/auth/login",
        data={"username": known_user.email, "password": "correct-horse-battery-staple"},
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]
