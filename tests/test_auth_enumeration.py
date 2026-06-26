import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.routes.auth as auth_routes
from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import User


def _signup_payload(email: str) -> dict[str, str]:
    return {
        "email": email,
        "password": "Sc0utPass!123",
        "full_name": "Niro Auth Probe",
    }


def _login_payload(email: str) -> dict[str, str]:
    return {"username": email, "password": "WrongPass!123"}


def _assert_generic_signup_response(body: dict[str, object]) -> None:
    rendered = repr(body).lower()
    assert "registered" not in rendered
    assert "already" not in rendered
    assert "exists" not in rendered
    assert "email" not in body
    assert "id" not in body


def test_signup_response_does_not_reveal_existing_account(client):
    email = "signup-enumeration@example.com"

    first = client.post("/auth/signup", json=_signup_payload(email))
    duplicate = client.post("/auth/signup", json=_signup_payload(email))

    assert first.status_code == duplicate.status_code
    assert first.json() == duplicate.json()
    _assert_generic_signup_response(first.json())

    login = client.post(
        "/auth/login",
        data={"username": email, "password": "Sc0utPass!123"},
    )
    assert login.status_code == 200
    assert login.json()["access_token"]


def test_login_checks_password_hash_for_missing_and_existing_users(client, db, monkeypatch):
    existing = User(
        email="login-enumeration@example.test",
        full_name="Login Enumeration",
        password_hash=hash_password("CorrectPass!123"),
    )
    db.add(existing)
    db.commit()

    checked_hashes = []

    def record_password_check(plain: str, hashed: str) -> bool:
        checked_hashes.append(hashed)
        return False

    monkeypatch.setattr(auth_routes, "verify_password", record_password_check)

    existing_resp = client.post("/auth/login", data=_login_payload(existing.email))
    absent_resp = client.post(
        "/auth/login",
        data=_login_payload("missing-login-enumeration@example.test"),
    )

    assert existing_resp.status_code == absent_resp.status_code == 401
    assert existing_resp.json() == absent_resp.json() == {
        "detail": "invalid credentials"
    }
    assert len(checked_hashes) == 2


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


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    app.middleware_stack = None
