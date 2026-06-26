from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pytest

from app.db import Base, get_db
from app.main import app
from app.models import User


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
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    app.middleware_stack = None


def _observable(response):
    return {
        "status": response.status_code,
        "content_type": response.headers.get("content-type", "").split(";")[0],
        "body": response.json(),
    }


def test_login_failures_verify_password_for_existing_and_missing_users(
    client, db, monkeypatch
):
    user = User(
        email="alex@example.com",
        password_hash="stored-password-hash",
        full_name="Alex Customer",
    )
    db.add(user)
    db.commit()

    calls = []

    def fake_verify_password(plain, hashed):
        calls.append((plain, hashed))
        return plain == "correct-pass-1234" and hashed == user.password_hash

    monkeypatch.setattr("app.routes.auth.verify_password", fake_verify_password)

    valid_response = client.post(
        "/auth/login",
        data={"username": user.email, "password": "correct-pass-1234"},
    )
    assert valid_response.status_code == 200
    assert "access_token" in valid_response.json()

    existing_response = client.post(
        "/auth/login",
        data={"username": user.email, "password": "wrong-pass-1234"},
    )
    assert existing_response.status_code == 401
    assert existing_response.json() == {"detail": "invalid credentials"}

    calls_before_missing_user = len(calls)
    missing_response = client.post(
        "/auth/login",
        data={"username": "missing@example.com", "password": "wrong-pass-1234"},
    )

    assert missing_response.status_code == 401
    assert missing_response.json() == existing_response.json()
    assert len(calls) == calls_before_missing_user + 1
    assert calls[-1][0] == "wrong-pass-1234"
    assert calls[-1][1] != user.password_hash


def test_signup_responses_do_not_reveal_existing_accounts(client, db):
    existing_user = User(
        email="agent@example.com",
        password_hash="existing-password-hash",
        full_name="Helpdesk Agent",
    )
    db.add(existing_user)
    db.commit()

    fresh_payload = {
        "email": "new-customer@example.com",
        "password": "fresh-pass-1234",
        "full_name": "New Customer",
    }
    existing_payload = {
        "email": existing_user.email,
        "password": "fresh-pass-1234",
        "full_name": "New Customer",
    }

    fresh_response = client.post("/auth/signup", json=fresh_payload)
    replay_response = client.post("/auth/signup", json=fresh_payload)
    existing_response = client.post("/auth/signup", json=existing_payload)

    assert _observable(replay_response) == _observable(fresh_response)
    assert _observable(existing_response) == _observable(fresh_response)

    body = fresh_response.json()
    assert isinstance(body, dict)
    assert "id" not in body
    assert "email" not in body
    assert "full_name" not in body
    assert "role" not in body

    fresh_count = db.scalar(
        select(func.count()).select_from(User).where(User.email == fresh_payload["email"])
    )
    existing_count = db.scalar(
        select(func.count()).select_from(User).where(User.email == existing_user.email)
    )
    assert fresh_count == 1
    assert existing_count == 1
