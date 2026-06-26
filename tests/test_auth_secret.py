import importlib
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app


DEFAULT_SECRET = "dev-secret-do-not-use-in-prod"
TEST_SECRET = "test-only-helpdesk-secret-32-bytes-minimum"
TEST_EMAIL = "niro-tc-4d4012b4@example.com"


def _reload_auth():
    import app.auth as auth

    return importlib.reload(auth)


@pytest.fixture(autouse=True)
def restore_configured_auth_secret(monkeypatch):
    yield
    monkeypatch.setenv("HELPDESK_SECRET", TEST_SECRET)
    _reload_auth()


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    app.middleware_stack = None
    Base.metadata.drop_all(bind=engine)


@pytest.mark.parametrize("secret", [None, "", DEFAULT_SECRET])
def test_auth_requires_non_placeholder_jwt_secret(monkeypatch, secret):
    if secret is None:
        monkeypatch.delenv("HELPDESK_SECRET", raising=False)
    else:
        monkeypatch.setenv("HELPDESK_SECRET", secret)

    with pytest.raises(RuntimeError, match="HELPDESK_SECRET"):
        _reload_auth()


def test_default_secret_forged_token_is_rejected_while_real_token_authenticates(client):
    signup = client.post(
        "/auth/signup",
        json={
            "email": TEST_EMAIL,
            "password": "niro-proof-pass-1234",
            "full_name": "Niro TC-4D4012B4 Proof",
        },
    )
    assert signup.status_code == 201

    login = client.post(
        "/auth/login",
        data={
            "username": TEST_EMAIL,
            "password": "niro-proof-pass-1234",
        },
    )
    assert login.status_code == 200

    real_token = login.json()["access_token"]
    me = client.get("/me", headers={"Authorization": f"Bearer {real_token}"})
    assert me.status_code == 200
    user_id = me.json()["id"]

    now = datetime.now(timezone.utc)
    forged_token = jwt.encode(
        {
            "sub": str(user_id),
            "role": "customer",
            "iat": now,
            "exp": now + timedelta(hours=1),
        },
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    forged_me = client.get(
        "/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert forged_me.status_code == 401
