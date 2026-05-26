"""Shared fixtures: in-memory DB, TestClient, and pre-seeded users."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, User
from app.search import _cache  # direct handle so tests can assert cache state


TEST_DB_URL = "sqlite://"  # in-memory, discarded after each test session


@pytest.fixture(scope="session")
def engine():
    eng = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    """Fresh session that rolls back after each test."""
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()
    transaction.rollback()
    connection.close()
    _cache.clear()


@pytest.fixture()
def client(db):
    """TestClient wired to the per-test in-memory session."""
    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    _cache.clear()


# ---------------------------------------------------------------------------
# Pre-seeded users
# ---------------------------------------------------------------------------

@pytest.fixture()
def agent_user(db):
    u = User(
        email="agent@example.com",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("agent-pw"),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def customer_alex(db):
    u = User(
        email="alex@example.com",
        full_name="Alex",
        role=Role.customer,
        password_hash=hash_password("alex-pw"),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def customer_blair(db):
    u = User(
        email="blair@example.org",
        full_name="Blair",
        role=Role.customer,
        password_hash=hash_password("blair-pw"),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login(client, email, password):
    resp = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}
