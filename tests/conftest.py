"""Shared fixtures for the helpdesk test suite.

Uses an in-memory SQLite DB so each test function gets a clean slate
without touching the dev helpdesk.db file.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import Role, User

SQLALCHEMY_TEST_URL = "sqlite:///:memory:"


@pytest.fixture()
def db_engine():
    engine = create_engine(
        SQLALCHEMY_TEST_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    TestingSession = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    session = TestingSession()
    yield session
    session.close()


@pytest.fixture()
def client(db_engine):
    TestingSession = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _seed_users(db_session):
    """Insert two customers and one agent. Returns (customer_a, customer_b, agent)."""
    a = User(
        email="customer.a@example.com",
        full_name="Customer A",
        role=Role.customer,
        password_hash=hash_password("pass-a"),
    )
    b = User(
        email="customer.b@example.com",
        full_name="Customer B",
        role=Role.customer,
        password_hash=hash_password("pass-b"),
    )
    ag = User(
        email="agent@example.com",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("pass-ag"),
    )
    db_session.add_all([a, b, ag])
    db_session.commit()
    db_session.refresh(a)
    db_session.refresh(b)
    db_session.refresh(ag)
    return a, b, ag


def login(client, email, password):
    resp = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}
