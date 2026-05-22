"""Shared fixtures for the helpdesk test suite.

Uses an in-memory SQLite database and FastAPI's TestClient so each test
module gets a fresh schema with no leftover state.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
from app.models import Role, Ticket, User
from app.search import _cache  # for cache-poisoning tests


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    """TestClient wired to the in-memory DB."""
    _cache.clear()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    _cache.clear()


@pytest.fixture()
def customer_a(db_session):
    u = User(
        email="a@test.com",
        full_name="Customer A",
        role=Role.customer,
        password_hash=hash_password("pass-a"),
    )
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture()
def customer_b(db_session):
    u = User(
        email="b@test.com",
        full_name="Customer B",
        role=Role.customer,
        password_hash=hash_password("pass-b"),
    )
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture()
def agent(db_session):
    u = User(
        email="agent@test.com",
        full_name="Agent",
        role=Role.agent,
        password_hash=hash_password("pass-agent"),
    )
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u


@pytest.fixture()
def token_a(customer_a):
    return issue_token(customer_a)


@pytest.fixture()
def token_b(customer_b):
    return issue_token(customer_b)


@pytest.fixture()
def token_agent(agent):
    return issue_token(agent)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def make_ticket(db, customer: User, subject: str = "ticket", priority: str = "normal"):
    t = Ticket(customer_id=customer.id, subject=subject, description="desc", priority=priority)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def make_search(client, token, name="s", filter_=None):
    r = client.post(
        "/searches",
        json={"name": name, "filter": filter_ or {}},
        headers=auth(token),
    )
    assert r.status_code == 201, r.text
    return r.json()
