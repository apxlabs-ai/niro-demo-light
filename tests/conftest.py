"""Shared test fixtures — in-memory SQLite DB, FastAPI test client, and
pre-seeded users (two customers + one agent) with JWT tokens."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password, issue_token
from app.db import Base, get_db
from app.main import app
# Import all models so SQLAlchemy registers them with Base.metadata before create_all
from app.models import (  # noqa: F401
    ReportRun,
    Role,
    SavedSearch,
    ScheduledReport,
    Ticket,
    User,
)
import app.search as search_module

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture()
def db_engine():
    # StaticPool ensures every SQLAlchemy connection reuses the same
    # underlying sqlite3 connection, so the in-memory database (and all
    # tables/rows created in fixtures) is visible to TestClient requests.
    engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


@pytest.fixture()
def client(db_session):
    """TestClient with the in-memory DB injected and cache cleared between tests."""
    search_module._cache.clear()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()
    search_module._cache.clear()


@pytest.fixture()
def users(db_session):
    """Seed two customers (A and B) and one agent."""
    customer_a = User(
        email="customer_a@test.com",
        password_hash=hash_password("pass"),
        role=Role.customer,
        full_name="Customer A",
    )
    customer_b = User(
        email="customer_b@test.com",
        password_hash=hash_password("pass"),
        role=Role.customer,
        full_name="Customer B",
    )
    agent = User(
        email="agent@test.com",
        password_hash=hash_password("pass"),
        role=Role.agent,
        full_name="Agent",
    )
    db_session.add_all([customer_a, customer_b, agent])
    db_session.commit()
    db_session.refresh(customer_a)
    db_session.refresh(customer_b)
    db_session.refresh(agent)
    return {"customer_a": customer_a, "customer_b": customer_b, "agent": agent}


@pytest.fixture()
def tokens(users):
    return {
        "customer_a": f"Bearer {issue_token(users['customer_a'])}",
        "customer_b": f"Bearer {issue_token(users['customer_b'])}",
        "agent": f"Bearer {issue_token(users['agent'])}",
    }


@pytest.fixture()
def tickets(db_session, users):
    """One open ticket per customer."""
    t_a = Ticket(
        customer_id=users["customer_a"].id,
        subject="Ticket belonging to Customer A",
        description="desc a",
    )
    t_b = Ticket(
        customer_id=users["customer_b"].id,
        subject="Ticket belonging to Customer B",
        description="desc b",
    )
    db_session.add_all([t_a, t_b])
    db_session.commit()
    db_session.refresh(t_a)
    db_session.refresh(t_b)
    return {"a": t_a, "b": t_b}
